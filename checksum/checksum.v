// checksum is the S3 checksum, separate from the on-disk bitrot frame. A client
// names the algorithm with x-amz-checksum-algorithm and may append the digest
// to the body; the stored value is the canonical byte string the header echoes.
module checksum

import crypto.sha1
import crypto.sha256
import encoding.base64
import stdsum
import encoding.binary
import hash.crc32

// Kind is one algorithm S3 accepts on a write.
pub enum Kind {
	crc_32
	crc_32c
	crc_64nvme
	sha_1
	sha_256
	sha_512
	xxh_3
	xxh_64
	xxh_128
}

// parse reads an x-amz-checksum-algorithm value. The match is case-sensitive
// because that is the header S3 defines.
pub fn parse(name string) !Kind {
	return match name {
		'CRC32' { Kind.crc_32 }
		'CRC32C' { Kind.crc_32c }
		'CRC64NVME' { Kind.crc_64nvme }
		'SHA1' { Kind.sha_1 }
		'SHA256' { Kind.sha_256 }
		'SHA512' { Kind.sha_512 }
		'XXH3' { Kind.xxh_3 }
		'XXH64' { Kind.xxh_64 }
		'XXH128' { Kind.xxh_128 }
		else { error('unsupported checksum algorithm: ${name}') }
	}
}

pub fn (k Kind) str() string {
	return match k {
		.crc_32 { 'CRC32' }
		.crc_32c { 'CRC32C' }
		.crc_64nvme { 'CRC64NVME' }
		.sha_1 { 'SHA1' }
		.sha_256 { 'SHA256' }
		.sha_512 { 'SHA512' }
		.xxh_3 { 'XXH3' }
		.xxh_64 { 'XXH64' }
		.xxh_128 { 'XXH128' }
	}
}

// size is the canonical checksum length. Integer algorithms are big-endian.
pub fn (k Kind) size() int {
	return match k {
		.crc_32, .crc_32c { 4 }
		.crc_64nvme, .xxh_3, .xxh_64 { 8 }
		.sha_1 { 20 }
		.sha_256 { 32 }
		.sha_512 { 64 }
		.xxh_128 { 16 }
	}
}

// sum is the canonical checksum bytes.
pub fn (k Kind) sum(data []u8) []u8 {
	return match k {
		.crc_32 { binary.big_endian_get_u32(crc32.sum(data)) }
		.crc_32c { binary.big_endian_get_u32(crc32.sum_crc32c(data)) }
		.crc_64nvme { binary.big_endian_get_u64(crc64_nvme(data)) }
		.sha_1 { sha1.sum(data) }
		.sha_256 { sha256.sum256(data) }
		.sha_512 { stdsum.sum_sha512(data) }
		.xxh_3 { binary.big_endian_get_u64(xxh3_64(data)) }
		.xxh_64 { binary.big_endian_get_u64(xxh64(data, 0)) }
		.xxh_128 { xxh3_128_bytes(data) }
	}
}

// header is the base64 value S3 puts in x-amz-checksum-*.
pub fn (k Kind) header(data []u8) string {
	return base64.encode(k.sum(data))
}

// split_trailing separates a body that ends with its own checksum. The prefix
// is what was hashed; the suffix is what the client claims that hash is.
pub fn split_trailing(kind Kind, body []u8) !( []u8, []u8) {
	width := kind.size()
	if body.len < width {
		return error('trailing checksum is short')
	}
	return body[..body.len - width].clone(), body[body.len - width..].clone()
}

// valid_trailing reports whether the suffix of body is the checksum of the prefix.
pub fn valid_trailing(kind Kind, body []u8) !bool {
	prefix, suffix := split_trailing(kind, body)!
	return equal_bytes(kind.sum(prefix), suffix)
}

fn equal_bytes(a []u8, b []u8) bool {
	if a.len != b.len {
		return false
	}
	mut diff := u8(0)
	for i in 0 .. a.len {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}

// xxh3_128_bytes is filled in by xxh128.v. A placeholder keeps this file
// compiling if the 128-bit specialisation is beside it.
fn xxh3_128_bytes(data []u8) []u8 {
	lo, hi := xxh3_128(data)
	mut out := []u8{cap: 16}
	out << binary.big_endian_get_u64(hi)
	out << binary.big_endian_get_u64(lo)
	return out
}
