// bitrot guards each erasure shard with a hash frame. The hash and the S3
// checksum are different jobs: the checksum is what the client asked to verify,
// and the frame is what a disk must match before its bytes are allowed into a
// rebuild. The algorithm is recorded beside the object so a volume can change
// its default without making older shards unreadable.
module bitrot

import crypto.blake2b
import crypto.md5
import crypto.sha256

// Algo names the hash stored ahead of a shard. none is a frame with no prefix,
// used when a deployment turns bitrot off.
pub enum Algo {
	sha256
	highway256
	highway256s
	highway256s_legacy
	blake2b512
	md5
	none
}

// magic_highway_key is the HighwayHash-256 key derived from the first digits
// of pi. highway256 and highway256s share it; the streaming name records which
// reader produced the frame, not a second function.
const magic_highway_key = key_of([
	u8(0x4b), 0xe7, 0x34, 0xfa, 0x8e, 0x23, 0x8a, 0xcd, 0x26, 0x3e, 0x83, 0xe6, 0xbb, 0x96, 0x85, 0x52,
	0x04, 0x0f, 0x93, 0x5d, 0xa3, 0x9f, 0x44, 0x14, 0x97, 0xe0, 0x9d, 0x13, 0x22, 0xde, 0x36, 0xa0,
])

// legacy_highway_key is the fixed [3, 4, 2, 1] key older shards were written with.
const legacy_highway_key = key_of([
	u8(3), 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0,
])

fn key_of(bytes []u8) [4]u64 {
	mut key := [4]u64{}
	for lane in 0 .. 4 {
		mut value := u64(0)
		for i in 0 .. 8 {
			value |= u64(bytes[lane * 8 + i]) << (i * 8)
		}
		key[lane] = value
	}
	return key
}

// parse reads the algorithm name stored in metadata. Unknown names fail closed:
// a shard hashed with an algorithm we cannot recompute must not be treated as
// intact.
pub fn parse(name string) !Algo {
	return match name {
		'sha256', 'SHA256' { Algo.sha256 }
		'highway256', 'HighwayHash256' { Algo.highway256 }
		'highway256s', 'HighwayHash256S', '' { Algo.highway256s }
		'highway256s-legacy', 'HighwayHash256SLegacy' { Algo.highway256s_legacy }
		'blake2b512', 'BLAKE2b512' { Algo.blake2b512 }
		'md5', 'MD5' { Algo.md5 }
		'none', 'None' { Algo.none }
		else { error('unknown bitrot algorithm: ${name}') }
	}
}

pub fn (a Algo) str() string {
	return match a {
		.sha256 { 'SHA256' }
		.highway256 { 'HighwayHash256' }
		.highway256s { 'HighwayHash256S' }
		.highway256s_legacy { 'HighwayHash256SLegacy' }
		.blake2b512 { 'BLAKE2b512' }
		.md5 { 'MD5' }
		.none { 'None' }
	}
}

// size is the number of bytes the frame stores ahead of the shard.
pub fn (a Algo) size() int {
	return match a {
		.sha256, .highway256, .highway256s, .highway256s_legacy { 32 }
		.blake2b512 { 64 }
		.md5 { 16 }
		.none { 0 }
	}
}

// sum hashes one shard payload.
pub fn (a Algo) sum(data []u8) []u8 {
	return match a {
		.sha256 { sha256.sum256(data) }
		.highway256, .highway256s { highway256(magic_highway_key, data) }
		.highway256s_legacy { highway256(legacy_highway_key, data) }
		.blake2b512 { blake2b.sum512(data) }
		.md5 { md5.sum(data) }
		.none { []u8{} }
	}
}

// frame writes the hash and then the shard. A none frame is the shard itself.
pub fn frame(algo Algo, data []u8) []u8 {
	digest := algo.sum(data)
	mut out := []u8{cap: digest.len + data.len}
	out << digest
	out << data
	return out
}

// open_frame checks the leading hash and returns the shard. A mismatch is a
// disk error, not a missing shard: the caller decides whether the set can
// still be rebuilt from the drives that survived.
pub fn open_frame(algo Algo, framed []u8) ![]u8 {
	width := algo.size()
	if framed.len < width {
		return error('bitrot frame is short')
	}
	digest := framed[..width]
	data := framed[width..]
	if !equal(digest, algo.sum(data)) {
		return error('bitrot mismatch')
	}
	return data.clone()
}

fn equal(a []u8, b []u8) bool {
	if a.len != b.len {
		return false
	}
	mut diff := u8(0)
	for i in 0 .. a.len {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}
