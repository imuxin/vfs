// xxh64 is XXH64, the 64-bit checksum S3 clients send as x-amz-checksum-xxh64.
// The primes and the three-way tail (8, 4, then single bytes) are the frozen
// algorithm, so a seed of zero matches the published sanity vectors.
module checksum

import encoding.binary

const xxh_prime64_1 = u64(0x9E3779B185EBCA87)
const xxh_prime64_2 = u64(0xC2B2AE3D27D4EB4F)
const xxh_prime64_3 = u64(0x165667B19E3779F9)
const xxh_prime64_4 = u64(0x85EBCA77C2B2AE63)
const xxh_prime64_5 = u64(0x27D4EB2F165667C5)

fn rotl64(x u64, n int) u64 {
	return (x << n) | (x >> (64 - n))
}

fn xxh64_round(acc u64, input u64) u64 {
	mut mixed := acc + input * xxh_prime64_2
	mixed = rotl64(mixed, 31)
	return mixed * xxh_prime64_1
}

fn xxh64_merge(acc u64, val u64) u64 {
	return (acc ^ xxh64_round(0, val)) * xxh_prime64_1 + xxh_prime64_4
}

fn xxh64_avalanche(h u64) u64 {
	mut mixed := h
	mixed ^= mixed >> 33
	mixed *= xxh_prime64_2
	mixed ^= mixed >> 29
	mixed *= xxh_prime64_3
	mixed ^= mixed >> 32
	return mixed
}

// xxh64 hashes data with the given seed.
pub fn xxh64(data []u8, seed u64) u64 {
	mut hash := u64(0)
	mut offset := 0
	if data.len >= 32 {
		mut acc1 := seed + xxh_prime64_1 + xxh_prime64_2
		mut acc2 := seed + xxh_prime64_2
		mut acc3 := seed + u64(0)
		mut acc4 := seed - xxh_prime64_1
		for offset + 32 <= data.len {
			acc1 = xxh64_round(acc1, binary.little_endian_u64_at(data, offset))
			acc2 = xxh64_round(acc2, binary.little_endian_u64_at(data, offset + 8))
			acc3 = xxh64_round(acc3, binary.little_endian_u64_at(data, offset + 16))
			acc4 = xxh64_round(acc4, binary.little_endian_u64_at(data, offset + 24))
			offset += 32
		}
		hash = rotl64(acc1, 1) + rotl64(acc2, 7) + rotl64(acc3, 12) + rotl64(acc4, 18)
		hash = xxh64_merge(hash, acc1)
		hash = xxh64_merge(hash, acc2)
		hash = xxh64_merge(hash, acc3)
		hash = xxh64_merge(hash, acc4)
	} else {
		hash = seed + xxh_prime64_5
	}
	hash += u64(data.len)
	for offset + 8 <= data.len {
		hash ^= xxh64_round(0, binary.little_endian_u64_at(data, offset))
		hash = rotl64(hash, 27) * xxh_prime64_1 + xxh_prime64_4
		offset += 8
	}
	if offset + 4 <= data.len {
		hash ^= u64(binary.little_endian_u32_at(data, offset)) * xxh_prime64_1
		hash = rotl64(hash, 23) * xxh_prime64_2 + xxh_prime64_3
		offset += 4
	}
	for offset < data.len {
		hash ^= u64(data[offset]) * xxh_prime64_5
		hash = rotl64(hash, 11) * xxh_prime64_1
		offset++
	}
	return xxh64_avalanche(hash)
}
