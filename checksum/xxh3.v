// xxh3 is the seed-zero XXH3 used by the S3 checksums XXH3 and XXH128.
// Long inputs mix 64-byte stripes against the default secret and scramble the
// eight accumulators once per 1024-byte block. Shorter inputs take the length
// specialisations, which is why the tests cover each band rather than one size.
module checksum

import encoding.binary
import math.bits

const x3_stripe = 64
const x3_block = 1024
const x3_prime32_1 = u64(2654435761)
const x3_prime32_2 = u64(2246822519)
const x3_prime32_3 = u64(3266489917)
const x3_prime64_1 = u64(11400714785074694791)
const x3_prime64_2 = u64(14029467366897019727)
const x3_prime64_3 = u64(1609587929392839161)
const x3_prime64_4 = u64(9650029242287828579)
const x3_prime64_5 = u64(2870177450012600261)

fn x3_secret() []u8 {
	return [
		u8(0xb8), 0xfe, 0x6c, 0x39, 0x23, 0xa4, 0x4b, 0xbe, 0x7c, 0x01, 0x81, 0x2c, 0xf7, 0x21, 0xad, 0x1c,
		0xde, 0xd4, 0x6d, 0xe9, 0x83, 0x90, 0x97, 0xdb, 0x72, 0x40, 0xa4, 0xa4, 0xb7, 0xb3, 0x67, 0x1f,
		0xcb, 0x79, 0xe6, 0x4e, 0xcc, 0xc0, 0xe5, 0x78, 0x82, 0x5a, 0xd0, 0x7d, 0xcc, 0xff, 0x72, 0x21,
		0xb8, 0x08, 0x46, 0x74, 0xf7, 0x43, 0x24, 0x8e, 0xe0, 0x35, 0x90, 0xe6, 0x81, 0x3a, 0x26, 0x4c,
		0x3c, 0x28, 0x52, 0xbb, 0x91, 0xc3, 0x00, 0xcb, 0x88, 0xd0, 0x65, 0x8b, 0x1b, 0x53, 0x2e, 0xa3,
		0x71, 0x64, 0x48, 0x97, 0xa2, 0x0d, 0xf9, 0x4e, 0x38, 0x19, 0xef, 0x46, 0xa9, 0xde, 0xac, 0xd8,
		0xa8, 0xfa, 0x76, 0x3f, 0xe3, 0x9c, 0x34, 0x3f, 0xf9, 0xdc, 0xbb, 0xc7, 0xc7, 0x0b, 0x4f, 0x1d,
		0x8a, 0x51, 0xe0, 0x4b, 0xcd, 0xb4, 0x59, 0x31, 0xc8, 0x9f, 0x7e, 0xc9, 0xd9, 0x78, 0x73, 0x64,
		0xea, 0xc5, 0xac, 0x83, 0x34, 0xd3, 0xeb, 0xc3, 0xc5, 0x81, 0xa0, 0xff, 0xfa, 0x13, 0x63, 0xeb,
		0x17, 0x0d, 0xdd, 0x51, 0xb7, 0xf0, 0xda, 0x49, 0xd3, 0x16, 0x55, 0x26, 0x29, 0xd4, 0x68, 0x9e,
		0x2b, 0x16, 0xbe, 0x58, 0x7d, 0x47, 0xa1, 0xfc, 0x8f, 0xf8, 0xb8, 0xd1, 0x7a, 0xd0, 0x31, 0xce,
		0x45, 0xcb, 0x3a, 0x8f, 0x95, 0x16, 0x04, 0x28, 0xaf, 0xd7, 0xfb, 0xca, 0xbb, 0x4b, 0x40, 0x7e,
	]
}

const x3_key = x3_secret()

fn x3_u8(data []u8, at int) u64 {
	return u64(data[at])
}

fn x3_u16(data []u8, at int) u64 {
	return u64(data[at]) | (u64(data[at + 1]) << 8)
}

fn x3_u32(data []u8, at int) u64 {
	return u64(binary.little_endian_u32_at(data, at))
}

fn x3_u64(data []u8, at int) u64 {
	return binary.little_endian_u64_at(data, at)
}

fn x3_key64(at int) u64 {
	return x3_u64(x3_key, at)
}

fn x3_mul_fold(x u64, y u64) u64 {
	hi, lo := bits.mul_64(x, y)
	return hi ^ lo
}

fn x3_avalanche(x u64) u64 {
	mut mixed := x
	mixed ^= mixed >> 37
	mixed *= u64(0x165667919e3779f9)
	mixed ^= mixed >> 32
	return mixed
}

fn x3_avalanche_small(x u64) u64 {
	mut mixed := x
	mixed ^= mixed >> 33
	mixed *= x3_prime64_2
	mixed ^= mixed >> 29
	mixed *= x3_prime64_3
	mixed ^= mixed >> 32
	return mixed
}

fn x3_rrmxmx(h u64, length u64) u64 {
	mut mixed := h ^ bits.rotate_left_64(h, 49) ^ bits.rotate_left_64(h, 24)
	mixed *= u64(0x9fb21c651e98df25)
	mixed ^= (mixed >> 35) + length
	mixed *= u64(0x9fb21c651e98df25)
	mixed ^= mixed >> 28
	return mixed
}

fn x3_neg(x u64) u64 {
	return ~x + 1
}

fn accum_stripe(mut accs [8]u64, data []u8, at int, secret_at int) {
	for off in 0 .. 4 {
		base := off * 2
		dv0 := x3_u64(data, at + 8 * base)
		dk0 := dv0 ^ x3_key64(secret_at + 8 * base)
		mut ac0 := u64(u32(dk0)) * (dk0 >> 32)
		mut ac1 := dv0
		dv1 := x3_u64(data, at + 8 * base + 8)
		dk1 := dv1 ^ x3_key64(secret_at + 8 * base + 8)
		ac0 += dv1
		ac1 += u64(u32(dk1)) * (dk1 >> 32)
		accs[base] += ac0
		accs[base + 1] += ac1
	}
}

fn accum_tail(mut accs [8]u64, data []u8, at int) {
	for i in 0 .. 8 {
		dv := x3_u64(data, at + 8 * i)
		dk := dv ^ x3_key64(121 + 8 * i)
		mixed := u64(u32(dk)) * (dk >> 32)
		if i % 2 == 0 {
			accs[i + 1] += dv
			accs[i] += mixed
		} else {
			accs[i - 1] += dv
			accs[i] += mixed
		}
	}
}

fn scramble(mut accs [8]u64) {
	for i in 0 .. 8 {
		accs[i] ^= accs[i] >> 47
		accs[i] ^= x3_key64(128 + 8 * i)
		accs[i] *= x3_prime32_1
	}
}

fn fresh_accs() [8]u64 {
	mut accs := [8]u64{}
	accs[0] = x3_prime32_3
	accs[1] = x3_prime64_1
	accs[2] = x3_prime64_2
	accs[3] = x3_prime64_3
	accs[4] = x3_prime64_4
	accs[5] = x3_prime32_2
	accs[6] = x3_prime64_5
	accs[7] = x3_prime32_1
	return accs
}

fn accumulate(data []u8) [8]u64 {
	mut accs := fresh_accs()
	mut length := data.len
	mut at := 0
	for length > x3_block {
		mut secret_at := 0
		for _ in 0 .. 16 {
			accum_stripe(mut accs, data, at, secret_at)
			length -= x3_stripe
			if length > 0 {
				at += x3_stripe
				secret_at += 8
			}
		}
		scramble(mut accs)
	}
	if length > 0 {
		stripes := (length - 1) / x3_stripe
		mut secret_at := 0
		for _ in 0 .. stripes {
			accum_stripe(mut accs, data, at, secret_at)
			length -= x3_stripe
			if length > 0 {
				at += x3_stripe
				secret_at += 8
			}
		}
		if length > 0 {
			at -= x3_stripe - length
			accum_tail(mut accs, data, at)
		}
	}
	return accs
}

fn xxh3_long(data []u8) u64 {
	accs := accumulate(data)
	mut acc := u64(data.len) * x3_prime64_1
	acc += x3_mul_fold(accs[0] ^ x3_key64(11), accs[1] ^ x3_key64(19))
	acc += x3_mul_fold(accs[2] ^ x3_key64(27), accs[3] ^ x3_key64(35))
	acc += x3_mul_fold(accs[4] ^ x3_key64(43), accs[5] ^ x3_key64(51))
	acc += x3_mul_fold(accs[6] ^ x3_key64(59), accs[7] ^ x3_key64(67))
	return x3_avalanche(acc)
}

fn xxh3_mid(data []u8) u64 {
	length := data.len
	mut acc := u64(length) * x3_prime64_1
	if length > 32 {
		if length > 64 {
			if length > 96 {
				acc += x3_mul_fold(x3_u64(data, 48) ^ x3_key64(96), x3_u64(data, 56) ^ x3_key64(104))
				acc += x3_mul_fold(x3_u64(data, length - 64) ^ x3_key64(112), x3_u64(data, length - 56) ^ x3_key64(120))
			}
			acc += x3_mul_fold(x3_u64(data, 32) ^ x3_key64(64), x3_u64(data, 40) ^ x3_key64(72))
			acc += x3_mul_fold(x3_u64(data, length - 48) ^ x3_key64(80), x3_u64(data, length - 40) ^ x3_key64(88))
		}
		acc += x3_mul_fold(x3_u64(data, 16) ^ x3_key64(32), x3_u64(data, 24) ^ x3_key64(40))
		acc += x3_mul_fold(x3_u64(data, length - 32) ^ x3_key64(48), x3_u64(data, length - 24) ^ x3_key64(56))
	}
	acc += x3_mul_fold(x3_u64(data, 0) ^ x3_key64(0), x3_u64(data, 8) ^ x3_key64(8))
	acc += x3_mul_fold(x3_u64(data, length - 16) ^ x3_key64(16), x3_u64(data, length - 8) ^ x3_key64(24))
	return x3_avalanche(acc)
}

fn xxh3_240(data []u8) u64 {
	length := data.len
	mut acc := u64(length) * x3_prime64_1
	for group in 0 .. 8 {
		acc += x3_mul_fold(x3_u64(data, group * 16) ^ x3_key64(group * 16), x3_u64(data, group * 16 + 8) ^ x3_key64(group * 16 + 8))
	}
	acc = x3_avalanche(acc)
	top := (length >> 4) << 4
	for i := 128; i < top; i += 16 {
		acc += x3_mul_fold(x3_u64(data, i) ^ x3_key64(i - 125), x3_u64(data, i + 8) ^ x3_key64(i - 117))
	}
	acc += x3_mul_fold(x3_u64(data, length - 16) ^ x3_key64(119), x3_u64(data, length - 8) ^ x3_key64(127))
	return x3_avalanche(acc)
}

// xxh3_64 hashes data with the default secret and a zero seed.
pub fn xxh3_64(data []u8) u64 {
	length := data.len
	if length > 240 {
		return xxh3_long(data)
	}
	if length > 128 {
		return xxh3_240(data)
	}
	if length > 16 {
		return xxh3_mid(data)
	}
	if length > 8 {
		lo := x3_u64(data, 0) ^ (x3_key64(24) ^ x3_key64(32))
		hi := x3_u64(data, length - 8) ^ (x3_key64(40) ^ x3_key64(48))
		mixed := u64(length) + bits.reverse_bytes_64(lo) + hi + x3_mul_fold(lo, hi)
		return x3_avalanche(mixed)
	}
	if length > 3 {
		input := x3_u32(data, length - 4) + (x3_u32(data, 0) << 32)
		keyed := input ^ (x3_key64(8) ^ x3_key64(16))
		return x3_rrmxmx(keyed, u64(length))
	}
	mut acc := u64(0)
	if length == 3 {
		acc = (x3_u16(data, 0) << 16) + x3_u8(data, 2) + (u64(3) << 8)
	} else if length == 2 {
		acc = ((x3_u16(data, 0) * ((u64(1) << 24) + 1)) >> 8) + (u64(2) << 8)
	} else if length == 1 {
		acc = x3_u8(data, 0) * ((u64(1) << 24) + (u64(1) << 16) + 1) + (u64(1) << 8)
	} else {
		return u64(0x2d06800538d394c2)
	}
	// The short avalanche is keyed by the first two 32-bit secret words.
	acc ^= x3_u32(x3_key, 0) ^ x3_u32(x3_key, 4)
	return x3_avalanche_small(acc)
}

fn x3_avalanche64_tail(x u64) u64 {
	mut mixed := x * x3_prime64_2
	mixed ^= mixed >> 29
	mixed *= x3_prime64_3
	mixed ^= mixed >> 32
	return mixed
}

fn mix128(lo u64, hi u64, i0 u64, i1 u64, i2 u64, i3 u64, k0 u64, k1 u64, k2 u64, k3 u64) (u64, u64) {
	mut next_lo := lo
	mut next_hi := hi
	next_hi += x3_mul_fold(i2 ^ k2, i3 ^ k3)
	next_hi ^= i0 + i1
	next_lo += x3_mul_fold(i0 ^ k0, i1 ^ k1)
	next_lo ^= i2 + i3
	return next_lo, next_hi
}

fn finish128(lo u64, hi u64, length int) (u64, u64) {
	next_hi := lo * x3_prime64_1 + hi * x3_prime64_4 + u64(length) * x3_prime64_2
	next_lo := hi + lo
	mut aval_lo := next_lo
	mut aval_hi := next_hi
	return x3_avalanche(aval_lo), x3_neg(x3_avalanche(aval_hi))
}

// xxh3_128 returns the low and high halves of XXH3-128 with the default secret.
pub fn xxh3_128(data []u8) (u64, u64) {
	length := data.len
	if length == 0 {
		return u64(0x6001c324468d497f), u64(0x99aa06d3014798d8)
	}
	if length > 240 {
		mut lo := u64(length) * x3_prime64_1
		mut hi := ~(u64(length) * x3_prime64_2)
		accs := accumulate(data)
		lo += x3_mul_fold(accs[0] ^ x3_key64(11), accs[1] ^ x3_key64(19))
		hi += x3_mul_fold(accs[0] ^ x3_key64(117), accs[1] ^ x3_key64(125))
		lo += x3_mul_fold(accs[2] ^ x3_key64(27), accs[3] ^ x3_key64(35))
		hi += x3_mul_fold(accs[2] ^ x3_key64(133), accs[3] ^ x3_key64(141))
		lo += x3_mul_fold(accs[4] ^ x3_key64(43), accs[5] ^ x3_key64(51))
		hi += x3_mul_fold(accs[4] ^ x3_key64(149), accs[5] ^ x3_key64(157))
		lo += x3_mul_fold(accs[6] ^ x3_key64(59), accs[7] ^ x3_key64(67))
		hi += x3_mul_fold(accs[6] ^ x3_key64(165), accs[7] ^ x3_key64(173))
		mut aval_lo := lo
		mut aval_hi := hi
		return x3_avalanche(aval_lo), x3_avalanche(aval_hi)
	}
	if length > 128 {
		mut lo := u64(length) * x3_prime64_1
		mut hi := u64(0)
		for group in 0 .. 4 {
			at := group * 32
			lo, hi = mix128(lo, hi, x3_u64(data, at), x3_u64(data, at + 8), x3_u64(data, at + 16),
				x3_u64(data, at + 24), x3_key64(at), x3_key64(at + 8), x3_key64(at + 16), x3_key64(at + 24))
		}
		mut aval_lo := lo
		mut aval_hi := hi
		lo = x3_avalanche(aval_lo)
		hi = x3_avalanche(aval_hi)
		top := (length >> 5) << 5
		for i := 128; i < top; i += 32 {
			lo, hi = mix128(lo, hi, x3_u64(data, i), x3_u64(data, i + 8), x3_u64(data, i + 16),
				x3_u64(data, i + 24), x3_key64(i - 125), x3_key64(i - 117), x3_key64(i - 109),
				x3_key64(i - 101))
		}
		// The closing 32 bytes pair the earlier half with the low accumulator
		// and the later half with the high one, the reverse of a normal stripe.
		earlier0 := x3_u64(data, length - 32)
		earlier1 := x3_u64(data, length - 24)
		later0 := x3_u64(data, length - 16)
		later1 := x3_u64(data, length - 8)
		hi += x3_mul_fold(earlier0 ^ x3_key64(119), earlier1 ^ x3_key64(127))
		hi ^= later0 + later1
		lo += x3_mul_fold(later0 ^ x3_key64(103), later1 ^ x3_key64(111))
		lo ^= earlier0 + earlier1
		return finish128(lo, hi, length)
	}
	if length > 16 {
		mut lo := u64(length) * x3_prime64_1
		mut hi := u64(0)
		if length > 96 {
			lo, hi = fold_ends(lo, hi, data, 96, 64, 48)
		}
		if length > 64 {
			lo, hi = fold_ends(lo, hi, data, 64, 48, 32)
		}
		if length > 32 {
			lo, hi = fold_ends(lo, hi, data, 32, 32, 16)
		}
		lo, hi = fold_ends(lo, hi, data, 0, 16, 0)
		return finish128(lo, hi, length)
	}
	if length > 8 {
		bit_lo := x3_key64(32) ^ x3_key64(40)
		bit_hi := x3_key64(48) ^ x3_key64(56)
		input_lo := x3_u64(data, 0)
		mut input_hi := x3_u64(data, length - 8)
		mut prod_hi, mut prod_lo := bits.mul_64(input_lo ^ input_hi ^ bit_lo, x3_prime64_1)
		prod_lo += u64(length - 1) << 54
		input_hi ^= bit_hi
		prod_hi += input_hi + u64(u32(input_hi)) * (x3_prime32_2 - 1)
		prod_lo ^= bits.reverse_bytes_64(prod_hi)
		mut out_hi, mut out_lo := bits.mul_64(prod_lo, x3_prime64_2)
		out_hi += prod_hi * x3_prime64_2
		return x3_avalanche(out_lo), x3_avalanche(out_hi)
	}
	if length > 3 {
		input := x3_u32(data, 0) + (x3_u32(data, length - 4) << 32)
		keyed := input ^ (x3_key64(16) ^ x3_key64(24))
		mut hi, mut lo := bits.mul_64(keyed, x3_prime64_1 + (u64(length) << 2))
		hi += lo << 1
		lo ^= hi >> 3
		lo ^= lo >> 35
		lo *= u64(0x9fb21c651e98df25)
		lo ^= lo >> 28
		return lo, x3_avalanche(hi)
	}
	mut lo := u64(0)
	if length == 3 {
		lo = (x3_u16(data, 0) << 16) + x3_u8(data, 2) + (u64(3) << 8)
	} else if length == 2 {
		lo = ((x3_u16(data, 0) * ((u64(1) << 24) + 1)) >> 8) + (u64(2) << 8)
	} else {
		lo = x3_u8(data, 0) * ((u64(1) << 24) + (u64(1) << 16) + 1) + (u64(1) << 8)
	}
	hi := u64(bits.rotate_left_32(bits.reverse_bytes_32(u32(lo)), 13))
	lo ^= x3_u32(x3_key, 0) ^ x3_u32(x3_key, 4)
	keyed_hi := hi ^ (x3_u32(x3_key, 8) ^ x3_u32(x3_key, 12))
	return x3_avalanche64_tail(lo), x3_avalanche64_tail(keyed_hi)
}

// fold_ends mixes one 16-byte window at `start` with the window the same
// distance from the end. `from_end` is how far the end window sits from the
// last byte, counted so the caller names the secret offset directly.
fn fold_ends(lo u64, hi u64, data []u8, secret_at int, end_back int, start int) (u64, u64) {
	end := data.len - end_back
	in_end0 := x3_u64(data, end)
	in_end1 := x3_u64(data, end + 8)
	i0 := x3_u64(data, start)
	i1 := x3_u64(data, start + 8)
	mut next_hi := hi + x3_mul_fold(in_end0 ^ x3_key64(secret_at + 16), in_end1 ^ x3_key64(secret_at + 24))
	next_hi ^= i0 + i1
	mut next_lo := lo + x3_mul_fold(i0 ^ x3_key64(secret_at), i1 ^ x3_key64(secret_at + 8))
	next_lo ^= in_end0 + in_end1
	return next_lo, next_hi
}
