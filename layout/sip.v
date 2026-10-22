// sip is SipHash-2-4, the function SIPMOD uses to choose an erasure set. The
// key is the deployment id, so two clusters hash the same object name apart.
module layout

import encoding.binary
import hash.crc32

fn rotl(x u64, n int) u64 {
	return (x << n) | (x >> (64 - n))
}

fn sip_round(v0 u64, v1 u64, v2 u64, v3 u64) (u64, u64, u64, u64) {
	mut a := v0
	mut b := v1
	mut c := v2
	mut d := v3
	a += b
	b = rotl(b, 13)
	b ^= a
	a = rotl(a, 32)
	c += d
	d = rotl(d, 16)
	d ^= c
	a += d
	d = rotl(d, 21)
	d ^= a
	c += b
	b = rotl(b, 17)
	b ^= c
	c = rotl(c, 32)
	return a, b, c, d
}

// siphash24 hashes data with a 16-byte key.
pub fn siphash24(data []u8, key []u8) u64 {
	k0 := binary.little_endian_u64(key[..8])
	k1 := binary.little_endian_u64(key[8..16])
	mut v0 := u64(0x736f6d6570736575) ^ k0
	mut v1 := u64(0x646f72616e646f6d) ^ k1
	mut v2 := u64(0x6c7967656e657261) ^ k0
	mut v3 := u64(0x7465646279746573) ^ k1
	mut offset := 0
	for offset + 8 <= data.len {
		word := binary.little_endian_u64_at(data, offset)
		v3 ^= word
		v0, v1, v2, v3 = sip_round(v0, v1, v2, v3)
		v0, v1, v2, v3 = sip_round(v0, v1, v2, v3)
		v0 ^= word
		offset += 8
	}
	mut tail := u64(data.len) << 56
	rest := data[offset..]
	for i := rest.len - 1; i >= 0; i-- {
		tail |= u64(rest[i]) << (i * 8)
	}
	v3 ^= tail
	v0, v1, v2, v3 = sip_round(v0, v1, v2, v3)
	v0, v1, v2, v3 = sip_round(v0, v1, v2, v3)
	v0 ^= tail
	v2 ^= 0xff
	v0, v1, v2, v3 = sip_round(v0, v1, v2, v3)
	v0, v1, v2, v3 = sip_round(v0, v1, v2, v3)
	v0, v1, v2, v3 = sip_round(v0, v1, v2, v3)
	v0, v1, v2, v3 = sip_round(v0, v1, v2, v3)
	return v0 ^ v1 ^ v2 ^ v3
}

// Algo selects which hash picks an erasure set. Reading still accepts the
// older CRC and plain SIP names; new volumes write SIPMOD+PARITY.
pub enum Algo {
	crcmod
	sipmod
	sipmod_parity
}

pub fn (a Algo) str() string {
	return match a {
		.crcmod { 'CRCMOD' }
		.sipmod { 'SIPMOD' }
		.sipmod_parity { 'SIPMOD+PARITY' }
	}
}

pub fn parse_algo(name string) !Algo {
	return match name {
		'CRCMOD' { Algo.crcmod }
		'SIPMOD' { Algo.sipmod }
		'SIPMOD+PARITY', '' { Algo.sipmod_parity }
		else { error('unknown distribution: ${name}') }
	}
}

// pick chooses a set index in `[0, cardinality)`.
pub fn pick(algo Algo, key string, cardinality int, id []u8) int {
	if cardinality <= 1 {
		return 0
	}
	match algo {
		.crcmod {
			return int(crc32.sum(key.bytes()) % u32(cardinality))
		}
		.sipmod, .sipmod_parity {
			return int(siphash24(key.bytes(), id) % u64(cardinality))
		}
	}
}

// rotate is how far SIPMOD+PARITY shifts shard placement inside a set, so
// parity does not always land on the same drives. The other algorithms leave
// shard zero on drive zero.
pub fn rotate(algo Algo, key string, drives int, id []u8) int {
	if algo != .sipmod_parity || drives <= 1 {
		return 0
	}
	return int(siphash24(key.bytes(), id) % u64(drives))
}
