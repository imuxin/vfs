// highway is the portable HighwayHash used for on-disk bitrot frames.
// The arithmetic is the frozen portable formulation: four lanes, a 32-byte
// packet, and a length-padded remainder. Golden vectors pin the bytes so a
// later simplification cannot silently change the disk format.
module bitrot

import encoding.binary

struct Highway {
mut:
	v0   [4]u64
	v1   [4]u64
	mul0 [4]u64
	mul1 [4]u64
}

fn rot64_by_32(x u64) u64 {
	return (x >> 32) | (x << 32)
}

fn (mut h Highway) reset(key [4]u64) {
	init0 := [u64(0xdbe6d5d5fe4cce2f), u64(0xa4093822299f31d0), u64(0x13198a2e03707344),
		u64(0x243f6a8885a308d3)]!
	init1 := [u64(0x3bd39e10cb0ef593), u64(0xc0acf169b5f18a8c), u64(0xbe5466cf34e90c6c),
		u64(0x452821e638d01377)]!
	h.mul0 = init0
	h.mul1 = init1
	for lane in 0 .. 4 {
		h.v0[lane] = init0[lane] ^ key[lane]
		h.v1[lane] = init1[lane] ^ rot64_by_32(key[lane])
	}
}

// zipper_merge interleaves bytes from two lanes. The pieces land in distinct
// bit ranges, so the mix is a bitwise or; adding them would be the same bytes
// only while those ranges stay disjoint.
fn zipper_merge(v1 u64, v0 u64) (u64, u64) {
	add0 := (((v0 & 0xff000000) | (v1 & 0xff00000000)) >> 24) | (((v0 & 0xff0000000000) | (v1 & 0xff000000000000)) >> 16) |
		(v0 & 0xff0000) | ((v0 & 0xff00) << 32) | ((v1 & 0xff00000000000000) >> 8) | (v0 << 56)
	add1 := (((v1 & 0xff000000) | (v0 & 0xff00000000)) >> 24) | (v1 & 0xff0000) | ((v1 & 0xff0000000000) >> 16) |
		((v1 & 0xff00) << 24) | ((v0 & 0xff000000000000) >> 8) | ((v1 & 0xff) << 48) | (v0 & 0xff00000000000000)
	return add0, add1
}

fn load_lanes(packet []u8) [4]u64 {
	mut lanes := [4]u64{}
	lanes[0] = binary.little_endian_u64_at(packet, 0)
	lanes[1] = binary.little_endian_u64_at(packet, 8)
	lanes[2] = binary.little_endian_u64_at(packet, 16)
	lanes[3] = binary.little_endian_u64_at(packet, 24)
	return lanes
}

fn (mut h Highway) update_lanes(lanes [4]u64) {
	for lane in 0 .. 4 {
		h.v1[lane] += lanes[lane]
		h.v1[lane] += h.mul0[lane]
		v1_32 := u32(h.v1[lane])
		h.mul0[lane] ^= u64(v1_32) * (h.v0[lane] >> 32)
		h.v0[lane] += h.mul1[lane]
		v0_32 := u32(h.v0[lane])
		h.mul1[lane] ^= u64(v0_32) * (h.v1[lane] >> 32)
	}
	z00, z01 := zipper_merge(h.v1[1], h.v1[0])
	h.v0[0] += z00
	h.v0[1] += z01
	z20, z21 := zipper_merge(h.v1[3], h.v1[2])
	h.v0[2] += z20
	h.v0[3] += z21
	z10, z11 := zipper_merge(h.v0[1], h.v0[0])
	h.v1[0] += z10
	h.v1[1] += z11
	z30, z31 := zipper_merge(h.v0[3], h.v0[2])
	h.v1[2] += z30
	h.v1[3] += z31
}

fn (mut h Highway) update_packet(packet []u8) {
	h.update_lanes(load_lanes(packet))
}

// rotate_halves rotates each 32-bit half of the four lanes. A zero count is the
// identity: a 32-bit shift of the full width contributes nothing.
fn rotate_halves(mut lanes [4]u64, count int) {
	if count == 0 {
		return
	}
	for lane in 0 .. 4 {
		lo := u32(lanes[lane])
		hi := u32(lanes[lane] >> 32)
		nlo := (lo << count) | (lo >> (32 - count))
		nhi := (hi << count) | (hi >> (32 - count))
		lanes[lane] = u64(nlo) | (u64(nhi) << 32)
	}
}

fn unordered_tail(tail []u8) u64 {
	if tail.len == 0 {
		return 0
	}
	idx1 := tail.len >> 1
	idx2 := tail.len - 1
	return u64(tail[0]) + (u64(tail[idx1]) << 8) + (u64(tail[idx2]) << 16)
}

// update_remainder pads a short tail so two messages with the same aligned
// prefix and different lengths cannot collide. `rest` is shorter than a packet.
fn (mut h Highway) update_remainder(rest []u8) {
	size := rest.len
	mod_pair := (u64(size) << 32) + u64(size)
	for lane in 0 .. 4 {
		h.v0[lane] += mod_pair
	}
	rotate_halves(mut h.v1, size)
	mut packet := [32]u8{}
	aligned := size & ~3
	for i in 0 .. aligned {
		packet[i] = rest[i]
	}
	if size & 16 != 0 {
		start := size - 4
		packet[28] = rest[start]
		packet[29] = rest[start + 1]
		packet[30] = rest[start + 2]
		packet[31] = rest[start + 3]
	} else {
		last := unordered_tail(rest[aligned..])
		for i in 0 .. 8 {
			packet[16 + i] = u8(last >> (i * 8))
		}
	}
	h.update_packet(packet[..])
}

fn (mut h Highway) permute_and_update() {
	mut permuted := [4]u64{}
	permuted[0] = rot64_by_32(h.v0[2])
	permuted[1] = rot64_by_32(h.v0[3])
	permuted[2] = rot64_by_32(h.v0[0])
	permuted[3] = rot64_by_32(h.v0[1])
	h.update_lanes(permuted)
}

fn shift128_left(hi u64, lo u64, bits int) (u64, u64) {
	return (hi << bits) | (lo >> (64 - bits)), lo << bits
}

fn modular_reduction(a3_unmasked u64, a2 u64, a1 u64, a0 u64) (u64, u64) {
	a3 := a3_unmasked & u64(0x3fffffffffffffff)
	s1_hi, s1_lo := shift128_left(a3, a2, 1)
	s2_hi, s2_lo := shift128_left(a3, a2, 2)
	return a1 ^ s1_hi ^ s2_hi, a0 ^ s1_lo ^ s2_lo
}

fn (mut h Highway) finalize64() u64 {
	for _ in 0 .. 4 {
		h.permute_and_update()
	}
	return h.v0[0] + h.v1[0] + h.mul0[0] + h.mul1[0]
}

fn (mut h Highway) finalize256() [4]u64 {
	for _ in 0 .. 10 {
		h.permute_and_update()
	}
	mut out := [4]u64{}
	out[1], out[0] = modular_reduction(h.v1[1] + h.mul1[1], h.v1[0] + h.mul1[0], h.v0[1] + h.mul0[1],
		h.v0[0] + h.mul0[0])
	out[3], out[2] = modular_reduction(h.v1[3] + h.mul1[3], h.v1[2] + h.mul1[2], h.v0[3] + h.mul0[3],
		h.v0[2] + h.mul0[2])
	return out
}

fn (mut h Highway) absorb(data []u8) {
	mut offset := 0
	for offset + 32 <= data.len {
		h.update_packet(data[offset..offset + 32])
		offset += 32
	}
	// A multiple of the packet, including the empty message, finalises as-is.
	// Only a short tail is length-padded.
	if offset < data.len {
		h.update_remainder(data[offset..])
	}
}

// highway64 is the 64-bit HighwayHash of data under key. Tests use it to pin
// the portable compression function against the published vectors.
fn highway64(key [4]u64, data []u8) u64 {
	mut state := Highway{}
	state.reset(key)
	state.absorb(data)
	return state.finalize64()
}

// highway256 is the 32-byte HighwayHash stored in a bitrot frame.
fn highway256(key [4]u64, data []u8) []u8 {
	mut state := Highway{}
	state.reset(key)
	state.absorb(data)
	lanes := state.finalize256()
	mut out := []u8{cap: 32}
	for lane in lanes {
		out << binary.little_endian_get_u64(lane)
	}
	return out
}
