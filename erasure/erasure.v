// erasure splits an object into data shards and rebuilds it when disks are
// missing. The code is XOR parity: one parity shard recovers any single
// missing shard, which is the layout RustFS uses for two to three drives and
// for REDUCED_REDUNDANCY. A parity count of zero stores the bytes verbatim,
// matching the single-drive deployment.
module erasure

import crypto.sha256

// Layout is the shard geometry of one object.
pub struct Layout {
pub:
	data_shards   int
	parity_shards int
}

pub fn (l Layout) total() int {
	return l.data_shards + l.parity_shards
}

// plan picks the geometry RustFS derives from the drive count: no parity on
// one drive, one parity shard on two or three, two on four or five, three on
// six or seven, and four after that. A single parity shard is plain XOR; wider
// sets use Reed-Solomon.
pub fn plan(drives int) !Layout {
	if drives <= 0 {
		return error('a set needs at least one drive')
	}
	if drives == 1 {
		return Layout{
			data_shards:   1
			parity_shards: 0
		}
	}
	parity := match true {
		drives <= 3 { 1 }
		drives <= 5 { 2 }
		drives <= 7 { 3 }
		else { 4 }
	}
	if drives > 16 {
		return error('an erasure set holds at most 16 drives')
	}
	return Layout{
		data_shards:   drives - parity
		parity_shards: parity
	}
}

// Shard is one drive's slice of an object plus the digest that guards it.
pub struct Shard {
pub:
	index  int
	data   []u8
	digest []u8
}

fn pad(data []u8, parts int) ([]u8, int) {
	rem := data.len % parts
	if rem == 0 {
		return data.clone(), 0
	}
	need := parts - rem
	mut out := []u8{cap: data.len + need}
	out << data
	for _ in 0 .. need {
		out << u8(0)
	}
	return out, need
}

fn digest_of(data []u8) []u8 {
	return sha256.sum256(data)
}

// encode splits data into the layout's shards. The returned slice is indexed
// by drive.
pub fn encode(layout Layout, data []u8) ![]Shard {
	if layout.data_shards <= 0 {
		return error('data shard count must be positive')
	}
	if layout.parity_shards > 1 {
		return encode_wide(layout, data)
	}
	mut shards := []Shard{cap: layout.total()}
	if layout.parity_shards == 0 {
		digest := digest_of(data)
		shards << Shard{
			index:  0
			data:   data.clone()
			digest: digest
		}
		return shards
	}
	padded, _ := pad(data, layout.data_shards)
	width := padded.len / layout.data_shards
	mut parity := []u8{len: width}
	for part in 0 .. layout.data_shards {
		chunk := padded[part * width..(part + 1) * width].clone()
		for i in 0 .. width {
			parity[i] ^= chunk[i]
		}
		shards << Shard{
			index:  part
			data:   chunk
			digest: digest_of(chunk)
		}
	}
	shards << Shard{
		index:  layout.data_shards
		data:   parity
		digest: digest_of(parity)
	}
	return shards
}

// decode rebuilds the original bytes from whichever shards survived. A nil
// entry means that drive is missing. size is the unpadded object length.
pub fn decode(layout Layout, shards []?Shard, size int) ![]u8 {
	if layout.parity_shards > 1 {
		return decode_wide(layout, shards, size)
	}
	if layout.parity_shards == 0 {
		only := shards[0] or { return error('the only shard is missing') }
		if only.data.len < size {
			return error('shard shorter than object')
		}
		return only.data[..size].clone()
	}
	width := if size == 0 { 0 } else { shard_width(shards) }
	mut parts := [][]u8{len: layout.data_shards}
	mut missing := -1
	for part in 0 .. layout.data_shards {
		if got := shards[part] {
			parts[part] = got.data.clone()
		} else {
			if missing != -1 {
				return error('more than one shard is missing')
			}
			missing = part
		}
	}
	if missing != -1 {
		parity := shards[layout.data_shards] or { return error('missing data shard and its parity') }
		mut rebuilt := parity.data.clone()
		for part in 0 .. layout.data_shards {
			if part == missing {
				continue
			}
			for i in 0 .. width {
				rebuilt[i] ^= parts[part][i]
			}
		}
		parts[missing] = rebuilt
	}
	mut out := []u8{cap: size}
	for part in parts {
		out << part
	}
	if out.len < size {
		return error('reconstructed object is short')
	}
	return out[..size].clone()
}

fn shard_width(shards []?Shard) int {
	for got in shards {
		if s := got {
			return s.data.len
		}
	}
	return 0
}

// verify reports whether a shard's stored digest matches its bytes.
pub fn verify(shard Shard) bool {
	return subtle_eq(digest_of(shard.data), shard.digest)
}

// encode_wide handles sets with more than one parity shard, where XOR no
// longer suffices and the bytes go through Reed-Solomon.
fn encode_wide(layout Layout, data []u8) ![]Shard {
	parts := encode_rs(layout.data_shards, layout.parity_shards, data)!
	mut shards := []Shard{cap: parts.len}
	for index, part in parts {
		shards << Shard{
			index:  index
			data:   part
			digest: digest_of(part)
		}
	}
	return shards
}

fn decode_wide(layout Layout, shards []?Shard, size int) ![]u8 {
	mut parts := []?[]u8{len: layout.total()}
	for index in 0 .. layout.total() {
		if got := shards[index] {
			parts[index] = got.data.clone()
		}
	}
	return decode_rs(layout.data_shards, layout.parity_shards, parts, size)
}

fn subtle_eq(a []u8, b []u8) bool {
	if a.len != b.len {
		return false
	}
	mut diff := u8(0)
	for i in 0 .. a.len {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}
