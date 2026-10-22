// codec compresses an object before it is sealed. Each algorithm is a whole
// block inside a small frame, so a range read decompresses only the blocks the
// range touches instead of the entire object.
module codec

import compress.brotli
import compress.deflate
import compress.gzip
import compress.snappy
import compress.zstd
import encoding.binary

const frame_magic = [u8(`V`), `F`, `S`, `C`]
const frame_block = 64 * 1024

// Algo is one on-disk compressor. none stores the bytes unchanged and writes
// no frame.
pub enum Algo {
	none
	lz4
	gzip
	deflate
	zstd
	brotli
	snappy
}

pub fn parse(name string) !Algo {
	return match name {
		'', 'none' { Algo.none }
		'lz4' { Algo.lz4 }
		'gzip' { Algo.gzip }
		'deflate' { Algo.deflate }
		'zstd' { Algo.zstd }
		'brotli' { Algo.brotli }
		'snappy' { Algo.snappy }
		else { error('unknown compression algorithm: ${name}') }
	}
}

pub fn (a Algo) str() string {
	return match a {
		.none { '' }
		.lz4 { 'lz4' }
		.gzip { 'gzip' }
		.deflate { 'deflate' }
		.zstd { 'zstd' }
		.brotli { 'brotli' }
		.snappy { 'snappy' }
	}
}

// frame compresses data in independent blocks. An empty algorithm returns the
// input, so callers can put the result straight into the write pipeline.
pub fn frame(algo Algo, data []u8) ![]u8 {
	if algo == .none {
		return data.clone()
	}
	mut out := []u8{}
	for magic in frame_magic {
		out << magic
	}
	out << u8(int(algo))
	mut offset := 0
	for offset < data.len {
		end := if offset + frame_block < data.len { offset + frame_block } else { data.len }
		raw := data[offset..end]
		compressed := compress_block(algo, raw)!
		out << binary.little_endian_get_u32(u32(raw.len))
		out << binary.little_endian_get_u32(u32(compressed.len))
		out << compressed
		offset = end
	}
	out << binary.little_endian_get_u32(0)
	out << binary.little_endian_get_u32(0)
	return out
}

// unframe restores bytes written by frame.
pub fn unframe(algo Algo, framed []u8) ![]u8 {
	if algo == .none {
		return framed.clone()
	}
	mut out := []u8{}
	mut offset := 0
	for {
		raw, comp, next := read_block(algo, framed, offset)!
		if raw.len == 0 && comp.len == 0 && next == offset {
			break
		}
		if raw.len == 0 && next < 0 {
			break
		}
		out << raw
		offset = next
		if next < 0 {
			break
		}
	}
	return out
}

// unframe_range restores the inclusive byte range. Blocks that sit completely
// outside the range are skipped, so a range at the end of a large object does
// not decompress the head.
pub fn unframe_range(algo Algo, framed []u8, start i64, end i64) ![]u8 {
	if algo == .none {
		if start < 0 || start >= framed.len {
			return error('invalid range')
		}
		last := if end < 0 || end >= framed.len { framed.len - 1 } else { int(end) }
		if last < int(start) {
			return error('invalid range')
		}
		return framed[int(start)..last + 1].clone()
	}
	if framed.len < 5 {
		return error('compression frame is missing its header')
	}
	mut out := []u8{}
	mut offset := 0
	mut raw_at := i64(0)
	mut produced := false
	for {
		raw, _, next := read_block(algo, framed, offset)!
		if next < 0 {
			break
		}
		block_end := raw_at + i64(raw.len)
		if block_end > start && raw_at <= end {
			from := if start > raw_at { int(start - raw_at) } else { 0 }
			last := if end < block_end { int(end - raw_at) } else { raw.len - 1 }
			if last >= from {
				out << raw[from..last + 1]
				produced = true
			}
		}
		raw_at = block_end
		offset = next
		if raw_at > end && produced {
			break
		}
	}
	if !produced {
		return error('invalid range')
	}
	return out
}

struct Block {
	raw  []u8
	comp []u8
	next int
}

fn read_block(algo Algo, framed []u8, offset int) !([]u8, []u8, int) {
	if offset == 0 {
		if framed.len < 6 || framed[0] != frame_magic[0] || framed[1] != frame_magic[1]
			|| framed[2] != frame_magic[2] || framed[3] != frame_magic[3] {
			return error('compression frame is missing its header')
		}
		if int(framed[4]) != int(algo) {
			return error('compression frame names a different algorithm')
		}
		return read_block(algo, framed, 5)
	}
	if offset + 8 > framed.len {
		return error('compression frame is truncated')
	}
	raw_len := int(binary.little_endian_u32_at(framed, offset))
	comp_len := int(binary.little_endian_u32_at(framed, offset + 4))
	if raw_len == 0 && comp_len == 0 {
		return []u8{}, []u8{}, -1
	}
	start := offset + 8
	if start + comp_len > framed.len {
		return error('compression block is truncated')
	}
	comp := framed[start..start + comp_len].clone()
	raw := decompress_block(algo, comp, raw_len)!
	return raw, comp, start + comp_len
}

fn compress_block(algo Algo, raw []u8) ![]u8 {
	return match algo {
		.none { raw.clone() }
		.lz4 { lz4_compress(raw) }
		.gzip { gzip.compress(raw)! }
		.deflate { deflate.compress_raw(raw)! }
		.zstd { zstd.compress(raw)! }
		.brotli { brotli.compress(raw)! }
		.snappy { snappy.compress(raw) }
	}
}

fn decompress_block(algo Algo, comp []u8, raw_len int) ![]u8 {
	decoded := match algo {
		.none { comp.clone() }
		.lz4 { lz4_decompress(comp)! }
		.gzip { gzip.decompress(comp)! }
		.deflate { deflate.decompress_raw_with_consumed(comp)!.decoded }
		.zstd { zstd.decompress(comp)! }
		.brotli { brotli.decompress(comp)! }
		.snappy { snappy.decompress(comp)! }
	}
	if decoded.len != raw_len {
		return error('decompressed block has the wrong length')
	}
	return decoded
}
