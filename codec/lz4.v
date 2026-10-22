// lz4 is a block compressor in the LZ4 frame-less format: a token, literals,
// a little-endian distance, and a match. The last sequence is literals only,
// and a match never runs into the final five bytes, which is what a standard
// decoder requires.
module codec

const lz4_min_match = 4
const lz4_window = 65535

pub fn lz4_compress(src []u8) []u8 {
	if src.len < lz4_min_match + 5 {
		return lz4_literals(src)
	}
	mut out := []u8{}
	mut anchor := 0
	mut pos := 0
	mut table := map[u32]int{}
	limit := src.len - 5
	for pos < limit {
		word := u32(src[pos]) | (u32(src[pos + 1]) << 8) | (u32(src[pos + 2]) << 16) | (u32(src[pos + 3]) << 24)
		candidate := table[word] or { -1 }
		table[word] = pos
		if candidate < 0 || pos - candidate > lz4_window || pos - candidate == 0 {
			pos++
			continue
		}
		mut length := 0
		for pos + length < limit && src[candidate + length] == src[pos + length] {
			length++
		}
		if length < lz4_min_match {
			pos++
			continue
		}
		out << lz4_sequence(src[anchor..pos], pos - candidate, length)
		pos += length
		anchor = pos
	}
	out << lz4_literals(src[anchor..])
	return out
}

pub fn lz4_decompress(src []u8) ![]u8 {
	mut out := []u8{}
	mut i := 0
	for i < src.len {
		token := src[i]
		i++
		mut lit := int(token >> 4)
		if lit == 15 {
			for {
				if i >= src.len {
					return error('lz4 literal length is truncated')
				}
				extra := int(src[i])
				i++
				lit += extra
				if extra != 255 {
					break
				}
			}
		}
		if i + lit > src.len {
			return error('lz4 literals are truncated')
		}
		out << src[i..i + lit]
		i += lit
		if i == src.len {
			return out
		}
		if i + 2 > src.len {
			return error('lz4 match is truncated')
		}
		offset := int(src[i]) | (int(src[i + 1]) << 8)
		i += 2
		if offset == 0 || offset > out.len {
			return error('lz4 match points outside the output')
		}
		mut match_len := int(token & 0x0f) + lz4_min_match
		if token & 0x0f == 15 {
			for {
				if i >= src.len {
					return error('lz4 match length is truncated')
				}
				extra := int(src[i])
				i++
				match_len += extra
				if extra != 255 {
					break
				}
			}
		}
		start := out.len - offset
		for _ in 0 .. match_len {
			out << out[start + (out.len - start) % offset]
		}
	}
	return out
}

fn lz4_literals(literals []u8) []u8 {
	return lz4_sequence(literals, 0, 0)
}

fn lz4_sequence(literals []u8, distance int, match_len int) []u8 {
	mut out := []u8{}
	mut lit := literals.len
	mut token_lit := lit
	if token_lit > 15 {
		token_lit = 15
	}
	extra_match := if match_len == 0 { 0 } else { match_len - lz4_min_match }
	mut token_match := extra_match
	if token_match > 15 {
		token_match = 15
	}
	out << u8((token_lit << 4) | token_match)
	lit -= token_lit
	for lit >= 255 {
		out << u8(255)
		lit -= 255
	}
	if literals.len >= 15 {
		out << u8(lit)
	}
	out << literals
	if match_len == 0 {
		return out
	}
	out << u8(distance)
	out << u8(distance >> 8)
	extra := extra_match - token_match
	mut left := extra
	for left >= 255 {
		out << u8(255)
		left -= 255
	}
	if extra_match >= 15 {
		out << u8(left)
	}
	return out
}
