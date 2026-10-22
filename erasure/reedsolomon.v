// reedsolomon encodes across any number of parity shards, which is what an
// erasure set wider than three drives needs. The code is systematic: the first
// data_shards outputs are the input bytes unchanged, and the rest are parity,
// so a read that loses nothing touches no field arithmetic at all.
module erasure

// encode_rs splits data into data_shards plus parity_shards. The input is
// padded to a multiple of data_shards with zeros; the caller trims on decode.
fn encode_rs(data_shards int, parity_shards int, data []u8) ![][]u8 {
	if data_shards <= 0 || parity_shards <= 0 {
		return error('shard counts must be positive')
	}
	if data_shards + parity_shards > 255 {
		return error('a reed-solomon code holds at most 255 shards')
	}
	padded := padded_to(data, data_shards)
	width := padded.len / data_shards
	mut shards := [][]u8{cap: data_shards + parity_shards}
	for part in 0 .. data_shards {
		shards << padded[part * width..(part + 1) * width].clone()
	}
	matrix := vandermonde(data_shards, parity_shards)
	invert := invert_matrix(matrix[..data_shards].clone())!
	gen := mul_matrix(matrix, invert)
	for row in data_shards .. data_shards + parity_shards {
		shards << parity_row(gen[row], shards[..data_shards])
	}
	return shards
}

// decode_rs rebuilds the original bytes from whichever shards survived. A nil
// entry is a missing shard. present lists the shard indexes that are there.
fn decode_rs(data_shards int, parity_shards int, shards []?[]u8, size int) ![]u8 {
	width := shard_len(shards)
	mut have := []int{}
	mut missing := []int{}
	for index in 0 .. data_shards {
		if shards[index] != none {
			have << index
		} else {
			missing << index
		}
	}
	mut out := [][]u8{len: data_shards, init: []u8{len: width}}
	for index in have {
		got := shards[index] or { []u8{} }
		out[index] = got.clone()
	}
	if missing.len == 0 {
		return join_shards(out, size)
	}
	mut parity := []int{}
	for index in data_shards .. data_shards + parity_shards {
		if shards[index] != none {
			parity << index
		}
	}
	if parity.len < missing.len {
		return error('not enough shards to rebuild')
	}
	used := parity[..missing.len]
	rebuilt := rebuild(data_shards, parity_shards, have, missing, used, shards)!
	for i, index in missing {
		out[index] = rebuilt[i]
	}
	return join_shards(out, size)
}

// rebuild recovers the missing data shards from the parity that survived.
fn rebuild(data_shards int, parity_shards int, have []int, missing []int, parity []int, shards []?[]u8) ![][]u8 {
	matrix := vandermonde(data_shards, parity_shards)
	mut rows := [][]u8{}
	mut known := [][]u8{}
	for index in have {
		rows << matrix[index].clone()
		got := shards[index] or { []u8{} }
		known << got.clone()
	}
	for index in parity {
		rows << matrix[index].clone()
		got := shards[index] or { []u8{} }
		known << got.clone()
	}
	decoder := invert_matrix(rows)!
	width := shard_len(shards)
	mut data := [][]u8{len: data_shards, init: []u8{len: width}}
	for col in 0 .. width {
		for row in 0 .. data_shards {
			mut acc := u8(0)
			for k in 0 .. known.len {
				acc ^= mul(decoder[row][k], known[k][col])
			}
			data[row][col] = acc
		}
	}
	mut recovered := [][]u8{cap: missing.len}
	for index in missing {
		recovered << data[index].clone()
	}
	return recovered
}

fn padded_to(data []u8, parts int) []u8 {
	rem := data.len % parts
	if rem == 0 {
		return data.clone()
	}
	mut out := []u8{cap: data.len + parts - rem}
	out << data
	for _ in 0 .. parts - rem {
		out << u8(0)
	}
	return out
}

fn shard_len(shards []?[]u8) int {
	for got in shards {
		if s := got {
			return s.len
		}
	}
	return 0
}

fn join_shards(shards [][]u8, size int) ![]u8 {
	mut out := []u8{cap: size}
	for shard in shards {
		out << shard
	}
	if out.len < size {
		return error('reconstructed object is short')
	}
	return out[..size].clone()
}

fn parity_row(coeff []u8, data [][]u8) []u8 {
	width := data[0].len
	mut out := []u8{len: width}
	for col in 0 .. width {
		mut acc := u8(0)
		for row in 0 .. data.len {
			acc ^= mul(coeff[row], data[row][col])
		}
		out[col] = acc
	}
	return out
}

// vandermonde builds the coding matrix: an identity on top, so the code is
// systematic, over a Vandermonde parity block.
fn vandermonde(data_shards int, parity_shards int) [][]u8 {
	total := data_shards + parity_shards
	mut m := [][]u8{len: total, init: []u8{len: data_shards}}
	for row in 0 .. data_shards {
		m[row][row] = 1
	}
	for row in 0 .. parity_shards {
		mut power := u8(1)
		base := u8(row + 1)
		for col in 0 .. data_shards {
			m[data_shards + row][col] = power
			power = mul(power, base)
		}
	}
	return m
}

fn mul_matrix(a [][]u8, b [][]u8) [][]u8 {
	mut out := [][]u8{len: a.len, init: []u8{len: b[0].len}}
	for row in 0 .. a.len {
		for col in 0 .. b[0].len {
			mut acc := u8(0)
			for k in 0 .. b.len {
				acc ^= mul(a[row][k], b[k][col])
			}
			out[row][col] = acc
		}
	}
	return out
}

// invert_matrix inverts a square matrix by Gauss-Jordan elimination.
fn invert_matrix(matrix [][]u8) ![][]u8 {
	n := matrix.len
	mut m := [][]u8{len: n, init: []u8{len: n * 2}}
	for row in 0 .. n {
		for col in 0 .. n {
			m[row][col] = matrix[row][col]
		}
		m[row][n + row] = 1
	}
	for col in 0 .. n {
		pivot := pivot_row(m, col) or { return error('coding matrix is singular') }
		swap_rows(mut m, col, pivot)
		factor := inv(m[col][col])
		scale_row(mut m, col, factor)
		for row in 0 .. n {
			if row == col {
				continue
			}
			eliminate(mut m, row, col)
		}
	}
	mut out := [][]u8{len: n, init: []u8{len: n}}
	for row in 0 .. n {
		for col in 0 .. n {
			out[row][col] = m[row][n + col]
		}
	}
	return out
}

fn pivot_row(m [][]u8, col int) ?int {
	for row in col .. m.len {
		if m[row][col] != 0 {
			return row
		}
	}
	return none
}

fn swap_rows(mut m [][]u8, a int, b int) {
	if a != b {
		m[a], m[b] = m[b], m[a]
	}
}

fn scale_row(mut m [][]u8, row int, factor u8) {
	for col in 0 .. m[row].len {
		m[row][col] = mul(m[row][col], factor)
	}
}

fn eliminate(mut m [][]u8, row int, col int) {
	factor := m[row][col]
	if factor == 0 {
		return
	}
	for c in 0 .. m[row].len {
		m[row][c] ^= mul(factor, m[col][c])
	}
}
