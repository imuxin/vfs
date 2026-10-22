// field is GF(2^8) with the Rijndael polynomial 0x11d, the field Reed-Solomon
// codecs use. Multiplication is a pair of log table lookups, so encoding a
// shard is one pass over its bytes. The tables are built once.
module erasure

const poly = 0x11d

struct Tables {
	exp [512]u8
	log [256]u8
}

fn build() Tables {
	mut exp := [512]u8{}
	mut log := [256]u8{}
	mut x := 1
	for i in 0 .. 255 {
		exp[i] = u8(x)
		log[x] = u8(i)
		x <<= 1
		if x & 0x100 != 0 {
			x ^= poly
		}
	}
	for i in 255 .. 512 {
		exp[i] = exp[i - 255]
	}
	return Tables{
		exp: exp
		log: log
	}
}

const tables = build()

// mul multiplies two field elements.
fn mul(a u8, b u8) u8 {
	if a == 0 || b == 0 {
		return 0
	}
	return tables.exp[int(tables.log[a]) + int(tables.log[b])]
}

// div divides two field elements. The divisor must not be zero.
fn div(a u8, b u8) u8 {
	if a == 0 {
		return 0
	}
	return tables.exp[int(tables.log[a]) + 255 - int(tables.log[b])]
}

// inv returns the multiplicative inverse. Zero has none and stays zero.
fn inv(a u8) u8 {
	if a == 0 {
		return 0
	}
	return tables.exp[255 - int(tables.log[a])]
}
