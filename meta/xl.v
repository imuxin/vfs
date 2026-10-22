// xl reads an unencrypted MinIO xl.meta. The header is `XL2 ` plus a version
// byte from 1 to 3, then MessagePack. Encrypted objects are refused.
module meta

pub struct XlVersion {
pub:
	id            string
	delete_marker bool
	free          bool
	data          []u8
	size          i64
}

pub struct XlMeta {
pub:
	header_ver int
	meta_ver   int
	versions   []XlVersion
}

pub fn write_xl(doc XlMeta) ![]u8 {
	if doc.header_ver < 1 || doc.header_ver > 3 {
		return error('xl header version must be 1, 2, or 3')
	}
	if doc.meta_ver < 1 || doc.meta_ver > 3 {
		return error('xl meta_ver must be 1, 2, or 3')
	}
	mut body := []u8{}
	body << `X`
	body << `L`
	body << `2`
	body << ` `
	body << u8(doc.header_ver)
	write_map(mut body, 3)
	write_str(mut body, 'meta_ver')
	write_int(mut body, i64(doc.meta_ver))
	write_str(mut body, 'versions')
	write_array(mut body, doc.versions.len)
	for version in doc.versions {
		write_map(mut body, 5)
		write_str(mut body, 'id')
		write_str(mut body, version.id)
		write_str(mut body, 'delete')
		write_bool(mut body, version.delete_marker)
		write_str(mut body, 'free')
		write_bool(mut body, version.free)
		write_str(mut body, 'size')
		write_int(mut body, if version.size > 0 { version.size } else { i64(version.data.len) })
		write_str(mut body, 'data')
		write_bin(mut body, version.data)
	}
	write_str(mut body, 'encrypted')
	write_bool(mut body, false)
	return body
}

pub fn read_xl(data []u8) !XlMeta {
	if data.len < 5 || data[..4].bytestr() != 'XL2 ' {
		return error('xl.meta header is missing')
	}
	header_ver := int(data[4])
	if header_ver < 1 || header_ver > 3 {
		return error('xl header version must be 1, 2, or 3')
	}
	mut cur := Cursor{
		data: data
		pos:  5
	}
	count := cur.map_len()!
	mut doc := XlMeta{
		header_ver: header_ver
	}
	for _ in 0 .. count {
		key := cur.text()!
		match key {
			'meta_ver' { doc = XlMeta{ header_ver: doc.header_ver, meta_ver: int(cur.integer()!), versions: doc.versions } }
			'versions' { doc = XlMeta{ header_ver: doc.header_ver, meta_ver: doc.meta_ver, versions: cur.versions()! } }
			'encrypted' {
				if cur.boolean()! {
					return error('invalid minio object: encrypted objects are not read')
				}
			}
			'kes' {
				text := cur.text() or {
					cur.skip()!
					return error('invalid minio object: encrypted objects are not read')
				}
				if text.len > 0 {
					return error('invalid minio object: encrypted objects are not read')
				}
			}
			else { cur.skip()! }
		}
	}
	if doc.meta_ver < 1 || doc.meta_ver > 3 {
		return error('xl meta_ver must be 1, 2, or 3')
	}
	return doc
}

pub fn (m XlMeta) latest() !XlVersion {
	mut index := m.versions.len - 1
	for index >= 0 {
		version := m.versions[index]
		if !version.free {
			return version
		}
		index--
	}
	return error('object not found')
}

struct Cursor {
mut:
	data []u8
	pos  int
}

fn (mut c Cursor) versions() ![]XlVersion {
	count := c.array_len()!
	mut out := []XlVersion{}
	for _ in 0 .. count {
		fields := c.map_len()!
		mut version := XlVersion{}
		for _ in 0 .. fields {
			key := c.text()!
			match key {
				'id' { version = XlVersion{ id: c.text()!, delete_marker: version.delete_marker, free: version.free, data: version.data, size: version.size } }
				'delete' { version = XlVersion{ id: version.id, delete_marker: c.boolean()!, free: version.free, data: version.data, size: version.size } }
				'free' { version = XlVersion{ id: version.id, delete_marker: version.delete_marker, free: c.boolean()!, data: version.data, size: version.size } }
				'size' { version = XlVersion{ id: version.id, delete_marker: version.delete_marker, free: version.free, data: version.data, size: c.integer()! } }
				'data' { version = XlVersion{ id: version.id, delete_marker: version.delete_marker, free: version.free, data: c.bin()!, size: version.size } }
				else { c.skip()! }
			}
		}
		out << version
	}
	return out
}

fn (mut c Cursor) map_len() !int {
	tag := c.byte()!
	if tag >= 0x80 && tag <= 0x8f {
		return int(tag & 0x0f)
	}
	if tag == 0xde {
		return c.be16()!
	}
	return error('xl map is invalid')
}

fn (mut c Cursor) array_len() !int {
	tag := c.byte()!
	if tag >= 0x90 && tag <= 0x9f {
		return int(tag & 0x0f)
	}
	if tag == 0xdc {
		return c.be16()!
	}
	return error('xl array is invalid')
}

fn (mut c Cursor) text() !string {
	tag := c.byte()!
	mut n := 0
	if tag >= 0xa0 && tag <= 0xbf {
		n = int(tag & 0x1f)
	} else if tag == 0xd9 {
		n = int(c.byte()!)
	} else if tag == 0xda {
		n = c.be16()!
	} else {
		return error('xl string is invalid')
	}
	return c.take(n)!.bytestr()
}

fn (mut c Cursor) bin() ![]u8 {
	tag := c.byte()!
	mut n := 0
	if tag == 0xc4 {
		n = int(c.byte()!)
	} else if tag == 0xc5 {
		n = c.be16()!
	} else {
		return error('xl binary is invalid')
	}
	return c.take(n)!
}

fn (mut c Cursor) boolean() !bool {
	tag := c.byte()!
	if tag == 0xc2 {
		return false
	}
	if tag == 0xc3 {
		return true
	}
	return error('xl bool is invalid')
}

fn (mut c Cursor) integer() !i64 {
	tag := c.byte()!
	if tag <= 0x7f {
		return i64(tag)
	}
	if tag >= 0xe0 {
		return i64(i8(tag))
	}
	match tag {
		0xcc { return i64(c.byte()!) }
		0xcd { return i64(c.be16()!) }
		0xce { return i64(c.be32()!) }
		0xd0 { return i64(i8(c.byte()!)) }
		0xd1 { return i64(i16(c.be16()!)) }
		0xd2 { return i64(int(c.be32()!)) }
		else { return error('xl integer is invalid') }
	}
}

fn (mut c Cursor) skip() ! {
	tag := c.byte()!
	if tag <= 0x7f || tag >= 0xe0 || tag == 0xc0 || tag == 0xc2 || tag == 0xc3 {
		return
	}
	if (tag >= 0xa0 && tag <= 0xbf) || tag == 0xd9 || tag == 0xda || tag == 0xc4 || tag == 0xc5
		|| tag == 0xcc || tag == 0xcd || tag == 0xce || tag == 0xd0 || tag == 0xd1 || tag == 0xd2 {
		c.pos--
		if tag == 0xc4 || tag == 0xc5 || (tag >= 0xa0 && tag <= 0xbf) || tag == 0xd9 || tag == 0xda {
			if tag == 0xc4 || tag == 0xc5 {
				_ = c.bin()!
			} else {
				_ = c.text()!
			}
			return
		}
		_ = c.integer()!
		return
	}
	if (tag >= 0x80 && tag <= 0x8f) || tag == 0xde {
		c.pos--
		n := c.map_len()!
		for _ in 0 .. n {
			_ = c.text()!
			c.skip()!
		}
		return
	}
	if (tag >= 0x90 && tag <= 0x9f) || tag == 0xdc {
		c.pos--
		n := c.array_len()!
		for _ in 0 .. n {
			c.skip()!
		}
		return
	}
	return error('xl value is not supported')
}

fn (mut c Cursor) byte() !u8 {
	if c.pos >= c.data.len {
		return error('xl.meta is truncated')
	}
	raw := c.data[c.pos]
	c.pos++
	return raw
}

fn (mut c Cursor) take(n int) ![]u8 {
	if n < 0 || c.pos + n > c.data.len {
		return error('xl.meta is truncated')
	}
	out := c.data[c.pos..c.pos + n].clone()
	c.pos += n
	return out
}

fn (mut c Cursor) be16() !int {
	hi := c.byte()!
	lo := c.byte()!
	return int(hi) << 8 | int(lo)
}

fn (mut c Cursor) be32() !u32 {
	b0 := u32(c.byte()!)
	b1 := u32(c.byte()!)
	b2 := u32(c.byte()!)
	b3 := u32(c.byte()!)
	return (b0 << 24) | (b1 << 16) | (b2 << 8) | b3
}

fn write_map(mut body []u8, n int) {
	body << u8(0x80 | n)
}

fn write_array(mut body []u8, n int) {
	body << u8(0x90 | n)
}

fn write_str(mut body []u8, text string) {
	if text.len < 32 {
		body << u8(0xa0 | text.len)
	} else {
		body << u8(0xd9)
		body << u8(text.len)
	}
	body << text.bytes()
}

fn write_bool(mut body []u8, value bool) {
	if value {
		body << u8(0xc3)
	} else {
		body << u8(0xc2)
	}
}

fn write_int(mut body []u8, value i64) {
	if value >= 0 && value <= 0x7f {
		body << u8(value)
		return
	}
	body << u8(0xce)
	raw := u32(value)
	body << u8(raw >> 24)
	body << u8(raw >> 16)
	body << u8(raw >> 8)
	body << u8(raw)
}

fn write_bin(mut body []u8, data []u8) {
	if data.len <= 255 {
		body << u8(0xc4)
		body << u8(data.len)
	} else {
		body << u8(0xc5)
		body << u8(data.len >> 8)
		body << u8(data.len)
	}
	body << data
}
