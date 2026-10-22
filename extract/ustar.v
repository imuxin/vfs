// ustar reads the tar members of a snowball upload. Each regular file becomes
// one object key. Directory entries, links, and paths that leave the bucket
// are not objects.
module extract

pub struct Member {
pub:
	key  string
	data []u8
}

// members returns the regular files in a ustar archive. The archive must be a
// whole number of 512-byte blocks and each header checksum must match.
pub fn members(archive []u8) ![]Member {
	if archive.len < 512 || archive.len % 512 != 0 {
		return error('invalid archive')
	}
	mut found := []Member{}
	mut offset := 0
	mut long_name := ''
	for offset+512 <= archive.len {
		header := archive[offset..offset + 512]
		offset += 512
		if zero_block(header) {
			break
		}
		if !checksum_ok(header) {
			return error('invalid archive')
		}
		size := octal(header[124..136])
		if size < 0 || offset + size > archive.len {
			return error('invalid archive')
		}
		payload := archive[offset..offset + size].clone()
		offset += ((size + 511) / 512) * 512
		kind := header[156]
		raw_name := if long_name.len > 0 {
			long_name
		} else {
			join_name(cstr(header[345..500]), cstr(header[0..100]))
		}
		long_name = ''
		if kind == `L` {
			long_name = payload.bytestr().trim_right('\0')
			continue
		}
		if kind == `5` || raw_name.ends_with('/') {
			continue
		}
		if kind != `0` && kind != 0 {
			continue
		}
		found << Member{
			key:  object_key(raw_name)!
			data: payload
		}
	}
	return found
}

// pack writes one ustar archive. It is the inverse of members for regular files.
pub fn pack(files []Member) []u8 {
	mut out := []u8{}
	for file in files {
		out << header_block(file.key, file.data.len)
		out << file.data
		pad := (512 - (file.data.len % 512)) % 512
		if pad > 0 {
			out << []u8{len: pad}
		}
	}
	out << []u8{len: 1024}
	return out
}

fn object_key(raw string) !string {
	if raw.starts_with('/') || raw.starts_with('\\') {
		return error('invalid archive entry path')
	}
	mut parts := []string{}
	for part in raw.replace('\\', '/').split('/') {
		if part.len == 0 || part == '.' {
			continue
		}
		if part == '..' {
			return error('invalid archive entry path')
		}
		parts << part
	}
	if parts.len == 0 {
		return error('invalid archive entry path')
	}
	return parts.join('/')
}

fn join_name(prefix string, name string) string {
	if prefix.len == 0 {
		return name
	}
	return '${prefix}/${name}'
}

fn cstr(field []u8) string {
	mut end := 0
	for end < field.len && field[end] != 0 {
		end++
	}
	return field[..end].bytestr()
}

fn octal(field []u8) int {
	mut n := 0
	for b in field {
		if b == 0 || b == ` ` {
			if n > 0 {
				break
			}
			continue
		}
		if b < `0` || b > `7` {
			break
		}
		n = n * 8 + int(b - `0`)
	}
	return n
}

fn checksum_ok(header []u8) bool {
	mut sum := 0
	for i, b in header {
		if i >= 148 && i < 156 {
			sum += 32
		} else {
			sum += int(b)
		}
	}
	return octal(header[148..156]) == sum
}

fn zero_block(header []u8) bool {
	for b in header {
		if b != 0 {
			return false
		}
	}
	return true
}

fn header_block(name string, size int) []u8 {
	mut block := []u8{len: 512}
	name_bytes := name.bytes()
	for i, b in name_bytes {
		if i >= 100 {
			break
		}
		block[i] = b
	}
	size_field := '${size:011o}\u0000'.bytes()
	for i, b in size_field {
		block[124 + i] = b
	}
	block[156] = `0`
	for i in 148 .. 156 {
		block[i] = ` `
	}
	mut sum := 0
	for b in block {
		sum += int(b)
	}
	check := '${sum:06o}\u0000 '.bytes()
	for i, b in check {
		block[148 + i] = b
	}
	return block
}
