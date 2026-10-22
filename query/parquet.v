// parquet reads and writes the uncompressed PLAIN subset S3 Select accepts:
// required byte-array columns, one row group, no compression. Other codecs
// are rejected.
module query

const magic = 'PAR1'

pub fn encode_parquet(columns [][]string) ![]u8 {
	if columns.len == 0 || columns[0].len == 0 {
		return error('parquet needs at least one value')
	}
	rows := columns[0].len
	for column in columns {
		if column.len != rows {
			return error('parquet columns must have the same length')
		}
	}
	mut pages := [][]u8{}
	mut plain_sizes := []int{}
	for column in columns {
		plain := plain_bytes(column)
		page := page_header(column.len, plain.len)
		mut full := page.clone()
		full << plain
		pages << full
		plain_sizes << plain.len
	}
	mut body := []u8{}
	body << magic.bytes()
	mut offsets := []int{}
	for page in pages {
		offsets << body.len
		body << page
	}
	meta := file_meta(columns, offsets, plain_sizes, rows)
	body << meta
	body << le32(u32(meta.len))
	body << magic.bytes()
	return body
}

pub fn parquet_rows(file []u8) ![][]string {
	if file.len < 12 || file[..4].bytestr() != magic || file[file.len - 4..].bytestr() != magic {
		return error('parquet magic is missing')
	}
	footer := int(u32(file[file.len - 8]) | (u32(file[file.len - 7]) << 8) | (u32(file[file.len - 6]) << 16) | (u32(file[file.len - 5]) << 24))
	start := file.len - 8 - footer
	if footer <= 0 || start < 4 {
		return error('parquet footer is truncated')
	}
	mut reader := Reader{
		data: file
	}
	reader.pos = start
	columns := read_meta(mut reader)!
	mut table := [][]string{}
	for column in columns {
		if column.codec != 0 {
			return error('compression combination is not supported')
		}
		if column.encoding != 0 {
			return error('parquet encoding is not supported')
		}
		table << read_page(file, column)!
	}
	return table
}

pub fn parquet_csv(file []u8) !string {
	table := parquet_rows(file)!
	if table.len == 0 {
		return ''
	}
	mut lines := []string{}
	for row in 0 .. table[0].len {
		mut fields := []string{}
		for column in table {
			fields << column[row]
		}
		lines << fields.join(',')
	}
	return lines.join('\n')
}

struct ColumnMeta {
mut:
	name     string
	codec    int
	encoding int
	offset   int
	values   int
}

struct Reader {
mut:
	data []u8
	pos  int
	last int
	stack []int
}

fn plain_bytes(values []string) []u8 {
	mut out := []u8{}
	for value in values {
		out << le32(u32(value.len))
		out << value.bytes()
	}
	return out
}

fn page_header(values int, plain_len int) []u8 {
	mut w := Writer{}
	w.i32_field(1, 0)
	w.i32_field(2, plain_len)
	w.i32_field(3, plain_len)
	w.begin(5)
	w.i32_field(1, values)
	w.i32_field(2, 0)
	w.i32_field(3, 0)
	w.i32_field(4, 0)
	w.end()
	w.end()
	return w.buf
}

fn file_meta(columns [][]string, offsets []int, plain_sizes []int, rows int) []u8 {
	mut w := Writer{}
	w.i32_field(1, 1)
	w.begin_list(2, 12, columns.len + 1)
	w.begin_struct()
		w.text_field(4, 'schema')
	w.i32_field(5, columns.len)
	w.end()
	for index, _ in columns {
		w.begin_struct()
		w.i32_field(1, 6)
		w.i32_field(3, 0)
		w.text_field(4, '_${index + 1}')
		w.end()
	}
	w.i64_field(3, i64(rows))
	w.begin_list(4, 12, 1)
	w.begin_struct()
	w.begin_list(1, 12, columns.len)
	for index, column in columns {
		w.begin_struct()
		w.i64_field(2, i64(offsets[index]))
		w.begin(3)
		w.i32_field(1, 6)
		w.begin_list(2, 5, 1)
		w.i32(0)
		w.begin_list(3, 8, 1)
		w.text('_${index + 1}')
		w.i32_field(4, 0)
		w.i64_field(5, i64(column.len))
		w.i64_field(6, i64(plain_sizes[index]))
		w.i64_field(7, i64(plain_sizes[index]))
		w.i64_field(9, i64(offsets[index]))
		w.end()
		w.end()
	}
	mut total := 0
	for size in plain_sizes {
		total += size
	}
	w.i64_field(2, i64(total))
	w.i64_field(3, i64(rows))
	w.end()
	w.text_field(6, 'vfs')
	w.end()
	return w.buf
}

struct Writer {
mut:
	buf   []u8
	last  int
	stack []int
}

fn (mut w Writer) begin(id int) {
	w.field(id, 12)
	w.stack << w.last
	w.last = 0
}

fn (mut w Writer) begin_struct() {
	w.stack << w.last
	w.last = 0
}

fn (mut w Writer) end() {
	w.buf << u8(0)
	if w.stack.len == 0 {
		w.last = 0
		return
	}
	w.last = w.stack[w.stack.len - 1]
	w.stack.delete_last()
}

fn (mut w Writer) field(id int, typ int) {
	delta := id - w.last
	if delta > 0 && delta < 16 {
		w.buf << u8((delta << 4) | typ)
	} else {
		w.buf << u8(typ)
		w.varint(zigzag(i64(id)))
	}
	w.last = id
}

fn (mut w Writer) i32_field(id int, value int) {
	w.field(id, 5)
	w.i32(value)
}

fn (mut w Writer) i64_field(id int, value i64) {
	w.field(id, 6)
	w.varint(zigzag(value))
}

fn (mut w Writer) text_field(id int, value string) {
	w.field(id, 8)
	w.text(value)
}

fn (mut w Writer) begin_list(id int, elem int, size int) {
	w.field(id, 9)
	if size < 15 {
		w.buf << u8((size << 4) | elem)
	} else {
		w.buf << u8(0xf0 | elem)
		w.varint(u64(size))
	}
}

fn (mut w Writer) i32(value int) {
	w.varint(zigzag(i64(value)))
}

fn (mut w Writer) text(value string) {
	w.varint(u64(value.len))
	w.buf << value.bytes()
}

fn (mut w Writer) varint(value u64) {
	mut rest := value
	for rest > 0x7f {
		w.buf << u8(rest & 0x7f) | 0x80
		rest >>= 7
	}
	w.buf << u8(rest)
}

fn read_meta(mut r Reader) ![]ColumnMeta {
	r.last = 0
	mut columns := []ColumnMeta{}
	for {
		id, typ := r.read_field()!
		if typ == 0 {
			break
		}
		if id == 4 && typ == 9 {
			groups := r.list_header()!
			if groups.elem != 12 {
				return error('parquet row group is not a struct')
			}
			for _ in 0 .. groups.size {
				columns = read_row_group(mut r)!
			}
			continue
		}
		r.skip(typ)!
	}
	if columns.len == 0 {
		return error('parquet has no columns')
	}
	return columns
}

fn read_row_group(mut r Reader) ![]ColumnMeta {
	r.push()
	mut columns := []ColumnMeta{}
	for {
		id, typ := r.read_field()!
		if typ == 0 {
			break
		}
		if id == 1 && typ == 9 {
			header := r.list_header()!
			for _ in 0 .. header.size {
				columns << read_chunk(mut r)!
			}
			continue
		}
		r.skip(typ)!
	}
	r.pop()
	return columns
}

fn read_chunk(mut r Reader) !ColumnMeta {
	r.push()
	mut column := ColumnMeta{}
	for {
		id, typ := r.read_field()!
		if typ == 0 {
			break
		}
		if id == 3 && typ == 12 {
			column = read_column_meta(mut r)!
			continue
		}
		r.skip(typ)!
	}
	r.pop()
	return column
}

fn read_column_meta(mut r Reader) !ColumnMeta {
	r.push()
	mut column := ColumnMeta{}
	for {
		id, typ := r.read_field()!
		if typ == 0 {
			break
		}
		if id == 2 && typ == 9 {
			header := r.list_header()!
			if header.size > 0 {
				column.encoding = int(r.zigzag()!)
				for _ in 1 .. header.size {
					r.skip(header.elem)!
				}
			}
			continue
		}
		if id == 3 && typ == 9 {
			header := r.list_header()!
			if header.size > 0 {
				column.name = r.binary()!
				for _ in 1 .. header.size {
					r.skip(header.elem)!
				}
			}
			continue
		}
		if id == 4 && typ == 5 {
			column.codec = int(r.zigzag()!)
			continue
		}
		if id == 5 && typ == 6 {
			column.values = int(r.zigzag()!)
			continue
		}
		if id == 9 && typ == 6 {
			column.offset = int(r.zigzag()!)
			continue
		}
		r.skip(typ)!
	}
	r.pop()
	return column
}

fn read_page(file []u8, column ColumnMeta) ![]string {
	if column.offset < 0 || column.offset >= file.len {
		return error('parquet page offset is outside the file')
	}
	mut r := Reader{
		data: file
		pos:  column.offset
	}
	r.push()
	for {
		_, typ := r.read_field()!
		if typ == 0 {
			break
		}
		r.skip(typ)!
	}
	mut out := []string{cap: column.values}
	for _ in 0 .. column.values {
		if r.pos + 4 > file.len {
			return error('parquet page is truncated')
		}
		n := int(u32(file[r.pos]) | (u32(file[r.pos + 1]) << 8) | (u32(file[r.pos + 2]) << 16) | (u32(file[r.pos + 3]) << 24))
		r.pos += 4
		if n < 0 || r.pos + n > file.len {
			return error('parquet value is truncated')
		}
		out << file[r.pos..r.pos + n].bytestr()
		r.pos += n
	}
	return out
}

struct ListHeader {
	elem int
	size int
}

fn (mut r Reader) list_header() !ListHeader {
	raw := r.byte()!
	elem := int(raw & 0x0f)
	mut size := int(raw >> 4)
	if size == 15 {
		size = int(r.varint()!)
	}
	return ListHeader{
		elem: elem
		size: size
	}
}

fn (mut r Reader) read_field() !(int, int) {
	raw := r.byte()!
	if raw == 0 {
		return 0, 0
	}
	typ := int(raw & 0x0f)
	delta := int(raw >> 4)
	mut id := r.last + delta
	if delta == 0 {
		id = int(r.zigzag()!)
	}
	r.last = id
	return id, typ
}

fn (mut r Reader) push() {
	r.stack << r.last
	r.last = 0
}

fn (mut r Reader) pop() {
	if r.stack.len == 0 {
		r.last = 0
		return
	}
	r.last = r.stack[r.stack.len - 1]
	r.stack.delete_last()
}

fn (mut r Reader) skip(typ int) ! {
	match typ {
		1, 2 {}
		3 { r.pos++ }
		4, 5, 6 { r.varint()! }
		7 { r.pos += 8 }
		8 {
			n := int(r.varint()!)
			r.pos += n
		}
		9, 10 {
			header := r.list_header()!
			for _ in 0 .. header.size {
				r.skip(header.elem)!
			}
		}
		11 {
			header := r.list_header()!
			for _ in 0 .. header.size {
				r.skip(header.elem)!
				r.skip(header.elem)!
			}
		}
		12 {
			r.push()
			for {
				_, next := r.read_field()!
				if next == 0 {
					break
				}
				r.skip(next)!
			}
			r.pop()
		}
		else {
			return error('parquet thrift type ${typ} is not supported')
		}
	}
}

fn (mut r Reader) zigzag() !i64 {
	raw := r.varint()!
	return i64((raw >> 1) ^ (-i64(raw & 1)))
}

fn (mut r Reader) binary() !string {
	n := int(r.varint()!)
	if n < 0 || r.pos + n > r.data.len {
		return error('parquet string is truncated')
	}
	text := r.data[r.pos..r.pos + n].bytestr()
	r.pos += n
	return text
}

fn (mut r Reader) varint() !u64 {
	mut shift := u64(0)
	mut out := u64(0)
	for {
		raw := r.byte()!
		out |= u64(raw & 0x7f) << shift
		if raw & 0x80 == 0 {
			return out
		}
		shift += 7
		if shift > 63 {
			return error('parquet varint is too long')
		}
	}
	return error('parquet varint is truncated')
}

fn (mut r Reader) byte() !u8 {
	if r.pos >= r.data.len {
		return error('parquet is truncated')
	}
	raw := r.data[r.pos]
	r.pos++
	return raw
}

fn zigzag(value i64) u64 {
	return (u64(value) << 1) ^ u64(value >> 63)
}

fn le32(value u32) []u8 {
	return [u8(value), u8(value >> 8), u8(value >> 16), u8(value >> 24)]
}
