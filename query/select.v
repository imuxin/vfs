// query evaluates the S3 Select subset this server runs locally: a projection
// and one equality filter over a CSV object. Columns are numbered _1, _2, ...
// the way S3 Select names CSV fields that have no header.
module query

pub struct Select {
pub:
	columns []string
	where_column string
	where_value  string
	as_json      bool
}

// parse reads `SELECT cols FROM S3Object [WHERE col = 'value']`.
pub fn parse(statement string) !Select {
	text := statement.trim_space()
	upper := text.to_upper()
	if !upper.starts_with('SELECT ') || !upper.contains(' FROM ') {
		return error('select must read SELECT ... FROM S3Object')
	}
	from_at := upper.index(' FROM ') or { return error('missing FROM') }
	cols := text[7..from_at].trim_space()
	rest := text[from_at + 6..].trim_space()
	mut where_column := ''
	mut where_value := ''
	mut source := rest
	where_at := rest.to_upper().index(' WHERE ') or { -1 }
	if where_at >= 0 {
		source = rest[..where_at].trim_space()
		clause := rest[where_at + 7..].trim_space()
		parts := clause.split('=')
		if parts.len != 2 {
			return error('where must be column = value')
		}
		where_column = column_name(parts[0].trim_space())
		where_value = unquote(parts[1].trim_space())
	}
	if !source.to_upper().contains('S3OBJECT') {
		return error('select source must be S3Object')
	}
	mut columns := []string{}
	if cols != '*' {
		for col in cols.split(',') {
			columns << column_name(col.trim_space())
		}
	}
	return Select{
		columns:      columns
		where_column: where_column
		where_value:  where_value
	}
}

// eval_json runs the query over JSON lines. Each line is an object whose
// fields are the column names, including _1 and _2.
pub fn eval_json(q Select, body string) !string {
	mut out := []string{}
	for line in body.split_into_lines() {
		if line.len == 0 {
			continue
		}
		if q.where_column.len > 0 && json_field(line, q.where_column) != q.where_value {
			continue
		}
		mut fields := []string{}
		columns := if q.columns.len == 0 { ['_1', '_2'] } else { q.columns }
		for column in columns {
			fields << json_field(line, column)
		}
		if q.as_json {
			out << json_row(fields)
		} else {
			out << fields.join(',')
		}
	}
	return out.join('\n')
}

fn json_field(line string, name string) string {
	token := '"${name}":"'
	at := line.index(token) or { return '' }
	return line[at + token.len..].all_before('"')
}

// eval_csv runs the query over CSV text and returns CSV, or JSON lines when
// as_json is set.
pub fn eval_csv(q Select, body string) !string {
	mut out := []string{}
	for line in body.split_into_lines() {
		if line.len == 0 {
			continue
		}
		fields := split_csv(line)
		if q.where_column.len > 0 {
			got := field_at(fields, q.where_column) or { continue }
			if got != q.where_value {
				continue
			}
		}
		chosen := project(fields, q.columns)
		if q.as_json {
			out << json_row(chosen)
		} else {
			out << chosen.join(',')
		}
	}
	return out.join('\n')
}

fn column_name(raw string) string {
	name := raw.all_after('.')
	return name.trim_space()
}

fn unquote(raw string) string {
	if raw.len >= 2 && (raw[0] == `'` || raw[0] == `"`) {
		return raw[1..raw.len - 1]
	}
	return raw
}

fn split_csv(line string) []string {
	mut fields := []string{}
	mut current := ''
	mut quoted := false
	for ch in line {
		if ch == `"` {
			quoted = !quoted
			continue
		}
		if ch == `,` && !quoted {
			fields << current
			current = ''
			continue
		}
		current += ch.ascii_str()
	}
	fields << current
	return fields
}

fn field_at(fields []string, column string) ?string {
	if !column.starts_with('_') {
		return none
	}
	index := column[1..].int() - 1
	if index < 0 || index >= fields.len {
		return none
	}
	return fields[index]
}

fn project(fields []string, columns []string) []string {
	if columns.len == 0 {
		return fields.clone()
	}
	mut out := []string{}
	for column in columns {
		out << field_at(fields, column) or { '' }
	}
	return out
}

fn json_row(fields []string) string {
	mut parts := []string{}
	for index, field in fields {
		parts << '"_${index + 1}":"${escape_json(field)}"'
	}
	return '{' + parts.join(',') + '}'
}

fn escape_json(value string) string {
	return value.replace('\\', '\\\\').replace('"', '\\"')
}
