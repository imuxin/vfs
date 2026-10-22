// form reads the small subset of multipart/form-data that an S3 browser upload
// sends: a key field and one file field. The boundary comes from the
// Content-Type header, so the body is not scanned for a guessed delimiter.
module form

pub struct Upload {
pub:
	key          string
	filename     string
	content_type string
	body         []u8
}

// parse returns the object key and the file bytes. A body without a key or a
// file is rejected.
pub fn parse(content_type string, payload []u8) !Upload {
	marker := boundary(content_type) or { return error('missing form boundary') }
	text := payload.bytestr()
	parts := text.split('--${marker}')
	mut key := ''
	mut filename := ''
	mut kind := 'application/octet-stream'
	mut body := []u8{}
	mut saw_file := false
	for part in parts {
		if part.len == 0 || part == '--' || part == '--\r\n' {
			continue
		}
		head, content := split_part(part)
		name := field(head, 'name')
		if name == 'key' {
			key = content.trim_space()
			continue
		}
		if name == 'x-amz-server-side-encryption' && content.trim_space() == 'aws:kms' {
			return error('SSE-KMS is not supported for form upload')
		}
		if name == 'file' {
			filename = field(head, 'filename')
			if found := header_value(head, 'content-type') {
				kind = found
			}
			body = content.bytes()
			saw_file = true
		}
	}
	if key.len == 0 || !saw_file {
		return error('form upload needs a key and a file')
	}
	return Upload{
		key:          key
		filename:     filename
		content_type: kind
		body:         body
	}
}

fn boundary(content_type string) ?string {
	lower := content_type.to_lower()
	at := lower.index('boundary=') or { return none }
	raw := content_type[at + 'boundary='.len..]
	return raw.all_before(';').trim_space().trim('"')
}

fn split_part(part string) (string, string) {
	trimmed := part.trim_left('\r\n')
	at := trimmed.index('\r\n\r\n') or {
		return trimmed, ''
	}
	content := trimmed[at + 4..].trim_right('\r\n')
	return trimmed[..at], content
}

fn field(head string, name string) string {
	token := '${name}="'
	at := head.index(token) or { return '' }
	rest := head[at + token.len..]
	return rest.all_before('"')
}

fn header_value(head string, name string) ?string {
	for line in head.split_into_lines() {
		if line.to_lower().starts_with('${name}:') {
			return line.all_after(':').trim_space()
		}
	}
	return none
}
