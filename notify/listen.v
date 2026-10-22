// listen filters bucket events the way MinIO's ListenBucketNotification does:
// event names may end in *, and the key may be limited by a prefix and a suffix.
module notify

import json2

pub struct Record {
pub:
	event  string
	bucket string
	key    string
}

pub struct Listen {
pub:
	events []string
	prefix string
	suffix string
}

pub fn parse_events(raw string) []string {
	mut names := []string{}
	for part in raw.split(',') {
		name := part.trim_space()
		if name.len > 0 {
			names << name
		}
	}
	return names
}

pub fn (q Listen) matches(record Record) bool {
	if !wants(q.events, record.event) {
		return false
	}
	if q.prefix.len > 0 && !record.key.starts_with(q.prefix) {
		return false
	}
	if q.suffix.len > 0 && !record.key.ends_with(q.suffix) {
		return false
	}
	return true
}

// sse renders matching records as one Server-Sent Event each. The payload is
// the MinIO record shape clients already parse.
pub fn sse(records []Record) string {
	mut out := ''
	for record in records {
		body := '{"Records":[{"eventName":"${json_escape(record.event)}","s3":{"bucket":{"name":"${json_escape(record.bucket)}"},"object":{"key":"${json_escape(record.key)}"}}}]}'
		out += 'data: ${body}\n\n'
	}
	return out
}

pub fn encode_record(record Record) string {
	return json2.encode[Record](record, escape_unicode: true)
}

pub fn decode_record(raw string) !Record {
	return json2.decode[Record](raw)
}

fn json_escape(raw string) string {
	return raw.replace('\\', '\\\\').replace('"', '\\"')
}
