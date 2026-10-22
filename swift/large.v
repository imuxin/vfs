// large reads Swift large-object manifests. SLO is a JSON list of segment
// paths. DLO is a container prefix whose object names are concatenated in
// order.
module swift

import json2

pub struct Segment {
pub:
	path       string
	etag       string
	size_bytes i64
}

pub fn parse_slo(raw string) ![]Segment {
	segments := json2.decode[[]Segment](raw)!
	if segments.len == 0 {
		return error('slo manifest is empty')
	}
	for segment in segments {
		segment_location(segment.path)!
	}
	return segments
}

// segment_location accepts /v1/account/container/object and container/object.
pub fn segment_location(path string) !(string, string) {
	mut parts := path.trim('/').split('/')
	if parts.len >= 4 && parts[0] == 'v1' {
		parts = parts[2..]
	}
	if parts.len < 2 || parts[0].len == 0 || parts[1..].join('/').len == 0 {
		return error('invalid slo segment')
	}
	return parts[0], parts[1..].join('/')
}

pub fn split_manifest(raw string) !(string, string) {
	parts := raw.trim_left('/').split_nth('/', 2)
	if parts.len < 2 || parts[0].len == 0 || parts[1].len == 0 {
		return error('invalid object manifest')
	}
	return parts[0], parts[1]
}
