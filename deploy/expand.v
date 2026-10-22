// deploy reads a deployment from the command line and the environment. Volumes
// are a static list: an ellipsis expands in place, and nothing here discovers
// peers at runtime.
module deploy

const max_span = 1024

pub struct Endpoint {
pub:
	raw  string
	kind string
	path string
}

// expand turns `{0...3}` and `{a...c}` into concrete strings. A string with no
// braces is one endpoint. Several braces are the cartesian product, matching
// `http://node{0...1}/disk{0...1}`.
pub fn expand(pattern string) ![]string {
	if !pattern.contains('{') {
		if pattern.contains('...') {
			return error('ellipsis must be written as {N...M}')
		}
		return [pattern]
	}
	return expand_braces(pattern)
}

fn expand_braces(pattern string) ![]string {
	start := pattern.index('{') or { return [pattern] }
	end := pattern.index('}') or { return error('ellipsis is missing }') }
	if end < start {
		return error('ellipsis is malformed')
	}
	body := pattern[start + 1..end]
	parts := body.split('...')
	if parts.len != 2 {
		return error('ellipsis must be written as {N...M}')
	}
	prefix := pattern[..start]
	suffix := pattern[end + 1..]
	tails := expand(suffix)!
	mut out := []string{}
	span := sequence(parts[0], parts[1])!
	if span.len > max_span {
		return error('ellipsis expands past ${max_span} values')
	}
	for item in span {
		for tail in tails {
			out << '${prefix}${item}${tail}'
		}
	}
	return out
}

fn sequence(from string, to string) ![]string {
	if from.len == 0 || to.len == 0 {
		return error('ellipsis bounds are empty')
	}
	if is_digits(from) && is_digits(to) {
		return number_span(from, to)
	}
	if from.len == 1 && to.len == 1 {
		return rune_span(from[0], to[0])
	}
	return error('ellipsis bounds must both be numbers or single letters')
}

fn is_digits(s string) bool {
	for ch in s {
		if ch < `0` || ch > `9` {
			return false
		}
	}
	return true
}

fn number_span(from string, to string) ![]string {
	start := from.int()
	end := to.int()
	if end < start {
		return error('ellipsis end is before the start')
	}
	width := if from.len == to.len { from.len } else { 0 }
	mut out := []string{}
	for n in start .. end + 1 {
		mut text := '${n}'
		if width > text.len {
			text = '0'.repeat(width - text.len) + text
		}
		out << text
	}
	return out
}

fn rune_span(from u8, to u8) ![]string {
	if to < from {
		return error('ellipsis end is before the start')
	}
	mut out := []string{}
	for ch in from .. to + 1 {
		out << ch.ascii_str()
	}
	return out
}

// parse_endpoint classifies a volume argument. A URL is a remote peer; anything
// else is a directory on this machine.
pub fn parse_endpoint(raw string) Endpoint {
	if raw.starts_with('http://') || raw.starts_with('https://') {
		return Endpoint{
			raw:  raw
			kind: 'remote'
			path: raw
		}
	}
	return Endpoint{
		raw:  raw
		kind: 'local'
		path: raw
	}
}

// volumes expands every pattern and classifies the results.
pub fn volumes(patterns []string) ![]Endpoint {
	mut out := []Endpoint{}
	for pattern in patterns {
		for item in expand(pattern)! {
			out << parse_endpoint(item)
		}
	}
	if out.len == 0 {
		return error('no volumes were configured')
	}
	return out
}

// local_paths is the directories this process formats. Remote endpoints are
// peers, not disks of this process.
pub fn local_paths(endpoints []Endpoint) []string {
	mut paths := []string{}
	for endpoint in endpoints {
		if endpoint.kind == 'local' {
			paths << endpoint.path
		}
	}
	return paths
}
