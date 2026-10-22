// gate decides the conditional headers on a read or a write before any bytes
// move. The comparisons follow S3: a matching If-None-Match is "not modified",
// and a failed If-Match or If-Unmodified-Since is a precondition failure.
module s3

import net.http
import checksum
import store

struct Verdict {
	stop    bool
	status  http.Status
	code    string
	message string
}

fn read_verdict(stat store.Stat, req http.Request) Verdict {
	if etag := header_of(req, 'if-match') {
		if !etag_matches(etag, stat.etag) {
			return blocked(.precondition_failed, 'PreconditionFailed', 'if-match failed')
		}
	}
	if etag := header_of(req, 'if-none-match') {
		if etag == '*' || etag_matches(etag, stat.etag) {
			return blocked(.not_modified, 'NotModified', 'if-none-match')
		}
	}
	if since := header_time(req, 'if-unmodified-since') {
		if stat.modified > since {
			return blocked(.precondition_failed, 'PreconditionFailed', 'if-unmodified-since failed')
		}
	}
	if since := header_time(req, 'if-modified-since') {
		if stat.modified <= since {
			return blocked(.not_modified, 'NotModified', 'if-modified-since')
		}
	}
	return Verdict{}
}

fn write_verdict(exists bool, stat store.Stat, req http.Request) Verdict {
	if etag := header_of(req, 'if-match') {
		if !exists || !etag_matches(etag, stat.etag) {
			return blocked(.precondition_failed, 'PreconditionFailed', 'if-match failed')
		}
	}
	if etag := header_of(req, 'if-none-match') {
		if exists && (etag == '*' || etag_matches(etag, stat.etag)) {
			return blocked(.precondition_failed, 'PreconditionFailed', 'if-none-match failed')
		}
	}
	return Verdict{}
}

fn blocked(status http.Status, code string, message string) Verdict {
	return Verdict{
		stop:    true
		status:  status
		code:    code
		message: message
	}
}

fn header_of(req http.Request, name string) ?string {
	value := req.header.get_custom(name) or { return none }
	trimmed := value.trim_space()
	if trimmed.len == 0 {
		return none
	}
	return trimmed
}

fn header_time(req http.Request, name string) ?i64 {
	raw := header_of(req, name) or { return none }
	return raw.i64()
}

fn etag_matches(header string, etag string) bool {
	for part in header.split(',') {
		candidate := part.trim_space().trim('"')
		if candidate == '*' || candidate == etag {
			return true
		}
	}
	return false
}

fn verdict_response(verdict Verdict, target Target) http.Response {
	if verdict.status == .not_modified {
		return empty(.not_modified)
	}
	return failure(verdict.status, verdict.code, verdict.message, target.bucket, target.key)
}

// checksum_mismatch compares a supplied x-amz-checksum-* header with the body.
// An empty result means the header is absent or it matches.
fn checksum_mismatch(alg string, req http.Request) string {
	kind := checksum.parse(alg) or { return '${err}' }
	got := req.header.get_custom('x-amz-checksum-${alg.to_lower()}') or { return '' }
	if got.len == 0 {
		return ''
	}
	if got != kind.header(req.data.bytes()) {
		return 'checksum does not match'
	}
	return ''
}

fn (s Service) delete_objects(req http.Request, target Target) http.Response {
	keys := delete_keys(req.data)
	mut body := '<?xml version="1.0" encoding="UTF-8"?>\n<DeleteResult>'
	for key in keys {
		s.volume.delete(target.bucket, key) or {
			body += '<Error><Key>${esc(key)}</Key><Code>InternalError</Code><Message>${esc('${err}')}</Message></Error>'
			continue
		}
		body += '<Deleted><Key>${esc(key)}</Key></Deleted>'
	}
	body += '</DeleteResult>\n'
	return xml_ok(body)
}

fn (s Service) session_ok(req http.Request, access_key string) bool {
	directory := s.directory or { return true }
	key := directory.key(access_key) or { return true }
	if key.session.len == 0 {
		return true
	}
	got := req.header.get_custom('x-amz-security-token') or { '' }
	return got == key.session
}

// delete_keys reads the object keys from a DeleteObjects document.
fn delete_keys(body string) []string {
	mut keys := []string{}
	mut rest := body
	for {
		key := between(rest, '<Key>', '</Key>') or { break }
		keys << key
		rest = rest.all_after('</Key>')
	}
	return keys
}
