// swift serves the OpenStack object API on the same buckets as S3. Clients
// exchange an access key and secret for a token at /auth/v1.0, then address
// containers and objects under /v1/{account}. A temp URL signed with the same
// secret can read or write one object without the token.
module swift

import crypto.hmac
import crypto.sha1
import crypto.sha256
import encoding.hex
import net.http
import net.urllib
import sync
import time
import auth
import iam
import store

pub struct Tokens {
mut:
	mu   sync.Mutex
	user map[string]string
}

pub fn new_tokens() &Tokens {
	return &Tokens{
		user: map[string]string{}
	}
}

pub fn (mut t Tokens) issue(access string) string {
	t.mu.lock()
	defer {
		t.mu.unlock()
	}
	digest := hex.encode(sha256.sum256('${access}:${time.now().unix_milli()}'.bytes()))
	token := 'tk_${digest}'
	t.user[token] = access
	return token
}

pub fn (mut t Tokens) account(token string) string {
	t.mu.lock()
	defer {
		t.mu.unlock()
	}
	return t.user[token] or { '' }
}

pub struct Service {
pub:
	volume    store.Volume
	creds     auth.Credentials
	directory ?iam.Directory
	tokens    &Tokens
}

pub fn (s Service) handle(req http.Request) http.Response {
	url := urllib.parse(req.url) or { return plain(http.Status.bad_request, 'bad url') }
	path := url.path
	if path == '/auth/v1.0' {
		return s.authenticate(req)
	}
	if !path.starts_with('/v1/') {
		return plain(http.Status.not_found, 'not found')
	}
	account, container, object := split_swift(path)
	access := s.caller(req, url, account) or { return plain(http.Status.unauthorized, 'unauthorized') }
	if access != account {
		return plain(http.Status.unauthorized, 'unauthorized')
	}
	return match req.method {
		.get { s.get(url, container, object) }
		.head { s.head(container, object) }
		.put { s.put(req, url, container, object) }
		.delete { s.delete(container, object) }
		else { plain(http.Status.method_not_allowed, 'method not allowed') }
	}
}

fn (s Service) authenticate(req http.Request) http.Response {
	user := req.header.get_custom('X-Auth-User') or { return plain(http.Status.unauthorized, 'unauthorized') }
	key := req.header.get_custom('X-Auth-Key') or { return plain(http.Status.unauthorized, 'unauthorized') }
	stored := s.creds.secret(user) or { return plain(http.Status.unauthorized, 'unauthorized') }
	if stored != key {
		return plain(http.Status.unauthorized, 'unauthorized')
	}
	if s.tokens == unsafe { nil } {
		return plain(http.Status.internal_server_error, 'tokens unavailable')
	}
	mut tokens := s.tokens
	token := tokens.issue(user)
	mut header := http.new_header()
	header.add_custom('X-Auth-Token', token) or {}
	header.add_custom('X-Storage-Url', '/v1/${user}') or {}
	return http.new_response(
		status: .ok
		body:   ''
		header: header
	)
}

fn (s Service) caller(req http.Request, url urllib.URL, account string) !string {
	if sig := url.query().get('temp_url_sig') {
		expires := url.query().get('temp_url_expires') or { return error('missing expiry') }
		secret := s.creds.secret(account) or { return error('unknown account') }
		if temp_url(req.method.str(), expires, url.path, secret, sig) {
			return account
		}
		return error('bad temp url')
	}
	token := req.header.get_custom('X-Auth-Token') or { return error('missing token') }
	if s.tokens == unsafe { nil } {
		return error('missing token')
	}
	mut tokens := s.tokens
	access := tokens.account(token)
	if access.len == 0 {
		return error('missing token')
	}
	return access
}

fn (s Service) get(url urllib.URL, container string, object string) http.Response {
	if container.len == 0 {
		names := s.volume.list_buckets() or { return plain(http.Status.internal_server_error, '${err}') }
		return text(names.join('\n'))
	}
	if object.len == 0 {
		stats := s.volume.list(container, '', 0) or { return plain(http.Status.not_found, 'not found') }
		mut names := []string{}
		for stat in stats {
			if !stat.delete_marker {
				names << stat.key
			}
		}
		return text(names.join('\n'))
	}
	stat := s.volume.stat(container, object) or { return plain(http.Status.not_found, 'not found') }
	show_manifest := (url.query().get('multipart-manifest') or { '' }) == 'get'
	manifest := stat.user_meta['swift-manifest'] or { '' }
	if !show_manifest && manifest.len > 0 {
		dest, prefix := split_manifest(manifest) or { return plain(http.Status.bad_request, '${err}') }
		joined := s.join_prefix(dest, prefix) or { return plain(http.Status.not_found, '${err}') }
		return bytes_ok(joined)
	}
	body := s.volume.get(container, object, []u8{}) or { return plain(http.Status.not_found, 'not found') }
	slo := stat.user_meta['swift-slo'] or { '' }
	if !show_manifest && slo == 'true' {
		joined := s.join_slo(body.bytestr()) or { return plain(http.Status.not_found, '${err}') }
		return bytes_ok(joined)
	}
	kind := if slo == 'true' {
		'application/json'
	} else {
		'application/octet-stream'
	}
	return http.new_response(
		status: .ok
		body:   body.bytestr()
		header: http.new_header(key: .content_type, value: kind)
	)
}

fn (s Service) join_slo(raw string) ![]u8 {
	mut out := []u8{}
	for segment in parse_slo(raw)! {
		container, key := segment_location(segment.path)!
		out << s.volume.get(container, key, []u8{})!
	}
	return out
}

fn (s Service) join_prefix(container string, prefix string) ![]u8 {
	mut out := []u8{}
	for stat in s.volume.list(container, prefix, 0)! {
		if stat.delete_marker || stat.key.ends_with('/') {
			continue
		}
		out << s.volume.get(container, stat.key, []u8{})!
	}
	return out
}

fn bytes_ok(body []u8) http.Response {
	return http.new_response(
		status: .ok
		body:   body.bytestr()
		header: http.new_header(key: .content_type, value: 'application/octet-stream')
	)
}

fn (s Service) head(container string, object string) http.Response {
	if container.len == 0 {
		return plain(http.Status.no_content, '')
	}
	if object.len == 0 {
		if !s.volume.bucket_exists(container) {
			return plain(http.Status.not_found, 'not found')
		}
		return plain(http.Status.no_content, '')
	}
	stat := s.volume.stat(container, object) or { return plain(http.Status.not_found, 'not found') }
	mut header := http.new_header()
	header.add(.content_length, '${stat.size}')
	return http.new_response(
		status: .no_content
		body:   ''
		header: header
	)
}

fn (s Service) put(req http.Request, url urllib.URL, container string, object string) http.Response {
	if container.len == 0 {
		return plain(http.Status.bad_request, 'missing container')
	}
	if object.len == 0 {
		s.volume.make_bucket(container) or { return plain(http.Status.conflict, '${err}') }
		return plain(http.Status.created, '')
	}
	if !s.volume.bucket_exists(container) {
		return plain(http.Status.not_found, 'not found')
	}
	mut meta := map[string]string{}
	data := req.data
	if (url.query().get('multipart-manifest') or { '' }) == 'put' {
		parse_slo(data) or { return plain(http.Status.bad_request, '${err}') }
		meta['swift-slo'] = 'true'
	}
	if manifest := req.header.get_custom('X-Object-Manifest') {
		split_manifest(manifest) or { return plain(http.Status.bad_request, '${err}') }
		meta['swift-manifest'] = manifest
	}
	s.volume.put(store.PutRequest{
		bucket:    container
		key:       object
		data:      data.bytes()
		user_meta: meta
	}) or {
		return plain(http.Status.internal_server_error, '${err}')
	}
	return plain(http.Status.created, '')
}

fn (s Service) delete(container string, object string) http.Response {
	if object.len == 0 {
		return plain(http.Status.method_not_allowed, 'missing object')
	}
	s.volume.delete(container, object) or { return plain(http.Status.not_found, 'not found') }
	return plain(http.Status.no_content, '')
}

pub fn temp_url(method string, expires string, path string, secret string, sig string) bool {
	when := expires.i64()
	if when <= time.now().unix() {
		return false
	}
	body := '${method.to_upper()}\n${expires}\n${path}'
	mac := hex.encode(hmac.new(secret.bytes(), body.bytes(), sha1.sum, sha1.block_size))
	return mac == sig.to_lower()
}

fn split_swift(path string) (string, string, string) {
	trimmed := path.trim_string_left('/v1/').trim('/')
	parts := trimmed.split_nth('/', 3)
	account := if parts.len > 0 { parts[0] } else { '' }
	container := if parts.len > 1 { parts[1] } else { '' }
	object := if parts.len > 2 { parts[2] } else { '' }
	return account, container, object
}

fn plain(status http.Status, body string) http.Response {
	return http.new_response(
		status: status
		body:   body
		header: http.new_header(key: .content_type, value: 'text/plain; charset=utf-8')
	)
}

fn text(body string) http.Response {
	suffix := if body.len == 0 { '' } else { '\n' }
	return plain(http.Status.ok, body + suffix)
}
