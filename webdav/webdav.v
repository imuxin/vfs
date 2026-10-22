// webdav serves the same buckets as S3. Clients authenticate with HTTP Basic,
// using an access key and its secret, and the request is authorized with the
// same IAM verdict and bucket policy as an S3 call. Depth infinity lists the
// prefix; it does not walk other buckets.
module webdav

import encoding.base64
import net.http
import net.urllib
import auth
import bucketcfg
import iam
import json2
import store

pub struct Service {
pub:
	volume    store.Volume
	creds     auth.Credentials
	directory ?iam.Directory
}

// wants reports whether this request belongs to WebDAV rather than S3. SigV4
// stays on the S3 path. A CORS preflight carries Origin and stays there too.
pub fn wants(req http.Request) bool {
	if req.method in [.propfind, .mkcol, .move, .copy] {
		return true
	}
	authorization := req.header.get(.authorization) or { '' }
	if authorization.to_lower().starts_with('basic ') {
		return true
	}
	if req.method == .options {
		origin := req.header.get_custom('origin') or { '' }
		return origin.len == 0
	}
	return false
}

pub fn (s Service) handle(req http.Request) http.Response {
	access, secret_ok := s.authenticate(req) or {
		return unauthorized()
	}
	if !secret_ok {
		return unauthorized()
	}
	bucket, key := split_path(req.url)
	if !s.permit(access, req.method, bucket, key) {
		return denied()
	}
	return match req.method {
		.propfind { s.propfind(req, bucket, key) }
		.get, .head { s.read(req, bucket, key) }
		.put { s.write(bucket, key, req.data) }
		.delete { s.remove(bucket, key) }
		.mkcol { s.mkcol(bucket, key) }
		.move, .copy { s.transfer(req, bucket, key) }
		.options { options() }
		else { text(http.Status.method_not_allowed, 'method not allowed') }
	}
}

fn (s Service) authenticate(req http.Request) !(string, bool) {
	header := req.header.get(.authorization) or { return error('missing authorization') }
	if !header.to_lower().starts_with('basic ') {
		return error('expected basic authorization')
	}
	decoded := base64.decode(header[6..].trim_space())
	pair := decoded.bytestr()
	access := pair.all_before(':')
	secret := pair.all_after(':')
	stored := s.creds.secret(access) or { return access, false }
	return access, secret_matches(secret, stored)
}

fn (s Service) permit(access_key string, method http.Method, bucket string, key string) bool {
	directory := s.directory or { return true }
	for action in actions(method, key) {
		resource := resource_for(bucket, key, action)
		iam_answer := directory.verdict(access_key, action, resource) or { return false }
		if !iam.join(iam_answer, bucket_verdict(s.volume, bucket, access_key, action, resource)) {
			return false
		}
	}
	return true
}

fn resource_for(bucket string, key string, action string) string {
	if bucket.len == 0 {
		return '*'
	}
	if key.len == 0 || action == 's3:ListBucket' || action == 's3:PutBucket' || action == 's3:DeleteBucket' {
		return 'arn:aws:s3:::${bucket}'
	}
	return 'arn:aws:s3:::${bucket}/${key}'
}

fn actions(method http.Method, key string) []string {
	return match method {
		.get, .head {
			if key.len == 0 { ['s3:ListBucket'] } else { ['s3:GetObject'] }
		}
		.put {
			['s3:PutObject']
		}
		.delete {
			if key.len == 0 { ['s3:DeleteBucket'] } else { ['s3:DeleteObject'] }
		}
		.mkcol {
			if key.len == 0 { ['s3:PutBucket'] } else { ['s3:PutObject'] }
		}
		.propfind {
			if key.len == 0 { ['s3:ListBucket'] } else { ['s3:GetObject', 's3:ListBucket'] }
		}
		.move { ['s3:GetObject', 's3:PutObject', 's3:DeleteObject'] }
		.copy { ['s3:GetObject', 's3:PutObject'] }
		else { []string{} }
	}
}

fn bucket_verdict(volume store.Volume, bucket_name string, principal string, action string, resource string) iam.Verdict {
	if bucket_name.len == 0 {
		return iam.Verdict.abstain
	}
	raw := volume.get_doc(bucket_name, 'policy') or { return iam.Verdict.abstain }
	policy := json2.decode[bucketcfg.Policy](raw.bytestr()) or { return iam.Verdict.abstain }
	return match bucketcfg.effect(policy, principal, action, resource) {
		'allow' { iam.Verdict.allow }
		'deny' { iam.Verdict.deny }
		else { iam.Verdict.abstain }
	}
}

fn (s Service) propfind(req http.Request, bucket string, key string) http.Response {
	depth := (req.header.get_custom('Depth') or { 'infinity' }).to_lower()
	entries := s.entries(bucket, key, depth) or { return text(http.Status.not_found, '${err}') }
	return http.new_response(
		status: .multi_status
		body:   multistatus(entries)
		header: http.new_header(key: .content_type, value: 'application/xml; charset=utf-8')
	)
}

fn (s Service) entries(bucket string, key string, depth string) ![]Entry {
	if bucket.len == 0 {
		mut entries := []Entry{}
		entries << Entry{
			href:       '/'
			name:       '/'
			collection: true
		}
		if depth != '0' {
			for name in s.volume.list_buckets()! {
				entries << Entry{
					href:       '/${name}/'
					name:       name
					collection: true
				}
			}
		}
		return entries
	}
	if !s.volume.bucket_exists(bucket) {
		return error('bucket not found')
	}
	if key.len == 0 {
		mut entries := [
			Entry{
				href:       '/${bucket}/'
				name:       bucket
				collection: true
			},
		]
		if depth != '0' {
			for stat in s.volume.list(bucket, '', 0)! {
				if stat.delete_marker {
					continue
				}
				entries << object_entry(bucket, stat)
			}
		}
		return entries
	}
	stat := s.volume.stat(bucket, key)!
	mut entries := [object_entry(bucket, stat)]
	if depth != '0' {
		prefix := if key.ends_with('/') { key } else { '${key}/' }
		for child in s.volume.list(bucket, prefix, 0)! {
			if child.delete_marker || child.key == key {
				continue
			}
			entries << object_entry(bucket, child)
		}
	}
	return entries
}

fn (s Service) read(req http.Request, bucket string, key string) http.Response {
	if bucket.len == 0 || key.len == 0 {
		return s.propfind(req, bucket, key)
	}
	stat := s.volume.stat(bucket, key) or { return text(http.Status.not_found, '${err}') }
	if req.method == .head {
		return http.new_response(
			status: .ok
			body:   ''
			header: object_headers(stat)
		)
	}
	body := s.volume.get(bucket, key, []u8{}) or { return text(http.Status.not_found, '${err}') }
	mut header := object_headers(stat)
	header.add(.content_length, '${body.len}')
	return http.new_response(
		status: .ok
		body:   body.bytestr()
		header: header
	)
}

fn (s Service) write(bucket string, key string, data string) http.Response {
	if bucket.len == 0 || key.len == 0 || !s.volume.bucket_exists(bucket) {
		return text(http.Status.conflict, 'bucket is missing')
	}
	s.volume.put(store.PutRequest{
		bucket:       bucket
		key:          key
		data:         data.bytes()
		content_type: 'application/octet-stream'
	}) or {
		return text(http.Status.internal_server_error, '${err}')
	}
	return text(http.Status.created, '')
}

fn (s Service) remove(bucket string, key string) http.Response {
	if bucket.len == 0 {
		return text(http.Status.method_not_allowed, 'missing bucket')
	}
	if key.len == 0 {
		s.volume.remove_bucket(bucket) or { return text(http.Status.conflict, '${err}') }
		return text(http.Status.no_content, '')
	}
	s.volume.delete(bucket, key) or { return text(http.Status.not_found, '${err}') }
	return text(http.Status.no_content, '')
}

fn (s Service) mkcol(bucket string, key string) http.Response {
	if bucket.len == 0 {
		return text(http.Status.method_not_allowed, 'missing bucket')
	}
	if key.len == 0 {
		s.volume.make_bucket(bucket) or { return text(http.Status.conflict, '${err}') }
		return text(http.Status.created, '')
	}
	if !s.volume.bucket_exists(bucket) {
		return text(http.Status.conflict, 'bucket is missing')
	}
	marker := if key.ends_with('/') { key } else { '${key}/' }
	s.volume.put(store.PutRequest{
		bucket:       bucket
		key:          marker
		data:         []u8{}
		content_type: 'application/x-directory'
	}) or {
		return text(http.Status.internal_server_error, '${err}')
	}
	return text(http.Status.created, '')
}

fn (s Service) transfer(req http.Request, bucket string, key string) http.Response {
	raw := req.header.get_custom('Destination') or { return text(http.Status.bad_request, 'missing destination') }
	dest_bucket, dest_key := split_path(destination_path(raw))
	if dest_bucket.len == 0 || dest_key.len == 0 || key.len == 0 {
		return text(http.Status.bad_request, 'destination must be an object')
	}
	access, ok := s.authenticate(req) or { return unauthorized() }
	if !ok || !s.permit(access, .put, dest_bucket, dest_key) {
		return denied()
	}
	s.volume.copy(bucket, key, dest_bucket, dest_key) or { return text(http.Status.not_found, '${err}') }
	if req.method == .move {
		s.volume.delete(bucket, key) or { return text(http.Status.internal_server_error, '${err}') }
	}
	return text(http.Status.created, '')
}

fn destination_path(raw string) string {
	if raw.contains('://') {
		after := raw.all_after('://')
		slash := after.index('/') or { return '/' }
		return after[slash..]
	}
	return raw
}

fn split_path(raw string) (string, string) {
	parsed := urllib.parse(raw) or {
		return '', ''
	}
	path := urllib.query_unescape(parsed.path) or { parsed.path }
	trimmed := path.trim('/')
	if trimmed.len == 0 {
		return '', ''
	}
	parts := trimmed.split_nth('/', 2)
	if parts.len == 1 {
		return parts[0], ''
	}
	return parts[0], parts[1]
}

fn secret_matches(got string, want string) bool {
	if got.len != want.len {
		return false
	}
	mut diff := u8(0)
	for i, ch in got {
		diff |= u8(ch) ^ want[i]
	}
	return diff == 0
}

fn unauthorized() http.Response {
	return http.new_response(
		status: .unauthorized
		body:   'unauthorized'
		header: http.new_header(key: .www_authenticate, value: 'Basic realm="vfs"')
	)
}

fn denied() http.Response {
	return text(http.Status.forbidden, 'not authorized')
}

fn options() http.Response {
	mut header := http.new_header()
	header.add_custom('Allow', 'OPTIONS, GET, HEAD, PUT, DELETE, PROPFIND, MKCOL, MOVE, COPY') or {}
	header.add_custom('DAV', '1, 2') or {}
	return http.new_response(
		status: .ok
		body:   ''
		header: header
	)
}

fn text(status http.Status, body string) http.Response {
	return http.new_response(
		status: status
		body:   body
		header: http.new_header(key: .content_type, value: 'text/plain; charset=utf-8')
	)
}

fn object_headers(stat store.Stat) http.Header {
	mut header := http.new_header(key: .content_type, value: stat.content_type)
	header.add_custom('ETag', '"${stat.etag}"') or {}
	return header
}
