// api turns HTTP into storage calls. Routing is by method and query shape,
// which is how S3 distinguishes operations that share one path. The handler
// owns no state of its own: the volume and the credentials are injected, so
// the same code serves the process and a test.
module s3

import net.http
import net.urllib
import crypto.md5
import encoding.base64
import auth
import iam
import json2
import lifecycle
import meta
import store
import time

// Service is the S3 endpoint.
pub struct Service {
pub mut:
	volume store.Volume
	creds  auth.Credentials
	// directory authorizes a verified identity. Empty means the credential store
	// is the whole policy: whoever can sign may do anything. That is the
	// bootstrap deployment with one root key.
	directory ?iam.Directory
	region    string = 'us-east-1'
	owner     string = 'vfs'
}

struct Target {
	bucket string
	key    string
	query  urllib.Values
}

// handle serves one request.
pub fn (s Service) handle(req http.Request) http.Response {
	target := route_of(req)
	if req.method == .options {
		return s.preflight(req, target)
	}
	verified := auth.verify(req, s.creds) or {
		return failure(http.Status.forbidden, 'SignatureDoesNotMatch', '${err}', '', '')
	}
	if verified.none {
		if target.bucket.len == 0 || !s.anonymous_policy(req.method, target) {
			return failure(http.Status.forbidden, 'AccessDenied', 'anonymous access is not enabled',
				'', '')
		}
		confirmed := s.confirm_plugin(true, '', action_of(req.method, target), resource_of(target),
			target) or {
			return failure(http.Status.forbidden, 'AccessDenied', '${err}', target.bucket, target.key)
		}
		if !confirmed {
			return failure(http.Status.forbidden, 'AccessDenied', 'not authorized', target.bucket,
				target.key)
		}
	} else {
		authorized := s.authorize(verified.identity, req.method, target) or {
			return failure(http.Status.forbidden, 'AccessDenied', '${err}', target.bucket, target.key)
		}
		if !authorized {
			return failure(http.Status.forbidden, 'AccessDenied', 'not authorized', target.bucket,
				target.key)
		}
		if !s.session_ok(req, verified.identity.access_key) {
			return failure(http.Status.forbidden, 'InvalidToken', 'session token is missing or wrong',
				target.bucket, target.key)
		}
	}
	return match req.method {
		.get { s.get(req, target) }
		.put { s.put(req, target) }
		.delete { s.delete(req, target) }
		.head { s.head(req, target) }
		.post { s.post(req, target) }
		else {
			failure(http.Status.method_not_allowed, 'MethodNotAllowed', 'method not allowed', target.bucket, target.key)
		}
	}
}

// authorize checks the verified identity against the IAM directory. With no
// directory every verified caller is allowed, which keeps the single-key
// deployment working.
fn (s Service) authorize(identity auth.Identity, method http.Method, target Target) !bool {
	action := action_of(method, target)
	resource := resource_of(target)
	mut allowed := true
	if directory := s.directory {
		iam_answer := directory.verdict(identity.access_key, action, resource)!
		allowed = iam.join(iam_answer, s.bucket_verdict(target.bucket, identity.access_key, action,
			resource))
	}
	return s.confirm_plugin(allowed, identity.access_key, action, resource, target)
}

// confirm_plugin keeps the local decision when no plugin is configured. A
// configured plugin must return allow, and a local deny is not sent to it.
fn (s Service) confirm_plugin(allowed bool, access_key string, action string, resource string, target Target) !bool {
	if !allowed {
		return false
	}
	url := s.volume.policy_plugin().url
	if url.len == 0 {
		return true
	}
	answer := iam.ask(url, iam.PluginQuery{
		access_key: access_key
		action:     action
		resource:   resource
		bucket:     target.bucket
		key:        target.key
	})!
	return answer == iam.Verdict.allow
}

// action_of names the S3 operation. The query shape distinguishes the
// operations that share a method, matching the routing below.
fn action_of(method http.Method, target Target) string {
	return match method {
		.get { read_action(target) }
		.head {
			if target.key.len == 0 { 's3:ListBucket' } else { 's3:GetObject' }
		}
		.put {
			if target.key.len == 0 { 's3:PutBucket' } else { 's3:PutObject' }
		}
		.post { 's3:PutObject' }
		.delete {
			if target.key.len == 0 { 's3:DeleteBucket' } else { 's3:DeleteObject' }
		}
		else { 's3:Unknown' }
	}
}

fn read_action(target Target) string {
	if target.bucket.len == 0 {
		return 's3:ListAllMyBuckets'
	}
	if target.key.len == 0 {
		return 's3:ListBucket'
	}
	return 's3:GetObject'
}

fn resource_of(target Target) string {
	if target.bucket.len == 0 {
		return '*'
	}
	if target.key.len == 0 {
		return 'arn:aws:s3:::${target.bucket}'
	}
	return 'arn:aws:s3:::${target.bucket}/${target.key}'
}

fn route_of(req http.Request) Target {
	url := urllib.parse(req.url) or {
		return Target{
			bucket: ''
			key:    ''
			query:  urllib.new_values()
		}
	}
	path := url.path.trim('/').trim_space()
	mut bucket := ''
	mut key := ''
	if path.len > 0 {
		parts := path.split_nth('/', 2)
		bucket = urllib.query_unescape(parts[0]) or { parts[0] }
		if parts.len == 2 {
			key = urllib.query_unescape(parts[1]) or { parts[1] }
		}
	}
	return Target{
		bucket: bucket
		key:    key
		query:  url.query()
	}
}

fn (s Service) get(req http.Request, target Target) http.Response {
	if response := s.website(req, target) {
		return response
	}
	if target.bucket.len == 0 {
		names := s.volume.list_buckets() or {
			return failure(http.Status.internal_server_error, 'InternalError', '${err}', '', '')
		}
		return xml_ok(list_buckets(s.owner, names))
	}
	if target.key.len == 0 {
		if response := s.bucket_extra(.get, req, target) {
			return response
		}
		if has_key(target.query, 'location') {
			return xml_ok(location(s.region))
		}
		if has_key(target.query, 'versioning') {
			config := s.volume.bucket_config(target.bucket) or {
				return storage_failure(err, target)
			}
			return xml_ok(versioning_config(config.versioning))
		}
		if has_key(target.query, 'lifecycle') {
			config := s.volume.lifecycle_of(target.bucket) or {
				return storage_failure(err, target)
			}
			return xml_ok(lifecycle_config(config))
		}
		if has_key(target.query, 'replication') {
			rule := s.volume.replication_of(target.bucket) or {
				return storage_failure(err, target)
			}
			return json_ok(json2.encode[store.Replication](rule, escape_unicode: true))
		}
		if has_key(target.query, 'events') {
			events := target.query.get('events') or { '' }
			prefix := target.query.get('prefix') or { '' }
			suffix := target.query.get('suffix') or { '' }
			body := s.volume.listen(target.bucket, events, prefix, suffix)
			return http.new_response(
				status: .ok
				body:   body
				header: http.new_header(key: .content_type, value: 'text/event-stream')
			)
		}
		if has_key(target.query, 'uploads') {
			uploads := s.volume.list_uploads(target.bucket) or {
				return storage_failure(err, target)
			}
			return xml_ok(list_uploads(target.bucket, uploads))
		}
		prefix := target.query.get('prefix') or { '' }
		if has_key(target.query, 'versions') {
			stats := s.volume.list_versions(target.bucket, prefix) or {
				return storage_failure(err, target)
			}
			return xml_ok(list_versions(target.bucket, stats))
		}
		stats := s.volume.list(target.bucket, prefix, 1000) or {
			return storage_failure(err, target)
		}
		return xml_ok(list_objects(target.bucket, stats, false))
	}
	if has_key(target.query, 'attributes') {
		stat := s.volume.stat(target.bucket, target.key) or { return storage_failure(err, target) }
		return xml_ok('<GetObjectAttributesResponse><ETag>&quot;${esc(stat.etag)}&quot;</ETag><ObjectSize>${stat.size}</ObjectSize><StorageClass>${esc(stat.storage_class)}</StorageClass></GetObjectAttributesResponse>')
	}
	if has_key(target.query, 'torrent') {
		return failure(http.Status.not_found, 'NoSuchKey', 'torrent is not implemented', target.bucket,
			target.key)
	}
	if has_key(target.query, 'acl') {
		return xml_ok('<AccessControlPolicy><Owner><ID>${esc_owner(s.owner)}</ID></Owner><AccessControlList><Grant><Grantee><ID>${esc_owner(s.owner)}</ID></Grantee><Permission>FULL_CONTROL</Permission></Grant></AccessControlList></AccessControlPolicy>')
	}
	if has_key(target.query, 'tagging') {
		tags := s.volume.get_tags(target.bucket, target.key) or { return storage_failure(err, target) }
		return xml_ok(tagging(tags))
	}
	if has_key(target.query, 'retention') || has_key(target.query, 'legal-hold') {
		version_id := target.query.get('versionId') or { '' }
		stat := s.version_stat(target, version_id) or { return storage_failure(err, target) }
		if has_key(target.query, 'retention') {
			return xml_ok(retention_xml(stat.retention_mode, stat.retention_until))
		}
		return xml_ok(legal_hold_xml(stat.legal_hold))
	}
	if has_key(target.query, 'uploadId') {
		upload_id := target.query.get('uploadId') or { '' }
		parts := s.volume.list_parts(target.bucket, target.key, upload_id) or {
			return storage_failure(err, target)
		}
		return xml_ok(list_parts(target.bucket, target.key, upload_id, parts))
	}
	if version_id := target.query.get('versionId') {
		stat := s.volume.stat_version(target.bucket, target.key, version_id) or {
			return storage_failure(err, target)
		}
		if stat.delete_marker {
			return delete_marker_response(stat)
		}
		_, customer_key := sse_of(req) or {
			return failure(http.Status.bad_request, 'InvalidArgument', '${err}', target.bucket,
				target.key)
		}
		body := s.volume.get_version_bytes(target.bucket, target.key, version_id, customer_key) or {
			return storage_failure(err, target)
		}
		return object_ok(body.bytestr(), stat)
	}
	stat := s.volume.stat(target.bucket, target.key) or { return storage_failure(err, target) }
	if stat.delete_marker {
		return delete_marker_response(stat)
	}
	verdict := read_verdict(stat, req)
	if verdict.stop {
		return verdict_response(verdict, target)
	}
	body := s.read_object(req, target) or { return storage_failure(err, target) }
	return object_ok(body, stat)
}

// version_stat reads one version when an id is given and the current version
// otherwise. Retention and legal hold apply to a version, so both forms exist.
// resolve_version turns an optional version id into the version to modify.
fn (s Service) resolve_version(target Target, version_id string) !string {
	if version_id.len > 0 {
		return version_id
	}
	stat := s.volume.stat(target.bucket, target.key)!
	return stat.version
}

fn (s Service) version_stat(target Target, version_id string) !store.Stat {
	if version_id.len == 0 {
		return s.volume.stat(target.bucket, target.key)
	}
	return s.volume.stat_version(target.bucket, target.key, version_id)
}

// read_object returns the bytes a GET should send, honouring a Range header.
fn (s Service) read_object(req http.Request, target Target) !string {
	_, customer_key := sse_of(req)!
	range_header := req.header.get(.range) or {
		body := s.volume.get(target.bucket, target.key, customer_key)!
		return body.bytestr()
	}
	start, end := parse_range(range_header)!
	body := s.volume.get_range(target.bucket, target.key, start, end, customer_key)!
	return body.bytestr()
}

fn (s Service) put(req http.Request, target Target) http.Response {
	if target.bucket.len == 0 {
		return failure(http.Status.method_not_allowed, 'MethodNotAllowed', 'missing bucket',
			'', '')
	}
	if target.key.len == 0 {
		if response := s.bucket_extra(.put, req, target) {
			return response
		}
		if has_key(target.query, 'versioning') {
			state := parse_versioning(req.data) or {
				return failure(http.Status.bad_request, 'MalformedXML', '${err}', target.bucket,
					'')
			}
			current := s.volume.bucket_config(target.bucket) or {
				return storage_failure(err, target)
			}
			s.volume.put_bucket_config(target.bucket, meta.BucketConfig{
				versioning:     state
				object_lock:    current.object_lock
				retention_mode: current.retention_mode
				retention_days: current.retention_days
			}) or {
				return storage_failure(err, target)
			}
			return empty(http.Status.ok)
		}
		if has_key(target.query, 'object-lock') {
			enabled, mode, days := parse_object_lock(req.data) or {
				return failure(http.Status.bad_request, 'MalformedXML', '${err}', target.bucket, '')
			}
			current := s.volume.bucket_config(target.bucket) or {
				return storage_failure(err, target)
			}
			s.volume.put_bucket_config(target.bucket, meta.BucketConfig{
				versioning:     current.versioning
				object_lock:    enabled || current.object_lock
				retention_mode: mode
				retention_days: days
			}) or {
				return storage_failure(err, target)
			}
			return empty(http.Status.ok)
		}
		if has_key(target.query, 'lifecycle') {
			rules := parse_lifecycle(req.data) or {
				return failure(http.Status.bad_request, 'MalformedXML', '${err}', target.bucket,
					'')
			}
			s.volume.put_lifecycle(target.bucket, lifecycle.Config{
				rules: rules
			}) or {
				return storage_failure(err, target)
			}
			return empty(http.Status.ok)
		}
		if has_key(target.query, 'replication') {
			rule := json2.decode[store.Replication](req.data) or {
				return failure(http.Status.bad_request, 'MalformedXML', '${err}', target.bucket,
					'')
			}
			s.volume.put_replication(target.bucket, rule) or {
				return storage_failure(err, target)
			}
			return empty(http.Status.ok)
		}
		s.volume.make_bucket(target.bucket) or { return storage_failure(err, target) }
		return empty(http.Status.ok)
	}
	if has_key(target.query, 'tagging') {
		tags := parse_tagging(req.data) or {
			return failure(http.Status.bad_request, 'MalformedXML', '${err}', target.bucket, target.key)
		}
		s.volume.put_tags(target.bucket, target.key, tags) or { return storage_failure(err, target) }
		return empty(http.Status.ok)
	}
	if has_key(target.query, 'retention') {
		mode, until := parse_retention(req.data) or {
			return failure(http.Status.bad_request, 'MalformedXML', '${err}', target.bucket, target.key)
		}
		version_id := target.query.get('versionId') or { '' }
		version := s.resolve_version(target, version_id) or { return storage_failure(err, target) }
		s.volume.put_retention(target.bucket, target.key, version, mode, until) or {
			return storage_failure(err, target)
		}
		return empty(http.Status.ok)
	}
	if has_key(target.query, 'legal-hold') {
		on := parse_legal_hold(req.data) or {
			return failure(http.Status.bad_request, 'MalformedXML', '${err}', target.bucket, target.key)
		}
		version_id := target.query.get('versionId') or { '' }
		version := s.resolve_version(target, version_id) or { return storage_failure(err, target) }
		s.volume.put_legal_hold(target.bucket, target.key, version, on) or {
			return storage_failure(err, target)
		}
		return empty(http.Status.ok)
	}
	if part := target.query.get('partNumber') {
		upload_id := target.query.get('uploadId') or { '' }
		if copy_source := req.header.get_custom('x-amz-copy-source') {
			src_bucket, src_key := split_copy_source(copy_source)
			copied := s.volume.get(src_bucket, src_key, []u8{}) or { return storage_failure(err, target) }
			stored := s.volume.put_part(target.bucket, target.key, upload_id, part.int(), copied) or {
				return storage_failure(err, target)
			}
			return xml_ok(copy_result(stored.etag))
		}
		stored := s.volume.put_part(target.bucket, target.key, upload_id, part.int(), req.data.bytes()) or {
			return storage_failure(err, target)
		}
		return http.new_response(
			status: .ok
			body:   ''
			header: etag_header(stored.etag)
		)
	}
	if copy_source := req.header.get_custom('x-amz-copy-source') {
		src_bucket, src_key := split_copy_source(copy_source)
		stat := s.volume.copy(src_bucket, src_key, target.bucket, target.key) or {
			return storage_failure(err, target)
		}
		return xml_ok(copy_result(stat.etag))
	}
	content_type := req.header.get(.content_type) or { 'application/octet-stream' }
	mut sse, customer_key := sse_of(req) or {
		return failure(http.Status.bad_request, 'InvalidArgument', '${err}', target.bucket, target.key)
	}
	if sse.len == 0 {
		sse = s.default_sse(target.bucket)
	}
	class := req.header.get_custom('x-amz-storage-class') or { '' }
	checksum_alg := req.header.get_custom('x-amz-checksum-algorithm') or { '' }
	if checksum_alg.len > 0 {
		mismatch := checksum_mismatch(checksum_alg, req)
		if mismatch.len > 0 {
			return failure(http.Status.bad_request, 'BadDigest', mismatch, target.bucket, target.key)
		}
	}
	mut exists := false
	mut current := store.Stat{}
	if got := s.volume.stat(target.bucket, target.key) {
		exists = !got.delete_marker
		current = got
	} else {
		if !'${err}'.contains('not found') {
			return storage_failure(err, target)
		}
	}
	verdict := write_verdict(exists, current, req)
	if verdict.stop {
		return verdict_response(verdict, target)
	}
	body := req.data.bytes()
	stat := s.volume.put(store.PutRequest{
		bucket:        target.bucket
		key:           target.key
		data:          body
		content_type:  content_type
		user_meta:     user_metadata(req)
		sse:           sse
		customer_key:  customer_key
		storage_class: class
		checksum_alg:  checksum_alg
		kms_key_id:    req.header.get_custom('x-amz-server-side-encryption-aws-kms-key-id') or { '' }
		replica:       (req.header.get_custom('x-amz-replication-status') or { '' }) == 'REPLICA'
	}) or {
		return storage_failure(err, target)
	}
	return versioned(http.new_response(
		status: .ok
		body:   ''
		header: object_header(stat, 0)
	), stat)
}

fn (s Service) post(req http.Request, target Target) http.Response {
	if target.key.len == 0 && has_key(target.query, 'delete') {
		return s.delete_objects(req, target)
	}
	if has_key(target.query, 'select') {
		return s.select_object(req, target)
	}
	posted_type := req.header.get(.content_type) or { '' }
	if posted_type.to_lower().contains('multipart/form-data') {
		return s.form_upload(req, target)
	}
	if has_key(target.query, 'restore') {
		return s.restore_object(req, target)
	}
	if has_key(target.query, 'uploads') {
		id := s.volume.create_upload(target.bucket, target.key) or {
			return storage_failure(err, target)
		}
		return xml_ok(initiate_upload(target.bucket, target.key, id))
	}
	if upload_id := target.query.get('uploadId') {
		numbers := parse_complete(req.data) or {
			return failure(http.Status.bad_request, 'MalformedXML', '${err}', target.bucket, target.key)
		}
		stat := s.volume.complete_upload(target.bucket, target.key, upload_id, numbers) or {
			return storage_failure(err, target)
		}
		return versioned(xml_ok(complete_upload(target.bucket, target.key, stat.etag)), stat)
	}
	return failure(http.Status.not_implemented, 'NotImplemented', 'this POST is not implemented',
		target.bucket, target.key)
}

fn (s Service) restore_object(req http.Request, target Target) http.Response {
	days := (between(req.data, '<Days>', '</Days>') or { '0' }).int()
	if days <= 0 {
		return failure(http.Status.bad_request, 'MalformedXML', 'restore days must be positive',
			target.bucket, target.key)
	}
	s.volume.restore_object(target.bucket, target.key, days, time.now().unix()) or {
		return storage_failure(err, target)
	}
	return empty(http.Status.accepted)
}

fn (s Service) delete(req http.Request, target Target) http.Response {
	if target.key.len == 0 {
		if response := s.bucket_extra(.delete, req, target) {
			return response
		}
		if has_key(target.query, 'lifecycle') {
			s.volume.delete_lifecycle(target.bucket) or { return storage_failure(err, target) }
			return empty(http.Status.no_content)
		}
		if has_key(target.query, 'replication') {
			s.volume.delete_replication(target.bucket) or { return storage_failure(err, target) }
			return empty(http.Status.no_content)
		}
		s.volume.remove_bucket(target.bucket) or { return storage_failure(err, target) }
		return empty(http.Status.no_content)
	}
	if has_key(target.query, 'tagging') {
		s.volume.delete_tags(target.bucket, target.key) or { return storage_failure(err, target) }
		return empty(http.Status.no_content)
	}
	if upload_id := target.query.get('uploadId') {
		s.volume.abort_upload(target.bucket, target.key, upload_id) or {
			return storage_failure(err, target)
		}
		return empty(http.Status.no_content)
	}
	if version_id := target.query.get('versionId') {
		bypass := req.header.get_custom('x-amz-bypass-governance-retention') or { '' }
		s.volume.delete_version(target.bucket, target.key, version_id, bypass == 'true') or {
			return storage_failure(err, target)
		}
		return empty(http.Status.no_content)
	}
	stat := s.volume.delete(target.bucket, target.key) or { return storage_failure(err, target) }
	return versioned(empty(http.Status.no_content), stat)
}

fn (s Service) head(req http.Request, target Target) http.Response {
	if target.key.len == 0 {
		if !s.volume.bucket_exists(target.bucket) {
			return failure(http.Status.not_found, 'NoSuchBucket', 'bucket not found', target.bucket,
				'')
		}
		return empty(http.Status.ok)
	}
	stat := s.volume.stat(target.bucket, target.key) or { return storage_failure(err, target) }
	return http.new_response(
		status: .ok
		body:   ''
		header: object_header(stat, 0)
	)
}

fn storage_failure(err IError, target Target) http.Response {
	msg := '${err}'
	code := if msg.contains('quota exceeded') {
		'QuotaExceeded'
	} else if msg.contains('document not found') {
		'NoSuchConfiguration'
	} else if msg.contains('not found') {
		'NoSuchKey'
	} else if msg.contains('object lock') {
		'AccessDenied'
	} else if msg.contains('already exists') {
		'BucketAlreadyExists'
	} else if msg.contains('not empty') {
		'BucketNotEmpty'
	} else if msg.contains('invalid') || msg.contains('must') || msg.contains('requires customer key') {
		'InvalidArgument'
	} else if msg.contains('authentication failed') {
		'AccessDenied'
	} else if msg.contains('archived') {
		'InvalidObjectState'
	} else if msg.contains('site replication') {
		'AccessDenied'
	} else if msg.contains('SSE-KMS is not supported') {
		'NotImplemented'
	} else if msg.contains('not writable') {
		'ServiceUnavailable'
	} else if msg.contains('lock held') {
		'OperationAborted'
	} else {
		eprintln('vfs: ${target.bucket}/${target.key}: ${msg}')
		'InternalError'
	}
	status := if code == 'InternalError' {
		http.Status.internal_server_error
	} else if code == 'NotImplemented' {
		http.Status.not_implemented
	} else if code == 'ServiceUnavailable' {
		http.Status.service_unavailable
	} else if code == 'QuotaExceeded' || code == 'AccessDenied' || code == 'InvalidObjectState' {
		http.Status.forbidden
	} else if code == 'InvalidArgument' {
		http.Status.bad_request
	} else if code == 'BucketAlreadyExists' || code == 'BucketNotEmpty' || code == 'OperationAborted' {
		http.Status.conflict
	} else {
		http.Status.not_found
	}
	return failure(status, code, msg, target.bucket, target.key)
}

fn failure(status http.Status, code string, message string, bucket string, key string) http.Response {
	err := S3Error{
		status:  int(status)
		code:    code
		message: message
		bucket:  bucket
		key:     key
	}
	return http.new_response(
		status: status
		body:   err.body()
		header: http.new_header(key: .content_type, value: 'application/xml')
	)
}

fn xml_ok(body string) http.Response {
	return http.new_response(
		status: .ok
		body:   body
		header: http.new_header(key: .content_type, value: 'application/xml')
	)
}

// json_ok answers a configuration that is stored and exchanged as JSON rather
// than S3 XML. Replication rules name a remote endpoint, which has no place in
// the S3 grammar, so they keep the encoding the volume persists.
fn json_ok(body string) http.Response {
	return http.new_response(
		status: .ok
		body:   body
		header: http.new_header(key: .content_type, value: 'application/json')
	)
}

fn object_ok(body string, stat store.Stat) http.Response {
	return versioned(http.new_response(
		status: .ok
		body:   body
		header: object_header(stat, body.len)
	), stat)
}

// delete_marker_response answers a read of a delete marker. S3 reports it as a
// missing object and names the marker in a header, so clients can tell a
// deletion apart from a key that never existed.
fn delete_marker_response(stat store.Stat) http.Response {
	mut header := http.new_header()
	header.add_custom('x-amz-delete-marker', 'true') or {}
	header.add_custom('x-amz-version-id', stat.version) or {}
	return http.new_response(
		status: .not_found
		body:   S3Error{
			code:    'NoSuchKey'
			message: 'object is a delete marker'
			key:     stat.key
		}.body()
		header: header
	)
}

fn versioned(response http.Response, stat store.Stat) http.Response {
	if stat.version.len == 0 {
		return response
	}
	mut out := response
	out.header.add_custom('x-amz-version-id', stat.version) or {}
	if stat.delete_marker {
		out.header.add_custom('x-amz-delete-marker', 'true') or {}
	}
	return out
}

// user_metadata collects the x-amz-meta-* headers. The prefix is stripped and
// lowercased, which is how S3 stores them.
fn user_metadata(req http.Request) map[string]string {
	mut collected := map[string]string{}
	for key in req.header.keys() {
		lower := key.to_lower()
		if lower.starts_with('x-amz-meta-') {
			collected[lower.all_after('x-amz-meta-')] = req.header.get_custom(key) or { '' }
		}
	}
	return collected
}

fn object_header(stat store.Stat, length int) http.Header {
	mut header := etag_header(stat.etag)
	header.add(.content_type, stat.content_type)
	for name, value in stat.user_meta {
		header.add_custom('x-amz-meta-${name}', value) or {}
	}
	header.add_custom('x-amz-storage-class', stat.storage_class) or {}
	if stat.tier.len > 0 && !stat.archived && stat.restore_until > 0 {
		header.add_custom('x-amz-restore', 'ongoing-request="false", expiry-date="${unix_iso(stat.restore_until)}"') or {}
	}
	if stat.sse == 'SSE-S3' {
		header.add_custom('x-amz-server-side-encryption', 'AES256') or {}
	}
	if stat.sse == 'SSE-C' {
		header.add_custom('x-amz-server-side-encryption-customer-algorithm', 'AES256') or {}
		header.add_custom('x-amz-server-side-encryption-customer-key-MD5', stat.sse_key_md5) or {}
	}
	if length > 0 {
		header.add(.content_length, '${length}')
	}
	return header
}

fn etag_header(etag string) http.Header {
	return http.new_header(key: .etag, value: '"${etag}"')
}

fn empty(status http.Status) http.Response {
	return http.new_response(
		status: status
		body:   ''
	)
}

fn has_key(values urllib.Values, key string) bool {
	return values.get_all(key).len > 0
}

// sse_scheme maps the S3 header value onto the scheme the volume stores. S3
// spells the managed-key scheme AES256; the volume calls it SSE-S3 so the record
// names who holds the key rather than which cipher was used.
fn sse_scheme(header string) string {
	return match header {
		'AES256' { 'SSE-S3' }
		'aws:kms' { 'SSE-KMS' }
		else { header }
	}
}

// sse_of reads the encryption a write asks for. SSE-C carries the key in the
// request and proves it with an MD5; the key never reaches the stored record.
fn sse_of(req http.Request) !(string, []u8) {
	customer := req.header.get_custom('x-amz-server-side-encryption-customer-algorithm') or { '' }
	if customer.len > 0 {
		return sse_customer(req)
	}
	header := req.header.get_custom('x-amz-server-side-encryption') or { '' }
	return sse_scheme(header), []u8{}
}

fn sse_customer(req http.Request) !(string, []u8) {
	algorithm := req.header.get_custom('x-amz-server-side-encryption-customer-algorithm') or { '' }
	if algorithm != 'AES256' {
		return error('SSE-C only supports AES256')
	}
	encoded := req.header.get_custom('x-amz-server-side-encryption-customer-key') or {
		return error('SSE-C key is missing')
	}
	key := base64.decode(encoded)
	if key.len != 32 {
		return error('SSE-C key must be 32 bytes')
	}
	checksum := req.header.get_custom('x-amz-server-side-encryption-customer-key-MD5') or {
		return error('SSE-C key checksum is missing')
	}
	if base64.decode(checksum) != md5.sum(key) {
		return error('SSE-C key checksum does not match')
	}
	return 'SSE-C', key
}

// split_copy_source reads the x-amz-copy-source header, which is `/bucket/key`
// with an optional leading slash.
fn split_copy_source(header string) (string, string) {
	trimmed := header.trim('/').trim_space()
	parts := trimmed.split_nth('/', 2)
	bucket := urllib.query_unescape(parts[0]) or { parts[0] }
	key := if parts.len == 2 { urllib.query_unescape(parts[1]) or { parts[1] } } else { '' }
	return bucket, key
}
