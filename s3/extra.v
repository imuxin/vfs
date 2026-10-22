// extra is the bucket configuration surface: policy, CORS, website, default
// encryption, and the documents S3 stores without this process acting further.
module s3

import os
import net.http
import bucketcfg
import iam
import json2
import store

fn esc_owner(value string) string {
	return value.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
}

fn (s Service) bucket_extra(method http.Method, req http.Request, target Target) ?http.Response {
	if target.key.len > 0 || target.bucket.len == 0 {
		return none
	}
	name := subresource(target)
	if name.len == 0 {
		return none
	}
	return match method {
		.get { s.read_extra(name, target) }
		.put { s.write_extra(name, req, target) }
		.delete { s.clear_extra(name, target) }
		else { none }
	}
}

fn subresource(target Target) string {
	for name in ['policy', 'cors', 'website', 'encryption', 'notification', 'publicAccessBlock',
		'accelerate', 'requestPayment', 'logging', 'quota'] {
		if has_key(target.query, name) {
			return name
		}
	}
	return ''
}

fn (s Service) read_extra(name string, target Target) http.Response {
	if name == 'policy' {
		raw := s.volume.get_doc(target.bucket, 'policy') or { return storage_failure(err, target) }
		policy := json2.decode[bucketcfg.Policy](raw.bytestr()) or { return storage_failure(err, target) }
		status := if bucketcfg.is_public(policy) { 'public' } else { 'private' }
		return json_ok('{"policy":${raw.bytestr()},"status":"${status}"}')
	}
	raw := s.volume.get_doc(target.bucket, name) or { return storage_failure(err, target) }
	return json_ok(raw.bytestr())
}

fn (s Service) write_extra(name string, req http.Request, target Target) http.Response {
	if name == 'policy' {
		policy := json2.decode[bucketcfg.Policy](req.data) or {
			return failure(http.Status.bad_request, 'MalformedXML', '${err}', target.bucket, '')
		}
		access := s.public_access(target.bucket)
		if access.block_public_policy && bucketcfg.is_public(policy) {
			return failure(http.Status.forbidden, 'AccessDenied', 'public bucket policy is blocked',
				target.bucket, '')
		}
	}
	if name == 'quota' {
		if _ := json2.decode[bucketcfg.Quota](req.data) {
		} else {
			return failure(http.Status.bad_request, 'MalformedXML', 'quota must be JSON', target.bucket, '')
		}
	}
	s.volume.put_doc(target.bucket, name, req.data.bytes()) or { return storage_failure(err, target) }
	return empty(http.Status.ok)
}

fn (s Service) clear_extra(name string, target Target) http.Response {
	s.volume.delete_doc(target.bucket, name) or { return storage_failure(err, target) }
	return empty(http.Status.no_content)
}

fn (s Service) public_access(bucket_name string) bucketcfg.PublicAccess {
	raw := s.volume.get_doc(bucket_name, 'publicAccessBlock') or { return bucketcfg.PublicAccess{} }
	return json2.decode[bucketcfg.PublicAccess](raw.bytestr()) or { return bucketcfg.PublicAccess{} }
}

fn (s Service) bucket_verdict(bucket_name string, principal string, action string, resource string) iam.Verdict {
	raw := s.volume.get_doc(bucket_name, 'policy') or { return iam.Verdict.abstain }
	policy := json2.decode[bucketcfg.Policy](raw.bytestr()) or { return iam.Verdict.abstain }
	return match bucketcfg.effect(policy, principal, action, resource) {
		'allow' { iam.Verdict.allow }
		'deny' { iam.Verdict.deny }
		else { iam.Verdict.abstain }
	}
}

fn (s Service) default_sse(bucket_name string) string {
	raw := s.volume.get_doc(bucket_name, 'encryption') or { return '' }
	config := json2.decode[bucketcfg.Encryption](raw.bytestr()) or { return '' }
	return match config.algorithm {
		'AES256' { 'SSE-S3' }
		'aws:kms' { 'SSE-KMS' }
		else { '' }
	}
}

fn (s Service) preflight(req http.Request, target Target) http.Response {
	origin := req.header.get_custom('origin') or {
		return failure(http.Status.forbidden, 'AccessDenied', 'missing origin', target.bucket, '')
	}
	method := req.header.get_custom('access-control-request-method') or { 'GET' }
	raw := s.volume.get_doc(target.bucket, 'cors') or { []u8{} }
	mut rule := bucketcfg.CorsRule{}
	if raw.len == 0 {
		found := global_cors(origin, method) or {
			return failure(http.Status.forbidden, 'AccessDenied', 'cors is not configured', target.bucket, '')
		}
		rule = found
	} else {
		config := json2.decode[bucketcfg.Cors](raw.bytestr()) or {
			return failure(http.Status.bad_request, 'MalformedXML', '${err}', target.bucket, '')
		}
		rule = bucketcfg.cors_match(config.rules, origin, method) or {
			return failure(http.Status.forbidden, 'AccessDenied', 'origin is not allowed', target.bucket, '')
		}
	}
	mut header := http.new_header()
	header.add_custom('access-control-allow-origin', origin) or {}
	header.add_custom('access-control-allow-methods', rule.methods.join(',')) or {}
	if rule.headers.len > 0 {
		header.add_custom('access-control-allow-headers', rule.headers.join(',')) or {}
	}
	return http.new_response(
		status: .ok
		body:   ''
		header: header
	)
}

fn (s Service) website(req http.Request, target Target) ?http.Response {
	if target.bucket.len == 0 {
		return none
	}
	raw := s.volume.get_doc(target.bucket, 'website') or { return none }
	site := json2.decode[bucketcfg.Website](raw.bytestr()) or { return none }
	host := req.header.get_custom('host') or { '' }
	if site.redirect.len > 0 && host == site.host {
		return redirect_to(site.redirect, http.Status.found)
	}
	rule_location := bucketcfg.website_redirect(site, host, target.key)
	if rule_location.len > 0 {
		return redirect_to(rule_location, http.Status.moved_permanently)
	}
	if target.key.len > 0 {
		if stat := s.volume.stat(target.bucket, target.key) {
			object_location := stat.user_meta['website-redirect-location'] or { '' }
			if object_location.len > 0 && host == site.host {
				return redirect_to(object_location, http.Status.moved_permanently)
			}
		}
	}
	key := bucketcfg.website_key(site, host, target.key) or { return none }
	body := s.volume.get(target.bucket, key, []u8{}) or {
		if site.error_doc.len == 0 {
			return none
		}
		err_body := s.volume.get(target.bucket, site.error_doc, []u8{}) or { return none }
		return http.new_response(
			status: .not_found
			body:   err_body.bytestr()
		)
	}
	return http.new_response(
		status: .ok
		body:   body.bytestr()
	)
}

fn redirect_to(location string, status http.Status) http.Response {
	mut header := http.new_header()
	header.add_custom('location', location) or {}
	return http.new_response(
		status: status
		body:   ''
		header: header
	)
}

fn global_cors(origin string, method string) ?bucketcfg.CorsRule {
	raw := first_set(['VFS_CORS_ALLOWED_ORIGINS', 'RUSTFS_CORS_ALLOWED_ORIGINS', 'ENV_CORS_ALLOWED_ORIGINS'])
	if raw.len == 0 {
		return none
	}
	for part in raw.split(',') {
		allowed := part.trim_space()
		if allowed != '*' && allowed != origin {
			continue
		}
		return bucketcfg.CorsRule{
			origins: [origin]
			methods: [method]
			headers: ['*']
		}
	}
	return none
}

fn first_set(names []string) string {
	for name in names {
		value := os.getenv(name)
		if value.len > 0 {
			return value
		}
	}
	return ''
}

struct ObjectLambda {
	url string
}

fn (s Service) maybe_lambda(target Target, body string, stat store.Stat) http.Response {
	raw := s.volume.get_doc(target.bucket, 'object-lambda') or { return object_ok(body, stat) }
	config := json2.decode[ObjectLambda](raw.bytestr()) or { return object_ok(body, stat) }
	if config.url.len == 0 {
		return object_ok(body, stat)
	}
	resp := http.post(config.url, body) or {
		return failure(http.Status.bad_gateway, 'InternalError', 'object lambda failed', target.bucket,
			target.key)
	}
	if resp.status_code >= 300 {
		return failure(http.Status.bad_gateway, 'InternalError', 'object lambda status ${resp.status_code}',
			target.bucket, target.key)
	}
	return object_ok(resp.body, stat)
}

fn (s Service) anonymous_policy(method http.Method, target Target) bool {
	raw := s.volume.get_doc(target.bucket, 'policy') or { return false }
	policy := json2.decode[bucketcfg.Policy](raw.bytestr()) or { return false }
	access := s.public_access(target.bucket)
	if access.restrict_public_buckets {
		return false
	}
	action := action_of(method, target)
	return bucketcfg.allows(policy, '*', action, resource_of(target))
}
