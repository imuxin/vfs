// admin serves the management API the deployment and the scenario tests use to
// provision identities. It is a separate surface from S3: requests arrive under
// /rustfs/admin, are signed the same way, and mutate the IAM directory rather
// than object bytes. Only the root key may call it.
module admin

import json2
import net.http
import net.urllib
import auth
import iam
import store

// Service is the admin endpoint.
pub struct Service {
pub:
	directory iam.Directory
	creds     auth.Credentials
	root_key  string
	// signer is the root secret used to sign session tokens. volume is the
	// store a heal or a lifecycle scan walks.
	signer string
	volume store.Volume
}

struct AddUser {
	secret_key string @[json: 'secretKey']
	status     string
	policy     string
}

// handle serves one admin request. Anything outside /rustfs/admin is reported
// as not handled so the caller can pass it on.
pub fn (s Service) handle(req http.Request) ?http.Response {
	url := urllib.parse(req.url) or { return none }
	if !url.path.starts_with('/rustfs/admin/') {
		return none
	}
	verified := auth.verify(req, s.creds) or {
		return denied('${err}')
	}
	if verified.none || verified.identity.access_key != s.root_key {
		return denied('admin requests require the root key')
	}
	path := url.path.trim_string_left('/rustfs/admin')
	query := url.query()
	if path == '/v3/add-user' && req.method == .put {
		return s.add_user(req, query)
	}
	if path == '/v3/set-user-or-group-policy' && req.method == .put {
		return s.set_policy(query)
	}
	if response := s.dispatch(path, req, query) {
		return response
	}
	return http.new_response(
		status: .not_found
		body:   'unknown admin route'
	)
}

// add_user creates a user whose name is the access key and stores the key. The
// optional policy names a policy to attach immediately.
fn (s Service) add_user(req http.Request, query urllib.Values) http.Response {
	access_key := query.get('accessKey') or {
		return bad('missing accessKey')
	}
	body := json2.decode[AddUser](req.data) or {
		return bad('malformed user')
	}
	mut policies := []string{}
	if body.policy.len > 0 {
		policies << body.policy
	}
	s.directory.put_user(iam.User{
		name:     access_key
		status:   'Enabled'
		policies: policies
	}) or {
		return failed('${err}')
	}
	s.directory.put_key(iam.AccessKey{
		access_key: access_key
		secret_key: body.secret_key
		user:       access_key
		status:     'Enabled'
	}) or {
		return failed('${err}')
	}
	return http.new_response(
		status: .ok
		body:   ''
	)
}

// set_policy attaches one named policy to a user, replacing earlier attachments.
fn (s Service) set_policy(query urllib.Values) http.Response {
	name := query.get('userOrGroup') or {
		return bad('missing user')
	}
	policy := query.get('policyName') or {
		return bad('missing policy')
	}
	current := s.directory.user(name) or {
		return bad('no such user')
	}
	s.directory.put_user(iam.User{
		name:     current.name
		status:   current.status
		policies: [policy]
	}) or {
		return failed('${err}')
	}
	return http.new_response(
		status: .ok
		body:   ''
	)
}

fn denied(message string) http.Response {
	return http.new_response(
		status: .forbidden
		body:   message
	)
}

fn bad(message string) http.Response {
	return http.new_response(
		status: .bad_request
		body:   message
	)
}

fn failed(message string) http.Response {
	return http.new_response(
		status: .internal_server_error
		body:   message
	)
}
