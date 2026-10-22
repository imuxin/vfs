// harness stands up one vfs process path: a volume, the root identity, and the
// HTTP endpoint the server binary serves. Scenario tests talk to that endpoint
// with signed requests, the same way a client does.
module scenario

import crypto.rand
import os
import rand as uid
import net.http
import admin
import auth
import iam
import kms
import s3
import server
import store
import swift

struct World {
mut:
	endpoint server.Endpoint
pub:
	base  string
	roots []string
	root  auth.Signer
}

fn open_world(drives int) !World {
	base := os.join_path(os.temp_dir(), 'vfs-scenario-${uid.uuid_v4()}')
	mut roots := []string{cap: drives}
	for index in 0 .. drives {
		roots << os.join_path(base, 'd${index}')
	}
	master := rand.bytes(32)!
	volume := store.open(roots)!.with_kms(kms.local_backend(master)!)
	directory := iam.open(os.join_path(base, 'iam'))!
	iam.install_builtin(directory)!
	directory.put_user(iam.User{
		name:     'vfsadmin'
		status:   'Enabled'
		policies: ['readwrite']
	})!
	directory.put_key(iam.AccessKey{
		access_key: 'vfsadmin'
		secret_key: 'vfsadmin'
		user:       'vfsadmin'
		status:     'Enabled'
	})!
	creds := iam.Credentials{
		directory: directory
	}
	return World{
		base:  base
		roots: roots
		root:  auth.Signer{
			access_key: 'vfsadmin'
			secret_key: 'vfsadmin'
		}
		endpoint: server.Endpoint{
			service: s3_service(volume, creds, directory)
			admin:   admin_service(volume, creds, directory)
			swift_tokens: swift_tokens()
		}
	}
}

fn (w &World) close() {
	os.rmdir_all(w.base) or {}
}

fn signer_for(access string, secret string) auth.Signer {
	return auth.Signer{
		access_key: access
		secret_key: secret
	}
}

fn (mut w World) send(method http.Method, url string, body string) !http.Response {
	return w.send_with(w.root, method, url, body, map[string]string{})
}

fn (mut w World) send_headers(method http.Method, url string, body string, extra map[string]string) !http.Response {
	return w.send_with(w.root, method, url, body, extra)
}

fn (mut w World) send_with(who auth.Signer, method http.Method, url string, body string, extra map[string]string) !http.Response {
	mut header := http.new_header()
	for key, value in extra {
		header.add_custom(key, value)!
	}
	signed := who.sign(http.Request{
		method: method
		url:    url
		data:   body
		header: header
	})!
	return w.endpoint.handle(signed)
}

fn (mut w World) raw(method http.Method, url string, body string) http.Response {
	return w.endpoint.handle(http.Request{
		method: method
		url:    url
		data:   body
	})
}

fn (mut w World) add_user(access string, secret string, policy string) ! {
	body := '{"secretKey":"${secret}","status":"Enabled","policy":"${policy}"}'
	res := w.send(.put, '/rustfs/admin/v3/add-user?accessKey=${access}', body)!
	if res.status_code != 200 {
		return error('add user ${access}: ${res.status_code} ${res.body}')
	}
}

fn expect(res http.Response, status int, what string) {
	assert res.status_code == status, '${what}: got ${res.status_code} body ${res.body}'
}

fn xml_text(body string, open string, close string) string {
	start := body.index(open) or { return '' }
	rest := body[start + open.len..]
	end := rest.index(close) or { return '' }
	return rest[..end]
}

fn version_of(res http.Response) string {
	return res.header.get_custom('x-amz-version-id') or { '' }
}

fn shard_path(root string, bucket string, key string, version string) string {
	return os.join_path(root, bucket, key, 'versions', version, 'shard')
}

fn s3_service(volume store.Volume, creds iam.Credentials, directory iam.Directory) s3.Service {
	return s3.Service{
		volume:    volume
		creds:     creds
		directory: directory
		region:    'us-east-1'
	}
}

fn admin_service(volume store.Volume, creds iam.Credentials, directory iam.Directory) admin.Service {
	return admin.Service{
		directory: directory
		creds:     creds
		root_key:  'vfsadmin'
		signer:    'vfsadmin'
		volume:    volume
	}
}

fn swift_tokens() &swift.Tokens {
	return swift.new_tokens()
}

// drop_shards removes up to count shard files, walking drives in order.
fn drop_shards(roots []string, bucket string, key string, version string, count int) int {
	mut dropped := 0
	for root in roots {
		if dropped >= count {
			break
		}
		path := shard_path(root, bucket, key, version)
		if !os.exists(path) {
			continue
		}
		os.rm(path) or { continue }
		dropped++
	}
	return dropped
}
