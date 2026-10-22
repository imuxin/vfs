module swift

import crypto.hmac
import crypto.sha1
import encoding.hex
import net.http
import os
import time
import store

struct MapCreds {
	secret string
}

pub fn (m MapCreds) secret(access_key string) !string {
	if access_key != 'vfsadmin' {
		return error('unknown key')
	}
	return m.secret
}

fn test_auth_object_and_temp_url() {
	root := os.join_path(os.temp_dir(), 'vfs-swift-${os.getpid()}')
	volume := store.open([root])!
	service := Service{
		volume: volume
		creds:  MapCreds{
			secret: 'vfsadmin'
		}
		tokens: new_tokens()
	}
	denied := service.handle(request(.get, '/v1/vfsadmin', ''))
	assert denied.status_code == 401
	authed := service.handle(auth_request())
	assert authed.status_code == 200
	token := authed.header.get_custom('X-Auth-Token') or { '' }
	assert token.starts_with('tk_')
	assert service.handle(token_request(.put, '/v1/vfsadmin/pics', '', token)).status_code == 201
	assert service.handle(token_request(.put, '/v1/vfsadmin/pics/a.txt', 'hello', token)).status_code == 201
	got := service.handle(token_request(.get, '/v1/vfsadmin/pics/a.txt', '', token))
	assert got.body == 'hello'
	listed := service.handle(token_request(.get, '/v1/vfsadmin/pics', '', token))
	assert listed.body.contains('a.txt')
	expires := (time.now().unix() + 60).str()
	path := '/v1/vfsadmin/pics/a.txt'
	body := 'GET\n${expires}\n${path}'
	sig := hex.encode(hmac.new('vfsadmin'.bytes(), body.bytes(), sha1.sum, sha1.block_size))
	open := service.handle(request(.get, '${path}?temp_url_sig=${sig}&temp_url_expires=${expires}', ''))
	assert open.status_code == 200
	assert open.body == 'hello'
	assert service.handle(token_request(.put, '/v1/vfsadmin/pics/0001', 'aa', token)).status_code == 201
	assert service.handle(token_request(.put, '/v1/vfsadmin/pics/0002', 'bb', token)).status_code == 201
	slo := '[{"path":"/v1/vfsadmin/pics/0001","etag":"a","size_bytes":2},{"path":"pics/0002","etag":"b","size_bytes":2}]'
	assert service.handle(token_request(.put, '/v1/vfsadmin/pics/whole?multipart-manifest=put', slo, token)).status_code == 201
	whole := service.handle(token_request(.get, '/v1/vfsadmin/pics/whole', '', token))
	assert whole.body == 'aabb'
	raw := service.handle(token_request(.get, '/v1/vfsadmin/pics/whole?multipart-manifest=get', '', token))
	assert raw.body.contains('0001')
	assert service.handle(token_request(.put, '/v1/vfsadmin/pics/big/1', 'cc', token)).status_code == 201
	assert service.handle(token_request(.put, '/v1/vfsadmin/pics/big/2', 'dd', token)).status_code == 201
	mut dynamic := token_request(.put, '/v1/vfsadmin/pics/dynamic', '', token)
	dynamic.header.add_custom('X-Object-Manifest', 'pics/big/') or {}
	assert service.handle(dynamic).status_code == 201
	assert service.handle(token_request(.get, '/v1/vfsadmin/pics/dynamic', '', token)).body == 'ccdd'
}

fn auth_request() http.Request {
	mut header := http.new_header()
	header.add_custom('X-Auth-User', 'vfsadmin') or {}
	header.add_custom('X-Auth-Key', 'vfsadmin') or {}
	return http.Request{
		method: .get
		url:    '/auth/v1.0'
		header: header
	}
}

fn token_request(method http.Method, url string, body string, token string) http.Request {
	mut header := http.new_header()
	header.add_custom('X-Auth-Token', token) or {}
	return http.Request{
		method: method
		url:    url
		data:   body
		header: header
	}
}

fn request(method http.Method, url string, body string) http.Request {
	return http.Request{
		method: method
		url:    url
		data:   body
	}
}
