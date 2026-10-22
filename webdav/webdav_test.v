module webdav

import encoding.base64
import net.http
import os
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

fn test_basic_roundtrip_propfind_and_move() {
	root := os.join_path(os.temp_dir(), 'vfs-webdav-${os.getpid()}')
	volume := store.open([root])!
	service := Service{
		volume: volume
		creds:  MapCreds{
			secret: 'vfsadmin'
		}
	}
	open := service.handle(request(.propfind, '/pics/', '', {}))
	assert open.status_code == 401
	assert service.handle(request(.mkcol, '/pics', '', basic())).status_code == 201
	assert service.handle(request(.put, '/pics/a.txt', 'hello', basic())).status_code == 201
	read := service.handle(request(.get, '/pics/a.txt', '', basic()))
	assert read.body == 'hello'
	found := service.handle(request(.propfind, '/pics/', '', basic()))
	assert found.status_code == 207
	assert found.body.contains('/pics/a.txt')
	assert found.body.contains('<d:collection/>')
	mut move_headers := basic()
	move_headers['Destination'] = '/pics/b.txt'
	moved := service.handle(request(.move, '/pics/a.txt', '', move_headers))
	assert moved.status_code == 201
	assert service.handle(request(.get, '/pics/b.txt', '', basic())).body == 'hello'
	missing := service.handle(request(.get, '/pics/a.txt', '', basic()))
	assert missing.status_code == 404
}

fn basic() map[string]string {
	token := base64.encode_str('vfsadmin:vfsadmin')
	return {
		'Authorization': 'Basic ${token}'
	}
}

fn request(method http.Method, url string, body string, headers map[string]string) http.Request {
	mut header := http.new_header()
	for name, value in headers {
		header.add_custom(name, value) or {}
	}
	return http.Request{
		method: method
		url:    url
		data:   body
		header: header
	}
}
