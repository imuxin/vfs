module s3

import os
import net
import time
import auth
import net.http
import net.urllib
import store

fn test_configured_plugin_can_deny_a_caller() {
	base := os.join_path(os.temp_dir(), 'vfs-plugin-${os.getpid()}')
	defer { os.rmdir_all(base) or {} }
	volume := store.open([os.join_path(base, 'd0')])!
	assert volume.policy_plugin().url.len == 0
	mut listener := net.listen_tcp(.ip, '127.0.0.1:0')!
	addr := listener.addr()!.str()
	volume.set_policy_plugin('http://${addr}/v1/data/vfs/authz')!
	spawn reply_deny(mut listener)
	service := Service{
		volume: volume
		creds:  StaticKey{}
	}
	allowed := service.authorize(auth.Identity{
		access_key: 'alice'
	}, http.Method.get, Target{
		bucket: 'pics'
		key:    'a.txt'
		query:  urllib.new_values()
	})!
	assert !allowed
	volume.clear_policy_plugin()!
	assert volume.policy_plugin().url.len == 0
	open := service.authorize(auth.Identity{
		access_key: 'alice'
	}, http.Method.get, Target{
		bucket: 'pics'
		key:    'a.txt'
		query:  urllib.new_values()
	})!
	assert open
}

struct StaticKey {}

fn (s StaticKey) secret(access_key string) !string {
	return 'secret'
}

fn reply_deny(mut listener net.TcpListener) {
	mut conn := listener.accept() or { return }
	conn.set_read_timeout(2 * time.second)
	mut buf := []u8{len: 4096}
	conn.read(mut buf) or {}
	body := '{"result":false}'
	payload := 'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: ${body.len}\r\nConnection: close\r\n\r\n${body}'
	conn.write_string(payload) or {}
	conn.close() or {}
}
