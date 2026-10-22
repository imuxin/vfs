module iam

import json2
import net
import time

fn test_plugin_verdict_reads_bool_and_object() {
	assert plugin_verdict('{"result":true}')! == Verdict.allow
	assert plugin_verdict('{"result":false}')! == Verdict.deny
	assert plugin_verdict('{"result":{"allow":true}}')! == Verdict.allow
	assert plugin_verdict('{"allow":false}')! == Verdict.deny
	assert plugin_verdict('{}')! == Verdict.deny
}

fn test_ask_posts_the_input_and_uses_the_reply() {
	mut allow_listener := net.listen_tcp(.ip, '127.0.0.1:0')!
	allow_addr := allow_listener.addr()!.str()
	spawn reply_plugin(mut allow_listener, '{"result":true}')
	allowed := ask('http://${allow_addr}/v1/data/vfs/authz', PluginQuery{
		access_key: 'alice'
		action:     's3:GetObject'
		resource:   'arn:aws:s3:::pics/a.txt'
		bucket:     'pics'
		key:        'a.txt'
	})!
	assert allowed == Verdict.allow

	mut deny_listener := net.listen_tcp(.ip, '127.0.0.1:0')!
	deny_addr := deny_listener.addr()!.str()
	spawn reply_plugin(mut deny_listener, '{"result":{"allow":false}}')
	denied := ask('http://${deny_addr}/v1/data/vfs/authz', PluginQuery{
		access_key: 'alice'
		action:     's3:GetObject'
		resource:   'arn:aws:s3:::pics/a.txt'
		bucket:     'pics'
		key:        'a.txt'
	})!
	assert denied == Verdict.deny
	assert json2.decode[PluginQuery]('{"accessKey":"alice","action":"s3:GetObject","resource":"arn:aws:s3:::pics/a.txt","bucket":"pics","key":"a.txt"}')!.action == 's3:GetObject'
}

fn reply_plugin(mut listener net.TcpListener, body string) {
	mut conn := listener.accept() or { return }
	conn.set_read_timeout(2 * time.second)
	mut buf := []u8{len: 4096}
	conn.read(mut buf) or {}
	payload := 'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: ${body.len}\r\nConnection: close\r\n\r\n${body}'
	conn.write_string(payload) or {}
	conn.close() or {}
}
