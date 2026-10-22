module notify

import net
import time

fn test_nats_pub_and_ok_reply() {
	body := nats_pub('bucket.events', '{"event":"put"}')
	assert body.contains('PUB bucket.events 15\r\n')
	assert body.ends_with('{"event":"put"}\r\n')
	mut listener := net.listen_tcp(.ip, '127.0.0.1:0')!
	addr := listener.addr()!.str()
	spawn reply_nats(mut listener)
	publish_nats(addr, 'bucket.events', '{"event":"put"}')!
}

fn reply_nats(mut listener net.TcpListener) {
	mut conn := listener.accept() or { return }
	conn.set_read_timeout(2 * time.second)
	conn.write_string('INFO {"server_id":"test"}\r\n') or { return }
	mut buf := []u8{len: 512}
	conn.read(mut buf) or {}
	conn.write_string('+OK\r\n') or {}
	conn.close() or {}
}
