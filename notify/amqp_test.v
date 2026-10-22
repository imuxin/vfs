module notify

import net
import time

fn test_amqp_publish_completes_the_handshake() {
	assert amqp_header[0] == u8(`A`)
	assert amqp_header[6] == 9
	mut listener := net.listen_tcp(.ip, '127.0.0.1:0')!
	addr := listener.addr()!.str()
	spawn reply_amqp(mut listener)
	publish_amqp(addr, 'bucket.events', '{"event":"put"}')!
}

fn reply_amqp(mut listener net.TcpListener) {
	mut conn := listener.accept() or { return }
	conn.set_read_timeout(2 * time.second)
	read_exact(mut conn, 8) or { return }
	conn.write(method_frame(0, 10, 10, []u8{})) or { return }
	read_frame(mut conn) or { return }
	conn.write(method_frame(0, 10, 30, []u8{})) or { return }
	read_frame(mut conn) or { return }
	read_frame(mut conn) or { return }
	conn.write(method_frame(0, 10, 41, []u8{})) or { return }
	read_frame(mut conn) or { return }
	conn.write(method_frame(1, 20, 11, []u8{})) or { return }
	read_frame(mut conn) or { return }
	read_frame(mut conn) or { return }
	read_frame(mut conn) or { return }
	conn.close() or {}
}
