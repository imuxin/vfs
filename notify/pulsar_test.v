module notify

import net
import time

fn test_pulsar_send_carries_the_event() {
	assert pulsar_simple(pulsar_producer('bucket')).bytestr().contains('bucket')
	frame := pulsar_send('{"event":"put"}')
	assert frame.bytestr().contains('{"event":"put"}')
	mut listener := net.listen_tcp(.ip, '127.0.0.1:0')!
	addr := listener.addr()!.str()
	spawn reply_pulsar(mut listener)
	publish_pulsar(addr, 'bucket', '{"event":"put"}')!
}

fn reply_pulsar(mut listener net.TcpListener) {
	mut conn := listener.accept() or { return }
	conn.set_read_timeout(2 * time.second)
	read_one(mut conn)
	conn.write(pulsar_simple(proto_varint(1, 3))) or { return }
	read_one(mut conn)
	conn.write(pulsar_simple(proto_varint(1, 18))) or { return }
	read_one(mut conn)
	conn.write(pulsar_simple(proto_varint(1, 7))) or { return }
	conn.close() or {}
}

fn read_one(mut conn net.TcpConn) {
	size_bytes := read_exact(mut conn, 4) or { return }
	size := be32(size_bytes)
	if size > 0 {
		read_exact(mut conn, size) or { return }
	}
}
