module notify

import net
import time

fn test_kafka_produce_accepts_a_zero_error() {
	request := kafka_produce('bucket-events', '{"event":"put"}')
	assert request.bytestr().contains('bucket-events')
	assert request.bytestr().contains('{"event":"put"}')
	assert kafka_error(kafka_response()[4..]) == 0
	mut listener := net.listen_tcp(.ip, '127.0.0.1:0')!
	addr := listener.addr()!.str()
	spawn reply_kafka(mut listener)
	publish_kafka(addr, 'bucket-events', '{"event":"put"}')!
}

fn reply_kafka(mut listener net.TcpListener) {
	mut conn := listener.accept() or { return }
	conn.set_read_timeout(2 * time.second)
	mut buf := []u8{len: 1024}
	conn.read(mut buf) or {}
	conn.write(kafka_response()) or {}
	conn.close() or {}
}
