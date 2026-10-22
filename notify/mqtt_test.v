module notify

import net
import time

fn test_mqtt_publish_after_connack() {
	packet := mqtt_publish('bucket/events', '{"event":"put"}')
	assert packet[0] == 0x30
	assert packet.bytestr().contains('bucket/events')
	assert encode_remaining(128) == [u8(0x80), 0x01]
	mut listener := net.listen_tcp(.ip, '127.0.0.1:0')!
	addr := listener.addr()!.str()
	spawn reply_mqtt(mut listener)
	publish_mqtt(addr, 'bucket/events', '{"event":"put"}')!
}

fn reply_mqtt(mut listener net.TcpListener) {
	mut conn := listener.accept() or { return }
	conn.set_read_timeout(2 * time.second)
	mut buf := []u8{len: 128}
	conn.read(mut buf) or {}
	conn.write([u8(0x20), 0x02, 0x00, 0x00]) or {}
	conn.read(mut buf) or {}
	conn.close() or {}
}
