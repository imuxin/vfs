module notify

import net
import time

fn test_mysql_insert_authenticates_and_queries() {
	assert mysql_insert('bucket', "a'b") == "INSERT INTO vfs_events(channel, body) VALUES ('bucket', 'a''b')"
	scramble := []u8{len: 20, init: 1}
	token := mysql_native_password('vfs', scramble)
	assert token.len == 20
	mut listener := net.listen_tcp(.ip, '127.0.0.1:0')!
	addr := listener.addr()!.str()
	spawn reply_mysql(mut listener, token)
	publish_mysql(addr, 'bucket', '{"event":"put"}')!
}

fn reply_mysql(mut listener net.TcpListener, token []u8) {
	mut conn := listener.accept() or { return }
	conn.set_read_timeout(2 * time.second)
	conn.write(mysql_greeting(scramble_bytes())) or { return }
	_, auth := mysql_read(mut conn) or { return }
	if !auth.bytestr().contains(token.bytestr()) {
		return
	}
	conn.write(mysql_ok(2)) or { return }
	mysql_read(mut conn) or { return }
	conn.write(mysql_ok(1)) or { return }
	conn.close() or {}
}

fn scramble_bytes() []u8 {
	return []u8{len: 20, init: 1}
}

fn mysql_greeting(scramble []u8) []u8 {
	mut payload := []u8{}
	payload << u8(10)
	payload << '5.7.0'.bytes()
	payload << u8(0)
	payload << [u8(1), 0, 0, 0]
	payload << scramble[..8]
	payload << u8(0)
	payload << [u8(0xff), 0xff]
	payload << u8(33)
	payload << [u8(0), 0]
	payload << [u8(0), 0]
	payload << u8(21)
	payload << []u8{len: 10}
	payload << scramble[8..]
	payload << u8(0)
	payload << 'mysql_native_password'.bytes()
	payload << u8(0)
	return mysql_packet(0, payload)
}

fn mysql_ok(seq u8) []u8 {
	return mysql_packet(seq, [u8(0x00), 0x00, 0x00, 0x02, 0x00, 0x00, 0x00])
}
