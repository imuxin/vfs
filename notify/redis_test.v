module notify

import net
import time

fn test_publish_command_and_live_reply() {
	command := publish_command('bucket-events', '{"event":"put"}')
	assert command.starts_with('*3\r\n')
	assert command.contains('PUBLISH')
	assert command.contains('bucket-events')
	mut listener := net.listen_tcp(.ip, '127.0.0.1:0')!
	addr := listener.addr()!.str()
	spawn reply_publish(mut listener)
	publish(addr, 'bucket-events', '{"event":"put"}')!
}

fn reply_publish(mut listener net.TcpListener) {
	mut conn := listener.accept() or { return }
	conn.set_read_timeout(2 * time.second)
	mut buf := []u8{len: 256}
	conn.read(mut buf) or {}
	conn.write_string(':1\r\n') or {}
	conn.close() or {}
}
