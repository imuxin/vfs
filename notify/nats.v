// nats delivers a bucket event with the NATS PUB command. The address is
// host:port. A missing subject uses "vfs". The server's INFO line is read and
// ignored so a normal NATS listener can answer +OK.
module notify

import net
import time

pub fn publish_nats(addr string, subject string, message string) ! {
	if addr.len == 0 {
		return error('nats address is required')
	}
	name := if subject.len > 0 { subject } else { 'vfs' }
	if name.contains(' ') || name.contains('\r') || name.contains('\n') {
		return error('nats subject is invalid')
	}
	mut conn := net.dial_tcp(addr)!
	conn.set_read_timeout(2 * time.second)
	conn.set_write_timeout(2 * time.second)
	_ = conn.read_line()
	conn.write_string(nats_pub(name, message))!
	for _ in 0 .. 4 {
		line := conn.read_line().trim_space()
		if line.starts_with('+OK') {
			conn.close() or {}
			return
		}
		if line.starts_with('-ERR') {
			conn.close() or {}
			return error(line)
		}
	}
	conn.close() or {}
	return error('nats publish rejected')
}

pub fn nats_pub(subject string, message string) string {
	return 'CONNECT {"verbose":false,"pedantic":false,"lang":"vfs","version":"0.1.0"}\r\nPUB ${subject} ${message.len}\r\n${message}\r\n'
}
