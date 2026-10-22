// postgres delivers a bucket event with NOTIFY. The address is host:port.
// The session uses user and database "vfs". A missing channel uses "vfs".
module notify

import net
import time

pub fn publish_postgres(addr string, channel string, message string) ! {
	if addr.len == 0 {
		return error('postgres address is required')
	}
	name := if channel.len > 0 { channel } else { 'vfs' }
	if !pg_ident(name) {
		return error('postgres channel is invalid')
	}
	mut conn := net.dial_tcp(addr)!
	conn.set_read_timeout(2 * time.second)
	conn.set_write_timeout(2 * time.second)
	conn.write(pg_startup())!
	pg_until_ready(mut conn)!
	conn.write(pg_query(pg_notify(name, message)))!
	pg_until_ready(mut conn)!
	conn.close() or {}
}

pub fn pg_notify(channel string, message string) string {
	return "NOTIFY ${channel}, '${message.replace("'", "''")}'"
}

fn pg_ident(value string) bool {
	if value.len == 0 {
		return false
	}
	for ch in value {
		ok := (ch >= `a` && ch <= `z`) || (ch >= `A` && ch <= `Z`) || (ch >= `0` && ch <= `9`) || ch == `_`
		if !ok {
			return false
		}
	}
	return true
}

fn pg_startup() []u8 {
	mut body := be32_bytes(196608)
	body << pg_cstring('user')
	body << pg_cstring('vfs')
	body << pg_cstring('database')
	body << pg_cstring('vfs')
	body << u8(0)
	mut out := be32_bytes(u32(body.len + 4))
	out << body
	return out
}

fn pg_query(statement string) []u8 {
	mut payload := statement.bytes()
	payload << u8(0)
	return pg_message(`Q`, payload)
}

fn pg_message(tag u8, payload []u8) []u8 {
	mut out := []u8{}
	out << tag
	out << be32_bytes(u32(payload.len + 4))
	out << payload
	return out
}

fn pg_cstring(value string) []u8 {
	mut out := value.bytes()
	out << u8(0)
	return out
}

fn pg_until_ready(mut conn net.TcpConn) ! {
	for _ in 0 .. 8 {
		tag, payload := pg_read(mut conn)!
		if tag == `E` {
			return error('postgres ${payload.bytestr()}')
		}
		if tag == `Z` {
			return
		}
	}
	return error('postgres ready not received')
}

fn pg_read(mut conn net.TcpConn) !(u8, []u8) {
	tag := read_exact(mut conn, 1)!
	len_bytes := read_exact(mut conn, 4)!
	size := be32(len_bytes)
	if size < 4 || size > 1024 * 1024 {
		return error('postgres message is invalid')
	}
	payload := read_exact(mut conn, size - 4)!
	return tag[0], payload
}
