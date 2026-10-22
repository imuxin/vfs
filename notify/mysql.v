// mysql delivers a bucket event as one INSERT. The address is host:port.
// The session user and password are "vfs", using mysql_native_password.
// The statement is INSERT INTO vfs_events(channel, body). A missing channel
// uses "vfs".
module notify

import crypto.sha1
import net
import time

pub fn publish_mysql(addr string, channel string, message string) ! {
	if addr.len == 0 {
		return error('mysql address is required')
	}
	name := if channel.len > 0 { channel } else { 'vfs' }
	mut conn := net.dial_tcp(addr)!
	conn.set_read_timeout(2 * time.second)
	conn.set_write_timeout(2 * time.second)
	_, greeting := mysql_read(mut conn)!
	scramble := mysql_scramble(greeting)!
	token := mysql_native_password('vfs', scramble)
	conn.write(mysql_packet(1, mysql_handshake(token)))!
	_, auth := mysql_read(mut conn)!
	if auth.len == 0 || auth[0] != 0x00 {
		conn.close() or {}
		return error('mysql authentication failed')
	}
	mut query := []u8{}
	query << u8(0x03)
	query << mysql_insert(name, message).bytes()
	conn.write(mysql_packet(0, query))!
	_, result := mysql_read(mut conn)!
	conn.close() or {}
	if result.len == 0 || result[0] != 0x00 {
		return error('mysql insert failed')
	}
}

pub fn mysql_insert(channel string, message string) string {
	return "INSERT INTO vfs_events(channel, body) VALUES ('${mysql_quote(channel)}', '${mysql_quote(message)}')"
}

pub fn mysql_native_password(password string, scramble []u8) []u8 {
	stage1 := sha1.sum(password.bytes())
	stage2 := sha1.sum(stage1)
	mut mixed := scramble.clone()
	mixed << stage2
	stage3 := sha1.sum(mixed)
	mut out := []u8{len: stage1.len}
	for i, b in stage1 {
		out[i] = b ^ stage3[i]
	}
	return out
}

fn mysql_quote(value string) string {
	return value.replace('\\', '\\\\').replace("'", "''")
}

fn mysql_handshake(token []u8) []u8 {
	mut payload := []u8{}
	payload << mysql_u32(0x00000200 | 0x00008000 | 0x00080000)
	payload << mysql_u32(16 * 1024 * 1024)
	payload << u8(33)
	payload << []u8{len: 23}
	payload << 'vfs'.bytes()
	payload << u8(0)
	payload << u8(token.len)
	payload << token
	payload << 'mysql_native_password'.bytes()
	payload << u8(0)
	return payload
}

pub fn mysql_scramble(payload []u8) ![]u8 {
	if payload.len == 0 || payload[0] != 10 {
		return error('mysql greeting is invalid')
	}
	mut i := 1
	for i < payload.len && payload[i] != 0 {
		i++
	}
	i++
	i += 4
	if i + 8 >= payload.len {
		return error('mysql greeting is invalid')
	}
	mut scramble := payload[i..i + 8].clone()
	i += 8
	i++
	i += 2
	i++
	i += 2
	i += 2
	if i >= payload.len {
		return error('mysql greeting is invalid')
	}
	auth_len := int(payload[i])
	i++
	i += 10
	rest := auth_len - 8
	if rest < 2 || i + rest > payload.len {
		return error('mysql greeting is invalid')
	}
	scramble << payload[i..i + rest - 1]
	return scramble
}

fn mysql_packet(seq u8, payload []u8) []u8 {
	mut out := []u8{}
	out << u8(payload.len)
	out << u8(payload.len >> 8)
	out << u8(payload.len >> 16)
	out << seq
	out << payload
	return out
}

fn mysql_read(mut conn net.TcpConn) !(u8, []u8) {
	head := read_exact(mut conn, 4)!
	size := int(head[0]) | int(head[1]) << 8 | int(head[2]) << 16
	if size <= 0 || size > 1024 * 1024 {
		return error('mysql packet is invalid')
	}
	payload := read_exact(mut conn, size)!
	return head[3], payload
}

fn mysql_u32(value int) []u8 {
	return [u8(value), u8(value >> 8), u8(value >> 16), u8(value >> 24)]
}
