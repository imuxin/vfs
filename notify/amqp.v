// amqp delivers a bucket event with AMQP 0-9-1 Basic.Publish. The address is
// host:port. A missing routing key uses "vfs". The exchange is the default
// exchange, and the broker is expected to answer the connection handshake.
module notify

import net
import time

const amqp_header = [u8(65), 77, 81, 80, 0, 0, 9, 1]

pub fn publish_amqp(addr string, routing_key string, message string) ! {
	if addr.len == 0 {
		return error('amqp address is required')
	}
	key := if routing_key.len > 0 { routing_key } else { 'vfs' }
	mut conn := net.dial_tcp(addr)!
	conn.set_read_timeout(2 * time.second)
	conn.set_write_timeout(2 * time.second)
	conn.write(amqp_header)!
	expect_method(mut conn, 10, 10)!
	conn.write(method_frame(0, 10, 11, start_ok()))!
	expect_method(mut conn, 10, 30)!
	conn.write(method_frame(0, 10, 31, tune_ok()))!
	conn.write(method_frame(0, 10, 40, open_vhost()))!
	expect_method(mut conn, 10, 41)!
	conn.write(method_frame(1, 20, 10, shortstr('')))!
	expect_method(mut conn, 20, 11)!
	conn.write(method_frame(1, 60, 40, publish_args(key)))!
	conn.write(content_header(1, message.len))!
	conn.write(frame(3, 1, message.bytes()))!
	conn.close() or {}
}

fn expect_method(mut conn net.TcpConn, class_id u16, method_id u16) ! {
	payload := read_frame(mut conn)!
	if payload.len < 4 {
		return error('amqp short method')
	}
	class_got := u16(payload[0]) << 8 | u16(payload[1])
	method_got := u16(payload[2]) << 8 | u16(payload[3])
	if class_got != class_id || method_got != method_id {
		return error('amqp unexpected method')
	}
}

fn read_frame(mut conn net.TcpConn) ![]u8 {
	head := read_exact(mut conn, 7)!
	size := int(head[3]) << 24 | int(head[4]) << 16 | int(head[5]) << 8 | int(head[6])
	if size < 0 || size > 1024 * 1024 {
		return error('amqp frame is too large')
	}
	payload := read_exact(mut conn, size)!
	end := read_exact(mut conn, 1)!
	if end[0] != 0xCE {
		return error('amqp frame end is missing')
	}
	return payload
}

fn read_exact(mut conn net.TcpConn, want int) ![]u8 {
	if want == 0 {
		return []u8{}
	}
	mut got := []u8{}
	mut buf := []u8{len: want}
	for got.len < want {
		n := conn.read(mut buf) or { return error('amqp read failed') }
		if n <= 0 {
			break
		}
		got << buf[..n]
	}
	if got.len < want {
		return error('amqp short read')
	}
	return got
}

fn method_frame(channel u16, class_id u16, method_id u16, args []u8) []u8 {
	mut payload := []u8{}
	payload << u16be(class_id)
	payload << u16be(method_id)
	payload << args
	return frame(1, channel, payload)
}

fn content_header(channel u16, size int) []u8 {
	mut payload := []u8{}
	payload << u16be(60)
	payload << u16be(0)
	payload << u64be(u64(size))
	payload << u16be(0)
	return frame(2, channel, payload)
}

fn frame(typ u8, channel u16, payload []u8) []u8 {
	mut out := []u8{}
	out << typ
	out << u16be(channel)
	out << u32be(u32(payload.len))
	out << payload
	out << u8(0xCE)
	return out
}

fn start_ok() []u8 {
	mut args := []u8{}
	args << u32be(0)
	args << shortstr('PLAIN')
	mut response := []u8{}
	response << u8(0)
	response << 'guest'.bytes()
	response << u8(0)
	response << 'guest'.bytes()
	args << longstr(response)
	args << shortstr('en_US')
	return args
}

fn tune_ok() []u8 {
	mut args := []u8{}
	args << u16be(0)
	args << u32be(0)
	args << u16be(0)
	return args
}

fn open_vhost() []u8 {
	mut args := shortstr('/')
	args << u8(0)
	return args
}

fn publish_args(key string) []u8 {
	mut args := []u8{}
	args << u16be(0)
	args << shortstr('')
	args << shortstr(key)
	args << u8(0)
	return args
}

fn shortstr(value string) []u8 {
	mut out := []u8{}
	out << u8(value.len)
	out << value.bytes()
	return out
}

fn longstr(value []u8) []u8 {
	mut out := []u8{}
	out << u32be(u32(value.len))
	out << value
	return out
}

fn u16be(value u16) []u8 {
	return [u8(value >> 8), u8(value)]
}

fn u32be(value u32) []u8 {
	return [u8(value >> 24), u8(value >> 16), u8(value >> 8), u8(value)]
}

fn u64be(value u64) []u8 {
	mut out := []u8{cap: 8}
	for shift := 56; shift >= 0; shift -= 8 {
		out << u8(value >> shift)
	}
	return out
}
