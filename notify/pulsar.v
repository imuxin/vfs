// pulsar delivers a bucket event with the Pulsar binary protocol. The address
// is host:port. The client sends CONNECT, waits for a reply, then SEND with a
// CRC32C message frame. A missing topic uses "vfs".
module notify

import hash.crc32
import net
import time

pub fn publish_pulsar(addr string, topic string, message string) ! {
	if addr.len == 0 {
		return error('pulsar address is required')
	}
	name := if topic.len > 0 { topic } else { 'vfs' }
	mut conn := net.dial_tcp(addr)!
	conn.set_read_timeout(2 * time.second)
	conn.set_write_timeout(2 * time.second)
	conn.write(pulsar_simple(pulsar_connect()))!
	read_pulsar(mut conn)!
	conn.write(pulsar_simple(pulsar_producer(name)))!
	read_pulsar(mut conn)!
	conn.write(pulsar_send(message))!
	read_pulsar(mut conn)!
	conn.close() or {}
}

pub fn pulsar_producer(topic string) []u8 {
	mut producer := []u8{}
	producer << proto_bytes(1, topic.bytes())
	producer << proto_varint(2, 1)
	mut cmd := []u8{}
	cmd << proto_varint(1, 5)
	cmd << proto_bytes(5, producer)
	return cmd
}

pub fn pulsar_send(message string) []u8 {
	mut send := []u8{}
	send << proto_varint(1, 1)
	send << proto_varint(2, 1)
	mut cmd := []u8{}
	cmd << proto_varint(1, 6)
	cmd << proto_bytes(6, send)
	return pulsar_payload(cmd, message.bytes())
}

fn pulsar_connect() []u8 {
	mut connect := []u8{}
	connect << proto_bytes(1, 'vfs'.bytes())
	connect << proto_varint(4, 12)
	mut cmd := []u8{}
	cmd << proto_varint(1, 2)
	cmd << proto_bytes(2, connect)
	return cmd
}

fn pulsar_simple(cmd []u8) []u8 {
	mut out := be32_bytes(u32(4 + cmd.len))
	out << be32_bytes(u32(cmd.len))
	out << cmd
	return out
}

fn pulsar_payload(cmd []u8, payload []u8) []u8 {
	mut checked := be32_bytes(u32(0))
	checked << payload
	sum := crc32.sum_crc32c(checked)
	mut tail := []u8{}
	tail << [u8(0x0e), 0x01]
	tail << be32_bytes(sum)
	tail << checked
	mut out := be32_bytes(u32(4 + cmd.len + tail.len))
	out << be32_bytes(u32(cmd.len))
	out << cmd
	out << tail
	return out
}

fn read_pulsar(mut conn net.TcpConn) ! {
	size_bytes := read_exact(mut conn, 4)!
	size := be32(size_bytes)
	if size <= 0 || size > 1024 * 1024 {
		return error('pulsar frame is invalid')
	}
	read_exact(mut conn, size)!
}

fn proto_varint(field int, value u64) []u8 {
	mut out := []u8{}
	out << u8((field << 3) | 0)
	mut n := value
	for {
		mut byte := u8(n & 0x7f)
		n >>= 7
		if n > 0 {
			byte |= 0x80
		}
		out << byte
		if n == 0 {
			break
		}
	}
	return out
}

fn proto_bytes(field int, data []u8) []u8 {
	mut out := []u8{}
	out << u8((field << 3) | 2)
	out << proto_len(data.len)
	out << data
	return out
}

fn proto_len(n int) []u8 {
	mut out := []u8{}
	mut value := n
	for {
		mut byte := u8(value & 0x7f)
		value >>= 7
		if value > 0 {
			byte |= 0x80
		}
		out << byte
		if value == 0 {
			break
		}
	}
	return out
}
