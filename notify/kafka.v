// kafka delivers a bucket event with a Kafka Produce request, API version 0.
// The address is host:port. A missing topic uses "vfs". The broker must answer
// with a produce response whose partition error code is zero.
module notify

import hash.crc32
import net
import time

pub fn publish_kafka(addr string, topic string, message string) ! {
	if addr.len == 0 {
		return error('kafka address is required')
	}
	name := if topic.len > 0 { topic } else { 'vfs' }
	mut conn := net.dial_tcp(addr)!
	conn.set_read_timeout(2 * time.second)
	conn.set_write_timeout(2 * time.second)
	request := kafka_produce(name, message)
	conn.write(kafka_size(request))!
	conn.write(request)!
	size_bytes := read_exact(mut conn, 4)!
	size := be32(size_bytes)
	if size <= 0 || size > 1024 * 1024 {
		conn.close() or {}
		return error('kafka response is invalid')
	}
	body := read_exact(mut conn, size)!
	conn.close() or {}
	if kafka_error(body) != 0 {
		return error('kafka produce failed')
	}
}

pub fn kafka_produce(topic string, message string) []u8 {
	mut body := []u8{}
	body << be16_bytes(0)
	body << be16_bytes(0)
	body << be32_bytes(1)
	body << kafka_string('vfs')
	body << be16_bytes(1)
	body << be32_bytes(1000)
	body << be32_bytes(1)
	body << kafka_string(topic)
	body << be32_bytes(1)
	body << be32_bytes(0)
	set := kafka_message_set(message)
	body << be32_bytes(u32(set.len))
	body << set
	return body
}

pub fn kafka_response() []u8 {
	mut body := []u8{}
	body << be32_bytes(1)
	body << be32_bytes(1)
	body << kafka_string('vfs')
	body << be32_bytes(1)
	body << be32_bytes(0)
	body << be16_bytes(0)
	body << []u8{len: 8}
	mut packet := kafka_size(body)
	packet << body
	return packet
}

fn kafka_error(body []u8) int {
	// correlation id, topic count, topic, partition count, partition, error.
	if body.len < 4 {
		return 1
	}
	mut at := 4
	if body.len < at + 4 {
		return 1
	}
	at += 4
	if body.len < at + 2 {
		return 1
	}
	name_len := int(body[at]) << 8 | int(body[at + 1])
	at += 2 + name_len
	at += 4
	at += 4
	if body.len < at + 2 {
		return 1
	}
	return int(body[at]) << 8 | int(body[at + 1])
}

fn kafka_message_set(message string) []u8 {
	mut msg := []u8{}
	msg << u8(0)
	msg << u8(0)
	msg << be32_bytes(u32(-1))
	msg << be32_bytes(u32(message.len))
	msg << message.bytes()
	crc := crc32.sum(msg)
	mut message_bytes := []u8{}
	message_bytes << be32_bytes(crc)
	message_bytes << msg
	mut set := []u8{}
	set << []u8{len: 8}
	set << be32_bytes(u32(message_bytes.len))
	set << message_bytes
	return set
}

fn kafka_size(payload []u8) []u8 {
	return be32_bytes(u32(payload.len))
}

fn kafka_string(value string) []u8 {
	mut out := be16_bytes(u16(value.len))
	out << value.bytes()
	return out
}

fn be16_bytes(value u16) []u8 {
	return [u8(value >> 8), u8(value)]
}

fn be32_bytes(value u32) []u8 {
	return [u8(value >> 24), u8(value >> 16), u8(value >> 8), u8(value)]
}

fn be32(raw []u8) int {
	return int(raw[0]) << 24 | int(raw[1]) << 16 | int(raw[2]) << 8 | int(raw[3])
}
