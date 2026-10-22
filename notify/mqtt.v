// mqtt delivers a bucket event with MQTT 3.1.1. The client connects with a
// clean session and publishes at QoS 0, which needs no acknowledgement beyond
// CONNACK. The address is host:port. A missing topic uses "vfs".
module notify

import net
import time

pub fn publish_mqtt(addr string, topic string, message string) ! {
	if addr.len == 0 {
		return error('mqtt address is required')
	}
	name := if topic.len > 0 { topic } else { 'vfs' }
	if name.contains('\u0000') {
		return error('mqtt topic is invalid')
	}
	mut conn := net.dial_tcp(addr)!
	conn.set_read_timeout(2 * time.second)
	conn.set_write_timeout(2 * time.second)
	conn.write(mqtt_connect('vfs'))!
	ack := read_bytes(mut conn, 4)!
	if ack.len < 4 || ack[0] != 0x20 || ack[3] != 0x00 {
		conn.close() or {}
		return error('mqtt connect rejected')
	}
	conn.write(mqtt_publish(name, message))!
	conn.close() or {}
}

pub fn mqtt_connect(client_id string) []u8 {
	mut body := []u8{}
	body << mqtt_str('MQTT')
	body << u8(0x04)
	body << u8(0x02)
	body << [u8(0x00), 0x3c]
	body << mqtt_str(client_id)
	mut packet := []u8{}
	packet << u8(0x10)
	packet << encode_remaining(body.len)
	packet << body
	return packet
}

pub fn mqtt_publish(topic string, message string) []u8 {
	mut body := []u8{}
	body << mqtt_str(topic)
	body << message.bytes()
	mut packet := []u8{}
	packet << u8(0x30)
	packet << encode_remaining(body.len)
	packet << body
	return packet
}

pub fn encode_remaining(n int) []u8 {
	mut value := n
	mut out := []u8{}
	for {
		mut encoded := u8(value % 128)
		value /= 128
		if value > 0 {
			encoded |= 0x80
		}
		out << encoded
		if value == 0 {
			break
		}
	}
	return out
}

fn mqtt_str(value string) []u8 {
	mut out := []u8{}
	out << u8(value.len >> 8)
	out << u8(value.len)
	out << value.bytes()
	return out
}

fn read_bytes(mut conn net.TcpConn, want int) ![]u8 {
	mut got := []u8{}
	mut buf := []u8{len: want}
	for got.len < want {
		n := conn.read(mut buf) or { return error('mqtt read failed') }
		if n <= 0 {
			break
		}
		got << buf[..n]
	}
	if got.len < want {
		return error('mqtt short read')
	}
	return got
}
