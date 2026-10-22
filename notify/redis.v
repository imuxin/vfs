// redis delivers a bucket event with the Redis PUBLISH command. The address
// is host:port. A missing channel uses "vfs".
module notify

import net
import time

pub fn publish(addr string, channel string, message string) ! {
	if addr.len == 0 {
		return error('redis address is required')
	}
	name := if channel.len > 0 { channel } else { 'vfs' }
	mut conn := net.dial_tcp(addr)!
	conn.set_read_timeout(2 * time.second)
	conn.set_write_timeout(2 * time.second)
	conn.write_string(publish_command(name, message))!
	reply := conn.read_line().trim_space()
	conn.close() or {}
	if reply.len == 0 || (reply[0] != `:` && reply[0] != `+`) {
		return error('redis publish rejected')
	}
}

pub fn publish_command(channel string, message string) string {
	return '*3\r\n' + bulk('PUBLISH') + bulk(channel) + bulk(message)
}

fn bulk(value string) string {
	return '\$${value.len}\r\n${value}\r\n'
}
