module ftp

// passive_reply is the 227 line a client parses to open the data connection.
pub fn passive_reply(ip string, port int) string {
	parts := ip.split('.')
	if parts.len != 4 {
		return '425 bad address'
	}
	p1 := port / 256
	p2 := port % 256
	return '227 Entering Passive Mode (${parts[0]},${parts[1]},${parts[2]},${parts[3]},${p1},${p2})'
}

pub fn parse_passive(reply string) !(string, int) {
	open := reply.index('(') or { return error('missing passive address') }
	close := reply.index(')') or { return error('missing passive address') }
	body := reply[open + 1..close]
	parts := body.split(',')
	if parts.len != 6 {
		return error('missing passive address')
	}
	port := parts[4].int() * 256 + parts[5].int()
	return '${parts[0]}.${parts[1]}.${parts[2]}.${parts[3]}', port
}
