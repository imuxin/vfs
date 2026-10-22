// hook is a tiny HTTP server the scenario tests use for object lambda, Vault,
// AWS KMS, and Keystone. It speaks only the responses those clients parse.
module scenario

import os
import net
import time

fn start_hook() !string {
	mut listener := net.listen_tcp(.ip, '127.0.0.1:0')!
	port := listener.addr()!.port()!
	spawn loop_hook(mut listener)
	time.sleep(50 * time.millisecond)
	return 'http://127.0.0.1:${port}'
}

fn loop_hook(mut listener net.TcpListener) {
	for {
		mut conn := listener.accept() or { continue }
		answer_hook(mut conn)
	}
}

fn answer_hook(mut conn net.TcpConn) {
	header, body := read_http(mut conn) or {
		conn.close() or {}
		return
	}
	payload := hook_payload(header, body)
	resp := 'HTTP/1.1 200 OK\r\nContent-Length: ${payload.len}\r\nConnection: close\r\n\r\n${payload}'
	conn.write_string(resp) or {}
	conn.close() or {}
}

fn read_http(mut conn net.TcpConn) !(string, string) {
	conn.set_read_timeout(2 * time.second)
	mut buf := []u8{}
	mut tmp := []u8{len: 4096}
	for buf.len < 1024 * 1024 {
		n := conn.read(mut tmp) or { break }
		if n <= 0 {
			break
		}
		buf << tmp[..n]
		text := buf.bytestr()
		at := text.index('\r\n\r\n') or { continue }
		head := text[..at]
		mut length := 0
		for line in head.split('\r\n') {
			if line.to_lower().starts_with('content-length:') {
				length = line.all_after(':').trim_space().int()
			}
		}
		got := text[at + 4..]
		if got.len >= length {
			return head, got[..length]
		}
	}
	return error('incomplete http request')
}

fn hook_payload(header string, body string) string {
	line := header.all_before('\r\n')
	if line.contains(' /lambda') {
		return body.to_upper()
	}
	if line.contains(' /audit') {
		os.write_file(os.join_path(os.temp_dir(), 'vfs-audit-hit'), body) or {}
		return ''
	}
	if line.contains('/v3/auth/tokens') {
		return '{"token":{"name":"alice","roles":[{"name":"reader"}]}}'
	}
	if line.starts_with('POST ') && line.contains('/v1/secret/data/') {
		name := line.all_after('/v1/secret/data/').all_before(' ')
		os.write_file(os.join_path(os.temp_dir(), 'vfs-kv-${name}'), body) or {}
		return '{}'
	}
	if line.starts_with('GET ') && line.contains('/v1/secret/data/') {
		name := line.all_after('/v1/secret/data/').all_before(' ')
		raw := os.read_file(os.join_path(os.temp_dir(), 'vfs-kv-${name}')) or { return '{}' }
		key := between_json(raw, 'key')
		return '{"data":{"data":{"key":"${key}"}}}'
	}
	if line.contains('/v1/transit/encrypt/') {
		plain := between_json(body, 'plaintext')
		return '{"data":{"ciphertext":"vault:v1:${plain}"}}'
	}
	if line.contains('/v1/transit/decrypt/') {
		cipher := between_json(body, 'ciphertext')
		plain := cipher.all_after('vault:v1:')
		return '{"data":{"plaintext":"${plain}"}}'
	}
	if body.contains('"Plaintext"') {
		plain := between_json(body, 'Plaintext')
		return '{"CiphertextBlob":"${plain}","KeyId":"alias"}'
	}
	if body.contains('"CiphertextBlob"') {
		blob := between_json(body, 'CiphertextBlob')
		return '{"Plaintext":"${blob}"}'
	}
	return ''
}

fn between_json(body string, key string) string {
	token := '"${key}":"'
	at := body.index(token) or { return '' }
	rest := body[at + token.len..]
	end := rest.index('"') or { return '' }
	return rest[..end]
}
