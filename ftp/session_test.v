module ftp

import net
import os
import time
import store

struct MapCreds {
	secret string
}

pub fn (m MapCreds) secret(access_key string) !string {
	if access_key != 'vfsadmin' {
		return error('unknown key')
	}
	return m.secret
}

fn test_commands_store_and_fetch_without_a_socket() {
	root := os.join_path(os.temp_dir(), 'vfs-ftp-${os.getpid()}')
	volume := store.open([root])!
	mut session := Session{
		volume: volume
		creds:  MapCreds{
			secret: 'vfsadmin'
		}
	}
	assert session.command('MKD pics').starts_with('530')
	assert session.command('USER vfsadmin') == '331 password required'
	assert session.command('PASS wrong').starts_with('530')
	assert session.command('PASS vfsadmin') == '230 login ok'
	assert session.command('MKD pics') == '257 "/pics" created'
	assert session.command('CWD pics') == '250 directory changed'
	assert session.command('STOR a.txt') == '150 ready for data'
	assert session.complete_store('hello'.bytes()) == '226 transfer complete'
	assert session.command('RETR a.txt') == '150 sending'
	assert session.outbound.bytestr() == 'hello'
	assert session.command('LIST').starts_with('150')
	assert session.outbound.bytestr().contains('a.txt')
	host, port := parse_passive(passive_reply('127.0.0.1', 2121))!
	assert host == '127.0.0.1'
	assert port == 2121
}

fn test_passive_transfer_roundtrip() {
	root := os.join_path(os.temp_dir(), 'vfs-ftp-tcp-${os.getpid()}')
	volume := store.open([root])!
	creds := MapCreds{
		secret: 'vfsadmin'
	}
	mut listener := net.listen_tcp(.ip, '127.0.0.1:0')!
	addr := listener.addr()!.str()
	spawn serve_one(mut listener, volume, creds, none)
	time.sleep(50 * time.millisecond)
	mut control := net.dial_tcp(addr)!
	control.set_read_timeout(2 * time.second)
	assert read_reply(mut control).starts_with('220')
	control.write_string('USER vfsadmin\r\n')!
	assert read_reply(mut control).starts_with('331')
	control.write_string('PASS vfsadmin\r\n')!
	assert read_reply(mut control).starts_with('230')
	control.write_string('MKD pics\r\n')!
	assert read_reply(mut control).starts_with('257')
	control.write_string('CWD pics\r\n')!
	assert read_reply(mut control).starts_with('250')
	control.write_string('PASV\r\n')!
	passive := read_reply(mut control)
	host, port := parse_passive(passive)!
	mut data := net.dial_tcp('${host}:${port}')!
	control.write_string('STOR a.txt\r\n')!
	data.write_string('hello')!
	data.close() or {}
	assert read_reply(mut control).starts_with('226')
	control.write_string('PASV\r\n')!
	again := read_reply(mut control)
	host2, port2 := parse_passive(again)!
	mut fetch := net.dial_tcp('${host2}:${port2}')!
	control.write_string('RETR a.txt\r\n')!
	body := read_socket(mut fetch)
	assert body == 'hello'
	assert read_reply(mut control).starts_with('226')
	control.write_string('QUIT\r\n')!
	assert read_reply(mut control).starts_with('221')
}

fn read_reply(mut conn net.TcpConn) string {
	line := conn.read_line()
	return line.trim_space()
}

fn read_socket(mut conn net.TcpConn) string {
	conn.set_read_timeout(2 * time.second)
	mut all := []u8{}
	mut buf := []u8{len: 64}
	for {
		n := conn.read(mut buf) or { break }
		if n <= 0 {
			break
		}
		all << buf[..n]
	}
	return all.bytestr()
}
