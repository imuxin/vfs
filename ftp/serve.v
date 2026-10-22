// serve accepts FTP control connections. PASV opens a data port on this host.
// One transfer is read or written, then the data connection is closed.
module ftp

import net
import time
import auth
import iam
import store

pub fn serve(volume store.Volume, creds auth.Credentials, directory ?iam.Directory, addr string) {
	mut listener := net.listen_tcp(.ip, addr) or {
		eprintln('vfs: ftp ${addr}: ${err}')
		return
	}
	for {
		mut conn := listener.accept() or { continue }
		spawn talk(conn, volume, creds, directory)
	}
}

pub fn serve_one(mut listener net.TcpListener, volume store.Volume, creds auth.Credentials, directory ?iam.Directory) {
	mut conn := listener.accept() or { return }
	talk(conn, volume, creds, directory)
}

fn talk(conn &net.TcpConn, volume store.Volume, creds auth.Credentials, directory ?iam.Directory) {
	mut link := Link{
		session: Session{
			volume:    volume
			creds:     creds
			directory: directory
		}
	}
	mut control := conn
	control.write_string('220 vfs ftp\r\n') or { return }
	for {
		line := control.read_line()
		if line.len == 0 {
			return
		}
		reply := link.reply(line)
		control.write_string('${reply}\r\n') or { return }
		if reply.starts_with('221') {
			return
		}
	}
}

struct Link {
mut:
	session Session
	pasv    &net.TcpListener = unsafe { nil }
}

fn (mut link Link) reply(line string) string {
	verb, _ := split_command(line.trim_space())
	if verb.to_upper() == 'PASV' {
		return link.open_passive()
	}
	answer := link.session.command(line)
	if !answer.starts_with('150') {
		return answer
	}
	mut data := link.accept_data() or { return '425 ${err}' }
	if link.session.store_key.len > 0 {
		payload := read_data(mut data)
		data.close() or {}
		return link.session.complete_store(payload)
	}
	data.write(link.session.outbound) or {}
	data.close() or {}
	link.session.outbound = []u8{}
	return '226 transfer complete'
}

fn (mut link Link) open_passive() string {
	if !link.session.authed {
		return '530 not logged in'
	}
	if link.pasv != unsafe { nil } {
		link.pasv.close() or {}
	}
	mut listener := net.listen_tcp(.ip, '127.0.0.1:0') or { return '425 cannot open data port' }
	listener.set_accept_timeout(2 * time.second)
	port := listener.addr() or { return '425 cannot open data port' }.port() or { return '425 cannot open data port' }
	link.pasv = listener
	return passive_reply('127.0.0.1', int(port))
}

fn (mut link Link) accept_data() !&net.TcpConn {
	if link.pasv == unsafe { nil } {
		return error('use PASV first')
	}
	mut listener := link.pasv
	return listener.accept()
}

fn read_data(mut conn net.TcpConn) []u8 {
	conn.set_read_timeout(2 * time.second)
	mut all := []u8{}
	mut buf := []u8{len: 4096}
	for all.len < 8 * 1024 * 1024 {
		n := conn.read(mut buf) or { break }
		if n <= 0 {
			break
		}
		all << buf[..n]
	}
	return all
}
