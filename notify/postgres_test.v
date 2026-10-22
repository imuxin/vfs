module notify

import net
import time

fn test_postgres_notify_reaches_ready() {
	sql := pg_notify('bucket_events', "a'b")
	assert sql == "NOTIFY bucket_events, 'a''b'"
	mut listener := net.listen_tcp(.ip, '127.0.0.1:0')!
	addr := listener.addr()!.str()
	spawn reply_postgres(mut listener)
	publish_postgres(addr, 'bucket_events', '{"event":"put"}')!
}

fn reply_postgres(mut listener net.TcpListener) {
	mut conn := listener.accept() or { return }
	conn.set_read_timeout(2 * time.second)
	read_startup(mut conn)
	conn.write(pg_auth_ok()) or { return }
	conn.write(pg_ready()) or { return }
	read_tagged(mut conn)
	conn.write(pg_message(`C`, pg_cstring('NOTIFY'))) or { return }
	conn.write(pg_ready()) or { return }
	conn.close() or {}
}

fn read_tagged(mut conn net.TcpConn) {
	read_exact(mut conn, 1) or { return }
	read_startup(mut conn)
}

fn read_startup(mut conn net.TcpConn) {
	len_bytes := read_exact(mut conn, 4) or { return }
	size := be32(len_bytes)
	if size > 4 {
		read_exact(mut conn, size - 4) or { return }
	}
}

fn pg_auth_ok() []u8 {
	return pg_message(`R`, be32_bytes(0))
}

fn pg_ready() []u8 {
	return pg_message(`Z`, [u8(`I`)])
}
