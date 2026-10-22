module auth

import net.http

fn test_presign_rejects_an_unsigned_amz_header() {
	mut header := http.new_header()
	header.add_custom('x-amz-copy-source', '/other/key') or {}
	req := http.Request{
		header: header
	}
	reject_unsigned_amz(req, ['host']) or { return }
	assert false
}
