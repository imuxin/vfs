module bitrot

fn published_key() [4]u64 {
	mut key := [4]u64{}
	key[0] = u64(0x0706050403020100)
	key[1] = u64(0x0f0e0d0c0b0a0908)
	key[2] = u64(0x1716151413121110)
	key[3] = u64(0x1f1e1d1c1b1a1918)
	return key
}

fn bytes_to(n int) []u8 {
	mut out := []u8{len: n}
	for i in 0 .. n {
		out[i] = u8(i)
	}
	return out
}

fn test_highway64_published_lengths() {
	key := published_key()
	expected := [
		u64(0x907a56de22c26e53),
		u64(0x7eab43aac7cddd78),
		u64(0xb8d0569ab0b53d62),
		u64(0x5c6befab8a463d80),
		u64(0xf205a46893007eda),
	]
	for size, want in expected {
		got := highway64(key, bytes_to(size))
		assert got == want
	}
	assert highway64(key, bytes_to(32)) == u64(0xa0c964d9ecd580fc)
	assert highway64(key, bytes_to(33)) == u64(0x2c90f73ca03181fc)
	assert highway64(key, bytes_to(64)) == u64(0x75542c5d4cd2a6ff)
}

fn test_highway256_empty_vector() {
	lanes := {
		0: u64(0xdd44482ac2c874f5)
		1: u64(0xd946017313c7351f)
		2: u64(0xb3aebeccb98714ff)
		3: u64(0x41da233145751df4)
	}
	got := highway256(published_key(), []u8{})
	assert got.len == 32
	for lane in 0 .. 4 {
		mut value := u64(0)
		for i in 0 .. 8 {
			value |= u64(got[lane * 8 + i]) << (i * 8)
		}
		assert value == lanes[lane]
	}
}

fn test_frame_roundtrip_rejects_a_flipped_bit() {
	payload := 'shard-bytes'.bytes()
	framed := frame(.highway256s, payload)
	assert open_frame(.highway256s, framed)! == payload
	mut broken := framed.clone()
	broken[broken.len - 1] ^= 0x01
	if _ := open_frame(.highway256s, broken) {
		assert false
	}
	assert open_frame(.none, payload)! == payload
}

fn test_parse_defaults_blank_to_streaming_highway() {
	assert parse('')! == .highway256s
	assert parse('SHA256')! == .sha256
	if _ := parse('crc32') {
		assert false
	}
}
