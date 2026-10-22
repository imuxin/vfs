module checksum

// sanity_buffer is the xxHash self-test sequence: each byte is the top of a
// generator that starts at prime32 and multiplies by prime64.
fn sanity_buffer(length int) []u8 {
	mut gen := u64(2654435761)
	prime := u64(11400714785074694797)
	mut out := []u8{len: length}
	for i in 0 .. length {
		out[i] = u8(gen >> 56)
		gen *= prime
	}
	return out
}

fn test_xxh64_sanity_vectors() {
	assert xxh64([]u8{}, 0) == u64(0xef46db3751d8e999)
	assert xxh64([]u8{}, u64(2654435761)) == u64(0xac75fda2929b17ef)
	assert xxh64(sanity_buffer(1), 0) == u64(0xe934a84adb052768)
	assert xxh64(sanity_buffer(4), 0) == u64(0x9136a0dca57457ee)
	assert xxh64(sanity_buffer(14), 0) == u64(0x8282dcc4994e35c8)
	assert xxh64(sanity_buffer(222), 0) == u64(0xb641ae8cb691c174)
	assert xxh64(sanity_buffer(222), u64(2654435761)) == u64(0x20cb8ab7ae10c14a)
}

fn test_xxh3_64_covers_every_length_band() {
	bands := {
		0:    u64(0x2d06800538d394c2)
		1:    u64(0xc44bdff4074eecdb)
		6:    u64(0x27b56a84cd2d7325)
		12:   u64(0xa713daf0dfbb77e7)
		24:   u64(0xa3fe70bf9d3510eb)
		48:   u64(0x397da259ecba1f11)
		80:   u64(0xbcdefbbb2c47c90a)
		195:  u64(0xcd94217ee362ec3a)
		403:  u64(0xcdeb804d65c6dea4)
		512:  u64(0x617e49599013cb6b)
		2048: u64(0xdd59e2c3a5f038e0)
		2367: u64(0xcb37aeb9e5d361ed)
	}
	for length, want in bands {
		assert xxh3_64(sanity_buffer(length)) == want
	}
}

fn test_xxh3_128_empty_and_long() {
	lo, hi := xxh3_128([]u8{})
	assert lo == u64(0x6001c324468d497f)
	assert hi == u64(0x99aa06d3014798d8)
	lo1, hi1 := xxh3_128(sanity_buffer(1))
	assert lo1 == u64(0xc44bdff4074eecdb)
	assert hi1 == u64(0xa6cd5e9392000f6a)
	lo403, hi403 := xxh3_128(sanity_buffer(403))
	assert lo403 == u64(0xcdeb804d65c6dea4)
	assert hi403 == u64(0x1b6de21e332dd73d)
	lo2048, hi2048 := xxh3_128(sanity_buffer(2048))
	assert lo2048 == u64(0xdd59e2c3a5f038e0)
	assert hi2048 == u64(0xf736557fd47073a5)
}

fn test_crc64_nvme_catalogue_check() {
	assert crc64_nvme('123456789'.bytes()) == u64(0xae8b14860a799888)
}

fn test_trailing_checksum_roundtrip() {
	body := 'object-bytes'.bytes()
	mut framed := []u8{}
	framed << body
	framed << Kind.sha_256.sum(body)
	assert valid_trailing(.sha_256, framed)!
	framed[framed.len - 1] ^= 1
	assert !valid_trailing(.sha_256, framed)!
}
