module layout

fn test_write_quorum_matches_the_parity_rule() {
	assert write_quorum(1, 0) == 1
	assert write_quorum(4, 2) == 3
	assert write_quorum(8, 4) == 5
	assert write_quorum(5, 2) == 3
	assert response_quorum(4) == 2
	assert response_quorum(1) == 1
}

fn test_reduced_redundancy_uses_one_parity_shard() {
	wide := plan(4, 'REDUCED_REDUNDANCY')!
	assert wide.parity_shards == 1
	assert wide.data_shards == 3
	standard := plan(4, 'STANDARD')!
	assert standard.parity_shards == 2
	if _ := storage_class_ok('GLACIER') {
		assert false
	}
	assert effective_class('GLACIER', '') == 'STANDARD'
	assert effective_class('STANDARD', 'WARM') == 'WARM'
}

fn test_siphash_published_vector() {
	key := [u8(0x00), 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
		0x0e, 0x0f]
	assert siphash24([]u8{}, key) == u64(0x726fdb47dd0e0e31)
	msg := [u8(0x00), 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
		0x0e]
	assert siphash24(msg, key) == u64(0xa129ca6149be45e5)
}

fn test_format_roundtrip_and_distribution() {
	base := fresh([4])!
	stamped := base.for_drive(0, 2)!
	parsed := decode_format(stamped.encode())!
	assert parsed.same_deployment(base)
	assert parsed.xl.this == base.xl.sets[0][2]
	assert parsed.xl.distribution_algo == 'SIPMOD+PARITY'
	assert parsed.format == 'xl'
	single := fresh([1])!
	assert single.format == 'xl-single'
	assert pick(.crcmod, 'photos/a', 4, []u8{len: 16}) == pick(.crcmod, 'photos/a', 4, []u8{len: 16})
	assert rotate(.sipmod, 'k', 4, []u8{len: 16}) == 0
}

fn test_set_pick_stays_inside_the_grid() {
	id := [u8(1), 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]
	for i in 0 .. 20 {
		got := pick(.sipmod_parity, 'obj-${i}', 3, id)
		assert got >= 0 && got < 3
	}
}
