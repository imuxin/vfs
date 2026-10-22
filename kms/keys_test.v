module kms

fn test_missing_kms_key_does_not_fall_back() {
	if _ := material(map[string][]u8{}, 'alias/app') {
		assert false
	}
	got := material({
		'alias/app': []u8{len: 32, init: u8(7)}
	}, 'alias/app')!
	assert got.len == 32
	assert got[0] == 7
}
