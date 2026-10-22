module objzip

fn test_zip_roundtrip_keeps_object_bytes() {
	packed := encode([
		File{
			name: 'a.txt'
			data: 'alpha'.bytes()
		},
		File{
			name: 'nested/b.txt'
			data: 'beta'.bytes()
		},
	])!
	found := decode(packed)!
	assert found.len == 2
	assert found[0].name == 'a.txt'
	assert found[0].data.bytestr() == 'alpha'
	assert found[1].data.bytestr() == 'beta'
	if _ := encode([
		File{
			name: '../secret'
			data: 'no'.bytes()
		},
	]) {
		assert false
	}
}
