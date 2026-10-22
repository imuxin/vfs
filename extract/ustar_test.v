module extract

fn test_ustar_roundtrip_skips_directories_and_rejects_escape() {
	archive := pack([
		Member{
			key:  'photos/a.txt'
			data: 'hello'.bytes()
		},
		Member{
			key:  'b.txt'
			data: 'beta'.bytes()
		},
	])
	found := members(archive)!
	assert found.len == 2
	assert found[0].key == 'photos/a.txt'
	assert found[0].data.bytestr() == 'hello'
	assert found[1].key == 'b.txt'
	if _ := object_key('../secret') {
		assert false
	}
	if _ := object_key('/etc/passwd') {
		assert false
	}
	assert object_key('./photos/a.txt')! == 'photos/a.txt'
}
