module deploy

fn test_ellipsis_expands_numbers_and_letters() {
	got := expand('http://node{0...1}/disk{0...1}')!
	assert got == ['http://node0/disk0', 'http://node0/disk1', 'http://node1/disk0', 'http://node1/disk1']
	padded := expand('/data/disk{00...02}')!
	assert padded == ['/data/disk00', '/data/disk01', '/data/disk02']
	letters := expand('/mnt/{a...c}')!
	assert letters == ['/mnt/a', '/mnt/b', '/mnt/c']
	if _ := expand('/data/disk1...3') {
		assert false
	}
}

fn test_volumes_split_local_and_remote() {
	endpoints := volumes(['/data/a', 'http://peer{0...1}:9000/disk'])!
	assert local_paths(endpoints) == ['/data/a']
	assert endpoints.len == 3
	assert endpoints[1].kind == 'remote'
}
