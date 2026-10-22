module worker

import os
import store

fn test_repair_rewrites_a_missing_shard() {
	base := os.join_path(os.temp_dir(), 'vfs-heal-${os.getpid()}')
	defer { os.rmdir_all(base) or {} }
	mut dirs := []string{}
	for index in 0 .. 2 {
		dirs << os.join_path(base, 'd${index}')
	}
	volume := store.open(dirs)!
	volume.make_bucket('pics')!
	body := 'heal me'.bytes()
	volume.put(store.PutRequest{
		bucket: 'pics'
		key:    'a.txt'
		data:   body
	})!
	versions := os.join_path(base, 'd0', 'pics', 'a.txt', 'versions')
	ids := os.ls(versions)!
	os.rm(os.join_path(versions, ids[0], 'shard'))!
	restored := volume.repair('pics', 'a.txt')!
	assert restored >= 1
	assert volume.get('pics', 'a.txt', []u8{})! == body
	os.setenv('VFS_SCANNER_ENABLED', 'false', true)
	assert !scanner_enabled()
	os.setenv('VFS_SCANNER_ENABLED', 'true', true)
	assert scanner_enabled()
}
