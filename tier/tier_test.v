module tier

import os

fn test_azure_auth_is_rejected_and_archive_roundtrips() {
	if _ := check(Remote{
		name: 'hot'
		kind: 'azure'
		auth: 'service-principal'
	}) {
		assert false
	}
	if _ := check(Remote{
		name: 'hot'
		kind: 'azure'
		auth: 'storage-class'
	}) {
		assert false
	}
	check(Remote{
		name: 'hot'
		kind: 'gcs'
	})!
	root := os.join_path(os.temp_dir(), 'vfs-tier-${os.getpid()}')
	archive := Archive{
		root: root
	}
	remote := Remote{
		name:   'WARM'
		kind:   's3'
		bucket: 'archive'
		prefix: 'p'
	}
	archive.put(remote, 'data', 'a.txt', 'cold'.bytes())!
	assert archive.get(remote, 'data', 'a.txt')!.bytestr() == 'cold'
	archive.clear('WARM')!
	if _ := archive.get(remote, 'data', 'a.txt') {
		assert false
	}
	http_tier := Remote{
		name:     'WARM'
		kind:     's3'
		bucket:   'archive'
		endpoint: 'http://127.0.0.1:9'
	}
	assert http_tier.uses_http()
	azure := Remote{
		name:     'cold'
		kind:     'azure'
		bucket:   'archive'
		endpoint: 'https://account.blob.core.windows.net'
	}
	assert !azure.uses_http()
	if _ := azure.target() {
		assert false
	}
}
