module iam

import os

fn test_zip_export_roundtrip_replaces_the_destination() {
	src_root := os.join_path(os.temp_dir(), 'vfs-iam-src-${os.getpid()}')
	dst_root := os.join_path(os.temp_dir(), 'vfs-iam-dst-${os.getpid()}')
	defer {
		os.rmdir_all(src_root) or {}
		os.rmdir_all(dst_root) or {}
	}
	src := open(src_root)!
	install_builtin(src)!
	src.put_user(User{
		name:     'ada'
		status:   'Enabled'
		policies: ['readonly']
	})!
	src.put_key(AccessKey{
		access_key: 'AKIA'
		secret_key: 'secret'
		user:       'ada'
		status:     'Enabled'
	})!
	src.put_group(Group{
		name:     'readers'
		status:   'Enabled'
		members:  ['ada']
		policies: ['readonly']
	})!
	payload := src.export_zip()!
	dst := open(dst_root)!
	dst.put_user(User{
		name:     'extra'
		status:   'Enabled'
		policies: []string{}
	})!
	dst.import_zip(payload)!
	assert dst.user('ada')!.status == 'Enabled'
	assert dst.key('AKIA')!.secret_key == 'secret'
	assert dst.group('readers')!.members == ['ada']
	assert dst.allows('AKIA', 's3:GetObject', 'arn:aws:s3:::b/k')!
	if _ := dst.user('extra') {
		assert false
	}
	if _ := dst.import_zip('not a zip'.bytes()) {
		assert false
	}
}
