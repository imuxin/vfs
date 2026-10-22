module iam

import encoding.base32
import os
import time

fn test_group_policy_and_service_key_restriction() {
	root := os.join_path(os.temp_dir(), 'vfs-iam-${os.getpid()}')
	defer { os.rmdir_all(root) or {} }
	directory := open(root)!
	install_builtin(directory)!
	directory.put_user(User{
		name:     'ada'
		status:   'Enabled'
		policies: []string{}
	})!
	directory.put_group(Group{
		name:     'readers'
		status:   'Enabled'
		members:  ['ada']
		policies: ['readonly']
	})!
	directory.put_key(AccessKey{
		access_key: 'AKIA'
		secret_key: 'secret'
		user:       'ada'
		status:     'Enabled'
	})!
	assert directory.allows('AKIA', 's3:GetObject', 'arn:aws:s3:::b/k')!
	assert !directory.allows('AKIA', 's3:PutObject', 'arn:aws:s3:::b/k')!
	directory.put_key(AccessKey{
		access_key: 'AKIA'
		secret_key: 'secret'
		user:       'ada'
		status:     'Enabled'
		policies:   ['writeonly']
	})!
	assert !directory.allows('AKIA', 's3:GetObject', 'arn:aws:s3:::b/k')!
}

fn test_join_lets_a_bucket_grant_stand_and_a_deny_win() {
	assert join(.abstain, .allow)
	assert !join(.deny, .allow)
	assert !join(.allow, .deny)
	assert !join(.abstain, .abstain)
}

fn test_assume_role_clamps_short_durations() {
	root := os.join_path(os.temp_dir(), 'vfs-sts-${os.getpid()}')
	defer { os.rmdir_all(root) or {} }
	directory := open(root)!
	install_builtin(directory)!
	directory.put_user(User{
		name:     'ada'
		status:   'Enabled'
		policies: ['readonly']
	})!
	session := directory.assume_role(AssumeRequest{
		user:     'ada'
		duration: 1
		signer:   'root-secret'
	})!
	assert session.expires >= time.now().unix() + 800
	assert session.token.contains('.')
	assert directory.allows(session.access_key, 's3:GetObject', '*')!
	assert directory.secret(session.access_key)! == session.secret_key
}

fn test_totp_accepts_the_current_step() {
	secret_raw := [u8(0x31), 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30]
	secret := base32_of(secret_raw)
	code := hotp(secret_raw, 1_700_000_000 / 30)
	assert totp(secret, 1_700_000_000, code)
	assert !totp(secret, 1_700_000_000, '000000')
}

fn base32_of(raw []u8) string {
	return base32.encode_to_string(raw).trim_right('=')
}
