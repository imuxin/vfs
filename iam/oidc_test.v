module iam

import os
import time

fn test_web_identity_session_and_callback_state() {
	root := os.join_path(os.temp_dir(), 'vfs-oidc-${os.getpid()}')
	defer { os.rmdir_all(root) or {} }
	directory := open(root)!
	install_builtin(directory)!
	directory.put_provider(Provider{
		id:        'google'
		issuer:    'https://issuer.example'
		audience:  'vfs'
		client_id: 'client'
		secret:    'oidc-secret'
		policy:    'readonly'
		enabled:   true
	})!
	assert discovery_document(directory.provider('google')!).contains('https://issuer.example/jwks')
	now := time.now().unix()
	token := sign_identity('oidc-secret', 'ada', 'https://issuer.example', 'vfs', now + 600)!
	if _ := verify_identity('oidc-secret', token, 'https://issuer.example', 'other', now) {
		assert false
	}
	if _ := verify_identity('oidc-secret', token, 'https://issuer.example', 'vfs', now + 600) {
		assert false
	}
	state := directory.begin_login('google')!
	session := directory.complete_callback(state, token, 900, 'root-secret', now)!
	assert directory.allows(session.access_key, 's3:GetObject', 'arn:aws:s3:::b/k')!
	assert !directory.allows(session.access_key, 's3:PutObject', 'arn:aws:s3:::b/k')!
	directory.complete_callback(state, token, 900, 'root-secret', now) or { return }
	assert false
}
