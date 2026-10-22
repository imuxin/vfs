// sts issues a temporary access key. The session token is an HMAC JWT so a
// process that knows the signing secret can recognise it, and the key itself
// is what SigV4 verifies. Duration is clamped to the STS window.
module iam

import crypto.hmac
import crypto.sha256
import encoding.base64
import json2
import time

const min_session = i64(900)
const max_session = i64(43200)

pub struct Session {
pub:
	access_key string
	secret_key string
	token      string
	expires    i64
}

pub struct AssumeRequest {
pub:
	user     string
	secret   string
	duration i64
	policy   string
	mfa_code string
	signer   string
}

// assume_role creates a session key for a user. The signer is the root secret
// that produces the JWT. A user with MFA enrolled must present a current code
// or a recovery code.
pub fn (d Directory) assume_role(req AssumeRequest) !Session {
	user := d.user(req.user)!
	if user.status == 'Disabled' {
		return error('user disabled')
	}
	if d.mfa_enrolled(req.user) {
		d.consume_mfa(req.user, req.mfa_code)!
	}
	duration := clamp_duration(req.duration)
	expires := time.now().unix() + duration
	access := 'ASIA' + fresh_token()[..12]
	secret := fresh_token()
	token := sign_jwt(req.signer, access, req.user, expires)!
	mut policies := user.policies.clone()
	if req.policy.len > 0 {
		policies << req.policy
	}
	d.put_key(AccessKey{
		access_key: access
		secret_key: secret
		user:       req.user
		status:     'Enabled'
		policies:   policies
		expires:    expires
		session:    token
	})!
	return Session{
		access_key: access
		secret_key: secret
		token:      token
		expires:    expires
	}
}

fn clamp_duration(asked i64) i64 {
	if asked < min_session {
		return min_session
	}
	if asked > max_session {
		return max_session
	}
	return asked
}

struct Claims {
	sub string
	ak  string
	exp i64
}

fn sign_jwt(secret string, access string, user string, expires i64) !string {
	header := base64.url_encode('{"alg":"HS256","typ":"JWT"}'.bytes())
	body := base64.url_encode(json2.encode[Claims](Claims{
		sub: user
		ak:  access
		exp: expires
	}, escape_unicode: true).bytes())
	signing := '${header}.${body}'
	mac := hmac.new(secret.bytes(), signing.bytes(), sha256.sum256, sha256.block_size)
	return '${signing}.${base64.url_encode(mac)}'
}

fn fresh_token() string {
	return rand_hex(32)
}
