// oidc checks an OpenID Connect identity token and turns it into an STS
// session. The provider record is the trust: issuer, audience, and the HMAC
// secret the identity token was signed with. The session token is still the
// root-signed JWT every other temporary key uses.
module iam

import crypto.hmac
import crypto.sha256
import encoding.base64
import json2
import os

pub struct Provider {
pub:
	id        string
	issuer    string
	audience  string
	client_id string
	secret    string
	policy    string
	enabled   bool
}

pub struct IdentityToken {
pub:
	subject  string
	issuer   string
	audience string
	expires  i64
}

struct OidcClaims {
	iss string
	aud string
	sub string
	exp i64
}

pub fn (d Directory) put_provider(provider Provider) ! {
	if provider.id.len == 0 || provider.id.contains('/') || provider.id.contains('..') {
		return error('invalid provider id')
	}
	if provider.issuer.len == 0 || provider.audience.len == 0 || provider.secret.len == 0 || provider.policy.len == 0 {
		return error('oidc provider is incomplete')
	}
	write(d.path('oidc', provider.id), json2.encode[Provider](provider, escape_unicode: true))!
}

pub fn (d Directory) provider(id string) !Provider {
	return json2.decode[Provider](read(d.path('oidc', id))!)
}

pub fn (d Directory) delete_provider(id string) ! {
	os.rm(d.path('oidc', id))!
}

// discovery_document is the OpenID metadata a client reads before login.
pub fn discovery_document(provider Provider) string {
	issuer := provider.issuer.trim_right('/')
	return '{"issuer":"${issuer}","authorization_endpoint":"${issuer}/authorize","token_endpoint":"${issuer}/token","jwks_uri":"${issuer}/jwks","response_types_supported":["code","id_token"],"subject_types_supported":["public"],"id_token_signing_alg_values_supported":["HS256"]}'
}

// begin_login records a one-time state value for the callback.
pub fn (d Directory) begin_login(provider_id string) !string {
	if _ := d.provider(provider_id) {
	} else {
		return error('oidc provider not found')
	}
	state := fresh_token()
	write(d.path('oidc-state', state), provider_id)!
	return state
}

// complete_callback checks the state and exchanges the identity token.
pub fn (d Directory) complete_callback(state string, id_token string, duration i64, signer string, now i64) !Session {
	provider_id := read(d.path('oidc-state', state)) or { return error('oidc state mismatch') }
	os.rm(d.path('oidc-state', state)) or {}
	return d.assume_web_identity(provider_id.trim_space(), id_token, duration, signer, now)
}

// assume_web_identity verifies the token and issues a session for its subject.
pub fn (d Directory) assume_web_identity(provider_id string, id_token string, duration i64, signer string, now i64) !Session {
	provider := d.provider(provider_id)!
	if !provider.enabled {
		return error('oidc provider is disabled')
	}
	identity := verify_identity(provider.secret, id_token, provider.issuer, provider.audience, now)!
	if _ := d.user(identity.subject) {
	} else {
		d.put_user(User{
			name:     identity.subject
			status:   'Enabled'
			policies: [provider.policy]
		})!
	}
	window := clamp_duration(duration)
	expires := now + window
	access := 'ASIA' + fresh_token()[..12]
	secret := fresh_token()
	token := sign_jwt(signer, access, identity.subject, expires)!
	d.put_key(AccessKey{
		access_key: access
		secret_key: secret
		user:       identity.subject
		status:     'Enabled'
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

// revoke_session removes a temporary key. The user record stays.
pub fn (d Directory) revoke_session(access_key string) ! {
	os.rm(d.path('keys', access_key))!
}

// sign_identity builds an HS256 identity token. Tests and a static provider
// use it; a real issuer produces the same shape.
pub fn sign_identity(secret string, subject string, issuer string, audience string, expires i64) !string {
	header := base64.url_encode('{"alg":"HS256","typ":"JWT"}'.bytes())
	body := base64.url_encode(json2.encode[OidcClaims](OidcClaims{
		iss: issuer
		aud: audience
		sub: subject
		exp: expires
	}, escape_unicode: true).bytes())
	signing := '${header}.${body}'
	mac := hmac.new(secret.bytes(), signing.bytes(), sha256.sum256, sha256.block_size)
	return '${signing}.${base64.url_encode(mac)}'
}

pub fn verify_identity(secret string, token string, issuer string, audience string, now i64) !IdentityToken {
	parts := token.split('.')
	if parts.len != 3 {
		return error('malformed identity token')
	}
	signing := '${parts[0]}.${parts[1]}'
	mac := hmac.new(secret.bytes(), signing.bytes(), sha256.sum256, sha256.block_size)
	if unpadded(base64.url_encode(mac)) != unpadded(parts[2]) {
		return error('identity token signature mismatch')
	}
	claims := json2.decode[OidcClaims](base64.url_decode(parts[1]).bytestr())!
	if claims.iss != issuer || claims.aud != audience {
		return error('identity token claim mismatch')
	}
	if claims.sub.len == 0 {
		return error('identity token missing subject')
	}
	if claims.exp <= now {
		return error('identity token expired')
	}
	return IdentityToken{
		subject:  claims.sub
		issuer:   claims.iss
		audience: claims.aud
		expires:  claims.exp
	}
}

fn unpadded(raw string) string {
	return raw.trim_right('=')
}
