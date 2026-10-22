// envelope encrypts object bytes with a per-object data key. The key itself is
// not this module's concern: the caller gets it from kms and stores the wrapped
// form. What lands on disk is a nonce, the ciphertext, and the GCM tag, so a
// disk that is copied elsewhere yields nothing without the key.
module envelope

import encoding.base64
import crypto.aes
import crypto.rand

const nonce_bytes = 12

// Envelope is the encryption state stored with an object. mode names the scheme
// (SSE-S3 or SSE-C) and wrapped_key is the data key protected by a master key.
// SSE-C leaves wrapped_key empty, because the customer holds the only key.
pub struct Envelope {
pub:
	mode        string
	wrapped_key string
	key_md5     string
}

// seal encrypts plaintext under a 32-byte data key. The nonce is random and
// travels with the ciphertext, so the same key can seal many objects.
pub fn seal(key []u8, plaintext []u8, context string) ![]u8 {
	aead := aes.new_aes_gcm(key)!
	nonce := rand.bytes(nonce_bytes)!
	sealed := aead.encrypt(plaintext, nonce, context.bytes())!
	mut out := []u8{cap: nonce.len + sealed.len}
	out << nonce
	out << sealed
	return out
}

// open recovers plaintext. A wrong key or a ciphertext moved to another object
// fails the tag check, which is reported as one error either way.
pub fn open(key []u8, sealed []u8, context string) ![]u8 {
	if sealed.len <= nonce_bytes {
		return error('ciphertext is truncated')
	}
	aead := aes.new_aes_gcm(key)!
	nonce := sealed[..nonce_bytes].clone()
	body := sealed[nonce_bytes..].clone()
	return aead.decrypt(body, nonce, context.bytes())
}

// encode renders an envelope as a single header value. The fields contain no
// spaces, so the split round-trips without an escape.
pub fn (e Envelope) encode() string {
	return '${e.mode} ${e.wrapped_key} ${e.key_md5}'
}

// decode reads an envelope back from its header value.
pub fn decode_envelope(raw string) !Envelope {
	parts := raw.split(' ')
	if parts.len != 3 {
		return error('malformed encryption envelope')
	}
	return Envelope{
		mode:        parts[0]
		wrapped_key: parts[1]
		key_md5:     parts[2]
	}
}

// key_context binds ciphertext to the object it was written for.
pub fn key_context(bucket string, key string) string {
	return '${bucket}/${key}'
}

// encode_key renders key bytes for the metadata record.
pub fn encode_key(key []u8) string {
	return base64.encode(key)
}

// decode_key reads key bytes back from the metadata record.
pub fn decode_key(encoded string) []u8 {
	if encoded.len == 0 {
		return []u8{}
	}
	return base64.decode(encoded)
}
