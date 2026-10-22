// kms wraps and unwraps data keys. It never sees object bytes: the object
// layer encrypts those with the data key this module hands out, and stores the
// wrapped form beside the object. A backend only has to protect 32-byte keys,
// so a local master key and a remote KMS satisfy the same interface.
module kms

import crypto.aes
import crypto.rand

const key_bytes = 32
const nonce_bytes = 12

// Backend protects data keys. wrap returns bytes that only unwrap can read back.
// The context binds a wrapped key to the object it belongs to, so a wrapped key
// copied onto another object fails to unwrap.
pub interface Backend {
	wrap(key []u8, context string) ![]u8
	unwrap(wrapped []u8, context string) ![]u8
}

// Local protects data keys with one AES-256 master key kept by the process. It
// is the backend a deployment uses when no external KMS is configured.
pub struct Local {
	master []u8
}

// local_backend builds a backend from a 32-byte master key.
pub fn local_backend(master []u8) !Local {
	if master.len != key_bytes {
		return error('master key must be ${key_bytes} bytes')
	}
	return Local{
		master: master.clone()
	}
}

fn (b Local) seal(key []u8, context string) ![]u8 {
	aead := aes.new_aes_gcm(b.master)!
	nonce := rand.bytes(nonce_bytes)!
	sealed := aead.encrypt(key, nonce, context.bytes())!
	mut out := []u8{cap: nonce.len + sealed.len}
	out << nonce
	out << sealed
	return out
}

fn (b Local) open(wrapped []u8, context string) ![]u8 {
	if wrapped.len <= nonce_bytes {
		return error('wrapped key is truncated')
	}
	aead := aes.new_aes_gcm(b.master)!
	nonce := wrapped[..nonce_bytes].clone()
	sealed := wrapped[nonce_bytes..].clone()
	return aead.decrypt(sealed, nonce, context.bytes())
}

pub fn (b Local) wrap(key []u8, context string) ![]u8 {
	return b.seal(key, context)
}

pub fn (b Local) unwrap(wrapped []u8, context string) ![]u8 {
	return b.open(wrapped, context)
}

// DataKey is one object's key: plaintext for immediate use, wrapped for storage.
pub struct DataKey {
pub:
	plain   []u8
	wrapped []u8
}

// generate creates a fresh data key and its wrapped form.
pub fn generate(backend Backend, context string) !DataKey {
	plain := rand.bytes(key_bytes)!
	wrapped := backend.wrap(plain, context)!
	return DataKey{
		plain:   plain
		wrapped: wrapped
	}
}

// reveal recovers a data key from its stored wrapped form.
pub fn reveal(backend Backend, wrapped []u8, context string) ![]u8 {
	return backend.unwrap(wrapped, context)
}
