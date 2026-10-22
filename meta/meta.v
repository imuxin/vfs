// meta is the per-object record stored beside its shards. It is JSON rather
// than RustFS's MessagePack xl.meta: the V tree keeps one codec for every
// record it owns, and the fields cover the same facts (version, size, etag,
// checksum, user metadata, storage class).
module meta

import json2
import time

pub struct Object {
pub:
	key           string
	version       string
	size          i64
	etag          string
	content_type  string
	storage_class string
	user_meta     map[string]string
	tags          map[string]string
	sha256        string
	modified      i64
	delete_marker bool
	// retention_until is a unix timestamp. Zero means the version carries no
	// retention. retention_mode is GOVERNANCE or COMPLIANCE.
	retention_mode  string
	retention_until i64
	legal_hold      bool
	// sse names the encryption scheme, empty when the object is plaintext.
	// wrapped_key is the data key sealed by a master key; SSE-C leaves it empty
	// because the customer holds the only copy of the key.
	sse         string
	wrapped_key string
	// sse_key_md5 is the base64 MD5 of an SSE-C key, echoed back so the client can
	// confirm which key was used. It is not enough to recover the key.
	sse_key_md5 string
	// bitrot names the per-shard hash. codec names a compression frame wrapped
	// around the plaintext before encryption. checksum_* is the S3 checksum of
	// that plaintext. placement rotates shard order inside the erasure set.
	bitrot        string
	codec         string
	checksum_alg  string
	checksum      string
	placement   int
	tier          string
	stored_size   i64
	kms_key_id    string
	archived      bool
	restore_until i64
	replica       bool
}

// BucketConfig is the per-bucket state that changes how objects behave:
// versioning and object lock. One record keeps those decisions together
// instead of scattering them across marker files.
pub struct BucketConfig {
pub:
	versioning      string
	object_lock     bool
	retention_mode  string
	retention_days  int
}

pub fn new(key string, size i64, etag string) Object {
	return Object{
		key:           key
		version:       ''
		size:          size
		etag:          etag
		content_type:  'application/octet-stream'
		storage_class: 'STANDARD'
		user_meta:     map[string]string{}
		tags:          map[string]string{}
		sha256:        ''
		modified:      time.now().unix()
	}
}

pub fn (o Object) encode() string {
	return json2.encode[Object](o, escape_unicode: true)
}

pub fn decode(raw string) !Object {
	return json2.decode[Object](raw)
}
