module iam

import auth

// Credentials adapts a directory to the signature verifier. The verifier asks
// only for a secret; authorization happens after the signature checks out.
pub struct Credentials {
pub:
	directory Directory
}

pub fn (c Credentials) secret(access_key string) !string {
	return c.directory.secret(access_key)
}

// identity reads who a verified access key belongs to.
pub fn (c Credentials) identity(access_key string) !auth.Identity {
	key := c.directory.key(access_key)!
	return auth.Identity{
		access_key: access_key
		user:       key.user
	}
}
