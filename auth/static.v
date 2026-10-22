module auth

// Static is a fixed access-key table. It is the bootstrap credential store:
// one root key, resolved in memory. IAM-backed lookup replaces it later
// without the signature code changing, because both satisfy Credentials.
pub struct Static {
pub:
	keys map[string]string
}

pub fn (s Static) secret(access_key string) !string {
	return s.keys[access_key] or { error('unknown access key') }
}
