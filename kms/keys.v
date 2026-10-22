// keys resolves an SSE-KMS key id. A missing id is not the SSE-S3 master key:
// the caller must fail the request instead of downgrading.
module kms

pub fn material(keys map[string][]u8, id string) ![]u8 {
	if id.len == 0 {
		return error('SSE-KMS requires a key id')
	}
	found := keys[id] or { return error('SSE-KMS requires a running key backend') }
	if found.len != 32 {
		return error('SSE-KMS key must be 32 bytes')
	}
	return found.clone()
}
