// digest isolates the standard hash functions whose enum names collide with
// the S3 checksum names when they are imported into the same module.
module stdsum

import crypto.sha512

pub fn sum_sha512(data []u8) []u8 {
	return sha512.sum512(data)
}
