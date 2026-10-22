// sigv2 checks AWS Signature Version 2 query authentication. The string to
// sign is the method, three empty header lines, the expiry, and the resource.
// SigV4 stays the default; this exists so an older presigned URL still verifies.
module auth

import crypto.hmac
import crypto.sha1
import encoding.base64
import net.http
import net.urllib
import time

// sigv2_sign is the base64 HMAC-SHA1 of the string to sign.
pub fn sigv2_sign(secret string, string_to_sign string) string {
	mac := hmac.new(secret.bytes(), string_to_sign.bytes(), sha1.sum, sha1.block_size)
	return base64.encode(mac)
}

fn verify_sigv2(req http.Request, creds Credentials) !Result {
	url := urllib.parse(req.url) or { return error('malformed url') }
	query := url.query()
	access_key := query.get('AWSAccessKeyId') or { return error('missing access key') }
	signature := query.get('Signature') or { return error('missing signature') }
	expires_at := query.get('Expires') or { return error('missing expiry') }
	if expires_at.i64() < time.now().unix() {
		return error('presigned url expired')
	}
	secret := creds.secret(access_key) or { return error('unknown access key') }
	string_to_sign := '${req.method.str().to_upper()}\n\n\n${expires_at}\n${url.path}'
	if sigv2_sign(secret, string_to_sign) != signature {
		return error('signature mismatch')
	}
	return Result{
		identity: Identity{
			access_key: access_key
		}
	}
}
