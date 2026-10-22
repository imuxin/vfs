// sigv4 checks AWS Signature Version 4, the scheme S3 clients use. The
// canonical request is built exactly as the client built it, so a mismatch is
// an authentication failure rather than a best effort. Only header
// authentication is implemented; presigned query authentication comes later.
module auth

import crypto.hmac
import crypto.sha256
import encoding.hex
import net.http
import net.urllib
import time

const empty_payload_hash = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'

// Identity is who a verified request acts as.
pub struct Identity {
pub:
	access_key string
	// user is the identity the key belongs to. The static credential store leaves
	// it empty; the IAM directory fills it in.
	user string
}

// Credentials resolves an access key to its secret. The server supplies one;
// tests supply another. Keeping the lookup out of the signature code means the
// algorithm never learns where keys are stored.
pub interface Credentials {
	secret(access_key string) !string
}

struct HeaderAuth {
	access_key string
	date       string
	region     string
	service    string
	signed     []string
	signature  string
}

// Result distinguishes a verified caller from an anonymous request. A bad
// signature is an error, not an anonymous result, so a client cannot skip
// authentication by sending a malformed header.
pub struct Result {
pub:
	identity Identity
	none     bool
}

// verify checks the Authorization header against the request. A request
// without one may instead carry its signature in the query string, which is how
// a presigned URL authenticates.
pub fn verify(req http.Request, creds Credentials) !Result {
	authorization := req.header.get(http.CommonHeader.authorization) or {
		return verify_presigned(req, creds)
	}
	if !authorization.starts_with('AWS4-HMAC-SHA256 ') {
		return error('unsupported authorization scheme')
	}
	parsed := parse_header(authorization)!
	secret := creds.secret(parsed.access_key) or {
		return error('unknown access key')
	}
	canonical := canonical_request(req, parsed.signed)
	string_to_sign := 'AWS4-HMAC-SHA256\n${amz_date(req)}\n${scope(parsed)}\n${hex256(canonical.bytes())}'
	expected := hex.encode(signing_key_sign(secret, parsed, string_to_sign))
	if !constant_eq(expected, parsed.signature) {
		return error('signature mismatch')
	}
	return Result{
		identity: Identity{
			access_key: parsed.access_key
		}
	}
}

// verify_presigned checks a signature carried in the query string. The
// signature parameter itself is excluded from the canonical request, and the
// payload is the literal UNSIGNED-PAYLOAD because the URL was signed before the
// body existed. X-Amz-Expires bounds how long the URL stays valid.
fn verify_presigned(req http.Request, creds Credentials) !Result {
	url := urllib.parse(req.url) or {
		return Result{
			none: true
		}
	}
	query := url.query()
	algorithm := query.get('X-Amz-Algorithm') or {
		if query.get('AWSAccessKeyId') or { '' }.len > 0 {
			return verify_sigv2(req, creds)
		}
		return Result{
			none: true
		}
	}
	if algorithm != 'AWS4-HMAC-SHA256' {
		return error('unsupported authorization scheme')
	}
	parsed := parse_query(query)!
	expires(query, parsed)!
	secret := creds.secret(parsed.access_key) or { return error('unknown access key') }
	canonical := presigned_canonical(req, parsed.signed)
	amz := query.get('X-Amz-Date') or { return error('missing presign date') }
	string_to_sign := 'AWS4-HMAC-SHA256\n${amz}\n${scope(parsed)}\n${hex256(canonical.bytes())}'
	expected := hex.encode(signing_key_sign(secret, parsed, string_to_sign))
	if !constant_eq(expected, parsed.signature) {
		return error('signature mismatch')
	}
	reject_unsigned_amz(req, parsed.signed)!
	return Result{
		identity: Identity{
			access_key: parsed.access_key
		}
	}
}

// reject_unsigned_amz refuses a presigned request that carries an x-amz-*
// header the signature did not cover. Those headers would otherwise change
// the request after it was signed.
fn reject_unsigned_amz(req http.Request, signed []string) ! {
	mut covered := map[string]bool{}
	for name in signed {
		covered[name.to_lower()] = true
	}
	for key in req.header.keys() {
		lower := key.to_lower()
		if lower.starts_with('x-amz-') && !covered[lower] {
			return error('unsigned header ${lower}')
		}
	}
}

fn parse_query(query urllib.Values) !HeaderAuth {
	credential := query.get('X-Amz-Credential') or { return error('missing credential') }
	pieces := credential.split('/')
	if pieces.len != 5 {
		return error('malformed credential scope')
	}
	signed := query.get('X-Amz-SignedHeaders') or { return error('missing signed headers') }
	signature := query.get('X-Amz-Signature') or { return error('missing signature') }
	return HeaderAuth{
		access_key: pieces[0]
		date:       pieces[1]
		region:     pieces[2]
		service:    pieces[3]
		signed:     signed.split(';')
		signature:  signature
	}
}

// expires rejects a presigned URL whose validity window has passed. The window
// starts at X-Amz-Date and lasts X-Amz-Expires seconds.
fn expires(query urllib.Values, parsed HeaderAuth) ! {
	seconds := query.get('X-Amz-Expires') or { return error('missing presign expiry') }
	window := seconds.i64()
	if window < 0 {
		return error('invalid presign expiry')
	}
	signed_at := time.parse_format(parsed_date(query), 'YYYYMMDDTHHmmssZ') or {
		return error('invalid presign date')
	}
	if time.now().unix() > signed_at.unix() + window {
		return error('presigned url expired')
	}
}

fn parsed_date(query urllib.Values) string {
	return query.get('X-Amz-Date') or { '' }
}

// presigned_canonical builds the canonical request with the signature parameter
// removed and the payload fixed to UNSIGNED-PAYLOAD.
fn presigned_canonical(req http.Request, signed []string) string {
	url := urllib.parse(req.url) or {
		return 'GET\n/\n\n\n\nUNSIGNED-PAYLOAD'
	}
	mut kept := urllib.new_values()
	for entry in url.query().data {
		if entry.key == 'X-Amz-Signature' {
			continue
		}
		kept.add(entry.key, entry.value)
	}
	mut header_lines := ''
	for name in signed {
		header_lines += '${name}:${header_value(req, name)}\n'
	}
	return '${req.method.str().to_upper()}\n${url.path}\n${kept.encode()}\n${header_lines}\n${signed.join(';')}\nUNSIGNED-PAYLOAD'
}

fn parse_header(header string) !HeaderAuth {
	body := header.all_after('AWS4-HMAC-SHA256 ').trim_space()
	mut fields := map[string]string{}
	for part in body.split(',') {
		kv := part.trim_space().split_nth('=', 2)
		if kv.len != 2 {
			return error('malformed authorization header')
		}
		fields[kv[0]] = kv[1]
	}
	credential := fields['Credential'] or { return error('missing credential') }
	pieces := credential.split('/')
	if pieces.len != 5 {
		return error('malformed credential scope')
	}
	signed := fields['SignedHeaders'] or { return error('missing signed headers') }
	signature := fields['Signature'] or { return error('missing signature') }
	return HeaderAuth{
		access_key: pieces[0]
		date:       pieces[1]
		region:     pieces[2]
		service:    pieces[3]
		signed:     signed.split(';')
		signature:  signature
	}
}

fn amz_date(req http.Request) string {
	return req.header.get_custom('x-amz-date') or { '' }
}

fn scope(parsed HeaderAuth) string {
	return '${parsed.date}/${parsed.region}/${parsed.service}/aws4_request'
}

fn canonical_request(req http.Request, signed []string) string {
	url := urllib.parse(req.url) or {
		return 'GET\n/\n\n\n\n${empty_payload_hash}'
	}
	mut header_lines := ''
	for name in signed {
		value := header_value(req, name)
		header_lines += '${name}:${value}\n'
	}
	payload_hash := req.header.get_custom('x-amz-content-sha256') or { empty_payload_hash }
	query := url.query().encode()
	return '${req.method.str().to_upper()}\n${url.path}\n${query}\n${header_lines}\n${signed.join(';')}\n${payload_hash}'
}

fn header_value(req http.Request, name string) string {
	got := req.header.get_custom(name) or {
		if name == 'host' {
			return req.host
		}
		return ''
	}
	return got.trim_space()
}

// Signer is the client half of header authentication. It fills the same
// canonical request the verifier rebuilds, so a scenario and a real client
// cannot disagree about what was signed.
pub struct Signer {
pub:
	access_key string
	secret_key string
	region     string = 'us-east-1'
	service    string = 's3'
	host       string = '127.0.0.1:9000'
}

// sign returns a copy of req with host, payload hash, date, and Authorization
// set. Headers the caller already added stay unsigned unless they are the
// three this function owns; the verifier only checks the signed set.
pub fn (s Signer) sign(req http.Request) !http.Request {
	if req.url.len == 0 {
		return error('request url is required')
	}
	mut signed_req := req
	amz := time.utc().custom_format('YYYYMMDDTHHmmss') + 'Z'
	payload := hex.encode(sha256.sum256(signed_req.data.bytes()))
	signed_req.header.add_custom('host', s.host)!
	signed_req.header.add_custom('x-amz-date', amz)!
	signed_req.header.add_custom('x-amz-content-sha256', payload)!
	signed_req.host = s.host
	names := ['host', 'x-amz-content-sha256', 'x-amz-date']
	parsed := HeaderAuth{
		access_key: s.access_key
		date:       amz[..8]
		region:     s.region
		service:    s.service
		signed:     names
	}
	canonical := canonical_request(signed_req, names)
	string_to_sign := 'AWS4-HMAC-SHA256\n${amz}\n${scope(parsed)}\n${hex256(canonical.bytes())}'
	signature := hex.encode(signing_key_sign(s.secret_key, parsed, string_to_sign))
	authorization := 'AWS4-HMAC-SHA256 Credential=${s.access_key}/${scope(parsed)}, SignedHeaders=${names.join(';')}, Signature=${signature}'
	signed_req.header.add(.authorization, authorization)
	return signed_req
}

fn signing_key_sign(secret string, parsed HeaderAuth, string_to_sign string) []u8 {
	date := hmac.new('AWS4${secret}'.bytes(), parsed.date.bytes(), sha256.sum256, sha256.block_size)
	region := hmac.new(date, parsed.region.bytes(), sha256.sum256, sha256.block_size)
	service := hmac.new(region, parsed.service.bytes(), sha256.sum256, sha256.block_size)
	signing := hmac.new(service, 'aws4_request'.bytes(), sha256.sum256, sha256.block_size)
	return hmac.new(signing, string_to_sign.bytes(), sha256.sum256, sha256.block_size)
}

fn hex256(data []u8) string {
	return hex.encode(sha256.sum256(data))
}

fn constant_eq(a string, b string) bool {
	if a.len != b.len {
		return false
	}
	mut diff := u8(0)
	for i in 0 .. a.len {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}
