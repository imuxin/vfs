// replicate pushes an object's bytes or its deletion to another S3 endpoint.
// It speaks the same SigV4 the server accepts, so a vfs node can replicate to
// another vfs node or to any S3 endpoint. The storage layer decides what to
// replicate; this module only delivers it.
module replicate

import crypto.hmac
import crypto.sha256
import encoding.hex
import net.http
import time

// Target is one destination endpoint.
pub struct Target {
pub:
	endpoint   string
	region     string
	access_key string
	secret_key string
}

// put copies an object's bytes to the target bucket.
pub fn put(target Target, bucket string, key string, data []u8, content_type string) ! {
	resp := signed(target, .put, '/${bucket}/${key}', data, content_type, map[string]string{})!
	if resp.status_code >= 300 {
		return error('replication put failed: ${resp.status_code}')
	}
}

// get reads an object's bytes back from the target bucket.
pub fn get(target Target, bucket string, key string) ![]u8 {
	resp := signed(target, .get, '/${bucket}/${key}', []u8{}, '', map[string]string{})!
	if resp.status_code >= 300 {
		return error('tier get failed: ${resp.status_code}')
	}
	return resp.body.bytes()
}

// delete removes an object from the target bucket.
pub fn delete(target Target, bucket string, key string) ! {
	resp := signed(target, .delete, '/${bucket}/${key}', []u8{}, '', map[string]string{})!
	if resp.status_code >= 300 {
		return error('replication delete failed: ${resp.status_code}')
	}
}

// delete_marker tells the target to record a delete marker rather than remove
// the object outright.
pub fn delete_marker(target Target, bucket string, key string) ! {
	resp := signed(target, .delete, '/${bucket}/${key}', []u8{}, '', {
		'x-amz-delete-marker': 'true'
	})!
	if resp.status_code >= 300 {
		return error('replication delete marker failed: ${resp.status_code}')
	}
}

// post_json sends a signed JSON body. The timeout is short so a down peer
// does not stall the owner that recorded the change.
pub fn post_json(target Target, path string, payload []u8) ! {
	resp := signed_in(target, .post, path, payload, 'application/json', map[string]string{},
		2 * time.second, 0)!
	if resp.status_code >= 300 {
		return error('site push failed: ${resp.status_code}')
	}
}

fn signed(target Target, method http.Method, path string, payload []u8, content_type string, extra map[string]string) !http.Response {
	return signed_in(target, method, path, payload, content_type, extra, 30 * time.second, 5)
}

fn signed_in(target Target, method http.Method, path string, payload []u8, content_type string, extra map[string]string, timeout i64, retries int) !http.Response {
	now := time.now().local_to_utc()
	amz := now.custom_format('YYYYMMDDTHHmmss') + 'Z'
	date := now.custom_format('YYYYMMDD')
	payload_hash := hex.encode(sha256.sum256(payload))
	host := target.endpoint.trim_string_left('http://').trim_string_left('https://').all_before('/')
	canonical_headers, signed_headers := canonical_headers(host, payload_hash, amz, extra)
	canonical := '${method.str().to_upper()}\n${path}\n\n${canonical_headers}\n${signed_headers}\n${payload_hash}'
	scope := '${date}/${target.region}/s3/aws4_request'
	string_to_sign := 'AWS4-HMAC-SHA256\n${amz}\n${scope}\n${hex.encode(sha256.sum256(canonical.bytes()))}'
	signature := hex.encode(signing_key(target.secret_key, date, target.region, string_to_sign))
	authorization := 'AWS4-HMAC-SHA256 Credential=${target.access_key}/${scope}, SignedHeaders=${signed_headers}, Signature=${signature}'
	mut header := http.new_header()
	header.add_custom('Authorization', authorization)!
	header.add_custom('x-amz-date', amz)!
	header.add_custom('x-amz-content-sha256', payload_hash)!
	if content_type.len > 0 {
		header.add(.content_type, content_type)
	}
	for name, value in extra {
		header.add_custom(name, value)!
	}
	return http.fetch(http.FetchConfig{
		url:           '${target.endpoint}${path}'
		method:        method
		data:          payload.bytestr()
		header:        header
		read_timeout:  timeout
		write_timeout: timeout
		max_retries:   retries
	})
}

fn canonical_headers(host string, payload_hash string, amz string, extra map[string]string) (string, string) {
	mut pairs := map[string]string{}
	pairs['host'] = host
	pairs['x-amz-content-sha256'] = payload_hash
	pairs['x-amz-date'] = amz
	for name, value in extra {
		pairs[name.to_lower()] = value
	}
	mut names := []string{}
	for name, _ in pairs {
		names << name
	}
	names.sort()
	mut lines := ''
	for name in names {
		lines += '${name}:${pairs[name]}\n'
	}
	return lines, names.join(';')
}

fn signing_key(secret string, date string, region string, string_to_sign string) []u8 {
	dated := hmac.new('AWS4${secret}'.bytes(), date.bytes(), sha256.sum256, sha256.block_size)
	regional := hmac.new(dated, region.bytes(), sha256.sum256, sha256.block_size)
	service := hmac.new(regional, 's3'.bytes(), sha256.sum256, sha256.block_size)
	signing := hmac.new(service, 'aws4_request'.bytes(), sha256.sum256, sha256.block_size)
	return hmac.new(signing, string_to_sign.bytes(), sha256.sum256, sha256.block_size)
}
