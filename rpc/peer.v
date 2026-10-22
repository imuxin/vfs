// peer is the inter-node channel. The inventory names gRPC; this tree has no
// protobuf stack, so peers authenticate with the same RPC secret over HTTP.
// The secret is VFS_RPC_SECRET, RUSTFS_RPC_SECRET, or the root secret.
module rpc

import crypto.hmac
import crypto.sha256
import encoding.hex
import json2
import net.http
import net.urllib
import store

pub fn signature(secret string, canonical string) string {
	mac := hmac.new(secret.bytes(), canonical.bytes(), sha256.sum, sha256.block_size)
	return hex.encode(mac)
}

pub fn canonical(method string, path string, query string) string {
	return '${method}\n${path}\n${query}'
}

struct StatBody {
pub:
	bucket string
	key    string
	size   i64
	etag   string
}

pub fn serve(req http.Request, volume store.Volume, secret string) http.Response {
	if secret.len == 0 {
		return http.new_response(status: .forbidden, body: 'rpc secret is not configured')
	}
	url := urllib.parse(req.url) or {
		return http.new_response(status: .bad_request, body: 'malformed rpc url')
	}
	if url.path != '/rustfs/rpc/v1/stat' || req.method != .post {
		return http.new_response(status: .not_found, body: 'unknown rpc route')
	}
	bucket := url.query().get('bucket') or { '' }
	key := url.query().get('key') or { '' }
	expected := signature(secret, canonical('POST', url.path, 'bucket=${bucket}&key=${key}'))
	got := req.header.get_custom('x-vfs-rpc') or { '' }
	if got != expected {
		return http.new_response(status: .forbidden, body: 'rpc signature mismatch')
	}
	stat := volume.stat(bucket, key) or {
		return http.new_response(status: .not_found, body: '${err}')
	}
	return http.new_response(
		status: .ok
		body:   json2.encode(StatBody{
			bucket: bucket
			key:    key
			size:   stat.size
			etag:   stat.etag
		}, escape_unicode: true)
		header: http.new_header(key: .content_type, value: 'application/json')
	)
}
