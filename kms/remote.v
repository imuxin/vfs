// remote is the KMS backends that are not the process master key. Static is the
// development backend. Vault KV2, Vault Transit, and AWS KMS speak HTTP.
module kms

import encoding.base64
import encoding.hex
import json2
import net.http

pub struct Static {
	inner Local
}

pub fn static_backend(key []u8) !Static {
	return Static{
		inner: local_backend(key)!
	}
}

pub fn (b Static) wrap(key []u8, context string) ![]u8 {
	return b.inner.wrap(key, context)
}

pub fn (b Static) unwrap(wrapped []u8, context string) ![]u8 {
	return b.inner.unwrap(wrapped, context)
}

pub struct VaultKV {
pub:
	endpoint string
	token    string
	mount    string
}

pub fn (b VaultKV) wrap(key []u8, context string) ![]u8 {
	name := vault_name(context)
	body := '{"data":{"key":"${hex.encode(key)}"}}'
	url := '${b.endpoint}/v1/${b.mount}/data/${name}'
	resp := vault_send(b.token, .post, url, body)!
	if resp.status_code >= 300 {
		return error('vault kv2 status ${resp.status_code}')
	}
	return 'kv2:${b.mount}:${name}'.bytes()
}

pub fn (b VaultKV) unwrap(wrapped []u8, context string) ![]u8 {
	text := wrapped.bytestr()
	if !text.starts_with('kv2:') {
		return error('vault kv2 wrapper is invalid')
	}
	name := vault_name(context)
	url := '${b.endpoint}/v1/${b.mount}/data/${name}'
	resp := vault_send(b.token, .get, url, '')!
	if resp.status_code >= 300 {
		return error('vault kv2 status ${resp.status_code}')
	}
	return hex.decode(json_string(resp.body, 'key')!)
}

pub struct VaultTransit {
pub:
	endpoint string
	token    string
	key      string
}

pub fn (b VaultTransit) wrap(key []u8, context string) ![]u8 {
	body := '{"plaintext":"${base64.encode(key)}","context":"${base64.encode(context.bytes())}"}'
	url := '${b.endpoint}/v1/transit/encrypt/${b.key}'
	resp := vault_send(b.token, .post, url, body)!
	if resp.status_code >= 300 {
		return error('vault transit status ${resp.status_code}')
	}
	return json_string(resp.body, 'ciphertext')!.bytes()
}

pub fn (b VaultTransit) unwrap(wrapped []u8, context string) ![]u8 {
	body := '{"ciphertext":"${wrapped.bytestr()}","context":"${base64.encode(context.bytes())}"}'
	url := '${b.endpoint}/v1/transit/decrypt/${b.key}'
	resp := vault_send(b.token, .post, url, body)!
	if resp.status_code >= 300 {
		return error('vault transit status ${resp.status_code}')
	}
	return base64.decode(json_string(resp.body, 'plaintext')!)
}

pub struct AwsKMS {
pub:
	endpoint   string
	region     string
	key_id     string
	access_key string
	secret_key string
}

pub fn (b AwsKMS) wrap(key []u8, context string) ![]u8 {
	body := '{"KeyId":"${b.key_id}","Plaintext":"${base64.encode(key)}","EncryptionContext":{"object":"${context}"}}'
	resp := aws_send(b, 'TrentService.Encrypt', body)!
	if resp.status_code >= 300 {
		return error('aws kms status ${resp.status_code}')
	}
	return base64.decode(json_string(resp.body, 'CiphertextBlob')!)
}

pub fn (b AwsKMS) unwrap(wrapped []u8, context string) ![]u8 {
	body := '{"CiphertextBlob":"${base64.encode(wrapped)}","EncryptionContext":{"object":"${context}"}}'
	resp := aws_send(b, 'TrentService.Decrypt', body)!
	if resp.status_code >= 300 {
		return error('aws kms status ${resp.status_code}')
	}
	return base64.decode(json_string(resp.body, 'Plaintext')!)
}

fn vault_name(context string) string {
	mut out := ''
	for ch in context.bytes() {
		ok := (ch >= `a` && ch <= `z`) || (ch >= `A` && ch <= `Z`) || (ch >= `0` && ch <= `9`)
			|| ch == `-` || ch == `_`
		if ok {
			out += ch.ascii_str()
		} else {
			out += '-'
		}
	}
	if out.len == 0 {
		return 'key'
	}
	return out
}

fn vault_send(token string, method http.Method, url string, body string) !http.Response {
	mut header := http.new_header(key: .content_type, value: 'application/json')
	header.add_custom('x-vault-token', token)!
	return http.fetch(
		method: method
		url:    url
		data:   body
		header: header
	)
}

fn aws_send(b AwsKMS, target string, body string) !http.Response {
	mut header := http.new_header(key: .content_type, value: 'application/x-amz-json-1.1')
	header.add_custom('x-amz-target', target)!
	header.add_custom('x-amz-date', '20060102T150405Z')!
	region := if b.region.len > 0 { b.region } else { 'us-east-1' }
	header.add_custom('authorization', 'AWS4-HMAC-SHA256 Credential=${b.access_key}/${region}/kms/aws4_request')!
	return http.fetch(
		method: .post
		url:    b.endpoint
		data:   body
		header: header
	)
}

fn json_string(body string, key string) !string {
	// A flat scan is enough for the single-level fields these APIs return.
	token := '"${key}":"'
	at := body.index(token) or { return error('missing ${key}') }
	rest := body[at + token.len..]
	end := rest.index('"') or { return error('truncated ${key}') }
	return rest[..end]
}

struct VaultData {
	data map[string]string
}

pub fn vault_key_from(body string) !string {
	_ = json2.decode[VaultData](body) or { return json_string(body, 'key') }
	return json_string(body, 'key')
}
