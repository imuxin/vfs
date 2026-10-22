// mfa is TOTP (RFC 6238) plus one-time recovery codes. Enrollment lives beside
// the user. A recovery code is stored as a hash and removed when it is used.
module iam

import crypto.hmac
import crypto.sha1
import crypto.sha256
import encoding.base32
import encoding.binary
import encoding.hex
import json2
import os
import rand
import time

pub struct MFA {
pub:
	secret   string
	recovery []string
}

pub fn (d Directory) enroll_mfa(user string) !MFA {
	raw := rand.bytes(20)!
	secret := base32.encode_to_string(raw).trim_right('=')
	mut recovery := []string{}
	mut stored := []string{}
	for _ in 0 .. 8 {
		code := hex.encode(rand.bytes(4)!)
		recovery << code
		stored << hex.encode(sha256.sum256(code.bytes()))
	}
	record := MFA{
		secret:   secret
		recovery: stored
	}
	write(d.path('mfa', user), json2.encode[MFA](record, escape_unicode: true))!
	return MFA{
		secret:   secret
		recovery: recovery
	}
}

pub fn (d Directory) mfa_enrolled(user string) bool {
	return os.exists(d.path('mfa', user))
}

pub fn (d Directory) reset_mfa(user string) ! {
	os.rm(d.path('mfa', user)) or { return error('mfa is not enrolled') }
}

// consume_mfa accepts a current TOTP code or a recovery code. A recovery code
// cannot be used twice.
pub fn (d Directory) consume_mfa(user string, code string) ! {
	raw := read(d.path('mfa', user))!
	mut record := json2.decode[MFA](raw)!
	if totp(record.secret, time.now().unix(), code) {
		return
	}
	hashed := hex.encode(sha256.sum256(code.bytes()))
	if hashed !in record.recovery {
		return error('mfa code rejected')
	}
	record = MFA{
		secret:   record.secret
		recovery: record.recovery.filter(it != hashed)
	}
	write(d.path('mfa', user), json2.encode[MFA](record, escape_unicode: true))!
}

// totp reports whether code matches the 30-second window around now, or one
// step either side, so a clock that is slightly off still works.
pub fn totp(secret string, now i64, code string) bool {
	key := base32.decode(pad_base32(secret).bytes()) or { return false }
	step := now / 30
	for delta in [-i64(1), 0, 1] {
		if hotp(key, step + delta) == code {
			return true
		}
	}
	return false
}

fn hotp(key []u8, counter i64) string {
	msg := binary.big_endian_get_u64(u64(counter))
	mac := hmac.new(key, msg, sha1.sum, sha1.block_size)
	offset := int(mac[mac.len - 1] & 0x0f)
	bin := (u32(mac[offset] & 0x7f) << 24) | (u32(mac[offset + 1]) << 16) | (u32(mac[offset + 2]) << 8) | u32(mac[offset + 3])
	n := bin % 1000000
	text := '${n}'
	if text.len >= 6 {
		return text
	}
	return '0'.repeat(6 - text.len) + text
}

fn pad_base32(secret string) string {
	mut padded := secret
	for padded.len % 8 != 0 {
		padded += '='
	}
	return padded
}

fn rand_hex(n int) string {
	bytes := rand.bytes(n) or { return '00'.repeat(n) }
	return hex.encode(bytes)
}
