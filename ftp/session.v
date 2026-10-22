// session is the FTP command handler. It speaks the control replies and uses
// the same buckets, keys, and IAM checks as S3. The socket layer only moves
// the bytes a 150 reply promised.
module ftp

import auth
import iam
import store

pub struct Session {
pub mut:
	volume    store.Volume
	creds     auth.Credentials
	directory ?iam.Directory
	access    string
	authed    bool
	bucket    string
	prefix    string
	outbound     []u8
	store_bucket string
	store_key    string
}

pub fn (mut s Session) command(raw string) string {
	line := raw.trim_space()
	if line.len == 0 {
		return '500 empty command'
	}
	verb, arg := split_command(line)
	upper := verb.to_upper()
	if upper !in ['USER', 'PASS', 'QUIT', 'AUTH', 'FEAT', 'NOOP'] && !s.authed {
		return '530 not logged in'
	}
	return match upper {
		'USER' { s.user(arg) }
		'PASS' { s.pass(arg) }
		'QUIT' { '221 goodbye' }
		'AUTH' { s.auth_tls(arg) }
		'SYST' { '215 UNIX Type: L8' }
		'TYPE' { '200 type set' }
		'NOOP' { '200 ok' }
		'FEAT' { '211-features\r\n PASV\r\n UTF8\r\n211 end' }
		'APPE' { '502 restart and append are not supported' }
		'REST' { '502 restart and append are not supported' }
		'PWD' { '257 "${s.pwd()}"' }
		'CWD' { s.cwd(arg) }
		'CDUP' { s.cwd('..') }
		'MKD' { s.mkdir(arg) }
		'DELE' { s.remove(arg) }
		'LIST' { s.list() }
		'RETR' { s.retrieve(arg) }
		'STOR' { s.store(arg) }
		else { '502 command not implemented' }
	}
}

// complete_store writes the bytes received on the data connection.
pub fn (mut s Session) complete_store(data []u8) string {
	key := s.store_key
	bucket := s.store_bucket
	s.store_key = ''
	s.store_bucket = ''
	if key.len == 0 || bucket.len == 0 {
		return '425 no store in progress'
	}
	s.volume.put(store.PutRequest{
		bucket: bucket
		key:    key
		data:   data
	}) or {
		return '550 ${err}'
	}
	return '226 transfer complete'
}

fn (mut s Session) auth_tls(arg string) string {
	if arg.to_upper() != 'TLS' {
		return '504 unsupported security'
	}
	// A plaintext listener must not pretend the control connection is encrypted.
	return '534 TLS is not available on this listener'
}

fn (mut s Session) user(name string) string {
	if name.len == 0 {
		return '501 missing user'
	}
	s.access = name
	s.authed = false
	return '331 password required'
}

fn (mut s Session) pass(secret string) string {
	if s.access.len == 0 {
		return '503 login with USER first'
	}
	stored := s.creds.secret(s.access) or { return '530 login incorrect' }
	if stored != secret {
		return '530 login incorrect'
	}
	s.authed = true
	return '230 login ok'
}

fn (s Session) pwd() string {
	if s.bucket.len == 0 {
		return '/'
	}
	if s.prefix.len == 0 {
		return '/${s.bucket}'
	}
	return '/${s.bucket}/${s.prefix}'
}

fn (mut s Session) cwd(path string) string {
	bucket, prefix := s.resolve(path)
	if bucket.len == 0 {
		s.bucket = ''
		s.prefix = ''
		return '250 directory changed'
	}
	if !s.volume.bucket_exists(bucket) {
		return '550 no such bucket'
	}
	if !s.permit(bucket, prefix, 's3:ListBucket') {
		return '550 not authorized'
	}
	s.bucket = bucket
	s.prefix = prefix
	return '250 directory changed'
}

fn (mut s Session) mkdir(path string) string {
	bucket, key := s.resolve(path)
	if bucket.len == 0 {
		return '550 missing name'
	}
	if key.len == 0 {
		if !s.permit(bucket, '', 's3:PutBucket') {
			return '550 not authorized'
		}
		s.volume.make_bucket(bucket) or { return '550 ${err}' }
		return '257 "/${bucket}" created'
	}
	if !s.permit(bucket, key, 's3:PutObject') {
		return '550 not authorized'
	}
	marker := if key.ends_with('/') { key } else { '${key}/' }
	s.volume.put(store.PutRequest{
		bucket:       bucket
		key:          marker
		data:         []u8{}
		content_type: 'application/x-directory'
	}) or {
		return '550 ${err}'
	}
	return '257 created'
}

fn (mut s Session) remove(path string) string {
	bucket, key := s.locate(path)
	if key.len == 0 {
		return '550 missing name'
	}
	if !s.permit(bucket, key, 's3:DeleteObject') {
		return '550 not authorized'
	}
	s.volume.delete(bucket, key) or { return '550 ${err}' }
	return '250 deleted'
}

fn (mut s Session) list() string {
	if s.bucket.len == 0 {
		names := s.volume.list_buckets() or { return '550 ${err}' }
		s.outbound = names.join('\r\n').bytes()
		if names.len > 0 {
			s.outbound << '\r\n'.bytes()
		}
		return '150 listing'
	}
	if !s.permit(s.bucket, s.prefix, 's3:ListBucket') {
		return '550 not authorized'
	}
	stats := s.volume.list(s.bucket, s.prefix, 0) or { return '550 ${err}' }
	mut lines := []string{}
	for stat in stats {
		if stat.delete_marker {
			continue
		}
		lines << '${stat.size} ${stat.key}'
	}
	s.outbound = lines.join('\r\n').bytes()
	if lines.len > 0 {
		s.outbound << '\r\n'.bytes()
	}
	return '150 listing'
}

fn (mut s Session) retrieve(path string) string {
	bucket, key := s.locate(path)
	if key.len == 0 {
		return '550 missing name'
	}
	if !s.permit(bucket, key, 's3:GetObject') {
		return '550 not authorized'
	}
	body := s.volume.get(bucket, key, []u8{}) or { return '550 ${err}' }
	s.outbound = body
	return '150 sending'
}

fn (mut s Session) store(path string) string {
	bucket, key := s.locate(path)
	if key.len == 0 {
		return '550 missing name'
	}
	if !s.permit(bucket, key, 's3:PutObject') {
		return '550 not authorized'
	}
	s.store_bucket = bucket
	s.store_key = key
	return '150 ready for data'
}

fn (s Session) locate(path string) (string, string) {
	bucket, key := s.resolve(path)
	return bucket, key
}

fn (s Session) resolve(path string) (string, string) {
	clean := path.trim_space().replace('\\', '/')
	if clean == '/' || clean.len == 0 {
		return '', ''
	}
	if clean == '..' {
		if s.prefix.len == 0 {
			return '', ''
		}
		parent := s.prefix.all_before_last('/')
		return s.bucket, parent
	}
	mut parts := []string{}
	if !clean.starts_with('/') && s.bucket.len > 0 {
		parts << s.bucket
		if s.prefix.len > 0 {
			for part in s.prefix.split('/') {
				parts << part
			}
		}
	}
	for part in clean.trim('/').split('/') {
		if part.len == 0 || part == '.' {
			continue
		}
		if part == '..' {
			if parts.len > 0 {
				parts.delete_last()
			}
			continue
		}
		parts << part
	}
	if parts.len == 0 {
		return '', ''
	}
	if parts.len == 1 {
		return parts[0], ''
	}
	return parts[0], parts[1..].join('/')
}

fn (s Session) permit(bucket string, key string, action string) bool {
	directory := s.directory or { return true }
	resource := if key.len == 0 || action == 's3:ListBucket' || action == 's3:PutBucket' {
		'arn:aws:s3:::${bucket}'
	} else {
		'arn:aws:s3:::${bucket}/${key}'
	}
	answer := directory.verdict(s.access, action, resource) or { return false }
	return answer == .allow
}

fn split_command(line string) (string, string) {
	space := line.index(' ') or { return line, '' }
	return line[..space], line[space + 1..].trim_space()
}
