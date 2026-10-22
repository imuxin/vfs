// sftp is the identity-authenticated file session. RustFS keeps the SSH
// transport out of the default build. This session still requires an IAM user
// and a stored SSH public key, then reads and writes the same volume.
module sftp

import iam
import store

pub struct Session {
pub mut:
	volume     store.Volume
	directory  iam.Directory
	user       string
	authed     bool
	outbound   []u8
	put_bucket string
	put_key    string
}

pub fn (mut s Session) command(line string) string {
	text := line.trim_space()
	if text.len == 0 {
		return '500 empty command'
	}
	parts := text.split_nth(' ', 3)
	verb := parts[0].to_upper()
	if verb != 'AUTH' && !s.authed {
		return '530 not logged in'
	}
	return match verb {
		'AUTH' { s.auth(parts) }
		'GET' { s.get(parts) }
		'PUT' { s.put(parts) }
		'LIST' { s.list(parts) }
		else { '502 command not implemented' }
	}
}

pub fn (mut s Session) complete_put(data []u8) string {
	if !s.authed || s.put_key.len == 0 {
		return '425 no store in progress'
	}
	allowed := s.directory.allows(s.user, 's3:PutObject', 'arn:aws:s3:::${s.put_bucket}/${s.put_key}') or {
		return '550 ${err}'
	}
	if !allowed {
		return '550 not authorized'
	}
	s.volume.put(store.PutRequest{
		bucket: s.put_bucket
		key:    s.put_key
		data:   data
	}) or {
		return '550 ${err}'
	}
	s.put_key = ''
	s.put_bucket = ''
	return '226 transfer complete'
}

fn (mut s Session) auth(parts []string) string {
	if parts.len < 3 {
		return '501 AUTH user key'
	}
	user := parts[1]
	key := parts[2]
	if !s.directory.ssh_allows(user, key) {
		return '530 public key rejected'
	}
	status := s.directory.user(user) or { return '530 public key rejected' }
	if status.status == 'Disabled' {
		return '530 user disabled'
	}
	s.user = user
	s.authed = true
	return '200 public key accepted'
}

fn (mut s Session) get(parts []string) string {
	if parts.len < 3 {
		return '501 GET bucket key'
	}
	allowed := s.directory.allows(s.user, 's3:GetObject', 'arn:aws:s3:::${parts[1]}/${parts[2]}') or {
		return '550 ${err}'
	}
	if !allowed {
		return '550 not authorized'
	}
	body := s.volume.get(parts[1], parts[2], []u8{}) or { return '550 ${err}' }
	s.outbound = body.clone()
	return '150 sending'
}

fn (mut s Session) put(parts []string) string {
	if parts.len < 3 {
		return '501 PUT bucket key'
	}
	s.put_bucket = parts[1]
	s.put_key = parts[2]
	return '150 ready for data'
}

fn (mut s Session) list(parts []string) string {
	if parts.len < 2 {
		return '501 LIST bucket'
	}
	stats := s.volume.list(parts[1], '', 0) or { return '550 ${err}' }
	mut lines := []string{}
	for stat in stats {
		lines << stat.key
	}
	s.outbound = lines.join('\n').bytes()
	return '150 sending'
}
