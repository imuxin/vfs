// roster is the identity administration the request path does not need: listing,
// status, key rotation, sessions, and the SSH public keys an SFTP login checks.
module iam

import json2
import os

struct SSHFile {
	keys []string
}

pub struct UserInfo {
pub:
	name     string
	status   string
	policies []string
}

pub struct KeyInfo {
pub:
	access_key string
	user       string
	status     string
	expires    i64
	session    bool
}

pub fn (d Directory) list_users() []UserInfo {
	mut out := []UserInfo{}
	for name in d.names('users') {
		user := d.user(name) or { continue }
		out << UserInfo{
			name:     user.name
			status:   user.status
			policies: user.policies
		}
	}
	return out
}

pub fn (d Directory) set_user_status(name string, status string) ! {
	if status != 'Enabled' && status != 'Disabled' {
		return error('status must be Enabled or Disabled')
	}
	current := d.user(name)!
	d.put_user(User{
		name:     current.name
		status:   status
		policies: current.policies
	})!
}

pub fn (d Directory) delete_user(name string) ! {
	_ = d.user(name)!
	os.rm(d.path('users', name)) or { return error('user could not be removed') }
	for access in d.names('keys') {
		key := d.key(access) or { continue }
		if key.user == name || key.access_key == name {
			os.rm(d.path('keys', access)) or {}
		}
	}
	os.rm(d.path('mfa', name)) or {}
	os.rm(d.path('ssh', name)) or {}
}

pub fn (d Directory) rotate_key(access string, secret string) ! {
	if secret.len < 8 {
		return error('secret must be at least 8 characters')
	}
	current := d.key(access)!
	d.put_key(AccessKey{
		access_key: current.access_key
		secret_key: secret
		user:       current.user
		status:     current.status
		policies:   current.policies
		expires:    current.expires
		session:    current.session
	})!
}

pub fn (d Directory) list_keys() []KeyInfo {
	mut out := []KeyInfo{}
	for access in d.names('keys') {
		key := d.key(access) or { continue }
		out << view_key(key)
	}
	return out
}

pub fn (d Directory) delete_key(access string) ! {
	_ = d.key(access)!
	os.rm(d.path('keys', access)) or { return error('access key could not be removed') }
}

pub fn (d Directory) service_accounts(parent string) []KeyInfo {
	mut out := []KeyInfo{}
	for access in d.names('keys') {
		key := d.key(access) or { continue }
		if key.session.len > 0 || key.access_key.starts_with('ASIA') {
			continue
		}
		if key.user == key.access_key {
			continue
		}
		if parent.len > 0 && key.user != parent {
			continue
		}
		out << view_key(key)
	}
	return out
}

pub fn (d Directory) sessions() []KeyInfo {
	mut out := []KeyInfo{}
	for access in d.names('keys') {
		key := d.key(access) or { continue }
		if key.session.len > 0 || key.access_key.starts_with('ASIA') {
			out << view_key(key)
		}
	}
	return out
}

fn view_key(key AccessKey) KeyInfo {
	return KeyInfo{
		access_key: key.access_key
		user:       key.user
		status:     key.status
		expires:    key.expires
		session:    key.session.len > 0
	}
}

pub fn (d Directory) list_groups() []Group {
	mut out := []Group{}
	for name in d.names('groups') {
		group := d.group(name) or { continue }
		out << group
	}
	return out
}

pub fn (d Directory) set_group_status(name string, status string) ! {
	if status != 'Enabled' && status != 'Disabled' {
		return error('status must be Enabled or Disabled')
	}
	current := d.group(name)!
	d.put_group(Group{
		name:     current.name
		status:   status
		members:  current.members
		policies: current.policies
	})!
}

pub fn (d Directory) group_member(name string, user string, add bool) ! {
	if user.len == 0 {
		return error('member name is required')
	}
	current := d.group(name)!
	mut members := current.members.clone()
	if add {
		if user !in members {
			members << user
		}
	} else {
		members = members.filter(it != user)
	}
	d.put_group(Group{
		name:     current.name
		status:   current.status
		members:  members
		policies: current.policies
	})!
}

pub fn (d Directory) put_ssh_key(user string, key string) ! {
	_ = d.user(user)!
	line := key.trim_space()
	if !line.starts_with('ssh-') {
		return error('ssh public key must start with ssh-')
	}
	mut keys := d.ssh_keys(user)
	if line !in keys {
		keys << line
	}
	write(d.path('ssh', user), json2.encode(SSHFile{ keys: keys }, escape_unicode: true))!
}

pub fn (d Directory) ssh_keys(user string) []string {
	raw := read(d.path('ssh', user)) or { return []string{} }
	parsed := json2.decode[SSHFile](raw) or { return []string{} }
	return parsed.keys
}

pub fn (d Directory) delete_ssh_key(user string, key string) ! {
	kept := d.ssh_keys(user).filter(it != key.trim_space())
	write(d.path('ssh', user), json2.encode(SSHFile{ keys: kept }, escape_unicode: true))!
}

pub fn (d Directory) ssh_allows(user string, presented string) bool {
	return presented.trim_space() in d.ssh_keys(user)
}
