// bundle is the IAM export. Version 2 is one JSON document inside a zip, so a
// deployment can move users, keys, groups, policies, and MFA enrollment
// without copying the directory by hand. OIDC login state is not part of the
// bundle; it is only valid on the node that created it.
module iam

import json2
import os
import compress.szip

const bundle_version = 2
const bundle_entry = 'iam-v2.json'

struct Bundle {
	version  int
	users    []User
	keys     []AccessKey
	groups   []Group
	policies []NamedPolicy
	mfa      []NamedMFA
}

struct NamedPolicy {
	name   string
	policy Policy
}

struct NamedMFA {
	user   string
	record MFA
}

pub fn (d Directory) export_zip() ![]u8 {
	bundle := Bundle{
		version:  bundle_version
		users:    d.read_users()
		keys:     d.read_keys()
		groups:   d.read_groups()
		policies: d.read_policies()
		mfa:      d.read_mfa()
	}
	raw := json2.encode[Bundle](bundle, escape_unicode: true)
	dir := os.join_path(os.temp_dir(), 'vfs-iam-zip-${os.getpid()}')
	os.mkdir_all(dir)!
	defer { os.rmdir_all(dir) or {} }
	zip_path := os.join_path(dir, 'iam.zip')
	mut archive := szip.open(zip_path, .no_compression, .write)!
	archive.open_entry(bundle_entry)!
	archive.write_entry(raw.bytes())!
	archive.close_entry()
	archive.close()
	return os.read_bytes(zip_path)
}

pub fn (d Directory) import_zip(payload []u8) ! {
	if payload.len == 0 {
		return error('iam export is empty')
	}
	dir := os.join_path(os.temp_dir(), 'vfs-iam-unzip-${os.getpid()}')
	os.mkdir_all(dir)!
	defer { os.rmdir_all(dir) or {} }
	zip_path := os.join_path(dir, 'iam.zip')
	os.write_file_array(zip_path, payload)!
	raw := zip_entry(zip_path, bundle_entry)!
	bundle := json2.decode[Bundle](raw)!
	if bundle.version != bundle_version {
		return error('unsupported iam export version')
	}
	d.replace_kind('users')!
	d.replace_kind('keys')!
	d.replace_kind('groups')!
	d.replace_kind('policies')!
	d.replace_kind('mfa')!
	for user in bundle.users {
		d.put_user(user)!
	}
	for key in bundle.keys {
		d.put_key(key)!
	}
	for group in bundle.groups {
		d.put_group(group)!
	}
	for item in bundle.policies {
		d.put_policy(item.name, item.policy)!
	}
	for item in bundle.mfa {
		write(d.path('mfa', item.user), json2.encode[MFA](item.record, escape_unicode: true))!
	}
}

fn (d Directory) read_users() []User {
	mut found := []User{}
	for name in d.names('users') {
		if user := d.user(name) {
			found << user
		}
	}
	return found
}

fn (d Directory) read_keys() []AccessKey {
	mut found := []AccessKey{}
	for name in d.names('keys') {
		if key := d.key(name) {
			found << key
		}
	}
	return found
}

fn (d Directory) read_groups() []Group {
	mut found := []Group{}
	for name in d.names('groups') {
		if group := d.group(name) {
			found << group
		}
	}
	return found
}

fn (d Directory) read_policies() []NamedPolicy {
	mut found := []NamedPolicy{}
	for name in d.names('policies') {
		raw := read(d.path('policies', name)) or { continue }
		policy := decode(raw) or { continue }
		found << NamedPolicy{
			name:   name
			policy: policy
		}
	}
	return found
}

fn (d Directory) read_mfa() []NamedMFA {
	mut found := []NamedMFA{}
	for name in d.names('mfa') {
		raw := read(d.path('mfa', name)) or { continue }
		record := json2.decode[MFA](raw) or { continue }
		found << NamedMFA{
			user:   name
			record: record
		}
	}
	return found
}

fn (d Directory) names(kind string) []string {
	dir := os.join_path(d.root, kind)
	entries := os.ls(dir) or { return []string{} }
	mut found := []string{}
	for entry in entries {
		if entry.ends_with('.json') {
			found << entry.trim_string_right('.json')
		}
	}
	found.sort()
	return found
}

fn (d Directory) replace_kind(kind string) ! {
	dir := os.join_path(d.root, kind)
	entries := os.ls(dir) or { return }
	for entry in entries {
		if entry.ends_with('.json') {
			os.rm(os.join_path(dir, entry))!
		}
	}
}

fn zip_entry(path string, name string) !string {
	mut archive := szip.open(path, .no_compression, .read_only)!
	defer { archive.close() }
	total := archive.total()!
	for index in 0 .. total {
		archive.open_entry_by_index(index)!
		if archive.name() == name {
			body := read_zip_entry(mut archive)!
			archive.close_entry()
			return body.bytestr()
		}
		archive.close_entry()
	}
	return error('unsupported iam export')
}

fn read_zip_entry(mut archive szip.Zip) ![]u8 {
	raw := archive.read_entry()!
	size := int(archive.size())
	if size == 0 {
		unsafe { free(raw) }
		return []u8{}
	}
	copied := unsafe { (&u8(raw)).vbytes(size).clone() }
	unsafe { free(raw) }
	return copied
}
