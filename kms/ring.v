// ring is the persisted SSE-KMS key set. Each record is wrapped by the local
// master. A disabled or deleted key is not returned, so a request cannot fall
// back to the SSE-S3 master.
module kms

import encoding.hex
import json2
import os
import time

struct Stored {
	id      string
	enabled bool
	tags    map[string]string
	version int
	deleted i64
	wrapped string
}

pub struct Info {
pub:
	id      string
	enabled bool
	tags    map[string]string
	version int
	deleted i64
}

pub struct Ring {
	root   string
	master Local
}

pub fn open_ring(root string, master Local) !Ring {
	os.mkdir_all(root)!
	return Ring{
		root:   root
		master: master
	}
}

pub fn (r Ring) create(id string, tags map[string]string) ! {
	check_id(id)!
	if os.exists(r.path(id)) {
		return error('kms key already exists')
	}
	plain := generate(r.master, id)!.plain
	r.save(Stored{
		id:      id
		enabled: true
		tags:    tags.clone()
		version: 1
		wrapped: hex.encode(r.master.wrap(plain, id)!)
	})!
}

pub fn (r Ring) describe(id string) !Info {
	return info_of(r.load(id)!)
}

pub fn (r Ring) list() ![]Info {
	entries := os.ls(r.root) or { return []Info{} }
	mut out := []Info{}
	for name in entries {
		if !name.ends_with('.json') {
			continue
		}
		id := name.trim_string_right('.json')
		out << r.describe(id) or { continue }
	}
	return out
}

pub fn (r Ring) set_enabled(id string, enabled bool) ! {
	stored := r.load(id)!
	if stored.deleted > 0 {
		return error('kms key is deleted')
	}
	r.save(Stored{
		id:      stored.id
		enabled: enabled
		tags:    stored.tags
		version: stored.version
		deleted: stored.deleted
		wrapped: stored.wrapped
	})!
}

pub fn (r Ring) rotate(id string) ! {
	stored := r.load(id)!
	if stored.deleted > 0 {
		return error('kms key is deleted')
	}
	plain := generate(r.master, id)!.plain
	r.save(Stored{
		id:      stored.id
		enabled: stored.enabled
		tags:    stored.tags
		version: stored.version + 1
		deleted: stored.deleted
		wrapped: hex.encode(r.master.wrap(plain, id)!)
	})!
}

// reencrypt wraps the same key bytes again. Callers that already hold the
// plaintext keep working; only the stored wrapper changes.
pub fn (r Ring) reencrypt(id string) ! {
	stored := r.load(id)!
	plain := r.master.unwrap(hex.decode(stored.wrapped)!, id)!
	r.save(Stored{
		id:      stored.id
		enabled: stored.enabled
		tags:    stored.tags
		version: stored.version
		deleted: stored.deleted
		wrapped: hex.encode(r.master.wrap(plain, id)!)
	})!
}

pub fn (r Ring) tag(id string, tags map[string]string) ! {
	stored := r.load(id)!
	r.save(Stored{
		id:      stored.id
		enabled: stored.enabled
		tags:    tags.clone()
		version: stored.version
		deleted: stored.deleted
		wrapped: stored.wrapped
	})!
}

pub fn (r Ring) material(id string) ![]u8 {
	stored := r.load(id)!
	if !stored.enabled || stored.deleted > 0 {
		return error('SSE-KMS requires a running key backend')
	}
	return r.master.unwrap(hex.decode(stored.wrapped)!, id)
}

pub fn (r Ring) mark_deleted(id string, now i64) ! {
	stored := r.load(id)!
	r.save(Stored{
		id:      stored.id
		enabled: false
		tags:    stored.tags
		version: stored.version
		deleted: now
		wrapped: stored.wrapped
	})!
}

pub fn (r Ring) purge(now i64, grace i64) ![]string {
	mut removed := []string{}
	for item in r.list()! {
		if item.deleted == 0 || now - item.deleted < grace {
			continue
		}
		os.rm(r.path(item.id)) or { continue }
		removed << item.id
	}
	return removed
}

pub fn (r Ring) backup() !string {
	entries := os.ls(r.root) or { return '[]' }
	mut docs := []string{}
	for name in entries {
		if !name.ends_with('.json') {
			continue
		}
		docs << os.read_file(os.join_path(r.root, name))!
	}
	return '[' + docs.join(',') + ']'
}

pub fn (r Ring) restore(body string) !int {
	rows := json2.decode[[]Stored](body)!
	mut n := 0
	for row in rows {
		check_id(row.id)!
		r.save(row)!
		n++
	}
	return n
}

pub fn (r Ring) load_enabled() !map[string][]u8 {
	mut out := map[string][]u8{}
	for item in r.list()! {
		if !item.enabled || item.deleted > 0 {
			continue
		}
		out[item.id] = r.material(item.id)!
	}
	return out
}

fn (r Ring) load(id string) !Stored {
	check_id(id)!
	raw := os.read_file(r.path(id))!
	return json2.decode[Stored](raw)
}

fn (r Ring) save(stored Stored) ! {
	check_id(stored.id)!
	os.write_file(r.path(stored.id), json2.encode(stored, escape_unicode: true))!
}

fn (r Ring) path(id string) string {
	return os.join_path(r.root, id + '.json')
}

fn info_of(stored Stored) Info {
	return Info{
		id:      stored.id
		enabled: stored.enabled
		tags:    stored.tags
		version: stored.version
		deleted: stored.deleted
	}
}

fn check_id(id string) ! {
	if id.len == 0 || id.len > 128 {
		return error('kms key id is invalid')
	}
	for ch in id {
		ok := (ch >= `a` && ch <= `z`) || (ch >= `A` && ch <= `Z`) || (ch >= `0` && ch <= `9`)
			|| ch == `-` || ch == `_` || ch == `:` || ch == `.`
		if !ok {
			return error('kms key id is invalid')
		}
	}
}

// purge_dir removes keys whose deletion timestamp is older than grace.
pub fn purge_dir(root string, master Local, now i64, grace i64) ![]string {
	if !os.exists(root) {
		return []string{}
	}
	return open_ring(root, master)!.purge(now, grace)
}

pub fn ring_now() i64 {
	return time.now().unix()
}
