// admin state is the service mode and the configuration document. Both live
// under .vfs.sys so every drive in the set carries the same record.
module store

import json2
import adminctl
import locktab
import objzip
import pool

const service_file = '.vfs.sys/service.json'
const config_doc = '.vfs.sys/config.json'

struct ServiceFile {
	mode string
}

struct ConfigFile {
	entries []adminctl.Entry
	history []adminctl.Revision
}

pub fn (v Volume) service_mode() string {
	raw := v.drives[0].read(service_file) or { return 'running' }
	parsed := json2.decode[ServiceFile](raw.bytestr()) or { return 'running' }
	if parsed.mode.len == 0 {
		return 'running'
	}
	return parsed.mode
}

pub fn (v Volume) service(action string) !string {
	next := adminctl.transition(v.service_mode(), action)!
	encoded := json2.encode[ServiceFile](ServiceFile{ mode: next }, escape_unicode: true).bytes()
	for drive in v.drives {
		drive.write(service_file, encoded)!
	}
	if next == 'stopping' {
		v.mark_clean()!
	}
	return next
}

pub fn (v Volume) ready() bool {
	if v.drives.len == 0 || v.service_mode() == 'stopping' {
		return false
	}
	for drive in v.drives {
		if !drive.exists('.') && !drive.exists('.vfs.sys/format.json') {
			return false
		}
	}
	return true
}

pub fn (v Volume) cluster_info() !string {
	names := v.list_buckets()!
	mut usage := ''
	for name in names {
		if usage.len > 0 {
			usage += ','
		}
		usage += '"${name}":${v.usage_of(name)}'
	}
	return '{"mode":"${v.service_mode()}","drives":${v.drives.len},"data":${v.layout.data_shards},"parity":${v.layout.parity_shards},"buckets":${names.len},"usage":{${usage}}}'
}

pub fn (v Volume) config_get(key string) !adminctl.Entry {
	return v.read_config().get(key)
}

pub fn (v Volume) config_set(key string, value string, now i64) ! {
	v.write_config(v.read_config().set(key, value, now)!)!
}

pub fn (v Volume) config_delete(key string, now i64) ! {
	v.write_config(v.read_config().delete(key, now)!)!
}

pub fn (v Volume) config_restore(key string, now i64) ! {
	v.write_config(v.read_config().restore(key, now)!)!
}

pub fn (v Volume) config_history(key string) []adminctl.Revision {
	return adminctl.history_of(v.read_config(), key)
}

pub fn (v Volume) lock_object(bucket string, key string) ! {
	v.guard('${bucket}/${key}')!
}

pub fn (v Volume) unlock_object(bucket string, key string) bool {
	return v.force_lock('${bucket}/${key}')
}

pub fn (v Volume) held_locks() []locktab.Hold {
	if v.locks == unsafe { nil } {
		return []locktab.Hold{}
	}
	mut locks := v.locks
	return locks.list()
}

pub fn (v Volume) force_lock(name string) bool {
	if v.locks == unsafe { nil } {
		return false
	}
	mut locks := v.locks
	return locks.force(name)
}

fn (v Volume) guard(name string) ! {
	if v.locks == unsafe { nil } {
		return
	}
	mut locks := v.locks
	locks.acquire(name, 's3')!
}

fn (v Volume) unguard(name string) {
	if v.locks == unsafe { nil } {
		return
	}
	mut locks := v.locks
	locks.release(name)
}

// zip_prefix packs the current objects under a prefix into one zip. Directory
// markers and delete markers are not files, so they are left out.
pub fn (v Volume) zip_prefix(bucket string, prefix string) ![]u8 {
	require_bucket(v, bucket)!
	mut files := []objzip.File{}
	for stat in v.list(bucket, prefix, 0)! {
		if stat.delete_marker || stat.key.ends_with('/') {
			continue
		}
		body := v.get(bucket, stat.key, []u8{})!
		files << objzip.File{
			name: stat.key
			data: body
		}
	}
	return objzip.encode(files)
}

pub fn (v Volume) pools() []pool.Set {
	return pool.sets_of([v.drives.len])
}

pub fn (v Volume) decommission_pool(index int) ! {
	pool.decommission(v.pools().len, index)!
}

pub fn (v Volume) rebalance(action string) !string {
	if v.balance == unsafe { nil } {
		return error('rebalance is not configured')
	}
	mut balance := v.balance
	if action == 'start' {
		balance.start(v.pools().len)!
	} else if action == 'stop' {
		balance.stop()
	} else if action != 'status' {
		return error('unknown rebalance action')
	}
	return balance.state
}

fn (v Volume) require_writable() ! {
	mode := v.service_mode()
	if mode == 'frozen' || mode == 'stopping' {
		return error('storage is not writable')
	}
}

fn (v Volume) read_config() adminctl.Document {
	raw := v.drives[0].read(config_doc) or { return adminctl.Document{} }
	parsed := json2.decode[ConfigFile](raw.bytestr()) or { return adminctl.Document{} }
	return adminctl.Document{
		entries: parsed.entries
		history: parsed.history
	}
}

fn (v Volume) write_config(doc adminctl.Document) ! {
	encoded := json2.encode[ConfigFile](ConfigFile{
		entries: doc.entries
		history: doc.history
	}, escape_unicode: true).bytes()
	for drive in v.drives {
		drive.write(config_doc, encoded)!
	}
}
