// background is the durable bookkeeping for heal, bitrot, usage, and migration.
// The scanner reads these records; a crash leaves them on disk so the next boot
// can finish the work.
module store

import bitrot
import json2
import os

const dirty_file = '.vfs.sys/dirty'
const heal_pending = '.vfs.sys/heal.pending'
const heal_file = '.vfs.sys/heal.mrf'
const modules_file = '.vfs.sys/modules.json'
const usage_file = '.vfs.sys/usage.json'
const migrate_file = '.vfs.sys/migrate.queue'

pub struct HealJob {
pub:
	bucket string
	key    string
}

pub struct HealFile {
pub:
	jobs []HealJob
}

pub struct MigrateJob {
pub:
	bucket string
	key    string
	tier   string
}

pub struct MigrateFile {
pub:
	jobs []MigrateJob
}

// Modules records which background passes are allowed to run.
pub struct Modules {
pub mut:
	scanner bool = true
	heal    bool = true
	bitrot  bool = true
	migrate bool = true
}

// note_boot remembers an unclean shutdown. A dirty file left by the previous
// process means heal must run before the set is treated as caught up.
fn (v Volume) note_boot() ! {
	if v.drives.len == 0 {
		return
	}
	if v.drives[0].exists(dirty_file) {
		v.drives[0].write(heal_pending, '1'.bytes())!
	}
	for drive in v.drives {
		drive.write(dirty_file, '1'.bytes())!
	}
}

// mark_clean is the graceful-stop handshake. The next open will not schedule
// a catch-up heal for this process.
pub fn (v Volume) mark_clean() ! {
	for drive in v.drives {
		drive.remove(dirty_file)!
	}
}

pub fn (v Volume) unclean_pending() bool {
	return v.drives.len > 0 && v.drives[0].exists(heal_pending)
}

pub fn (v Volume) clear_heal_pending() ! {
	for drive in v.drives {
		drive.remove(heal_pending)!
	}
}

// heal_object repairs one key and, when the set cannot be rebuilt yet, keeps
// the key on the heal queue for a later pass.
pub fn (v Volume) heal_object(bucket string, key string) !int {
	restored := v.repair(bucket, key) or {
		message := err.msg()
		v.remember_heal(bucket, key) or { return error(message) }
		return error(message)
	}
	v.forget_heal(bucket, key)!
	return restored
}

pub fn (v Volume) heal_backlog() int {
	return v.heal_jobs().len
}

pub fn (v Volume) resume_heal() !int {
	jobs := v.heal_jobs()
	mut kept := []HealJob{}
	mut restored := 0
	for job in jobs {
		n := v.repair(job.bucket, job.key) or {
			kept << job
			continue
		}
		restored += n
	}
	v.write_heal(kept)!
	return restored
}

// clear_delete_marker removes the current delete marker and points the key at
// the newest version that is still on disk.
pub fn (v Volume) clear_delete_marker(bucket string, key string) !bool {
	version := v.current(bucket, key) or { return false }
	record := v.read_record(bucket, key, version)!
	if !record.delete_marker {
		return false
	}
	if retention_blocks(record, false) {
		return error('object lock denies deletion')
	}
	v.remove_version(bucket, key, version)!
	dir := version_dir(bucket, key, version)
	for drive in v.drives {
		drive.remove_tree(dir)!
	}
	v.advance_current(bucket, key)!
	v.drop_object_cache(bucket, key)
	return true
}

pub fn (v Volume) clear_markers(bucket string) !int {
	mut cleared := 0
	for stat in v.list(bucket, '', 0)! {
		if v.clear_delete_marker(bucket, stat.key)! {
			cleared++
		}
	}
	return cleared
}

// scrub drops shards whose bitrot frame does not match and asks heal to
// rewrite them from the drives that still verify.
pub fn (v Volume) scrub(bucket string, key string) !int {
	version := v.current(bucket, key)!
	record := v.read_record(bucket, key, version)!
	if record.delete_marker || record.archived {
		return 0
	}
	algo := bitrot.parse(record.bitrot)!
	mut bad := 0
	path := os.join_path(version_dir(bucket, key, version), shard_file)
	for drive in v.drives {
		framed := drive.read(path) or { continue }
		bitrot.open_frame(algo, framed) or {
			drive.remove(path)!
			bad++
			continue
		}
	}
	if bad == 0 {
		return 0
	}
	return v.heal_object(bucket, key)
}

pub fn (v Volume) scrub_volume() !int {
	mut total := 0
	for name in v.list_buckets()! {
		for stat in v.list(name, '', 0)! {
			if stat.delete_marker || stat.archived {
				continue
			}
			total += v.scrub(name, stat.key) or { continue }
		}
	}
	return total
}

pub fn (v Volume) saved_modules() Modules {
	raw := v.drives[0].read(modules_file) or { return Modules{} }
	return json2.decode[Modules](raw.bytestr()) or { return Modules{} }
}

pub fn (v Volume) module_on(name string) bool {
	mods := v.saved_modules()
	base := match name {
		'heal' { mods.heal }
		'bitrot' { mods.bitrot }
		'migrate' { mods.migrate }
		'scanner' { mods.scanner }
		else { false }
	}
	env_name := match name {
		'heal' { 'VFS_HEAL_ENABLED' }
		'bitrot' { 'VFS_BITROT_ENABLED' }
		'migrate' { 'VFS_MIGRATE_ENABLED' }
		'scanner' { 'VFS_SCANNER_ENABLED' }
		else { '' }
	}
	raw := os.getenv(env_name).to_lower()
	if raw.len == 0 {
		return base
	}
	return raw == '1' || raw == 'true' || raw == 'on'
}

pub fn (v Volume) set_module(name string, on bool) ! {
	mut mods := v.saved_modules()
	match name {
		'scanner' { mods.scanner = on }
		'heal' { mods.heal = on }
		'bitrot' { mods.bitrot = on }
		'migrate' { mods.migrate = on }
		else { return error('unknown module: ${name}') }
	}
	encoded := json2.encode[Modules](mods, escape_unicode: true).bytes()
	for drive in v.drives {
		drive.write(modules_file, encoded)!
	}
}

pub fn (v Volume) modules_json() string {
	mods := v.saved_modules()
	return '{"scanner":${mods.scanner},"heal":${mods.heal},"bitrot":${mods.bitrot},"migrate":${mods.migrate}}'
}

// refresh_usage counts current objects and stores the snapshot the admin
// surface reads back.
pub fn (v Volume) refresh_usage() !string {
	names := v.list_buckets()!
	mut objects := 0
	mut bytes := i64(0)
	mut rows := []string{}
	for name in names {
		mut count := 0
		mut size := i64(0)
		for stat in v.list(name, '', 0)! {
			if stat.delete_marker {
				continue
			}
			count++
			size += stat.size
		}
		objects += count
		bytes += size
		rows << '{"bucket":"${name}","objects":${count},"bytes":${size}}'
	}
	body := '{"objects":${objects},"bytes":${bytes},"buckets":[${rows.join(',')}]}'
	for drive in v.drives {
		drive.write(usage_file, body.bytes())!
	}
	return body
}

pub fn (v Volume) usage_report() string {
	if v.drives.len == 0 {
		return '{"objects":0,"bytes":0,"buckets":[]}'
	}
	raw := v.drives[0].read(usage_file) or { return '{"objects":0,"bytes":0,"buckets":[]}' }
	return raw.bytestr()
}

// enqueue_migrate lines up current objects under a prefix for a named tier.
pub fn (v Volume) enqueue_migrate(bucket string, prefix string, tier_name string) !int {
	if !v.module_on('migrate') {
		return error('migration is disabled')
	}
	v.tier_named(tier_name)!
	mut jobs := v.migrate_jobs()
	mut added := 0
	for stat in v.list(bucket, prefix, 0)! {
		if stat.delete_marker || stat.archived {
			continue
		}
		if queued(jobs, bucket, stat.key) {
			continue
		}
		jobs << MigrateJob{
			bucket: bucket
			key:    stat.key
			tier:   tier_name
		}
		added++
	}
	v.write_migrate(jobs)!
	return added
}

pub fn (v Volume) drain_migrate() !int {
	if !v.module_on('migrate') {
		return error('migration is disabled')
	}
	jobs := v.migrate_jobs()
	mut kept := []MigrateJob{}
	mut done := 0
	for job in jobs {
		version := v.current(job.bucket, job.key) or { continue }
		v.transition_version(job.bucket, job.key, version, job.tier) or {
			kept << job
			continue
		}
		done++
	}
	v.write_migrate(kept)!
	return done
}

fn (v Volume) heal_jobs() []HealJob {
	raw := v.read_sys(heal_file) or { return []HealJob{} }
	parsed := json2.decode[HealFile](raw.bytestr()) or { return []HealJob{} }
	return parsed.jobs
}

fn (v Volume) remember_heal(bucket string, key string) ! {
	mut jobs := v.heal_jobs()
	for job in jobs {
		if job.bucket == bucket && job.key == key {
			return
		}
	}
	jobs << HealJob{
		bucket: bucket
		key:    key
	}
	v.write_heal(jobs)!
}

fn (v Volume) forget_heal(bucket string, key string) ! {
	jobs := v.heal_jobs()
	mut kept := []HealJob{}
	mut found := false
	for job in jobs {
		if job.bucket == bucket && job.key == key {
			found = true
			continue
		}
		kept << job
	}
	if found {
		v.write_heal(kept)!
	}
}

fn (v Volume) write_heal(jobs []HealJob) ! {
	encoded := json2.encode[HealFile](HealFile{ jobs: jobs }, escape_unicode: true).bytes()
	v.write_sys(heal_file, encoded)!
}

fn (v Volume) migrate_jobs() []MigrateJob {
	raw := v.read_sys(migrate_file) or { return []MigrateJob{} }
	parsed := json2.decode[MigrateFile](raw.bytestr()) or { return []MigrateJob{} }
	return parsed.jobs
}

fn (v Volume) write_migrate(jobs []MigrateJob) ! {
	encoded := json2.encode[MigrateFile](MigrateFile{ jobs: jobs }, escape_unicode: true).bytes()
	v.write_sys(migrate_file, encoded)!
}

fn queued(jobs []MigrateJob, bucket string, key string) bool {
	for job in jobs {
		if job.bucket == bucket && job.key == key {
			return true
		}
	}
	return false
}

fn (v Volume) read_sys(path string) ?[]u8 {
	for drive in v.drives {
		raw := drive.read(path) or { continue }
		return raw
	}
	return none
}

fn (v Volume) write_sys(path string, data []u8) ! {
	for drive in v.drives {
		drive.write(path, data)!
	}
}
