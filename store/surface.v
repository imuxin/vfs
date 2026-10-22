// surface is the admin data plane: inspection, traces, pool membership, audit
// configuration, and the other operations that are not object writes.
module store

import crypto.x509
import json2
import os
import time
import kms
import pool

const pools_file = '.vfs.sys/pools.json'
const trace_file = '.vfs.sys/trace.ndjson'
const audit_file = '.vfs.sys/audit.json'
const cert_file = '.vfs.sys/tls/cert.pem'
const plugins_file = '.vfs.sys/plugins.json'
const durability_file = '.vfs.sys/durability.json'
const snapshot_file = '.vfs.sys/snapshot.json'
const target_file = '.vfs.sys/targets.json'

struct TraceLine {
	time   i64
	kind   string
	detail string
}

pub fn (v Volume) pool_layout() pool.Layout {
	raw := v.drives[0].read(pools_file) or { return pool.single(v.drives.len) }
	parsed := json2.decode[pool.Layout](raw.bytestr()) or { return pool.single(v.drives.len) }
	if parsed.members.len == 0 {
		return pool.single(v.drives.len)
	}
	return parsed
}

fn (v Volume) save_layout(layout pool.Layout) ! {
	v.write_sys(pools_file, json2.encode(layout, escape_unicode: true).bytes())!
}

pub fn (v Volume) expand_pool(drives int, root string) ! {
	if !os.is_dir(root) {
		return error('pool root does not exist')
	}
	v.save_layout(v.pool_layout().expand(drives, root)!)!
}

pub fn (v Volume) cancel_decommission() ! {
	v.save_layout(v.pool_layout().cancel()!)!
}

pub fn (v Volume) clear_decommission() ! {
	current := v.pool_layout()
	root := current.root_of(current.decommission_index)
	next := current.clear()!
	v.save_layout(next)!
	if root.len > 0 {
		os.rmdir_all(os.join_path(root, '.vfs-pool')) or {}
	}
}

pub fn (v Volume) rebalance_copy() !int {
	layout := v.pool_layout()
	if layout.members.len < 2 {
		return error('layout does not allow rebalance')
	}
	mut moved := 0
	for member in layout.members {
		if member.index == 0 || member.root.len == 0 {
			continue
		}
		for bucket in v.list_buckets()! {
			for stat in v.list(bucket, '', 0)! {
				if stat.delete_marker {
					continue
				}
				body := v.get(bucket, stat.key, []u8{})!
				dest := os.join_path(member.root, '.vfs-pool', bucket, stat.key)
				os.mkdir_all(os.dir(dest))!
				os.write_file_array(dest, body)!
				moved++
			}
		}
	}
	return moved
}

pub fn (v Volume) trace(kind string, detail string) {
	line := json2.encode(TraceLine{
		time:   time.now().unix()
		kind:   kind
		detail: detail
	}, escape_unicode: true)
	current := v.read_sys(trace_file) or { []u8{} }
	mut next := current.clone()
	if next.len > 0 && next[next.len - 1] != `\n` {
		next << `\n`
	}
	next << line.bytes()
	next << `\n`
	v.write_sys(trace_file, next) or {}
}

pub fn (v Volume) trace_text() string {
	raw := v.read_sys(trace_file) or { return '' }
	return raw.bytestr()
}

pub fn (v Volume) inspect_data(bucket string, key string) ![]u8 {
	return v.get(bucket, key, []u8{})
}

pub fn (v Volume) export_bucket_meta(bucket string) !string {
	require_bucket(v, bucket)!
	mut parts := []string{}
	for name in ['policy', 'cors', 'website', 'encryption', 'lifecycle', 'replication', 'quota',
		'notification', 'publicAccessBlock', 'object-lambda'] {
		raw := v.get_doc(bucket, name) or { continue }
		parts << '"${name}":${json_string(raw.bytestr())}'
	}
	return '{' + parts.join(',') + '}'
}

pub fn (v Volume) import_bucket_meta(bucket string, body string) ! {
	require_bucket(v, bucket)!
	for name in ['policy', 'cors', 'website', 'encryption', 'lifecycle', 'replication', 'quota',
		'notification', 'publicAccessBlock', 'object-lambda'] {
		raw := quoted_field(body, name) or { continue }
		v.put_doc(bucket, name, raw.bytes())!
	}
}

fn json_string(value string) string {
	escaped := value.replace('\\', '\\\\').replace('"', '\\"')
	return '"${escaped}"'
}

fn quoted_field(body string, name string) ?string {
	token := '"${name}":"'
	at := body.index(token) or { return none }
	rest := body[at + token.len..]
	mut out := ''
	mut escaped := false
	for ch in rest {
		if escaped {
			out += ch.ascii_str()
			escaped = false
			continue
		}
		if ch == `\\` {
			escaped = true
			continue
		}
		if ch == `"` {
			return out
		}
		out += ch.ascii_str()
	}
	return none
}

pub fn (v Volume) recover_orphans() int {
	mut removed := 0
	for drive in v.drives {
		removed += orphan_shards(drive.root())
	}
	return removed
}

fn orphan_shards(root string) int {
	entries := os.ls(root) or { return 0 }
	mut removed := 0
	for name in entries {
		if name == '.vfs.sys' {
			continue
		}
		full := os.join_path(root, name)
		if os.is_dir(full) {
			removed += orphan_shards(full)
			continue
		}
		if name == shard_file && !os.exists(os.join_path(root, meta_file)) && !os.exists(os.join_path(root, 'xl.meta')) {
			os.rm(full) or { continue }
			removed++
		}
	}
	return removed
}

pub fn (v Volume) speedtest() !string {
	payload := []u8{len: 1024 * 1024, init: `x`}
	started := time.ticks()
	v.drives[0].write('.vfs.sys/speedtest.bin', payload)!
	got := v.drives[0].read('.vfs.sys/speedtest.bin')!
	v.drives[0].remove('.vfs.sys/speedtest.bin')!
	if got.len != payload.len {
		return error('speedtest read did not match the write')
	}
	elapsed := time.ticks() - started
	return '{"bytes":${payload.len},"elapsed_ms":${elapsed}}'
}

pub fn (v Volume) devnull(body []u8) string {
	return '{"received":${body.len}}'
}

pub fn (v Volume) snapshot() !string {
	body := '{"info":${v.cluster_info()!},"modules":${v.modules_json()},"pools":${json2.encode(v.pools(), escape_unicode: true)}}'
	v.write_sys(snapshot_file, body.bytes())!
	return body
}

pub fn (v Volume) publish_cert(pem string) ! {
	x509.parse_pem(pem)!
	v.write_sys(cert_file, pem.bytes())!
}

pub fn (v Volume) cert_status() !string {
	raw := v.read_sys(cert_file) or { return error('tls certificate is not published') }
	cert := x509.parse_pem(raw.bytestr())!
	return '{"subject":"${cert.common_name()}","not_after":${cert.not_after.unix()}}'
}

pub fn (v Volume) reload_cert() !string {
	return v.cert_status()
}

pub fn (v Volume) put_plugins(body string) ! {
	if !body.trim_space().starts_with('[') {
		return error('plugins must be a JSON array')
	}
	v.write_sys(plugins_file, body.bytes())!
}

pub fn (v Volume) plugins() string {
	raw := v.read_sys(plugins_file) or { return '[]' }
	return raw.bytestr()
}

struct Durability {
pub:
	copies map[string]int
}

pub fn (v Volume) put_durability(bucket string, n int) ! {
	require_bucket(v, bucket)!
	if n < 1 {
		return error('durability copies must be at least 1')
	}
	mut copies := map[string]int{}
	for name, value in v.durability().copies {
		copies[name] = value
	}
	copies[bucket] = n
	v.write_sys(durability_file, json2.encode(Durability{ copies: copies }, escape_unicode: true).bytes())!
}

pub fn (v Volume) durability() Durability {
	raw := v.read_sys(durability_file) or { return Durability{} }
	return json2.decode[Durability](raw.bytestr()) or { return Durability{} }
}

pub fn (v Volume) durability_of(bucket string) int {
	return v.durability().copies[bucket] or { 0 }
}

pub fn (v Volume) put_audit(body string) ! {
	v.write_sys(audit_file, body.bytes())!
}

pub fn (v Volume) audit_text() string {
	raw := v.read_sys(audit_file) or { return '{"enabled":false}' }
	return raw.bytestr()
}

pub fn (v Volume) clear_audit() ! {
	for drive in v.drives {
		drive.remove(audit_file)!
	}
}

pub struct RemoteTarget {
pub:
	name       string
	endpoint   string
	bucket     string
	access_key string
	secret_key string
	bandwidth  i64
	synced     []string
}

struct TargetFile {
	targets []RemoteTarget
}

pub fn (v Volume) put_target(target RemoteTarget) ! {
	if target.name.len == 0 || target.bucket.len == 0 {
		return error('replication target name and bucket are required')
	}
	mut doc := v.read_targets()
	mut next := []RemoteTarget{}
	mut replaced := false
	for existing in doc.targets {
		if existing.name == target.name {
			next << target
			replaced = true
			continue
		}
		next << existing
	}
	if !replaced {
		next << target
	}
	v.write_targets(TargetFile{ targets: next })!
}

pub fn (v Volume) targets() []RemoteTarget {
	return v.read_targets().targets
}

pub fn (v Volume) delete_target(name string) ! {
	mut next := []RemoteTarget{}
	mut found := false
	for target in v.targets() {
		if target.name == name {
			found = true
			continue
		}
		next << target
	}
	if !found {
		return error('replication target not found')
	}
	v.write_targets(TargetFile{ targets: next })!
}

pub fn (v Volume) target_diff(name string) ![]string {
	mut wanted := RemoteTarget{}
	mut found := false
	for target in v.targets() {
		if target.name == name {
			wanted = target
			found = true
		}
	}
	if !found {
		return error('replication target not found')
	}
	mut missing := []string{}
	for stat in v.list(wanted.bucket, '', 0)! {
		if stat.key !in wanted.synced {
			missing << stat.key
		}
	}
	for job in v.replication_backlog() {
		if job.bucket == wanted.bucket && job.key !in missing {
			missing << '${job.op}:${job.key}'
		}
	}
	return missing
}

fn (v Volume) read_targets() TargetFile {
	raw := v.read_sys(target_file) or { return TargetFile{} }
	return json2.decode[TargetFile](raw.bytestr()) or { return TargetFile{} }
}

fn (v Volume) write_targets(doc TargetFile) ! {
	v.write_sys(target_file, json2.encode(doc, escape_unicode: true).bytes())!
}

pub fn (mut v Volume) install_kms_key(id string, key []u8) {
	v.kms_keys[id] = key.clone()
	v.drop_cached_objects()
}

pub fn (mut v Volume) remove_kms_key(id string) {
	v.kms_keys.delete(id)
	v.drop_cached_objects()
}

fn (v Volume) drop_cached_objects() {
	if v.objects == unsafe { nil } {
		return
	}
	mut mem := v.objects
	mem.invalidate_prefix('')
}

pub fn (v Volume) kms_root() string {
	return os.join_path(v.drives[0].root(), '.vfs.sys', 'kms')
}

pub fn (v Volume) purge_kms(now i64, grace i64) {
	backend := v.keys or { return }
	removed := kms.purge_dir(v.kms_root(), backend, now, grace) or { return }
	mut loaded := v
	for id in removed {
		loaded.remove_kms_key(id)
	}
}
