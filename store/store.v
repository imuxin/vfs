// store is the object layer. It knows buckets, keys, versions, and bytes; it
// does not know HTTP. Object bytes live in a version directory under the key,
// so versioning, copy, and multipart completion all write through one path. A
// get reads whichever shards survived and rebuilds the payload, so a missing
// drive is a degraded read for as long as the parity holds.
module store

import crypto.md5
import crypto.sha256
import encoding.base64
import encoding.hex
import json2
import os
import rand
import time
import bitrot
import cache as objcache
import checksum
import codec
import disk
import envelope
import erasure
import extract
import kms
import layout
import locktab
import pool
import lifecycle
import meta
import notify
import obs
import replicate

const shard_file = 'shard'
const meta_file = 'meta.json'
const current_file = 'current'
const versions_dir = 'versions'
const uploads_dir = '.uploads'

// Volume is one deployment: a set of drives plus the erasure layout they imply.
// keys protects per-object data keys. It is optional: without one the volume
// stores plaintext and refuses SSE-S3, matching a deployment with no KMS.
pub struct Volume {
pub mut:
	drives []disk.Local
	layout erasure.Layout
	keys     ?kms.Local
	kms_keys map[string][]u8
	// bitrot is the hash written ahead of every shard. distribution and
	// deploy_id pick a set once a volume spans more than one.
	bitrot       bitrot.Algo = .highway256s
	distribution layout.Algo = .sipmod_parity
	deploy_id    []u8
	objects      &objcache.Memory = unsafe { nil }
	metrics      &obs.Registry = unsafe { nil }
	locks        &locktab.Table = unsafe { nil }
	balance      &pool.Balance = unsafe { nil }
	repl         &replicate.Counters = unsafe { nil }
}

// open builds a volume from one data directory per drive. One directory is the
// single-drive layout; two or three are an erasure set with one parity shard.
pub fn open(data_dirs []string) !Volume {
	geometry := erasure.plan(data_dirs.len)!
	mut drives := []disk.Local{cap: data_dirs.len}
	for dir in data_dirs {
		drives << disk.open(dir)!
	}
	volume := Volume{
		drives:       drives
		layout:       geometry
		bitrot:       .highway256s
		distribution: .sipmod_parity
		deploy_id:    deployment_id()
		objects:      objcache.new_memory()
		metrics:      obs.new_registry()
		kms_keys:     map[string][]u8{}
		locks:        locktab.new_table()
		balance:      &pool.Balance{
			state: 'idle'
		}
		repl:         replicate.new_counters()
	}
	volume.ensure_format()!
	volume.note_boot()!
	return volume
}

fn (v Volume) duplicate() Volume {
	return Volume{
		drives:       v.drives
		layout:       v.layout
		keys:         v.keys
		kms_keys:     v.kms_keys.clone()
		bitrot:       v.bitrot
		distribution: v.distribution
		deploy_id:    v.deploy_id
		objects:      v.objects
		metrics:      v.metrics
		locks:        v.locks
		balance:      v.balance
		repl:         v.repl
	}
}

// with_kms attaches the backend that protects per-object data keys.
pub fn (v Volume) with_kms(backend kms.Local) Volume {
	mut next := v.duplicate()
	next.keys = backend
	return next
}

// with_kms_key registers one SSE-KMS key. The master key used for SSE-S3 is
// not used for these objects.
pub fn (v Volume) with_kms_key(id string, key []u8) !Volume {
	if id.len == 0 || key.len != 32 {
		return error('SSE-KMS key must be 32 bytes')
	}
	mut next := v.duplicate()
	next.kms_keys[id] = key.clone()
	return next
}

fn deployment_id() []u8 {
	decoded := hex.decode(rand.uuid_v4().replace('-', '')) or { return []u8{len: 16} }
	if decoded.len == 16 {
		return decoded
	}
	return []u8{len: 16}
}

// ensure_format writes format.json the first time a set is opened and checks
// it on every later open. A drive that lost its copy is restored from a sibling
// that still has the same set. A drive formatted for a different set is refused.
fn (v Volume) ensure_format() ! {
	format_path := '.vfs.sys/format.json'
	mut present := []bool{len: v.drives.len, init: false}
	mut sample := layout.Format{}
	mut have := false
	for index, drive in v.drives {
		raw := drive.read(format_path) or { continue }
		parsed := layout.decode_format(raw.bytestr())!
		if have && !same_format(sample, parsed) {
			return error('format.json does not match this set')
		}
		if !have {
			sample = parsed
			have = true
		}
		present[index] = true
	}
	if !have {
		written := layout.fresh([v.drives.len])!
		for index, drive in v.drives {
			stamped := written.for_drive(0, index)!
			drive.write(format_path, stamped.encode().bytes())!
		}
		return
	}
	if sample.xl.sets.len != 1 || sample.xl.sets[0].len != v.drives.len {
		return error('format.json does not match this set')
	}
	for index, drive in v.drives {
		if present[index] {
			continue
		}
		stamped := sample.for_drive(0, index)!
		drive.write(format_path, stamped.encode().bytes())!
	}
}

fn same_format(a layout.Format, b layout.Format) bool {
	if a.id != b.id || a.xl.sets.len != b.xl.sets.len {
		return false
	}
	for i, row in a.xl.sets {
		if row.len != b.xl.sets[i].len {
			return false
		}
		for j, id in row {
			if id != b.xl.sets[i][j] {
				return false
			}
		}
	}
	return true
}

pub struct Stat {
pub:
	key             string
	version         string
	size            i64
	etag            string
	content_type    string
	storage_class   string
	modified        i64
	user_meta       map[string]string
	tags            map[string]string
	delete_marker   bool
	latest          bool
	sse             string
	sse_key_md5     string
	retention_mode  string
	retention_until i64
	legal_hold      bool
	tier            string
	archived        bool
	restore_until   i64
	replica         bool
}

// Part is one uploaded piece of a multipart upload.
pub struct Part {
pub:
	number int
	size   i64
	etag   string
}

fn bucket_ok(name string) ! {
	if name.len < 3 || name.len > 63 {
		return error('bucket name must be between 3 and 63 characters')
	}
	for ch in name {
		ok := (ch >= `a` && ch <= `z`) || (ch >= `0` && ch <= `9`) || ch == `-` || ch == `.`
		if !ok {
			return error('bucket name has an invalid character')
		}
	}
}

fn key_ok(key string) ! {
	if key.len == 0 {
		return error('object key is empty')
	}
	for segment in key.split('/') {
		if segment == '.' || segment == '..' {
			return error('object key must not contain . or .. segments')
		}
	}
}

fn object_dir(bucket string, key string) string {
	return os.join_path(bucket, key)
}

fn version_dir(bucket string, key string, version string) string {
	return os.join_path(object_dir(bucket, key), versions_dir, version)
}

fn require_bucket(v Volume, bucket string) ! {
	if !v.bucket_exists(bucket) {
		return error('bucket not found: ${bucket}')
	}
}

// make_bucket creates the bucket marker on every drive.
pub fn (v Volume) make_bucket(bucket string) ! {
	v.require_writable()!
	bucket_ok(bucket)!
	if v.bucket_exists(bucket) {
		return error('bucket already exists: ${bucket}')
	}
	for drive in v.drives {
		drive.write(os.join_path(bucket, '.bucket'), [])!
	}
	v.note_site('bucket-create', bucket)
}

// remove_bucket deletes an empty bucket.
pub fn (v Volume) remove_bucket(bucket string) ! {
	v.require_writable()!
	require_bucket(v, bucket)!
	objects := v.list(bucket, '', 1)!
	if objects.len > 0 {
		return error('bucket is not empty: ${bucket}')
	}
	for drive in v.drives {
		drive.remove(os.join_path(bucket, '.bucket'))!
	}
	v.note_site('bucket-delete', bucket)
}

pub fn (v Volume) bucket_exists(bucket string) bool {
	return v.drives.len > 0 && v.drives[0].exists(os.join_path(bucket, '.bucket'))
}

// list_buckets returns the bucket names in order.
pub fn (v Volume) list_buckets() ![]string {
	entries := v.drives[0].list('')!
	mut names := []string{}
	for entry in entries {
		if v.bucket_exists(entry) {
			names << entry
		}
	}
	names.sort()
	return names
}

// PutRequest is one object write. sse selects the encryption: empty stores
// plaintext, SSE-S3 uses the volume's key backend, SSE-C uses the customer key.
pub struct PutRequest {
pub:
	bucket       string
	key          string
	data         []u8
	content_type string
	user_meta    map[string]string
	sse            string
	customer_key   []u8
	storage_class  string
	codec          string
	checksum_alg   string
	kms_key_id     string
	replica        bool
}

// put writes an object as a new version and makes it current.
pub fn (v Volume) put(req PutRequest) !Stat {
	require_bucket(v, req.bucket)!
	v.require_writable()!
	key_ok(req.key)!
	held := '${req.bucket}/${req.key}'
	v.guard(held)!
	defer {
		v.unguard(held)
	}
	layout.storage_class_ok(req.storage_class)!
	if (req.user_meta['snowball-auto-extract'] or { '' }) == 'true' {
		if req.sse == 'SSE-KMS' {
			return error('SSE-KMS is not supported for extract uploads')
		}
		return v.put_extract(req)
	}
	v.enforce_quota(req.bucket, i64(req.data.len))!
	version := fresh_id()
	prepared, sum := prepare_body(req.data, req.codec, req.checksum_alg)!
	sealed_bytes, sealed_env := v.seal(req.bucket, req.key, prepared, req.sse, req.customer_key,
		req.kms_key_id)!
	v.write_version(req.bucket, req.key, version, sealed_bytes, req.data, req.content_type,
		req.user_meta, map[string]string{}, sealed_env, req.storage_class, req.codec, req.checksum_alg,
		sum, req.kms_key_id)!
	if req.replica {
		record := v.read_record(req.bucket, req.key, version)!
		v.write_record(req.bucket, req.key, version, meta.Object{
			...record
			replica: true
		})!
	}
	v.set_current(req.bucket, req.key, version)!
	v.drop_object_cache(req.bucket, req.key)
	v.add_usage(req.bucket, i64(req.data.len))!
	v.replicate_put(req.bucket, req.key, req.data, req.content_type)
	v.emit('s3:ObjectCreated:Put', req.bucket, req.key)
	v.audit('s3:PutObject', req.bucket, req.key)
	v.count_metric('put')
	return v.stat_version(req.bucket, req.key, version)
}

// put_extract expands a snowball tar into one object per member. The archive
// itself is not stored. Member keys come from the tar, not from the upload key.
fn (v Volume) put_extract(req PutRequest) !Stat {
	found := extract.members(req.data)!
	if found.len == 0 {
		return error('invalid archive')
	}
	for member in found {
		v.put(PutRequest{
			bucket:        req.bucket
			key:           member.key
			data:          member.data
			content_type:  req.content_type
			sse:           req.sse
			customer_key:  req.customer_key.clone()
			storage_class: req.storage_class
			kms_key_id:    req.kms_key_id
			replica:       req.replica
		})!
	}
	return Stat{
		key:  req.key
		etag: hex.encode(md5_of(req.data))
		size: i64(req.data.len)
	}
}

// get rebuilds the current version. One missing shard is reconstructed.
// customer_key is required only for SSE-C objects and ignored otherwise.
pub fn (v Volume) get(bucket string, key string, customer_key []u8) ![]u8 {
	body := v.get_version(bucket, key, v.current(bucket, key)!, customer_key)!
	v.count_metric('get')
	v.audit('s3:GetObject', bucket, key)
	return body
}

// get_range rebuilds the current version and returns a slice of it. The range
// is inclusive, matching S3's bytes=start-end.
pub fn (v Volume) get_range(bucket string, key string, start i64, end i64, customer_key []u8) ![]u8 {
	body := v.get(bucket, key, customer_key)!
	from, to := clamp_range(start, end, i64(body.len))!
	return body[from..to + 1].clone()
}

fn clamp_range(start i64, end i64, size i64) !(int, int) {
	if size == 0 || start >= size || start < 0 {
		return error('invalid range')
	}
	last := if end < 0 || end >= size { size - 1 } else { end }
	if last < start {
		return error('invalid range')
	}
	return int(start), int(last)
}

// stat reads the current version's record.
pub fn (v Volume) stat(bucket string, key string) !Stat {
	return v.stat_version(bucket, key, v.current(bucket, key)!)
}

// delete removes the current version when versioning is off. With versioning
// enabled it writes a delete marker instead, so earlier versions stay readable
// by version id. Deleting a missing object is not an error; a missing bucket is.
pub fn (v Volume) delete(bucket string, key string) !Stat {
	require_bucket(v, bucket)!
	v.require_writable()!
	held := '${bucket}/${key}'
	v.guard(held)!
	defer {
		v.unguard(held)
	}
	versioning := v.versioning_of(bucket)
	if versioning == 'Enabled' {
		prior := v.stat(bucket, key) or { Stat{} }
		stat := v.write_delete_marker(bucket, key)!
		v.drop_object_cache(bucket, key)
		v.replicate_delete(bucket, key, prior.tags, 'delete-marker')
		v.emit('s3:ObjectRemoved:DeleteMarkerCreated', bucket, key)
		v.audit('s3:DeleteObject', bucket, key)
		return stat
	}
	version := v.current(bucket, key) or {
		return Stat{
			key: key
		}
	}
	removed := v.stat_version(bucket, key, version) or {
		Stat{
			key: key
		}
	}
	v.add_usage(bucket, -removed.size)!
	v.remove_version(bucket, key, version)!
	v.advance_current(bucket, key)!
	v.replicate_delete(bucket, key, removed.tags, 'delete')
		v.emit('s3:ObjectRemoved:Delete', bucket, key)
		v.audit('s3:DeleteObject', bucket, key)
		v.count_metric('delete')
	return Stat{
		key:     key
		version: version
	}
}

// delete_version removes one version, or a delete marker, by id. A legal hold
// or an unexpired retention blocks it. Governance retention yields only when
// the caller passes bypass, which the S3 layer gates on its own permission.
pub fn (v Volume) delete_version(bucket string, key string, version string, bypass bool) ! {
	require_bucket(v, bucket)!
	record := v.read_record(bucket, key, version) or { return }
	if retention_blocks(record, bypass) {
		return error('object lock denies deletion')
	}
	current := v.current(bucket, key) or { '' }
	v.remove_version(bucket, key, version)!
	if current == version {
		v.advance_current(bucket, key)!
	}
}

// retention_blocks reports whether a version is currently protected. A legal
// hold always blocks. Compliance retention blocks until it expires. Governance
// retention blocks unless the caller holds bypass permission.
fn retention_blocks(record meta.Object, bypass bool) bool {
	if record.legal_hold {
		return true
	}
	if record.retention_until == 0 || record.retention_until <= time.now().unix() {
		return false
	}
	if record.retention_mode == 'GOVERNANCE' && bypass {
		return false
	}
	return record.retention_mode == 'GOVERNANCE' || record.retention_mode == 'COMPLIANCE'
}

// get_version_bytes rebuilds one version. A delete marker has no bytes.
pub fn (v Volume) get_version_bytes(bucket string, key string, version string, customer_key []u8) ![]u8 {
	record := v.read_record(bucket, key, version)!
	if record.delete_marker {
		return error('version is a delete marker')
	}
	return v.get_version(bucket, key, version, customer_key)
}

// copy duplicates an object's current version into another key. The bytes are
// re-encoded, so the destination is a normal object with its own version and its
// own data key when the source was encrypted.
pub fn (v Volume) copy(src_bucket string, src_key string, dst_bucket string, dst_key string) !Stat {
	body := v.get(src_bucket, src_key, []u8{})!
	src := v.stat(src_bucket, src_key)!
	return v.put(PutRequest{
		bucket:       dst_bucket
		key:          dst_key
		data:         body
		content_type: src.content_type
		user_meta:    src.user_meta
		sse:          src.sse
	})
}

// put_retention sets one version's retention. Mode is GOVERNANCE or
// COMPLIANCE; until is the unix timestamp it expires at.
pub fn (v Volume) put_retention(bucket string, key string, version string, mode string, until i64) ! {
	if mode != 'GOVERNANCE' && mode != 'COMPLIANCE' {
		return error('invalid retention mode')
	}
	mut record := v.read_record(bucket, key, version)!
	record = meta.Object{
		...record
		retention_mode:  mode
		retention_until: until
	}
	v.write_record(bucket, key, version, record)!
}

// put_legal_hold sets or clears a version's legal hold.
pub fn (v Volume) put_legal_hold(bucket string, key string, version string, on bool) ! {
	mut record := v.read_record(bucket, key, version)!
	record = meta.Object{
		...record
		legal_hold: on
	}
	v.write_record(bucket, key, version, record)!
}

// put_tags replaces the current version's tags.
pub fn (v Volume) put_tags(bucket string, key string, tags map[string]string) ! {
	version := v.current(bucket, key)!
	record := v.read_record(bucket, key, version)!
	v.write_record(bucket, key, version, meta.Object{
		...record
		tags: tags.clone()
	})!
}

// get_tags reads the current version's tags.
pub fn (v Volume) get_tags(bucket string, key string) !map[string]string {
	stat := v.stat(bucket, key)!
	return stat.tags.clone()
}

// delete_tags clears the current version's tags.
pub fn (v Volume) delete_tags(bucket string, key string) ! {
	v.put_tags(bucket, key, map[string]string{})!
}

// list returns current-version stats under a prefix, up to limit.
pub fn (v Volume) list(bucket string, prefix string, limit int) ![]Stat {
	require_bucket(v, bucket)!
	entries := walk_keys(v.drives[0], bucket)!
	mut stats := []Stat{}
	for key in entries {
		if prefix.len > 0 && !key.starts_with(prefix) {
			continue
		}
		stats << v.stat(bucket, key) or { continue }
		if limit > 0 && stats.len >= limit {
			break
		}
	}
	return stats
}

// list_versions returns every version of every key under a prefix.
pub fn (v Volume) list_versions(bucket string, prefix string) ![]Stat {
	require_bucket(v, bucket)!
	entries := walk_keys(v.drives[0], bucket)!
	mut stats := []Stat{}
	for key in entries {
		if prefix.len > 0 && !key.starts_with(prefix) {
			continue
		}
		for version in v.versions_of(bucket, key)! {
			stats << v.stat_version(bucket, key, version) or { continue }
		}
	}
	return stats
}

// apply_lifecycle enforces the bucket's rules as of the given moment. Expired
// current versions are deleted, expired noncurrent versions are removed, and
// uploads older than the abort window are discarded. The moment is a parameter
// so a test can move the clock without sleeping.
pub fn (v Volume) apply_lifecycle(bucket string, now i64) ! {
	config := v.lifecycle_of(bucket)!
	for stat in v.list(bucket, '', 0)! {
		fact := lifecycle_fact(stat, now)
		if stat.delete_marker && lifecycle.marker_expired(config, fact, stat.modified, now) {
			v.delete_version(bucket, stat.key, stat.version, false)!
			continue
		}
		if lifecycle.restore_lapsed(fact, now) {
			v.rearchive(bucket, stat.key)!
		}
		expired_now := lifecycle.expired(config, fact, stat.modified, now)
		if expired_now {
			v.delete(bucket, stat.key)!
		}
		if !expired_now {
			target := lifecycle.transition_target(config, fact, stat.modified, now)
			if target.len > 0 {
				v.transition_version(bucket, stat.key, stat.version, target)!
			}
		}
		versions := v.versions_of(bucket, stat.key)!
		for version in versions {
			if version == stat.version {
				continue
			}
			older := v.stat_version(bucket, stat.key, version) or { continue }
			older_fact := lifecycle_fact(older, now)
			replaced_at := v.version_time(bucket, stat.key, next_version(versions, version))
			if lifecycle.noncurrent_expired(config, older_fact, replaced_at, now) {
				v.delete_version(bucket, stat.key, version, false)!
				continue
			}
			target := lifecycle.noncurrent_transition_target(config, older_fact, replaced_at, now)
			if target.len > 0 {
				v.transition_version(bucket, stat.key, version, target)!
			}
		}
	}
	v.abort_stale_uploads(bucket, config, now)!
}

fn next_version(versions []string, version string) string {
	for index, candidate in versions {
		if candidate == version && index + 1 < versions.len {
			return versions[index + 1]
		}
	}
	return version
}

fn (v Volume) version_time(bucket string, key string, version string) i64 {
	record := v.read_record(bucket, key, version) or { return 0 }
	return record.modified
}

fn (v Volume) abort_stale_uploads(bucket string, config lifecycle.Config, now i64) ! {
	base := os.join_path(bucket, uploads_dir)
	ids := v.drives[0].list(base) or { return }
	for id in ids {
		raw := v.drives[0].read(os.join_path(base, id, 'started')) or { continue }
		started := raw.bytestr().i64()
		if lifecycle.abort_upload(config, lifecycle.Fact{}, started, now) {
			for entry in v.drives[0].list(os.join_path(base, id)) or { []string{} } {
				for drive in v.drives {
					drive.remove(os.join_path(base, id, entry))!
				}
			}
		}
	}
}

// Replication is one destination for a bucket's writes. The prefix limits
// which keys are forwarded; an empty prefix forwards everything.
pub struct Replication {
pub:
	target         replicate.Target
	prefix         string
	tags           map[string]string
	delete_marker  bool
	bandwidth_bps  i64
	replica_mods   bool
}

const replication_file = '.replication.json'

// replication_of reads the bucket's replication rule. A bucket without one
// replicates nothing.
pub fn (v Volume) replication_of(bucket string) !Replication {
	require_bucket(v, bucket)!
	for drive in v.drives {
		raw := drive.read(os.join_path(bucket, replication_file)) or { continue }
		return json2.decode[Replication](raw.bytestr()) or { continue }
	}
	return Replication{}
}

// put_replication sets where the bucket's writes are copied.
pub fn (v Volume) put_replication(bucket string, rule Replication) ! {
	require_bucket(v, bucket)!
	replicate.may_edit(v.site())!
	encoded := json2.encode[Replication](rule, escape_unicode: true).bytes()
	for drive in v.drives {
		drive.write(os.join_path(bucket, replication_file), encoded)!
	}
}

fn (v Volume) replicate_put(bucket string, key string, data []u8, content_type string) {
	rule := v.replication_of(bucket) or { return }
	if rule.target.endpoint.len == 0 {
		return
	}
	stat := v.stat(bucket, key) or { return }
	if !replicate.forward_replica(stat.replica, rule.replica_mods) {
		return
	}
	if !replicate.selected(rule.prefix, rule.tags, key, stat.tags) {
		return
	}
	job := replicate.Job{
		op:           'put'
		bucket:       bucket
		key:          key
		content_type: content_type
	}
	if !v.admit_bandwidth(bucket, rule.bandwidth_bps, i64(data.len)) {
		v.remember_replication(job)
		v.count_repl(false)
		return
	}
	replicate.put(rule.target, bucket, key, data, content_type) or {
		v.remember_replication(job)
		v.count_repl(false)
		eprintln('vfs: replication of ${bucket}/${key} failed: ${err}')
		return
	}
	v.forget_replication(job)
	v.count_repl(true)
}

fn (v Volume) replicate_delete(bucket string, key string, tags map[string]string, op string) {
	rule := v.replication_of(bucket) or { return }
	if rule.target.endpoint.len == 0 || !replicate.selected(rule.prefix, rule.tags, key, tags) {
		return
	}
	if op == 'delete-marker' && !rule.delete_marker {
		return
	}
	v.deliver_removal(rule, bucket, key, op)
}

fn (v Volume) deliver_removal(rule Replication, bucket string, key string, op string) {
	job := replicate.Job{
		op:     op
		bucket: bucket
		key:    key
	}
	if op == 'delete-marker' {
		replicate.delete_marker(rule.target, bucket, key) or {
			v.remember_replication(job)
			v.count_repl(false)
			eprintln('vfs: replication ${op} of ${bucket}/${key} failed: ${err}')
			return
		}
	} else {
		replicate.delete(rule.target, bucket, key) or {
			v.remember_replication(job)
			v.count_repl(false)
			eprintln('vfs: replication ${op} of ${bucket}/${key} failed: ${err}')
			return
		}
	}
	v.forget_replication(job)
	v.count_repl(true)
}

const backlog_file = '.vfs.sys/replication.mrf'

fn (v Volume) replication_backlog() []replicate.Job {
	raw := v.drives[0].read(backlog_file) or { return []replicate.Job{} }
	return json2.decode[[]replicate.Job](raw.bytestr()) or { return []replicate.Job{} }
}

fn (v Volume) save_backlog(jobs []replicate.Job) {
	encoded := json2.encode[[]replicate.Job](jobs, escape_unicode: true).bytes()
	for drive in v.drives {
		drive.write(backlog_file, encoded) or {}
	}
}

fn (v Volume) remember_replication(job replicate.Job) {
	v.save_backlog(replicate.enqueue(v.replication_backlog(), job))
}

fn (v Volume) forget_replication(job replicate.Job) {
	v.save_backlog(replicate.without(v.replication_backlog(), job))
}

// retry_replication attempts every queued delivery again. A job that still
// fails stays in the queue. The returned count is how many were delivered.
pub fn (v Volume) retry_replication() !int {
	mut done := 0
	for job in v.replication_backlog() {
		if job.op == 'delete' || job.op == 'delete-marker' {
			rule := v.replication_of(job.bucket) or { continue }
			v.deliver_removal(rule, job.bucket, job.key, job.op)
		} else {
			body := v.get(job.bucket, job.key, []u8{}) or { continue }
			v.replicate_put(job.bucket, job.key, body, job.content_type)
		}
		if !v.still_queued(job) {
			done++
		}
	}
	return done
}

fn (v Volume) still_queued(job replicate.Job) bool {
	for waiting in v.replication_backlog() {
		if waiting.op == job.op && waiting.bucket == job.bucket && waiting.key == job.key {
			return true
		}
	}
	return false
}

const lifecycle_file = '.lifecycle.json'

// lifecycle_of reads the bucket's lifecycle rules. A bucket without any has an
// empty configuration, which expires nothing.
pub fn (v Volume) lifecycle_of(bucket string) !lifecycle.Config {
	require_bucket(v, bucket)!
	for drive in v.drives {
		raw := drive.read(os.join_path(bucket, lifecycle_file)) or { continue }
		return lifecycle.decode(raw.bytestr()) or { continue }
	}
	return lifecycle.Config{}
}

// put_lifecycle replaces the bucket's lifecycle rules.
pub fn (v Volume) put_lifecycle(bucket string, config lifecycle.Config) ! {
	require_bucket(v, bucket)!
	encoded := config.encode().bytes()
	for drive in v.drives {
		drive.write(os.join_path(bucket, lifecycle_file), encoded)!
	}
}

// delete_lifecycle removes the bucket's lifecycle rules.
pub fn (v Volume) delete_lifecycle(bucket string) ! {
	require_bucket(v, bucket)!
	for drive in v.drives {
		drive.remove(os.join_path(bucket, lifecycle_file))!
	}
}

// create_upload starts a multipart upload and returns its id.
pub fn (v Volume) create_upload(bucket string, key string) !string {
	require_bucket(v, bucket)!
	key_ok(key)!
	id := fresh_id()
	stamped := '${time.now().unix()}'.bytes()
	for drive in v.drives {
		drive.write(v.upload_path(bucket, key, id, 'started'), stamped)!
		drive.write(v.upload_path(bucket, key, id, 'key'), key.bytes())!
	}
	return id
}

// Upload is one multipart upload that has not been completed.
pub struct Upload {
pub:
	key        string
	upload_id  string
	initiated  i64
}

// list_uploads returns the open uploads in a bucket. The key is stored beside
// the upload so a listing does not have to guess it from the path.
pub fn (v Volume) list_uploads(bucket string) ![]Upload {
	require_bucket(v, bucket)!
	ids := v.drives[0].list(os.join_path(bucket, uploads_dir)) or { return []Upload{} }
	mut uploads := []Upload{}
	for id in ids {
		raw_key := v.drives[0].read(v.upload_path(bucket, '', id, 'key')) or { continue }
		raw_started := v.drives[0].read(v.upload_path(bucket, '', id, 'started')) or { continue }
		uploads << Upload{
			key:       raw_key.bytestr()
			upload_id: id
			initiated: raw_started.bytestr().i64()
		}
	}
	return uploads
}

fn (v Volume) default_hold(bucket string) (string, i64) {
	config := v.bucket_config(bucket) or { return '', 0 }
	if config.retention_days <= 0 || config.retention_mode.len == 0 {
		return '', 0
	}
	return config.retention_mode, time.now().unix() + i64(config.retention_days) * 86400
}

fn (v Volume) count_metric(name string) {
	if v.metrics == unsafe { nil } {
		return
	}
	registry := v.metrics
	match name {
		'put' { registry.count_put() }
		'get' { registry.count_get() }
		'delete' { registry.count_delete() }
		else {}
	}
}

fn (v Volume) audit(action string, bucket_name string, key string) {
	raw := v.drives[0].read('.vfs.sys/audit.json') or { return }
	config := notify.decode(raw.bytestr()) or { return }
	notify.send(config, notify.Event{
		event:  action
		bucket: bucket_name
		key:    key
	}) or {
		eprintln('vfs: audit ${bucket_name}/${key}: ${err}')
	}
}

fn (v Volume) emit(event string, bucket_name string, key string) {
	v.remember_listen(event, bucket_name, key)
	raw := v.get_doc(bucket_name, 'notification') or { return }
	config := notify.decode(raw.bytestr()) or { return }
	notify.send(config, notify.Event{
		event:  event
		bucket: bucket_name
		key:    key
	}) or {
		eprintln('vfs: notify ${bucket_name}/${key}: ${err}')
	}
}

// put_part stores one part. Parts are held verbatim and erasure coded only
// when the upload completes, because completion may reorder or drop parts.
pub fn (v Volume) put_part(bucket string, key string, upload_id string, number int, data []u8) !Part {
	v.require_upload(bucket, key, upload_id)!
	if number < 1 {
		return error('part number must be positive')
	}
	for drive in v.drives {
		drive.write(v.upload_path(bucket, key, upload_id, 'part-${number}'), data)!
	}
	return Part{
		number: number
		size:   i64(data.len)
		etag:   hex.encode(md5_of(data))
	}
}

// list_parts returns the parts uploaded so far, in number order.
pub fn (v Volume) list_parts(bucket string, key string, upload_id string) ![]Part {
	v.require_upload(bucket, key, upload_id)!
	entries := v.drives[0].list(v.upload_dir(bucket, key, upload_id))!
	mut parts := []Part{}
	for entry in entries {
		if !entry.starts_with('part-') {
			continue
		}
		number := entry.all_after('part-').int()
		data := v.drives[0].read(v.upload_path(bucket, key, upload_id, entry))!
		parts << Part{
			number: number
			size:   i64(data.len)
			etag:   hex.encode(md5_of(data))
		}
	}
	parts.sort(a.number < b.number)
	return parts
}

// complete_upload concatenates the named parts into one object. The etag is
// the multipart form: md5 of the concatenated part md5s, dash, part count.
pub fn (v Volume) complete_upload(bucket string, key string, upload_id string, numbers []int) !Stat {
	v.require_upload(bucket, key, upload_id)!
	mut body := []u8{}
	mut md5s := []u8{}
	for number in numbers {
		data := v.read_part(bucket, key, upload_id, number)!
		body << data
		md5s << md5_of(data)
	}
	etag := '${hex.encode(md5_of(md5s))}-${numbers.len}'
	version := fresh_id()
	v.write_version(bucket, key, version, body, body, 'application/octet-stream', map[string]string{},
		map[string]string{}, envelope.Envelope{}, '', '', '', '', '')!
	v.rewrite_etag(bucket, key, version, etag)!
	v.set_current(bucket, key, version)!
	v.abort_upload(bucket, key, upload_id)!
	return v.stat_version(bucket, key, version)
}

// abort_upload discards an upload and its parts.
pub fn (v Volume) abort_upload(bucket string, key string, upload_id string) ! {
	require_bucket(v, bucket)!
	entries := v.drives[0].list(v.upload_dir(bucket, key, upload_id)) or {
		return error('upload not found: ${upload_id}')
	}
	for entry in entries {
		for drive in v.drives {
			drive.remove(v.upload_path(bucket, key, upload_id, entry))!
		}
	}
}

// seal encrypts object bytes when the request asks for it. SSE-S3 wraps a
// fresh data key with the volume's key backend; SSE-C uses the key the caller
// supplied and stores nothing that could recover it.
fn (v Volume) seal(bucket string, key string, data []u8, sse string, customer_key []u8, kms_key_id string) !([]u8, envelope.Envelope) {
	if sse.len == 0 {
		return data, envelope.Envelope{}
	}
	context := envelope.key_context(bucket, key)
	if sse == 'SSE-KMS' {
		raw := kms.material(v.kms_keys, kms_key_id)!
		backend := kms.local_backend(raw)!
		generated := kms.generate(backend, context)!
		sealed := envelope.seal(generated.plain, data, context)!
		return sealed, envelope.Envelope{
			mode:        'SSE-KMS'
			wrapped_key: envelope.encode_key(generated.wrapped)
		}
	}
	if sse == 'SSE-C' {
		if customer_key.len != 32 {
			return error('SSE-C key must be 32 bytes')
		}
		sealed := envelope.seal(customer_key, data, context)!
		return sealed, envelope.Envelope{
			mode:    'SSE-C'
			key_md5: base64.encode(md5_of(customer_key))
		}
	}
	if sse != 'SSE-S3' {
		return error('unsupported encryption scheme')
	}
	backend := v.keys or { return error('SSE-S3 requires a key backend') }
	generated := kms.generate(backend, context)!
	sealed := envelope.seal(generated.plain, data, context)!
	return sealed, envelope.Envelope{
		mode:        'SSE-S3'
		wrapped_key: envelope.encode_key(generated.wrapped)
	}
}

// unseal recovers object bytes. SSE-S3 unwraps the stored data key; SSE-C uses
// the key the caller brought, which the volume never stored.
fn (v Volume) unseal(bucket string, key string, sealed []u8, record meta.Object, customer_key []u8) ![]u8 {
	context := envelope.key_context(bucket, key)
	if record.sse == 'SSE-KMS' {
		raw := kms.material(v.kms_keys, record.kms_key_id)!
		backend := kms.local_backend(raw)!
		wrapped := envelope.decode_key(record.wrapped_key)
		data_key := kms.reveal(backend, wrapped, context)!
		return envelope.open(data_key, sealed, context)
	}
	if record.sse == 'SSE-S3' {
		backend := v.keys or { return error('SSE-S3 requires a key backend') }
		wrapped := envelope.decode_key(record.wrapped_key)
		data_key := kms.reveal(backend, wrapped, context)!
		return envelope.open(data_key, sealed, context)
	}
	if record.sse == 'SSE-C' {
		if customer_key.len == 0 {
			return error('object requires customer key')
		}
		return envelope.open(customer_key, sealed, context)
	}
	return error('unsupported encryption scheme')
}

// geometry_of is the erasure layout one object was written with. Reduced
// redundancy keeps a single parity shard; every other accepted class uses the
// set default. Reads and heals must use this, not the volume default, or a
// reduced object would be rebuilt with the wrong stripe.
fn (v Volume) geometry_of(class string) !erasure.Layout {
	return layout.plan(v.drives.len, class)
}

fn (v Volume) put_shards(bucket string, key string, version string, stored []u8, shift int, geometry erasure.Layout) ! {
	shards := erasure.encode(geometry, stored)!
	mut wrote := 0
	width := geometry.total()
	for shard in shards {
		drive_index := (shard.index + shift) % width
		base := os.join_path(version_dir(bucket, key, version), shard_file)
		framed := bitrot.frame(v.bitrot, shard.data)
		v.drives[drive_index].write(base, framed) or { continue }
		wrote++
	}
	if wrote < layout.write_quorum(width, geometry.parity_shards) {
		return error('write quorum not met')
	}
}

fn (v Volume) write_version(bucket string, key string, version string, stored []u8, plain []u8, content_type string, user_meta map[string]string, tags map[string]string, sealed_env envelope.Envelope, storage_class string, codec_name string, checksum_alg string, sum string, kms_key_id string) ! {
	class := if storage_class.len > 0 { storage_class } else { 'STANDARD' }
	geometry := v.geometry_of(class)!
	shift := layout.rotate(v.distribution, key, geometry.total(), v.deploy_id)
	v.put_shards(bucket, key, version, stored, shift, geometry)!
	hold_mode, hold_until := v.default_hold(bucket)
	record := meta.Object{
		key:           key
		version:       version
		size:          i64(plain.len)
		etag:          hex.encode(md5_of(plain))
		content_type:  if content_type.len > 0 { content_type } else { 'application/octet-stream' }
		storage_class: class
		user_meta:     user_meta.clone()
		tags:          tags.clone()
		sha256:        hex.encode(sha256.sum256(plain))
		modified:      meta.new(key, i64(plain.len), '').modified
		sse:           sealed_env.mode
		wrapped_key:   sealed_env.wrapped_key
		sse_key_md5:   sealed_env.key_md5
		bitrot:        v.bitrot.str()
		codec:         codec_name
		checksum_alg:  checksum_alg
		checksum:      sum
		placement:       shift
		stored_size:     i64(stored.len)
		retention_mode:  hold_mode
		retention_until: hold_until
		kms_key_id:      kms_key_id
	}
	v.write_record(bucket, key, version, record)!
}

// prepare_body checksums the plaintext and then compresses it. The checksum is
// of the bytes the client sent; encryption is applied to the compressed form.
fn prepare_body(data []u8, codec_name string, checksum_name string) !([]u8, string) {
	sum := if checksum_name.len == 0 {
		''
	} else {
		kind := checksum.parse(checksum_name)!
		hex.encode(kind.sum(data))
	}
	chosen := codec.parse(codec_name)!
	return codec.frame(chosen, data)!, sum
}

fn (v Volume) rewrite_etag(bucket string, key string, version string, etag string) ! {
	record := v.read_record(bucket, key, version)!
	v.write_record(bucket, key, version, meta.Object{
		...record
		etag: etag
	})!
}

fn (v Volume) write_record(bucket string, key string, version string, record meta.Object) ! {
	encoded := record.encode().bytes()
	for drive in v.drives {
		drive.write(os.join_path(version_dir(bucket, key, version), meta_file), encoded)!
	}
}

fn (v Volume) read_record(bucket string, key string, version string) !meta.Object {
	path := os.join_path(version_dir(bucket, key, version), meta_file)
	for drive in v.drives {
		raw := drive.read(path) or { continue }
		return meta.decode(raw.bytestr()) or { continue }
	}
	return error('object not found: ${key}')
}

fn (v Volume) get_version(bucket string, key string, version string, customer_key []u8) ![]u8 {
	record := v.read_record(bucket, key, version)!
	if record.archived {
		return error('object is archived')
	}
	cache_key := '${bucket}/${key}/${version}'
	if v.objects != unsafe { nil } {
		mut mem := v.objects
		if found := mem.get(cache_key) {
			return found
		}
	}
	stored_len := if record.stored_size > 0 { record.stored_size } else { record.size }
	sealed := v.read_shards(bucket, key, version, stored_len, record)!
	mut body := sealed.clone()
	if record.sse.len > 0 {
		body = v.unseal(bucket, key, sealed, record, customer_key)!
	}
	chosen := codec.parse(record.codec)!
	plain := codec.unframe(chosen, body)!
	if record.checksum_alg.len > 0 {
		kind := checksum.parse(record.checksum_alg)!
		if hex.encode(kind.sum(plain)) != record.checksum {
			return error('checksum mismatch')
		}
	}
	if v.objects != unsafe { nil } && customer_key.len == 0 {
		mut mem := v.objects
		mem.put(cache_key, plain)
	}
	return plain
}

fn (v Volume) read_shards(bucket string, key string, version string, size i64, record meta.Object) ![]u8 {
	algo := bitrot.parse(record.bitrot)!
	geometry := v.geometry_of(record.storage_class)!
	mut shards := []?erasure.Shard{len: geometry.total()}
	mut present := 0
	shift := record.placement
	width := geometry.total()
	for index in 0 .. width {
		base := os.join_path(version_dir(bucket, key, version), shard_file)
		framed := v.drives[index].read(base) or { continue }
		data := bitrot.open_frame(algo, framed) or { continue }
		logical := (index - shift + width) % width
		shards[logical] = erasure.Shard{
			index:  logical
			data:   data
			digest: algo.sum(data)
		}
		present++
	}
	if present < layout.response_quorum(width) {
		return error('read quorum not met')
	}
	return erasure.decode(geometry, shards, int(size))
}

pub fn (v Volume) stat_version(bucket string, key string, version string) !Stat {
	require_bucket(v, bucket)!
	record := v.read_record(bucket, key, version)!
	current := v.current(bucket, key) or { '' }
	return stat_of(record, current == version)
}

fn (v Volume) remove_version(bucket string, key string, version string) ! {
	base := os.join_path(version_dir(bucket, key, version), shard_file)
	for drive in v.drives {
		drive.remove(base)!
		drive.remove(base + '.sha256')!
		drive.remove(os.join_path(version_dir(bucket, key, version), meta_file))!
	}
}

fn (v Volume) versions_of(bucket string, key string) ![]string {
	dir := os.join_path(object_dir(bucket, key), versions_dir)
	entries := v.drives[0].list(dir) or { return []string{} }
	mut versions := []string{}
	for entry in entries {
		versions << entry
	}
	versions.sort()
	return versions
}

fn (v Volume) current(bucket string, key string) !string {
	require_bucket(v, bucket)!
	path := os.join_path(object_dir(bucket, key), current_file)
	for drive in v.drives {
		raw := drive.read(path) or { continue }
		version := raw.bytestr().trim_space()
		if version.len > 0 {
			return version
		}
	}
	return error('object not found: ${key}')
}

// write_delete_marker adds a version with no bytes and makes it current.
fn (v Volume) write_delete_marker(bucket string, key string) !Stat {
	key_ok(key)!
	version := fresh_id()
	record := meta.Object{
		key:           key
		version:       version
		modified:      meta.new(key, 0, '').modified
		delete_marker: true
	}
	v.write_record(bucket, key, version, record)!
	v.set_current(bucket, key, version)!
	return stat_of(record, true)
}

// advance_current points a key at its newest surviving version, or clears the
// pointer when nothing survives.
fn (v Volume) advance_current(bucket string, key string) ! {
	versions := v.versions_of(bucket, key)!
	if versions.len == 0 {
		v.clear_current(bucket, key)!
		return
	}
	v.set_current(bucket, key, versions[versions.len - 1])!
}

fn (v Volume) versioning_of(bucket string) string {
	config := v.bucket_config(bucket) or {
		return ''
	}
	return config.versioning
}

fn (v Volume) object_lock_of(bucket string) bool {
	config := v.bucket_config(bucket) or { return false }
	return config.object_lock
}

const config_file = '.config.json'

// bucket_config reads the bucket's behaviour record. A bucket without one
// behaves as unversioned and unlocked.
pub fn (v Volume) bucket_config(bucket string) !meta.BucketConfig {
	require_bucket(v, bucket)!
	for drive in v.drives {
		raw := drive.read(os.join_path(bucket, config_file)) or { continue }
		return json2.decode[meta.BucketConfig](raw.bytestr()) or { continue }
	}
	return meta.BucketConfig{}
}

// put_bucket_config stores the bucket's behaviour record on every drive.
pub fn (v Volume) put_bucket_config(bucket string, config meta.BucketConfig) ! {
	require_bucket(v, bucket)!
	encoded := json2.encode[meta.BucketConfig](config, escape_unicode: true).bytes()
	for drive in v.drives {
		drive.write(os.join_path(bucket, config_file), encoded)!
	}
}

fn (v Volume) set_current(bucket string, key string, version string) ! {
	for drive in v.drives {
		drive.write(os.join_path(object_dir(bucket, key), current_file), version.bytes())!
	}
}

fn (v Volume) clear_current(bucket string, key string) ! {
	for drive in v.drives {
		drive.remove(os.join_path(object_dir(bucket, key), current_file))!
	}
}

fn (v Volume) upload_dir(bucket string, key string, upload_id string) string {
	return os.join_path(bucket, uploads_dir, upload_id)
}

fn (v Volume) upload_path(bucket string, key string, upload_id string, name string) string {
	return os.join_path(v.upload_dir(bucket, key, upload_id), name)
}

fn (v Volume) require_upload(bucket string, key string, upload_id string) ! {
	require_bucket(v, bucket)!
	key_ok(key)!
	if !v.drives[0].exists(v.upload_path(bucket, key, upload_id, 'started')) {
		return error('upload not found: ${upload_id}')
	}
}

fn (v Volume) read_part(bucket string, key string, upload_id string, number int) ![]u8 {
	path := v.upload_path(bucket, key, upload_id, 'part-${number}')
	for drive in v.drives {
		data := drive.read(path) or { continue }
		return data
	}
	return error('part not found: ${number}')
}

// walk_keys lists object keys by finding current pointers. Upload scratch and
// the bucket marker are skipped.
fn walk_keys(drive disk.Local, dir string) ![]string {
	mut found := []string{}
	entries := drive.list(dir) or { return found }
	for entry in entries {
		if entry == '.bucket' || entry == uploads_dir || entry.ends_with('.tmp') {
			continue
		}
		child := os.join_path(dir, entry)
		if entry == current_file {
			key := dir.all_after_first('/')
			if key.len > 0 {
				found << key
			}
			continue
		}
		if entry == versions_dir {
			continue
		}
		found << walk_keys(drive, child)!
	}
	found.sort()
	return found
}

fn stat_of(record meta.Object, latest bool) Stat {
	return Stat{
		key:             record.key
		version:         record.version
		size:            record.size
		etag:            record.etag
		content_type:    record.content_type
		storage_class:   layout.effective_class(record.storage_class, record.tier)
		modified:        record.modified
		user_meta:       record.user_meta
		tags:            record.tags
		delete_marker:   record.delete_marker
		latest:          latest
		sse:             record.sse
		sse_key_md5:     record.sse_key_md5
		retention_mode:  record.retention_mode
		retention_until: record.retention_until
		legal_hold:      record.legal_hold
		tier:            record.tier
		archived:        record.archived
		restore_until:   record.restore_until
		replica:         record.replica
	}
}

fn lifecycle_fact(stat Stat, now i64) lifecycle.Fact {
	locked := stat.legal_hold || (stat.retention_mode.len > 0 && stat.retention_until > now)
	return lifecycle.Fact{
		key:           stat.key
		size:          stat.size
		tags:          stat.tags
		locked:        locked
		tier:          stat.tier
		archived:      stat.archived
		restore_until: stat.restore_until
	}
}

fn fresh_id() string {
	return rand.uuid_v4().replace('-', '')
}

fn md5_of(data []u8) []u8 {
	return md5.sum(data)
}
