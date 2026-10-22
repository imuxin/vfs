module main

import crypto.rand
import encoding.hex
import os
import time
import admin
import deploy
import diagnose
import erasure
import extract
import ftp
import iam
import inspect
import kms
import lifecycle
import meta
import objzip
import server
import store
import swift
import worker
import replicate
import s3
import tier

fn main() {
	args := os.args[1..]
	if args.len == 0 {
		println('vfs: object storage')
		println('usage: vfs server <volume>{ <volume>} [addr]')
		println('       vfs info')
		println('       vfs diagnose <log-file>')
		println('       vfs tls inspect <pem>')
		println('       vfs inspect bucket-meta <file>')
		println('       vfs connect <command>')
		return
	}
	match args[0] {
		'server' {
			addr, patterns := server_args(args[1..]) or {
				eprintln('vfs: ${err}')
				exit(2)
			}
			serve(patterns, addr) or {
				eprintln('vfs: ${err}')
				exit(1)
			}
		}
		'info' {
			println('vfs 0.1.0')
			println('erasure sets: 1 drive, or 2-16 drives')
			println('distribution: SIPMOD+PARITY (read CRCMOD and SIPMOD)')
			println('bitrot: HighwayHash256S')
		}
		'diagnose' {
			if args.len < 2 {
				eprintln('usage: vfs diagnose <log-file>')
				exit(2)
			}
			text := os.read_file(args[1]) or {
				eprintln('vfs: ${err}')
				exit(1)
			}
			hits := diagnose.scan(text)
			if hits.len == 0 {
				println('no known failure pattern')
				return
			}
			for hit in hits {
				println('${hit.rule.name}: ${hit.rule.meaning}')
			}
		}
		'selftest' {
			selftest() or {
				eprintln('selftest failed: ${err}')
				exit(1)
			}
			println('selftest ok')
		}
		'tls' {
			if args.len < 3 || args[1] != 'inspect' {
				eprintln('usage: vfs tls inspect <pem>')
				exit(2)
			}
			text := os.read_file(args[2]) or {
				eprintln('vfs: ${err}')
				exit(1)
			}
			report := inspect.tls_text(text) or {
				eprintln('vfs: ${err}')
				exit(1)
			}
			println(report)
		}
		'inspect' {
			if args.len < 3 || args[1] != 'bucket-meta' {
				eprintln('usage: vfs inspect bucket-meta <file>')
				exit(2)
			}
			text := os.read_file(args[2]) or {
				eprintln('vfs: ${err}')
				exit(1)
			}
			report := inspect.bucket_meta(text) or {
				eprintln('vfs: ${err}')
				exit(1)
			}
			println(report)
		}
		'connect' {
			report := inspect.connect(args[1..]) or {
				eprintln('vfs: ${err}')
				exit(1)
			}
			println(report)
		}
		else {
			eprintln('unknown command: ${args[0]}')
			exit(2)
		}
	}
}

fn server_args(rest []string) !(string, []string) {
	mut addr := ':9000'
	mut patterns := []string{}
	configured := os.getenv('VFS_VOLUMES')
	if configured.len > 0 {
		for part in configured.split(',') {
			trimmed := part.trim_space()
			if trimmed.len > 0 {
				patterns << trimmed
			}
		}
	}
	for arg in rest {
		if arg.starts_with(':') || (arg.contains(':') && !arg.contains('/') && !arg.contains('{')) {
			addr = arg
		} else {
			patterns << arg
		}
	}
	if patterns.len == 0 {
		return error('usage: vfs server <volume>{ <volume>} [addr]')
	}
	return addr, patterns
}

fn serve(patterns []string, addr string) ! {
	endpoints := deploy.volumes(patterns)!
	paths := deploy.local_paths(endpoints)
	if paths.len == 0 {
		return error('server needs at least one local volume')
	}
	volume := store.open(paths)!.with_kms(kms.local_backend(master_key()!)!)
	if volume.module_on('scanner') || volume.module_on('heal') || volume.module_on('bitrot')
		|| volume.module_on('migrate') {
		spawn worker.loop_scan(volume)
	}
	directory := identity_dir(paths[0])!
	access_key := env_or('VFS_ACCESS_KEY', 'vfsadmin')
	secret_key := env_or('VFS_SECRET_KEY', 'vfsadmin')
	root(directory, access_key, secret_key)!
	creds := iam.Credentials{
		directory: directory
	}
	mut endpoint := server.Endpoint{
		service: s3.Service{
			volume:    volume
			creds:     creds
			directory: directory
			region:    env_or('VFS_REGION', 'us-east-1')
		}
		admin:   admin.Service{
			directory: directory
			creds:     creds
			root_key:  access_key
			signer:    secret_key
			volume:    volume
		}
		swift_tokens: swift.new_tokens()
	}
	ftp_addr := env_or('VFS_FTP_ADDR', ':8021')
	if ftp_addr != 'off' {
		spawn ftp.serve(volume, creds, directory, ftp_addr)
	}
	ftps_addr := env_or('VFS_FTPS_ADDR', ':8022')
	if ftps_addr != 'off' {
		spawn ftp.serve_ftps(ftps_addr)
	}
	dav_addr := env_or('VFS_WEBDAV_ADDR', ':8080')
	if dav_addr != 'off' {
		mut dav := endpoint
		dav.dav_only = true
		spawn server.serve_async(&dav, dav_addr)
	}
	server.serve(mut endpoint, addr)!
}

// identity_dir opens the IAM directory beside the data, installing the built-in
// policies the admin API hands out.
fn identity_dir(data_dir string) !iam.Directory {
	chosen := os.getenv('VFS_IAM_DIR')
	root := if chosen.len > 0 { chosen } else { os.join_path(data_dir, '.iam') }
	directory := iam.open(root)!
	iam.install_builtin(directory)!
	return directory
}

// root ensures the root access key exists and carries the readwrite policy, so
// the operator named by the environment can both call the admin API and use S3.
fn root(directory iam.Directory, access_key string, secret_key string) ! {
	directory.put_user(iam.User{
		name:     access_key
		status:   'Enabled'
		policies: ['readwrite']
	})!
	directory.put_key(iam.AccessKey{
		access_key: access_key
		secret_key: secret_key
		user:       access_key
		status:     'Enabled'
	})!
}

// credentials picks the identity source. VFS_IAM_DIR selects an IAM directory,
// where each key's rights come from the policies attached to its user.
// Otherwise the process has one root key that may do anything.
fn env_or(name string, fallback string) string {
	got := os.getenv(name)
	return if got.len > 0 { got } else { fallback }
}

// master_key reads the SSE-S3 master key from VFS_MASTER_KEY as 64 hex
// characters. A deployment without one gets a key generated at startup, which
// encrypts within the process lifetime and cannot outlive it.
fn master_key() ![]u8 {
	configured := os.getenv('VFS_MASTER_KEY')
	if configured.len == 0 {
		eprintln('vfs: VFS_MASTER_KEY is unset, SSE-S3 data is readable only until restart')
		return rand.bytes(32)
	}
	if configured.len != 64 {
		return error('VFS_MASTER_KEY must be 64 hex characters')
	}
	return hex.decode(configured)
}

fn selftest() ! {
	layout := erasure.plan(2)!
	payload := 'the quick brown fox jumps'.bytes()
	shards := erasure.encode(layout, payload)!
	if shards.len != 2 {
		return error('expected 2 shards, got ${shards.len}')
	}
	for shard in shards {
		if !erasure.verify(shard) {
			return error('shard ${shard.index} failed its digest')
		}
	}
	mut missing_data := []?erasure.Shard{len: 2}
	missing_data[1] = shards[1]
	rebuilt := erasure.decode(layout, missing_data, payload.len)!
	if rebuilt != payload {
		return error('rebuilt payload does not match')
	}
	reed_solomon_selftest()!
	store_selftest()!
}

// reed_solomon_selftest checks a four drive set, which carries two parity
// shards. Dropping any two shards must still rebuild the payload, and dropping
// a third must fail rather than return bytes.
fn reed_solomon_selftest() ! {
	layout := erasure.plan(4)!
	if layout.parity_shards != 2 {
		return error('four drives should carry two parity shards')
	}
	payload := 'reed solomon survives two losses'.bytes()
	shards := erasure.encode(layout, payload)!
	for drop_a in 0 .. 4 {
		for drop_b in drop_a + 1 .. 4 {
			mut kept := []?erasure.Shard{len: 4}
			for index in 0 .. 4 {
				if index != drop_a && index != drop_b {
					kept[index] = shards[index]
				}
			}
			rebuilt := erasure.decode(layout, kept, payload.len)!
			if rebuilt != payload {
				return error('rebuild mismatch dropping shards ${drop_a} and ${drop_b}')
			}
		}
	}
	mut too_few := []?erasure.Shard{len: 4}
	too_few[2] = shards[2]
	if _ := erasure.decode(layout, too_few, payload.len) {
		return error('rebuild succeeded with a single shard')
	}
	wide_volume_selftest()!
}

// wide_volume_selftest writes through a four drive volume and reads the object
// back after two drives have lost their shard, the failure a two parity layout
// is sized for.
fn wide_volume_selftest() ! {
	base := os.join_path(os.temp_dir(), 'vfs-wide-${os.getpid()}')
	defer {
		os.rmdir_all(base) or {}
	}
	mut dirs := []string{}
	for index in 0 .. 4 {
		dirs << os.join_path(base, 'd${index}')
	}
	volume := store.open(dirs)!
	volume.make_bucket('wide')!
	body := 'kept across four drives'.bytes()
	volume.put(store.PutRequest{
		bucket: 'wide'
		key:    'obj.txt'
		data:   body
	})!
	os.rmdir_all(os.join_path(base, 'd1', 'wide'))!
	os.rmdir_all(os.join_path(base, 'd2', 'wide'))!
	got := volume.get('wide', 'obj.txt', []u8{})!
	if got != body {
		return error('four drive degraded read mismatch')
	}
}

fn store_selftest() ! {
	base := os.join_path(os.temp_dir(), 'vfs-selftest-${os.getpid()}')
	defer { os.rmdir_all(base) or {} }
	volume := store.open([
		os.join_path(base, 'd0'),
		os.join_path(base, 'd1'),
	])!
	volume.make_bucket('data')!
	body := 'stored across two drives'.bytes()
	wrote := volume.put(store.PutRequest{
		bucket:       'data'
		key:          'dir/file.txt'
		data:         body
		content_type: 'text/plain'
	})!
	if wrote.size != i64(body.len) {
		return error('stored size mismatch')
	}
	got := volume.get('data', 'dir/file.txt', []u8{})!
	if got != body {
		return error('read back payload mismatch')
	}
	// Drop the first drive's copy and confirm the object rebuilds.
	os.rmdir_all(os.join_path(base, 'd0', 'data', 'dir'))!
	rebuilt_obj := volume.get('data', 'dir/file.txt', []u8{})!
	if rebuilt_obj != body {
		return error('degraded read mismatch')
	}
	upload := volume.create_upload('data', 'joined.bin')!
	volume.put_part('data', 'joined.bin', upload, 1, 'aaa'.bytes())!
	volume.put_part('data', 'joined.bin', upload, 2, 'bbb'.bytes())!
	completed := volume.complete_upload('data', 'joined.bin', upload, [1, 2])!
	if completed.etag.ends_with('-2') == false {
		return error('multipart etag missing part count')
	}
	joined := volume.get('data', 'joined.bin', []u8{})!
	if joined.bytestr() != 'aaabbb' {
		return error('multipart body mismatch')
	}
	volume.copy('data', 'joined.bin', 'data', 'joined-copy.bin')!
	copied := volume.get('data', 'joined-copy.bin', []u8{})!
	if copied.bytestr() != 'aaabbb' {
		return error('copy mismatch')
	}
	volume.put_tags('data', 'joined.bin', {
		'env': 'test'
	})!
	tags := volume.get_tags('data', 'joined.bin')!
	if tags['env'] or { '' } != 'test' {
		return error('tag mismatch: ${tags}')
	}
	parsed := s3.parse_tagging('<Tagging><TagSet><Tag><Key>env</Key><Value>test</Value></Tag></TagSet></Tagging>')!
	if parsed['env'] or { '' } != 'test' {
		return error('tag parse mismatch: ${parsed}')
	}
	volume.put_bucket_config('data', meta.BucketConfig{
		versioning:  'Enabled'
		object_lock: true
	})!
	locked := volume.put(store.PutRequest{
		bucket:       'data'
		key:          'locked.txt'
		data:         'keep'.bytes()
		content_type: 'text/plain'
	})!
	volume.put_retention('data', 'locked.txt', locked.version, 'COMPLIANCE', time.now().unix() + 3600)!
	volume.delete_version('data', 'locked.txt', locked.version, true) or {}
	still := volume.get_version_bytes('data', 'locked.txt', locked.version, []u8{}) or {
		return error('object lock failed to keep the version')
	}
	if still.bytestr() != 'keep' {
		return error('locked version was modified')
	}
	volume.put_lifecycle('data', lifecycle.Config{
		rules: [
			lifecycle.Rule{
				expire_days: 1
				abort_days:  1
			},
		]
	})!
	volume.put(store.PutRequest{
		bucket:       'data'
		key:          'aging.txt'
		data:         'old'.bytes()
		content_type: 'text/plain'
	})!
	stale := volume.create_upload('data', 'pending.bin')!
	volume.put_part('data', 'pending.bin', stale, 1, 'part'.bytes())!
	volume.apply_lifecycle('data', time.now().unix() + 2 * 86400)!
	ageing := volume.stat('data', 'aging.txt') or { return error('expiry did not remove the object') }
	if !ageing.delete_marker {
		return error('expired object has no delete marker')
	}
	volume.list_parts('data', 'pending.bin', stale) or {}
	if _ := volume.list_parts('data', 'pending.bin', stale) {
		return error('stale upload was not aborted')
	}
	encryption_selftest(base)!
	kms_selftest(base)!
	tier_selftest(base)!
	replication_selftest(base)!
	snowball_selftest(base)!
	admin_selftest(base)!
	lock_selftest(base)!
	zip_selftest(base)!
	site_broadcast_selftest(base)!
	listen_selftest(base)!
}

fn listen_selftest(base string) ! {
	volume := store.open([
		os.join_path(base, 'listen'),
	])!
	volume.make_bucket('pics')!
	volume.put(store.PutRequest{
		bucket: 'pics'
		key:    'logs/a.json'
		data:   'x'.bytes()
	})!
	volume.put(store.PutRequest{
		bucket: 'pics'
		key:    'other.txt'
		data:   'y'.bytes()
	})!
	body := volume.listen('pics', 's3:ObjectCreated:*', 'logs/', '.json')
	if !body.contains('logs/a.json') || body.contains('other.txt') {
		return error('listen filter mismatch: ${body}')
	}
}

fn site_broadcast_selftest(base string) ! {
	owner := store.open([
		os.join_path(base, 'site-owner'),
	])!
	peer := store.open([
		os.join_path(base, 'site-peer'),
	])!
	owner.put_site(replicate.Site{
		enabled:  true
		owner:    true
		endpoint: 'http://127.0.0.1:1'
	})!
	owner.make_bucket('pics')!
	changes := owner.site_changes()
	if changes.len != 1 || changes[0].kind != 'bucket-create' || changes[0].name != 'pics' {
		return error('owner did not record the bucket')
	}
	applied := peer.apply_site(changes)!
	if applied != 1 || !peer.bucket_exists('pics') {
		return error('peer did not apply the bucket')
	}
	peer.make_bucket('local')!
	if peer.site_changes().len != 0 {
		return error('a non-owner recorded a site change')
	}
	if !owner.site_status().contains('"state":"offline"') {
		return error('a refused peer was not marked offline: ${owner.site_status()}')
	}
	if !owner.replication_metrics().contains('"failed":1') {
		return error('site push was not counted: ${owner.replication_metrics()}')
	}
}

fn zip_selftest(base string) ! {
	volume := store.open([
		os.join_path(base, 'zip'),
	])!
	volume.make_bucket('pics')!
	volume.put(store.PutRequest{
		bucket: 'pics'
		key:    'a.txt'
		data:   'alpha'.bytes()
	})!
	packed := volume.zip_prefix('pics', '')!
	found := objzip.decode(packed)!
	if found.len != 1 || found[0].data.bytestr() != 'alpha' {
		return error('object zip mismatch')
	}
}

fn lock_selftest(base string) ! {
	volume := store.open([
		os.join_path(base, 'locks'),
	])!
	volume.make_bucket('pics')!
	if volume.pools().len != 1 {
		return error('expected one pool')
	}
	volume.decommission_pool(0) or {
		if !'${err}'.contains('does not allow decommission') {
			return error('${err}')
		}
		volume.rebalance('start') or {
			if !'${err}'.contains('does not allow rebalance') {
				return error('${err}')
			}
			volume.lock_object('pics', 'a.txt')!
			volume.put(store.PutRequest{
				bucket: 'pics'
				key:    'a.txt'
				data:   'held'.bytes()
			}) or {
				if !'${err}'.contains('lock held') {
					return error('${err}')
				}
				if !volume.unlock_object('pics', 'a.txt') {
					return error('force unlock found nothing')
				}
				volume.put(store.PutRequest{
					bucket: 'pics'
					key:    'a.txt'
					data:   'held'.bytes()
				})!
				return
			}
			return error('a held lock did not block the write')
		}
		return error('single pool rebalance was accepted')
	}
	return error('single pool decommission was accepted')
}

fn admin_selftest(base string) ! {
	volume := store.open([
		os.join_path(base, 'admin'),
	])!
	if !volume.ready() {
		return error('fresh volume is not ready')
	}
	volume.make_bucket('pics')!
	volume.config_set('region', 'us-east-1', 1)!
	volume.config_set('region', 'eu-west-1', 2)!
	volume.config_restore('region', 3)!
	if volume.config_get('region')!.value != 'us-east-1' {
		return error('config restore failed')
	}
	info := volume.cluster_info()!
	if !info.contains('"drives":1') || !info.contains('"pics":0') {
		return error('cluster info: ${info}')
	}
	if volume.service('freeze')! != 'frozen' {
		return error('freeze did not stick')
	}
	volume.put(store.PutRequest{
		bucket: 'pics'
		key:    'a.txt'
		data:   'no'.bytes()
	}) or {
		if !'${err}'.contains('not writable') {
			return error('freeze rejected the write for the wrong reason: ${err}')
		}
		volume.service('unfreeze')!
		volume.service('stop')!
		if volume.ready() {
			return error('stopping volume is still ready')
		}
		return
	}
	return error('frozen volume accepted a write')
}

fn snowball_selftest(base string) ! {
	volume := store.open([
		os.join_path(base, 'snow'),
	])!
	volume.make_bucket('pics')!
	archive := extract.pack([
		extract.Member{
			key:  'a.txt'
			data: 'alpha'.bytes()
		},
	])
	volume.put(store.PutRequest{
		bucket:    'pics'
		key:       'ball.tar'
		data:      archive
		user_meta: {
			'snowball-auto-extract': 'true'
		}
		sse: 'SSE-KMS'
	}) or {
		if !'${err}'.contains('SSE-KMS') {
			return error('extract upload accepted SSE-KMS: ${err}')
		}
		volume.put(store.PutRequest{
			bucket:    'pics'
			key:       'ball.tar'
			data:      archive
			user_meta: {
				'snowball-auto-extract': 'true'
			}
		})!
		got := volume.get('pics', 'a.txt', []u8{})!
		if got.bytestr() != 'alpha' {
			return error('snowball member mismatch')
		}
		if stat := volume.stat('pics', 'ball.tar') {
			if stat.key == 'ball.tar' {
				return error('snowball archive was stored')
			}
		}
		return
	}
	return error('extract upload accepted SSE-KMS')
}

fn replication_selftest(base string) ! {
	volume := store.open([
		os.join_path(base, 'repl'),
	])!
	volume.make_bucket('pics')!
	volume.put(store.PutRequest{
		bucket: 'pics'
		key:    'a.txt'
		data:   'alpha'.bytes()
	})!
	volume.put(store.PutRequest{
		bucket: 'pics'
		key:    'b.txt'
		data:   'beta'.bytes()
	})!
	volume.put_tags('pics', 'a.txt', {
		'env': 'prod'
	})!
	volume.put_replication('pics', store.Replication{
		target: replicate.Target{
			endpoint:   'http://127.0.0.1:9'
			region:     'us-east-1'
			access_key: 'a'
			secret_key: 'b'
		}
		prefix:        'a'
		tags:          {
			'env': 'prod'
		}
		delete_marker: true
		bandwidth_bps: 1
	})!
	queued := volume.resync_replication('pics')!
	if queued != 1 {
		return error('resync queued ${queued}')
	}
	volume.put_site(replicate.Site{
		enabled:  true
		owner:    false
		endpoint: 'http://peer'
	})!
	volume.put_replication('pics', store.Replication{}) or { return }
	return error('non-owner changed replication')
}

// tier_selftest moves an object to a warm tier, refuses a read until restore,
// and drops the hot copy again when the restore window ends.
fn tier_selftest(base string) ! {
	volume := store.open([
		os.join_path(base, 'tier'),
	])!
	volume.make_bucket('warm')!
	volume.put_tier(tier.Remote{
		name:   'WARM'
		kind:   's3'
		bucket: 'archive'
	})!
	volume.put(store.PutRequest{
		bucket: 'warm'
		key:    'a.txt'
		data:   'cold-me'.bytes()
	})!
	volume.put_lifecycle('warm', lifecycle.Config{
		rules: [
			lifecycle.Rule{
				transition_days: 1
				transition_tier: 'WARM'
				tags:            {
					'keep': 'yes'
				}
				min_size: 1
			},
		]
	})!
	later := time.now().unix() + 2 * 86400
	volume.apply_lifecycle('warm', later)!
	kept := volume.get('warm', 'a.txt', []u8{})!
	if kept.bytestr() != 'cold-me' {
		return error('untagged object was transitioned')
	}
	volume.put_tags('warm', 'a.txt', {
		'keep': 'yes'
	})!
	volume.apply_lifecycle('warm', later)!
	volume.get('warm', 'a.txt', []u8{}) or {
		if !'${err}'.contains('archived') {
			return error('transition did not archive the object: ${err}')
		}
		volume.restore_object('warm', 'a.txt', 1, time.now().unix())!
		restored := volume.get('warm', 'a.txt', []u8{})!
		if restored.bytestr() != 'cold-me' {
			return error('restored payload mismatch')
		}
		volume.apply_lifecycle('warm', time.now().unix() + 2 * 86400)!
		volume.get('warm', 'a.txt', []u8{}) or {
			if '${err}'.contains('archived') {
				return
			}
			return error('restore window did not lapse: ${err}')
		}
		return error('archived object was readable after the restore window')
	}
	return error('tagged object stayed on the hot set')
}

// encryption_selftest checks the envelope: SSE-S3 bytes come back intact, the
// shards on disk are not the plaintext, and a different master key cannot read
// them. The last point is what makes the wrapping a key boundary rather than an
// encoding.
fn encryption_selftest(base string) ! {
	master := rand.bytes(32)!
	backend := kms.local_backend(master)!
	volume := store.open([
		os.join_path(base, 'enc'),
	])!.with_kms(backend)
	volume.make_bucket('sealed')!
	plain := 'sealed payload'.bytes()
	volume.put(store.PutRequest{
		bucket: 'sealed'
		key:    'secret.txt'
		data:   plain
		sse:    'SSE-S3'
	})!
	read := volume.get('sealed', 'secret.txt', []u8{})!
	if read != plain {
		return error('decrypted payload mismatch')
	}
	shard := newest_shard(os.join_path(base, 'enc', 'sealed', 'secret.txt', 'versions'))!
	if shard.bytestr().contains('sealed payload') {
		return error('plaintext leaked onto disk')
	}
	other := store.open([
		os.join_path(base, 'enc'),
	])!.with_kms(kms.local_backend(rand.bytes(32)!)!)
	other.get('sealed', 'secret.txt', []u8{}) or { return }
	return error('a foreign master key read the object')
}

// kms_selftest checks that SSE-KMS uses a registered key id and never the
// SSE-S3 master key. A missing id and an unknown id both fail closed.
fn kms_selftest(base string) ! {
	key := rand.bytes(32)!
	volume := store.open([
		os.join_path(base, 'kms'),
	])!.with_kms_key('alias/app', key)!
	volume.make_bucket('sealed')!
	plain := 'kms payload'.bytes()
	if _ := volume.put(store.PutRequest{
		bucket: 'sealed'
		key:    'secret.txt'
		data:   plain
		sse:    'SSE-KMS'
	}) {
		return error('SSE-KMS without a key id was accepted')
	}
	if _ := volume.put(store.PutRequest{
		bucket:     'sealed'
		key:        'secret.txt'
		data:       plain
		sse:        'SSE-KMS'
		kms_key_id: 'alias/missing'
	}) {
		return error('unknown SSE-KMS key was accepted')
	}
	volume.put(store.PutRequest{
		bucket:     'sealed'
		key:        'secret.txt'
		data:       plain
		sse:        'SSE-KMS'
		kms_key_id: 'alias/app'
	})!
	read := volume.get('sealed', 'secret.txt', []u8{})!
	if read != plain {
		return error('SSE-KMS payload mismatch')
	}
	foreign := store.open([
		os.join_path(base, 'kms'),
	])!.with_kms_key('alias/app', rand.bytes(32)!)!
	foreign.get('sealed', 'secret.txt', []u8{}) or { return }
	return error('a foreign SSE-KMS key read the object')
}

// newest_shard reads the shard file of the one version under a versions dir.
fn newest_shard(versions string) ![]u8 {
	ids := os.ls(versions)!
	if ids.len == 0 {
		return error('no version written')
	}
	return os.read_bytes(os.join_path(versions, ids[0], 'shard'))
}
