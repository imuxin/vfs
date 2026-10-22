// surface is the rest of the management API: identity administration, the KMS
// key ring, inspection, pools, audit, and replication targets.
module admin

import json2
import net.http
import net.urllib
import time
import kms
import store

fn (s Service) surface(path string, req http.Request, query urllib.Values) ?http.Response {
	if path == '/v3/users' && req.method == .get {
		return json_body(json2.encode(s.directory.list_users(), escape_unicode: true))
	}
	if path == '/v3/user' && req.method == .delete {
		name := query.get('accessKey') or { return bad('missing accessKey') }
		s.directory.delete_user(name) or { return failed('${err}') }
		return empty_ok()
	}
	if path == '/v3/user/status' && req.method == .put {
		name := query.get('accessKey') or { return bad('missing accessKey') }
		status := query.get('status') or { return bad('missing status') }
		s.directory.set_user_status(name, status) or { return failed('${err}') }
		return empty_ok()
	}
	if path == '/v3/user/rotate' && req.method == .post {
		name := query.get('accessKey') or { return bad('missing accessKey') }
		body := json2.decode[SecretBody](req.data) or { return bad('malformed secret') }
		s.directory.rotate_key(name, body.secret_key) or { return failed('${err}') }
		return empty_ok()
	}
	if path == '/v3/groups' && req.method == .get {
		return json_body(json2.encode(s.directory.list_groups(), escape_unicode: true))
	}
	if path == '/v3/group' && req.method == .delete {
		name := query.get('name') or { return bad('missing name') }
		s.directory.delete_group(name) or { return failed('${err}') }
		return empty_ok()
	}
	if path == '/v3/group/status' && req.method == .put {
		name := query.get('name') or { return bad('missing name') }
		status := query.get('status') or { return bad('missing status') }
		s.directory.set_group_status(name, status) or { return failed('${err}') }
		return empty_ok()
	}
	if path == '/v3/group/member' && req.method == .post {
		name := query.get('group') or { return bad('missing group') }
		user := query.get('user') or { return bad('missing user') }
		action := query.get('action') or { return bad('missing action') }
		s.directory.group_member(name, user, action == 'add') or { return failed('${err}') }
		return empty_ok()
	}
	if path == '/v3/service-accounts' && req.method == .get {
		parent := query.get('user') or { '' }
		return json_body(json2.encode(s.directory.service_accounts(parent), escape_unicode: true))
	}
	if path == '/v3/service-account' && req.method == .get {
		access := query.get('accessKey') or { return bad('missing accessKey') }
		for item in s.directory.service_accounts('') {
			if item.access_key == access {
				return json_body(json2.encode(item, escape_unicode: true))
			}
		}
		return bad('service account not found')
	}
	if path == '/v3/service-account' && req.method == .delete {
		access := query.get('accessKey') or { return bad('missing accessKey') }
		s.directory.delete_key(access) or { return failed('${err}') }
		return empty_ok()
	}
	if path == '/v3/sessions' && req.method == .get {
		return json_body(json2.encode(s.directory.sessions(), escape_unicode: true))
	}
	if path == '/v3/session' && req.method == .delete {
		access := query.get('accessKey') or { return bad('missing accessKey') }
		mut found := false
		for item in s.directory.sessions() {
			if item.access_key == access {
				found = true
			}
		}
		if !found {
			return bad('not a session key')
		}
		s.directory.revoke_session(access) or { return failed('${err}') }
		return empty_ok()
	}
	if path == '/v3/mfa/enroll' && req.method == .post {
		user := query.get('user') or { return bad('missing user') }
		_ = s.directory.user(user) or { return bad('no such user') }
		record := s.directory.enroll_mfa(user) or { return failed('${err}') }
		return json_body(json2.encode(record, escape_unicode: true))
	}
	if path == '/v3/mfa/reset' && req.method == .post {
		user := query.get('user') or { return bad('missing user') }
		s.directory.reset_mfa(user) or { return failed('${err}') }
		return empty_ok()
	}
	if path == '/v3/ssh-key' && req.method == .put {
		user := query.get('user') or { return bad('missing user') }
		body := json2.decode[SSHBody](req.data) or { return bad('malformed ssh key') }
		s.directory.put_ssh_key(user, body.key) or { return failed('${err}') }
		return empty_ok()
	}
	if path == '/v3/ssh-key' && req.method == .get {
		user := query.get('user') or { return bad('missing user') }
		return json_body(json2.encode(s.directory.ssh_keys(user), escape_unicode: true))
	}
	if path == '/v3/ssh-key' && req.method == .delete {
		user := query.get('user') or { return bad('missing user') }
		key := query.get('key') or { return bad('missing key') }
		s.directory.delete_ssh_key(user, key) or { return failed('${err}') }
		return empty_ok()
	}
	if response := s.kms_routes(path, req, query) {
		return response
	}
	if response := s.data_routes(path, req, query) {
		return response
	}
	return none
}

struct SecretBody {
	secret_key string @[json: 'secretKey']
}

struct SSHBody {
	key string
}

struct KeyBody {
	id   string
	tags map[string]string
}

fn (s Service) kms_routes(path string, req http.Request, query urllib.Values) ?http.Response {
	if path == '/v3/kms/key' && req.method == .post {
		body := json2.decode[KeyBody](req.data) or { return bad('malformed kms key') }
		ring := s.ring() or { return failed('${err}') }
		ring.create(body.id, body.tags) or { return failed('${err}') }
		s.refresh_key(body.id) or { return failed('${err}') }
		return empty_ok()
	}
	if path == '/v3/kms/key' && req.method == .get {
		id := query.get('id') or { return bad('missing id') }
		ring := s.ring() or { return failed('${err}') }
		info := ring.describe(id) or { return failed('${err}') }
		return json_body(json2.encode(info, escape_unicode: true))
	}
	if path == '/v3/kms/keys' && req.method == .get {
		ring := s.ring() or { return failed('${err}') }
		list := ring.list() or { return failed('${err}') }
		return json_body(json2.encode(list, escape_unicode: true))
	}
	if path == '/v3/kms/key/status' && req.method == .put {
		id := query.get('id') or { return bad('missing id') }
		enabled := query.get('enabled') or { return bad('missing enabled') }
		ring := s.ring() or { return failed('${err}') }
		ring.set_enabled(id, enabled == 'true') or { return failed('${err}') }
		s.refresh_key(id) or { return failed('${err}') }
		return empty_ok()
	}
	if path == '/v3/kms/key/rotate' && req.method == .post {
		id := query.get('id') or { return bad('missing id') }
		ring := s.ring() or { return failed('${err}') }
		ring.rotate(id) or { return failed('${err}') }
		s.refresh_key(id) or { return failed('${err}') }
		return empty_ok()
	}
	if path == '/v3/kms/key/reencrypt' && req.method == .post {
		id := query.get('id') or { return bad('missing id') }
		ring := s.ring() or { return failed('${err}') }
		ring.reencrypt(id) or { return failed('${err}') }
		s.refresh_key(id) or { return failed('${err}') }
		return empty_ok()
	}
	if path == '/v3/kms/key/tags' && req.method == .put {
		id := query.get('id') or { return bad('missing id') }
		tags := json2.decode[map[string]string](req.data) or { return bad('malformed tags') }
		ring := s.ring() or { return failed('${err}') }
		ring.tag(id, tags) or { return failed('${err}') }
		return empty_ok()
	}
	if path == '/v3/kms/key' && req.method == .delete {
		id := query.get('id') or { return bad('missing id') }
		ring := s.ring() or { return failed('${err}') }
		ring.mark_deleted(id, time.now().unix()) or { return failed('${err}') }
		mut loaded := s.volume
		loaded.remove_kms_key(id)
		return empty_ok()
	}
	if path == '/v3/kms/backup' && req.method == .get {
		ring := s.ring() or { return failed('${err}') }
		body := ring.backup() or { return failed('${err}') }
		return json_body(body)
	}
	if path == '/v3/kms/restore' && req.method == .put {
		ring := s.ring() or { return failed('${err}') }
		count := ring.restore(req.data) or { return failed('${err}') }
		s.reload_keys() or { return failed('${err}') }
		return json_body('{"restored":${count}}')
	}
	if path == '/v3/kms/purge' && req.method == .post {
		grace := (query.get('grace') or { '0' }).i64()
		s.volume.purge_kms(time.now().unix(), grace)
		return empty_ok()
	}
	return none
}

fn (s Service) data_routes(path string, req http.Request, query urllib.Values) ?http.Response {
	if path == '/v3/inspect-data' && req.method == .get {
		bucket := query.get('bucket') or { return bad('missing bucket') }
		key := query.get('key') or { return bad('missing key') }
		body := s.volume.inspect_data(bucket, key) or { return failed('${err}') }
		return http.new_response(status: .ok, body: body.bytestr())
	}
	if path == '/v3/trace' && req.method == .get {
		return http.new_response(
			status: .ok
			body:   s.volume.trace_text()
			header: http.new_header(key: .content_type, value: 'application/x-ndjson')
		)
	}
	if path == '/v3/bucket-meta' && req.method == .get {
		bucket := query.get('bucket') or { return bad('missing bucket') }
		body := s.volume.export_bucket_meta(bucket) or { return failed('${err}') }
		return json_body(body)
	}
	if path == '/v3/bucket-meta' && req.method == .put {
		bucket := query.get('bucket') or { return bad('missing bucket') }
		s.volume.import_bucket_meta(bucket, req.data) or { return failed('${err}') }
		return empty_ok()
	}
	if path == '/v3/orphans' && req.method == .post {
		return json_body('{"removed":${s.volume.recover_orphans()}}')
	}
	if path == '/v3/integrity' && req.method == .post {
		fixed := s.volume.scrub_volume() or { return failed('${err}') }
		s.volume.trace('integrity', 'fixed=${fixed}')
		return json_body('{"fixed":${fixed}}')
	}
	if path == '/v3/speedtest' && req.method == .post {
		body := s.volume.speedtest() or { return failed('${err}') }
		return json_body(body)
	}
	if path == '/v3/speedtest/devnull' && req.method == .post {
		return json_body(s.volume.devnull(req.data.bytes()))
	}
	if path == '/v3/snapshot' && req.method == .get {
		body := s.volume.snapshot() or { return failed('${err}') }
		return json_body(body)
	}
	if path == '/v3/tls/cert' && req.method == .put {
		s.volume.publish_cert(req.data) or { return failed('${err}') }
		return empty_ok()
	}
	if path == '/v3/tls/status' && req.method == .get {
		body := s.volume.cert_status() or { return failed('${err}') }
		return json_body(body)
	}
	if path == '/v3/tls/reload' && req.method == .post {
		body := s.volume.reload_cert() or { return failed('${err}') }
		return json_body(body)
	}
	if path == '/v3/plugins' && req.method == .get {
		return json_body(s.volume.plugins())
	}
	if path == '/v3/plugins' && req.method == .put {
		s.volume.put_plugins(req.data) or { return failed('${err}') }
		return empty_ok()
	}
	if path == '/v3/durability' && req.method == .put {
		bucket := query.get('bucket') or { return bad('missing bucket') }
		copies := (query.get('copies') or { return bad('missing copies') }).int()
		s.volume.put_durability(bucket, copies) or { return failed('${err}') }
		return empty_ok()
	}
	if path == '/v3/durability' && req.method == .get {
		bucket := query.get('bucket') or { return bad('missing bucket') }
		return json_body('{"copies":${s.volume.durability_of(bucket)}}')
	}
	if path == '/v3/audit' && req.method == .put {
		s.volume.put_audit(req.data) or { return failed('${err}') }
		return empty_ok()
	}
	if path == '/v3/audit' && req.method == .get {
		return json_body(s.volume.audit_text())
	}
	if path == '/v3/audit' && req.method == .delete {
		s.volume.clear_audit() or { return failed('${err}') }
		return empty_ok()
	}
	if path == '/v3/pools/expand' && req.method == .post {
		drives := (query.get('drives') or { return bad('missing drives') }).int()
		root := query.get('root') or { return bad('missing root') }
		s.volume.expand_pool(drives, root) or { return failed('${err}') }
		return empty_ok()
	}
	if path == '/v3/pools/decommission/cancel' && req.method == .post {
		s.volume.cancel_decommission() or { return failed('${err}') }
		return empty_ok()
	}
	if path == '/v3/pools/decommission/clear' && req.method == .post {
		s.volume.clear_decommission() or { return failed('${err}') }
		return empty_ok()
	}
	if path == '/v3/site-replication/netperf' && req.method == .post {
		return json_body('{"traffic":false}')
	}
	if path == '/v3/replication/target' && req.method == .put {
		target := json2.decode[store.RemoteTarget](req.data) or { return bad('malformed target') }
		s.volume.put_target(target) or { return failed('${err}') }
		return empty_ok()
	}
	if path == '/v3/replication/target' && req.method == .get {
		return json_body(json2.encode(s.public_targets(), escape_unicode: true))
	}
	if path == '/v3/replication/target' && req.method == .delete {
		name := query.get('name') or { return bad('missing name') }
		s.volume.delete_target(name) or { return failed('${err}') }
		return empty_ok()
	}
	if path == '/v3/replication/target/diff' && req.method == .get {
		name := query.get('name') or { return bad('missing name') }
		missing := s.volume.target_diff(name) or { return failed('${err}') }
		return json_body(json2.encode(missing, escape_unicode: true))
	}
	if path == '/v3/metrics/catalog' && req.method == .get {
		mut put := u64(0)
		mut got := u64(0)
		mut deleted := u64(0)
		if s.volume.metrics != unsafe { nil } {
			snap := s.volume.metrics.snapshot()
			put = snap.put
			got = snap.get
			deleted = snap.delete
		}
		return json_body(obs_catalog(put, got, deleted, s.volume.drives.len, s.volume.pools().len))
	}
	if path == '/v3/idp-config' && (req.method == .put || req.method == .delete) {
		return http.new_response(
			status: .not_implemented
			body:   'use /v3/oidc/config/{provider_id}'
		)
	}
	return none
}

struct PublicTarget {
pub:
	name       string
	endpoint   string
	bucket     string
	access_key string
	bandwidth  i64
	synced     []string
}

fn (s Service) public_targets() []PublicTarget {
	mut out := []PublicTarget{}
	for target in s.volume.targets() {
		out << PublicTarget{
			name:       target.name
			endpoint:   target.endpoint
			bucket:     target.bucket
			access_key: target.access_key
			bandwidth:  target.bandwidth
			synced:     target.synced
		}
	}
	return out
}

fn (s Service) ring() !kms.Ring {
	backend := s.volume.keys or { return error('kms is not configured') }
	return kms.open_ring(s.volume.kms_root(), backend)
}

fn (s Service) refresh_key(id string) ! {
	ring := s.ring()!
	material := ring.material(id) or {
		mut missing := s.volume
		missing.remove_kms_key(id)
		return
	}
	mut loaded := s.volume
	loaded.install_kms_key(id, material)
}

fn (s Service) reload_keys() ! {
	ring := s.ring()!
	for item in ring.list()! {
		s.refresh_key(item.id)!
	}
}

fn obs_catalog(put u64, get u64, delete u64, drives int, sets int) string {
	return '{"vfs_requests_put":${put},"vfs_requests_get":${get},"vfs_requests_delete":${delete},"vfs_cluster_drives":${drives},"vfs_erasure_sets":${sets},"vfs_node_online":1,"vfs_process_cpu":0,"vfs_process_memory":0,"vfs_network_rx":0}'
}

fn json_body(body string) http.Response {
	return http.new_response(
		status: .ok
		body:   body
		header: http.new_header(key: .content_type, value: 'application/json')
	)
}

fn empty_ok() http.Response {
	return http.new_response(status: .ok, body: '')
}
