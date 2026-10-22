// ops is the admin surface for identities and background passes: groups,
// temporary credentials, a lifecycle scan, and a shard repair.
module admin

import json2
import net.http
import net.urllib
import time
import adminctl
import iam
import locktab
import pool
import replicate
import store
import tier
import worker

fn (s Service) dispatch(path string, req http.Request, query urllib.Values) ?http.Response {
	if path == '/v3/group' && req.method == .put {
		return s.put_group(req, query)
	}
	if path == '/v3/assume-role' && req.method == .post {
		return s.assume(req)
	}
	if path == '/v3/oidc/config' && req.method == .put {
		return s.put_oidc(req)
	}
	if path == '/v3/oidc/config' && req.method == .get {
		id := query.get('id') or { return bad('missing id') }
		provider := s.directory.provider(id) or { return failed('${err}') }
		return http.new_response(
			status: .ok
			body:   json2.encode[iam.Provider](provider, escape_unicode: true)
			header: http.new_header(key: .content_type, value: 'application/json')
		)
	}
	if path == '/v3/oidc/config' && req.method == .delete {
		id := query.get('id') or { return bad('missing id') }
		s.directory.delete_provider(id) or { return failed('${err}') }
		return http.new_response(status: .ok, body: '')
	}
	if path == '/v3/oidc/discovery' && req.method == .get {
		id := query.get('id') or { return bad('missing id') }
		provider := s.directory.provider(id) or { return failed('${err}') }
		return http.new_response(
			status: .ok
			body:   iam.discovery_document(provider)
			header: http.new_header(key: .content_type, value: 'application/json')
		)
	}
	if path == '/v3/oidc/login' && req.method == .post {
		id := query.get('id') or { return bad('missing id') }
		state := s.directory.begin_login(id) or { return failed('${err}') }
		return http.new_response(status: .ok, body: '{"state":"${state}"}')
	}
	if path == '/v3/oidc/callback' && req.method == .post {
		return s.oidc_callback(req)
	}
	if path == '/v3/oidc/logout' && req.method == .post {
		access_key := query.get('accessKey') or { return bad('missing accessKey') }
		s.directory.revoke_session(access_key) or { return failed('${err}') }
		return http.new_response(status: .ok, body: '')
	}
	if path == '/v3/assume-role-with-web-identity' && req.method == .post {
		return s.assume_web(req)
	}
	if path == '/v3/heal' && req.method == .post {
		return s.heal(query)
	}
	if path == '/v3/heal/resume' && req.method == .post {
		done := s.volume.resume_heal() or { return failed('${err}') }
		return http.new_response(status: .ok, body: '{"restored":${done},"backlog":${s.volume.heal_backlog()}}')
	}
	if path == '/v3/modules' && req.method == .get {
		return http.new_response(
			status: .ok
			body:   s.volume.modules_json()
			header: http.new_header(key: .content_type, value: 'application/json')
		)
	}
	if path == '/v3/modules' && req.method == .put {
		return s.put_modules(query)
	}
	if path == '/v3/bitrot' && req.method == .post {
		return s.bitrot(query)
	}
	if path == '/v3/datausage' && req.method == .post {
		body := s.volume.refresh_usage() or { return failed('${err}') }
		return http.new_response(
			status: .ok
			body:   body
			header: http.new_header(key: .content_type, value: 'application/json')
		)
	}
	if path == '/v3/datausage' && req.method == .get {
		return http.new_response(
			status: .ok
			body:   s.volume.usage_report()
			header: http.new_header(key: .content_type, value: 'application/json')
		)
	}
	if path == '/v3/migrate' && req.method == .post {
		return s.migrate(query)
	}
	if path == '/v3/migrate/drain' && req.method == .post {
		done := s.volume.drain_migrate() or { return failed('${err}') }
		return http.new_response(status: .ok, body: '{"migrated":${done}}')
	}
	if path == '/v3/scanner' && req.method == .post {
		return s.scan(query)
	}
	if path == '/v3/service-account' && req.method == .put {
		return s.put_service_account(req)
	}
	if path == '/v3/metrics/stream' && req.method == .get {
		body := if s.volume.metrics == unsafe { nil } {
			''
		} else {
			s.volume.metrics.ndjson()
		}
		return http.new_response(
			status: .ok
			body:   body
			header: http.new_header(key: .content_type, value: 'application/x-ndjson')
		)
	}
	if path == '/v3/metrics' && req.method == .get {
		body := if s.volume.metrics == unsafe { nil } {
			'{}'
		} else {
			s.volume.metrics.json()
		}
		return http.new_response(
			status: .ok
			body:   body
			header: http.new_header(key: .content_type, value: 'application/json')
		)
	}
	if path == '/v3/tier' && req.method == .put {
		return s.put_tier(req)
	}
	if path == '/v3/tier' && req.method == .delete {
		name := query.get('name') or { return bad('missing name') }
		s.volume.delete_tier(name) or { return failed('${err}') }
		return http.new_response(status: .ok, body: '')
	}
	if path == '/v3/tiers' && req.method == .get {
		remotes := s.volume.list_tiers() or { return failed('${err}') }
		return http.new_response(
			status: .ok
			body:   json2.encode[[]tier.Remote](remotes)
			header: http.new_header(key: .content_type, value: 'application/json')
		)
	}
	if path == '/v3/site-replication/iam' && req.method == .post {
		body := s.directory.export_zip() or { return failed('${err}') }
		s.volume.put_site_iam(body) or { return failed('${err}') }
		return http.new_response(status: .ok, body: '')
	}
	if path == '/v3/site-replication/iam' && req.method == .get {
		body := s.volume.site_iam() or { return failed('${err}') }
		return http.new_response(
			status: .ok
			body:   body.bytestr()
			header: http.new_header(key: .content_type, value: 'application/zip')
		)
	}
	if path == '/v3/site-replication/status' && req.method == .get {
		return http.new_response(
			status: .ok
			body:   s.volume.site_status()
			header: http.new_header(key: .content_type, value: 'application/json')
		)
	}
	if path == '/v3/site-replication/push' && req.method == .post {
		s.volume.push_site()
		return http.new_response(
			status: .ok
			body:   s.volume.site_status()
			header: http.new_header(key: .content_type, value: 'application/json')
		)
	}
	if path == '/v3/site-replication/apply' && req.method == .post {
		changes := json2.decode[[]replicate.Change](req.data) or { return bad('malformed site changes') }
		applied := s.volume.apply_site(changes) or { return failed('${err}') }
		return http.new_response(status: .ok, body: '{"applied":${applied}}')
	}
	if path == '/v3/site-replication' && req.method == .put {
		site := json2.decode[replicate.Site](req.data) or { return bad('malformed site') }
		s.volume.put_site(site) or { return failed('${err}') }
		return http.new_response(status: .ok, body: '')
	}
	if path == '/v3/site-replication' && req.method == .get {
		return http.new_response(
			status: .ok
			body:   json2.encode[replicate.Site](s.volume.site())
			header: http.new_header(key: .content_type, value: 'application/json')
		)
	}
	if path == '/v3/site-replication' && req.method == .delete {
		s.volume.delete_site() or { return failed('${err}') }
		return http.new_response(status: .ok, body: '')
	}
	if path == '/v3/replication/resync' && req.method == .post {
		bucket := query.get('bucket') or { return bad('missing bucket') }
		queued := s.volume.resync_replication(bucket) or { return failed('${err}') }
		return http.new_response(status: .ok, body: '{"queued":${queued}}')
	}
	if path == '/v3/info' && req.method == .get {
		body := s.volume.cluster_info() or { return failed('${err}') }
		return http.new_response(
			status: .ok
			body:   body
			header: http.new_header(key: .content_type, value: 'application/json')
		)
	}
	if path == '/v3/config' && req.method == .put {
		key := query.get('key') or { return bad('missing key') }
		value := query.get('value') or { return bad('missing value') }
		s.volume.config_set(key, value, time.now().unix()) or { return failed('${err}') }
		return http.new_response(status: .ok, body: '')
	}
	if path == '/v3/config' && req.method == .get {
		key := query.get('key') or { return bad('missing key') }
		entry := s.volume.config_get(key) or { return failed('${err}') }
		return http.new_response(
			status: .ok
			body:   json2.encode[adminctl.Entry](entry, escape_unicode: true)
			header: http.new_header(key: .content_type, value: 'application/json')
		)
	}
	if path == '/v3/config' && req.method == .delete {
		key := query.get('key') or { return bad('missing key') }
		s.volume.config_delete(key, time.now().unix()) or { return failed('${err}') }
		return http.new_response(status: .ok, body: '')
	}
	if path == '/v3/config/history' && req.method == .get {
		key := query.get('key') or { return bad('missing key') }
		return http.new_response(
			status: .ok
			body:   json2.encode[[]adminctl.Revision](s.volume.config_history(key), escape_unicode: true)
			header: http.new_header(key: .content_type, value: 'application/json')
		)
	}
	if path == '/v3/config/restore' && req.method == .post {
		key := query.get('key') or { return bad('missing key') }
		s.volume.config_restore(key, time.now().unix()) or { return failed('${err}') }
		return http.new_response(status: .ok, body: '')
	}
	if path == '/v3/locks' && req.method == .get {
		return http.new_response(
			status: .ok
			body:   json2.encode[[]locktab.Hold](s.volume.held_locks(), escape_unicode: true)
			header: http.new_header(key: .content_type, value: 'application/json')
		)
	}
	if path == '/v3/locks/unlock' && req.method == .post {
		name := query.get('name') or { return bad('missing name') }
		removed := s.volume.force_lock(name)
		return http.new_response(status: .ok, body: '{"removed":${removed}}')
	}
	if path == '/v3/pools' && req.method == .get {
		return http.new_response(
			status: .ok
			body:   json2.encode[[]pool.Set](s.volume.pools(), escape_unicode: true)
			header: http.new_header(key: .content_type, value: 'application/json')
		)
	}
	if path == '/v3/pools/decommission' && req.method == .post {
		index := (query.get('index') or { return bad('missing index') }).int()
		s.volume.decommission_pool(index) or { return failed('${err}') }
		return http.new_response(status: .ok, body: '')
	}
	if path == '/v3/rebalance' && req.method == .get {
		state := s.volume.rebalance('status') or { return failed('${err}') }
		return http.new_response(status: .ok, body: '{"state":"${state}"}')
	}
	if path == '/v3/rebalance' && req.method == .post {
		action := query.get('action') or { return bad('missing action') }
		state := s.volume.rebalance(action) or { return failed('${err}') }
		return http.new_response(status: .ok, body: '{"state":"${state}"}')
	}
	if path == '/v3/download' && req.method == .get {
		bucket := query.get('bucket') or { return bad('missing bucket') }
		prefix := query.get('prefix') or { '' }
		body := s.volume.zip_prefix(bucket, prefix) or { return failed('${err}') }
		return http.new_response(
			status: .ok
			body:   body.bytestr()
			header: http.new_header(key: .content_type, value: 'application/zip')
		)
	}
	if path == '/v3/iam/export' && req.method == .get {
		body := s.directory.export_zip() or { return failed('${err}') }
		return http.new_response(
			status: .ok
			body:   body.bytestr()
			header: http.new_header(key: .content_type, value: 'application/zip')
		)
	}
	if path == '/v3/iam/import' && req.method == .put {
		s.directory.import_zip(req.data.bytes()) or { return failed('${err}') }
		return http.new_response(status: .ok, body: '')
	}
	if path == '/v3/service' && req.method == .post {
		return s.service_action(query)
	}
	if path == '/v3/policy-plugin' && req.method == .get {
		return http.new_response(
			status: .ok
			body:   json2.encode[store.PolicyPlugin](s.volume.policy_plugin(), escape_unicode: true)
			header: http.new_header(key: .content_type, value: 'application/json')
		)
	}
	if path == '/v3/policy-plugin' && req.method == .put {
		url := query.get('url') or { return bad('missing url') }
		s.volume.set_policy_plugin(url) or { return failed('${err}') }
		return http.new_response(status: .ok, body: '')
	}
	if path == '/v3/policy-plugin' && req.method == .delete {
		s.volume.clear_policy_plugin() or { return failed('${err}') }
		return http.new_response(status: .ok, body: '')
	}
	if path == '/v3/replicationmetrics' && req.method == .get {
		return http.new_response(
			status: .ok
			body:   s.volume.replication_metrics()
			header: http.new_header(key: .content_type, value: 'application/json')
		)
	}
	if path == '/v3/replication/retry' && req.method == .post {
		done := s.volume.retry_replication() or { return failed('${err}') }
		return http.new_response(status: .ok, body: '{"delivered":${done}}')
	}
	return none
}

fn (s Service) put_tier(req http.Request) http.Response {
	remote := json2.decode[tier.Remote](req.data) or { return bad('malformed tier') }
	s.volume.put_tier(remote) or { return failed('${err}') }
	return http.new_response(status: .ok, body: '')
}

fn (s Service) put_service_account(req http.Request) http.Response {
	account := json2.decode[iam.ServiceAccount](req.data) or { return bad('malformed service account') }
	s.directory.put_service_account(account) or { return failed('${err}') }
	return http.new_response(status: .ok, body: '')
}

fn (s Service) put_group(req http.Request, query urllib.Values) http.Response {
	name := query.get('name') or { return bad('missing name') }
	body := json2.decode[iam.Group](req.data) or { return bad('malformed group') }
	s.directory.put_group(iam.Group{
		name:     name
		status:   if body.status.len > 0 { body.status } else { 'Enabled' }
		members:  body.members
		policies: body.policies
	}) or { return failed('${err}') }
	return http.new_response(status: .ok, body: '')
}

struct AssumeBody {
	user     string
	duration i64
	policy   string
	mfa_code string @[json: 'mfaCode']
}

struct WebIdentityBody {
	provider string
	token    string
	duration i64
}

struct CallbackBody {
	state    string
	token    string
	duration i64
}

fn (s Service) put_oidc(req http.Request) http.Response {
	provider := json2.decode[iam.Provider](req.data) or { return bad('malformed oidc provider') }
	s.directory.put_provider(provider) or { return failed('${err}') }
	return http.new_response(status: .ok, body: '')
}

fn (s Service) oidc_callback(req http.Request) http.Response {
	body := json2.decode[CallbackBody](req.data) or { return bad('malformed oidc callback') }
	session := s.directory.complete_callback(body.state, body.token, body.duration, s.signer, time.now().unix()) or {
		return failed('${err}')
	}
	return http.new_response(
		status: .ok
		body:   json2.encode[iam.Session](session, escape_unicode: true)
		header: http.new_header(key: .content_type, value: 'application/json')
	)
}

fn (s Service) assume_web(req http.Request) http.Response {
	body := json2.decode[WebIdentityBody](req.data) or { return bad('malformed web identity') }
	session := s.directory.assume_web_identity(body.provider, body.token, body.duration, s.signer, time.now().unix()) or {
		return failed('${err}')
	}
	return http.new_response(
		status: .ok
		body:   json2.encode[iam.Session](session, escape_unicode: true)
		header: http.new_header(key: .content_type, value: 'application/json')
	)
}

fn (s Service) assume(req http.Request) http.Response {
	body := json2.decode[AssumeBody](req.data) or { return bad('malformed assume-role') }
	session := s.directory.assume_role(iam.AssumeRequest{
		user:     body.user
		duration: body.duration
		policy:   body.policy
		mfa_code: body.mfa_code
		signer:   s.signer
	}) or { return failed('${err}') }
	return http.new_response(
		status: .ok
		body:   json2.encode[iam.Session](session, escape_unicode: true)
		header: http.new_header(key: .content_type, value: 'application/json')
	)
}

fn (s Service) service_action(query urllib.Values) http.Response {
	action := query.get('action') or { return bad('missing action') }
	mode := s.volume.service(action) or { return failed('${err}') }
	if action == 'stop' || action == 'restart' {
		spawn exit_process()
	}
	return http.new_response(status: .ok, body: '{"mode":"${mode}"}')
}

fn exit_process() {
	time.sleep(200 * time.millisecond)
	exit(0)
}

fn (s Service) heal(query urllib.Values) http.Response {
	bucket_name := query.get('bucket') or { return bad('missing bucket') }
	if query.get('remove') or { '' } == 'delete-marker' {
		if key := query.get('key') {
			cleared := s.volume.clear_delete_marker(bucket_name, key) or { return failed('${err}') }
			return http.new_response(status: .ok, body: '{"cleared":${cleared}}')
		}
		cleared := s.volume.clear_markers(bucket_name) or { return failed('${err}') }
		return http.new_response(status: .ok, body: '{"cleared":${cleared}}')
	}
	if key := query.get('key') {
		restored := s.volume.heal_object(bucket_name, key) or { return failed('${err}') }
		return http.new_response(status: .ok, body: '{"restored":${restored},"backlog":${s.volume.heal_backlog()}}')
	}
	restored := worker.heal_bucket(s.volume, bucket_name) or { return failed('${err}') }
	return http.new_response(status: .ok, body: '{"restored":${restored},"backlog":${s.volume.heal_backlog()}}')
}

fn (s Service) put_modules(query urllib.Values) http.Response {
	for name in ['scanner', 'heal', 'bitrot', 'migrate'] {
		raw := query.get(name) or { continue }
		on := match raw {
			'1', 'true', 'on' { true }
			'0', 'false', 'off' { false }
			else { return bad('bad module value') }
		}
		s.volume.set_module(name, on) or { return failed('${err}') }
	}
	return http.new_response(
		status: .ok
		body:   s.volume.modules_json()
		header: http.new_header(key: .content_type, value: 'application/json')
	)
}

fn (s Service) bitrot(query urllib.Values) http.Response {
	bucket_name := query.get('bucket') or { return bad('missing bucket') }
	if key := query.get('key') {
		rewritten := s.volume.scrub(bucket_name, key) or { return failed('${err}') }
		return http.new_response(status: .ok, body: '{"rewritten":${rewritten}}')
	}
	mut rewritten := 0
	stats := s.volume.list(bucket_name, '', 0) or { return failed('${err}') }
	for stat in stats {
		if stat.delete_marker || stat.archived {
			continue
		}
		rewritten += s.volume.scrub(bucket_name, stat.key) or { continue }
	}
	return http.new_response(status: .ok, body: '{"rewritten":${rewritten}}')
}

fn (s Service) migrate(query urllib.Values) http.Response {
	bucket_name := query.get('bucket') or { return bad('missing bucket') }
	tier_name := query.get('tier') or { return bad('missing tier') }
	prefix := query.get('prefix') or { '' }
	queued := s.volume.enqueue_migrate(bucket_name, prefix, tier_name) or { return failed('${err}') }
	return http.new_response(status: .ok, body: '{"queued":${queued}}')
}

// scan runs one lifecycle pass. `at` is a unix timestamp the pass treats as
// now, so an operator can evaluate expiry without waiting out the rule. The
// default is the current time.
fn (s Service) scan(query urllib.Values) http.Response {
	now := if raw := query.get('at') {
		stamp := raw.i64()
		if stamp <= 0 {
			return bad('at must be a unix timestamp')
		}
		stamp
	} else {
		time.now().unix()
	}
	worker.lifecycle(s.volume, now) or { return failed('${err}') }
	return http.new_response(status: .ok, body: '')
}
