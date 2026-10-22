module scenario

import crypto.md5
import encoding.base64
import os
import net.http
import ftp
import iam
import inspect
import keystone
import kms
import meta
import obs
import query
import rpc
import sftp
import store

fn test_admin_identity_kms_and_audit() {
	mut world := open_world(1)!
	defer {
		world.close()
	}
	expect(world.send(.put, '/pics', '')!, 200, 'bucket')
	world.add_user('writer', 'writersecret', 'readwrite')!
	listed := world.send(.get, '/rustfs/admin/v3/users', '')!
	expect(listed, 200, 'list users')
	assert listed.body.contains('writer')
	expect(world.send(.put, '/rustfs/admin/v3/user/status?accessKey=writer&status=Disabled', '')!, 200, 'disable')
	denied := world.send_with(signer_for('writer', 'writersecret'), .put, '/pics/nope.txt', 'x', map[string]string{})!
	assert denied.status_code == 403
	expect(world.send(.put, '/rustfs/admin/v3/user/status?accessKey=writer&status=Enabled', '')!, 200, 'enable')
	expect(world.send(.post, '/rustfs/admin/v3/user/rotate?accessKey=writer', '{"secretKey":"rotated-secret"}')!, 200, 'rotate')
	old := world.send_with(signer_for('writer', 'writersecret'), .get, '/pics', '', map[string]string{})!
	assert old.status_code == 403
	fresh := world.send_with(signer_for('writer', 'rotated-secret'), .put, '/pics/ok.txt', 'ok', map[string]string{})!
	expect(fresh, 200, 'rotated secret writes')
	expect(world.send(.put, '/rustfs/admin/v3/group?name=readers', '{"status":"Enabled","members":[],"policies":["readonly"]}')!, 200, 'group')
	expect(world.send(.post, '/rustfs/admin/v3/group/member?group=readers&user=writer&action=add', '')!, 200, 'add member')
	groups := world.send(.get, '/rustfs/admin/v3/groups', '')!
	assert groups.body.contains('writer')
	expect(world.send(.put, '/rustfs/admin/v3/service-account', '{"access_key":"svc","secret_key":"svcsecret","parent":"writer","policy":"readonly","status":"Enabled"}')!, 200, 'service account')
	accounts := world.send(.get, '/rustfs/admin/v3/service-accounts?user=writer', '')!
	expect(accounts, 200, 'list service accounts')
	assert accounts.body.contains('svc')
	expect(world.send(.delete, '/rustfs/admin/v3/service-account?accessKey=svc', '')!, 200, 'delete service account')
	assumed := world.send(.post, '/rustfs/admin/v3/assume-role', '{"user":"writer","duration":900}')!
	expect(assumed, 200, 'assume role')
	assert assumed.body.contains('ASIA')
	sessions := world.send(.get, '/rustfs/admin/v3/sessions', '')!
	assert sessions.body.contains('ASIA')
	access := between_json_field(assumed.body, 'access_key')
	expect(world.send(.delete, '/rustfs/admin/v3/session?accessKey=${access}', '')!, 200, 'revoke session')
	left := world.send(.get, '/rustfs/admin/v3/sessions', '')!
	assert !left.body.contains(access)
	enrolled := world.send(.post, '/rustfs/admin/v3/mfa/enroll?user=writer', '')!
	expect(enrolled, 200, 'enroll mfa')
	assert enrolled.body.contains('secret')
	expect(world.send(.post, '/rustfs/admin/v3/mfa/reset?user=writer', '')!, 200, 'reset mfa')
	again := world.send(.post, '/rustfs/admin/v3/mfa/reset?user=writer', '')!
	assert again.status_code != 200
	ssh := 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItest vfs'
	expect(world.send(.put, '/rustfs/admin/v3/ssh-key?user=writer', '{"key":"${ssh}"}')!, 200, 'ssh key')
	keys := world.send(.get, '/rustfs/admin/v3/ssh-key?user=writer', '')!
	assert keys.body.contains('ssh-ed25519')
	expect(world.send(.post, '/rustfs/admin/v3/kms/key', '{"id":"alias.app","tags":{"env":"lab"}}')!, 200, 'kms create')
	described := world.send(.get, '/rustfs/admin/v3/kms/key?id=alias.app', '')!
	expect(described, 200, 'kms describe')
	assert described.body.contains('alias.app')
	assert described.body.contains('lab')
	assert !described.body.contains('wrapped')
	expect(world.send_headers(.put, '/pics/secret.txt', 'top-secret', {
		'x-amz-server-side-encryption':            'aws:kms'
		'x-amz-server-side-encryption-aws-kms-key-id': 'alias.app'
	})!, 200, 'sse-kms put')
	assert world.send(.get, '/pics/secret.txt', '')!.body == 'top-secret'
	expect(world.send(.post, '/rustfs/admin/v3/kms/key/reencrypt?id=alias.app', '')!, 200, 'reencrypt')
	assert world.send(.get, '/pics/secret.txt', '')!.body == 'top-secret'
	backup := world.send(.get, '/rustfs/admin/v3/kms/backup', '')!
	expect(backup, 200, 'backup')
	assert backup.body.contains('alias.app')
	expect(world.send(.delete, '/rustfs/admin/v3/kms/key?id=alias.app', '')!, 200, 'mark deleted')
	expect(world.send(.post, '/rustfs/admin/v3/kms/purge?grace=0', '')!, 200, 'purge')
	missing := world.send(.get, '/pics/secret.txt', '')!
	assert missing.status_code != 200, missing.body
	expect(world.send(.put, '/rustfs/admin/v3/kms/restore', backup.body)!, 200, 'restore')
	assert world.send(.get, '/pics/secret.txt', '')!.body == 'top-secret'
	hook := start_hook()!
	expect(world.send(.put, '/rustfs/admin/v3/audit', '{"enabled":true,"targets":[{"url":"${hook}/audit","events":["*"],"kind":"webhook"}]}')!, 200, 'audit on')
	os.rm(os.join_path(os.temp_dir(), 'vfs-audit-hit')) or {}
	expect(world.send(.put, '/pics/audited.txt', 'a')!, 200, 'audited put')
	assert os.exists(os.join_path(os.temp_dir(), 'vfs-audit-hit'))
	expect(world.send(.put, '/rustfs/admin/v3/audit', '{"enabled":false,"targets":[{"url":"${hook}/audit","events":["*"],"kind":"webhook"}]}')!, 200, 'audit off')
	os.rm(os.join_path(os.temp_dir(), 'vfs-audit-hit')) or {}
	expect(world.send(.put, '/pics/quiet.txt', 'b')!, 200, 'quiet put')
	assert !os.exists(os.join_path(os.temp_dir(), 'vfs-audit-hit'))
	expect(world.send(.delete, '/rustfs/admin/v3/user?accessKey=writer', '')!, 200, 'delete user')
	gone := world.send(.get, '/rustfs/admin/v3/users', '')!
	assert !gone.body.contains('writer')
}

fn test_pools_inspection_and_targets() {
	mut world := open_world(1)!
	defer {
		world.close()
	}
	expect(world.send(.put, '/pics', '')!, 200, 'bucket')
	expect(world.send(.put, '/pics/a.txt', 'hello-pool')!, 200, 'object')
	pool := os.join_path(world.base, 'pool2')
	os.mkdir_all(pool)!
	expect(world.send(.post, '/rustfs/admin/v3/pools/expand?drives=4&root=${pool}', '')!, 200, 'expand')
	balanced := world.send(.post, '/rustfs/admin/v3/rebalance?action=start', '')!
	expect(balanced, 200, 'rebalance')
	assert balanced.body.contains('"moved":1')
	assert os.exists(os.join_path(pool, '.vfs-pool', 'pics', 'a.txt'))
	expect(world.send(.post, '/rustfs/admin/v3/pools/decommission?index=1', '')!, 200, 'decommission')
	expect(world.send(.post, '/rustfs/admin/v3/pools/decommission/cancel', '')!, 200, 'cancel')
	expect(world.send(.post, '/rustfs/admin/v3/pools/decommission/clear', '')!, 200, 'clear')
	pools := world.send(.get, '/rustfs/admin/v3/pools', '')!
	assert pools.body.contains('"index":0')
	assert !pools.body.contains('"index":1')
	refused := world.send(.post, '/rustfs/admin/v3/pools/decommission?index=0', '')!
	assert refused.status_code != 200
	inspected := world.send(.get, '/rustfs/admin/v3/inspect-data?bucket=pics&key=a.txt', '')!
	expect(inspected, 200, 'inspect')
	assert inspected.body == 'hello-pool'
	expect(world.send(.post, '/rustfs/admin/v3/scanner', '')!, 200, 'scanner')
	trace := world.send(.get, '/rustfs/admin/v3/trace', '')!
	assert trace.body.contains('scanner')
	expect(world.send(.put, '/pics?quota', '{"hard":100}')!, 200, 'quota doc')
	exported := world.send(.get, '/rustfs/admin/v3/bucket-meta?bucket=pics', '')!
	expect(exported, 200, 'export meta')
	assert exported.body.contains('quota')
	expect(world.send(.put, '/rustfs/admin/v3/bucket-meta?bucket=pics', exported.body)!, 200, 'import meta')
	orphan := os.join_path(world.roots[0], 'pics', 'lost', 'versions', 'abc')
	os.mkdir_all(orphan)!
	os.write_file(os.join_path(orphan, 'shard'), 'junk')!
	recovered := world.send(.post, '/rustfs/admin/v3/orphans', '')!
	expect(recovered, 200, 'orphans')
	assert recovered.body.contains('"removed":')
	assert !recovered.body.contains('"removed":0')
	expect(world.send(.post, '/rustfs/admin/v3/integrity', '')!, 200, 'integrity')
	speed := world.send(.post, '/rustfs/admin/v3/speedtest', '')!
	expect(speed, 200, 'speedtest')
	assert speed.body.contains('"bytes":1048576')
	null := world.send(.post, '/rustfs/admin/v3/speedtest/devnull', 'abcdef')!
	expect(null, 200, 'devnull')
	assert null.body.contains('"received":6')
	snap := world.send(.get, '/rustfs/admin/v3/snapshot', '')!
	expect(snap, 200, 'snapshot')
	assert snap.body.contains('pics')
	expect(world.send(.put, '/rustfs/admin/v3/durability?bucket=pics&copies=2', '')!, 200, 'durability')
	assert world.send(.get, '/rustfs/admin/v3/durability?bucket=pics', '')!.body.contains('"copies":2')
	expect(world.send(.put, '/rustfs/admin/v3/plugins', '[{"name":"demo","url":"http://127.0.0.1/plugin"}]')!, 200, 'plugins')
	assert world.send(.get, '/rustfs/admin/v3/plugins', '')!.body.contains('demo')
	netperf := world.send(.post, '/rustfs/admin/v3/site-replication/netperf', '')!
	expect(netperf, 200, 'netperf')
	assert netperf.body.contains('"traffic":false')
	expect(world.send(.put, '/rustfs/admin/v3/replication/target', '{"name":"east","endpoint":"http://127.0.0.1:9","bucket":"pics","access_key":"a","secret_key":"b","bandwidth":10,"synced":[]}')!, 200, 'target')
	diff := world.send(.get, '/rustfs/admin/v3/replication/target/diff?name=east', '')!
	expect(diff, 200, 'diff')
	assert diff.body.contains('a.txt')
	expect(world.send(.delete, '/rustfs/admin/v3/replication/target?name=east', '')!, 200, 'delete target')
	idp := world.send(.put, '/rustfs/admin/v3/idp-config', '{}')!
	assert idp.status_code == 501
	assert idp.body.contains('/v3/oidc/config')
	catalog := world.send(.get, '/rustfs/admin/v3/metrics/catalog', '')!
	expect(catalog, 200, 'catalog')
	assert catalog.body.contains('vfs_requests_put')
	assert catalog.body.contains('vfs_cluster_drives')
	payload := obs.otlp_metrics(1, 2, 3, 1)
	assert payload.contains('vfs_requests_get')
	assert payload.contains('vfs_node_online')
	assert inspect.connect(['license'])! == 'license feature is off'
}

fn test_data_plane_gaps() {
	mut world := open_world(1)!
	defer {
		os.unsetenv('VFS_CORS_ALLOWED_ORIGINS')
		os.unsetenv('VFS_SSE_C_REQUIRE_TLS')
		world.close()
	}
	expect(world.send(.put, '/pics', '')!, 200, 'bucket')
	expect(world.send(.put, '/site', '')!, 200, 'site bucket')
	os.setenv('VFS_CORS_ALLOWED_ORIGINS', 'https://app.example', true)
	mut header := http.new_header()
	header.add_custom('origin', 'https://app.example')!
	header.add_custom('access-control-request-method', 'GET')!
	preflight := world.endpoint.handle(http.Request{
		method: .options
		url:    '/pics/a.txt'
		header: header
	})
	assert preflight.status_code == 200
	origin := preflight.header.get_custom('access-control-allow-origin') or { '' }
	assert origin == 'https://app.example'
	os.unsetenv('VFS_CORS_ALLOWED_ORIGINS')
	site := '{"index":"index.html","error_doc":"missing.html","host":"site.example","rules":[{"prefix":"go/","redirect":"https://example.com/gone"}]}'
	expect(world.send(.put, '/site?website', site)!, 200, 'website')
	expect(world.send(.put, '/site/missing.html', 'nope')!, 200, 'error doc')
	expect(world.send_headers(.put, '/site/jump', 'body', {
		'x-amz-website-redirect-location': 'https://example.com/obj'
	})!, 200, 'redirect object')
	moved := world.send_headers(.get, '/site/go/old', '', { 'host': 'site.example' })!
	assert moved.status_code == 301
	gone := moved.header.get_custom('location') or { '' }
	assert gone == 'https://example.com/gone'
	object_moved := world.send_headers(.get, '/site/jump', '', { 'host': 'site.example' })!
	assert object_moved.status_code == 301
	missing := world.send_headers(.get, '/site/absent', '', { 'host': 'site.example' })!
	assert missing.status_code == 404
	assert missing.body == 'nope'
	hook := start_hook()!
	lambda := '{"object-lambda":"{\\"url\\":\\"${hook}/lambda\\"}"}'
	expect(world.send(.put, '/rustfs/admin/v3/bucket-meta?bucket=pics', lambda)!, 200, 'lambda config')
	expect(world.send(.put, '/pics/plain.txt', 'hello')!, 200, 'plain')
	transformed := world.send(.get, '/pics/plain.txt', '')!
	expect(transformed, 200, 'lambda get')
	assert transformed.body == 'HELLO'
	rows := query.encode_parquet([['a', 'b'], ['keep', 'drop']])!
	expect(world.send(.put, '/pics/rows.parquet', rows.bytestr())!, 200, 'parquet put')
	select_xml := '<SelectRequest><Expression>SELECT _1 FROM S3Object WHERE _2 = \'keep\'</Expression><InputSerialization><Parquet></Parquet></InputSerialization></SelectRequest>'
	selected := world.send(.post, '/pics/rows.parquet?select', select_xml)!
	expect(selected, 200, 'parquet select')
	assert selected.body == 'a'
	compressed := '<SelectRequest><Expression>SELECT _1 FROM S3Object</Expression><InputSerialization><CSV><CompressionType>SNAPPY</CompressionType></CSV></InputSerialization></SelectRequest>'
	rejected := world.send(.post, '/pics/rows.parquet?select', compressed)!
	assert rejected.status_code == 400
	assert rejected.body.contains('compression combination is not supported')
	xl := meta.write_xl(meta.XlMeta{
		header_ver: 3
		meta_ver:   2
		versions:   [
			meta.XlVersion{
				id:   'free1'
				free: true
				data: 'skip'.bytes()
			},
			meta.XlVersion{
				id:   'v1'
				data: 'from-xl'.bytes()
			},
		]
	})!
	expect(world.send(.put, '/cold', '')!, 200, 'cold bucket')
	xl_dir := os.join_path(world.roots[0], 'cold', 'legacy')
	os.mkdir_all(xl_dir)!
	os.write_file_array(os.join_path(xl_dir, 'xl.meta'), xl)!
	legacy := world.send(.get, '/cold/legacy', '')!
	assert legacy.status_code == 200
	assert legacy.body == 'from-xl', legacy.body
	mut sealed := xl.clone()
	sealed[sealed.len - 1] = 0xc3
	os.mkdir_all(os.join_path(world.roots[0], 'cold', 'sealed'))!
	os.write_file_array(os.join_path(world.roots[0], 'cold', 'sealed', 'xl.meta'), sealed)!
	blocked := world.send(.get, '/cold/sealed', '')!
	assert blocked.status_code == 400
	os.setenv('VFS_SSE_C_REQUIRE_TLS', '1', true)
	key := '0123456789abcdef0123456789abcdef'
	customer := {
		'x-amz-server-side-encryption-customer-algorithm': 'AES256'
		'x-amz-server-side-encryption-customer-key':       base64.encode(key.bytes())
		'x-amz-server-side-encryption-customer-key-MD5':   base64.encode(md5.sum(key.bytes()))
	}
	needs_tls := world.send_headers(.put, '/pics/c.txt', 'secret', customer)!
	assert needs_tls.status_code == 400
	assert needs_tls.body.contains('TLS')
	mut allowed := customer.clone()
	allowed['x-forwarded-proto'] = 'https'
	expect(world.send_headers(.put, '/pics/c.txt', 'secret', allowed)!, 200, 'sse-c on tls')
	os.unsetenv('VFS_SSE_C_REQUIRE_TLS')
	cert := os.join_path(world.base, 'cert.pem')
	key_path := os.join_path(world.base, 'cert.key')
	wrote := os.execute('openssl req -x509 -newkey rsa:2048 -keyout ${key_path} -out ${cert} -days 1 -nodes -subj /CN=vfs.example')
	assert wrote.exit_code == 0
	text := os.read_file(cert)!
	report := inspect.tls_text(text)!
	assert report.contains('vfs.example')
	expect(world.send(.put, '/rustfs/admin/v3/tls/cert', text)!, 200, 'publish cert')
	status := world.send(.get, '/rustfs/admin/v3/tls/status', '')!
	expect(status, 200, 'cert status')
	assert status.body.contains('vfs.example')
	meta_doc := world.send(.get, '/rustfs/admin/v3/bucket-meta?bucket=pics', '')!
	parsed := inspect.bucket_meta(meta_doc.body)!
	assert parsed.contains('object-lambda')
}

fn test_rpc_sftp_and_remote_kms() {
	mut world := open_world(1)!
	defer {
		world.close()
	}
	expect(world.send(.put, '/pics', '')!, 200, 'bucket')
	expect(world.send(.put, '/pics/a.txt', 'peer')!, 200, 'object')
	stat_query := 'bucket=pics&key=a.txt'
	sig := rpc.signature('vfsadmin', rpc.canonical('POST', '/rustfs/rpc/v1/stat', stat_query))
	mut header := http.new_header()
	header.add_custom('x-vfs-rpc', sig)!
	ok := world.endpoint.handle(http.Request{
		method: .post
		url:    '/rustfs/rpc/v1/stat?${stat_query}'
		header: header
	})
	assert ok.status_code == 200
	assert ok.body.contains('"size":4')
	bad := world.endpoint.handle(http.Request{
		method: .post
		url:    '/rustfs/rpc/v1/stat?${stat_query}'
	})
	assert bad.status_code == 403
	world.add_user('writer', 'writersecret', 'readwrite')!
	ssh := 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItest vfs'
	expect(world.send(.put, '/rustfs/admin/v3/ssh-key?user=writer', '{"key":"${ssh}"}')!, 200, 'ssh')
	directory := iam.open(os.join_path(world.base, 'iam'))!
	volume := store.open(world.roots)!
	mut session := sftp.Session{
		volume:    volume
		directory: directory
	}
	assert session.command('AUTH writer ${ssh}') == '200 public key accepted'
	assert session.command('GET pics a.txt') == '150 sending'
	assert session.outbound.bytestr() == 'peer'
	assert session.command('PUT pics from-sftp.txt') == '150 ready for data'
	assert session.complete_put('via-sftp'.bytes()) == '226 transfer complete'
	assert world.send(.get, '/pics/from-sftp.txt', '')!.body == 'via-sftp'
	creds := iam.Credentials{
		directory: directory
	}
	mut ftp_session := ftp.Session{
		volume:    volume
		creds:     creds
		directory: directory
	}
	assert ftp_session.command('AUTH TLS') == '534 TLS is not available on this listener'
	assert ftp_session.command('USER vfsadmin') == '331 password required'
	assert ftp_session.command('PASS vfsadmin') == '230 login ok'
	assert ftp_session.command('APPE a.txt') == '502 restart and append are not supported'
	assert ftp_session.command('REST 0') == '502 restart and append are not supported'
	hook := start_hook()!
	master := []u8{len: 32, init: 7}
	dev := kms.static_backend(master)!
	sealed_key := dev.wrap(master, 'object')!
	assert dev.unwrap(sealed_key, 'object')! == master
	kv := kms.VaultKV{
		endpoint: hook
		token:    'token'
		mount:    'secret'
	}
	wrapped := kv.wrap(master, 'app')!
	assert kv.unwrap(wrapped, 'app')! == master
	transit := kms.VaultTransit{
		endpoint: hook
		token:    'token'
		key:      'app'
	}
	cipher := transit.wrap(master, 'object')!
	assert transit.unwrap(cipher, 'object')! == master
	aws := kms.AwsKMS{
		endpoint:   hook
		region:     'us-east-1'
		key_id:     'alias.app'
		access_key: 'ak'
		secret_key: 'sk'
	}
	blob := aws.wrap(master, 'object')!
	assert aws.unwrap(blob, 'object')! == master
	roles := keystone.fetch_roles('${hook}/v3/auth/tokens', 'tok')!
	assert roles == ['reader']
	assert keystone.policies(roles, {
		'reader': 'readonly'
	}) == ['readonly']
}

fn between_json_field(body string, key string) string {
	token := '"${key}":"'
	at := body.index(token) or { return '' }
	rest := body[at + token.len..]
	end := rest.index('"') or { return '' }
	return rest[..end]
}
