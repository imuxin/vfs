// core_test walks the paths a client actually uses: signed S3 calls, the admin
// API, erasure rebuild, and the scanner. Each test opens its own volume so a
// failure names the path that broke.
module scenario

import os
import time
import checksum

fn test_signed_object_roundtrip_copy_range_and_checksum() {
	mut world := open_world(1)!
	defer {
		world.close()
	}
	unsigned := world.raw(.put, '/pics', '')
	expect(unsigned, 403, 'unsigned create')
	expect(world.send(.put, '/pics', '')!, 200, 'create bucket')
	expect(world.send(.head, '/pics', '')!, 200, 'head bucket')
	expect(world.send(.put, '/pics/a/../b.txt', 'no')!, 400, 'dot segment')
	body := 'hello-world'
	put := world.send_headers(.put, '/pics/notes/a.txt', body, {
		'Content-Type':  'text/plain'
		'x-amz-meta-color': 'blue'
	})!
	expect(put, 200, 'put object')
	got := world.send(.get, '/pics/notes/a.txt', '')!
	expect(got, 200, 'get object')
	assert got.body == body
	assert (got.header.get_custom('x-amz-meta-color') or { '' }) == 'blue'
	ranged := world.send_headers(.get, '/pics/notes/a.txt', '', {
		'Range': 'bytes=0-4'
	})!
	expect(ranged, 200, 'range get')
	assert ranged.body == 'hello'
	copied := world.send_headers(.put, '/pics/notes/b.txt', '', {
		'x-amz-copy-source': '/pics/notes/a.txt'
	})!
	expect(copied, 200, 'copy')
	assert world.send(.get, '/pics/notes/b.txt', '')!.body == body
	sum := checksum.parse('SHA256')!.header(body.bytes())
	good := world.send_headers(.put, '/pics/notes/sum.txt', body, {
		'x-amz-checksum-algorithm': 'SHA256'
		'x-amz-checksum-sha256':    sum
	})!
	expect(good, 200, 'checksum put')
	bad := world.send_headers(.put, '/pics/notes/bad.txt', body, {
		'x-amz-checksum-algorithm': 'SHA256'
		'x-amz-checksum-sha256':    'aaaa'
	})!
	expect(bad, 400, 'bad checksum')
	assert bad.body.contains('BadDigest')
	cold := world.send_headers(.put, '/pics/notes/cold.txt', body, {
		'x-amz-storage-class': 'GLACIER'
	})!
	expect(cold, 400, 'glacier rejected')
	listed := world.send(.get, '/pics?prefix=notes/', '')!
	expect(listed, 200, 'list')
	assert listed.body.contains('notes/a.txt')
	assert listed.body.contains('notes/b.txt')
	buckets := world.send(.get, '/', '')!
	expect(buckets, 200, 'list buckets')
	assert buckets.body.contains('<Name>pics</Name>')
	expect(world.send(.put, '/limited', '')!, 200, 'quota bucket')
	expect(world.send(.put, '/limited?quota', '{"hard":4}')!, 200, 'quota')
	expect(world.send(.put, '/limited/ok.txt', 'abcd')!, 200, 'under quota')
	over := world.send(.put, '/limited/over.txt', 'abcde')!
	expect(over, 403, 'over quota')
	assert over.body.contains('QuotaExceeded')
}

fn test_multipart_form_and_select() {
	mut world := open_world(1)!
	defer {
		world.close()
	}
	expect(world.send(.put, '/pics', '')!, 200, 'create bucket')
	started := world.send(.post, '/pics/joined.bin?uploads', '')!
	expect(started, 200, 'start upload')
	upload_id := xml_text(started.body, '<UploadId>', '</UploadId>')
	assert upload_id.len > 0, 'missing upload id: ${started.body}'
	expect(world.send(.put, '/pics/joined.bin?partNumber=1&uploadId=${upload_id}', 'aaa')!, 200,
		'part 1')
	expect(world.send(.put, '/pics/joined.bin?partNumber=2&uploadId=${upload_id}', 'bbb')!, 200,
		'part 2')
	parts := world.send(.get, '/pics/joined.bin?uploadId=${upload_id}', '')!
	expect(parts, 200, 'list parts')
	assert parts.body.contains('<PartNumber>1</PartNumber>')
	complete := '<CompleteMultipartUpload><Part><PartNumber>1</PartNumber></Part><Part><PartNumber>2</PartNumber></Part></CompleteMultipartUpload>'
	done := world.send(.post, '/pics/joined.bin?uploadId=${upload_id}', complete)!
	expect(done, 200, 'complete')
	assert world.send(.get, '/pics/joined.bin', '')!.body == 'aaabbb'
	form := '--bound\r\nContent-Disposition: form-data; name="key"\r\n\r\nphotos/a.txt\r\n--bound\r\nContent-Disposition: form-data; name="file"; filename="a.txt"\r\nContent-Type: text/plain\r\n\r\nhello\r\n--bound--\r\n'
	posted := world.send_headers(.post, '/pics', form, {
		'Content-Type': 'multipart/form-data; boundary=bound'
	})!
	expect(posted, 200, 'form upload')
	assert world.send(.get, '/pics/photos/a.txt', '')!.body == 'hello'
	csv := 'a,keep\nb,drop\n'
	expect(world.send(.put, '/pics/rows.csv', csv)!, 200, 'csv')
	query := '<SelectRequest><Expression>SELECT _1 FROM S3Object WHERE _2 = \'keep\'</Expression><InputSerialization><CSV></CSV></InputSerialization></SelectRequest>'
	selected := world.send(.post, '/pics/rows.csv?select', query)!
	expect(selected, 200, 'select')
	assert selected.body == 'a'
	assert !selected.body.contains('drop')
}

fn test_versioning_lock_and_identity() {
	mut world := open_world(1)!
	defer {
		world.close()
	}
	expect(world.send(.put, '/pics', '')!, 200, 'create bucket')
	expect(world.send(.put, '/pics?versioning', '<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>')!,
		200, 'enable versioning')
	first := world.send(.put, '/pics/doc.txt', 'v1')!
	expect(first, 200, 'version 1')
	v1 := version_of(first)
	assert v1.len > 0
	expect(world.send(.put, '/pics/doc.txt', 'v2')!, 200, 'version 2')
	assert world.send(.get, '/pics/doc.txt', '')!.body == 'v2'
	assert world.send(.get, '/pics/doc.txt?versionId=${v1}', '')!.body == 'v1'
	removed := world.send(.delete, '/pics/doc.txt', '')!
	expect(removed, 204, 'delete marker')
	assert (removed.header.get_custom('x-amz-delete-marker') or { '' }) == 'true'
	marker := world.send(.get, '/pics/doc.txt', '')!
	expect(marker, 404, 'current is marker')
	assert (marker.header.get_custom('x-amz-delete-marker') or { '' }) == 'true'
	assert world.send(.get, '/pics/doc.txt?versionId=${v1}', '')!.body == 'v1'

	expect(world.send(.put, '/comp', '')!, 200, 'compliance bucket')
	lock_doc := '<ObjectLockConfiguration><ObjectLockEnabled>Enabled</ObjectLockEnabled><Rule><DefaultRetention><Mode>COMPLIANCE</Mode><Days>1</Days></DefaultRetention></Rule></ObjectLockConfiguration>'
	expect(world.send(.put, '/comp?object-lock', lock_doc)!, 200, 'compliance lock')
	held := world.send(.put, '/comp/keep.txt', 'keep')!
	expect(held, 200, 'locked put')
	held_id := version_of(held)
	denied := world.send_headers(.delete, '/comp/keep.txt?versionId=${held_id}', '', {
		'x-amz-bypass-governance-retention': 'true'
	})!
	expect(denied, 403, 'compliance bypass')
	assert world.send(.get, '/comp/keep.txt', '')!.body == 'keep'

	expect(world.send(.put, '/gov', '')!, 200, 'governance bucket')
	gov := lock_doc.replace('COMPLIANCE', 'GOVERNANCE')
	expect(world.send(.put, '/gov?object-lock', gov)!, 200, 'governance lock')
	world.add_user('writer', 'writersecret', 'writeonly')!
	writer := signer_for('writer', 'writersecret')
	written := world.send_with(writer, .put, '/gov/keep.txt', 'keep', map[string]string{})!
	expect(written, 200, 'writer put')
	gov_id := version_of(written)
	skipped := world.send_with(writer, .delete, '/gov/keep.txt?versionId=${gov_id}', '', {
		'x-amz-bypass-governance-retention': 'true'
	})!
	expect(skipped, 403, 'writer cannot bypass')
	assert skipped.body.contains('governance bypass is not permitted')
	assert world.send(.get, '/gov/keep.txt', '')!.body == 'keep'
	expect(world.send_headers(.delete, '/gov/keep.txt?versionId=${gov_id}', '', {
		'x-amz-bypass-governance-retention': 'true'
	})!, 204, 'root bypass')
	expect(world.send(.get, '/gov/keep.txt', '')!, 404, 'governance deleted')

	world.add_user('reader', 'readersecret', 'readonly')!
	reader := signer_for('reader', 'readersecret')
	expect(world.send(.put, '/pics/shared.txt', 'visible')!, 200, 'shared')
	readable := world.send_with(reader, .get, '/pics/shared.txt', '', map[string]string{})!
	expect(readable, 200, 'reader get')
	assert readable.body == 'visible'
	forbidden := world.send_with(reader, .put, '/pics/nope.txt', 'no', map[string]string{})!
	expect(forbidden, 403, 'reader put')
}

fn test_sse_s3_ciphertext_is_not_plaintext() {
	mut world := open_world(1)!
	defer {
		world.close()
	}
	expect(world.send(.put, '/sealed', '')!, 200, 'create bucket')
	plain := 'sealed payload'
	put := world.send_headers(.put, '/sealed/secret.txt', plain, {
		'x-amz-server-side-encryption': 'AES256'
	})!
	expect(put, 200, 'sse put')
	assert (put.header.get_custom('x-amz-server-side-encryption') or { '' }) == 'AES256'
	assert world.send(.get, '/sealed/secret.txt', '')!.body == plain
	version := version_of(put)
	shard := os.read_file(shard_path(world.roots[0], 'sealed', 'secret.txt', version))!
	assert !shard.contains(plain)
}

fn test_reduced_redundancy_loses_one_parity_shard() {
	mut world := open_world(4)!
	defer {
		world.close()
	}
	expect(world.send(.put, '/pics', '')!, 200, 'create bucket')
	standard := world.send(.put, '/pics/std.txt', 'standard-body')!
	expect(standard, 200, 'standard put')
	std_version := version_of(standard)
	assert drop_shards(world.roots, 'pics', 'std.txt', std_version, 2) == 2
	assert world.send(.get, '/pics/std.txt', '')!.body == 'standard-body'
	healed := world.send(.post, '/rustfs/admin/v3/heal?bucket=pics&key=std.txt', '')!
	expect(healed, 200, 'heal')
	assert healed.body.contains('"restored":2')
	for root in world.roots {
		assert os.exists(shard_path(root, 'pics', 'std.txt', std_version))
	}
	reduced := world.send_headers(.put, '/pics/rr.txt', 'reduced-body', {
		'x-amz-storage-class': 'REDUCED_REDUNDANCY'
	})!
	expect(reduced, 200, 'reduced put')
	assert (reduced.header.get_custom('x-amz-storage-class') or { '' }) == 'REDUCED_REDUNDANCY'
	rr_version := version_of(reduced)
	assert drop_shards(world.roots, 'pics', 'rr.txt', rr_version, 2) == 2
	lost := world.send(.get, '/pics/rr.txt', '')!
	assert lost.status_code != 200, 'reduced redundancy survived two losses: ${lost.body}'
	one := world.send_headers(.put, '/pics/one.txt', 'one-loss', {
		'x-amz-storage-class': 'REDUCED_REDUNDANCY'
	})!
	expect(one, 200, 'one parity put')
	assert drop_shards(world.roots, 'pics', 'one.txt', version_of(one), 1) == 1
	assert world.send(.get, '/pics/one.txt', '')!.body == 'one-loss'
}

fn test_lifecycle_scan_expires_and_aborts() {
	mut world := open_world(1)!
	defer {
		world.close()
	}
	expect(world.send(.put, '/pics', '')!, 200, 'create bucket')
	expect(world.send(.put, '/pics?versioning', '<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>')!,
		200, 'versioning')
	rules := '<LifecycleConfiguration><Rule><Expiration><Days>1</Days></Expiration><AbortIncompleteMultipartUpload><DaysAfterInitiation>1</DaysAfterInitiation></AbortIncompleteMultipartUpload><Status>Enabled</Status></Rule></LifecycleConfiguration>'
	expect(world.send(.put, '/pics?lifecycle', rules)!, 200, 'lifecycle')
	expect(world.send(.put, '/pics/aging.txt', 'old')!, 200, 'aging object')
	started := world.send(.post, '/pics/pending.bin?uploads', '')!
	expect(started, 200, 'stale upload')
	upload_id := xml_text(started.body, '<UploadId>', '</UploadId>')
	expect(world.send(.put, '/pics/pending.bin?partNumber=1&uploadId=${upload_id}', 'part')!,
		200, 'stale part')
	later := time.now().unix() + 3 * 86400
	expect(world.send(.post, '/rustfs/admin/v3/scanner?at=${later}', '')!, 200, 'scan')
	expired := world.send(.get, '/pics/aging.txt', '')!
	expect(expired, 404, 'expired object')
	assert (expired.header.get_custom('x-amz-delete-marker') or { '' }) == 'true'
	uploads := world.send(.get, '/pics?uploads', '')!
	expect(uploads, 200, 'list uploads')
	assert !uploads.body.contains(upload_id)
}

fn test_admin_health_config_and_iceberg() {
	mut world := open_world(1)!
	defer {
		world.close()
	}
	ready := world.raw(.get, '/health/ready', '')
	expect(ready, 200, 'ready')
	assert ready.body == 'ok'
	info := world.send(.get, '/rustfs/admin/v3/info', '')!
	expect(info, 200, 'info')
	assert info.body.contains('"drives":1')
	expect(world.send(.put, '/rustfs/admin/v3/config?key=region&value=eu-west-1', '')!, 200,
		'set config')
	saved := world.send(.get, '/rustfs/admin/v3/config?key=region', '')!
	expect(saved, 200, 'get config')
	assert saved.body.contains('eu-west-1')
	made := world.raw(.post, '/iceberg/v1/namespaces', '{"namespace":["demo"]}')
	expect(made, 200, 'namespace')
	listed := world.raw(.get, '/iceberg/v1/namespaces', '')
	expect(listed, 200, 'list namespaces')
	assert listed.body.contains('demo')
	table := world.raw(.post, '/iceberg/v1/namespaces/demo/tables', '{"name":"events"}')
	expect(table, 200, 'table')
	tables := world.raw(.get, '/iceberg/v1/namespaces/demo/tables', '')
	expect(tables, 200, 'list tables')
	assert tables.body.contains('events')
}
