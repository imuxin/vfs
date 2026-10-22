module swift

fn test_slo_and_dlo_manifests() {
	raw := '[{"path":"/v1/acct/pics/0001","etag":"a","size_bytes":2},{"path":"pics/0002","etag":"b","size_bytes":2}]'
	segments := parse_slo(raw)!
	container, key := segment_location(segments[0].path)!
	assert container == 'pics'
	assert key == '0001'
	container2, key2 := segment_location(segments[1].path)!
	assert container2 == 'pics'
	assert key2 == '0002'
	dlo_container, prefix := split_manifest('pics/big/')!
	assert dlo_container == 'pics'
	assert prefix == 'big/'
	if _ := parse_slo('[]') {
		assert false
	}
}
