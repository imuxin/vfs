module diagnose

fn test_scan_names_the_matching_rule() {
	hits := scan('vfs: write quorum not met\nvfs: bitrot mismatch on shard 2\n')
	assert hits.len == 2
	assert hits[0].rule.name == 'write-quorum'
	assert hits[1].rule.name == 'bitrot'
	assert scan('server listening').len == 0
}
