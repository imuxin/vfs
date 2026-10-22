module replicate

fn test_rule_filters_bandwidth_and_site_owner() {
	tags := {
		'env': 'prod'
	}
	assert selected('logs/', tags, 'logs/a', tags)
	assert !selected('logs/', tags, 'logs/a', map[string]string{})
	assert !selected('img/', tags, 'logs/a', tags)
	assert !forward_replica(true, false)
	assert forward_replica(true, true)
	if _ := may_edit(Site{
		enabled:  true
		owner:    false
		endpoint: 'http://peer'
	}) {
		assert false
	}
	may_edit(Site{
		enabled: true
		owner:   true
	})!
	mut state := Window{}
	next, ok := admit(10, state, 5, 4)
	assert ok
	assert next.used == 4
	state = next
	_, blocked := admit(10, state, 5, 8)
	assert !blocked
	_, large := admit(10, Window{}, 6, 40)
	assert large
	_, second := admit(10, Window{
		window: 6
		used:   10
	}, 6, 40)
	assert !second
	jobs := existing_jobs('pics', 'a', tags, [
		Candidate{
			key:          'a.txt'
			tags:         tags
			content_type: 'text/plain'
		},
		Candidate{
			key:           'b.txt'
			tags:          tags
			delete_marker: true
		},
		Candidate{
			key:  'a-other.txt'
			tags: map[string]string{}
		},
	])
	assert jobs.len == 1
	assert jobs[0].key == 'a.txt'
	assert note(false, true, 'bucket-create', 'pics', []Change{}).len == 0
	assert note(true, false, 'bucket-create', 'pics', []Change{}).len == 0
	recorded := note(true, true, 'bucket-create', 'pics', []Change{})
	assert recorded.len == 1
	assert recorded[0].name == 'pics'
}
