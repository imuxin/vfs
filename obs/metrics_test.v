module obs

fn test_counters_move_independently() {
	registry := new_registry()
	registry.count_put()
	registry.count_get()
	registry.count_get()
	got := registry.snapshot()
	assert got.put == 1
	assert got.get == 2
	assert got.delete == 0
	for _ in 0 .. 121 {
		registry.count_put()
	}
	lines := registry.ndjson().split_into_lines().filter(it.len > 0)
	assert lines.len == 120
	assert lines[lines.len - 1].contains('"put":122')
}
