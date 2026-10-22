module replicate

fn test_replication_counters_move_independently() {
	counters := new_counters()
	counters.deliver()
	counters.fail()
	counters.fail()
	assert counters.json(4) == '{"delivered":1,"failed":2,"backlog":4}'
}