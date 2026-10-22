module pool

fn test_single_set_refuses_decommission_and_rebalance() {
	found := sets_of([4])
	assert found.len == 1
	assert found[0].drives == 4
	if _ := decommission(1, 0) {
		assert false
	}
	decommission(2, 1)!
	mut balance := Balance{}
	if _ := balance.start(1) {
		assert false
	}
	balance.start(2)!
	assert balance.state == 'running'
	balance.stop()
	assert balance.state == 'idle'
}
