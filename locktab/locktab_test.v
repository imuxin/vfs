module locktab

fn test_force_unlock_lets_the_next_acquire_through() {
	mut table := new_table()
	table.acquire('pics/a', 'put')!
	assert table.list().len == 1
	if _ := table.acquire('pics/a', 'other') {
		assert false
	}
	assert table.force('pics/a')
	assert !table.force('pics/a')
	table.acquire('pics/a', 'put')!
	table.release('pics/a')
	assert table.list().len == 0
}
