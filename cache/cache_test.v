module cache

fn test_memory_invalidates_and_evicts() {
	mut store := new_memory()
	store.limit = 2
	store.put('a', 'one'.bytes())
	store.put('b', 'two'.bytes())
	assert store.get('a')? == 'one'.bytes()
	store.put('c', 'three'.bytes())
	if _ := store.get('a') {
		assert false
	}
	store.invalidate('b')
	if _ := store.get('b') {
		assert false
	}
	assert store.get('c')? == 'three'.bytes()
}

fn test_flight_returns_each_completed_producer() {
	mut flight := new_flight()
	first := flight.do('k', fn () ![]u8 {
		return 'value'.bytes()
	})!
	second := flight.do('k', fn () ![]u8 {
		return 'other'.bytes()
	})!
	assert first == 'value'.bytes()
	assert second == 'other'.bytes()
}
