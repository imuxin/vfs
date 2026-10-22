// pool describes the erasure sets of one deployment and the operations that
// only make sense once there is somewhere to move data. A single set can be
// listed. Decommission and rebalance need a second set, so they fail closed
// instead of pretending the drives were drained.
module pool

pub struct Set {
pub:
	index  int
	drives int
	state  string
}

pub struct Balance {
pub mut:
	state string = 'idle'
}

pub fn sets_of(widths []int) []Set {
	mut found := []Set{}
	for index, width in widths {
		found << Set{
			index:  index
			drives: width
			state:  'active'
		}
	}
	return found
}

pub fn decommission(sets int, index int) ! {
	if index < 0 || index >= sets {
		return error('pool not found')
	}
	if sets < 2 {
		return error('layout does not allow decommission')
	}
}

pub fn (mut b Balance) start(sets int) ! {
	if sets < 2 {
		return error('layout does not allow rebalance')
	}
	b.state = 'running'
}

pub fn (mut b Balance) stop() {
	b.state = 'idle'
}
