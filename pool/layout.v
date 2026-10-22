// layout is the persisted pool list. Expand only appends. Decommission, cancel,
// and clear are a state machine. A single pool still fails closed.
module pool

pub struct Member {
pub:
	index  int
	drives int
	root   string
	state  string
}

pub struct Layout {
pub:
	members              []Member
	decommission_index   int
	decommission_state   string
}

pub fn single(drives int) Layout {
	return Layout{
		members: [
			Member{
				index:  0
				drives: drives
				state:  'active'
			},
		]
		decommission_index: -1
		decommission_state: 'idle'
	}
}

pub fn (l Layout) sets() []Set {
	mut out := []Set{}
	for member in l.members {
		mut state := member.state
		if state.len == 0 {
			state = 'active'
		}
		if member.index == l.decommission_index && l.decommission_state.len > 0
			&& l.decommission_state != 'idle' {
			state = l.decommission_state
		}
		out << Set{
			index:  member.index
			drives: member.drives
			state:  state
		}
	}
	return out
}

pub fn (l Layout) expand(drives int, root string) !Layout {
	if drives < 1 || drives > 16 {
		return error('pool width must be 1 to 16 drives')
	}
	if root.len == 0 {
		return error('pool root is required')
	}
	mut members := l.members.clone()
	members << Member{
		index:  members.len
		drives: drives
		root:   root
		state:  'active'
	}
	return Layout{
		members:              members
		decommission_index:   l.decommission_index
		decommission_state:   l.decommission_state
	}
}

pub fn (l Layout) decommission(index int) !Layout {
	if index < 0 || index >= l.members.len {
		return error('pool not found')
	}
	if l.members.len < 2 {
		return error('layout does not allow decommission')
	}
	return Layout{
		members:              l.members.clone()
		decommission_index:   index
		decommission_state:   'draining'
	}
}

pub fn (l Layout) cancel() !Layout {
	if l.decommission_state != 'draining' {
		return error('decommission is not in progress')
	}
	return Layout{
		members:              l.members.clone()
		decommission_index:   l.decommission_index
		decommission_state:   'cancelled'
	}
}

pub fn (l Layout) clear() !Layout {
	if l.decommission_state != 'cancelled' && l.decommission_state != 'drained' {
		return error('decommission must be cancelled or finished before clear')
	}
	if l.decommission_index == 0 {
		return error('the live erasure set stays in the layout')
	}
	mut members := []Member{}
	for member in l.members {
		if member.index == l.decommission_index {
			continue
		}
		members << member
	}
	return Layout{
		members:              members
		decommission_index:   -1
		decommission_state:   'idle'
	}
}

pub fn (l Layout) root_of(index int) string {
	for member in l.members {
		if member.index == index {
			return member.root
		}
	}
	return ''
}
