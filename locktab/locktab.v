// locktab records which object keys an operation currently holds. The mutex
// only guards the map. Callers keep the name in the map for the whole
// operation and release it when they finish, so an admin list can see a lock
// that is still in use and force-unlock one that was left behind.
module locktab

import sync

pub struct Hold {
pub:
	name  string
	owner string
}

pub struct Table {
mut:
	mu   sync.Mutex
	held map[string]string
}

pub fn new_table() &Table {
	return &Table{
		held: map[string]string{}
	}
}

pub fn (mut t Table) acquire(name string, owner string) ! {
	t.mu.lock()
	defer {
		t.mu.unlock()
	}
	if name in t.held {
		return error('lock held: ${name}')
	}
	t.held[name] = owner
}

pub fn (mut t Table) release(name string) {
	t.mu.lock()
	defer {
		t.mu.unlock()
	}
	t.held.delete(name)
}

// force removes a lock even when the owner is still recorded. It reports
// whether a lock was actually present.
pub fn (mut t Table) force(name string) bool {
	t.mu.lock()
	defer {
		t.mu.unlock()
	}
	if name !in t.held {
		return false
	}
	t.held.delete(name)
	return true
}

pub fn (mut t Table) list() []Hold {
	t.mu.lock()
	defer {
		t.mu.unlock()
	}
	mut found := []Hold{}
	for name, owner in t.held {
		found << Hold{
			name:  name
			owner: owner
		}
	}
	return found
}
