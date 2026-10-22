// cache is the process-local object cache. A get that misses is computed once
// even if several callers ask for it together; a put or delete drops the entry
// so the next read cannot return the bytes that were just replaced.
module cache

import sync

pub struct Memory {
mut:
	mu    sync.Mutex
	items map[string][]u8
	limit int = 256
	order []string
}

pub fn new_memory() &Memory {
	return &Memory{
		items: map[string][]u8{}
		order: []string{}
	}
}

pub fn (mut m Memory) get(key string) ?[]u8 {
	m.mu.lock()
	defer {
		m.mu.unlock()
	}
	found := m.items[key] or { return none }
	return found.clone()
}

pub fn (mut m Memory) put(key string, value []u8) {
	m.mu.lock()
	defer {
		m.mu.unlock()
	}
	if key !in m.items {
		m.order << key
	}
	m.items[key] = value.clone()
	for m.order.len > m.limit {
		oldest := m.order[0]
		m.order.delete(0)
		m.items.delete(oldest)
	}
}

pub fn (mut m Memory) invalidate(key string) {
	m.mu.lock()
	defer {
		m.mu.unlock()
	}
	m.items.delete(key)
}

pub fn (mut m Memory) invalidate_prefix(prefix string) {
	m.mu.lock()
	defer {
		m.mu.unlock()
	}
	mut kept := []string{}
	for key in m.order {
		if key.starts_with(prefix) {
			m.items.delete(key)
		} else {
			kept << key
		}
	}
	m.order = kept
}

struct Slot {
mut:
	mu    sync.Mutex
	done  bool
	value []u8
	err   string
}

// Flight collapses concurrent computations of one key. The first caller runs
// the producer; the others wait on the same slot and receive its result.
pub struct Flight {
mut:
	mu    sync.Mutex
	slots map[string]&Slot
}

pub fn new_flight() &Flight {
	return &Flight{
		slots: map[string]&Slot{}
	}
}

pub fn (mut f Flight) do(key string, producer fn () ![]u8) ![]u8 {
	f.mu.lock()
	if mut existing := f.slots[key] {
		f.mu.unlock()
		return existing.wait()
	}
	slot := &Slot{}
	f.slots[key] = slot
	f.mu.unlock()
	produced := producer() or {
		slot.fail(err.msg())
		f.clear(key)
		return err
	}
	slot.succeed(produced)
	f.clear(key)
	return produced
}

fn (mut s Slot) wait() ![]u8 {
	for {
		s.mu.lock()
		if s.done {
			value := s.value.clone()
			failed := s.err
			s.mu.unlock()
			if failed.len > 0 {
				return error(failed)
			}
			return value
		}
		s.mu.unlock()
	}
}

fn (mut s Slot) succeed(value []u8) {
	s.mu.lock()
	s.value = value.clone()
	s.done = true
	s.mu.unlock()
}

fn (mut s Slot) fail(message string) {
	s.mu.lock()
	s.err = message
	s.done = true
	s.mu.unlock()
}

fn (mut f Flight) clear(key string) {
	f.mu.lock()
	f.slots.delete(key)
	f.mu.unlock()
}
