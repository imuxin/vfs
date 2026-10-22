// metrics counts requests for one process. Counters are atomic so every copy
// of a volume, which shares this registry, can update them without a lock.
// The sample ring keeps the last 120 observations for the NDJSON admin stream.
module obs

import json2
import sync.stdatomic

const sample_limit = 120

pub struct Registry {
mut:
	put    u64
	get    u64
	delete u64
	stream &Stream = unsafe { nil }
}

pub struct Snapshot {
pub:
	put    u64
	get    u64
	delete u64
}

struct Stream {
mut:
	n      u64
	puts   [120]u64
	gets   [120]u64
	deletes [120]u64
}

fn new_stream() &Stream {
	return &Stream{}
}

pub fn new_registry() &Registry {
	return &Registry{
		stream: new_stream()
	}
}

pub fn (r &Registry) count_put() {
	stdatomic.add_u64(&r.put, 1)
	r.record()
}

pub fn (r &Registry) count_get() {
	stdatomic.add_u64(&r.get, 1)
	r.record()
}

pub fn (r &Registry) count_delete() {
	stdatomic.add_u64(&r.delete, 1)
	r.record()
}

fn (r &Registry) record() {
	if r.stream == unsafe { nil } {
		return
	}
	r.stream.push(r.snapshot())
}

fn (s &Stream) push(sample Snapshot) {
	slot := int(stdatomic.fetch_add_u64(&s.n, 1) % u64(sample_limit))
	stdatomic.store_u64(&s.puts[slot], sample.put)
	stdatomic.store_u64(&s.gets[slot], sample.get)
	stdatomic.store_u64(&s.deletes[slot], sample.delete)
}

fn (s &Stream) copy() []Snapshot {
	total := stdatomic.load_u64(&s.n)
	count := if total > u64(sample_limit) { u64(sample_limit) } else { total }
	start := total - count
	mut out := []Snapshot{cap: int(count)}
	for i in 0 .. int(count) {
		slot := int((start + u64(i)) % u64(sample_limit))
		out << Snapshot{
			put:    stdatomic.load_u64(&s.puts[slot])
			get:    stdatomic.load_u64(&s.gets[slot])
			delete: stdatomic.load_u64(&s.deletes[slot])
		}
	}
	return out
}

pub fn (r &Registry) snapshot() Snapshot {
	return Snapshot{
		put:    r.put
		get:    r.get
		delete: r.delete
	}
}

pub fn (r &Registry) json() string {
	return json2.encode[Snapshot](r.snapshot(), escape_unicode: true)
}

// ndjson is the recent sample window, one JSON object per line, at most 120.
pub fn (r &Registry) ndjson() string {
	if r.stream == unsafe { nil } {
		return ''
	}
	mut lines := []string{}
	for sample in r.stream.copy() {
		lines << json2.encode[Snapshot](sample, escape_unicode: true)
	}
	if lines.len == 0 {
		return ''
	}
	return lines.join('\n') + '\n'
}
