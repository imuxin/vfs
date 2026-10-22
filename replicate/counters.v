// counters records how many replication and site deliveries succeeded or
// failed. The numbers are atomic so every copy of a volume can update them.
module replicate

import sync.stdatomic

pub struct Counters {
mut:
	delivered u64
	failed    u64
}

pub fn new_counters() &Counters {
	return &Counters{}
}

pub fn (c &Counters) deliver() {
	stdatomic.add_u64(&c.delivered, 1)
}

pub fn (c &Counters) fail() {
	stdatomic.add_u64(&c.failed, 1)
}

pub fn (c &Counters) json(backlog int) string {
	return '{"delivered":${c.delivered},"failed":${c.failed},"backlog":${backlog}}'
}
