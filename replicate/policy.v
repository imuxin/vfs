// policy decides which objects a replication rule forwards, how much of a
// bandwidth window a transfer may use, and whether a site peer may edit the
// bucket rule. Delivery stays in the client; this file only makes the decision.
module replicate

// selected reports whether a key and its tags match the rule. An empty prefix
// matches every key. Every configured tag must be present.
pub fn selected(prefix string, tags map[string]string, key string, object_tags map[string]string) bool {
	if prefix.len > 0 && !key.starts_with(prefix) {
		return false
	}
	for name, value in tags {
		got := object_tags[name] or { '' }
		if got != value {
			return false
		}
	}
	return true
}

// forward_replica reports whether a replica object should be sent onward.
// Replica modification is off unless the rule asks for it.
pub fn forward_replica(replica bool, replica_mods bool) bool {
	return !replica || replica_mods
}

// Site is one peer in a site-replication mesh. The owner is the only peer
// allowed to change a bucket's replication configuration.
pub struct Site {
pub:
	name       string
	endpoint   string
	access_key string
	secret_key string
	owner      bool
	enabled    bool
}

pub fn may_edit(site Site) ! {
	if site.enabled && !site.owner {
		return error('site replication owner controls replication configuration')
	}
}

// Change is one bucket or IAM fact the site owner broadcasts to peers.
pub struct Change {
pub:
	kind string
	name string
}

// note appends a change only when this node is the enabled site owner.
pub fn note(enabled bool, owner bool, kind string, name string, log []Change) []Change {
	if !enabled || !owner || kind.len == 0 || name.len == 0 {
		return log
	}
	mut next := log.clone()
	next << Change{
		kind: kind
		name: name
	}
	return next
}

// Window is the bytes already accepted in one unix-second bucket.
pub struct Window {
pub mut:
	window i64
	used   i64
}

// admit consumes bytes from the current second. A limit of zero is unlimited.
// An object larger than the limit still passes, but only one such object is
// accepted in that second.
pub fn admit(limit i64, state Window, now i64, bytes i64) (Window, bool) {
	if limit <= 0 || bytes <= 0 {
		return state, true
	}
	mut next := state
	if next.window != now {
		next.window = now
		next.used = 0
	}
	if bytes > limit {
		if next.used > 0 {
			return next, false
		}
		next.used = limit
		return next, true
	}
	if next.used + bytes > limit {
		return next, false
	}
	next.used += bytes
	return next, true
}

// existing_jobs lists the current objects a resync should copy. Delete markers
// are not object bytes, so they are left out.
pub fn existing_jobs(bucket string, prefix string, tags map[string]string, objects []Candidate) []Job {
	mut jobs := []Job{}
	for object in objects {
		if object.delete_marker {
			continue
		}
		if !selected(prefix, tags, object.key, object.tags) {
			continue
		}
		jobs << Job{
			op:           'put'
			bucket:       bucket
			key:          object.key
			content_type: object.content_type
		}
	}
	return jobs
}

pub struct Candidate {
pub:
	key           string
	tags          map[string]string
	delete_marker bool
	content_type  string
}
