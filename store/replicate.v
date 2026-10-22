// replicate keeps the site peer and the bandwidth window beside the bucket
// rule. Resync records existing objects onto the backlog; it does not open a
// connection itself.
module store

import json2
import os
import time
import replicate

const site_file = '.vfs.sys/site-replication.json'
const site_log_file = '.vfs.sys/site-broadcast.json'
const site_iam_file = '.vfs.sys/site-iam.zip'
const site_status_file = '.vfs.sys/site-status.json'
const windows_file = '.vfs.sys/replication.bandwidth.json'

struct WindowEntry {
	bucket string
	window i64
	used   i64
}

pub fn (v Volume) site() replicate.Site {
	raw := v.drives[0].read(site_file) or { return replicate.Site{} }
	return json2.decode[replicate.Site](raw.bytestr()) or { return replicate.Site{} }
}

pub fn (v Volume) put_site(site replicate.Site) ! {
	encoded := json2.encode[replicate.Site](site, escape_unicode: true).bytes()
	for drive in v.drives {
		drive.write(site_file, encoded)!
	}
}

pub fn (v Volume) site_changes() []replicate.Change {
	raw := v.drives[0].read(site_log_file) or { return []replicate.Change{} }
	return json2.decode[[]replicate.Change](raw.bytestr()) or { return []replicate.Change{} }
}

fn (v Volume) note_site(kind string, name string) {
	site := v.site()
	next := replicate.note(site.enabled, site.owner, kind, name, v.site_changes())
	if next.len == v.site_changes().len {
		return
	}
	encoded := json2.encode[[]replicate.Change](next, escape_unicode: true).bytes()
	for drive in v.drives {
		drive.write(site_log_file, encoded) or {}
	}
	v.push_site()
}

struct SiteStatus {
	pending bool
	detail  string
}

// site_status reports whether the last push to the peer is still waiting.
// A deployment with no endpoint is unset. A failed push is offline.
pub fn (v Volume) site_status() string {
	site := v.site()
	if !site.enabled || site.endpoint.len == 0 {
		return '{"state":"unset","pending":false}'
	}
	pending := v.site_pending()
	state := if pending { 'offline' } else { 'online' }
	return '{"state":"${state}","pending":${pending}}'
}

// push_site sends the recorded changes to the peer. A failure stays pending
// so a later retry can deliver the same log.
pub fn (v Volume) push_site() {
	site := v.site()
	if !site.enabled || !site.owner || site.endpoint.len == 0 {
		return
	}
	body := json2.encode[[]replicate.Change](v.site_changes(), escape_unicode: true)
	replicate.post_json(replicate.Target{
		endpoint:   site.endpoint
		region:     'us-east-1'
		access_key: site.access_key
		secret_key: site.secret_key
	}, '/rustfs/admin/v3/site-replication/apply', body.bytes()) or {
		v.set_site_pending(true, '${err}')
		v.count_repl(false)
		return
	}
	v.set_site_pending(false, '')
	v.count_repl(true)
}

pub fn (v Volume) replication_metrics() string {
	backlog := v.replication_backlog().len
	if v.repl == unsafe { nil } {
		return '{"delivered":0,"failed":0,"backlog":${backlog}}'
	}
	return v.repl.json(backlog)
}

fn (v Volume) count_repl(ok bool) {
	if v.repl == unsafe { nil } {
		return
	}
	if ok {
		v.repl.deliver()
	} else {
		v.repl.fail()
	}
}

fn (v Volume) site_pending() bool {
	raw := v.drives[0].read(site_status_file) or { return false }
	parsed := json2.decode[SiteStatus](raw.bytestr()) or { return false }
	return parsed.pending
}

fn (v Volume) set_site_pending(pending bool, detail string) {
	encoded := json2.encode[SiteStatus](SiteStatus{
		pending: pending
		detail:  detail
	}, escape_unicode: true).bytes()
	for drive in v.drives {
		drive.write(site_status_file, encoded) or {}
	}
}

// apply_site replays owner changes onto this volume. Creating a bucket that
// already exists is a no-op. A peer that is not the owner does not rebroadcast.
pub fn (v Volume) apply_site(changes []replicate.Change) !int {
	mut applied := 0
	for change in changes {
		if change.kind == 'bucket-create' {
			if v.bucket_exists(change.name) {
				continue
			}
			v.make_bucket(change.name)!
			applied++
		} else if change.kind == 'bucket-delete' {
			if !v.bucket_exists(change.name) {
				continue
			}
			v.remove_bucket(change.name) or { continue }
			applied++
		}
	}
	return applied
}

pub fn (v Volume) put_site_iam(payload []u8) ! {
	site := v.site()
	if !site.enabled || !site.owner {
		return error('site replication owner broadcasts IAM')
	}
	for drive in v.drives {
		drive.write(site_iam_file, payload)!
	}
	v.note_site('iam', 'current')
}

pub fn (v Volume) site_iam() ![]u8 {
	return v.drives[0].read(site_iam_file) or { return error('site IAM snapshot is missing') }
}

pub fn (v Volume) delete_site() ! {
	for drive in v.drives {
		drive.remove(site_file)!
	}
}

pub fn (v Volume) delete_replication(bucket string) ! {
	require_bucket(v, bucket)!
	replicate.may_edit(v.site())!
	for drive in v.drives {
		drive.remove(os.join_path(bucket, replication_file))!
	}
}

// resync_replication queues every current object the rule selects. Delivery
// happens on the retry pass, so a down target does not block the scan.
pub fn (v Volume) resync_replication(bucket string) !int {
	rule := v.replication_of(bucket)!
	if rule.target.endpoint.len == 0 {
		return error('no replication target')
	}
	mut objects := []replicate.Candidate{}
	for stat in v.list(bucket, '', 0)! {
		objects << replicate.Candidate{
			key:           stat.key
			tags:          stat.tags
			delete_marker: stat.delete_marker
			content_type:  stat.content_type
		}
	}
	jobs := replicate.existing_jobs(bucket, rule.prefix, rule.tags, objects)
	for job in jobs {
		v.remember_replication(job)
	}
	return jobs.len
}

fn (v Volume) admit_bandwidth(bucket string, limit i64, bytes i64) bool {
	if limit <= 0 {
		return true
	}
	mut entries := v.read_windows()
	mut state := replicate.Window{}
	mut found := -1
	for index, entry in entries {
		if entry.bucket == bucket {
			state = replicate.Window{
				window: entry.window
				used:   entry.used
			}
			found = index
			break
		}
	}
	next, ok := replicate.admit(limit, state, time.now().unix(), bytes)
	updated := WindowEntry{
		bucket: bucket
		window: next.window
		used:   next.used
	}
	if found >= 0 {
		entries[found] = updated
	} else {
		entries << updated
	}
	v.write_windows(entries)
	return ok
}

fn (v Volume) read_windows() []WindowEntry {
	raw := v.drives[0].read(windows_file) or { return []WindowEntry{} }
	return json2.decode[[]WindowEntry](raw.bytestr()) or { return []WindowEntry{} }
}

fn (v Volume) write_windows(entries []WindowEntry) {
	encoded := json2.encode[[]WindowEntry](entries, escape_unicode: true).bytes()
	for drive in v.drives {
		drive.write(windows_file, encoded) or {}
	}
}
