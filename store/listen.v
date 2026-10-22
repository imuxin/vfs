// listen keeps a short log of bucket events so a ListenBucketNotification
// request can return the records that already match its filter.
module store

import notify

const listen_limit = 200

fn listen_path(bucket string) string {
	return '.vfs.sys/listen/${bucket}.log'
}

fn (v Volume) remember_listen(event string, bucket_name string, key string) {
	if bucket_name.len == 0 || bucket_name.contains('/') || bucket_name.contains('..') {
		return
	}
	line := notify.encode_record(notify.Record{
		event:  event
		bucket: bucket_name
		key:    key
	})
	mut lines := v.listen_lines(bucket_name)
	lines << line
	if lines.len > listen_limit {
		lines = lines[lines.len - listen_limit..]
	}
	v.drives[0].write(listen_path(bucket_name), lines.join('\n').bytes()) or {}
}

fn (v Volume) listen_lines(bucket_name string) []string {
	raw := v.drives[0].read(listen_path(bucket_name)) or { return []string{} }
	mut lines := []string{}
	for line in raw.bytestr().split_into_lines() {
		if line.len > 0 {
			lines << line
		}
	}
	return lines
}

// listen returns the SSE body for one bucket. events is a comma-separated
// list; an empty list matches every event name.
pub fn (v Volume) listen(bucket_name string, events string, prefix string, suffix string) string {
	query := notify.Listen{
		events: notify.parse_events(events)
		prefix: prefix
		suffix: suffix
	}
	mut matched := []notify.Record{}
	for line in v.listen_lines(bucket_name) {
		record := notify.decode_record(line) or { continue }
		if query.matches(record) {
			matched << record
		}
	}
	return notify.sse(matched)
}
