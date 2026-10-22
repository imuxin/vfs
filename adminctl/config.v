// config is the process configuration document and the service mode. History
// keeps every write so a key can be restored to the value before the latest
// change. The storage layer persists the document; this module only edits it.
module adminctl

pub struct Entry {
pub:
	key   string
	value string
	help  string
}

pub struct Revision {
pub:
	key   string
	value string
	at    i64
}

pub struct Document {
pub:
	entries []Entry
	history []Revision
}

pub fn (d Document) get(key string) !Entry {
	for entry in d.entries {
		if entry.key == key {
			return entry
		}
	}
	return error('config not found')
}

pub fn (d Document) set(key string, value string, now i64) !Document {
	check_key(key)!
	mut entries := []Entry{}
	for entry in d.entries {
		if entry.key != key {
			entries << entry
		}
	}
	entries << Entry{
		key:   key
		value: value
		help:  help(key)
	}
	mut history := d.history.clone()
	history << Revision{
		key:   key
		value: value
		at:    now
	}
	return Document{
		entries: entries
		history: history
	}
}

pub fn (d Document) delete(key string, now i64) !Document {
	check_key(key)!
	if _ := d.get(key) {
	} else {
		return error('config not found')
	}
	mut entries := []Entry{}
	for entry in d.entries {
		if entry.key != key {
			entries << entry
		}
	}
	mut history := d.history.clone()
	history << Revision{
		key:   key
		value: ''
		at:    now
	}
	return Document{
		entries: entries
		history: history
	}
}

// restore puts back the value from before the latest write of this key.
pub fn (d Document) restore(key string, now i64) !Document {
	mut seen := 0
	mut prior := ''
	for i := d.history.len - 1; i >= 0; i-- {
		if d.history[i].key != key {
			continue
		}
		seen++
		if seen == 2 {
			prior = d.history[i].value
			break
		}
	}
	if seen < 2 {
		return error('config has no history')
	}
	return d.set(key, prior, now)
}

pub fn history_of(d Document, key string) []Revision {
	mut found := []Revision{}
	for revision in d.history {
		if revision.key == key {
			found << revision
		}
	}
	return found
}

pub fn help(key string) string {
	return match key {
		'region' { 'S3 region advertised by the server' }
		'storage.freeze' { 'freeze rejects new writes until unfreeze' }
		else { 'configuration value' }
	}
}

// transition is the service mode after one admin action.
pub fn transition(mode string, action string) !string {
	current := if mode.len == 0 { 'running' } else { mode }
	if action == 'freeze' {
		return 'frozen'
	}
	if action == 'unfreeze' {
		if current != 'frozen' {
			return error('storage is not frozen')
		}
		return 'running'
	}
	if action == 'stop' || action == 'restart' {
		return 'stopping'
	}
	return error('unknown service action')
}

fn check_key(key string) ! {
	if key.len == 0 || key.contains('..') || key.contains('/') {
		return error('invalid config key')
	}
}
