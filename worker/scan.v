// scan is the background pass over a volume. It applies lifecycle rules, resumes
// heal jobs left from an unclean shutdown, checks bitrot frames, and drains the
// on-demand migration queue. Each pass can be switched off.
module worker

import os
import store
import time

pub struct Switches {
pub:
	scanner bool = true
	heal    bool = true
}

pub fn lifecycle(volume store.Volume, now i64) ! {
	for name in volume.list_buckets()! {
		volume.apply_lifecycle(name, now)!
	}
}

pub fn heal_bucket(volume store.Volume, bucket_name string) !int {
	mut restored := 0
	for stat in volume.list(bucket_name, '', 0)! {
		if stat.delete_marker {
			continue
		}
		restored += volume.heal_object(bucket_name, stat.key) or { continue }
	}
	return restored
}

// scanner_enabled reports whether the background pass should run. An empty
// value keeps the historical default: the scanner is on.
pub fn scanner_enabled() bool {
	raw := os.getenv('VFS_SCANNER_ENABLED').to_lower()
	return raw.len == 0 || raw == '1' || raw == 'true' || raw == 'on'
}

// loop_scan applies lifecycle and heal until the volume is stopping.
pub fn loop_scan(volume store.Volume) {
	for {
		if volume.service_mode() == 'stopping' {
			return
		}
		run(volume, Switches{}) or {
			eprintln('vfs: scanner: ${err}')
		}
		time.sleep(60 * time.second)
	}
}

pub fn run(volume store.Volume, switches Switches) ! {
	now := time.now().unix()
	if switches.scanner && volume.module_on('scanner') {
		lifecycle(volume, now)!
	}
	if switches.heal && volume.module_on('heal') {
		volume.resume_heal()!
		for name in volume.list_buckets()! {
			heal_bucket(volume, name)!
		}
		if volume.unclean_pending() {
			volume.clear_heal_pending()!
		}
	}
	if volume.module_on('bitrot') {
		volume.scrub_volume()!
	}
	if volume.module_on('migrate') {
		volume.drain_migrate()!
	}
	volume.refresh_usage()!
	volume.purge_kms(now, 7 * 86400)
}
