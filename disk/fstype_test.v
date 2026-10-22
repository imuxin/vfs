module disk

import os

fn test_this_machine_temp_dir_is_allowed() {
	kind := probe_filesystem(os.temp_dir())
	reject_filesystem(kind)!
	$if macos {
		assert kind.len > 0
	}
}

fn test_network_and_fuse_filesystems_are_rejected() {
	reject_filesystem('apfs')!
	reject_filesystem('')!
	reject_filesystem('nfs') or { return }
	assert false
}
