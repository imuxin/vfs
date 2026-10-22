// disk is the only layer that touches a filesystem. Everything above it
// addresses drives by index and objects by bucket, key, and shard, so a
// remote drive can later satisfy the same interface without callers changing.
module disk

import os

// Drive is one backing volume. A single-drive deployment has one; an erasure
// set has one per disk in the set.
pub interface Drive {
	root() string
	read(path string) ![]u8
	write(path string, data []u8) !
	remove(path string) !
	exists(path string) bool
	list(dir string) ![]string
}

// Local is a drive rooted at one directory. Paths are relative to the root and
// may not escape it.
pub struct Local {
pub:
	root_path string
}

pub fn open(root_path string) !Local {
	reject_filesystem(probe_filesystem(root_path))!
	os.mkdir_all(root_path)!
	return Local{
		root_path: root_path
	}
}

// probe_filesystem reports the mount type when the platform can name it.
// Other platforms return an empty string, which reject_filesystem allows.
fn probe_filesystem(path string) string {
	$if macos {
		return probe_filesystem_host(path)
	}
	return ''
}

pub fn (d Local) root() string {
	return d.root_path
}

fn (d Local) resolve(path string) !string {
	if path.contains('..') {
		return error('path escapes drive root: ${path}')
	}
	return os.join_path(d.root_path, path)
}

pub fn (d Local) read(path string) ![]u8 {
	return os.read_bytes(d.resolve(path)!)
}

pub fn (d Local) write(path string, data []u8) ! {
	full := d.resolve(path)!
	os.mkdir_all(os.dir(full))!
	// A trailing suffix keeps a crash mid-write from exposing a partial object;
	// the rename is the commit point.
	tmp := '${full}.tmp'
	os.write_file_array(tmp, data)!
	os.rm(full) or {}
	os.mv(tmp, full)!
}

pub fn (d Local) remove(path string) ! {
	full := d.resolve(path)!
	if os.exists(full) {
		os.rm(full)!
	}
}

// remove_tree deletes a directory the volume owns, such as one object version.
// The drive root itself is not a valid target.
pub fn (d Local) remove_tree(path string) ! {
	if path.len == 0 || path == '.' || path == '/' {
		return error('refusing to remove the drive root')
	}
	full := d.resolve(path)!
	if os.exists(full) {
		os.rmdir_all(full)!
	}
}

pub fn (d Local) exists(path string) bool {
	full := d.resolve(path) or { return false }
	return os.exists(full)
}

pub fn (d Local) list(dir string) ![]string {
	full := d.resolve(dir)!
	if !os.exists(full) {
		return []string{}
	}
	return os.ls(full)
}
