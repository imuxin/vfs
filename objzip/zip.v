// zip packs named object bytes into one archive and reads that archive back.
// Entry names are object keys: they stay relative, so a download cannot be
// asked to write outside the archive.
module objzip

import compress.szip
import os

pub struct File {
pub:
	name string
	data []u8
}

pub fn encode(files []File) ![]u8 {
	for file in files {
		check_name(file.name)!
	}
	dir := os.join_path(os.temp_dir(), 'vfs-objzip-${os.getpid()}')
	os.mkdir_all(dir)!
	defer { os.rmdir_all(dir) or {} }
	path := os.join_path(dir, 'objects.zip')
	mut archive := szip.open(path, .no_compression, .write)!
	for file in files {
		archive.open_entry(file.name)!
		archive.write_entry(file.data)!
		archive.close_entry()
	}
	archive.close()
	return os.read_bytes(path)
}

pub fn decode(payload []u8) ![]File {
	if payload.len == 0 {
		return error('object zip is empty')
	}
	dir := os.join_path(os.temp_dir(), 'vfs-objunzip-${os.getpid()}')
	os.mkdir_all(dir)!
	defer { os.rmdir_all(dir) or {} }
	path := os.join_path(dir, 'objects.zip')
	os.write_file_array(path, payload)!
	mut archive := szip.open(path, .no_compression, .read_only)!
	defer { archive.close() }
	total := archive.total()!
	mut files := []File{cap: total}
	for index in 0 .. total {
		archive.open_entry_by_index(index)!
		name := archive.name().clone()
		body := read_entry(mut archive)!
		archive.close_entry()
		if name.ends_with('/') || archive_dir(name) {
			continue
		}
		files << File{
			name: name
			data: body
		}
	}
	return files
}

fn archive_dir(name string) bool {
	return name.len == 0
}

fn check_name(name string) ! {
	if name.len == 0 || name.starts_with('/') || name.contains('..') || name.ends_with('/') {
		return error('invalid object zip name')
	}
}

fn read_entry(mut archive szip.Zip) ![]u8 {
	raw := archive.read_entry()!
	size := int(archive.size())
	if size == 0 {
		unsafe { free(raw) }
		return []u8{}
	}
	copied := unsafe { (&u8(raw)).vbytes(size).clone() }
	unsafe { free(raw) }
	return copied
}
