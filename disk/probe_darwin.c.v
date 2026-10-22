module disk

#include <sys/mount.h>

fn C.statfs(path &char, buf voidptr) int

// Darwin's statfs puts the 16-byte filesystem name at offset 72. The buffer is
// the full struct size so the call cannot write past it.
fn probe_filesystem_host(path string) string {
	mut buf := [2168]u8{}
	unsafe {
		if C.statfs(&char(path.str), &buf[0]) != 0 {
			return ''
		}
	}
	mut name := ''
	for i in 72 .. 88 {
		if buf[i] == 0 {
			break
		}
		name += buf[i].ascii_str()
	}
	return name
}
