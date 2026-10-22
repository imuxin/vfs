// fstype decides whether a backing filesystem is allowed to hold shards.
// Network and userspace mounts are rejected because a partial write or a
// stale attribute cache there breaks the erasure quorum.
module disk

// reject_filesystem fails for NFS, CIFS/SMB, and FUSE. An empty name means the
// type could not be read, which is allowed so a local disk without a probe
// still opens.
pub fn reject_filesystem(kind string) ! {
	name := kind.to_lower()
	if name.len == 0 {
		return
	}
	if name.contains('nfs') || name.contains('cifs') || name.contains('smb') || name.contains('fuse') {
		return error('filesystem ${kind} cannot hold data')
	}
}
