// tier names a warm destination and stores the bytes that have left the hot
// erasure set. The archive is a directory spool: transition and restore share
// one contract whether the configured kind is S3, a compatible cloud, or a
// local stand-in used by tests. Azure storage-class and service-principal
// authentication are rejected, matching the deployments that cannot use them.
module tier

import os
import replicate

pub struct Remote {
pub:
	name       string
	kind       string
	auth       string
	bucket     string
	prefix     string
	endpoint   string
	region     string
	access_key string
	secret_key string
}

pub struct Archive {
pub:
	root string
}

// check accepts the warm-tier kinds this process can name. An empty auth is
// access-key authentication. Azure refuses the two schemes it cannot use.
pub fn check(remote Remote) ! {
	if remote.name.len == 0 {
		return error('tier name is required')
	}
	kind := remote.kind.to_lower()
	match kind {
		's3', 'wasabi', 'rustfs', 'minio', 'ali', 'tencent', 'huawei', 'azure', 'gcs', 'r2' {}
		else {
			return error('unsupported tier kind: ${remote.kind}')
		}
	}
	if kind == 'azure' && (remote.auth == 'storage-class' || remote.auth == 'service-principal') {
		return error('azure ${remote.auth} authentication is not supported')
	}
}

pub fn (a Archive) put(remote Remote, bucket string, key string, data []u8) ! {
	check(remote)!
	if remote.uses_http() {
		replicate.put(remote.target()!, remote.bucket, object_key(remote, key), data, 'application/octet-stream')!
		return
	}
	full := a.path(remote, bucket, key)!
	os.mkdir_all(os.dir(full))!
	os.write_file_array(full, data)!
}

pub fn (a Archive) get(remote Remote, bucket string, key string) ![]u8 {
	check(remote)!
	if remote.uses_http() {
		return replicate.get(remote.target()!, remote.bucket, object_key(remote, key))
	}
	return os.read_bytes(a.path(remote, bucket, key)!)
}

// uses_http reports whether this tier ships bytes to an S3 endpoint. Kinds
// that do not speak SigV4 stay on the local spool even if an address is set.
pub fn (r Remote) uses_http() bool {
	lower := r.endpoint.to_lower()
	if !(lower.starts_with('http://') || lower.starts_with('https://')) {
		return false
	}
	return r.s3_compatible()
}

fn (r Remote) s3_compatible() bool {
	return match r.kind.to_lower() {
		's3', 'wasabi', 'rustfs', 'minio', 'ali', 'tencent', 'huawei', 'r2' { true }
		else { false }
	}
}

fn (r Remote) target() !replicate.Target {
	if !r.s3_compatible() {
		return error('tier kind does not speak s3 sigv4')
	}
	if r.endpoint.len == 0 || r.bucket.len == 0 {
		return error('tier endpoint and bucket are required')
	}
	region := if r.region.len > 0 { r.region } else { 'us-east-1' }
	return replicate.Target{
		endpoint:   r.endpoint
		region:     region
		access_key: r.access_key
		secret_key: r.secret_key
	}
}

fn object_key(remote Remote, key string) string {
	if remote.prefix.len == 0 {
		return key
	}
	return '${remote.prefix}/${key}'
}

pub fn (a Archive) remove(remote Remote, bucket string, key string) ! {
	full := a.path(remote, bucket, key)!
	if os.exists(full) {
		os.rm(full)!
	}
}

pub fn (a Archive) clear(name string) ! {
	if name.len == 0 || name.contains('..') || name.contains('/') {
		return error('invalid tier name')
	}
	os.rmdir_all(os.join_path(a.root, name)) or {}
}

fn (a Archive) path(remote Remote, bucket string, key string) !string {
	if remote.name.contains('..') || bucket.contains('..') || key.contains('..') {
		return error('tier path escapes the archive')
	}
	rel := if remote.prefix.len == 0 { key } else { '${remote.prefix}/${key}' }
	return os.join_path(a.root, remote.name, bucket, rel)
}
