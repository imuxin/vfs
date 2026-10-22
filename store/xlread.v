// xlread serves an unencrypted xl.meta that was placed beside an object key.
// The volume's own records stay JSON. This path only reads the foreign file.
module store

import encoding.hex
import os
import meta

fn (v Volume) load_xl(bucket string, key string) !meta.XlMeta {
	require_bucket(v, bucket)!
	path := os.join_path(object_dir(bucket, key), 'xl.meta')
	for drive in v.drives {
		raw := drive.read(path) or { continue }
		return meta.read_xl(raw)
	}
	return error('object not found: ${key}')
}

fn stat_from_xl(key string, version meta.XlVersion) Stat {
	size := if version.size > 0 { version.size } else { i64(version.data.len) }
	return Stat{
		key:           key
		version:       version.id
		size:          size
		etag:          hex.encode(md5_of(version.data))
		content_type:  'application/octet-stream'
		storage_class: 'STANDARD'
		user_meta:     map[string]string{}
		tags:          map[string]string{}
		delete_marker: version.delete_marker
		latest:        true
	}
}

fn (v Volume) stat_xl(bucket string, key string) !Stat {
	version := v.load_xl(bucket, key)!.latest()!
	return stat_from_xl(key, version)
}

fn (v Volume) bytes_xl(bucket string, key string) ![]u8 {
	version := v.load_xl(bucket, key)!.latest()!
	if version.delete_marker {
		return error('object not found: ${key}')
	}
	return version.data.clone()
}
