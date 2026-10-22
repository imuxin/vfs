// documents are the JSON records stored beside a bucket: policy, CORS,
// website, encryption, quota, and the configurations that are kept verbatim.
module store

import bucketcfg

fn doc_path(bucket_name string, name string) string {
	return '${bucket_name}/.${name}.json'
}

pub fn (v Volume) put_doc(bucket_name string, name string, body []u8) ! {
	require_bucket(v, bucket_name)!
	for drive in v.drives {
		drive.write(doc_path(bucket_name, name), body)!
	}
}

pub fn (v Volume) get_doc(bucket_name string, name string) ![]u8 {
	require_bucket(v, bucket_name)!
	for drive in v.drives {
		raw := drive.read(doc_path(bucket_name, name)) or { continue }
		return raw
	}
	return error('document not found: ${name}')
}

pub fn (v Volume) delete_doc(bucket_name string, name string) ! {
	require_bucket(v, bucket_name)!
	for drive in v.drives {
		drive.remove(doc_path(bucket_name, name))!
	}
}

fn (v Volume) enforce_quota(bucket_name string, adding i64) ! {
	raw := v.get_doc(bucket_name, 'quota') or { return }
	quota := bucketcfg.decode[bucketcfg.Quota](raw.bytestr()) or { return }
	if quota.hard <= 0 {
		return
	}
	if v.usage_of(bucket_name) + adding > quota.hard {
		return error('quota exceeded')
	}
}

fn (v Volume) usage_of(bucket_name string) i64 {
	raw := v.drives[0].read('${bucket_name}/.usage') or { return 0 }
	return raw.bytestr().trim_space().i64()
}

fn (v Volume) add_usage(bucket_name string, delta i64) ! {
	next := v.usage_of(bucket_name) + delta
	value := if next < 0 { i64(0) } else { next }
	encoded := '${value}'.bytes()
	for drive in v.drives {
		drive.write('${bucket_name}/.usage', encoded)!
	}
}

fn (v Volume) drop_object_cache(bucket_name string, key string) {
	if v.objects == unsafe { nil } {
		return
	}
	mut mem := v.objects
	mem.invalidate_prefix('${bucket_name}/${key}/')
}
