module s3

import net.http
import store

fn request_with(name string, value string) http.Request {
	mut header := http.new_header()
	header.add_custom(name, value) or {}
	return http.Request{
		header: header
	}
}

fn test_read_conditions() {
	stat := store.Stat{
		etag:     'abc'
		modified: 100
	}
	assert !read_verdict(stat, request_with('If-Match', '"abc"')).stop
	miss := read_verdict(stat, request_with('If-Match', '"nope"'))
	assert miss.stop && miss.code == 'PreconditionFailed'
	same := read_verdict(stat, request_with('If-None-Match', '"abc"'))
	assert same.code == 'NotModified'
	stale := read_verdict(stat, request_with('If-Modified-Since', '100'))
	assert stale.code == 'NotModified'
	changed := read_verdict(stat, request_with('If-Unmodified-Since', '50'))
	assert changed.code == 'PreconditionFailed'
}

fn test_write_conditions_and_delete_keys() {
	stat := store.Stat{
		etag: 'abc'
	}
	assert write_verdict(true, stat, request_with('If-None-Match', '*')).code == 'PreconditionFailed'
	assert !write_verdict(false, stat, request_with('If-None-Match', '*')).stop
	keys := delete_keys('<Delete><Object><Key>a.txt</Key></Object><Object><Key>b.txt</Key></Object></Delete>')
	assert keys == ['a.txt', 'b.txt']
}
