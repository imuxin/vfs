module webdav

import store

struct Entry {
	href        string
	name        string
	size        i64
	kind        string
	collection  bool
}

fn object_entry(bucket string, stat store.Stat) Entry {
	return Entry{
		href: '/${bucket}/${stat.key}'
		name: display_name(stat.key)
		size: stat.size
		kind: stat.content_type
	}
}

fn multistatus(entries []Entry) string {
	mut body := '<?xml version="1.0" encoding="utf-8"?>\n<d:multistatus xmlns:d="DAV:">'
	for entry in entries {
		kind := if entry.collection {
			'<d:resourcetype><d:collection/></d:resourcetype>'
		} else {
			'<d:resourcetype/><d:getcontentlength>${entry.size}</d:getcontentlength><d:getcontenttype>${xml_escape(entry.kind)}</d:getcontenttype>'
		}
		body += '<d:response><d:href>${xml_escape(entry.href)}</d:href><d:propstat><d:prop><d:displayname>${xml_escape(entry.name)}</d:displayname>${kind}</d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>'
	}
	body += '</d:multistatus>'
	return body
}

fn display_name(key string) string {
	if !key.contains('/') {
		return key
	}
	return key.all_after_last('/')
}

fn xml_escape(raw string) string {
	return raw.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;')
}
