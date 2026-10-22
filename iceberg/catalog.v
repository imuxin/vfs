// catalog is a file-backed Iceberg REST catalog. It stores namespaces and
// table names. It does not run queries and does not claim multi-table
// transactions. Clients that only need config, namespaces, and tables can
// talk to it on /iceberg/v1 and /_iceberg/v1.
module iceberg

import json2
import net.http
import net.urllib
import os

pub struct Catalog {
pub:
	root string
}

pub fn open(root string) !Catalog {
	os.mkdir_all(root)!
	return Catalog{
		root: root
	}
}

pub fn (c Catalog) namespaces() []string {
	names := os.ls(c.root) or { return []string{} }
	mut out := []string{}
	for name in names {
		if os.is_dir(os.join_path(c.root, name)) {
			out << name
		}
	}
	out.sort()
	return out
}

pub fn (c Catalog) create_namespace(name string) ! {
	if name.len == 0 || name.contains('/') || name.contains('..') {
		return error('invalid namespace')
	}
	os.mkdir_all(os.join_path(c.root, name))!
}

pub fn (c Catalog) tables(namespace string) []string {
	dir := os.join_path(c.root, namespace)
	names := os.ls(dir) or { return []string{} }
	mut out := []string{}
	for name in names {
		if name.ends_with('.json') {
			out << name.trim_string_right('.json')
		}
	}
	out.sort()
	return out
}

pub fn (c Catalog) create_table(namespace string, name string) ! {
	if name.len == 0 || name.contains('/') || name.contains('..') {
		return error('invalid table')
	}
	c.create_namespace(namespace)!
	path := os.join_path(c.root, namespace, '${name}.json')
	os.write_file(path, '{"name":"${name}","namespace":"${namespace}"}')!
}

struct NamespaceBody {
	name      string
	namespace []string
}

struct TableBody {
	name string
}

// handle serves one Iceberg REST request. Paths may use either prefix.
pub fn handle(req http.Request, root string) http.Response {
	catalog := open(root) or {
		return http.new_response(status: .internal_server_error, body: '${err}')
	}
	url := urllib.parse(req.url) or {
		return http.new_response(status: .bad_request, body: 'bad url')
	}
	path := strip_prefix(url.path)
	if path == '/config' && req.method == .get {
		return json_response(.ok, '{"overrides":{},"defaults":{}}')
	}
	if path == '/namespaces' && req.method == .get {
		return json_response(.ok, namespace_list(catalog.namespaces()))
	}
	if path == '/namespaces' && req.method == .post {
		body := json2.decode[NamespaceBody](req.data) or {
			return http.new_response(status: .bad_request, body: 'bad namespace')
		}
		name := if body.namespace.len > 0 { body.namespace[0] } else { body.name }
		catalog.create_namespace(name) or {
			return http.new_response(status: .bad_request, body: '${err}')
		}
		return json_response(.ok, '{"namespace":["${name}"]}')
	}
	if path.starts_with('/namespaces/') && path.ends_with('/tables') {
		namespace := path.trim_string_left('/namespaces/').trim_string_right('/tables')
		if req.method == .get {
			return json_response(.ok, table_list(namespace, catalog.tables(namespace)))
		}
		if req.method == .post {
			body := json2.decode[TableBody](req.data) or {
				return http.new_response(status: .bad_request, body: 'bad table')
			}
			catalog.create_table(namespace, body.name) or {
				return http.new_response(status: .bad_request, body: '${err}')
			}
			return json_response(.ok, '{"namespace":["${namespace}"],"name":"${body.name}"}')
		}
	}
	return http.new_response(status: .not_found, body: 'unknown iceberg route')
}

fn strip_prefix(path string) string {
	if path.starts_with('/iceberg/v1') {
		return path.trim_string_left('/iceberg/v1')
	}
	if path.starts_with('/_iceberg/v1') {
		return path.trim_string_left('/_iceberg/v1')
	}
	return path
}

fn namespace_list(names []string) string {
	mut items := []string{}
	for name in names {
		items << '["${name}"]'
	}
	return '{"namespaces":[' + items.join(',') + ']}'
}

fn table_list(namespace string, names []string) string {
	mut items := []string{}
	for name in names {
		items << '{"namespace":["${namespace}"],"name":"${name}"}'
	}
	return '{"identifiers":[' + items.join(',') + ']}'
}

fn json_response(status http.Status, body string) http.Response {
	return http.new_response(
		status: status
		body:   body
		header: http.new_header(key: .content_type, value: 'application/json')
	)
}
