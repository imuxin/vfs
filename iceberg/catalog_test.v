module iceberg

import net.http
import os

fn test_namespace_and_table_roundtrip() {
	root := os.join_path(os.temp_dir(), 'vfs-iceberg-${os.getpid()}')
	defer { os.rmdir_all(root) or {} }
	catalog := open(root)!
	catalog.create_namespace('analytics')!
	catalog.create_table('analytics', 'events')!
	assert catalog.namespaces() == ['analytics']
	assert catalog.tables('analytics') == ['events']
	listed := handle(http.Request{
		method: .get
		url:    '/iceberg/v1/namespaces'
	}, root)
	assert listed.body.contains('analytics')
	alt := handle(http.Request{
		method: .get
		url:    '/_iceberg/v1/namespaces/analytics/tables'
	}, root)
	assert alt.body.contains('events')
}
