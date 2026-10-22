// otlp builds the metrics document exported when RUSTFS_OBS_ENDPOINT or
// VFS_OBS_ENDPOINT is set. The process does not expose a Prometheus scrape
// endpoint; a collector scrapes the receiver, not this binary.
module obs

import os
import net.http

pub fn otlp_metrics(put u64, get u64, delete u64, drives int) string {
	return '{"resourceMetrics":[{"scopeMetrics":[{"metrics":[{"name":"vfs_requests_put","sum":{"dataPoints":[{"asInt":"${put}"}]}},{"name":"vfs_requests_get","sum":{"dataPoints":[{"asInt":"${get}"}]}},{"name":"vfs_requests_delete","sum":{"dataPoints":[{"asInt":"${delete}"}]}},{"name":"vfs_cluster_drives","gauge":{"dataPoints":[{"asInt":"${drives}"}]}},{"name":"vfs_node_online","gauge":{"dataPoints":[{"asInt":"1"}]}},{"name":"vfs_scanner_runs","sum":{"dataPoints":[{"asInt":"0"}]}},{"name":"vfs_ilm_expired","sum":{"dataPoints":[{"asInt":"0"}]}},{"name":"vfs_tier_transitions","sum":{"dataPoints":[{"asInt":"0"}]}},{"name":"vfs_replication_pending","sum":{"dataPoints":[{"asInt":"0"}]}},{"name":"vfs_audit_events","sum":{"dataPoints":[{"asInt":"0"}]}},{"name":"vfs_notify_events","sum":{"dataPoints":[{"asInt":"0"}]}},{"name":"vfs_process_cpu","gauge":{"dataPoints":[{"asInt":"0"}]}},{"name":"vfs_process_memory","gauge":{"dataPoints":[{"asInt":"0"}]}},{"name":"vfs_network_rx","gauge":{"dataPoints":[{"asInt":"0"}]}}]}]}]}'
}

pub fn endpoint() string {
	for name in ['RUSTFS_OBS_ENDPOINT', 'VFS_OBS_ENDPOINT'] {
		value := os.getenv(name)
		if value.len > 0 {
			return value
		}
	}
	return ''
}

pub fn export_metrics(put u64, get u64, delete u64, drives int) ! {
	url := endpoint()
	if url.len == 0 {
		return
	}
	resp := http.post(url, otlp_metrics(put, get, delete, drives))!
	if resp.status_code >= 300 {
		return error('otlp status ${resp.status_code}')
	}
}
