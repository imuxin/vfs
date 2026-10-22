// select serves S3 Select for CSV objects. The expression is the SQL subset
// in the query module; the response body is the projected CSV or JSON lines.
module s3

import net.http
import form
import query
import store

fn (s Service) form_upload(req http.Request, target Target) http.Response {
	if target.bucket.len == 0 {
		return failure(http.Status.bad_request, 'InvalidArgument', 'missing bucket', '', '')
	}
	content_type := req.header.get(.content_type) or { '' }
	upload := form.parse(content_type, req.data.bytes()) or {
		return failure(http.Status.bad_request, 'InvalidArgument', '${err}', target.bucket, '')
	}
	stat := s.volume.put(store.PutRequest{
		bucket:       target.bucket
		key:          upload.key
		data:         upload.body
		content_type: upload.content_type
	}) or {
		return storage_failure(err, target)
	}
	return versioned(http.new_response(
		status: .ok
		body:   ''
		header: etag_header(stat.etag)
	), stat)
}

fn (s Service) select_object(req http.Request, target Target) http.Response {
	expr := between(req.data, '<Expression>', '</Expression>') or {
		return failure(http.Status.bad_request, 'MalformedXML', 'missing expression', target.bucket, target.key)
	}
	parsed := query.parse(expr) or {
		return failure(http.Status.bad_request, 'MalformedXML', '${err}', target.bucket, target.key)
	}
	input := between(req.data, '<InputSerialization>', '</InputSerialization>') or { '' }
	output := between(req.data, '<OutputSerialization>', '</OutputSerialization>') or { '' }
	json_in := input.contains('<JSON>')
	as_json := output.contains('<JSON>') || (input.len == 0 && req.data.contains('<JSON>'))
	body := s.volume.get(target.bucket, target.key, []u8{}) or {
		if '${err}'.contains('archived') {
			return failure(http.Status.not_implemented, 'NotImplemented',
				'select on an archived object is not implemented', target.bucket, target.key)
		}
		return storage_failure(err, target)
	}
	selected := query.Select{
		columns:      parsed.columns
		where_column: parsed.where_column
		where_value:  parsed.where_value
		as_json:      as_json
	}
	out := if json_in {
		query.eval_json(selected, body.bytestr()) or {
			return failure(http.Status.bad_request, 'InvalidRequest', '${err}', target.bucket,
				target.key)
		}
	} else {
		query.eval_csv(selected, body.bytestr()) or {
			return failure(http.Status.bad_request, 'InvalidRequest', '${err}', target.bucket,
				target.key)
		}
	}
	kind := if as_json { 'application/json' } else { 'text/csv' }
	return http.new_response(
		status: .ok
		body:   out
		header: http.new_header(key: .content_type, value: kind)
	)
}

fn parse_object_lock(body string) !(bool, string, int) {
	enabled := body.contains('<ObjectLockEnabled>Enabled</ObjectLockEnabled>')
	mode := between(body, '<Mode>', '</Mode>') or { '' }
	days := (between(body, '<Days>', '</Days>') or { '0' }).int()
	if mode.len > 0 && mode != 'GOVERNANCE' && mode != 'COMPLIANCE' {
		return error('invalid retention mode')
	}
	if !enabled && mode.len == 0 {
		return error('object lock configuration is empty')
	}
	return enabled, mode, days
}
