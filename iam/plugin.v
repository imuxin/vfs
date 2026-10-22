// plugin asks an external OPA-style HTTP endpoint before a request is allowed.
// The deployment keeps using IAM and bucket policies; a configured plugin is an
// extra decision that must allow the call. A false result or a failed call
// refuses the request.
module iam

import json2
import net.http
import time

// PluginQuery is the document posted as `input`.
pub struct PluginQuery {
pub:
	access_key string @[json: 'accessKey']
	action     string
	resource   string
	bucket     string
	key        string
}

// ask posts the query and reads the decision. `result: true` and
// `result: {"allow": true}` both allow. Anything else, including a missing
// result, denies. The caller treats a transport error as a denial too.
pub fn ask(url string, query PluginQuery) !Verdict {
	if url.len == 0 {
		return error('policy plugin url is empty')
	}
	body := '{"input":${json2.encode[PluginQuery](query, escape_unicode: true)}}'
	response := http.fetch(
		method:                  .post
		url:                     url
		data:                    body
		header:                  http.new_header(key: .content_type, value: 'application/json')
		read_timeout:             2 * time.second
		write_timeout:            2 * time.second
		max_retries:              1
		allow_redirect:           false
		disable_connection_reuse: true
	)!
	if response.status_code >= 300 {
		return error('policy plugin rejected the request: ${response.status_code}')
	}
	return plugin_verdict(response.body)
}

// plugin_verdict reads an OPA or webhook JSON body.
pub fn plugin_verdict(body string) !Verdict {
	parsed := json2.decode[json2.Any](body)!
	match parsed {
		map[string]json2.Any {
			if 'result' in parsed {
				return value_verdict(parsed['result'] or { return Verdict.deny })
			}
			if 'allow' in parsed {
				return value_verdict(parsed['allow'] or { return Verdict.deny })
			}
			return Verdict.deny
		}
		else {
			return error('policy plugin response is not an object')
		}
	}
}

fn value_verdict(value json2.Any) !Verdict {
	match value {
		bool {
			if value {
				return Verdict.allow
			}
			return Verdict.deny
		}
		map[string]json2.Any {
			if 'allow' in value {
				return value_verdict(value['allow'] or { return Verdict.deny })
			}
			return Verdict.deny
		}
		else {
			return Verdict.deny
		}
	}
}
