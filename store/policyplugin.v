// policyplugin stores the external authorization endpoint. An empty url means
// the process decides with IAM and bucket policies only.
module store

import json2

const plugin_file = '.vfs.sys/policy-plugin.json'

pub struct PolicyPlugin {
pub:
	url string
}

pub fn (v Volume) policy_plugin() PolicyPlugin {
	if v.drives.len == 0 {
		return PolicyPlugin{}
	}
	raw := v.drives[0].read(plugin_file) or { return PolicyPlugin{} }
	return json2.decode[PolicyPlugin](raw.bytestr()) or { return PolicyPlugin{} }
}

pub fn (v Volume) set_policy_plugin(url string) ! {
	if !url.starts_with('http://') && !url.starts_with('https://') {
		return error('plugin url must be http or https')
	}
	encoded := json2.encode[PolicyPlugin](PolicyPlugin{ url: url }, escape_unicode: true).bytes()
	for drive in v.drives {
		drive.write(plugin_file, encoded)!
	}
}

pub fn (v Volume) clear_policy_plugin() ! {
	for drive in v.drives {
		drive.remove(plugin_file)!
	}
}
