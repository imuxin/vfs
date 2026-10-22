// group is a set of users that share policies. A user's effective policy is
// the user's own attachments plus every enabled group the user belongs to.
// A deny in any of them still wins.
module iam

import json2
import os

pub struct Group {
pub:
	name     string
	status   string
	members  []string
	policies []string
}

pub fn (d Directory) put_group(group Group) ! {
	write(d.path('groups', group.name), json2.encode[Group](group, escape_unicode: true))!
}

pub fn (d Directory) group(name string) !Group {
	return json2.decode[Group](read(d.path('groups', name))!)
}

pub fn (d Directory) delete_group(name string) ! {
	os.rm(d.path('groups', name)) or {}
}

// groups_for lists the enabled groups that name this user.
pub fn (d Directory) groups_for(user string) []Group {
	dir := os.join_path(d.root, 'groups')
	names := os.ls(dir) or { return []Group{} }
	mut found := []Group{}
	for name in names {
		if !name.ends_with('.json') {
			continue
		}
		group := d.group(name.trim_string_right('.json')) or { continue }
		if group.status == 'Disabled' {
			continue
		}
		if user in group.members {
			found << group
		}
	}
	return found
}
