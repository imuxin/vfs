// The directory is where identities live. It stores users, their access keys,
// and named policies, and answers the one question the request path asks: does
// this access key's identity allow this action on this resource. Persistence is
// a directory of JSON files, the same shape as every other record in the tree.
module iam

import json2
import os
import time

// User is one identity. Policies name entries in the directory; a user with
// none is denied everything.
pub struct User {
pub:
	name     string
	status   string
	policies []string
}

// AccessKey binds a secret to a user. Status Disabled keeps the key resolvable
// but refuses every request made with it.
pub struct AccessKey {
pub:
	access_key string
	secret_key string
	user       string
	status     string
	// policies, when set, are an extra restriction on top of the user and
	// groups. expires is a unix time; zero means the key does not expire.
	// session is the STS token that must accompany the key.
	policies []string
	expires  i64
	session  string
}

// Directory is the identity store, rooted at one directory.
pub struct Directory {
pub:
	root string
}

// open creates a directory at root, making the path if it does not exist.
pub fn open(root string) !Directory {
	os.mkdir_all(root)!
	return Directory{
		root: root
	}
}

// put_user creates or replaces a user.
pub fn (d Directory) put_user(user User) ! {
	write(d.path('users', user.name), json2.encode[User](user, escape_unicode: true))!
}

// user reads one user.
pub fn (d Directory) user(name string) !User {
	return json2.decode[User](read(d.path('users', name))!)
}

// put_key stores an access key.
pub fn (d Directory) put_key(key AccessKey) ! {
	write(d.path('keys', key.access_key), json2.encode[AccessKey](key, escape_unicode: true))!
}

// key reads one access key.
pub fn (d Directory) key(access_key string) !AccessKey {
	return json2.decode[AccessKey](read(d.path('keys', access_key))!)
}

// put_policy stores a named policy.
pub fn (d Directory) put_policy(name string, policy Policy) ! {
	write(d.path('policies', name), policy.encode())!
}

// policy reads one named policy.
pub fn (d Directory) policy(name string) !Policy {
	return decode(read(d.path('policies', name))!)
}

// has_policy reports whether a named policy is stored.
pub fn (d Directory) has_policy(name string) bool {
	return os.exists(d.path('policies', name))
}

// secret resolves an access key to its secret. A disabled key resolves to
// nothing, so a request signed with it fails authentication outright.
pub fn (d Directory) secret(access_key string) !string {
	key := d.key(access_key)!
	if key.status == 'Disabled' {
		return error('access key disabled')
	}
	if key.expires > 0 && key.expires < time.now().unix() {
		return error('access key expired')
	}
	return key.secret_key
}

// allows reports whether the access key's user may perform the action. Every
// attached policy is consulted; one deny in any of them refuses the request.
pub fn (d Directory) allows(access_key string, action string, resource string) !bool {
	key := d.key(access_key)!
	if key.expires > 0 && key.expires < time.now().unix() {
		return false
	}
	user := d.user(key.user)!
	if user.status == 'Disabled' {
		return false
	}
	mut names := user.policies.clone()
	for group in d.groups_for(key.user) {
		names << group.policies
	}
	granted := d.any_allows(names, action, resource)!
	if !granted {
		return false
	}
	if key.policies.len == 0 {
		return true
	}
	return d.any_allows(key.policies, action, resource)
}

fn (d Directory) any_allows(names []string, action string, resource string) !bool {
	mut granted := false
	for name in names {
		policy := d.policy(name)!
		if denies(policy, action, resource) {
			return false
		}
		if policy.allows(action, resource) {
			granted = true
		}
	}
	return granted
}

// Verdict is one policy set's answer before it is combined with the bucket policy.
// abstain means the set neither allowed nor denied.
pub enum Verdict {
	abstain
	allow
	deny
}

// verdict is allows without collapsing a missing allow into the same answer as
// an explicit deny. The request path needs that distinction so a bucket policy
// can still grant what IAM left open.
pub fn (d Directory) verdict(access_key string, action string, resource string) !Verdict {
	key := d.key(access_key)!
	if key.expires > 0 && key.expires < time.now().unix() {
		return Verdict.deny
	}
	user := d.user(key.user)!
	if user.status == 'Disabled' {
		return Verdict.deny
	}
	mut names := user.policies.clone()
	for group in d.groups_for(key.user) {
		names << group.policies
	}
	base := d.verdict_of(names, action, resource)!
	if key.policies.len == 0 {
		return base
	}
	limited := d.verdict_of(key.policies, action, resource)!
	if base == .deny || limited == .deny {
		return Verdict.deny
	}
	if base == .allow && limited == .allow {
		return Verdict.allow
	}
	return Verdict.abstain
}

fn (d Directory) verdict_of(names []string, action string, resource string) !Verdict {
	mut granted := false
	for name in names {
		policy := d.policy(name)!
		if denies(policy, action, resource) {
			return Verdict.deny
		}
		if policy.allows(action, resource) {
			granted = true
		}
	}
	if granted {
		return Verdict.allow
	}
	return Verdict.abstain
}

// join combines IAM and a bucket policy. An explicit deny on either side wins.
// Otherwise either side may grant.
pub fn join(iam_answer Verdict, bucket_answer Verdict) bool {
	if iam_answer == .deny || bucket_answer == .deny {
		return false
	}
	return iam_answer == .allow || bucket_answer == .allow
}

// denies reports whether any statement of the policy explicitly refuses.
fn denies(policy Policy, action string, resource string) bool {
	for statement in policy.statements {
		if statement.effect == 'Deny' && statement.matches(action, resource) {
			return true
		}
	}
	return false
}

fn (d Directory) path(kind string, name string) string {
	return os.join_path(d.root, kind, name + '.json')
}

fn write(path string, body string) ! {
	os.mkdir_all(os.dir(path))!
	os.write_file(path, body)!
}

fn read(path string) !string {
	return os.read_file(path)
}
