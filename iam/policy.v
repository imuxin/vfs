// iam decides whether an identity may perform an action. The decision is the
// same one S3 makes: an explicit deny wins, otherwise any matching allow
// grants, otherwise the request is refused. The module knows nothing about
// HTTP or storage; callers hand it the action and the resource.
module iam

import json2

// Statement is one clause of a policy. Effect is Allow or Deny. Action and
// resource are patterns: `*` matches across segments, `?` matches one
// character, so `s3:Get*` and `arn:aws:s3:::logs/*` read as written.
pub struct Statement {
pub:
	effect     string
	action     []string
	resource   []string
	conditions []Condition
}

// Policy is an ordered list of statements. Order only matters between deny and
// allow, which the decision below handles explicitly.
pub struct Policy {
pub:
	version    string
	statements []Statement
}

// encode renders a policy as JSON for storage.
pub fn (p Policy) encode() string {
	return json2.encode[Policy](p, escape_unicode: true)
}

// decode reads a policy back from storage.
pub fn decode(raw string) !Policy {
	return json2.decode[Policy](raw)
}

// allows reports whether the policy grants action on resource. A policy with no
// statements grants nothing.
pub fn (p Policy) allows(action string, resource string) bool {
	for statement in p.statements {
		if statement.effect == 'Deny' && statement.matches(action, resource) {
			return false
		}
	}
	for statement in p.statements {
		if statement.effect == 'Allow' && statement.matches(action, resource) {
			return true
		}
	}
	return false
}

pub fn (s Statement) matches(action string, resource string) bool {
	return s.matches_in(action, resource, map[string][]string{})
}

// matches_in applies action, resource, and conditions. An empty condition list
// does not change the decision, so policies written before conditions existed
// still mean what they meant.
pub fn (s Statement) matches_in(action string, resource string, ctx map[string][]string) bool {
	return matches_any(s.action, action) && matches_any(s.resource, resource) && s.conditions_hold(ctx)
}

fn matches_any(patterns []string, value string) bool {
	for pattern in patterns {
		if wildcard(pattern, value) {
			return true
		}
	}
	return false
}

// wildcard matches `*` across any run of characters and `?` against one.
fn wildcard(pattern string, value string) bool {
	mut pi := 0
	mut vi := 0
	mut star := -1
	mut mark := 0
	for vi < value.len {
		if pi < pattern.len && (pattern[pi] == value[vi] || pattern[pi] == `?`) {
			pi++
			vi++
		} else if pi < pattern.len && pattern[pi] == `*` {
			star = pi
			mark = vi
			pi++
		} else if star != -1 {
			pi = star + 1
			mark++
			vi = mark
		} else {
			return false
		}
	}
	for pi < pattern.len && pattern[pi] == `*` {
		pi++
	}
	return pi == pattern.len
}
