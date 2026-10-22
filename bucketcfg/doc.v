// bucket is the configuration that hangs off a bucket and is not object bytes:
// policy, CORS, website, default encryption, quota, and the documents that are
// stored even when the server does not act on them. One document API keeps
// those records from each growing a private file format.
module bucketcfg

import json2

pub struct Policy {
pub:
	version    string
	statements []Statement
}

pub struct Statement {
pub:
	effect    string
	principal []string
	action    []string
	resource  []string
}

pub struct CorsRule {
pub:
	origins []string
	methods []string
	headers []string
}

pub struct Website {
pub:
	index     string
	error_doc string
	redirect  string
	host      string
}

// website_key is the object a website host should read. An empty option means
// this request is ordinary S3, not the configured website host.
pub fn website_key(site Website, host string, key string) ?string {
	if site.host.len == 0 || host != site.host {
		return none
	}
	if key.len == 0 || key.ends_with('/') {
		return key + site.index
	}
	return key
}

pub struct Encryption {
pub:
	algorithm string
}

pub struct Quota {
pub:
	hard i64
}

pub struct PublicAccess {
pub:
	block_public_policy     bool
	restrict_public_buckets bool
	ignore_public_acls      bool
}

// effect is allow, deny, or empty when the policy does not speak to the request.
pub fn effect(policy Policy, principal string, action string, resource string) string {
	mut granted := false
	for statement in policy.statements {
		if !matches(statement.action, action) || !matches(statement.resource, resource) {
			continue
		}
		if statement.principal.len > 0 && !matches(statement.principal, principal) && !matches(statement.principal, '*') {
			continue
		}
		if statement.effect == 'Deny' {
			return 'deny'
		}
		if statement.effect == 'Allow' {
			granted = true
		}
	}
	if granted {
		return 'allow'
	}
	return ''
}

pub fn allows(policy Policy, principal string, action string, resource string) bool {
	return effect(policy, principal, action, resource) == 'allow'
}

pub struct Cors {
pub:
	rules []CorsRule
}

// cors_match returns the first rule whose origin and method fit the request.
pub fn cors_match(rules []CorsRule, origin string, method string) ?CorsRule {
	for rule in rules {
		if !list_has(rule.origins, origin) && !list_has(rule.origins, '*') {
			continue
		}
		if rule.methods.len > 0 && !list_has(rule.methods, method) && !list_has(rule.methods, '*') {
			continue
		}
		return rule
	}
	return none
}

fn list_has(values []string, want string) bool {
	for value in values {
		if value == want {
			return true
		}
	}
	return false
}

pub fn is_public(policy Policy) bool {
	for statement in policy.statements {
		if statement.effect == 'Allow' && matches(statement.principal, '*') {
			return true
		}
	}
	return false
}

fn matches(patterns []string, value string) bool {
	if patterns.len == 0 {
		return true
	}
	for pattern in patterns {
		if wildcard(pattern, value) {
			return true
		}
	}
	return false
}

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

pub fn encode[T](value T) string {
	return json2.encode[T](value, escape_unicode: true)
}

pub fn decode[T](raw string) !T {
	return json2.decode[T](raw)
}
