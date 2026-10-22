// token maps an OpenStack Keystone v3 token, or an EC2 credential document,
// onto local policy names. The live service is optional and used only when a
// URL is configured.
module keystone

import json2
import net.http

struct Role {
	name string
}

struct Named {
	name  string
	roles []Role
}

struct TokenDoc {
	token Named
}

struct EC2Doc {
	access string
	secret string
	roles  []string
}

pub fn roles(body string) ![]string {
	if body.contains('"token"') {
		doc := json2.decode[TokenDoc](body)!
		mut out := []string{}
		for role in doc.token.roles {
			if role.name.len > 0 {
				out << role.name
			}
		}
		return out
	}
	doc := json2.decode[EC2Doc](body)!
	if doc.access.len == 0 {
		return error('keystone document has no roles')
	}
	return doc.roles
}

pub fn policies(found []string, mapping map[string]string) []string {
	mut out := []string{}
	for role in found {
		name := mapping[role] or { continue }
		if name.len > 0 && name !in out {
			out << name
		}
	}
	return out
}

pub fn fetch_roles(url string, token string) ![]string {
	mut header := http.new_header()
	header.add_custom('x-subject-token', token)!
	header.add_custom('x-auth-token', token)!
	resp := http.fetch(
		method: .get
		url:    url
		header: header
	)!
	if resp.status_code >= 300 {
		return error('keystone status ${resp.status_code}')
	}
	return roles(resp.body)
}
