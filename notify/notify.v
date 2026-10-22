// notify fans a bucket event out to the webhook targets in its configuration.
// A target listens for an event name or a prefix of one, such as
// s3:ObjectCreated:*. Delivery is best effort: a down target does not fail
// the write that produced the event.
module notify

import json2
import net.http

pub struct Target {
pub:
	url     string
	events  []string
	kind    string
	channel string
}

pub struct Config {
pub:
	targets []Target
}

pub struct Event {
pub:
	event  string
	bucket string
	key    string
}

pub fn decode(raw string) !Config {
	return json2.decode[Config](raw)
}

// urls returns the webhook endpoints that asked to hear this event.
pub fn urls(config Config, event string) []string {
	mut out := []string{}
	for target in config.targets {
		kind := if target.kind.len == 0 { 'webhook' } else { target.kind }
		if kind != 'webhook' || target.url.len == 0 {
			continue
		}
		if wants(target.events, event) {
			out << target.url
		}
	}
	return out
}

fn wants(patterns []string, event string) bool {
	if patterns.len == 0 {
		return true
	}
	for pattern in patterns {
		if pattern == event || pattern == '*' {
			return true
		}
		if pattern.ends_with('*') && event.starts_with(pattern.trim_string_right('*')) {
			return true
		}
	}
	return false
}

// send delivers the event to every interested target. An empty kind is a
// webhook. Redis targets publish the same JSON document. Failures are counted
// after every target has been tried.
pub fn send(config Config, event Event) ! {
	mut failed := 0
	payload := json2.encode[Event](event, escape_unicode: true)
	for target in config.targets {
		if !wants(target.events, event.event) {
			continue
		}
		deliver(target, payload) or { failed++ }
	}
	if failed > 0 {
		return error('notification delivery failed for ${failed} target(s)')
	}
}

fn deliver(target Target, payload string) ! {
	kind := if target.kind.len == 0 { 'webhook' } else { target.kind }
	if kind == 'redis' {
		return publish(target.url, target.channel, payload)
	}
	if kind == 'nats' {
		return publish_nats(target.url, target.channel, payload)
	}
	if kind == 'mqtt' {
		return publish_mqtt(target.url, target.channel, payload)
	}
	if kind == 'amqp' {
		return publish_amqp(target.url, target.channel, payload)
	}
	if kind == 'kafka' {
		return publish_kafka(target.url, target.channel, payload)
	}
	if kind == 'postgres' {
		return publish_postgres(target.url, target.channel, payload)
	}
	if kind == 'mysql' {
		return publish_mysql(target.url, target.channel, payload)
	}
	if kind == 'pulsar' {
		return publish_pulsar(target.url, target.channel, payload)
	}
	if kind != 'webhook' {
		return error('unsupported notification target ${kind}')
	}
	if target.url.len == 0 {
		return error('webhook url is required')
	}
	resp := http.post_json(target.url, payload)!
	if resp.status_code >= 300 {
		return error('webhook status ${resp.status_code}')
	}
}
