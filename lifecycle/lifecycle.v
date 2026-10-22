// lifecycle decides what should happen to an object or an unfinished upload.
// It is a pure function of the rules and the timestamps: it reads nothing and
// changes nothing, so the storage layer can apply the decision however it
// stores bytes. A day is 86400 seconds, matching S3's expiry granularity.
module lifecycle

import json2

const day = i64(86400)

// Rule is one lifecycle rule. Zero means that action is not configured.
// min_size and max_size are exclusive bounds, matching ObjectSizeGreaterThan
// and ObjectSizeLessThan. lock_boundary keeps the rule off objects that still
// have a retention or a legal hold.
pub struct Rule {
pub:
	prefix                      string
	expire_days                 int
	noncurrent_days             int
	abort_days                  int
	marker_days                 int
	tags                        map[string]string
	min_size                    i64
	max_size                    i64
	lock_boundary               bool
	transition_days             int
	transition_tier             string
	noncurrent_transition_days  int
}

// Fact is the object a rule is matched against. The scanner fills it from the
// object record; the decision functions do not read storage themselves.
pub struct Fact {
pub:
	key           string
	size          i64
	tags          map[string]string
	locked        bool
	tier          string
	archived      bool
	restore_until i64
}

// Config is the bucket's lifecycle document.
pub struct Config {
pub:
	rules []Rule
}

pub fn (c Config) encode() string {
	return json2.encode[Config](c, escape_unicode: true)
}

pub fn decode(raw string) !Config {
	return json2.decode[Config](raw)
}

// expired reports whether a current version is past its expiry. Age is measured
// from the object's modification time to now, both unix seconds.
pub fn expired(config Config, fact Fact, modified i64, now i64) bool {
	for rule in config.rules {
		if !applies(rule, fact) {
			continue
		}
		if rule.expire_days > 0 && now - modified >= i64(rule.expire_days) * day {
			return true
		}
	}
	return false
}

// noncurrent_expired reports whether an older version has been noncurrent long
// enough. noncurrent_since is when a newer version replaced it.
pub fn noncurrent_expired(config Config, fact Fact, noncurrent_since i64, now i64) bool {
	for rule in config.rules {
		if !applies(rule, fact) {
			continue
		}
		if rule.noncurrent_days > 0 && now - noncurrent_since >= i64(rule.noncurrent_days) * day {
			return true
		}
	}
	return false
}

// marker_expired reports whether a delete marker has been current long enough
// to remove. The clock starts when the marker was written.
pub fn marker_expired(config Config, fact Fact, modified i64, now i64) bool {
	for rule in config.rules {
		if !applies(rule, fact) {
			continue
		}
		if rule.marker_days > 0 && now - modified >= i64(rule.marker_days) * day {
			return true
		}
	}
	return false
}

// abort_upload reports whether an unfinished multipart upload has outlived the
// rule.
pub fn abort_upload(config Config, fact Fact, started i64, now i64) bool {
	for rule in config.rules {
		if !applies(rule, fact) {
			continue
		}
		if rule.abort_days > 0 && now - started >= i64(rule.abort_days) * day {
			return true
		}
	}
	return false
}

// transition_target is the warm tier a current version should move to. An
// object already on a tier stays there.
pub fn transition_target(config Config, fact Fact, modified i64, now i64) string {
	if fact.tier.len > 0 {
		return ''
	}
	for rule in config.rules {
		if !applies(rule, fact) || rule.transition_days <= 0 || rule.transition_tier.len == 0 {
			continue
		}
		if now - modified >= i64(rule.transition_days) * day {
			return rule.transition_tier
		}
	}
	return ''
}

// noncurrent_transition_target is the warm tier an older version should move to.
pub fn noncurrent_transition_target(config Config, fact Fact, noncurrent_since i64, now i64) string {
	if fact.tier.len > 0 {
		return ''
	}
	for rule in config.rules {
		if !applies(rule, fact) || rule.noncurrent_transition_days <= 0 || rule.transition_tier.len == 0 {
			continue
		}
		if now - noncurrent_since >= i64(rule.noncurrent_transition_days) * day {
			return rule.transition_tier
		}
	}
	return ''
}

// restore_lapsed reports that a temporary hot copy of a tiered object has
// passed the expiry chosen by RestoreObject.
pub fn restore_lapsed(fact Fact, now i64) bool {
	return fact.tier.len > 0 && !fact.archived && fact.restore_until > 0 && now >= fact.restore_until
}

fn applies(rule Rule, fact Fact) bool {
	if rule.prefix.len > 0 && !fact.key.starts_with(rule.prefix) {
		return false
	}
	if rule.min_size > 0 && fact.size <= rule.min_size {
		return false
	}
	if rule.max_size > 0 && fact.size >= rule.max_size {
		return false
	}
	if rule.lock_boundary && fact.locked {
		return false
	}
	for name, value in rule.tags {
		got := fact.tags[name] or { '' }
		if got != value {
			return false
		}
	}
	return true
}
