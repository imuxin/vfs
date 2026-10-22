// condition evaluates the IAM condition operators a request can be tested
// against. The set is the one the inventory names: string, numeric, date,
// bool, null, IP address, and binary, each with ForAllValues, ForAnyValue,
// and IfExists. aws:MultiFactorAuthPresent is deliberately not a working
// condition; a policy that names it does not match.
module iam

pub struct Condition {
pub:
	operator string
	key      string
	values   []string
}

fn (s Statement) conditions_hold(ctx map[string][]string) bool {
	for condition in s.conditions {
		if !condition.holds(ctx) {
			return false
		}
	}
	return true
}

fn (c Condition) holds(ctx map[string][]string) bool {
	if c.key == 'aws:MultiFactorAuthPresent' || c.operator.contains('MultiFactorAuth') {
		return false
	}
	quantifier, name, if_exists := split_operator(c.operator)
	present := c.key in ctx && ctx[c.key].len > 0
	if !present {
		if name == 'Null' {
			return null_check(c.values, false)
		}
		return if_exists
	}
	got := ctx[c.key]
	return match quantifier {
		'ForAllValues' { got.all(it_matches(name, it, c.values)) }
		'ForAnyValue' { got.any(it_matches(name, it, c.values)) }
		else { got.any(it_matches(name, it, c.values)) }
	}
}

fn split_operator(raw string) (string, string, bool) {
	mut quantifier := ''
	mut name := raw
	if raw.starts_with('ForAllValues:') {
		quantifier = 'ForAllValues'
		name = raw.all_after('ForAllValues:')
	} else if raw.starts_with('ForAnyValue:') {
		quantifier = 'ForAnyValue'
		name = raw.all_after('ForAnyValue:')
	}
	if_exists := name.ends_with('IfExists')
	if if_exists {
		name = name.trim_string_right('IfExists')
	}
	return quantifier, name, if_exists
}

fn it_matches(name string, value string, expected []string) bool {
	return match name {
		'StringEquals' { expected.any(it == value) }
		'StringLike' { expected.any(wildcard(it, value)) }
		'NumericEquals', 'NumericLessThan', 'NumericGreaterThan', 'NumericLessThanEquals',
		'NumericGreaterThanEquals' {
			numeric(name, value, expected)
		}
		'DateEquals', 'DateLessThan', 'DateGreaterThan', 'DateLessThanEquals', 'DateGreaterThanEquals' {
			numeric(name.replace('Date', 'Numeric'), value, expected)
		}
		'Bool' { expected.any(it.to_lower() == value.to_lower()) }
		'Null' { null_check(expected, true) }
		'IpAddress' { expected.any(cidr_contains(it, value)) }
		'BinaryEquals' { expected.any(it == value) }
		else { false }
	}
}

fn null_check(expected []string, present bool) bool {
	want_absent := expected.any(it.to_lower() == 'true')
	return want_absent != present
}

fn numeric(name string, value string, expected []string) bool {
	got := value.f64()
	for want_text in expected {
		want := want_text.f64()
		ok := match name {
			'NumericEquals' { got == want }
			'NumericLessThan' { got < want }
			'NumericGreaterThan' { got > want }
			'NumericLessThanEquals' { got <= want }
			'NumericGreaterThanEquals' { got >= want }
			else { false }
		}
		if ok {
			return true
		}
	}
	return false
}

// cidr_contains matches an IPv4 address against a.b.c.d or a.b.c.d/nn.
fn cidr_contains(cidr string, ip string) bool {
	network, bits := cidr_parts(cidr)
	addr := ipv4(ip) or { return false }
	base := ipv4(network) or { return false }
	if bits == 0 {
		return true
	}
	shift := 32 - bits
	return (addr >> shift) == (base >> shift)
}

fn cidr_parts(cidr string) (string, int) {
	if !cidr.contains('/') {
		return cidr, 32
	}
	parts := cidr.split('/')
	return parts[0], parts[1].int()
}

fn ipv4(text string) ?u32 {
	parts := text.split('.')
	if parts.len != 4 {
		return none
	}
	mut out := u32(0)
	for part in parts {
		n := part.int()
		if n < 0 || n > 255 || (part != '0' && part.starts_with('0')) {
			return none
		}
		out = (out << 8) | u32(n)
	}
	return out
}
