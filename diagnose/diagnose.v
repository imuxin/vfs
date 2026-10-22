// diagnose matches log lines against known failure patterns. It does not start
// the server; an operator points it at a log and gets the rule that explains
// the line.
module diagnose

pub struct Rule {
pub:
	name    string
	pattern string
	meaning string
}

pub struct Hit {
pub:
	rule Rule
	line string
}

pub fn rules() []Rule {
	return [
		Rule{
			name:    'write-quorum'
			pattern: 'write quorum not met'
			meaning: 'Fewer drives accepted the write than the erasure set requires. Check disk space and that every volume path is mounted.'
		},
		Rule{
			name:    'read-quorum'
			pattern: 'read quorum not met'
			meaning: 'Too few drives answered a read. The object can be rebuilt only while at least half the set responds and the parity budget holds.'
		},
		Rule{
			name:    'bitrot'
			pattern: 'bitrot mismatch'
			meaning: 'A shard hash did not match its bytes. The drive is corrupt or the bitrot algorithm on the object is not the one this process uses.'
		},
		Rule{
			name:    'format'
			pattern: 'format.json does not match'
			meaning: 'A volume was formatted for a different set. Do not mix drives from two deployments.'
		},
		Rule{
			name:    'quota'
			pattern: 'quota exceeded'
			meaning: 'The bucket hard quota refused the write. Raise the quota or delete objects.'
		},
		Rule{
			name:    'checksum'
			pattern: 'checksum mismatch'
			meaning: 'The stored S3 checksum does not match the bytes read back. Treat the object as damaged.'
		},
		Rule{
			name:    'sse'
			pattern: 'SSE-S3 requires a key backend'
			meaning: 'An encrypted object was read without VFS_MASTER_KEY or a KMS. The process that wrote it had a master key this one does not.'
		},
	]
}

// scan returns every rule that matches a line. A line may hit more than one
// rule; callers print them in rule order.
pub fn scan(text string) []Hit {
	mut hits := []Hit{}
	for line in text.split_into_lines() {
		for rule in rules() {
			if line.contains(rule.pattern) {
				hits << Hit{
					rule: rule
					line: line
				}
			}
		}
	}
	return hits
}
