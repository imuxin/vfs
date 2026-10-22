module iam

// builtin_policies are the named policies a deployment starts with. readwrite is
// what the scenario tests attach to their second user; the others cover the
// common splits of that.
pub fn builtin_policies() map[string]Policy {
	any := ['*']
	read := ['s3:Get*', 's3:List*']
	write := ['s3:Put*', 's3:Delete*', 's3:Abort*']
	return {
		'readwrite':           allow(any)
		'readonly':            allow(read)
		'writeonly':           allow(write)
		'diagnostics':         allow(read)
		'consoleAdmin':        allow(['s3:*', 'admin:*'])
		'KMSKeyAdministrator': allow(['kms:*'])
		'KMSKeyUser':          allow(['kms:Decrypt', 'kms:Encrypt', 'kms:Describe*', 'kms:GenerateDataKey'])
	}
}

fn allow(actions []string) Policy {
	return Policy{
		version:    '2012-10-17'
		statements: [
			Statement{
				effect:   'Allow'
				action:   actions
				resource: ['*']
			},
		]
	}
}

// install_builtin writes the built-in policies a directory does not already
// have, so a deployment can replace one without the next start restoring it.
pub fn install_builtin(directory Directory) ! {
	for name, policy in builtin_policies() {
		if directory.has_policy(name) {
			continue
		}
		directory.put_policy(name, policy)!
	}
}
