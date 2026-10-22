module iam

fn test_conditions_cover_the_operator_families() {
	ctx := {
		'aws:username':        ['ada']
		's3:max-keys':         ['10']
		'aws:CurrentTime':     ['1000']
		's3:TlsVersion':       ['1.2']
		'aws:SecureTransport': ['true']
		'aws:SourceIp':        ['10.1.2.3']
		's3:object-lock':      ['']
	}
	assert (Condition{
		operator: 'StringEquals'
		key:      'aws:username'
		values:   ['ada']
	}).holds(ctx)
	assert (Condition{
		operator: 'StringEqualsIfExists'
		key:      'aws:missing'
		values:   ['x']
	}).holds(ctx)
	assert !(Condition{
		operator: 'StringEquals'
		key:      'aws:missing'
		values:   ['x']
	}).holds(ctx)
	assert (Condition{
		operator: 'ForAllValues:StringEquals'
		key:      'aws:username'
		values:   ['ada', 'bea']
	}).holds(ctx)
	assert (Condition{
		operator: 'NumericLessThanEquals'
		key:      's3:max-keys'
		values:   ['10']
	}).holds(ctx)
	assert (Condition{
		operator: 'DateGreaterThan'
		key:      'aws:CurrentTime'
		values:   ['500']
	}).holds(ctx)
	assert (Condition{
		operator: 'Bool'
		key:      'aws:SecureTransport'
		values:   ['true']
	}).holds(ctx)
	assert (Condition{
		operator: 'Null'
		key:      's3:object-lock'
		values:   ['true']
	}).holds({
		'other': ['1']
	})
	assert (Condition{
		operator: 'IpAddress'
		key:      'aws:SourceIp'
		values:   ['10.1.0.0/16']
	}).holds(ctx)
	assert !(Condition{
		operator: 'StringEquals'
		key:      'aws:MultiFactorAuthPresent'
		values:   ['true']
	}).holds(ctx)
}

fn test_policy_with_a_condition_refuses_the_wrong_caller() {
	policy := Policy{
		statements: [
			Statement{
				effect:   'Allow'
				action:   ['s3:GetObject']
				resource: ['*']
				conditions: [
					Condition{
						operator: 'StringEquals'
						key:      'aws:username'
						values:   ['ada']
					},
				]
			},
		]
	}
	assert !policy.allows('s3:GetObject', 'arn:aws:s3:::b/k')
	assert policy.statements[0].matches_in('s3:GetObject', 'arn:aws:s3:::b/k', {
		'aws:username': ['ada']
	})
}
