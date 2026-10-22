module bucketcfg

fn test_policy_deny_wins_and_public_is_star() {
	policy := Policy{
		statements: [
			Statement{
				effect:    'Allow'
				principal: ['*']
				action:    ['s3:GetObject']
				resource:  ['arn:aws:s3:::photos/*']
			},
			Statement{
				effect:    'Deny'
				principal: ['*']
				action:    ['s3:GetObject']
				resource:  ['arn:aws:s3:::photos/secret/*']
			},
		]
	}
	assert allows(policy, '*', 's3:GetObject', 'arn:aws:s3:::photos/cat.jpg')
	assert !allows(policy, '*', 's3:GetObject', 'arn:aws:s3:::photos/secret/a')
	assert is_public(policy)
	assert effect(policy, '*', 's3:GetObject', 'arn:aws:s3:::photos/secret/a') == 'deny'
	rule := cors_match([
		CorsRule{
			origins: ['https://app.example']
			methods: ['GET', 'PUT']
			headers: ['authorization']
		},
	], 'https://app.example', 'PUT') or { panic('cors') }
	assert rule.headers == ['authorization']
	assert website_key(Website{ index: 'index.html', host: 'site.example' }, 'site.example', '')? == 'index.html'
	if _ := website_key(Website{ index: 'index.html', host: 'site.example' }, 'api.example', '') {
		assert false
	}
	if _ := cors_match([
		CorsRule{
			origins: ['https://app.example']
			methods: ['GET']
		},
	], 'https://other.example', 'GET') {
		assert false
	}
	again := decode[Policy](encode[Policy](policy))!
	assert again.statements.len == 2
}
