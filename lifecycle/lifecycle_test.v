module lifecycle

fn test_delete_marker_expiry_uses_its_own_clock() {
	config := Config{
		rules: [
			Rule{
				marker_days: 1
				expire_days: 30
			},
		]
	}
	fact := Fact{
		key: 'logs/a'
	}
	assert marker_expired(config, fact, 0, 86400)
	assert !marker_expired(config, fact, 0, 10)
	assert !expired(config, fact, 0, 86400)
	filtered := Config{
		rules: [
			Rule{
				prefix:          'logs/'
				tags:            {
					'env': 'prod'
				}
				min_size:        10
				lock_boundary:   true
				transition_days: 1
				transition_tier: 'WARM'
			},
		]
	}
	small := Fact{
		key:  'logs/a'
		size: 4
		tags: {
			'env': 'prod'
		}
	}
	assert transition_target(filtered, small, 0, 86400).len == 0
	locked := Fact{
		key:    'logs/a'
		size:   20
		locked: true
		tags:   {
			'env': 'prod'
		}
	}
	assert transition_target(filtered, locked, 0, 86400).len == 0
	ready := Fact{
		key:  'logs/a'
		size: 20
		tags: {
			'env': 'prod'
		}
	}
	assert transition_target(filtered, ready, 0, 86400) == 'WARM'
	lapsed := Fact{
		key:           'logs/a'
		tier:          'WARM'
		restore_until: 10
	}
	assert restore_lapsed(lapsed, 10)
	assert !restore_lapsed(lapsed, 9)
}
