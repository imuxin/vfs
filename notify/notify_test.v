module notify

fn test_event_prefix_selects_targets() {
	config := Config{
		targets: [
			Target{
				url:    'http://created.example'
				events: ['s3:ObjectCreated:*']
			},
			Target{
				url:    'http://removed.example'
				events: ['s3:ObjectRemoved:Delete']
			},
		]
	}
	assert urls(config, 's3:ObjectCreated:Put') == ['http://created.example']
	assert urls(config, 's3:ObjectRemoved:Delete') == ['http://removed.example']
	assert urls(config, 's3:ObjectRestore:Post').len == 0
}
