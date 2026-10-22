module notify

fn test_listen_filter_and_sse() {
	query := Listen{
		events: parse_events('s3:ObjectCreated:*,s3:ObjectRemoved:Delete')
		prefix: 'logs/'
		suffix: '.json'
	}
	kept := Record{
		event:  's3:ObjectCreated:Put'
		bucket: 'pics'
		key:    'logs/a.json'
	}
	assert query.matches(kept)
	assert !query.matches(Record{
		event:  's3:ObjectCreated:Put'
		bucket: 'pics'
		key:    'logs/a.txt'
	})
	assert !query.matches(Record{
		event:  's3:ObjectRemoved:DeleteMarkerCreated'
		bucket: 'pics'
		key:    'logs/a.json'
	})
	body := sse([kept])
	assert body.starts_with('data: ')
	assert body.contains('"eventName":"s3:ObjectCreated:Put"')
	assert body.ends_with('\n\n')
}
