module replicate

fn test_backlog_keeps_one_job_per_object() {
	first := Job{
		op:     'put'
		bucket: 'pics'
		key:    'a'
	}
	again := enqueue(enqueue([]Job{}, first), first)
	assert again.len == 1
	left := without(again, first)
	assert left.len == 0
	other := enqueue(again, Job{
		op:     'delete'
		bucket: 'pics'
		key:    'a'
	})
	assert other.len == 2
}
