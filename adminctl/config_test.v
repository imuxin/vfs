module adminctl

fn test_config_history_restore_and_service_mode() {
	mut doc := Document{}
	doc = doc.set('region', 'us-east-1', 1)!
	doc = doc.set('region', 'eu-west-1', 2)!
	assert doc.get('region')!.value == 'eu-west-1'
	assert history_of(doc, 'region').len == 2
	doc = doc.restore('region', 3)!
	assert doc.get('region')!.value == 'us-east-1'
	assert help('region').contains('region')
	assert transition('running', 'freeze')! == 'frozen'
	assert transition('frozen', 'unfreeze')! == 'running'
	assert transition('running', 'stop')! == 'stopping'
	if _ := transition('running', 'unfreeze') {
		assert false
	}
}
