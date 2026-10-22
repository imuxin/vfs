module query

fn test_select_filters_and_projects_csv() {
	statement := "SELECT s._2 FROM S3Object s WHERE s._1 = 'keep'"
	parsed := parse(statement)!
	assert parsed.columns == ['_2']
	assert parsed.where_value == 'keep'
	body := 'keep,alpha\ndrop,beta\nkeep,gamma\n'
	assert eval_csv(parsed, body)! == 'alpha\ngamma'
	all := parse('SELECT * FROM S3Object')!
	mut json_query := all
	json_query = Select{
		columns: all.columns
		as_json: true
	}
	assert eval_csv(json_query, 'a,b')!.contains('"_1":"a"')
	lines := '{"_1":"keep","_2":"alpha"}\n{"_1":"drop","_2":"beta"}\n'
	assert eval_json(parsed, lines)! == 'alpha'
}
