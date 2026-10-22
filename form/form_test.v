module form

fn test_parse_reads_key_and_file() {
	body := '--bound\r\nContent-Disposition: form-data; name="key"\r\n\r\nphotos/a.txt\r\n--bound\r\nContent-Disposition: form-data; name="file"; filename="a.txt"\r\nContent-Type: text/plain\r\n\r\nhello\r\n--bound--\r\n'
	got := parse('multipart/form-data; boundary=bound', body.bytes())!
	assert got.key == 'photos/a.txt'
	assert got.filename == 'a.txt'
	assert got.content_type == 'text/plain'
	assert got.body.bytestr() == 'hello'
	kms := '--bound\r\nContent-Disposition: form-data; name="x-amz-server-side-encryption"\r\n\r\naws:kms\r\n--bound\r\nContent-Disposition: form-data; name="key"\r\n\r\nphotos/a.txt\r\n--bound\r\nContent-Disposition: form-data; name="file"; filename="a.txt"\r\n\r\nhello\r\n--bound--\r\n'
	if _ := parse('multipart/form-data; boundary=bound', kms.bytes()) {
		assert false
	}
}
