module auth

fn test_sigv2_sign_is_stable() {
	first := sigv2_sign('secret', 'GET\n\n\n1700000000\n/pics/a.txt')
	second := sigv2_sign('secret', 'GET\n\n\n1700000000\n/pics/a.txt')
	assert first == second
	assert first.len > 0
	assert sigv2_sign('secret', 'GET\n\n\n1700000000\n/pics/b.txt') != first
}
