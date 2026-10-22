// service accounts are access keys owned by a user. Their policy, when set,
// is an extra restriction on top of the parent. The parent must already exist.
module iam

pub struct ServiceAccount {
pub:
	access_key string
	secret_key string
	parent     string
	policy     string
	status     string
}

pub fn (d Directory) put_service_account(account ServiceAccount) ! {
	parent := d.user(account.parent)!
	if parent.status == 'Disabled' {
		return error('parent user is disabled')
	}
	mut policies := []string{}
	if account.policy.len > 0 {
		policies << account.policy
	}
	status := if account.status.len > 0 { account.status } else { 'Enabled' }
	d.put_key(AccessKey{
		access_key: account.access_key
		secret_key: account.secret_key
		user:       account.parent
		status:     status
		policies:   policies
	})!
}
