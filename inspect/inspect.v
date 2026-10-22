// inspect is the offline reading the vfs command line does: a certificate,
// a bucket metadata export, and the connect subcommands that stay on this host.
module inspect

import crypto.x509
import os
import diagnose
import store

pub fn tls_text(pem string) !string {
	cert := x509.parse_pem(pem)!
	names := cert.dns_names.join(',')
	return 'subject: ${cert.common_name()}\nnot_after: ${cert.not_after.unix()}\ndns: ${names}'
}

pub fn bucket_meta(raw string) !string {
	text := raw.trim_space()
	if text.len == 0 || text[0] != `{` {
		return error('bucket meta must be a JSON object')
	}
	mut lines := []string{}
	for name in ['policy', 'cors', 'website', 'encryption', 'lifecycle', 'replication', 'quota',
		'notification', 'publicAccessBlock', 'object-lambda'] {
		if text.contains('"${name}"') {
			lines << name
		}
	}
	if lines.len == 0 {
		return error('bucket meta has no known documents')
	}
	return lines.join('\n')
}

pub fn connect(args []string) !string {
	if args.len == 0 {
		return error('usage: vfs connect <register|license|relay|report|inventory|perf|profile|health|logs|telemetry|top|object>')
	}
	match args[0] {
		'license' {
			return 'license feature is off'
		}
		'telemetry' {
			endpoint := os.getenv('RUSTFS_OBS_ENDPOINT')
			if endpoint.len == 0 {
				return 'telemetry endpoint is unset'
			}
			return 'telemetry endpoint is set'
		}
		'relay' {
			if os.getenv('VFS_RPC_SECRET').len > 0 || os.getenv('RUSTFS_RPC_SECRET').len > 0 {
				return 'rpc secret is configured'
			}
			return 'rpc secret falls back to the root secret'
		}
		'profile' {
			return 'in-process profiling is not part of this build'
		}
		'register' {
			root := need_path(args)!
			id_path := os.join_path(root, '.vfs.sys', 'connect.json')
			os.mkdir_all(os.dir(id_path))!
			if !os.exists(id_path) {
				os.write_file(id_path, '{"registered":true}')!
			}
			return 'registered'
		}
		'health' {
			volume := store.open([need_path(args)!])!
			if !volume.ready() {
				return error('volume is not ready')
			}
			return 'ready'
		}
		'report', 'inventory', 'top' {
			volume := store.open([need_path(args)!])!
			names := volume.list_buckets()!
			return 'buckets: ${names.len}'
		}
		'perf' {
			volume := store.open([need_path(args)!])!
			return volume.speedtest()
		}
		'logs' {
			if args.len < 2 {
				return error('usage: vfs connect logs <file>')
			}
			text := os.read_file(args[1])!
			hits := diagnose.scan(text)
			if hits.len == 0 {
				return 'no known failure pattern'
			}
			return '${hits[0].rule.name}: ${hits[0].rule.meaning}'
		}
		'object' {
			if args.len < 2 {
				return error('usage: vfs connect object <meta.json>')
			}
			raw := os.read_file(args[1])!
			if !raw.contains('"key"') {
				return error('object meta has no key')
			}
			return 'object meta'
		}
		else {
			return error('unknown connect command: ${args[0]}')
		}
	}
}

fn need_path(args []string) !string {
	if args.len < 2 {
		return error('usage: vfs connect ${args[0]} <volume>')
	}
	return args[1]
}
