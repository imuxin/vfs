module store

import os
import meta
import tier

fn fresh_volume() !Volume {
	base := os.join_path(os.temp_dir(), 'vfs-bg-${os.getpid()}')
	os.rmdir_all(base) or {}
	mut dirs := []string{}
	for index in 0 .. 2 {
		dirs << os.join_path(base, 'd${index}')
	}
	return open(dirs)
}

fn test_scrub_rewrites_a_corrupt_shard() {
	volume := fresh_volume()!
	defer { os.rmdir_all(os.dir(volume.drives[0].root())) or {} }
	volume.make_bucket('pics')!
	body := 'heal me'.bytes()
	volume.put(PutRequest{
		bucket: 'pics'
		key:    'a.txt'
		data:   body
	})!
	shard := os.join_path(volume.drives[0].root(), 'pics', 'a.txt', 'versions')
	ids := os.ls(shard)!
	os.write_file_array(os.join_path(shard, ids[0], 'shard'), []u8{len: 8, init: 1})!
	rewritten := volume.scrub('pics', 'a.txt')!
	assert rewritten >= 1
	assert volume.get('pics', 'a.txt', []u8{})! == body
}

fn test_unreadable_object_stays_on_the_heal_queue() {
	volume := fresh_volume()!
	defer { os.rmdir_all(os.dir(volume.drives[0].root())) or {} }
	volume.make_bucket('pics')!
	volume.put(PutRequest{
		bucket: 'pics'
		key:    'a.txt'
		data:   'gone'.bytes()
	})!
	for drive in volume.drives {
		versions := os.join_path(drive.root(), 'pics', 'a.txt', 'versions')
		for id in os.ls(versions)! {
			os.rm(os.join_path(versions, id, 'shard')) or {}
		}
	}
	volume.heal_object('pics', 'a.txt') or {}
	assert volume.heal_backlog() == 1
	restored := volume.resume_heal()!
	assert restored == 0
	assert volume.heal_backlog() == 1
}

fn test_resume_heal_restores_a_queued_shard() {
	volume := fresh_volume()!
	defer { os.rmdir_all(os.dir(volume.drives[0].root())) or {} }
	volume.make_bucket('pics')!
	body := 'back'.bytes()
	volume.put(PutRequest{
		bucket: 'pics'
		key:    'a.txt'
		data:   body
	})!
	versions := os.join_path(volume.drives[0].root(), 'pics', 'a.txt', 'versions')
	ids := os.ls(versions)!
	os.rm(os.join_path(versions, ids[0], 'shard'))!
	volume.remember_heal('pics', 'a.txt')!
	restored := volume.resume_heal()!
	assert restored >= 1
	assert volume.heal_backlog() == 0
	assert volume.get('pics', 'a.txt', []u8{})! == body
}

fn test_clear_delete_marker_drops_the_marker() {
	volume := fresh_volume()!
	defer { os.rmdir_all(os.dir(volume.drives[0].root())) or {} }
	volume.make_bucket('pics')!
	volume.put_bucket_config('pics', meta.BucketConfig{
		versioning: 'Enabled'
	})!
	volume.put(PutRequest{
		bucket: 'pics'
		key:    'a.txt'
		data:   'one'.bytes()
	})!
	volume.delete('pics', 'a.txt')!
	assert volume.stat('pics', 'a.txt')!.delete_marker
	assert volume.clear_delete_marker('pics', 'a.txt')!
	assert !volume.stat('pics', 'a.txt')!.delete_marker
	assert volume.get('pics', 'a.txt', []u8{})! == 'one'.bytes()
}

fn test_missing_format_is_restored_from_a_sibling() {
	volume := fresh_volume()!
	defer { os.rmdir_all(os.dir(volume.drives[0].root())) or {} }
	format_path := os.join_path(volume.drives[0].root(), '.vfs.sys', 'format.json')
	os.rm(format_path)!
	again := open([volume.drives[0].root(), volume.drives[1].root()])!
	assert os.exists(format_path)
	assert again.drives.len == 2
}

fn test_unclean_boot_requests_heal_until_a_clean_stop() {
	volume := fresh_volume()!
	root := os.dir(volume.drives[0].root())
	defer { os.rmdir_all(root) or {} }
	assert !volume.unclean_pending()
	again := open([volume.drives[0].root(), volume.drives[1].root()])!
	assert again.unclean_pending()
	again.mark_clean()!
	again.clear_heal_pending()!
	third := open([volume.drives[0].root(), volume.drives[1].root()])!
	assert !third.unclean_pending()
}

fn test_usage_and_modules_and_migration() {
	volume := fresh_volume()!
	defer { os.rmdir_all(os.dir(volume.drives[0].root())) or {} }
	volume.make_bucket('pics')!
	volume.put(PutRequest{
		bucket: 'pics'
		key:    'a.txt'
		data:   'heal me'.bytes()
	})!
	os.unsetenv('VFS_HEAL_ENABLED')
	report := volume.refresh_usage()!
	assert report.contains('"bytes":7')
	assert volume.usage_report().contains('"objects":1')
	volume.set_module('heal', false)!
	assert !volume.module_on('heal')
	volume.set_module('heal', true)!
	assert volume.module_on('heal')
	volume.put_tier(tier.Remote{
		name: 'warm'
		kind: 's3'
	})!
	queued := volume.enqueue_migrate('pics', 'a.txt', 'warm')!
	assert queued == 1
	done := volume.drain_migrate()!
	assert done == 1
	assert volume.stat('pics', 'a.txt')!.archived
	volume.get('pics', 'a.txt', []u8{}) or {
		assert '${err}'.contains('archived')
		return
	}
	assert false
}
