// tier moves an object's stored bytes out of the erasure set and back again.
// The hot shards are removed on transition. RestoreObject copies them back for
// a limited number of days; the scanner drops that copy when the window ends.
module store

import json2
import os
import meta
import tier

const tiers_file = '.vfs.sys/tiers.json'

struct TierFile {
	remotes []tier.Remote
}

pub fn (v Volume) put_tier(remote tier.Remote) ! {
	tier.check(remote)!
	doc := v.read_tiers()
	mut remotes := []tier.Remote{}
	mut replaced := false
	for existing in doc.remotes {
		if existing.name == remote.name {
			remotes << remote
			replaced = true
		} else {
			remotes << existing
		}
	}
	if !replaced {
		remotes << remote
	}
	v.write_tiers(TierFile{
		remotes: remotes
	})!
}

pub fn (v Volume) list_tiers() ![]tier.Remote {
	return v.read_tiers().remotes
}

pub fn (v Volume) delete_tier(name string) ! {
	doc := v.read_tiers()
	mut kept := []tier.Remote{}
	for remote in doc.remotes {
		if remote.name != name {
			kept << remote
		}
	}
	v.write_tiers(TierFile{
		remotes: kept
	})!
	v.archive().clear(name)!
}

// transition_version copies one version's stored bytes into the named tier and
// drops the hot shards. A second call is a no-op.
pub fn (v Volume) transition_version(bucket string, key string, version string, tier_name string) ! {
	remote := v.tier_named(tier_name)!
	record := v.read_record(bucket, key, version)!
	if record.delete_marker || record.tier.len > 0 {
		return
	}
	stored_len := if record.stored_size > 0 { record.stored_size } else { record.size }
	stored := v.read_shards(bucket, key, version, stored_len, record)!
	v.archive().put(remote, bucket, tier_object_key(key, version), stored)!
	v.remove_shards(bucket, key, version)!
	v.write_record(bucket, key, version, meta.Object{
		...record
		tier:     tier_name
		archived: true
	})!
	v.drop_object_cache(bucket, key)
}

// restore_object brings an archived version back onto the hot set until
// until_unix. The tier copy stays, so a later lapse can drop the hot shards
// without losing the object.
pub fn (v Volume) restore_object(bucket string, key string, days int, now i64) ! {
	if days <= 0 {
		return error('restore days must be positive')
	}
	version := v.current(bucket, key)!
	record := v.read_record(bucket, key, version)!
	if record.tier.len == 0 {
		return error('object is not archived')
	}
	remote := v.tier_named(record.tier)!
	stored := v.archive().get(remote, bucket, tier_object_key(key, version))!
	v.put_shards(bucket, key, version, stored, record.placement)!
	until := now + i64(days) * 86400
	v.write_record(bucket, key, version, meta.Object{
		...record
		archived:      false
		restore_until: until
	})!
	v.drop_object_cache(bucket, key)
}

fn (v Volume) rearchive(bucket string, key string) ! {
	version := v.current(bucket, key)!
	record := v.read_record(bucket, key, version)!
	if record.tier.len == 0 || record.archived {
		return
	}
	v.remove_shards(bucket, key, version)!
	v.write_record(bucket, key, version, meta.Object{
		...record
		archived:      true
		restore_until: 0
	})!
	v.drop_object_cache(bucket, key)
}

fn (v Volume) tier_named(name string) !tier.Remote {
	for remote in v.read_tiers().remotes {
		if remote.name == name {
			return remote
		}
	}
	return error('tier not found: ${name}')
}

fn (v Volume) archive() tier.Archive {
	return tier.Archive{
		root: os.join_path(v.drives[0].root(), '.vfs.sys', 'tier-data')
	}
}

fn (v Volume) read_tiers() TierFile {
	raw := v.drives[0].read(tiers_file) or { return TierFile{} }
	return json2.decode[TierFile](raw.bytestr()) or { return TierFile{} }
}

fn (v Volume) write_tiers(doc TierFile) ! {
	encoded := json2.encode[TierFile](doc, escape_unicode: true).bytes()
	for drive in v.drives {
		drive.write(tiers_file, encoded)!
	}
}

fn tier_object_key(key string, version string) string {
	return '${version}/${key}'
}

fn (v Volume) remove_shards(bucket string, key string, version string) ! {
	base := os.join_path(version_dir(bucket, key, version), shard_file)
	for drive in v.drives {
		drive.remove(base)!
	}
}
