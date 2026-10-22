// heal rewrites the shards a read can already rebuild. The read path tolerates
// a missing drive; heal is what puts the bytes back so the next failure still
// has parity to spend.
module store

import os
import bitrot
import erasure

pub fn (v Volume) repair(bucket_name string, key string) !int {
	version := v.current(bucket_name, key)!
	record := v.read_record(bucket_name, key, version)!
	if record.delete_marker {
		return 0
	}
	stored_len := if record.stored_size > 0 { record.stored_size } else { record.size }
	stored := v.read_shards(bucket_name, key, version, stored_len, record)!
	geometry := v.geometry_of(record.storage_class)!
	shards := erasure.encode(geometry, stored)!
	algo := bitrot.parse(record.bitrot)!
	width := geometry.total()
	mut restored := 0
	for shard in shards {
		drive_index := (shard.index + record.placement) % width
		path := os.join_path(version_dir(bucket_name, key, version), shard_file)
		if v.drives[drive_index].exists(path) {
			continue
		}
		v.drives[drive_index].write(path, bitrot.frame(algo, shard.data))!
		restored++
	}
	return restored
}
