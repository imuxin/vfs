// format is the on-disk format.json. One document is shared by every drive in
// a deployment; each drive records which uuid in the set grid is its own.
module layout

import json2
import rand

pub struct Format {
pub:
	version string
	format  string
	id      string
	xl      Erasure
}

pub struct Erasure {
pub:
	version           string
	this              string
	sets              [][]string
	distribution_algo string @[json: 'distributionAlgo']
}

// fresh builds a format for one pool. `sets` is the drive count of each
// erasure set. The returned document has an empty `this`; the caller stamps
// the uuid of the drive it is about to write.
pub fn fresh(set_widths []int) !Format {
	if set_widths.len == 0 {
		return error('a format needs at least one set')
	}
	mut grid := [][]string{}
	for width in set_widths {
		if width < 1 || width > 16 {
			return error('an erasure set holds 1 to 16 drives')
		}
		mut row := []string{cap: width}
		for _ in 0 .. width {
			row << rand.uuid_v4()
		}
		grid << row
	}
	backend := if set_widths.len == 1 && set_widths[0] == 1 { 'xl-single' } else { 'xl' }
	return Format{
		version: '1'
		format:  backend
		id:      rand.uuid_v4()
		xl:      Erasure{
			version:           '3'
			this:              ''
			sets:              grid
			distribution_algo: 'SIPMOD+PARITY'
		}
	}
}

// for_drive copies the format and records which uuid this drive is.
pub fn (f Format) for_drive(set_index int, drive_index int) !Format {
	id := f.xl.sets[set_index][drive_index]
	return Format{
		version: f.version
		format:  f.format
		id:      f.id
		xl:      Erasure{
			version:           f.xl.version
			this:              id
			sets:              f.xl.sets
			distribution_algo: f.xl.distribution_algo
		}
	}
}

pub fn (f Format) encode() string {
	return json2.encode[Format](f, escape_unicode: true)
}

pub fn decode_format(raw string) !Format {
	parsed := json2.decode[Format](raw)!
	if parsed.version != '1' {
		return error('unsupported format version')
	}
	if parsed.xl.version != '1' && parsed.xl.version != '2' && parsed.xl.version != '3' {
		return error('unsupported erasure format version')
	}
	parse_algo(parsed.xl.distribution_algo)!
	return parsed
}

// same_deployment reports whether two drives belong to one formatted cluster.
// `this` is allowed to differ; everything else is identity.
pub fn (f Format) same_deployment(other Format) bool {
	if f.version != other.version || f.format != other.format || f.id != other.id {
		return false
	}
	if f.xl.version != other.xl.version || f.xl.distribution_algo != other.xl.distribution_algo {
		return false
	}
	if f.xl.sets.len != other.xl.sets.len {
		return false
	}
	for i, row in f.xl.sets {
		if row != other.xl.sets[i] {
			return false
		}
	}
	return true
}
