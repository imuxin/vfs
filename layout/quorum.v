// quorum is how many drives a write or a read must hear from. It is a property
// of the erasure geometry, not of a particular request, so the store asks
// rather than re-deriving the rule at each call.
module layout

import erasure

// write_quorum is the number of drives that must accept a write. No parity, or
// parity that covers every drive, requires every drive. Otherwise it is the
// data-drive count, plus one when that count equals the parity count.
pub fn write_quorum(total int, parity int) int {
	if total <= 0 {
		return 0
	}
	if parity <= 0 || parity >= total {
		return total
	}
	data := total - parity
	if data == parity {
		return data + 1
	}
	return data
}

// response_quorum is how many drives must answer before a read is attempted.
// It is half the set, rounding down, and at least one.
pub fn response_quorum(total int) int {
	if total <= 0 {
		return 0
	}
	half := total / 2
	if half == 0 {
		return 1
	}
	return half
}

// plan is the erasure geometry for a set, including reduced redundancy. A
// reduced class on more than one drive keeps a single parity shard.
pub fn plan(drives int, storage_class string) !erasure.Layout {
	base := erasure.plan(drives)!
	if storage_class == 'REDUCED_REDUNDANCY' && drives > 1 {
		return erasure.Layout{
			data_shards:   drives - 1
			parity_shards: 1
		}
	}
	return base
}

// storage_class_ok accepts the two classes this process can store. Anything
// else, including the cold classes, is refused at write time.
pub fn storage_class_ok(class string) ! {
	if class.len == 0 || class == 'STANDARD' || class == 'REDUCED_REDUNDANCY' {
		return
	}
	return error('unsupported storage class: ${class}')
}

// effective_class is what a read reports. A lifecycle tier name is kept. Any
// other stored label is standard, except reduced redundancy, which really did
// change the parity.
pub fn effective_class(stored string, tier string) string {
	if tier.len > 0 {
		return tier
	}
	if stored == 'REDUCED_REDUNDANCY' {
		return stored
	}
	return 'STANDARD'
}
