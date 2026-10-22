// crc64nvme is CRC-64/NVME, the checksum S3 names CRC64NVME. The reflected
// polynomial, the all-ones seed, and the final inversion are the catalogue
// parameters; the check value for "123456789" is part of that catalogue.
module checksum

const nvme_poly = u64(0x9A6C9329AC4BC9B5)

struct NvmeTable {
	row [256]u64
}

fn build_nvme() NvmeTable {
	mut row := [256]u64{}
	for i in 0 .. 256 {
		mut crc := u64(i)
		for _ in 0 .. 8 {
			if crc & 1 != 0 {
				crc = (crc >> 1) ^ nvme_poly
			} else {
				crc >>= 1
			}
		}
		row[i] = crc
	}
	return NvmeTable{
		row: row
	}
}

const nvme_table = build_nvme()

// crc64_nvme returns the CRC-64/NVME of data.
pub fn crc64_nvme(data []u8) u64 {
	mut crc := u64(0xffffffffffffffff)
	for b in data {
		crc = nvme_table.row[u8(crc) ^ b] ^ (crc >> 8)
	}
	return crc ^ u64(0xffffffffffffffff)
}
