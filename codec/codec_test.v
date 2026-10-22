module codec

fn test_lz4_roundtrip_and_literal_block() {
	plain := 'hello hello hello hello hello'.bytes()
	compressed := lz4_compress(plain)
	assert lz4_decompress(compressed)! == plain
	assert lz4_decompress(lz4_compress([]u8{}))! == []u8{}
	long := 'abcdefghijklmnopqrstuvwxyz'.repeat(200).bytes()
	assert lz4_decompress(lz4_compress(long))! == long
}

fn test_framed_codecs_roundtrip() {
	plain := 'the quick brown fox jumps over the lazy dog. '.repeat(40).bytes()
	for algo in [Algo.lz4, Algo.gzip, Algo.deflate, Algo.snappy] {
		framed := frame(algo, plain)!
		assert unframe(algo, framed)! == plain
		got := unframe_range(algo, framed, 4, 10)!
		assert got == plain[4..11]
	}
	assert frame(.none, plain)! == plain
}
