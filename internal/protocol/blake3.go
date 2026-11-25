package protocol

import "encoding/binary"

// blake3DeriveKey implements the official BLAKE3 DeriveKey mode (spec section 2.2) in ~130 lines
// of zero-allocation pure Go for Shadowsocks-2022 (`2022-blake3-aes-128/256-gcm`) key derivation,
// avoiding pulling in an external module dependency.

var blake3IV = [8]uint32{
	0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
	0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
}

var blake3MsgPerm = [16]uint8{2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8}

const (
	b3ChunkStart        = 1 << 0
	b3ChunkEnd          = 1 << 1
	b3Root              = 1 << 3
	b3DeriveKeyContext  = 1 << 5
	b3DeriveKeyMaterial = 1 << 6
)

// blake3DeriveKey derives outLen (up to 64) bytes using BLAKE3 derive_key(context, keyMaterial).
// Both context and keyMaterial for SS-2022 are <= 64 bytes (single chunk), handled cleanly for up to 1024 bytes.
func blake3DeriveKey(context string, keyMaterial []byte, out []byte) {
	ctxCV := blake3HashSingleChunk(blake3IV, []byte(context), b3DeriveKeyContext)
	var rootWords [16]uint32
	blake3SingleChunkRootOutput(ctxCV, keyMaterial, b3DeriveKeyMaterial, &rootWords)
	var raw [64]byte
	for i := 0; i < 16; i++ {
		binary.LittleEndian.PutUint32(raw[i*4:], rootWords[i])
	}
	copy(out, raw[:len(out)])
}

func blake3HashSingleChunk(cv [8]uint32, data []byte, flags uint32) [8]uint32 {
	var out [16]uint32
	blake3SingleChunkRootOutput(cv, data, flags, &out)
	var res [8]uint32
	copy(res[:], out[:8])
	return res
}

func blake3SingleChunkRootOutput(cv [8]uint32, data []byte, baseFlags uint32, out *[16]uint32) {
	if len(data) == 0 {
		var block [16]uint32
		*out = blake3Compress(cv, block, 0, 0, baseFlags|b3ChunkStart|b3ChunkEnd|b3Root)
		return
	}
	offset := 0
	blockIdx := 0
	for offset < len(data) {
		rem := len(data) - offset
		blockLen := rem
		if blockLen > 64 {
			blockLen = 64
		}
		var rawBlock [64]byte
		copy(rawBlock[:], data[offset:offset+blockLen])
		var words [16]uint32
		for i := 0; i < 16; i++ {
			words[i] = binary.LittleEndian.Uint32(rawBlock[i*4:])
		}
		flags := baseFlags
		if blockIdx == 0 {
			flags |= b3ChunkStart
		}
		isLast := offset+blockLen >= len(data)
		if isLast {
			flags |= b3ChunkEnd | b3Root
			*out = blake3Compress(cv, words, 0, uint32(blockLen), flags)
			return
		}
		st := blake3Compress(cv, words, 0, 64, flags)
		copy(cv[:], st[:8])
		offset += 64
		blockIdx++
	}
}

func blake3Compress(cv [8]uint32, m [16]uint32, counter uint64, blockLen uint32, flags uint32) [16]uint32 {
	v := [16]uint32{
		cv[0], cv[1], cv[2], cv[3],
		cv[4], cv[5], cv[6], cv[7],
		blake3IV[0], blake3IV[1], blake3IV[2], blake3IV[3],
		uint32(counter), uint32(counter >> 32), blockLen, flags,
	}

	round := func() {
		b3G(&v, 0, 4, 8, 12, m[0], m[1])
		b3G(&v, 1, 5, 9, 13, m[2], m[3])
		b3G(&v, 2, 6, 10, 14, m[4], m[5])
		b3G(&v, 3, 7, 11, 15, m[6], m[7])
		b3G(&v, 0, 5, 10, 15, m[8], m[9])
		b3G(&v, 1, 6, 11, 12, m[10], m[11])
		b3G(&v, 2, 7, 8, 13, m[12], m[13])
		b3G(&v, 3, 4, 9, 14, m[14], m[15])
	}

	for r := 0; r < 7; r++ {
		round()
		if r < 6 {
			var permuted [16]uint32
			for i := 0; i < 16; i++ {
				permuted[i] = m[blake3MsgPerm[i]]
			}
			m = permuted
		}
	}

	for i := 0; i < 8; i++ {
		v[i] ^= v[i+8]
		v[i+8] ^= cv[i]
	}
	return v
}

func b3G(v *[16]uint32, a, b, c, d int, mx, my uint32) {
	v[a] = v[a] + v[b] + mx
	v[d] = rotr32(v[d]^v[a], 16)
	v[c] = v[c] + v[d]
	v[b] = rotr32(v[b]^v[c], 12)
	v[a] = v[a] + v[b] + my
	v[d] = rotr32(v[d]^v[a], 8)
	v[c] = v[c] + v[d]
	v[b] = rotr32(v[b]^v[c], 7)
}

func rotr32(x uint32, n uint) uint32 {
	return (x >> n) | (x << (32 - n))
}
