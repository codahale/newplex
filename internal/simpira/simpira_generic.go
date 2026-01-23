package simpira

import (
	"encoding/binary"
)

// sbox is the AES S-box.
var sbox = [256]byte{ //nolint:gochecknoglobals // too big to initialize dynamically
	0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
	0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
	0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
	0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
	0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
	0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
	0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
	0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
	0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
	0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
	0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
	0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
	0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
	0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
	0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
	0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
}

func subBytes(state *[16]byte) {
	for i := range 16 {
		state[i] = sbox[state[i]]
	}
}

func shiftRows(state *[16]byte) {
	s := *state
	state[1], state[5], state[9], state[13] = s[5], s[9], s[13], s[1]
	state[2], state[6], state[10], state[14] = s[10], s[14], s[2], s[6]
	state[3], state[7], state[11], state[15] = s[15], s[3], s[7], s[11]
}

func mul2(b byte) byte {
	if b&0x80 != 0 {
		return (b << 1) ^ 0x1b
	}
	return b << 1
}

func mixColumns(state *[16]byte) {
	for i := range 4 {
		s0, s1, s2, s3 := state[i*4], state[i*4+1], state[i*4+2], state[i*4+3]
		state[i*4] = mul2(s0) ^ (mul2(s1) ^ s1) ^ s2 ^ s3
		state[i*4+1] = s0 ^ mul2(s1) ^ (mul2(s2) ^ s2) ^ s3
		state[i*4+2] = s0 ^ s1 ^ mul2(s2) ^ (mul2(s3) ^ s3)
		state[i*4+3] = (mul2(s0) ^ s0) ^ s1 ^ s2 ^ mul2(s3)
	}
}

func aesEnc(state, key [16]byte) [16]byte {
	subBytes(&state)
	shiftRows(&state)
	mixColumns(&state)
	for i := range 16 {
		state[i] ^= key[i]
	}
	return state
}

func fFunction(x [16]byte, c, b uint32) [16]byte {
	var constant [16]byte
	xb := c ^ b
	for j := range uint32(4) {
		binary.LittleEndian.PutUint32(constant[j*4:], xb^(j<<4))
	}

	x = aesEnc(x, constant)
	x = aesEnc(x, [16]byte{}) // XOR 0
	return x
}

func permute256Generic(state *[32]byte) {
	c := uint32(1)
	b := uint32(2)
	// We need to work with 128-bit (16-byte) blocks.
	// Since state is *[32]byte, block 0 is state[0:16], block 1 is state[16:32].
	// However, we need to copy to [16]byte to pass to fFunction (which returns [16]byte)
	// and then XOR back. To avoid excessive copying, let's just use a helper or slice.
	// fFunction takes [16]byte (value).

	var block0, block1 [16]byte
	copy(block0[:], state[0:16])
	copy(block1[:], state[16:32])

	for r := range 15 {
		if r%2 == 0 {
			f := fFunction(block0, c, b)
			for i := range 16 {
				block1[i] ^= f[i]
			}
		} else {
			f := fFunction(block1, c, b)
			for i := range 16 {
				block0[i] ^= f[i]
			}
		}
		c++
	}
	copy(state[0:16], block0[:])
	copy(state[16:32], block1[:])
}

func permute512Generic(state *[64]byte) {
	c := uint32(1)
	b := uint32(4)

	var blocks [4][16]byte
	for i := range 4 {
		copy(blocks[i][:], state[i*16:(i+1)*16])
	}

	for r := range 15 {
		// Round r uses subblocks x_{r%4} and x_{(r+2)%4}
		// and modifies x_{(r+1)%4} and x_{(r+3)%4}

		idx0 := r % 4
		idx1 := (r + 1) % 4
		idx2 := (r + 2) % 4
		idx3 := (r + 3) % 4

		f1 := fFunction(blocks[idx0], c, b)
		c++
		for i := range 16 {
			blocks[idx1][i] ^= f1[i]
		}

		f2 := fFunction(blocks[idx2], c, b)
		c++
		for i := range 16 {
			blocks[idx3][i] ^= f2[i]
		}
	}

	for i := range 4 {
		copy(state[i*16:(i+1)*16], blocks[i][:])
	}
}

func permute784Generic(state *[96]byte) {
	c := uint32(1)
	b := uint32(6)
	s := [6]int{0, 1, 2, 5, 4, 3}

	var blocks [6][16]byte
	for i := range 6 {
		copy(blocks[i][:], state[i*16:(i+1)*16])
	}

	for r := range 15 {
		// Three F-functions per round
		src1 := s[r%6]
		dst1 := s[(r+1)%6]

		src2 := s[(r+2)%6]
		dst2 := s[(r+5)%6]

		src3 := s[(r+4)%6]
		dst3 := s[(r+3)%6]

		f1 := fFunction(blocks[src1], c, b)
		c++
		f2 := fFunction(blocks[src2], c, b)
		c++
		f3 := fFunction(blocks[src3], c, b)
		c++

		for i := range 16 {
			blocks[dst1][i] ^= f1[i]
			blocks[dst2][i] ^= f2[i]
			blocks[dst3][i] ^= f3[i]
		}
	}

	for i := range 6 {
		copy(state[i*16:(i+1)*16], blocks[i][:])
	}
}

func permute1024Generic(state *[128]byte) {
	c := uint32(1)
	b := uint32(8)
	s := [6]int{0, 1, 6, 5, 4, 3}
	t := [2]int{2, 7}

	var blocks [8][16]byte
	for i := range 8 {
		copy(blocks[i][:], state[i*16:(i+1)*16])
	}

	for r := range 18 {
		// Four F-functions per round
		src1 := s[r%6]
		dst1 := s[(r+1)%6]

		src2 := t[r%2]
		dst2 := s[(r+5)%6]

		src3 := s[(r+4)%6]
		dst3 := s[(r+3)%6]

		src4 := s[(r+2)%6]
		dst4 := t[(r+1)%2]

		f1 := fFunction(blocks[src1], c, b)
		c++
		f2 := fFunction(blocks[src2], c, b)
		c++
		f3 := fFunction(blocks[src3], c, b)
		c++
		f4 := fFunction(blocks[src4], c, b)
		c++

		for i := range 16 {
			blocks[dst1][i] ^= f1[i]
			blocks[dst2][i] ^= f2[i]
			blocks[dst3][i] ^= f3[i]
			blocks[dst4][i] ^= f4[i]
		}
	}

	for i := range 8 {
		copy(state[i*16:(i+1)*16], blocks[i][:])
	}
}
