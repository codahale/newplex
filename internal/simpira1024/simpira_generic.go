package simpira1024

import (
	"encoding/binary"
)

// fCB is an implementation of Algorithm 2 from the Simpira V2 paper.
func fCB(x [16]byte, c uint32) [16]byte {
	// SETR_EPI32(0x00 ⊕ c ⊕ b, 0x10 ⊕ c ⊕ b, 0x20 ⊕ c ⊕ b, 0x30 ⊕ c ⊕ b)
	const b = 8
	var constant [16]byte
	binary.LittleEndian.PutUint32(constant[0:4], 0x00^b^c)
	binary.LittleEndian.PutUint32(constant[4:8], 0x10^b^c)
	binary.LittleEndian.PutUint32(constant[8:12], 0x20^b^c)
	binary.LittleEndian.PutUint32(constant[12:16], 0x30^b^c)

	x = aesEnc(x, constant)
	x = aesEnc(x, [16]byte{}) // XOR 0
	return x
}

// permuteGeneric is an implementation of Algorithm 9 from the Simpira V2 paper.
func permuteGeneric(state *[Width]byte) {
	const R = 18 //nolint:gocritic // for clarity
	c := uint32(1)
	s := [6]int{0, 1, 6, 5, 4, 3}
	t := [2]int{2, 7}

	var blocks [8][16]byte
	for i := range 8 {
		copy(blocks[i][:], state[i*16:(i+1)*16])
	}

	for r := range R {
		// Four F-functions per round
		src1 := s[r%6]
		dst1 := s[(r+1)%6]

		src2 := t[r%2]
		dst2 := s[(r+5)%6]

		src3 := s[(r+4)%6]
		dst3 := s[(r+3)%6]

		src4 := s[(r+2)%6]
		dst4 := t[(r+1)%2]

		f1 := fCB(blocks[src1], c)
		c++
		f2 := fCB(blocks[src2], c)
		c++
		f3 := fCB(blocks[src3], c)
		c++
		f4 := fCB(blocks[src4], c)
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
