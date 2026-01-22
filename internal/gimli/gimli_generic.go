package gimli

import (
	"encoding/binary"
	"math/bits"
)

func permuteGeneric(state *[48]byte) {
	var s [12]uint32
	for i := range 12 {
		s[i] = binary.LittleEndian.Uint32(state[i*4 : (i+1)*4])
	}

	for round := 24; round > 0; round-- {
		// SP-box applied to each column
		for col := range 4 {
			x := bits.RotateLeft32(s[col], 24)
			y := bits.RotateLeft32(s[4+col], 9)
			z := s[8+col]

			s[8+col] = x ^ (z << 1) ^ ((y & z) << 2)
			s[4+col] = y ^ x ^ ((x | z) << 1)
			s[col] = z ^ y ^ ((x & y) << 3)
		}

		// Linear mixing layer
		if (round & 3) == 0 { // Small swap
			s[0], s[1] = s[1], s[0]
			s[2], s[3] = s[3], s[2]
		}
		if (round & 3) == 2 { // Big swap
			s[0], s[2] = s[2], s[0]
			s[1], s[3] = s[3], s[1]
		}

		// Constant addition
		if (round & 3) == 0 {
			s[0] ^= 0x9e377900 | uint32(round) //nolint:gosec // round is always [1,24]
		}
	}

	for i := range 12 {
		binary.LittleEndian.PutUint32(state[i*4:(i+1)*4], s[i])
	}
}
