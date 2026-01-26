package simpira1024

import (
	"encoding/binary"

	"github.com/codahale/newplex/internal/aesni"
)

const b = 8

func fFunction(x [16]byte, c uint32) [16]byte {
	var constant [16]byte
	xb := c ^ b
	for j := range uint32(4) {
		binary.LittleEndian.PutUint32(constant[j*4:], xb^(j<<4))
	}

	x = aesni.AESENC(x, constant)
	x = aesni.AESENC(x, [16]byte{}) // XOR 0
	return x
}

func permuteGeneric(state *[Width]byte) {
	c := uint32(1)
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

		f1 := fFunction(blocks[src1], c)
		c++
		f2 := fFunction(blocks[src2], c)
		c++
		f3 := fFunction(blocks[src3], c)
		c++
		f4 := fFunction(blocks[src4], c)
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
