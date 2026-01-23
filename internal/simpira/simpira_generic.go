package simpira

import (
	"encoding/binary"

	"github.com/codahale/newplex/internal/aesni"
)

func fFunction(x [16]byte, c, b uint32) [16]byte {
	var constant [16]byte
	xb := c ^ b
	for j := range uint32(4) {
		binary.LittleEndian.PutUint32(constant[j*4:], xb^(j<<4))
	}

	x = aesni.AESEnc(x, constant)
	x = aesni.AESEnc(x, [16]byte{}) // XOR 0
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
