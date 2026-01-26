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

	x = aesni.AESENC(x, constant)
	x = aesni.AESENC(x, [16]byte{}) // XOR 0
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

func permute768Generic(state *[96]byte) {
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

func permute1536Generic(state *[192]byte) {
	c := uint32(1)
	b := uint32(12)
	s := [10]int{0, 1, 10, 9, 8, 7, 6, 5, 4, 3}
	t := [2]int{2, 11}

	var blocks [12][16]byte
	for i := range 12 {
		copy(blocks[i][:], state[i*16:(i+1)*16])
	}

	for r := range 24 {
		// Six F-functions per round
		f1 := fFunction(blocks[s[r%10]], c, b)
		c++
		f2 := fFunction(blocks[t[r%2]], c, b)
		c++
		f3 := fFunction(blocks[s[(r+8)%10]], c, b)
		c++
		f4 := fFunction(blocks[s[(r+6)%10]], c, b)
		c++
		f5 := fFunction(blocks[s[(r+4)%10]], c, b)
		c++
		f6 := fFunction(blocks[s[(r+2)%10]], c, b)
		c++

		dst1 := s[(r+1)%10]
		dst2 := s[(r+9)%10]
		dst3 := s[(r+7)%10]
		dst4 := s[(r+5)%10]
		dst5 := s[(r+3)%10]
		dst6 := t[(r+1)%2]

		for i := range 16 {
			blocks[dst1][i] ^= f1[i]
			blocks[dst2][i] ^= f2[i]
			blocks[dst3][i] ^= f3[i]
			blocks[dst4][i] ^= f4[i]
			blocks[dst5][i] ^= f5[i]
			blocks[dst6][i] ^= f6[i]
		}
	}

	for i := range 12 {
		copy(state[i*16:(i+1)*16], blocks[i][:])
	}
}

func permute2048Generic(state *[256]byte) {
	c := uint32(1)
	b := uint32(16)
	s := [14]int{0, 1, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3}
	t := [2]int{2, 15}

	var blocks [16][16]byte
	for i := range 16 {
		copy(blocks[i][:], state[i*16:(i+1)*16])
	}

	for r := range 30 {
		// Eight F-functions per round
		f1 := fFunction(blocks[s[r%14]], c, b)
		c++
		f2 := fFunction(blocks[t[r%2]], c, b)
		c++
		f3 := fFunction(blocks[s[(r+12)%14]], c, b)
		c++
		f4 := fFunction(blocks[s[(r+10)%14]], c, b)
		c++
		f5 := fFunction(blocks[s[(r+8)%14]], c, b)
		c++
		f6 := fFunction(blocks[s[(r+6)%14]], c, b)
		c++
		f7 := fFunction(blocks[s[(r+4)%14]], c, b)
		c++
		f8 := fFunction(blocks[s[(r+2)%14]], c, b)
		c++

		dst1 := s[(r+1)%14]
		dst2 := s[(r+13)%14]
		dst3 := s[(r+11)%14]
		dst4 := s[(r+9)%14]
		dst5 := s[(r+7)%14]
		dst6 := s[(r+5)%14]
		dst7 := s[(r+3)%14]
		dst8 := t[(r+1)%2]

		for i := range 16 {
			blocks[dst1][i] ^= f1[i]
			blocks[dst2][i] ^= f2[i]
			blocks[dst3][i] ^= f3[i]
			blocks[dst4][i] ^= f4[i]
			blocks[dst5][i] ^= f5[i]
			blocks[dst6][i] ^= f6[i]
			blocks[dst7][i] ^= f7[i]
			blocks[dst8][i] ^= f8[i]
		}
	}

	for i := range 16 {
		copy(state[i*16:(i+1)*16], blocks[i][:])
	}
}
