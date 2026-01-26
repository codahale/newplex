package xoodoo

import (
	"encoding/binary"
	"math/bits"
)

var roundConstants = [12]uint32{ //nolint:gochecknoglobals // these are constants
	0x058, 0x038, 0x3c0, 0x0d0,
	0x120, 0x014, 0x060, 0x02c,
	0x380, 0x0f0, 0x1a0, 0x012,
}

func permuteGeneric(state *[48]byte) {
	var a [12]uint32
	for i := range 12 {
		a[i] = binary.LittleEndian.Uint32(state[i*4 : i*4+4])
	}

	for round := range 12 {
		// Theta
		p0 := a[0] ^ a[4] ^ a[8]
		p1 := a[1] ^ a[5] ^ a[9]
		p2 := a[2] ^ a[6] ^ a[10]
		p3 := a[3] ^ a[7] ^ a[11]

		e0 := bits.RotateLeft32(p3, 5) ^ bits.RotateLeft32(p3, 14)
		e1 := bits.RotateLeft32(p0, 5) ^ bits.RotateLeft32(p0, 14)
		e2 := bits.RotateLeft32(p1, 5) ^ bits.RotateLeft32(p1, 14)
		e3 := bits.RotateLeft32(p2, 5) ^ bits.RotateLeft32(p2, 14)

		a[0] ^= e0
		a[4] ^= e0
		a[8] ^= e0
		a[1] ^= e1
		a[5] ^= e1
		a[9] ^= e1
		a[2] ^= e2
		a[6] ^= e2
		a[10] ^= e2
		a[3] ^= e3
		a[7] ^= e3
		a[11] ^= e3

		// Rho-west
		a[4], a[5], a[6], a[7] = a[7], a[4], a[5], a[6]
		a[8] = bits.RotateLeft32(a[8], 11)
		a[9] = bits.RotateLeft32(a[9], 11)
		a[10] = bits.RotateLeft32(a[10], 11)
		a[11] = bits.RotateLeft32(a[11], 11)

		// Iota
		a[0] ^= roundConstants[round]

		// Chi
		for i := range 4 {
			a0, a1, a2 := a[i], a[i+4], a[i+8]
			a[i] ^= (^a1) & a2
			a[i+4] ^= (^a2) & a0
			a[i+8] ^= (^a0) & a1
		}

		// Rho-east
		a[4] = bits.RotateLeft32(a[4], 1)
		a[5] = bits.RotateLeft32(a[5], 1)
		a[6] = bits.RotateLeft32(a[6], 1)
		a[7] = bits.RotateLeft32(a[7], 1)
		a[8], a[9], a[10], a[11] = bits.RotateLeft32(a[10], 8), bits.RotateLeft32(a[11], 8), bits.RotateLeft32(a[8], 8), bits.RotateLeft32(a[9], 8)
	}

	for i := range 12 {
		binary.LittleEndian.PutUint32(state[i*4:i*4+4], a[i])
	}
}
