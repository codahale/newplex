package ascon

import (
	"encoding/binary"
	"math/bits"
)

var constants = [12]uint64{ //nolint:gochecknoglobals // round constants
	0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b,
}

func round(x0, x1, x2, x3, x4 *uint64, c uint64) {
	// Addition of constant
	*x2 ^= c

	// Substitution layer
	s0 := *x0
	s1 := *x1
	s2 := *x2
	s3 := *x3
	s4 := *x4

	s0 ^= s4
	s4 ^= s3
	s2 ^= s1

	t0 := ^s0 & s1
	t1 := ^s1 & s2
	t2 := ^s2 & s3
	t3 := ^s3 & s4
	t4 := ^s4 & s0

	s0 ^= t1
	s1 ^= t2
	s2 ^= t3
	s3 ^= t4
	s4 ^= t0

	s1 ^= s0
	s0 ^= s4
	s3 ^= s2
	s2 = ^s2

	*x0 = s0
	*x1 = s1
	*x2 = s2
	*x3 = s3
	*x4 = s4

	// Linear diffusion layer
	*x0 ^= bits.RotateLeft64(*x0, -19) ^ bits.RotateLeft64(*x0, -28)
	*x1 ^= bits.RotateLeft64(*x1, -61) ^ bits.RotateLeft64(*x1, -39)
	*x2 ^= bits.RotateLeft64(*x2, -1) ^ bits.RotateLeft64(*x2, -6)
	*x3 ^= bits.RotateLeft64(*x3, -10) ^ bits.RotateLeft64(*x3, -17)
	*x4 ^= bits.RotateLeft64(*x4, -7) ^ bits.RotateLeft64(*x4, -41)
}

func permuteGeneric8(state *[40]byte) {
	x0 := binary.BigEndian.Uint64(state[0:8])
	x1 := binary.BigEndian.Uint64(state[8:16])
	x2 := binary.BigEndian.Uint64(state[16:24])
	x3 := binary.BigEndian.Uint64(state[24:32])
	x4 := binary.BigEndian.Uint64(state[32:40])

	for i := 4; i < 12; i++ {
		round(&x0, &x1, &x2, &x3, &x4, constants[i])
	}

	binary.BigEndian.PutUint64(state[0:8], x0)
	binary.BigEndian.PutUint64(state[8:16], x1)
	binary.BigEndian.PutUint64(state[16:24], x2)
	binary.BigEndian.PutUint64(state[24:32], x3)
	binary.BigEndian.PutUint64(state[32:40], x4)
}

func permuteGeneric12(state *[40]byte) {
	x0 := binary.BigEndian.Uint64(state[0:8])
	x1 := binary.BigEndian.Uint64(state[8:16])
	x2 := binary.BigEndian.Uint64(state[16:24])
	x3 := binary.BigEndian.Uint64(state[24:32])
	x4 := binary.BigEndian.Uint64(state[32:40])

	for i := range 12 {
		round(&x0, &x1, &x2, &x3, &x4, constants[i])
	}

	binary.BigEndian.PutUint64(state[0:8], x0)
	binary.BigEndian.PutUint64(state[8:16], x1)
	binary.BigEndian.PutUint64(state[16:24], x2)
	binary.BigEndian.PutUint64(state[24:32], x3)
	binary.BigEndian.PutUint64(state[32:40], x4)
}
