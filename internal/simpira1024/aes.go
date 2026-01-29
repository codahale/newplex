package simpira1024

// aesEnc is an implementation of Algorithm 1 of the Simpira V2 paper.
//
// It is equivalent to the AESENC instruction from AES-NI, but uses a bitsliced, pure Go implementation.
func aesEnc(state, key [16]byte) [16]byte {
	q := pack(state)
	q = sbox(q)
	q = shiftRows(q)
	q = mixColumns(q)
	state = unpack(q)
	for i := range 16 {
		state[i] ^= key[i]
	}
	return state
}

func pack(s [16]byte) (q [8]uint16) {
	for i := range 16 {
		b := uint16(s[i])
		m := uint16(1) << i
		q[0] |= (b & 1) * m
		q[1] |= ((b >> 1) & 1) * m
		q[2] |= ((b >> 2) & 1) * m
		q[3] |= ((b >> 3) & 1) * m
		q[4] |= ((b >> 4) & 1) * m
		q[5] |= ((b >> 5) & 1) * m
		q[6] |= ((b >> 6) & 1) * m
		q[7] |= ((b >> 7) & 1) * m
	}
	return q
}

func unpack(q [8]uint16) (s [16]byte) {
	for i := range 16 {
		m := uint16(1) << i
		b := (q[0] & m) >> i
		b |= ((q[1] & m) >> i) << 1
		b |= ((q[2] & m) >> i) << 2
		b |= ((q[3] & m) >> i) << 3
		b |= ((q[4] & m) >> i) << 4
		b |= ((q[5] & m) >> i) << 5
		b |= ((q[6] & m) >> i) << 6
		b |= ((q[7] & m) >> i) << 7
		s[i] = byte(b)
	}
	return s
}

func shiftRows(q [8]uint16) [8]uint16 {
	// ShiftRows permutes bits in each q_i.
	var r [8]uint16
	rot := func(in uint16) uint16 {
		return (in & 0x1111) |
			((in & 0x2220) >> 4) | ((in & 0x0002) << 12) |
			((in & 0x4400) >> 8) | ((in & 0x0044) << 8) |
			((in & 0x0888) << 4) | ((in & 0x8000) >> 12)
	}
	for i := range 8 {
		r[i] = rot(q[i])
	}
	return r
}

func mixColumns(q [8]uint16) [8]uint16 {
	// xtime: multiplication by 2 in GF(2^8).
	t0 := q[7]
	t1 := q[0] ^ q[7]
	t2 := q[1]
	t3 := q[2] ^ q[7]
	t4 := q[3] ^ q[7]
	t5 := q[4]
	t6 := q[5]
	t7 := q[6]

	t := [8]uint16{t0, t1, t2, t3, t4, t5, t6, t7}

	// Rotations for MixColumns (cyclic shift of nibbles)
	rot1 := func(x uint16) uint16 { return (x>>1)&0x7777 | (x&0x1111)<<3 }
	rot2 := func(x uint16) uint16 { return (x>>2)&0x3333 | (x&0x3333)<<2 }
	rot3 := func(x uint16) uint16 { return (x>>3)&0x1111 | (x&0x7777)<<1 }

	var r [8]uint16
	for k := range 8 {
		r[k] = t[k] ^ rot1(t[k]^q[k]) ^ rot2(q[k]) ^ rot3(q[k])
	}

	return r
}

func mul(a, b [8]uint16) [8]uint16 {
	var p [15]uint16
	for i := range 8 {
		for j := range 8 {
			p[i+j] ^= a[i] & b[j]
		}
	}
	return reduce(&p)
}

func sq(a [8]uint16) [8]uint16 {
	var p [15]uint16
	for i := range 8 {
		p[2*i] = a[i]
	}
	return reduce(&p)
}

func reduce(p *[15]uint16) [8]uint16 {
	// Reduce modulo x^8 + x^4 + x^3 + x + 1
	for i := 14; i >= 8; i-- {
		v := p[i]
		p[i-4] ^= v
		p[i-5] ^= v
		p[i-7] ^= v
		p[i-8] ^= v
	}
	var res [8]uint16
	for i := range 8 {
		res[i] = p[i]
	}
	return res
}

func inv(a [8]uint16) [8]uint16 {
	// x^254 using addition chain
	x2 := sq(a)
	x4 := sq(x2)
	x8 := sq(x4)
	x16 := sq(x8)
	x32 := sq(x16)
	x64 := sq(x32)
	x128 := sq(x64)

	res := x2
	res = mul(res, x4)
	res = mul(res, x8)
	res = mul(res, x16)
	res = mul(res, x32)
	res = mul(res, x64)
	res = mul(res, x128)
	return res
}

func affine(a [8]uint16) [8]uint16 {
	var s [8]uint16
	for i := range 8 {
		s[i] = a[i] ^ a[(i+4)%8] ^ a[(i+5)%8] ^ a[(i+6)%8] ^ a[(i+7)%8]
	}
	s[0] = ^s[0]
	s[1] = ^s[1]
	s[5] = ^s[5]
	s[6] = ^s[6]
	return s
}

func sbox(u [8]uint16) [8]uint16 {
	return affine(inv(u))
}
