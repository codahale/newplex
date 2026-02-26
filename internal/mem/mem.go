package mem

import (
	"crypto/subtle"
	"slices"
)

// XOR XORs a and b into dst. Uses subtle.XORBytes for slices larger than
// 16 bytes (which benefits from SIMD) and a scalar loop for small slices.
func XOR(dst, a, b []byte) {
	if len(dst) > 16 {
		subtle.XORBytes(dst, a, b)
	} else {
		for i := range dst {
			dst[i] = a[i] ^ b[i]
		}
	}
}

// SliceForAppend takes a slice and a requested number of bytes. It returns a
// slice with the contents of the given slice followed by that many bytes and a
// second slice that aliases into it and contains only the extra bytes. If the
// original slice has sufficient capacity, then no allocation is performed.
func SliceForAppend(in []byte, n int) (head, tail []byte) {
	head = slices.Grow(in, n)
	head = head[:len(in)+n]
	tail = head[len(in):]
	return head, tail
}
