// Package tuplehash implements various routines from [NIST SP 800-185].
//
// [NIST SP 800-185]: https://www.nist.gov/publications/sha-3-derived-functions-cshake-kmac-tuplehash-and-parallelhash
package tuplehash

import (
	"math/bits"
)

// MaxSize is the length, in bytes, of the largest encoded integer.
const MaxSize = 9

// AppendLeftEncode encodes an integer value using NIST SP 800-185's left_encode and appends it to b.
func AppendLeftEncode(b []byte, value uint64) []byte {
	n := 8 - (bits.LeadingZeros64(value|1) / 8)
	value <<= (8 - n) * 8
	b = append(b, byte(n))
	for range n {
		b = append(b, byte(value>>56))
		value <<= 8
	}
	return b
}

// AppendRightEncode encodes an integer value using NIST SP 800-185's right_encode and appends it to b.
func AppendRightEncode(b []byte, value uint64) []byte {
	n := 8 - (bits.LeadingZeros64(value|1) / 8)
	value <<= (8 - n) * 8
	for range n {
		b = append(b, byte(value>>56))
		value <<= 8
	}
	b = append(b, byte(n))
	return b
}
