// Package turboshake implements TurboSHAKE128 as specified in RFC 9861.
//
// TurboSHAKE128 is an eXtendable-Output Function (XOF) based on the
// Keccak-p[1600,12] permutation with a rate of 168 bytes.
package turboshake

import (
	"github.com/codahale/newplex/internal/mem"
	"github.com/codahale/permutation-city/keccak"
)

// Rate is the TurboSHAKE128 rate in bytes (200 - 32).
const Rate = 168

// Sum computes TurboSHAKE128(msg, ds, outLen) and returns the result.
// The domain separation byte ds must be in the range [0x01, 0x7F].
func Sum(msg []byte, ds byte, outLen int) []byte {
	var s [200]byte

	// Absorb full rate blocks.
	for len(msg) >= Rate {
		mem.XOR(s[:Rate], s[:Rate], msg[:Rate])
		keccak.P1600(&s)
		msg = msg[Rate:]
	}

	// Absorb remaining bytes + padding.
	mem.XOR(s[:len(msg)], s[:len(msg)], msg)
	s[len(msg)] ^= ds
	s[Rate-1] ^= 0x80
	keccak.P1600(&s)

	// Squeeze output.
	out := make([]byte, outLen)
	buf := out
	for len(buf) > 0 {
		n := copy(buf, s[:Rate])
		buf = buf[n:]
		if len(buf) > 0 {
			keccak.P1600(&s)
		}
	}

	return out
}
