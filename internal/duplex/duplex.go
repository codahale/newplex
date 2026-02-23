// Package duplex implements a cryptographic duplex construction using the Simpira-1024 permutation.
//
// This package provides the core duplex state management for the Newplex cryptographic framework. It implements a
// sponge-like construction with a 1024-bit state, 256-bit capacity, and 752-bit rate, offering 128-bit security against
// generic attacks. The duplex supports absorption, squeezing, encryption/decryption operations, and includes
// STROBE-like framing for domain separation.
package duplex

import (
	"crypto/subtle"
	"encoding"
	"errors"

	"github.com/codahale/newplex/internal/simpira1024"
)

// A State is the state of a cryptographic duplex, sans padding or framing schemes. It uses the Simpira-1024
// permutation, has a width of 1024 bits, a capacity of 256 bits, 8 bits of framing, 8 bits of padding, and a rate of
// 752 bits. This offers 128 bits of security for collision resistance, 256 bits of security for state recovery, and 128
// bits of security for birthday-bound indistinguishability.
//
// In addition to using SHA-3's pad10*1 scheme for each block of permutation input, it also uses a STROBE-like framing
// mechanism for domain separation of sets of operations.
type State struct {
	state             [width]byte
	rateIdx, frameIdx int
}

// Permute applies a Frame-oriented padding scheme to the state by absorbing the Frame index into the rate or
// potentially overflowing into the first of two padding bytes, then applies SHA-3's pad10*1 padding scheme to the
// entire, unpadded rate. Finally, it permutes the entire state with Simpira-1024 and resets rateIdx and frameIdx.
func (d *State) Permute() {
	d.state[d.rateIdx] ^= byte(d.frameIdx)
	d.rateIdx++
	d.state[d.rateIdx] ^= 0x01
	d.state[padByteIdx] ^= 0x80
	simpira1024.Permute(&d.state)
	d.rateIdx = 0
	d.frameIdx = 0
}

// Absorb updates the duplex's state with the given data, running the permutation as the rate is exhausted.
//
// Multiple Absorb calls are effectively the same thing as a single Absorb call with concatenated inputs.
func (d *State) Absorb(b []byte) {
	for len(b) > 0 {
		remain := min(len(b), maxRateIdx-d.rateIdx)
		absorbBlock(d.state[d.rateIdx:d.rateIdx+remain], b[:remain])
		d.rateIdx += remain
		if d.rateIdx == maxRateIdx {
			d.Permute()
		}
		b = b[remain:]
	}
}

// AbsorbByte absorbs a single byte.
func (d *State) AbsorbByte(b byte) {
	d.state[d.rateIdx] ^= b
	d.rateIdx++
	if d.rateIdx == maxRateIdx {
		d.Permute()
	}
}

// AbsorbLEB128 absorbs the LEB128 form of the given value.
func (d *State) AbsorbLEB128(x uint64) {
	for x >= 0x80 {
		d.AbsorbByte(byte(x) | 0x80)
		x >>= 7
	}
	d.AbsorbByte(byte(x))
}

// AbsorbHeader absorbs the common protocol operation header pattern:
//
//	Frame + AbsorbByte(op) + Absorb(label) + Frame + AbsorbByte(op|0x80)
//
// in a single pass, avoiding per-byte overflow checks when the header fits within the remaining rate.
//
// The fast path inlines the two Frame() calls and their associated absorptions. Given a starting rateIdx of R, the
// layout within the rate is:
//
//	state[R]       ^= frameIdx    // First Frame(): absorb the old frameIdx
//	state[R+1]     ^= op          // AbsorbByte(op): absorb the metadata opcode
//	state[R+2..R+2+n) ^= label    // Absorb(label): absorb the label bytes
//	state[R+2+n]   ^= R+1         // Second Frame(): absorb the new frameIdx
//	                              //   (frameIdx was set to R+1 after the first
//	                              //   Frame absorbed the old value at R, then
//	                              //   the opcode byte advanced rateIdx to R+1,
//	                              //   so Frame() records R+1 as the start of
//	                              //   the metadata frame)
//	state[R+3+n]   ^= op | 0x80  // AbsorbByte(op|0x80): absorb the data opcode
//
// After the fast path:
//
//	frameIdx = R + 3 + n   (start of the data frame, i.e., the position after
//	                        the second Frame's AbsorbByte advanced rateIdx)
//	rateIdx  = R + 4 + n   (= R + headerLen, ready for the operation's payload)
//
// This is equivalent to the slow path but avoids five separate boundary checks.
func (d *State) AbsorbHeader(op byte, label string) {
	n := len(label)
	headerLen := 4 + n // frame byte + op + label + frame byte + op|0x80

	if d.rateIdx+headerLen <= maxRateIdx {
		// Fast path: absorb the entire header without overflow checks.
		R := d.rateIdx
		d.state[R] ^= byte(d.frameIdx) // Frame: absorb old frameIdx
		d.state[R+1] ^= op             // Op byte
		s := d.state[R+2 : R+2+n]
		for i := range n {
			s[i] ^= label[i]
		}
		d.state[R+2+n] ^= byte(R + 1) // Frame: absorb new frameIdx (set to R+1)
		d.state[R+3+n] ^= op | 0x80   // Op|0x80
		d.frameIdx = R + 3 + n
		d.rateIdx = R + headerLen
		if d.rateIdx == maxRateIdx {
			d.Permute()
		}
		return
	}

	// Slow path: use individual operations for cases near the rate boundary.
	d.Frame(op)
	d.Absorb([]byte(label))
	d.Frame(op | 0x80)
}

// Frame absorbs the current frame index, updates the frame index to be the current rate index, and absorbs the given
// identifier byte.
func (d *State) Frame(id byte) {
	// Absorb the previous frame index.
	d.AbsorbByte(byte(d.frameIdx))
	// Record the current frame index.
	d.frameIdx = d.rateIdx
	// Absorb the identifier byte.
	d.AbsorbByte(id)
}

// Squeeze fills the given slice with data from the duplex's state and zeros out the portion of the duplex's state which
// was returned, running the permutation as the state becomes exhausted.
//
// Multiple Squeeze calls are effectively the same thing as a single Squeeze call with concatenated outputs.
func (d *State) Squeeze(out []byte) {
	for len(out) > 0 {
		remain := min(len(out), maxRateIdx-d.rateIdx)
		copy(out[:remain], d.state[d.rateIdx:d.rateIdx+remain])
		clear(d.state[d.rateIdx : d.rateIdx+remain])
		d.rateIdx += remain
		if d.rateIdx == maxRateIdx {
			d.Permute()
		}
		out = out[remain:]
	}
}

// Encrypt XORs the given plaintext slice with the duplex's state, copies the result to the given ciphertext slice, and
// updates the duplex's state with the ciphertext.
//
// Multiple Encrypt calls are effectively the same thing as a single Encrypt call with concatenated inputs.
func (d *State) Encrypt(ciphertext, plaintext []byte) {
	for len(plaintext) > 0 {
		remain := min(len(plaintext), maxRateIdx-d.rateIdx)
		k := d.state[d.rateIdx : d.rateIdx+remain]

		// C = K = K ^ P (single pass: write state and ciphertext simultaneously)
		encryptBlock(ciphertext[:remain], k, plaintext[:remain])

		d.rateIdx += remain
		if d.rateIdx == maxRateIdx {
			d.Permute()
		}
		plaintext = plaintext[remain:]
		ciphertext = ciphertext[remain:]
	}
}

// Decrypt XORs the given ciphertext slice with the duplex's state, copies the result to the given plaintext slice, and
// updates the duplex's state with the ciphertext.
//
// Multiple Decrypt calls are effectively the same thing as a single Decrypt call with concatenated inputs.
func (d *State) Decrypt(plaintext, ciphertext []byte) {
	for len(ciphertext) > 0 {
		remain := min(len(ciphertext), maxRateIdx-d.rateIdx)
		k := d.state[d.rateIdx : d.rateIdx+remain]

		// P = C ^ K; K = C
		// decryptBlock reads ciphertext[i] before writing plaintext[i], so it
		// is correct even when plaintext and ciphertext are the same slice.
		decryptBlock(plaintext[:remain], k, ciphertext[:remain])

		d.rateIdx += remain
		if d.rateIdx == maxRateIdx {
			d.Permute()
		}
		ciphertext = ciphertext[remain:]
		plaintext = plaintext[remain:]
	}
}

// Ratchet applies the Simpira-1024 permutation if needed, then zeros out 256 bits of the rate, preventing rollback.
func (d *State) Ratchet() {
	if d.rateIdx > 0 {
		d.Permute()
	}
	// Zero out a portion of the rate equal to the size of the capacity and advance past it. This ensures the security
	// margin for state recovery (i.e., the size of the capacity) applies to rollback attacks as well.
	const ratchetSize = capacity
	clear(d.state[:ratchetSize])
	d.rateIdx = ratchetSize
}

// Equal returns 1 if d and d2 are equal, and 0 otherwise.
func (d *State) Equal(d2 *State) int {
	return subtle.ConstantTimeCompare(d.state[:], d2.state[:]) &
		subtle.ConstantTimeEq(int32(d.rateIdx), int32(d2.rateIdx)) &
		subtle.ConstantTimeEq(int32(d.frameIdx), int32(d2.frameIdx))
}

// Clear zeros out the duplex's state.
func (d *State) Clear() {
	clear(d.state[:])
	d.rateIdx = 0
	d.frameIdx = 0
}

// UnmarshalBinary restores the duplex's state from the given binary representation. It implements
// encoding.BinaryUnmarshaler.
func (d *State) UnmarshalBinary(data []byte) error {
	if len(data) != len(d.state)+2 {
		return errors.New("newplex: invalid state length")
	}
	if data[0] >= maxRateIdx || data[1] >= maxRateIdx {
		return errors.New("newplex: invalid duplex state")
	}
	d.rateIdx = int(data[0])
	d.frameIdx = int(data[1])
	copy(d.state[:], data[2:])
	return nil
}

// AppendBinary appends the binary representation of the duplex's state to the given slice. It implements
// encoding.BinaryAppender.
func (d *State) AppendBinary(b []byte) ([]byte, error) {
	return append(append(b, byte(d.rateIdx), byte(d.frameIdx)), d.state[:]...), nil
}

// MarshalBinary returns the binary representation of the duplex's state. It implements encoding.BinaryMarshaler.
func (d *State) MarshalBinary() (data []byte, err error) {
	return d.AppendBinary(make([]byte, 0, 2+len(d.state)))
}

var (
	_ encoding.BinaryAppender    = (*State)(nil)
	_ encoding.BinaryMarshaler   = (*State)(nil)
	_ encoding.BinaryUnmarshaler = (*State)(nil)
)

const (
	width      = simpira1024.Width // The width of the permutation in bytes.
	capacity   = 32                // The duplex's capacity in bytes.
	padding    = 1                 // The duplex uses a dedicated byte for pad10*1 block padding.
	framing    = 1                 // The duplex uses a reserved byte for framing.
	maxRateIdx = width - padding - framing - capacity
	padByteIdx = width - capacity - padding
)
