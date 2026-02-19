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
		dst := d.state[d.rateIdx : d.rateIdx+remain]
		if remain <= 16 {
			for i := range remain {
				dst[i] ^= b[i]
			}
		} else {
			absorbBlock(dst, b[:remain])
		}
		d.rateIdx += remain
		if d.rateIdx == maxRateIdx {
			d.Permute()
		}
		b = b[remain:]
	}
}

// AbsorbString updates the duplex's state with the given string, running the permutation as the rate is exhausted.
// It avoids the []byte conversion overhead of Absorb for string labels.
func (d *State) AbsorbString(s string) {
	for len(s) > 0 {
		remain := min(len(s), maxRateIdx-d.rateIdx)
		dst := d.state[d.rateIdx : d.rateIdx+remain]
		for i := range remain {
			dst[i] ^= s[i]
		}
		d.rateIdx += remain
		if d.rateIdx == maxRateIdx {
			d.Permute()
		}
		s = s[remain:]
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

// Frame absorbs the current frame index and updates the frame index to be the current rate index.
func (d *State) Frame() {
	// Absorb the previous frame index.
	d.AbsorbByte(byte(d.frameIdx))
	// Record the current frame index.
	d.frameIdx = d.rateIdx
}

// Squeeze fills the given slice with data from the duplex's state, running the permutation as the state becomes
// exhausted.
//
// Multiple Squeeze calls are effectively the same thing as a single Squeeze call with concatenated outputs.
func (d *State) Squeeze(out []byte) {
	for len(out) > 0 {
		remain := min(len(out), maxRateIdx-d.rateIdx)
		src := d.state[d.rateIdx : d.rateIdx+remain]
		if remain <= 16 {
			for i := range remain {
				out[i] = src[i]
			}
		} else {
			copy(out[:remain], src)
		}
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
		if remain <= 16 {
			for i := range remain {
				c := ciphertext[i]
				plaintext[i] = k[i] ^ c
				k[i] = c
			}
		} else {
			decryptBlock(plaintext[:remain], k, ciphertext[:remain])
		}

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
