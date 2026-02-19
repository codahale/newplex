package newplex

import (
	"crypto/subtle"
	"encoding"
	"errors"

	"github.com/codahale/newplex/internal/simpira1024"
)

// A duplex is a cryptographic duplex, sans padding or framing schemes. It uses the Simpira-1024 permutation, has a
// width of 1024 bits, a capacity of 256 bits, 16 bits of padding, and a rate of 752 bits. This offers 128 bits of
// security for collision resistance, 256 bits of security for state recovery, and 128 bits of security for
// birthday-bound indistinguishability.
//
// In addition to using SHA-3's pad10*1 scheme for each block of permutation input, it also uses a STROBE-like framing
// mechanism for domain separation of sets of operations.
type duplex struct {
	state             [width]byte
	rateIdx, frameIdx int
}

// permute applies a frame-oriented padding scheme to the state by absorbing the frame index into the rate or
// potentially overflowing into the first of two padding bytes, then applies SHA-3's pad10*1 padding scheme to the
// entire, unpadded rate. Finally, it permutes the entire state with Simpira-1024 and resets rateIdx and frameIdx.
func (d *duplex) permute() {
	d.state[d.rateIdx] ^= byte(d.frameIdx)
	d.rateIdx++
	d.state[d.rateIdx] ^= 0x01
	d.state[padByteIdx] ^= 0x80
	simpira1024.Permute(&d.state)
	d.rateIdx = 0
	d.frameIdx = 0
}

// absorb updates the duplex's state with the given data, running the permutation as the rate is exhausted.
//
// Multiple absorb calls are effectively the same thing as a single absorb call with concatenated inputs.
func (d *duplex) absorb(b []byte) {
	for len(b) > 0 {
		remain := min(len(b), maxRateIdx-d.rateIdx)
		dst := d.state[d.rateIdx : d.rateIdx+remain]
		if remain <= 16 {
			for i := range remain {
				dst[i] ^= b[i]
			}
		} else {
			subtle.XORBytes(dst, dst, b[:remain])
		}
		d.rateIdx += remain
		if d.rateIdx == maxRateIdx {
			d.permute()
		}
		b = b[remain:]
	}
}

// absorbString updates the duplex's state with the given string, running the permutation as the rate is exhausted.
// It avoids the []byte conversion overhead of absorb for string labels.
func (d *duplex) absorbString(s string) {
	for len(s) > 0 {
		remain := min(len(s), maxRateIdx-d.rateIdx)
		dst := d.state[d.rateIdx : d.rateIdx+remain]
		for i := range remain {
			dst[i] ^= s[i]
		}
		d.rateIdx += remain
		if d.rateIdx == maxRateIdx {
			d.permute()
		}
		s = s[remain:]
	}
}

// absorbByte absorbs a single byte.
func (d *duplex) absorbByte(b byte) {
	d.state[d.rateIdx] ^= b
	d.rateIdx++
	if d.rateIdx == maxRateIdx {
		d.permute()
	}
}

// absorbLEB128 absorbs the LEB128 form of the given value.
func (d *duplex) absorbLEB128(x uint64) {
	for x >= 0x80 {
		d.absorbByte(byte(x) | 0x80)
		x >>= 7
	}
	d.absorbByte(byte(x))
}

// frame absorbs the current frame index and updates the frame index to be the current rate index.
func (d *duplex) frame() {
	// Absorb the previous frame index.
	d.absorbByte(byte(d.frameIdx))
	// Record the current frame index.
	d.frameIdx = d.rateIdx
}

// squeeze fills the given slice with data from the duplex's state, running the permutation as the state becomes
// exhausted.
//
// Multiple squeeze calls are effectively the same thing as a single squeeze call with concatenated outputs.
func (d *duplex) squeeze(out []byte) {
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
			d.permute()
		}
		out = out[remain:]
	}
}

// encrypt XORs the given plaintext slice with the duplex's state, copies the result to the given ciphertext slice, and
// updates the duplex's state with the ciphertext.
//
// Multiple encrypt calls are effectively the same thing as a single encrypt call with concatenated inputs.
func (d *duplex) encrypt(ciphertext, plaintext []byte) {
	for len(plaintext) > 0 {
		remain := min(len(plaintext), maxRateIdx-d.rateIdx)
		k := d.state[d.rateIdx : d.rateIdx+remain]

		// C = K = K ^ P
		subtle.XORBytes(k, k, plaintext[:remain])
		copy(ciphertext[:remain], k)

		d.rateIdx += remain
		if d.rateIdx == maxRateIdx {
			d.permute()
		}
		plaintext = plaintext[remain:]
		ciphertext = ciphertext[remain:]
	}
}

// decrypt XORs the given ciphertext slice with the duplex's state, copies the result to the given plaintext slice, and
// updates the duplex's state with the ciphertext.
//
// Multiple decrypt calls are effectively the same thing as a single decrypt call with concatenated inputs.
func (d *duplex) decrypt(plaintext, ciphertext []byte) {
	var tmp [rate]byte
	for len(ciphertext) > 0 {
		remain := min(len(ciphertext), maxRateIdx-d.rateIdx)
		k := d.state[d.rateIdx : d.rateIdx+remain]
		// Make a copy of this block of ciphertext. If plaintext is the same slice as ciphertext, the decryption will
		// overwrite the ciphertext, making it impossible to copy it to the state afterward.
		copy(tmp[:remain], ciphertext[:remain])

		// P = C ^ K; K = C
		subtle.XORBytes(plaintext[:remain], k, ciphertext[:remain])
		copy(k, tmp[:remain])

		d.rateIdx += remain
		if d.rateIdx == maxRateIdx {
			d.permute()
		}
		ciphertext = ciphertext[remain:]
		plaintext = plaintext[remain:]
	}
}

// ratchet applies the Simpira-1024 permutation if needed, then zeros out 256 bits of the rate, preventing rollback.
func (d *duplex) ratchet() {
	if d.rateIdx > 0 {
		d.permute()
	}
	// Zero out a portion of the rate equal to the size of the capacity and advance past it. This ensures the security
	// margin for state recovery (i.e., the size of the capacity) applies to rollback attacks as well.
	const ratchetSize = capacity
	clear(d.state[:ratchetSize])
	d.rateIdx = ratchetSize
}

// equal returns 1 if d and d2 are equal, and 0 otherwise.
func (d *duplex) equal(d2 *duplex) int {
	return subtle.ConstantTimeCompare(d.state[:], d2.state[:]) &
		subtle.ConstantTimeEq(int32(d.rateIdx), int32(d2.rateIdx)) &
		subtle.ConstantTimeEq(int32(d.frameIdx), int32(d2.frameIdx))
}

// clear zeros out the duplex's state.
func (d *duplex) clear() {
	clear(d.state[:])
	d.rateIdx = 0
	d.frameIdx = 0
}

// UnmarshalBinary restores the duplex's state from the given binary representation. It implements
// encoding.BinaryUnmarshaler.
func (d *duplex) UnmarshalBinary(data []byte) error {
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
func (d *duplex) AppendBinary(b []byte) ([]byte, error) {
	return append(append(b, byte(d.rateIdx), byte(d.frameIdx)), d.state[:]...), nil
}

// MarshalBinary returns the binary representation of the duplex's state. It implements encoding.BinaryMarshaler.
func (d *duplex) MarshalBinary() (data []byte, err error) {
	return d.AppendBinary(make([]byte, 0, 2+len(d.state)))
}

var (
	_ encoding.BinaryAppender    = (*duplex)(nil)
	_ encoding.BinaryMarshaler   = (*duplex)(nil)
	_ encoding.BinaryUnmarshaler = (*duplex)(nil)
)

const (
	width      = simpira1024.Width // The width of the permutation in bytes.
	capacity   = 32                // The duplex's capacity in bytes.
	padding    = 1                 // The duplex uses a dedicated byte for pad10*1 block padding.
	framing    = 1                 // The duplex uses a reserved byte for framing.
	maxRateIdx = width - padding - framing - capacity
	padByteIdx = width - capacity - padding
	rate       = width - padding - framing - capacity // The rate of the duplex with padding.
)
