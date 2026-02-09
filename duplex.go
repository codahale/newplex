package newplex

import (
	"crypto/subtle"
	"encoding"
	"errors"

	"github.com/codahale/newplex/internal/simpira1024"
)

// duplex is a cryptographic duplex, sans padding or framing schemes. It uses the Simpira-1024 permutation, has a width
// of 1024 bits, a capacity of 256 bits, and a rate of 768 bits. This offers 128 bits of security for collision
// resistance, 256 bits of security for state recovery, and 128 bits of security for birthday-bound
// indistinguishability.
type duplex struct {
	state         [width]byte
	pos, posBegin int
}

// permute pads the block with the operation beginning and SHA-3's pad10*1 scheme, then runs the Simpira-1024
// permutation.
func (d *duplex) permute() {
	d.state[d.pos] ^= byte(d.posBegin)
	d.state[d.pos+1] ^= 0x01
	d.state[unpaddedRate-1] ^= 0x80
	simpira1024.Permute(&d.state)
	d.pos = 0
	d.posBegin = 0
}

// beginOp updates the duplex's operation pointer and absorbs the old operation pointer and an operation code.
func (d *duplex) beginOp(op byte) {
	// Update the operation pointer.
	oldBegin := d.posBegin
	d.posBegin = d.pos + 1

	// Absorb the old operation pointer and the operation code.
	d.absorbByte(byte(oldBegin))
	d.absorbByte(op)
}

// absorb updates the duplex's state with the given data, running the permutation as the state becomes fully updated.
//
// Multiple absorb calls are effectively the same thing as a single absorb call with concatenated inputs.
func (d *duplex) absorb(b []byte) {
	for len(b) > 0 {
		remain := min(len(b), rate-d.pos)
		subtle.XORBytes(d.state[d.pos:], d.state[d.pos:], b[:remain])
		d.pos += remain
		if d.pos == rate {
			d.permute()
		}
		b = b[remain:]
	}
}

// absorbByte absorbs a single byte.
func (d *duplex) absorbByte(b byte) {
	d.state[d.pos] ^= b
	d.pos++
	if d.pos == rate {
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

// squeeze fills the given slice with data from the duplex's state, running the permutation as the state becomes
// exhausted.
//
// Multiple squeeze calls are effectively the same thing as a single squeeze call with concatenated outputs.
func (d *duplex) squeeze(out []byte) {
	for len(out) > 0 {
		remain := min(len(out), rate-d.pos)
		copy(out[:remain], d.state[d.pos:d.pos+remain])
		d.pos += remain
		if d.pos == rate {
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
		remain := min(len(plaintext), rate-d.pos)
		k := d.state[d.pos : d.pos+remain]

		// C = K = K ^ P
		subtle.XORBytes(k, k, plaintext[:remain])
		copy(ciphertext[:remain], k)

		d.pos += remain
		if d.pos == rate {
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
		remain := min(len(ciphertext), rate-d.pos)
		k := d.state[d.pos : d.pos+remain]
		// Make a copy of this block of ciphertext. If plaintext is the same slice as ciphertext, the decryption will
		// overwrite the ciphertext, making it impossible to copy it to the state afterward.
		copy(tmp[:remain], ciphertext[:remain])

		// P = C ^ K; K = C
		subtle.XORBytes(plaintext[:remain], k, ciphertext[:remain])
		copy(k, tmp[:remain])

		d.pos += remain
		if d.pos == rate {
			d.permute()
		}
		ciphertext = ciphertext[remain:]
		plaintext = plaintext[remain:]
	}
}

// ratchet applies the Simpira-1024 permutation if needed, then zeros out 256 bits of the rate, preventing rollback.
func (d *duplex) ratchet() {
	if d.pos > 0 {
		d.permute()
	}
	// Zero out a portion of the rate equal to the size of the capacity and advance past it. This ensures the security
	// margin for state recovery (i.e., the size of the capacity) applies to rollback attacks as well.
	const ratchetSize = capacity
	clear(d.state[:ratchetSize])
	d.pos = ratchetSize
}

// UnmarshalBinary restores the duplex's state from the given binary representation. It implements
// encoding.BinaryUnmarshaler.
func (d *duplex) UnmarshalBinary(data []byte) error {
	if len(data) != len(d.state)+2 {
		return errors.New("newplex: invalid state length")
	}
	if data[0] >= rate || data[1] >= rate {
		return errors.New("newplex: invalid duplex state")
	}
	d.pos = int(data[0])
	d.posBegin = int(data[1])
	copy(d.state[:], data[2:])
	return nil
}

// AppendBinary appends the binary representation of the duplex's state to the given slice. It implements
// encoding.BinaryAppender.
func (d *duplex) AppendBinary(b []byte) ([]byte, error) {
	return append(append(b, byte(d.pos), byte(d.posBegin)), d.state[:]...), nil
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
	width        = simpira1024.Width      // The width of the permutation in bytes.
	capacity     = 32                     // The duplex's capacity in bytes.
	unpaddedRate = width - capacity       // The duplex's rate without padding.
	padding      = 2                      // The duplex uses two bytes for padding each block.
	rate         = unpaddedRate - padding // The rate of the duplex with padding.
)
