package newplex

import (
	"crypto/subtle"
	"encoding"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/codahale/newplex/internal/simpira"
)

// Duplex is a cryptographic duplex, sans padding or framing schemes. It uses the Simpira-8 V2 permutation, has a width
// of 1024 bits, a capacity of 256 bits, and a rate of 768 bits. This offers 128 bits of security for collision
// resistance, 256 bits of security for state recovery, and 128 bits of security for birthday-bound
// indistinguishability.
type Duplex struct {
	state [width]byte
	idx   int
}

// Absorb updates the duplex's state with the given data, running the permutation as the state becomes fully updated.
//
// Multiple Absorb calls are effectively the same thing as a single Absorb call with concatenated inputs.
func (d *Duplex) Absorb(b []byte) {
	for len(b) > 0 {
		remain := min(len(b), rate-d.idx)
		subtle.XORBytes(d.state[d.idx:], d.state[d.idx:], b[:remain])
		d.idx += remain
		if d.idx == rate {
			d.Permute()
		}
		b = b[remain:]
	}
}

// Squeeze fills the given slice with data from the duplex's state, running the permutaiton as the state becomes
// exhausted.
//
// Multiple Squeeze calls are effectively the same thing as a single Squeeze call with concatenated outputs.
func (d *Duplex) Squeeze(out []byte) {
	for len(out) > 0 {
		remain := min(len(out), rate-d.idx)
		copy(out[:remain], d.state[d.idx:d.idx+remain])
		d.idx += remain
		if d.idx == rate {
			d.Permute()
		}
		out = out[remain:]
	}
}

// Encrypt updates the duplex's state with the given plaintext source and writes an encrypted copy to the given
// ciphertext destination.
//
// Multiple Encrypt calls are effectively the same thing as a single Encrypt call with concatenated inputs.
func (d *Duplex) Encrypt(dst, src []byte) {
	for len(src) > 0 {
		remain := min(len(src), rate-d.idx)
		in := src[:remain]
		out := dst[:remain]
		state := d.state[d.idx : d.idx+remain]

		subtle.XORBytes(state, state, in)
		copy(out, state)

		d.idx += remain
		if d.idx == rate {
			d.Permute()
		}
		src = src[remain:]
	}
}

// Decrypt writes a decrypted copy of the given ciphertext source to the given plaintext destination and updates the
// duplex's state with the plaintext.
//
// Multiple Decrypt calls are effectively the same thing as a single Decrypt call with concatenated inputs.
func (d *Duplex) Decrypt(dst, src []byte) {
	for len(src) > 0 {
		remain := min(len(src), rate-d.idx)
		in := src[:remain]
		out := dst[:remain]
		state := d.state[d.idx : d.idx+remain]

		subtle.XORBytes(out, state, in)
		copy(state, in)

		d.idx += remain
		if d.idx == rate {
			d.Permute()
		}
		src = src[remain:]
	}
}

// Permute resets the duplex's state index and applies the Simpira-8 V2 permutation to its 1024-bit state.
func (d *Duplex) Permute() {
	simpira.Permute8(&d.state)
	d.idx = 0
}

func (d *Duplex) String() string {
	return hex.EncodeToString(d.state[:])
}

func (d *Duplex) UnmarshalBinary(data []byte) error {
	if len(data) != len(d.state)+2 {
		return errors.New("newplex: invalid state length")
	}
	d.idx = int(binary.LittleEndian.Uint16(data[:2]))
	copy(d.state[:], data[2:])
	return nil
}

func (d *Duplex) AppendBinary(b []byte) ([]byte, error) {
	return append(binary.LittleEndian.AppendUint16(b, uint16(d.idx)), d.state[:]...), nil //nolint:gosec // idx < 1024
}

func (d *Duplex) MarshalBinary() (data []byte, err error) {
	return d.AppendBinary(make([]byte, 0, 2+len(d.state)))
}

var (
	_ fmt.Stringer               = (*Duplex)(nil)
	_ encoding.BinaryAppender    = (*Duplex)(nil)
	_ encoding.BinaryMarshaler   = (*Duplex)(nil)
	_ encoding.BinaryUnmarshaler = (*Duplex)(nil)
)

const (
	width    = 128              // The width of the permutation in bytes.
	capacity = 32               // The duplex's capacity in bytes.
	rate     = width - capacity // The rate of the duplex as determined by its width and capacity.
)
