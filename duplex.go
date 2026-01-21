package newplex

import (
	"crypto/subtle"
	"encoding"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/codahale/newplex/internal/simpira"
)

type Duplex struct {
	state [width]byte
	idx   int
	keyed bool
}

func (d *Duplex) Key() {
	d.Permute()
	d.keyed = true
}

func (d *Duplex) Unkey() {
	d.Permute()
	d.keyed = false
}

func (d *Duplex) Absorb(b []byte) {
	if d.keyed {
		panic("newplex: cannot absorb in keyed mode")
	}

	for len(b) > 0 {
		remain := min(len(b), unkeyedRate-d.idx)
		subtle.XORBytes(d.state[d.idx:], d.state[d.idx:], b[:remain])
		d.idx += remain
		if d.idx == unkeyedRate {
			d.Permute()
		}
		b = b[remain:]
	}
}

func (d *Duplex) Squeeze(out []byte) {
	if d.keyed {
		panic("newplex: cannot squeeze in keyed mode")
	}

	for len(out) > 0 {
		remain := min(len(out), unkeyedRate-d.idx)
		copy(out[:remain], d.state[d.idx:d.idx+remain])
		d.idx += remain
		if d.idx == unkeyedRate {
			d.Permute()
		}
		out = out[remain:]
	}
}

func (d *Duplex) Encrypt(dst, src []byte) {
	if !d.keyed {
		panic("newplex: cannot encrypt in unkeyed mode")
	}

	for len(src) > 0 {
		remain := min(len(src), keyedRate-d.idx)
		in := src[:remain]
		out := dst[:remain]
		state := d.state[d.idx : d.idx+remain]

		subtle.XORBytes(state, state, in)
		copy(out, state)

		d.idx += remain
		if d.idx == keyedRate {
			d.Permute()
		}
		src = src[remain:]
	}
}

func (d *Duplex) Decrypt(dst, src []byte) {
	if !d.keyed {
		panic("newplex: cannot decrypt in unkeyed mode")
	}

	for len(src) > 0 {
		remain := min(len(src), keyedRate-d.idx)
		in := src[:remain]
		out := dst[:remain]
		state := d.state[d.idx : d.idx+remain]

		subtle.XORBytes(out, state, in)
		copy(state, in)

		d.idx += remain
		if d.idx == keyedRate {
			d.Permute()
		}
		src = src[remain:]
	}
}

func (d *Duplex) Permute() {
	simpira.Permute8(&d.state)
	d.idx = 0
}

func (d *Duplex) Clear() {
	clear(d.state[:])
}

func (d *Duplex) String() string {
	return hex.EncodeToString(d.state[:])
}

func (d *Duplex) UnmarshalBinary(data []byte) error {
	if len(data) != len(d.state) {
		return errors.New("newplex: invalid state length")
	}
	copy(d.state[:], data)
	return nil
}

func (d *Duplex) AppendBinary(b []byte) ([]byte, error) {
	return append(b, d.state[:]...), nil
}

func (d *Duplex) MarshalBinary() (data []byte, err error) {
	return d.AppendBinary(make([]byte, 0, len(d.state)))
}

var (
	_ fmt.Stringer               = (*Duplex)(nil)
	_ encoding.BinaryAppender    = (*Duplex)(nil)
	_ encoding.BinaryMarshaler   = (*Duplex)(nil)
	_ encoding.BinaryUnmarshaler = (*Duplex)(nil)
)

const (
	width           = 128 // The width of the permutation in bytes.
	unkeyedCapacity = 32  // The duplex's capacity in bytes, with the collision resistance being capacity/2.
	unkeyedRate     = width - unkeyedCapacity
	keyedCapacity   = 16
	keyedRate       = width - keyedCapacity
)
