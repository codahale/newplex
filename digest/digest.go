// Package digest provides an implementation of a message digest (hash) using the Newplex protocol.
package digest

import (
	"hash"
	"io"

	"github.com/codahale/newplex"
)

const (
	// UnkeyedSize is the size, in bytes, of the unkeyed hash's digest.
	UnkeyedSize = 32

	// KeyedSize is the size, in bytes, of the keyed hash's digest.
	KeyedSize = 16
)

// New returns a new hash.Hash instance which uses the given domain string.
func New(domain string) hash.Hash {
	base := newplex.NewProtocol(domain)
	d := &digest{ //nolint:exhaustruct // initialized via Reset
		base: base,
		size: UnkeyedSize,
	}
	d.Reset()
	return d
}

// NewKeyed returns a new hash.Hash instance which uses the given domain string and the given key.
func NewKeyed(domain string, key []byte) hash.Hash {
	base := newplex.NewProtocol(domain)
	base.Mix("key", key)
	d := &digest{ //nolint:exhaustruct // initialized via Reset
		base: base,
		size: KeyedSize,
	}
	d.Reset()
	return d
}

type digest struct {
	base, p newplex.Protocol
	w       *newplex.MixWriter
	size    int
	n       uint64
}

func (d *digest) Write(p []byte) (n int, err error) {
	n, err = d.w.Write(p)
	d.n += uint64(n) //nolint:gosec // n is always >= 0
	return n, err
}

func (d *digest) Sum(b []byte) []byte {
	p := d.w.Fork()
	return p.Derive("digest", b, d.size)
}

func (d *digest) Reset() {
	d.p = d.base.Clone()
	d.w = d.p.MixWriter("message", io.Discard)
	d.n = 0
}

func (d *digest) Size() int {
	return d.size
}

func (d *digest) BlockSize() int {
	return 96 // newplex rate (768 bits)
}

var _ hash.Hash = (*digest)(nil)
