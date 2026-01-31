// Package digest provides an implementation of a message digest (hash) using the Newplex protocol.
package digest

import (
	"hash"
	"io"

	"github.com/codahale/newplex"
)

// Size is the size, in bytes, of the hash's digest.
const Size = 32

// New returns a new hash.Hash instance which uses the given domain string.
func New(domain string) hash.Hash {
	d := &digest{ //nolint:exhaustruct // initialized via Reset
		domain: domain,
	}
	d.Reset()
	return d
}

type digest struct {
	p      newplex.Protocol
	w      *newplex.MixWriter
	domain string
	n      uint64
}

func (d *digest) Write(p []byte) (n int, err error) {
	n, err = d.w.Write(p)
	d.n += uint64(n) //nolint:gosec // n is always >= 0
	return n, err
}

func (d *digest) Sum(b []byte) []byte {
	p := d.w.Clone()
	return p.Derive("digest", b, Size)
}

func (d *digest) Reset() {
	d.p = newplex.NewProtocol(d.domain)
	d.w = d.p.MixWriter("message", io.Discard)
	d.n = 0
}

func (d *digest) Size() int {
	return Size
}

func (d *digest) BlockSize() int {
	return 96 // newplex rate (768 bits)
}

var _ hash.Hash = (*digest)(nil)
