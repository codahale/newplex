package newplex

import (
	"errors"
	"io"

	"github.com/codahale/newplex/internal/tuplehash"
)

type mixWriter struct {
	p *Protocol
	w io.Writer
	n uint64
}

func (m *mixWriter) Write(p []byte) (n int, err error) {
	n, err = m.w.Write(p)
	m.p.duplex.absorb(p[:n])
	m.n += uint64(n) //nolint:gosec // n can't be <0
	return n, err
}

func (m *mixWriter) Close() error {
	m.p.duplex.absorb(tuplehash.AppendRightEncode(nil, m.n))
	return nil
}

type mixReader struct {
	p *Protocol
	r io.Reader
	n uint64
}

func (m *mixReader) Read(p []byte) (n int, err error) {
	n, err = m.r.Read(p)
	m.n += uint64(n) //nolint:gosec // n can't be <0
	m.p.duplex.absorb(p[:n])
	return n, err
}

func (m *mixReader) Close() error {
	m.p.duplex.absorb(tuplehash.AppendRightEncode(nil, m.n))
	return nil
}

type cryptWriter struct {
	p   *Protocol
	f   func(dst, src []byte)
	w   io.Writer
	n   uint64
	buf []byte
}

func (c *cryptWriter) Write(p []byte) (n int, err error) {
	c.buf = append(c.buf[:0], p...)
	c.f(c.buf, c.buf)
	for n < len(c.buf) {
		nn, err := c.w.Write(c.buf[n:])
		n += nn
		c.n += uint64(nn) //nolint:gosec // n can't be <0
		if err != nil && !errors.Is(err, io.ErrShortWrite) {
			return n, err
		}
	}
	return n, nil
}

func (c *cryptWriter) Close() error {
	c.p.duplex.absorb(tuplehash.AppendRightEncode(nil, c.n))
	c.p.duplex.ratchet()
	return nil
}

type cryptReader struct {
	p *Protocol
	f func(dst, src []byte)
	r io.Reader
	n uint64
}

func (c *cryptReader) Read(p []byte) (n int, err error) {
	n, err = c.r.Read(p)
	c.n += uint64(n) //nolint:gosec // n can't be <0
	c.f(p[:n], p[:n])
	return n, err
}

func (c *cryptReader) Close() error {
	c.p.duplex.absorb(tuplehash.AppendRightEncode(nil, c.n))
	c.p.duplex.ratchet()
	return nil
}

var (
	_ io.WriteCloser = (*mixWriter)(nil)
	_ io.ReadCloser  = (*mixReader)(nil)
	_ io.ReadCloser  = (*cryptReader)(nil)
	_ io.WriteCloser = (*cryptWriter)(nil)
)
