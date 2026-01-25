package newplex

import (
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
	m.p.duplex.Absorb(p[:n])
	m.n += uint64(n) //nolint:gosec // n can't be <0
	return n, err
}

func (m *mixWriter) Close() error {
	m.p.duplex.Absorb(tuplehash.AppendRightEncode(nil, m.n*bitsPerByte))
	if wc, ok := m.w.(io.WriteCloser); ok {
		return wc.Close()
	}
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
	m.p.duplex.Absorb(p[:n])
	return n, err
}

func (m *mixReader) Close() error {
	m.p.duplex.Absorb(tuplehash.AppendRightEncode(nil, m.n*bitsPerByte))
	if rc, ok := m.r.(io.ReadCloser); ok {
		return rc.Close()
	}
	return nil
}

type cryptWriter struct {
	p *Protocol
	f func(dst, src []byte)
	w io.Writer
	n uint64
}

func (c *cryptWriter) Write(p []byte) (n int, err error) {
	c.f(p, p)
	n, err = c.w.Write(p)
	c.n += uint64(n) //nolint:gosec // n can't be <0
	return n, err
}

func (c *cryptWriter) Close() error {
	c.p.duplex.Absorb(tuplehash.AppendRightEncode(nil, c.n*bitsPerByte))
	c.p.duplex.Permute()
	if wc, ok := c.w.(io.WriteCloser); ok {
		return wc.Close()
	}
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
	c.p.duplex.Absorb(tuplehash.AppendRightEncode(nil, c.n*bitsPerByte))
	c.p.duplex.Permute()
	if rc, ok := c.r.(io.ReadCloser); ok {
		return rc.Close()
	}
	return nil
}

var (
	_ io.WriteCloser = (*mixWriter)(nil)
	_ io.ReadCloser  = (*mixReader)(nil)
	_ io.ReadCloser  = (*cryptReader)(nil)
	_ io.WriteCloser = (*cryptWriter)(nil)
)
