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
	m.p.duplex.Absorb(p)
	n, err = m.w.Write(p)
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

var (
	_ io.WriteCloser = (*mixWriter)(nil)
	_ io.ReadCloser  = (*mixReader)(nil)
)
