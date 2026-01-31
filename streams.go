package newplex

import (
	"errors"
	"io"

	"github.com/codahale/newplex/internal/tuplehash"
)

// MixWriter updates the protocol's state using the given label and whatever data is written to the wrapped io.Writer.
//
// N.B.: The returned io.WriteCloser must be closed for the Mix operation to be complete. While the returned
// io.WriteCloser is open, any other operation on the Protocol will panic.
//
// MixWriter panics if a streaming operation is currently active.
func (p *Protocol) MixWriter(label string, w io.Writer) *MixWriter {
	p.checkStreaming()
	p.streaming = true
	p.absorbMetadata(opMix, label)
	return &MixWriter{p: p, w: w, n: 0, closed: false}
}

// MixReader updates the protocol's state using the given label and whatever data is read from the wrapped io.Reader.
//
// N.B.: The returned io.ReadCloser must be closed for the Mix operation to be complete. While the returned
// io.ReadCloser is open, any other operation on the Protocol will panic.
//
// MixReader panics if a streaming operation is currently active.
func (p *Protocol) MixReader(label string, r io.Reader) io.ReadCloser {
	p.checkStreaming()
	p.streaming = true
	p.absorbMetadata(opMix, label)
	return &mixReader{p: p, r: r, n: 0, closed: false}
}

// MaskWriter updates the protocol's state using the given label and encrypts whatever data is written to the wrapped
// io.Writer.
//
// To avoid encrypting the written slices in-place, this writer copies the data before encrypting. As such, it is
// slightly slower than its MaskReader counterpart.
//
// If a Write call returns an error, then the Protocol will be out of sync and must be discarded.
//
// N.B.: The returned io.WriteCloser must be closed for the Mask operation to be complete. While the returned
// io.WriteCloser is open, any other operation on the Protocol will panic.
//
// MaskWriter panics if a streaming operation is currently active.
func (p *Protocol) MaskWriter(label string, w io.Writer) io.WriteCloser {
	p.checkStreaming()
	p.streaming = true
	p.absorbMetadata(opCrypt, label)
	p.duplex.permute()
	return &cryptWriter{p: p, f: p.duplex.encrypt, w: w, n: 0, buf: nil, closed: false}
}

// MaskReader updates the protocol's state using the given label and encrypts whatever data is read
// from the wrapped io.Reader.
//
// N.B.: The returned io.ReadCloser must be closed for the Mask operation to be complete. While the
// returned io.ReadCloser is open, any other operation on the Protocol will panic.
//
// MaskReader panics if a streaming operation is currently active.
func (p *Protocol) MaskReader(label string, r io.Reader) io.ReadCloser {
	p.checkStreaming()
	p.streaming = true
	p.absorbMetadata(opCrypt, label)
	p.duplex.permute()
	return &cryptReader{p: p, f: p.duplex.encrypt, r: r, n: 0, closed: false}
}

// UnmaskWriter updates the protocol's state using the given label and decrypts whatever data is written to the wrapped
// io.Writer.
//
// To avoid decrypting the written slices in-place, this writer copies the data before decrypting. As such, it is
// slightly slower than its UnmaskReader counterpart.
//
// If a Write call returns an error, then the Protocol will be out of sync and must be discarded.
//
// N.B.: The returned io.WriteCloser must be closed for the Unmask operation to be complete. While the
// returned io.WriteCloser is open, any other operation on the Protocol will panic.
//
// UnmaskWriter panics if a streaming operation is currently active.
func (p *Protocol) UnmaskWriter(label string, w io.Writer) io.WriteCloser {
	p.checkStreaming()
	p.streaming = true
	p.absorbMetadata(opCrypt, label)
	p.duplex.permute()
	return &cryptWriter{p: p, f: p.duplex.decrypt, w: w, n: 0, buf: nil, closed: false}
}

// UnmaskReader updates the protocol's state using the given label and decrypts whatever data is read from the wrapped
// io.Reader.
//
// N.B.: The returned io.ReadCloser must be closed for the Unmask operation to be complete. While the returned
// io.ReadCloser is open, any other operation on the Protocol will panic.
//
// UnmaskReader panics if a streaming operation is currently active.
func (p *Protocol) UnmaskReader(label string, r io.Reader) io.ReadCloser {
	p.checkStreaming()
	p.streaming = true
	p.absorbMetadata(opCrypt, label)
	p.duplex.permute()
	return &cryptReader{p: p, f: p.duplex.decrypt, r: r, n: 0, closed: false}
}

// MixWriter allows for the incremental processing of a stream of data into a single Mix operation on a protocol.
type MixWriter struct {
	p      *Protocol
	w      io.Writer
	n      uint64
	closed bool
}

// Clone returns a clone of the writer's protocol with the Mix operation completed. The original writer and protocol
// remain unmodified.
func (m *MixWriter) Clone() Protocol {
	p := *m.p
	p.streaming = false
	p.duplex.absorb(tuplehash.AppendRightEncode(nil, m.n))
	return p
}

func (m *MixWriter) Write(p []byte) (n int, err error) {
	n, err = m.w.Write(p)
	m.p.duplex.absorb(p[:n])
	m.n += uint64(n) //nolint:gosec // n can't be <0
	return n, err
}

func (m *MixWriter) Close() error {
	if m.closed {
		return nil
	}
	m.closed = true
	m.p.duplex.absorb(tuplehash.AppendRightEncode(nil, m.n))
	m.p.streaming = false
	return nil
}

type mixReader struct {
	p      *Protocol
	r      io.Reader
	n      uint64
	closed bool
}

func (m *mixReader) Read(p []byte) (n int, err error) {
	n, err = m.r.Read(p)
	m.n += uint64(n) //nolint:gosec // n can't be <0
	m.p.duplex.absorb(p[:n])
	return n, err
}

func (m *mixReader) Close() error {
	if m.closed {
		return nil
	}
	m.closed = true
	m.p.duplex.absorb(tuplehash.AppendRightEncode(nil, m.n))
	m.p.streaming = false
	return nil
}

type cryptWriter struct {
	p      *Protocol
	f      func(dst, src []byte)
	w      io.Writer
	n      uint64
	buf    []byte
	closed bool
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
	if c.closed {
		return nil
	}
	c.closed = true
	c.p.duplex.absorb(tuplehash.AppendRightEncode(nil, c.n))
	c.p.duplex.ratchet()
	c.p.streaming = false
	return nil
}

type cryptReader struct {
	p      *Protocol
	f      func(dst, src []byte)
	r      io.Reader
	n      uint64
	closed bool
}

func (c *cryptReader) Read(p []byte) (n int, err error) {
	n, err = c.r.Read(p)
	c.n += uint64(n) //nolint:gosec // n can't be <0
	c.f(p[:n], p[:n])
	return n, err
}

func (c *cryptReader) Close() error {
	if c.closed {
		return nil
	}
	c.closed = true
	c.p.duplex.absorb(tuplehash.AppendRightEncode(nil, c.n))
	c.p.duplex.ratchet()
	c.p.streaming = false
	return nil
}

type cloneWriteCloser interface {
	io.WriteCloser

	Clone() Protocol
}

var (
	_ cloneWriteCloser = (*MixWriter)(nil)
	_ io.ReadCloser    = (*mixReader)(nil)
	_ io.ReadCloser    = (*cryptReader)(nil)
	_ io.WriteCloser   = (*cryptWriter)(nil)
)
