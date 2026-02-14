package newplex

import (
	"crypto/cipher"
	"io"
)

// MixWriter updates the protocol's state using the given label and whatever data is written to the wrapped io.Writer.
//
// N.B.: The returned io.WriteCloser must be closed for the Mix operation to be complete. While the returned
// io.WriteCloser is open, any other operation on the Protocol will panic.
//
// MixWriter panics if a streaming operation is currently active.
func (p *Protocol) MixWriter(label string, w io.Writer) *MixWriter {
	p.checkState()
	p.streaming = true
	p.duplex.frame()
	p.duplex.absorbByte(opMix)
	p.duplex.absorb([]byte(label))
	p.duplex.frame()
	p.duplex.absorbByte(opMix | 0x80)
	return &MixWriter{p: p, w: w, closed: false}
}

// MixReader updates the protocol's state using the given label and whatever data is read from the wrapped io.Reader.
//
// N.B.: The returned io.ReadCloser must be closed for the Mix operation to be complete. While the returned
// io.ReadCloser is open, any other operation on the Protocol will panic.
//
// MixReader panics if a streaming operation is currently active.
func (p *Protocol) MixReader(label string, r io.Reader) io.ReadCloser {
	p.checkState()
	p.streaming = true
	p.duplex.frame()
	p.duplex.absorbByte(opMix)
	p.duplex.absorb([]byte(label))
	p.duplex.frame()
	p.duplex.absorbByte(opMix | 0x80)
	return &mixReader{p: p, r: r, closed: false}
}

// MaskStream updates the protocol's state using the given label and returns a cipher.Stream which will mask any data
// passed to it. This can be used with cipher.StreamReader or cipher.StreamWriter to mask data during IO operations.
//
// N.B.: The returned CryptStream must be closed for the Mask operation to be complete. While the returned
// CryptStream is open, any other operation on the Protocol will panic.
//
// MaskStream panics if a streaming operation is currently active.
func (p *Protocol) MaskStream(label string) *CryptStream {
	p.checkState()
	p.streaming = true
	p.duplex.frame()
	p.duplex.absorbByte(opCrypt)
	p.duplex.absorb([]byte(label))
	p.duplex.frame()
	p.duplex.absorbByte(opCrypt | 0x80)
	p.duplex.permute()
	return &CryptStream{p: p, f: p.duplex.encrypt, closed: false}
}

// UnmaskStream updates the protocol's state using the given label and returns a cipher.Stream which will unmask any
// data passed to it. This can be used with cipher.StreamReader or cipher.StreamWriter to unmask data during IO
// operations.
//
// N.B.: The returned CryptStream must be closed for the Unmask operation to be complete. While the returned
// CryptStream is open, any other operation on the Protocol will panic.
//
// UnmaskStream panics if a streaming operation is currently active.
func (p *Protocol) UnmaskStream(label string) *CryptStream {
	p.checkState()
	p.streaming = true
	p.duplex.frame()
	p.duplex.absorbByte(opCrypt)
	p.duplex.absorb([]byte(label))
	p.duplex.frame()
	p.duplex.absorbByte(opCrypt | 0x80)
	p.duplex.permute()
	return &CryptStream{p: p, f: p.duplex.decrypt, closed: false}
}

// MixWriter allows for the incremental processing of a stream of data into a single Mix operation on a protocol.
type MixWriter struct {
	p      *Protocol
	w      io.Writer
	closed bool
}

// Branch returns a clone of the writer's protocol with the Mix operation completed. The original writer and protocol
// remain unmodified.
func (m *MixWriter) Branch() Protocol {
	p := *m.p // Using a copy instead of Clone to bypass the streaming flag.
	p.streaming = false
	return p
}

func (m *MixWriter) Write(p []byte) (n int, err error) {
	n, err = m.w.Write(p)
	m.p.duplex.absorb(p[:n])
	return n, err
}

// Close ends the Mix operation and marks the underlying protocol as available for other operations.
func (m *MixWriter) Close() error {
	if m.closed {
		return nil
	}
	m.closed = true
	m.p.streaming = false
	return nil
}

type mixReader struct {
	p      *Protocol
	r      io.Reader
	closed bool
}

func (m *mixReader) Read(p []byte) (n int, err error) {
	n, err = m.r.Read(p)
	m.p.duplex.absorb(p[:n])
	return n, err
}

func (m *mixReader) Close() error {
	if m.closed {
		return nil
	}
	m.closed = true
	m.p.streaming = false
	return nil
}

// CryptStream implements a streaming version of a protocol's Mask or Unmask operation.
//
// N.B.: After the stream has been masked or unmasked, the caller MUST call Close to complete the operation.
type CryptStream struct {
	p      *Protocol
	f      func(dst, src []byte)
	closed bool
}

// XORKeyStream XORs each byte in the given slice with a byte from the cipher's key stream. Dst and src must overlap
// entirely or not at all.
//
// If len(dst) < len(src), XORKeyStream should panic. It is acceptable to pass a dst bigger than src, and in that case,
// XORKeyStream will only update dst[:len(src)] and will not touch the rest of dst.
//
// Multiple calls to XORKeyStream behave as if the concatenation of the src buffers was passed in a single run. That is,
// Stream maintains state and does not reset at each XORKeyStream call.
func (c *CryptStream) XORKeyStream(dst, src []byte) {
	c.f(dst, src)
}

// Close ends the Mask or Unmask operation and marks the underlying protocol as available for other operations.
func (c *CryptStream) Close() error {
	if c.closed {
		return nil
	}
	c.closed = true
	c.p.streaming = false
	return nil
}

var (
	_ io.WriteCloser = (*MixWriter)(nil)
	_ io.ReadCloser  = (*mixReader)(nil)
	_ cipher.Stream  = (*CryptStream)(nil)
)
