package newplex

import (
	"errors"
	"io"
	"slices"

	"github.com/codahale/newplex/internal/tuplehash"
)

// MixWriter updates the protocol's state using the given label and whatever data is written to the wrapped io.Writer.
//
// N.B.: The returned io.WriteCloser must be closed for the Mix operation to be complete. While the returned
// io.WriteCloser is open, any other operation on the Protocol will panic.
//
// MixWriter panics if a streaming operation is currently active.
func (p *Protocol) MixWriter(label string, w io.Writer) io.WriteCloser {
	p.checkStreaming()
	p.streaming = true
	p.absorbMetadata(opMix, label)
	return &mixWriter{p: p, w: w, n: 0, closed: false}
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

// EncryptWriter updates the protocol's state using the given label and encrypts whatever data is written to the wrapped
// io.Writer.
//
// To avoid encrypting the written slices in-place, this writer copies the data before encrypting. As such, it is
// slightly slower than its EncryptReader counterpart.
//
// If a Write call returns an error, then the Protocol will be out of sync and must be discarded.
//
// N.B.: The returned io.WriteCloser must be closed for the Encrypt operation to be complete. While the returned
// io.WriteCloser is open, any other operation on the Protocol will panic.
//
// EncryptWriter panics if a streaming operation is currently active.
func (p *Protocol) EncryptWriter(label string, w io.Writer) io.WriteCloser {
	p.checkStreaming()
	p.streaming = true
	p.absorbMetadata(opCrypt, label)
	p.duplex.permute()
	return &cryptWriter{p: p, f: p.duplex.encrypt, w: w, n: 0, buf: nil, closed: false}
}

// EncryptReader updates the protocol's state using the given label and encrypts whatever data is read from the wrapped
// io.Reader.
//
// N.B.: The returned io.ReadCloser must be closed for the Encrypt operation to be complete. While the returned
// io.ReadCloser is open, any other operation on the Protocol will panic.
//
// EncryptReader panics if a streaming operation is currently active.
func (p *Protocol) EncryptReader(label string, r io.Reader) io.ReadCloser {
	p.checkStreaming()
	p.streaming = true
	p.absorbMetadata(opCrypt, label)
	p.duplex.permute()
	return &cryptReader{p: p, f: p.duplex.encrypt, r: r, n: 0, closed: false}
}

// DecryptWriter updates the protocol's state using the given label and decrypts whatever data is written to the wrapped
// io.Writer.
//
// To avoid decrypting the written slices in-place, this writer copies the data before decrypting. As such, it is
// slightly slower than its DecryptReader counterpart.
//
// If a Write call returns an error, then the Protocol will be out of sync and must be discarded.
//
// N.B.: The returned io.WriteCloser must be closed for the Decrypt operation to be complete. While the returned
// io.WriteCloser is open, any other operation on the Protocol will panic.
//
// DecryptWriter panics if a streaming operation is currently active.
func (p *Protocol) DecryptWriter(label string, w io.Writer) io.WriteCloser {
	p.checkStreaming()
	p.streaming = true
	p.absorbMetadata(opCrypt, label)
	p.duplex.permute()
	return &cryptWriter{p: p, f: p.duplex.decrypt, w: w, n: 0, buf: nil, closed: false}
}

// DecryptReader updates the protocol's state using the given label and decrypts whatever data is read from the wrapped
// io.Reader.
//
// N.B.: The returned io.ReadCloser must be closed for the Decrypt operation to be complete. While the returned
// io.ReadCloser is open, any other operation on the Protocol will panic.
//
// DecryptReader panics if a streaming operation is currently active.
func (p *Protocol) DecryptReader(label string, r io.Reader) io.ReadCloser {
	p.checkStreaming()
	p.streaming = true
	p.absorbMetadata(opCrypt, label)
	p.duplex.permute()
	return &cryptReader{p: p, f: p.duplex.decrypt, r: r, n: 0, closed: false}
}

// MaxBlockSize is the maximum size of an aestream block, in bytes. Writes larger than this broken up into blocks of
// this size.
const MaxBlockSize = 1<<24 - 1

// ErrBlockTooLarge is returned when a reading a block which is larger than the specified maximum block size.
var ErrBlockTooLarge = errors.New("newplex: block size > max block size")

// AEWriter wraps the given newplex.Protocol and io.Writer with a streaming authenticated encryption writer.
//
// The writer encodes each block's length as a 3-byte big endian integer, seals that header, seals the block, and
// writes both to the wrapped writer. An empty block is used to mark the end of the stream when the writer is closed. A
// block may be at most 2^24-1 bytes long (16,777,216 bytes).
//
// The reader reads the sealed header, opens it, decodes it into a block length, reads an encrypted block of that
// length and its authentication tag, then opens the sealed block. When it encounters the empty block, it returns EOF.
// If the stream terminates before that, an invalid ciphertext error is returned.
//
// For maximum throughput and transmission efficiency, the use of bufio.Reader and bufio.Writer wrappers is strongly
// recommended.
//
// The returned io.WriteCloser MUST be closed for the encrypted stream to be valid and for the protocol to return to
// non-streaming mode.
//
// AEWriter panics if maxBlockSize is less than 1 or greater than MaxBlockSize.
func (p *Protocol) AEWriter(w io.Writer, maxBlockSize int) io.WriteCloser {
	p.checkStreaming()
	if maxBlockSize < 1 || maxBlockSize > MaxBlockSize {
		panic("newplex: invalid max block size")
	}
	p.streaming = true
	return &sealWriter{
		p:            p,
		w:            w,
		buf:          make([]byte, 0, 1024),
		closed:       false,
		maxBlockSize: maxBlockSize,
	}
}

// AEReader wraps the given newplex.Protocol and io.Reader with a streaming authenticated encryption reader. See the
// AEWriter documentation for details.
//
// The maxBlockSize parameter limits the size of the blocks that will be read. If a block is encountered that is larger
// than this limit, a newplex.ErrInvalidCiphertext is returned.
//
// If the stream has been modified or truncated, a newplex.ErrInvalidCiphertext is returned.
//
// WARNING: The reader allocates a buffer of size equal to the block length specified in the stream header (up to
// maxBlockSize) before authenticating the block. This creates a potential denial-of-service vector where a malicious
// stream can cause the reader to allocate large amounts of memory. To mitigate this, set maxBlockSize to a reasonable
// limit for your application (e.g., 64KiB or 1MiB) rather than the default MaxBlockSize (16MiB).
//
// The returned io.ReadCloser MUST be closed for the protocol to return to non-streaming mode.
func (p *Protocol) AEReader(r io.Reader, maxBlockSize int) io.ReadCloser {
	p.checkStreaming()
	p.streaming = true
	return &openReader{
		p:            p,
		r:            r,
		buf:          make([]byte, 0, 1024),
		blockBuf:     nil,
		eos:          false,
		closed:       false,
		maxBlockSize: maxBlockSize,
	}
}

type mixWriter struct {
	p      *Protocol
	w      io.Writer
	n      uint64
	closed bool
}

func (m *mixWriter) Write(p []byte) (n int, err error) {
	n, err = m.w.Write(p)
	m.p.duplex.absorb(p[:n])
	m.n += uint64(n) //nolint:gosec // n can't be <0
	return n, err
}

func (m *mixWriter) Close() error {
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

type sealWriter struct {
	p            *Protocol
	w            io.Writer
	buf          []byte
	closed       bool
	maxBlockSize int
}

func (s *sealWriter) Write(p []byte) (n int, err error) {
	if len(p) == 0 {
		return 0, nil
	}

	total := len(p)
	for len(p) > 0 {
		blockLen := min(len(p), s.maxBlockSize)
		err = s.sealAndWrite(p[:blockLen])
		if err != nil {
			return total - len(p), err
		}
		p = p[blockLen:]
	}

	return total, nil
}

func (s *sealWriter) Close() error {
	if s.closed {
		return nil
	}
	s.closed = true

	// Encode and seal a header for a zero-length block.
	if err := s.sealAndWrite(nil); err != nil {
		return err
	}
	s.p.streaming = false
	return nil
}

func (s *sealWriter) sealAndWrite(p []byte) error {
	// Encode a header with a 4-byte big endian block length and seal it.
	s.buf = slices.Grow(s.buf[:0], headerSize+TagSize+len(p)+TagSize)
	header := s.buf[:headerSize]
	putUint24(header, uint32(len(p))) //nolint:gosec // len(p) <= MaxBlockSize
	encryptedHeader := s.p.seal("header", header[:0], header)

	// Seal the block, append it to the header, and send it.
	block := s.p.seal("block", encryptedHeader, p)
	if _, err := s.w.Write(block); err != nil {
		return err
	}
	return nil
}

type openReader struct {
	p             *Protocol
	r             io.Reader
	buf, blockBuf []byte
	eos           bool
	closed        bool
	maxBlockSize  int
}

func (o *openReader) Read(p []byte) (n int, err error) {
	if o.closed {
		return 0, io.ErrClosedPipe
	}

	if len(p) == 0 {
		return 0, nil
	}

	for {
		// If a block is buffer, satisfy the read with that.
		if len(o.blockBuf) > 0 {
			n = min(len(o.blockBuf), len(p))
			copy(p, o.blockBuf[:n])
			o.blockBuf = o.blockBuf[n:]
			return n, nil
		}

		// If the stream is closed, return EOF.
		if o.eos {
			return 0, io.EOF
		}

		// Read and open the header and decode the block length.
		header, err := o.readAndOpen("header", headerSize)
		if err != nil {
			return 0, err
		}
		blockLen := int(uint24(header))
		if blockLen > o.maxBlockSize {
			return 0, ErrBlockTooLarge
		}

		// Read and open the block.
		block, err := o.readAndOpen("block", blockLen)
		if err != nil {
			return 0, err
		}
		o.eos = len(block) == 0
		o.blockBuf = block
	}
}

func (o *openReader) Close() error {
	if o.closed {
		return nil
	}
	o.closed = true
	o.p.streaming = false
	return nil
}

func (o *openReader) readAndOpen(label string, n int) ([]byte, error) {
	o.buf = slices.Grow(o.buf[:0], n+TagSize)
	data := o.buf[:n+TagSize]
	_, err := io.ReadFull(o.r, data)
	if err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, ErrInvalidCiphertext
		}
		return nil, err
	}
	data, err = o.p.open(label, data[:0], data)
	if err != nil {
		return nil, err
	}
	return data, nil
}

const headerSize = 3

func uint24(b []byte) uint32 {
	_ = b[2] // bounds check hint to compiler; see golang.org/issue/14808
	return uint32(b[2]) | uint32(b[1])<<8 | uint32(b[0])<<16
}

func putUint24(b []byte, v uint32) {
	_ = b[2] // early bounds check to guarantee the safety of writes below
	b[0] = byte(v >> 16)
	b[1] = byte(v >> 8)
	b[2] = byte(v)
}

var (
	_ io.WriteCloser = (*mixWriter)(nil)
	_ io.ReadCloser  = (*mixReader)(nil)
	_ io.ReadCloser  = (*cryptReader)(nil)
	_ io.WriteCloser = (*cryptWriter)(nil)
	_ io.WriteCloser = (*sealWriter)(nil)
	_ io.ReadCloser  = (*openReader)(nil)
)
