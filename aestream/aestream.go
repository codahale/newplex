// Package aestream provides a streaming authenticated encryption scheme on top of a newplex.Protocol.
//
// A stream of data is broken up into a sequence of blocks.
//
// The writer encodes each block's length as a 3-byte big endian integer, seals that header, seals the block, and
// writes both to the wrapped writer. An empty block is used to mark the end of the stream when the writer is closed. A
// block may be at most 2^24-1 bytes long (16,777,216 bytes).
//
// The reader reads the sealed header, opens it, decodes it into a block length, reads an encrypted block of that
// length and its authentication tag, then opens the sealed block. When it encounters the empty block, it returns EOF.
// If the stream terminates before that, an invalid ciphertext error is returned.
package aestream

import (
	"errors"
	"io"
	"slices"

	"github.com/codahale/newplex"
)

// MaxBlockSize is the maximum size of an aestream block, in bytes. Writes larger than this broken up into blocks of
// this size.
const MaxBlockSize = 1<<24 - 1

// ErrBlockTooLarge is returned when a reading a block which is larger than the specified maximum block size.
var ErrBlockTooLarge = errors.New("newplex: block size > max block size")

// Ratchet is a generic double-ratchet mechanism.
type Ratchet interface {
	// BlockSize returns the size of each ratchet block in bytes.
	BlockSize() int

	// Send generates a new ratchet key, returning the ciphertext to be sent and the associated shared secret.
	Send() (ct, ss []byte)

	// Receive converts a ratchet ciphertext into the associated shared secret or returns an error.
	Receive(ct []byte) (ss []byte, err error)
}

// Writer encrypts written data in blocks, ensuring both confidentiality and authenticity.
type Writer struct {
	p            *newplex.Protocol
	w            io.Writer
	buf          []byte
	closed       bool
	maxBlockSize int

	// Ratchet is an optional ratchet mechanism for the writer.
	Ratchet Ratchet
}

// NewWriter wraps the given newplex.Protocol and io.Writer with a streaming authenticated encryption writer.
//
// The returned io.WriteCloser MUST be closed for the encrypted stream to be valid. The provided newplex.Protocol MUST
// NOT be used while the writer is open.
//
// For maximum throughput and transmission efficiency, the use of a bufio.Writer wrapper is strongly recommended.
// Unbuffered writes will result in blocks the length of each write, rather than blocks of the maximum size.
//
// NewWriter panics if maxBlockSize is less than 1 or greater than MaxBlockSize.
func NewWriter(p *newplex.Protocol, w io.Writer, maxBlockSize int) *Writer {
	if maxBlockSize < 1 || maxBlockSize > MaxBlockSize {
		panic("newplex: invalid max block size")
	}
	return &Writer{
		p:            p,
		w:            w,
		buf:          make([]byte, 0, 1024),
		closed:       false,
		maxBlockSize: maxBlockSize,
		Ratchet:      nil,
	}
}

func (s *Writer) Write(p []byte) (n int, err error) {
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

// Close ends the stream with a terminal block, ensuring no further writes can be made to the stream.
func (s *Writer) Close() error {
	if s.closed {
		return nil
	}
	s.closed = true

	// Encode and seal a header for a zero-length block.
	if err := s.sealAndWrite(nil); err != nil {
		return err
	}
	return nil
}

func (s *Writer) sealAndWrite(p []byte) error {
	// Ensure we have enough room for the ratchet block, if any.
	var ratchetBufferSize int
	if s.Ratchet != nil && len(p) > 0 {
		ratchetBufferSize = s.Ratchet.BlockSize() + newplex.TagSize
	}

	// Encode a header with a 3-byte big endian block length and seal it.
	s.buf = slices.Grow(s.buf[:0], headerSize+newplex.TagSize+ratchetBufferSize+len(p)+newplex.TagSize)
	header := s.buf[:headerSize]
	putUint24(header, uint32(len(p))) //nolint:gosec // len(p) <= MaxBlockSize
	block := s.p.Seal("header", header[:0], header)

	// If a ratchet is specified, generate a ratchet block.
	if s.Ratchet != nil && len(p) > 0 {
		ct, ss := s.Ratchet.Send()
		block = s.p.Seal("ratchet", block, ct)
		s.p.Mix("ratchet-key", ss)
	}

	// Seal the block, append it to the header/ratchet block, and send it.
	block = s.p.Seal("block", block, p)
	if _, err := s.w.Write(block); err != nil {
		return err
	}

	return nil
}

// Reader decrypts written data in blocks, ensuring both confidentiality and authenticity.
type Reader struct {
	p             *newplex.Protocol
	r             io.Reader
	buf, blockBuf []byte
	eos           bool
	maxBlockSize  int

	// Ratchet is an optional ratchet mechanism for the writer.
	Ratchet Ratchet
}

// NewReader wraps the given newplex.Protocol and io.Reader with a streaming authenticated encryption reader. See
// the NewWriter documentation for details.
//
// The maxBlockSize parameter limits the size of the blocks that will be read. If a block is encountered that is larger
// than this limit, a newplex.ErrInvalidCiphertext is returned.
//
// If the stream has been modified or truncated, a newplex.ErrInvalidCiphertext is returned.
//
// The provided newplex.Protocol MUST NOT be used while the reader is open.
//
// WARNING: The reader allocates a buffer of size equal to the block length specified in the stream header (up to
// maxBlockSize) before authenticating the block. This creates a potential denial-of-service vector where a malicious
// stream can cause the reader to allocate large amounts of memory. To mitigate this, set maxBlockSize to a reasonable
// limit for your application (e.g., 64KiB or 1MiB) rather than the default MaxBlockSize (16MiB).
func NewReader(p *newplex.Protocol, r io.Reader, maxBlockSize int) *Reader {
	return &Reader{
		p:            p,
		r:            r,
		buf:          make([]byte, 0, 1024),
		blockBuf:     nil,
		eos:          false,
		maxBlockSize: maxBlockSize,
		Ratchet:      nil,
	}
}

func (o *Reader) Read(p []byte) (n int, err error) {
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

		// If a ratchet is specified, process the ratchet block.
		if o.Ratchet != nil && blockLen != 0 {
			var ct, ss []byte
			ct, err = o.readAndOpen("ratchet", o.Ratchet.BlockSize())
			if err != nil {
				return 0, err
			}
			ss, err = o.Ratchet.Receive(ct)
			if err != nil {
				return 0, err
			}
			o.p.Mix("ratchet-key", ss)
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

func (o *Reader) readAndOpen(label string, n int) ([]byte, error) {
	o.buf = slices.Grow(o.buf[:0], n+newplex.TagSize)
	data := o.buf[:n+newplex.TagSize]
	_, err := io.ReadFull(o.r, data)
	if err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, newplex.ErrInvalidCiphertext
		}
		return nil, err
	}
	data, err = o.p.Open(label, data[:0], data)
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
	_ io.WriteCloser = (*Writer)(nil)
	_ io.Reader      = (*Reader)(nil)
)
