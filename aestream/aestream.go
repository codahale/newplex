// Package aestream provides a streaming authenticated encryption scheme on top of a newplex.Protocol.
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
var ErrBlockTooLarge = errors.New("aestream: block size > max block size")

// NewWriter wraps the given newplex.Protocol and io.Writer with a streaming authenticated encryption writer.
//
// The returned io.WriteCloser MUST be closed for the encrypted stream to be valid.
func NewWriter(p *newplex.Protocol, w io.Writer) io.WriteCloser {
	return &sealWriter{
		p:      p,
		w:      w,
		buf:    make([]byte, 0, 1024),
		closed: false,
	}
}

// NewReader wraps the given newplex.Protocol and io.Reader with a streaming authenticated encryption reader.
//
// The maxBlockSize parameter limits the size of the blocks that will be read. If a block is encountered that is larger
// than this limit, a newplex.ErrInvalidCiphertext is returned.
//
// If the stream has been modified or truncated, a newplex.ErrInvalidCiphertext is returned.
func NewReader(p *newplex.Protocol, r io.Reader, maxBlockSize int) io.Reader {
	return &openReader{
		p:            p,
		r:            r,
		buf:          make([]byte, 0, 1024),
		blockBuf:     nil,
		closed:       false,
		maxBlockSize: maxBlockSize,
	}
}

type sealWriter struct {
	p      *newplex.Protocol
	w      io.Writer
	buf    []byte
	closed bool
}

func (s *sealWriter) Write(p []byte) (n int, err error) {
	if len(p) == 0 {
		return 0, nil
	}

	total := len(p)
	for len(p) > 0 {
		blockLen := min(len(p), MaxBlockSize)
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
	return s.sealAndWrite(nil)
}

func (s *sealWriter) sealAndWrite(p []byte) error {
	// Encode a header with a 4-byte big endian block length and seal it.
	s.buf = slices.Grow(s.buf[:0], headerSize+newplex.TagSize+len(p)+newplex.TagSize)
	header := s.buf[:headerSize]
	putUint24(header, uint32(len(p))) //nolint:gosec // len(p) <= MaxBlockSize
	encryptedHeader := s.p.Seal("header", header[:0], header)

	// Seal the block, append it to the header, and send it.
	block := s.p.Seal("block", encryptedHeader, p)
	if _, err := s.w.Write(block); err != nil {
		return err
	}
	return nil
}

type openReader struct {
	p             *newplex.Protocol
	r             io.Reader
	buf, blockBuf []byte
	closed        bool
	maxBlockSize  int
}

func (o *openReader) Read(p []byte) (n int, err error) {
	if len(p) == 0 {
		return 0, nil
	}

readBuffered:

	// If a block is buffer, satisfy the read with that.
	if len(o.blockBuf) > 0 {
		n = min(len(o.blockBuf), len(p))
		copy(p, o.blockBuf[:n])
		o.blockBuf = o.blockBuf[n:]
		return n, nil
	}

	// If the stream is closed, return EOF.
	if o.closed {
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
	o.closed = len(block) == 0
	o.blockBuf = block

	// Satisfy the read with the buffered contents.
	goto readBuffered
}

func (o *openReader) readAndOpen(label string, n int) ([]byte, error) {
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
	_ io.WriteCloser = (*sealWriter)(nil)
	_ io.Reader      = (*openReader)(nil)
)
