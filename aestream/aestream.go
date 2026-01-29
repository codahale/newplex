// Package aestream provides a streaming authenticated encryption scheme on top of a newplex.Protocol.
//
// The writer encodes each block's length as a 4-byte big endian integer, seals that header, seals the block, and
// writes both to the wrapped writer. An empty block is used to mark the end of the stream when the writer is closed.
//
// The reader reads the sealed header, opens it, decodes it into a block length, reads an encrypted block of that
// length and its authentication tag, then opens the sealed block. When it encounters the empty block, it returns EOF.
// If the stream terminates before that, an invalid ciphertext error is returned.
//
// For maximum throughput and transmission efficiency, the use of bufio.Reader and bufio.Writer wrappers is strongly
// recommended.
//
// N.B.: For compatibility with 32-bit systems, this implementation has a maximum block size of 2^31-1-16
// (2,147,483,631) bytes. The construction has a theoretical maximum block size of 2^32-1 bytes.
package aestream

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"slices"

	"github.com/codahale/newplex"
)

// MaxBlockSize is the maximum size of an aestream block, in bytes. Writes larger than this will be rejected.
const MaxBlockSize = math.MaxInt32 - newplex.TagSize

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
// If the stream has been modified or truncated, a newplex.ErrInvalidCiphertext is returned.
func NewReader(p *newplex.Protocol, r io.Reader) io.Reader {
	return &openReader{
		p:        p,
		r:        r,
		buf:      make([]byte, 0, 1024),
		blockBuf: nil,
		closed:   false,
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

	err = s.sealAndWrite(p)
	if err != nil {
		return 0, err
	}
	return len(p), nil
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
	pLen := uint64(len(p))
	if pLen > MaxBlockSize {
		return fmt.Errorf("oversized write: %d bytes, max = %d", pLen, MaxBlockSize)
	}

	// Encode a header with a 4-byte big endian block length and seal it.
	s.buf = slices.Grow(s.buf[:0], headerSize+newplex.TagSize+len(p)+newplex.TagSize)
	header := s.buf[:headerSize]
	binary.BigEndian.PutUint32(header, uint32(pLen))
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
	uLen := binary.BigEndian.Uint32(header)
	if uLen > MaxBlockSize {
		return 0, newplex.ErrInvalidCiphertext
	}

	// Read and open the block.
	block, err := o.readAndOpen("block", int(uLen))
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

const headerSize = 4

var (
	_ io.WriteCloser = (*sealWriter)(nil)
	_ io.Reader      = (*openReader)(nil)
)
