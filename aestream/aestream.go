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
const MaxBlockSize = math.MaxUint32

// NewWriter wraps the given newplex.Protocol and io.Writer with a streaming authenticated encryption writer.
//
// The returned io.WriteCloser MUST be closed for the encrypted stream to be valid.
func NewWriter(p *newplex.Protocol, w io.Writer) io.WriteCloser {
	return &sealWriter{
		p:   p,
		w:   w,
		buf: make([]byte, 0, 1024),
	}
}

// NewReader wraps the given newplex.Protocol and io.Reader with a streaming authenticated encryption reader.
//
// If the stream has been modified or truncated, a newplex.ErrInvalidCiphertext is returned.
func NewReader(p *newplex.Protocol, r io.Reader) io.ReadCloser {
	return &openReader{
		p:        p,
		r:        r,
		buf:      make([]byte, 0, 1024),
		blockBuf: make([]byte, 0, 1024),
		closed:   false,
	}
}

type sealWriter struct {
	p   *newplex.Protocol
	w   io.Writer
	buf []byte
}

func (s *sealWriter) Write(p []byte) (n int, err error) {
	if len(p) == 0 {
		return 0, nil
	}
	pLen := uint64(len(p))
	if pLen > MaxBlockSize {
		return 0, fmt.Errorf("oversized write: %d bytes, max = %d", pLen, MaxBlockSize)
	}

	// Encode a header with a 4-byte big endian block length and seal it.
	s.buf = slices.Grow(s.buf[:0], headerSize+newplex.TagSize+len(p)+newplex.TagSize)
	header := s.buf[:headerSize]
	binary.BigEndian.PutUint32(header, uint32(pLen))
	encryptedHeader := s.p.Seal("header", header[:0], header)

	// Seal the block, append it to the header, and send it.
	block := s.p.Seal("block", encryptedHeader, p)
	if _, err := s.w.Write(block); err != nil {
		return 0, err
	}

	return len(p), nil
}

func (s *sealWriter) Close() error {
	// Encode and seal a header for a zero-length block.
	s.buf = slices.Grow(s.buf[:0], headerSize+newplex.TagSize+newplex.TagSize)
	header := s.buf[:headerSize]
	binary.BigEndian.PutUint32(header, 0)
	encryptedHeader := s.p.Seal("header", header[:0], header)

	// Seal an empty block, append it to the header, and send it.
	block := s.p.Seal("block", encryptedHeader, nil)
	if _, err := s.w.Write(block); err != nil {
		return err
	}

	if wc, ok := s.w.(io.WriteCloser); ok {
		return wc.Close()
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
	o.buf = slices.Grow(o.buf[:0], headerSize+newplex.TagSize)
	header := o.buf[:headerSize+newplex.TagSize]
	_, err = io.ReadFull(o.r, header)
	if err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return 0, newplex.ErrInvalidCiphertext
		}
		return 0, err
	}
	header, err = o.p.Open("header", header[:0], header)
	if err != nil {
		return 0, err
	}
	messageLen := int(binary.BigEndian.Uint32(header))
	if messageLen > MaxBlockSize {
		return 0, newplex.ErrInvalidCiphertext
	}

	// Read and open the block.
	o.buf = slices.Grow(o.buf[:0], messageLen+newplex.TagSize)
	block := o.buf[:messageLen+newplex.TagSize]
	_, err = io.ReadFull(o.r, block)
	if err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return 0, newplex.ErrInvalidCiphertext
		}
		return 0, err
	}
	block, err = o.p.Open("block", block[:0], block)
	if err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return 0, newplex.ErrInvalidCiphertext
		}
		return 0, err
	}
	o.closed = len(block) == 0
	o.blockBuf = block

	// Satisfy the read with the buffered contents.
	return o.Read(p)
}

func (o *openReader) Close() error {
	if rc, ok := o.r.(io.ReadCloser); ok {
		return rc.Close()
	}
	return nil
}

const headerSize = 4

var (
	_ io.WriteCloser = (*sealWriter)(nil)
	_ io.ReadCloser  = (*openReader)(nil)
)
