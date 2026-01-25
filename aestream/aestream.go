// Package aestream provides a streaming authenticated encryption scheme on top of a newplex.Protocol.
//
// The writer encodes each block's length as a 24-bit big endian integer, encrypts that header, seals the block, and
// writes both to the wrapped writer. An empty block is used to mark the end of the stream when the writer is closed.
//
// The reader reads the encrypted header, decrypts it, decodes it into a block length, reads an encrypted block of that
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
	"slices"

	"github.com/codahale/newplex"
)

// MaxBlockSize is the maximum size of an aestream block, in bytes. Writes larger than this will be rejected.
const MaxBlockSize = (1 << 24) - 1

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
func NewReader(p *newplex.Protocol, r io.Reader) io.Reader {
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

	// Encode a header with a 3-byte big endian block length and encrypt it.
	s.buf = slices.Grow(s.buf[:0], 4+len(p)+newplex.TagSize)
	header := s.buf[:4]
	binary.BigEndian.PutUint32(header, uint32(pLen))
	encryptedHeader := s.p.Encrypt("header", header[1:1], header[1:])

	// Seal the block, append it to the header, and send it.
	block := s.p.Seal("block", encryptedHeader, p)
	if _, err := s.w.Write(block); err != nil {
		return 0, err
	}

	return len(p), nil
}

func (s *sealWriter) Close() error {
	// Encode a header for a zero-length block.
	s.buf = slices.Grow(s.buf[:0], 4+newplex.TagSize)
	header := s.buf[:4]
	binary.BigEndian.PutUint32(header, 0)
	encryptedHeader := s.p.Encrypt("header", header[1:1], header[1:])

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

	// Read and decrypt the header and decode the block length.
	o.buf = slices.Grow(o.buf[:0], 4)[:4]
	header := o.buf[:4]
	header[0] = 0 // Ensure the 24-bit length is correctly decoded.
	_, err = io.ReadFull(o.r, header[1:])
	if err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return 0, newplex.ErrInvalidCiphertext
		}
		return 0, err
	}
	o.p.Decrypt("header", header[1:1], header[1:])
	messageLen := int(binary.BigEndian.Uint32(header))
	if messageLen > MaxBlockSize {
		return 0, newplex.ErrInvalidCiphertext
	}

	// Read and open the block.
	o.buf = slices.Grow(o.buf[:0], messageLen+newplex.TagSize)[:messageLen+newplex.TagSize]
	block := o.buf
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

var (
	_ io.WriteCloser = (*sealWriter)(nil)
	_ io.Reader      = (*openReader)(nil)
)
