package newplex

import (
	"crypto/subtle"
	"errors"
	"slices"

	"github.com/codahale/newplex/internal/tuplehash"
)

const TagSize = 16

var ErrInvalidCiphertext = errors.New("newplex: invalid ciphertext")

type Protocol struct {
	d Duplex
}

func NewProtocol(domain string) Protocol {
	var p Protocol

	metadata := make([]byte, 1, 1+tuplehash.MaxSize+len(domain))
	metadata[0] = opInit
	metadata = tuplehash.AppendLeftEncode(metadata, uint64(len(domain))*bitsPerByte)
	metadata = append(metadata, domain...)

	p.d.Absorb(metadata)
	p.d.Permute()

	return p
}

func (p *Protocol) Mix(label string, input []byte) {
	metadata := make([]byte, 1, 1+tuplehash.MaxSize+len(label))
	metadata[0] = opMix
	metadata = tuplehash.AppendLeftEncode(metadata, uint64(len(label))*bitsPerByte)
	metadata = append(metadata, label...)

	p.d.Absorb(metadata)
	p.d.Absorb(input)
	p.d.Absorb(tuplehash.AppendRightEncode(metadata[:0], uint64(len(input))*bitsPerByte))
}

func (p *Protocol) Derive(label string, dst []byte, n int) []byte {
	metadata := make([]byte, 1, 1+tuplehash.MaxSize+len(label)+tuplehash.MaxSize)
	metadata[0] = opDerive
	metadata = tuplehash.AppendLeftEncode(metadata, uint64(len(label))*bitsPerByte)
	metadata = append(metadata, label...)
	metadata = tuplehash.AppendRightEncode(metadata, uint64(n)*bitsPerByte)

	ret, prf := sliceForAppend(dst, n)
	p.d.Absorb(metadata)
	p.d.Permute()
	p.d.Squeeze(prf)
	p.d.Permute()
	return ret
}

func (p *Protocol) Encrypt(label string, dst, plaintext []byte) []byte {
	metadata := make([]byte, 1, 1+tuplehash.MaxSize+len(label)+tuplehash.MaxSize)
	metadata[0] = opCrypt
	metadata = tuplehash.AppendLeftEncode(metadata, uint64(len(label))*bitsPerByte)
	metadata = append(metadata, label...)
	metadata = tuplehash.AppendRightEncode(metadata, uint64(len(plaintext))*bitsPerByte)

	ret, ciphertext := sliceForAppend(dst, len(plaintext))
	p.d.Absorb(metadata)
	p.d.Key()
	p.d.Encrypt(ciphertext, plaintext)
	p.d.Unkey()
	return ret
}

func (p *Protocol) Decrypt(label string, dst, plaintext []byte) []byte {
	metadata := make([]byte, 1, 1+tuplehash.MaxSize+len(label)+tuplehash.MaxSize)
	metadata[0] = opCrypt
	metadata = tuplehash.AppendLeftEncode(metadata, uint64(len(label))*bitsPerByte)
	metadata = append(metadata, label...)
	metadata = tuplehash.AppendRightEncode(metadata, uint64(len(plaintext))*bitsPerByte)

	ret, ciphertext := sliceForAppend(dst, len(plaintext))
	p.d.Absorb(metadata)
	p.d.Key()
	p.d.Decrypt(ciphertext, plaintext)
	p.d.Unkey()
	return ret
}

func (p *Protocol) Seal(label string, dst, plaintext []byte) []byte {
	ret, ciphertext := sliceForAppend(dst, len(plaintext)+TagSize)
	ciphertext, tag := ciphertext[:len(plaintext)], ciphertext[len(plaintext):]

	metadata := make([]byte, 1, 1+tuplehash.MaxSize+len(label)+tuplehash.MaxSize)
	metadata[0] = opAuthCrypt
	metadata = tuplehash.AppendLeftEncode(metadata, uint64(len(label))*bitsPerByte)
	metadata = append(metadata, label...)
	metadata = tuplehash.AppendRightEncode(metadata, uint64(len(plaintext))*bitsPerByte)

	p.d.Absorb(metadata)
	p.d.Key()
	p.d.Encrypt(ciphertext, plaintext)
	p.d.Unkey()
	p.d.Squeeze(tag)
	p.d.Permute()
	return ret
}

func (p *Protocol) Open(label string, dst, ciphertext []byte) ([]byte, error) {
	ret, plaintext := sliceForAppend(dst, len(ciphertext)-TagSize)
	ciphertext, tag := ciphertext[:len(plaintext)], ciphertext[len(plaintext):]
	var tagP [TagSize]byte

	metadata := make([]byte, 1, 1+tuplehash.MaxSize+len(label)+tuplehash.MaxSize)
	metadata[0] = opAuthCrypt
	metadata = tuplehash.AppendLeftEncode(metadata, uint64(len(label))*bitsPerByte)
	metadata = append(metadata, label...)
	metadata = tuplehash.AppendRightEncode(metadata, uint64(len(plaintext))*bitsPerByte)

	p.d.Absorb(metadata)
	p.d.Key()
	p.d.Decrypt(plaintext, ciphertext)
	p.d.Unkey()
	p.d.Squeeze(tagP[:])
	p.d.Permute()

	if subtle.ConstantTimeCompare(tag, tagP[:]) == 0 {
		clear(plaintext)
		return nil, ErrInvalidCiphertext
	}
	return ret, nil
}

const (
	opInit      = 0x01
	opMix       = 0x02
	opDerive    = 0x03
	opCrypt     = 0x04
	opAuthCrypt = 0x05
)

const (
	bitsPerByte = 8
)

// sliceForAppend takes a slice and a requested number of bytes. It returns a slice with the contents of the given slice
// followed by that many bytes and a second slice that aliases into it and contains only the extra bytes. If the
// original slice has sufficient capacity, then no allocation is performed.
func sliceForAppend(in []byte, n int) (head, tail []byte) {
	head = slices.Grow(in, n)
	head = head[:len(in)+n]
	tail = head[len(in):]
	return head, tail
}
