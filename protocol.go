// Package newplex provides an incremental, stateful cryptographic primitive for symmetric-key cryptographic operations
// (e.g., hashing, encryption, message authentication codes, and authenticated encryption) in complex protocols.
// Inspired by [TupleHash], [STROBE], [Noise Protocol]'s stateful objects, [Merlin] transcripts, and [Xoodyak]'s Cyclist
// mode, Newplex uses the [Simpira] V2 permutation to provide 10+ Gb/sec performance on modern processors at a 128-bit
// security level.
//
// [TupleHash]: https://www.nist.gov/publications/sha-3-derived-functions-cshake-kmac-tuplehash-and-parallelhash
// [STROBE]: https://strobe.sourceforge.io
// [Noise Protocol]: http://www.noiseprotocol.org
// [Merlin]: https://merlin.cool
// [Xoodyak]: https://keccak.team/xoodyak.html
// [Simpira]: https://eprint.iacr.org/2016/122.pdf
package newplex

import (
	"crypto/subtle"
	"encoding"
	"errors"
	"io"
	"slices"

	"github.com/codahale/newplex/internal/tuplehash"
)

// TagSize is the number of bytes added to the plaintext by the Seal operation.
const TagSize = 16

// ErrInvalidCiphertext is returned when the ciphertext is invalid or has been decrypted with the wrong key.
var ErrInvalidCiphertext = errors.New("newplex: invalid ciphertext")

// A Protocol is a stateful object providing fine-grained symmetric-key cryptographic services like hashing, message
// authentication codes, pseudorandom functions, authenticated encryption, and more.
//
// Protocol instances are not concurrent-safe.
type Protocol struct {
	duplex Duplex
}

// NewProtocol creates a new Protocol with the given domain separation string.
//
// The domain separation string should be unique to the application and specific protocol. It should not contain dynamic
// data like timestamps or user IDs. A good format is "application-name.protocol-name".
func NewProtocol(domain string) Protocol {
	var p Protocol

	metadata := make([]byte, 1, 1+tuplehash.MaxSize+len(domain))
	metadata[0] = opInit
	metadata = tuplehash.AppendLeftEncode(metadata, uint64(len(domain))*bitsPerByte)
	metadata = append(metadata, domain...)

	p.duplex.Absorb(metadata)

	return p
}

// Mix updates the protocol's state using the given label and input.
func (p *Protocol) Mix(label string, input []byte) {
	metadata := make([]byte, 1, 1+tuplehash.MaxSize+len(label))
	metadata[0] = opMix
	metadata = tuplehash.AppendLeftEncode(metadata, uint64(len(label))*bitsPerByte)
	metadata = append(metadata, label...)

	p.duplex.Absorb(metadata)
	p.duplex.Absorb(input)
	p.duplex.Absorb(tuplehash.AppendRightEncode(metadata[:0], uint64(len(input))*bitsPerByte))
}

// MixWriter updates the protocol's state using the given label and whatever data is written to the wrapped io.Writer.
//
// N.B.: The returned io.WriteCloser must be closed for the mix operation to be complete.
func (p *Protocol) MixWriter(label string, w io.Writer) io.WriteCloser {
	metadata := make([]byte, 1, 1+tuplehash.MaxSize+len(label))
	metadata[0] = opMix
	metadata = tuplehash.AppendLeftEncode(metadata, uint64(len(label))*bitsPerByte)
	metadata = append(metadata, label...)

	p.duplex.Absorb(metadata)

	return &mixWriter{p: p, w: w, n: 0}
}

// MixReader updates the protocol's state using the given label and whatever data is read from the wrapped io.Reader.
//
// N.B.: The returned io.ReadCloser must be closed for the mix operation to be complete.
func (p *Protocol) MixReader(label string, r io.Reader) io.ReadCloser {
	metadata := make([]byte, 1, 1+tuplehash.MaxSize+len(label))
	metadata[0] = opMix
	metadata = tuplehash.AppendLeftEncode(metadata, uint64(len(label))*bitsPerByte)
	metadata = append(metadata, label...)

	p.duplex.Absorb(metadata)

	return &mixReader{p: p, r: r, n: 0}
}

// Derive updates the protocol's state with the given label and output length and then generates n bytes of pseudorandom
// output. It appends the output to dst and returns the resulting slice.
//
// Derive panics if n is negative.
func (p *Protocol) Derive(label string, dst []byte, n int) []byte {
	if n < 0 {
		panic("invalid argument to Derive: n cannot be negative")
	}

	p.absorbMetadata(opDerive, label, n)

	ret, prf := sliceForAppend(dst, n)
	p.duplex.Permute()
	p.duplex.Squeeze(prf)
	p.duplex.Permute()
	return ret
}

// Encrypt updates the protocol's state with the given label and plaintext length, then uses the state to encrypt the
// given plaintext. It appends the ciphertext to dst and returns the resulting slice.
//
// Encrypt provides confidentiality but not authenticity. To ensure ciphertext authenticity, use Seal instead.
//
// To reuse plaintext's storage for the encrypted output, use plaintext[:0] as dst. Otherwise, the remaining capacity of
// dst must not overlap plaintext.
func (p *Protocol) Encrypt(label string, dst, plaintext []byte) []byte {
	p.absorbMetadata(opCrypt, label, len(plaintext))

	ret, ciphertext := sliceForAppend(dst, len(plaintext))
	p.duplex.Permute()
	p.duplex.Encrypt(ciphertext, plaintext)
	p.duplex.Permute()
	return ret
}

// Decrypt updates the protocol's state with the given label and plaintext length, then uses the state to decrypt the
// given ciphertext. It appends the plaintext to dst and returns the resulting slice.
//
// Decrypt provides confidentiality but not authenticity. To ensure ciphertext authenticity, use Seal instead.
//
// To reuse ciphertext's storage for the encrypted output, use ciphertext[:0] as dst. Otherwise, the remaining capacity
// of dst must not overlap ciphertext.
func (p *Protocol) Decrypt(label string, dst, ciphertext []byte) []byte {
	p.absorbMetadata(opCrypt, label, len(ciphertext))

	ret, plaintext := sliceForAppend(dst, len(ciphertext))
	p.duplex.Permute()
	p.duplex.Decrypt(plaintext, ciphertext)
	p.duplex.Permute()
	return ret
}

// Seal updates the protocol's state with the given label and plaintext length, then uses the state to encrypt the
// given plaintext, appending an authentication tag of TagSize bytes. It appends the ciphertext to dst and returns the
// resulting slice.
//
// To reuse plaintext's storage for the encrypted output, use plaintext[:0] as dst. Otherwise, the remaining capacity of
// dst must not overlap plaintext.
func (p *Protocol) Seal(label string, dst, plaintext []byte) []byte {
	ret, ciphertext := sliceForAppend(dst, len(plaintext)+TagSize)
	ciphertext, tag := ciphertext[:len(plaintext)], ciphertext[len(plaintext):]

	p.absorbMetadata(opAuthCrypt, label, len(plaintext))

	p.duplex.Permute()
	p.duplex.Encrypt(ciphertext, plaintext)
	p.duplex.Permute()
	p.duplex.Squeeze(tag)
	p.duplex.Permute()
	return ret
}

// Open updates the protocol's state with the given label and plaintext length, then uses the state to decrypt the given
// ciphertext, verifying the final TagSize bytes as an authentication tag. If the ciphertext is authentic, it appends
// the ciphertext to dst and returns the resulting slice; otherwise, ErrInvalidCiphertext is returned.
//
// To reuse ciphertext's storage for the decrypted output, use ciphertext[:0] as dst. Otherwise, the remaining capacity
// of dst must not overlap ciphertext.
func (p *Protocol) Open(label string, dst, ciphertextAndTag []byte) ([]byte, error) {
	ret, plaintext := sliceForAppend(dst, len(ciphertextAndTag)-TagSize)
	ciphertext, receivedTag := ciphertextAndTag[:len(plaintext)], ciphertextAndTag[len(plaintext):]
	var calculatedTag [TagSize]byte

	p.absorbMetadata(opAuthCrypt, label, len(plaintext))

	p.duplex.Permute()
	p.duplex.Decrypt(plaintext, ciphertext)
	p.duplex.Permute()
	p.duplex.Squeeze(calculatedTag[:])
	p.duplex.Permute()

	if subtle.ConstantTimeCompare(receivedTag, calculatedTag[:]) == 0 {
		clear(plaintext)
		return nil, ErrInvalidCiphertext
	}
	return ret, nil
}

// Clone returns a full clone of the receiver.
func (p *Protocol) Clone() Protocol {
	return *p
}

// AppendBinary appends the binary representation of the protocol's state to the given slice. It implements
// encoding.BinaryAppender.
func (p *Protocol) AppendBinary(b []byte) ([]byte, error) {
	return p.duplex.AppendBinary(b)
}

// MarshalBinary returns the binary representation of the protocol's state. It implements encoding.BinaryMarshaler.
func (p *Protocol) MarshalBinary() (data []byte, err error) {
	return p.duplex.MarshalBinary()
}

// UnmarshalBinary restores the protocol's state from the given binary representation. It implements
// encoding.BinaryUnmarshaler.
func (p *Protocol) UnmarshalBinary(data []byte) error {
	return p.duplex.UnmarshalBinary(data)
}

func (p *Protocol) absorbMetadata(op byte, label string, n int) {
	metadata := make([]byte, 1, 1+tuplehash.MaxSize+len(label)+tuplehash.MaxSize)
	metadata[0] = op
	metadata = tuplehash.AppendLeftEncode(metadata, uint64(len(label))*bitsPerByte)
	metadata = append(metadata, label...)
	metadata = tuplehash.AppendRightEncode(metadata, uint64(n)*bitsPerByte) //nolint:gosec // unlikely to see 18 EB outputs

	p.duplex.Absorb(metadata)
}

var (
	_ encoding.BinaryAppender    = (*Protocol)(nil)
	_ encoding.BinaryMarshaler   = (*Protocol)(nil)
	_ encoding.BinaryUnmarshaler = (*Protocol)(nil)
)

const (
	opInit      = 0x01 // Initialize a protocol with a domain separation string.
	opMix       = 0x02 // Mix a labeled input value into the protocol's state.
	opDerive    = 0x03 // Derive pseudorandom data from the protocol's state.
	opCrypt     = 0x04 // Encrypt or decrypt an input value.
	opAuthCrypt = 0x05 // Seal or open an input value.

	bitsPerByte = 8 // The number of bits in one byte.
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
