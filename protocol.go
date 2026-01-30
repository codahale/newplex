// Package newplex provides an incremental, stateful cryptographic primitive for symmetric-key cryptographic operations
// (e.g., hashing, encryption, message authentication codes, and authenticated encryption) in complex protocols.
// Inspired by [TupleHash], [STROBE], [Noise Protocol]'s stateful objects, [Merlin] transcripts, [SpongeWrap], and
// [Xoodyak]'s Cyclist mode, Newplex uses the [Simpira-1024] permutation to provide 10+ Gb/second performance on modern
// processors at a 128-bit security level.
//
// On AMD64 and ARM64 architectures, newplex uses the AES-NI instruction set to achieve this level of performance. On
// other architectures, or if the purego build tag is used, it uses a much-slower Go implementation with a bitsliced,
// constant-time AES round implementation.
//
// [TupleHash]: https://www.nist.gov/publications/sha-3-derived-functions-cshake-kmac-tuplehash-and-parallelhash
// [STROBE]: https://strobe.sourceforge.io
// [Noise Protocol]: http://www.noiseprotocol.org
// [Merlin]: https://merlin.cool
// [SpongeWrap]: https://eprint.iacr.org/2011/499.pdf
// [Xoodyak]: https://keccak.team/xoodyak.html
// [Simpira-1024]: https://eprint.iacr.org/2016/122.pdf
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
	duplex duplex
}

// NewProtocol creates a new Protocol with the given domain separation string.
//
// The domain separation string should be unique to the application and specific protocol. It should not contain dynamic
// data like timestamps or user IDs. A good format is "application-name.protocol-name".
func NewProtocol(domain string) Protocol {
	var p Protocol
	p.absorbMetadata(opInit, domain)
	return p
}

// Mix updates the protocol's state using the given label and input.
func (p *Protocol) Mix(label string, input []byte) {
	p.absorbMetadata(opMix, label)
	p.duplex.absorb(input)
	p.duplex.absorb(tuplehash.AppendRightEncode(nil, uint64(len(input))))
}

// MixWriter updates the protocol's state using the given label and whatever data is written to the wrapped io.Writer.
//
// N.B.: The returned io.WriteCloser must be closed for the Mix operation to be complete.
func (p *Protocol) MixWriter(label string, w io.Writer) io.WriteCloser {
	p.absorbMetadata(opMix, label)
	return &mixWriter{p: p, w: w, n: 0}
}

// MixReader updates the protocol's state using the given label and whatever data is read from the wrapped io.Reader.
//
// N.B.: The returned io.ReadCloser must be closed for the Mix operation to be complete.
func (p *Protocol) MixReader(label string, r io.Reader) io.ReadCloser {
	p.absorbMetadata(opMix, label)
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

	p.absorbMetadataAndLen(opDerive, label, n)

	ret, prf := sliceForAppend(dst, n)
	p.duplex.permute()
	p.duplex.squeeze(prf)
	p.duplex.ratchet()
	return ret
}

// Encrypt updates the protocol's state with the given label, then uses the state to encrypt the given plaintext. It
// appends the ciphertext to dst and returns the resulting slice.
//
// Encrypt provides confidentiality but not authenticity. To ensure ciphertext authenticity, use Seal instead.
//
// Ciphertexts produced by Encrypt do not depend on their length, so the ciphertexts for 'A' and 'AB' will share a
// prefix. To prevent this, include the message length in a prior Mix operation.
//
// To reuse plaintext's storage for the encrypted output, use plaintext[:0] as dst. Otherwise, the remaining capacity of
// dst must not overlap plaintext.
func (p *Protocol) Encrypt(label string, dst, plaintext []byte) []byte {
	ret, ciphertext := sliceForAppend(dst, len(plaintext))
	p.absorbMetadata(opCrypt, label)
	p.duplex.permute()
	p.duplex.encrypt(ciphertext, plaintext)
	p.duplex.absorb(tuplehash.AppendRightEncode(nil, uint64(len(plaintext))))
	p.duplex.ratchet()
	return ret
}

// EncryptWriter updates the protocol's state using the given label and encrypts whatever data is written to the wrapped
// io.Writer.
//
// To avoid encrypting the written slices in-place, this writer copies the data before encrypting. As such, it is
// slightly slower than its EncryptReader counterpart.
//
// If a Write call returns an error, then the Protocol will be out of sync and must be discarded.
//
// N.B.: The returned io.WriteCloser must be closed for the Encrypt operation to be complete.
func (p *Protocol) EncryptWriter(label string, w io.Writer) io.WriteCloser {
	p.absorbMetadata(opCrypt, label)
	p.duplex.permute()
	return &cryptWriter{p: p, f: p.duplex.encrypt, w: w, n: 0, buf: nil}
}

// EncryptReader updates the protocol's state using the given label and encrypts whatever data is read from the wrapped
// io.Reader.
//
// N.B.: The returned io.ReadCloser must be closed for the Encrypt operation to be complete.
func (p *Protocol) EncryptReader(label string, r io.Reader) io.ReadCloser {
	p.absorbMetadata(opCrypt, label)
	p.duplex.permute()
	return &cryptReader{p: p, f: p.duplex.encrypt, r: r, n: 0}
}

// Decrypt updates the protocol's state with the given label, then uses the state to decrypt the given ciphertext. It
// appends the plaintext to dst and returns the resulting slice.
//
// Decrypt provides confidentiality but not authenticity. To ensure ciphertext authenticity, use Seal instead.
//
// To reuse ciphertext's storage for the encrypted output, use ciphertext[:0] as dst. Otherwise, the remaining capacity
// of dst must not overlap ciphertext.
func (p *Protocol) Decrypt(label string, dst, ciphertext []byte) []byte {
	ret, plaintext := sliceForAppend(dst, len(ciphertext))
	p.absorbMetadata(opCrypt, label)
	p.duplex.permute()
	p.duplex.decrypt(plaintext, ciphertext)
	p.duplex.absorb(tuplehash.AppendRightEncode(nil, uint64(len(plaintext))))
	p.duplex.ratchet()
	return ret
}

// DecryptWriter updates the protocol's state using the given label and decrypts whatever data is written to the wrapped
// io.Writer.
//
// To avoid decrypting the written slices in-place, this writer copies the data before decrypting. As such, it is
// slightly slower than its DecryptReader counterpart.
//
// If a Write call returns an error, then the Protocol will be out of sync and must be discarded.
//
// N.B.: The returned io.WriteCloser must be closed for the Decrypt operation to be complete.
func (p *Protocol) DecryptWriter(label string, w io.Writer) io.WriteCloser {
	p.absorbMetadata(opCrypt, label)
	p.duplex.permute()
	return &cryptWriter{p: p, f: p.duplex.decrypt, w: w, n: 0, buf: nil}
}

// DecryptReader updates the protocol's state using the given label and decrypts whatever data is read from the wrapped
// io.Reader.
//
// N.B.: The returned io.ReadCloser must be closed for the Decrypt operation to be complete.
func (p *Protocol) DecryptReader(label string, r io.Reader) io.ReadCloser {
	p.absorbMetadata(opCrypt, label)
	p.duplex.permute()
	return &cryptReader{p: p, f: p.duplex.decrypt, r: r, n: 0}
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

	p.absorbMetadataAndLen(opAuthCrypt, label, len(plaintext))

	p.duplex.permute()
	p.duplex.encrypt(ciphertext, plaintext)
	p.duplex.permute()
	p.duplex.squeeze(tag)
	p.duplex.ratchet()
	return ret
}

// Open updates the protocol's state with the given label and plaintext length, then uses the state to decrypt the given
// ciphertext, verifying the final TagSize bytes as an authentication tag. If the ciphertext is authentic, it appends
// the ciphertext to dst and returns the resulting slice; otherwise, ErrInvalidCiphertext is returned.
//
// To reuse ciphertext's storage for the decrypted output, use ciphertext[:0] as dst. Otherwise, the remaining capacity
// of dst must not overlap ciphertext.
//
// WARNING: Open decrypts the ciphertext in-place before verifying the authentication tag. If the tag is invalid, the
// decrypted plaintext (which is now in dst) is zeroed out, but the original ciphertext is lost. If you need to preserve
// the ciphertext in case of error, do not use in-place decryption (i.e., do not use ciphertext[:0] as dst).
func (p *Protocol) Open(label string, dst, ciphertextAndTag []byte) ([]byte, error) {
	if len(ciphertextAndTag) < TagSize {
		return nil, ErrInvalidCiphertext
	}
	ret, plaintext := sliceForAppend(dst, len(ciphertextAndTag)-TagSize)
	ciphertext, receivedTag := ciphertextAndTag[:len(plaintext)], ciphertextAndTag[len(plaintext):]
	var expectedTag [TagSize]byte

	p.absorbMetadataAndLen(opAuthCrypt, label, len(plaintext))

	p.duplex.permute()
	p.duplex.decrypt(plaintext, ciphertext)
	p.duplex.permute()
	p.duplex.squeeze(expectedTag[:])
	p.duplex.ratchet()

	if subtle.ConstantTimeCompare(receivedTag, expectedTag[:]) == 0 {
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

func (p *Protocol) absorbMetadata(op byte, label string) {
	metadata := make([]byte, 1, 1+tuplehash.MaxSize+len(label))
	metadata[0] = op
	metadata = tuplehash.AppendLeftEncode(metadata, uint64(len(label)))
	metadata = append(metadata, label...)

	p.duplex.absorb(metadata)
}

func (p *Protocol) absorbMetadataAndLen(op byte, label string, n int) {
	metadata := make([]byte, 1, 1+tuplehash.MaxSize+len(label)+tuplehash.MaxSize)
	metadata[0] = op
	metadata = tuplehash.AppendLeftEncode(metadata, uint64(len(label)))
	metadata = append(metadata, label...)
	metadata = tuplehash.AppendRightEncode(metadata, uint64(n)) //nolint:gosec // n > 0

	p.duplex.absorb(metadata)
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
