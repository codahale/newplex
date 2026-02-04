// Package siv implements a Synthetic Initialization Vector (SIV) AEAD scheme.
//
// This provides nonce-misuse resistant authenticated encryption (mrAE) and deterministic encryption (DAE) with a
// two-pass algorithm using a cloned protocol.
package siv

import (
	"crypto/cipher"
	"crypto/subtle"

	"github.com/codahale/newplex"
)

// New returns a new cipher.AEAD instance which uses the given domain string and key.
func New(domain string, key []byte, nonceSize int) cipher.AEAD {
	if nonceSize < 16 {
		panic("newplex/siv: nonce size must be at least 16 bytes")
	}
	p := newplex.NewProtocol(domain)
	p.Mix("key", key)
	return &aead{
		p:         p,
		nonceSize: nonceSize,
	}
}

type aead struct {
	p         newplex.Protocol
	nonceSize int
}

func (a *aead) NonceSize() int {
	return a.nonceSize
}

func (a *aead) Overhead() int {
	return newplex.TagSize
}

func (a *aead) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	if len(nonce) != a.NonceSize() {
		panic("newplex/siv: invalid nonce size")
	}

	p := a.p.Clone()
	p.Mix("nonce", nonce)
	p.Mix("ad", additionalData)

	clone := p.Clone()
	clone.Mix("message", plaintext)
	tag := clone.Derive("tag", nil, newplex.TagSize)

	p.Mix("tag", tag)

	return append(p.Mask("message", dst, plaintext), tag...)
}

func (a *aead) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	if len(nonce) != a.NonceSize() {
		panic("newplex/siv: invalid nonce size")
	}

	p := a.p.Clone()
	p.Mix("nonce", nonce)
	p.Mix("ad", additionalData)
	clone := p.Clone()

	p.Mix("tag", ciphertext[len(ciphertext)-newplex.TagSize:])
	plaintext := p.Unmask("message", nil, ciphertext[:len(ciphertext)-newplex.TagSize])

	clone.Mix("message", plaintext)
	tag := clone.Derive("tag", nil, newplex.TagSize)
	if subtle.ConstantTimeCompare(tag, ciphertext[len(ciphertext)-newplex.TagSize:]) == 0 {
		return nil, newplex.ErrInvalidCiphertext
	}

	return append(dst, plaintext...), nil
}

var _ cipher.AEAD = (*aead)(nil)
