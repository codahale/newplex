// Package aead provides an implementation of Authenticated Encryption with Associated Data (AEAD) using the Newplex
// protocol.
package aead

import (
	"crypto/cipher"

	"github.com/codahale/newplex"
)

// New returns a new cipher.AEAD instance which uses the given domain string and key.
func New(domain string, key []byte, nonceSize int) cipher.AEAD {
	if nonceSize < 16 {
		panic("newplex/aead: nonce size must be at least 16 bytes")
	}
	p := newplex.NewProtocol(domain)
	p.Mix("key", key)
	return &aead{
		p:         p,
		nonceSize: nonceSize,
	}
}

type aead struct {
	p         *newplex.Protocol
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
		panic("newplex/aead: invalid nonce size")
	}

	p := a.p.Clone()
	p.Mix("nonce", nonce)
	p.Mix("ad", additionalData)
	return p.Seal("message", dst, plaintext)
}

func (a *aead) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	if len(nonce) != a.NonceSize() {
		panic("newplex/aead: invalid nonce size")
	}

	p := a.p.Clone()
	p.Mix("nonce", nonce)
	p.Mix("ad", additionalData)
	return p.Open("message", dst, ciphertext)
}

var _ cipher.AEAD = (*aead)(nil)
