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

	p := a.p
	p.Mix("nonce", nonce)
	p.Mix("ad", additionalData)

	auth, conf := p.Fork("role", []byte("auth"), []byte("conf"))
	auth.Mix("message", plaintext)
	tag := auth.Derive("tag", nil, newplex.TagSize)

	conf.Mix("tag", tag)

	return append(conf.Mask("message", dst, plaintext), tag...)
}

func (a *aead) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	if len(nonce) != a.NonceSize() {
		panic("newplex/siv: invalid nonce size")
	}

	if len(ciphertext) < newplex.TagSize {
		return nil, newplex.ErrInvalidCiphertext
	}

	ciphertext, receivedTag := ciphertext[:len(ciphertext)-newplex.TagSize], ciphertext[len(ciphertext)-newplex.TagSize:]

	p := a.p
	p.Mix("nonce", nonce)
	p.Mix("ad", additionalData)

	auth, conf := p.Fork("role", []byte("auth"), []byte("conf"))

	conf.Mix("tag", receivedTag)

	ret := conf.Unmask("message", dst, ciphertext)
	plaintext := ret[len(dst):]

	auth.Mix("message", plaintext)
	expectedTag := auth.Derive("tag", nil, newplex.TagSize)
	if subtle.ConstantTimeCompare(expectedTag, receivedTag) == 0 {
		clear(plaintext)
		return nil, newplex.ErrInvalidCiphertext
	}

	return ret, nil
}

var _ cipher.AEAD = (*aead)(nil)
