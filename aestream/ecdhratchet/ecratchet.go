// Package ecdhratchet implements an ECDH-based Ratchet mechanism for aestream. For each block, a new ephemeral key is
// generated and used to update the protocol's state.
package ecdhratchet

import (
	"crypto/rand"

	"github.com/codahale/newplex/aestream"
	"github.com/gtank/ristretto255"
)

// Ratchet implements an ECDH ratchet using Ristretto255.
type Ratchet struct {
	// Receiver is the private key of the receiver (or reader).
	Receiver *ristretto255.Scalar
	// Sender is the public key of the sender (or writer).
	Sender *ristretto255.Element
}

// BlockSize returns the length of a ratchet key in bytes.
func (r *Ratchet) BlockSize() int {
	return 32
}

// Send generates a new ratchet key ciphertext and shared secret.
func (r *Ratchet) Send() (ct, ss []byte) {
	var b [64]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	dE, _ := ristretto255.NewScalar().SetUniformBytes(b[:])
	qE := ristretto255.NewIdentityElement().ScalarBaseMult(dE)
	x := ristretto255.NewIdentityElement().ScalarMult(dE, r.Sender)
	return qE.Bytes(), x.Bytes()
}

// Receive decodes a ciphertext into a shared secret.
func (r *Ratchet) Receive(ct []byte) (ss []byte, err error) {
	qE, err := ristretto255.NewIdentityElement().SetCanonicalBytes(ct)
	if err != nil {
		return nil, err
	}
	x := ristretto255.NewIdentityElement().ScalarMult(r.Receiver, qE)
	return x.Bytes(), nil
}

var _ aestream.Ratchet = (*Ratchet)(nil)
