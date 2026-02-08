// Package adratchet implements an asynchronous double ratchet mechanism with Newplex and Ristretto255.
//
// This package provides a Ratchet type that maintains send and receive states, allowing for encrypted communication
// with forward secrecy and break-in recovery. It uses ephemeral Ristretto255 keys for the ratchet steps and Newplex for
// the underlying symmetric encryption and state management.
package adratchet

import (
	"crypto/rand"

	"github.com/codahale/newplex"
	"github.com/gtank/ristretto255"
)

// Overhead is the number of bytes added to the plaintext by SendMessage. It consists of the 32-byte ephemeral public
// key and the Newplex tag size.
const Overhead = 32 + newplex.TagSize

// Ratchet tracks the state of an asynchronous double ratchet conversation. It maintains separate Newplex protocols for
// sending and receiving, along with the local private key and the remote public key for ECDH operations.
type Ratchet struct {
	// Send is the Newplex protocol instance used for encrypting outgoing messages.
	Send *newplex.Protocol
	// Recv is the Newplex protocol instance used for decrypting incoming messages.
	Recv *newplex.Protocol
	// Local is the local private key (scalar) used for ECDH.
	Local *ristretto255.Scalar
	// Remote is the remote party's public key (element) used for ECDH.
	Remote *ristretto255.Element
}

// SendMessage encrypts the plaintext and appends it to dst. It generates a new ephemeral key pair, performs an ECDH
// exchange with the remote static key, mixes the shared secret into the Send protocol, and then seals the message. The
// output format is masked_ephemeral_pk || ciphertext || tag.
func (r *Ratchet) SendMessage(dst, plaintext []byte) []byte {
	var b [64]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	dE, _ := ristretto255.NewScalar().SetUniformBytes(b[:])
	qE := ristretto255.NewIdentityElement().ScalarBaseMult(dE)
	ciphertext := r.Send.Mask("ratchet-pk", dst, qE.Bytes())

	ss := ristretto255.NewIdentityElement().ScalarMult(dE, r.Remote)
	r.Send.Mix("ratchet-ss", ss.Bytes())

	return r.Send.Seal("message", ciphertext, plaintext)
}

// ReceiveMessage decrypts the ciphertext and appends the plaintext to dst. It extracts the ephemeral public key,
// performs an ECDH exchange with the local static key, mixes the shared secret into the Recv protocol, and then opens
// the message. It returns an error if the ciphertext is too short or invalid.
func (r *Ratchet) ReceiveMessage(dst, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < Overhead {
		return nil, newplex.ErrInvalidCiphertext
	}

	qE, _ := ristretto255.NewIdentityElement().SetCanonicalBytes(r.Recv.Unmask("ratchet-pk", nil, ciphertext[:32]))
	if qE == nil {
		return nil, newplex.ErrInvalidCiphertext
	}

	ss := ristretto255.NewIdentityElement().ScalarMult(r.Local, qE)
	r.Recv.Mix("ratchet-ss", ss.Bytes())

	return r.Recv.Open("message", dst, ciphertext[32:])
}
