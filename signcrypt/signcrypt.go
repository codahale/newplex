// Package signcrypt implements an integrated signcryption scheme using Ristretto255 and Newplex.
package signcrypt

import (
	"bytes"

	"github.com/codahale/newplex"
	"github.com/gtank/ristretto255"
)

// Overhead is the length, in bytes, of the additional data added to a plaintext to produce a signcrypted ciphertext.
const Overhead = 32 + 32 + 32

// Seal encrypts and signs the message to protect its confidentiality and authenticity. Only the owner of the
// receiver's private key can decrypt it, and only the owner of the sender's private key could have sent it.
func Seal(domain string, dS *ristretto255.Scalar, qR *ristretto255.Element, rand, message []byte) []byte {
	// Initialize the protocol and mix in the sender and receiver's public keys.
	p := newplex.NewProtocol(domain)
	p.Mix("receiver", qR.Bytes())
	p.Mix("sender", ristretto255.NewIdentityElement().ScalarBaseMult(dS).Bytes())

	// Clone the protocol and mix in the sender's private key, the user-supplied randomness, and the message. Use the
	// clone to derive an ephemeral private ky and commitment scalar which are unique to the inputs.
	clone := p.Clone()
	clone.Mix("sender-private", dS.Bytes())
	clone.Mix("rand", rand)
	clone.Mix("message", message)
	dE, _ := ristretto255.NewScalar().SetUniformBytes(clone.Derive("ephemeral-private", nil, 64))
	qE := ristretto255.NewIdentityElement().ScalarBaseMult(dE)
	k, err := ristretto255.NewScalar().SetUniformBytes(clone.Derive("commitment", nil, 64))
	if err != nil {
		panic(err)
	}
	r := ristretto255.NewIdentityElement().ScalarBaseMult(k)

	// Mix in the ephemeral public key.
	p.Mix("ephemeral", qE.Bytes())

	// Mix in the ECDH shared secret.
	ss := ristretto255.NewIdentityElement().ScalarMult(dE, qR)
	p.Mix("ecdh", ss.Bytes())

	// Mask the message.
	ciphertext := p.Mask("message", qE.Bytes(), message)

	// Mask the commitment point. This a) provides signer confidentiality unless the verifier has both the signer's
	// public key and the message and b) makes the protocol's state dependent on the commitment.
	sig := p.Mask("commitment", ciphertext, r.Bytes())

	// Derive a challenge scalar from the signer's public key, the message, and the commitment point.
	c, err := ristretto255.NewScalar().SetUniformBytes(p.Derive("challenge", nil, 64))
	if err != nil {
		panic(err)
	}

	// Calculate the proof scalar s = d * c + k and mask it.
	s := ristretto255.NewScalar().Multiply(dS, c)
	s = s.Add(s, k)
	return p.Mask("proof", sig, s.Bytes())
}

// Open decrypts and verifies a ciphertext produced by Seal. Returns either the confidential, authentic plaintext or
// newplex.ErrInvalidCiphertext.
func Open(domain string, dR *ristretto255.Scalar, qS *ristretto255.Element, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < Overhead {
		return nil, newplex.ErrInvalidCiphertext
	}

	// Initialize the protocol and mix in the sender and receiver's public keys.
	p := newplex.NewProtocol(domain)
	p.Mix("receiver", ristretto255.NewIdentityElement().ScalarBaseMult(dR).Bytes())
	p.Mix("sender", qS.Bytes())

	// Mix in the ephemeral public key and decode it.
	p.Mix("ephemeral", ciphertext[:32])
	qE, _ := ristretto255.NewIdentityElement().SetCanonicalBytes(ciphertext[:32])
	if qE == nil {
		return nil, newplex.ErrInvalidCiphertext
	}

	// Mix in the ECDH shared secret.
	ss := ristretto255.NewIdentityElement().ScalarMult(dR, qE)
	p.Mix("ecdh", ss.Bytes())

	// Unmask the message.
	plaintext := p.Unmask("message", nil, ciphertext[32:len(ciphertext)-64])

	// Unmask the received commitment point. As we do not use it for calculations, leave it encoded.
	receivedR := p.Unmask("commitment", nil, ciphertext[len(ciphertext)-64:len(ciphertext)-32])

	// Derive an expected challenge scalar from the signer's public key, the message, and the commitment point.
	expectedC, err := ristretto255.NewScalar().SetUniformBytes(p.Derive("challenge", nil, 64))
	if err != nil {
		panic(err)
	}

	// Unmask the proof scalar. If not canonically encoded, the signature is invalid.
	s, _ := ristretto255.NewScalar().SetCanonicalBytes(p.Unmask("proof", nil, ciphertext[len(ciphertext)-32:]))
	if s == nil {
		return nil, newplex.ErrInvalidCiphertext
	}

	// Calculate the expected commitment point: [s]G - [r']Q
	expectedR := ristretto255.NewIdentityElement().VarTimeDoubleScalarBaseMult(ristretto255.NewScalar().Negate(expectedC), qS, s)

	// If the received and expected commitment points are equal (as compared in encoded form), the signature is valid.
	if !bytes.Equal(receivedR, expectedR.Bytes()) {
		return nil, newplex.ErrInvalidCiphertext
	}

	return plaintext, nil
}
