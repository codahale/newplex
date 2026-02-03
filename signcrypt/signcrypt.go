// Package signcrypt implements an integrated signcryption scheme using Ristretto255 and Newplex.
package signcrypt

import (
	"bytes"

	"github.com/codahale/newplex"
	"github.com/gtank/ristretto255"
)

func Seal(domain string, dS *ristretto255.Scalar, qR *ristretto255.Element, rand, message []byte) []byte {
	// Initialize the protocol and mix in the sender and receiver's public keys.
	p := newplex.NewProtocol(domain)
	p.Mix("sender", ristretto255.NewIdentityElement().ScalarBaseMult(dS).Bytes())
	p.Mix("receiver", qR.Bytes())

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
	i := ristretto255.NewIdentityElement().ScalarBaseMult(k)

	// Mix in the ephemeral public key.
	p.Mix("ephemeral", qE.Bytes())

	// Mask the message.
	ciphertext := p.Mask("message", qE.Bytes(), message)

	// Mask the commitment point. This a) provides signer confidentiality unless the verifier has both the signer's
	// public key and the message and b) makes the protocol's state dependent on the commitment.
	iOut := p.Mask("commitment", ciphertext, i.Bytes())

	// Derive a challenge scalar from the signer's public key, the message, and the commitment point.
	r, err := ristretto255.NewScalar().SetUniformBytes(p.Derive("challenge", nil, 64))
	if err != nil {
		panic(err)
	}

	// Calculate the proof scalar s = d * r + k and mask it.
	s := ristretto255.NewScalar().Multiply(dS, r)
	s = s.Add(s, k)
	return p.Mask("proof", iOut, s.Bytes())
}

func Open(domain string, dR *ristretto255.Scalar, qS *ristretto255.Element, ciphertext []byte) ([]byte, error) {
	// Initialize the protocol and mix in the sender and receiver's public keys.
	p := newplex.NewProtocol(domain)
	p.Mix("sender", qS.Bytes())
	p.Mix("receiver", ristretto255.NewIdentityElement().ScalarBaseMult(dR).Bytes())

	// Mix in the ephemeral public key and decode it.
	p.Mix("ephemeral", ciphertext[:32])
	qE, _ := ristretto255.NewIdentityElement().SetCanonicalBytes(ciphertext[:32])
	if qE == nil {
		return nil, newplex.ErrInvalidCiphertext
	}

	// Unmask the message.
	plaintext := p.Unmask("message", nil, ciphertext[32:len(ciphertext)-64])

	// Unmask the received commitment point. As we do not use it for calculations, leave it encoded.
	receivedI := p.Unmask("commitment", nil, ciphertext[len(ciphertext)-64:len(ciphertext)-32])

	// Derive an expected challenge scalar from the signer's public key, the message, and the commitment point.
	expectedR, err := ristretto255.NewScalar().SetUniformBytes(p.Derive("challenge", nil, 64))
	if err != nil {
		panic(err)
	}

	// Unmask the proof scalar. If not canonically encoded, the signature is invalid.
	s, _ := ristretto255.NewScalar().SetCanonicalBytes(p.Unmask("proof", nil, ciphertext[len(ciphertext)-32:]))
	if s == nil {
		return nil, newplex.ErrInvalidCiphertext
	}

	// Calculate the expected commitment point: [s]G - [r']Q
	negR := ristretto255.NewScalar().Negate(expectedR)
	expectedI := ristretto255.NewIdentityElement().VarTimeDoubleScalarBaseMult(negR, qS, s)

	// If the received and expected commitment points are equal (as compared in encoded form), the signature is valid.
	if !bytes.Equal(receivedI, expectedI.Bytes()) {
		return nil, newplex.ErrInvalidCiphertext
	}

	return plaintext, nil
}
