// Package sig implements an EdDSA-style Schnorr digital signature scheme using Ristretto255 and Newplex.
package sig

import (
	"bytes"
	"io"

	"github.com/codahale/newplex"
	"github.com/gtank/ristretto255"
)

// Size is the length of a signature in bytes.
const Size = 64

// Sign uses the given Ristretto255 private key and an optional slice of random data to generate a strongly unforgeable
// digital signature of the reader's contents.
//
// Returns any error from the underlying reader.
func Sign(d *ristretto255.Scalar, rand []byte, message io.Reader) ([]byte, error) {
	// Initialize the protocol and mix in the signer's public key and the message.
	p := newplex.NewProtocol("sig")
	p.Mix("signer", ristretto255.NewIdentityElement().ScalarBaseMult(d).Bytes())
	w := p.MixWriter("message", io.Discard)
	_, err := io.Copy(w, message)
	if err != nil {
		return nil, err
	}
	_ = w.Close()

	// Clone the protocol and mix both the signer's private key and the provided random data (if any) into the clone.
	clone := p.Clone()
	clone.Mix("signer-private", d.Bytes())
	clone.Mix("hedged-rand", rand)

	// Use the clone to derive a commitment scalar and commitment point which is guaranteed to be unique for the
	// combination of signer and message. This eliminates the risk of private key recovery via nonce reuse, and the
	// user-provided random data hedges the deterministic scheme against fault attacks.
	k, err := ristretto255.NewScalar().SetUniformBytes(clone.Derive("commitment", nil, 64))
	if err != nil {
		panic(err)
	}
	i := ristretto255.NewIdentityElement().ScalarBaseMult(k)

	// Mask the commitment point. This a) provides signer confidentiality unless the verifier has both the signer's
	// public key and the message and b) makes the protocol's state dependent on the commitment.
	iOut := p.Mask("commitment", nil, i.Bytes())

	// Derive a challenge scalar from the signer's public key, the message, and the commitment point.
	r, err := ristretto255.NewScalar().SetUniformBytes(p.Derive("challenge", nil, 64))
	if err != nil {
		panic(err)
	}

	// Calculate the proof scalar s = d * r + k and mask it.
	s := ristretto255.NewScalar().Multiply(d, r)
	s = s.Add(s, k)
	return p.Mask("proof", iOut, s.Bytes()), nil
}

// Verify uses the given Ristretto255 public key and signature to verify the contents of the given reader. Returns true
// if and only if the signature was made of the message by the holder of the signer's private key.
//
// Returns any error from the underlying reader.
func Verify(q *ristretto255.Element, sig []byte, message io.Reader) (bool, error) {
	// Valid signatures consist of a 32-byte masked point and a 32-byte masked scalar.
	if len(sig) != Size {
		return false, nil
	}

	// Initialize the protocol and mix in the signer's public key and the message.
	p := newplex.NewProtocol("sig")
	p.Mix("signer", q.Bytes())
	w := p.MixWriter("message", io.Discard)
	_, err := io.Copy(w, message)
	if err != nil {
		return false, err
	}
	_ = w.Close()

	// Unmask the received commitment point. As we do not use it for calculations, leave it encoded.
	receivedI := p.Unmask("commitment", nil, sig[:32])

	// Derive an expected challenge scalar from the signer's public key, the message, and the commitment point.
	expectedR, err := ristretto255.NewScalar().SetUniformBytes(p.Derive("challenge", nil, 64))
	if err != nil {
		panic(err)
	}

	// Unmask the proof scalar. If not canonically encoded, the signature is invalid.
	s, _ := ristretto255.NewScalar().SetCanonicalBytes(p.Unmask("proof", nil, sig[32:]))
	if s == nil {
		return false, nil
	}

	// Calculate the expected commitment point: [s]G - [r']Q
	negR := ristretto255.NewScalar().Negate(expectedR)
	expectedI := ristretto255.NewIdentityElement().VarTimeDoubleScalarBaseMult(negR, q, s)

	// If the received and expected commitment points are equal (as compared in encoded form), the signature is valid.
	return bytes.Equal(receivedI, expectedI.Bytes()), nil
}
