// Package hpke implements a hybrid public key encryption (HPKE) scheme.
//
// Messages are encrypted using a static-ephemeral Diffie-Hellman shared secret over Ristretto255 as the key. An
// authentication tag is appended to the end of the ciphertext, ensuring that the ciphertext can only be modified by
// someone in possession of either private key.
//
// In the signcryption model (which is suitable for analyzing confidentiality and authenticity in the public key model),
// this scheme is outsider-secure for both confidentiality and authenticity. No attacker only in possession of public
// keys can read plaintexts or forge ciphertexts. It is also insider-secure for confidentiality: an attacker who has
// the sender's private key but not the receiver's private key cannot read plaintexts. It is not, however,
// insider-secure for authenticity. An attacker in possession of the receiver's private key can forge messages from any
// sender whose public key they possess (aka Key Compromise Impersonation).
package hpke

import (
	"github.com/codahale/newplex"
	"github.com/gtank/ristretto255"
)

// Overhead is the size, in bytes, of the additional data added to a message by Seal.
const Overhead = 32 + newplex.TagSize

// Seal encrypts the given plaintext for the owner of the given public key, using the given sender's private key and
// user-provided random data.
func Seal(domain string, qR *ristretto255.Element, dS *ristretto255.Scalar, rand, plaintext []byte) []byte {
	p := newplex.NewProtocol(domain)
	p.Mix("sender", ristretto255.NewIdentityElement().ScalarBaseMult(dS).Bytes())
	p.Mix("receiver", qR.Bytes())

	hedge, sealer := p.Fork("role", "hedge", "sealer")

	hedge.Mix("random", rand)
	hedge.Mix("message", plaintext)
	dE, _ := ristretto255.NewScalar().SetUniformBytes(hedge.Derive("ephemeral", nil, 64))
	qE := ristretto255.NewIdentityElement().ScalarBaseMult(dE)
	ssE := ristretto255.NewIdentityElement().ScalarMult(dE, qR)
	ssS := ristretto255.NewIdentityElement().ScalarMult(dS, qR)

	sealer.Mix("ephemeral", qE.Bytes())
	sealer.Mix("ephemeral ecdh", ssE.Bytes())
	sealer.Mix("static ecdh", ssS.Bytes())
	return sealer.Seal("message", qE.Bytes(), plaintext)
}

// Open decrypts the ciphertext produced by Seal.
func Open(domain string, dR *ristretto255.Scalar, qS *ristretto255.Element, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < Overhead {
		return nil, newplex.ErrInvalidCiphertext
	}

	p := newplex.NewProtocol(domain)
	p.Mix("sender", qS.Bytes())
	p.Mix("receiver", ristretto255.NewIdentityElement().ScalarBaseMult(dR).Bytes())
	_, sealer := p.Fork("role", "hedge", "sealer")

	qE, _ := ristretto255.NewIdentityElement().SetCanonicalBytes(ciphertext[:32])
	if qE == nil {
		return nil, newplex.ErrInvalidCiphertext
	}

	ssE := ristretto255.NewIdentityElement().ScalarMult(dR, qE)
	ssS := ristretto255.NewIdentityElement().ScalarMult(dR, qS)
	sealer.Mix("ephemeral", qE.Bytes())
	sealer.Mix("ephemeral ecdh", ssE.Bytes())
	sealer.Mix("static ecdh", ssS.Bytes())
	return sealer.Open("message", nil, ciphertext[32:])
}
