package signcrypt_test

import (
	"bytes"
	"crypto/sha3"
	"slices"
	"testing"

	"github.com/codahale/newplex/signcrypt"
	"github.com/gtank/ristretto255"
)

func TestOpen(t *testing.T) {
	drbg := sha3.NewSHAKE128()
	_, _ = drbg.Write([]byte("newplex signcryption"))

	var r [64]byte
	_, _ = drbg.Read(r[:])
	dS, _ := ristretto255.NewScalar().SetUniformBytes(r[:])
	qS := ristretto255.NewIdentityElement().ScalarBaseMult(dS)

	_, _ = drbg.Read(r[:])
	dR, _ := ristretto255.NewScalar().SetUniformBytes(r[:])
	qR := ristretto255.NewIdentityElement().ScalarBaseMult(dR)

	_, _ = drbg.Read(r[:])
	dX, _ := ristretto255.NewScalar().SetUniformBytes(r[:])
	qX := ristretto255.NewIdentityElement().ScalarBaseMult(dX)

	_, _ = drbg.Read(r[:])
	ciphertext := signcrypt.Seal("signcrypt", dS, qR, r[:], []byte("this is a message"))

	t.Run("valid", func(t *testing.T) {
		plaintext, err := signcrypt.Open("signcrypt", dR, qS, ciphertext)
		if err != nil {
			t.Fatal(err)
		}

		if got, want := plaintext, []byte("this is a message"); !bytes.Equal(got, want) {
			t.Errorf("Open(Seal(%x)) = %x, want = %x", want, got, want)
		}
	})

	t.Run("wrong receiver", func(t *testing.T) {
		plaintext, err := signcrypt.Open("signcrypt", dX, qS, ciphertext)
		if err == nil {
			t.Errorf("should not have been valid, unsigncrypted = %x", plaintext)
		}
	})

	t.Run("wrong sender", func(t *testing.T) {
		plaintext, err := signcrypt.Open("signcrypt", dR, qX, ciphertext)
		if err == nil {
			t.Errorf("should not have been valid, unsigncrypted = %x", plaintext)
		}
	})

	t.Run("invalid ephemeral public key", func(t *testing.T) {
		badQE := slices.Clone(ciphertext)
		badQE[0] ^= 1
		plaintext, err := signcrypt.Open("signcrypt", dR, qS, badQE)
		if err == nil {
			t.Errorf("should not have been valid, unsigncrypted = %x", plaintext)
		}
	})

	t.Run("invalid message", func(t *testing.T) {
		badM := slices.Clone(ciphertext)
		badM[33] ^= 1
		plaintext, err := signcrypt.Open("signcrypt", dR, qS, badM)
		if err == nil {
			t.Errorf("should not have been valid, unsigncrypted = %x", plaintext)
		}
	})

	t.Run("invalid I", func(t *testing.T) {
		badI := slices.Clone(ciphertext)
		badI[len(badI)-61] ^= 1
		plaintext, err := signcrypt.Open("signcrypt", dR, qS, badI)
		if err == nil {
			t.Errorf("should not have been valid, unsigncrypted = %x", plaintext)
		}
	})

	t.Run("invalid s", func(t *testing.T) {
		badS := slices.Clone(ciphertext)
		badS[len(badS)-30] ^= 1
		plaintext, err := signcrypt.Open("signcrypt", dR, qS, badS)
		if err == nil {
			t.Errorf("should not have been valid, unsigncrypted = %x", plaintext)
		}
	})
}

func BenchmarkSeal(b *testing.B) {
	drbg := sha3.NewSHAKE128()
	_, _ = drbg.Write([]byte("newplex signcryption"))

	var r [64]byte
	_, _ = drbg.Read(r[:])
	dS, _ := ristretto255.NewScalar().SetUniformBytes(r[:])

	_, _ = drbg.Read(r[:])
	dR, _ := ristretto255.NewScalar().SetUniformBytes(r[:])
	qR := ristretto255.NewIdentityElement().ScalarBaseMult(dR)

	_, _ = drbg.Read(r[:])

	message := []byte("this is a message")
	b.ReportAllocs()
	for b.Loop() {
		signcrypt.Seal("signcrypt", dS, qR, r[:], message)
	}
}

func BenchmarkOpen(b *testing.B) {
	drbg := sha3.NewSHAKE128()
	_, _ = drbg.Write([]byte("newplex signcryption"))

	var r [64]byte
	_, _ = drbg.Read(r[:])
	dS, _ := ristretto255.NewScalar().SetUniformBytes(r[:])
	qS := ristretto255.NewIdentityElement().ScalarBaseMult(dS)

	_, _ = drbg.Read(r[:])
	dR, _ := ristretto255.NewScalar().SetUniformBytes(r[:])
	qR := ristretto255.NewIdentityElement().ScalarBaseMult(dR)

	_, _ = drbg.Read(r[:])
	ciphertext := signcrypt.Seal("signcrypt", dS, qR, r[:], []byte("this is a message"))

	b.ReportAllocs()
	for b.Loop() {
		_, _ = signcrypt.Open("signcrypt", dR, qS, ciphertext)
	}
}
