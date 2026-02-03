package signcrypt_test

import (
	"bytes"
	"crypto/sha3"
	"errors"
	"slices"
	"testing"

	"github.com/codahale/newplex"
	"github.com/codahale/newplex/signcrypt"
	"github.com/gtank/ristretto255"
)

func TestOpen(t *testing.T) {
	r, dS, qS, dR, qR, dX, qX := setup()
	ciphertext := signcrypt.Seal("signcrypt", dS, qR, r, []byte("this is a message"))

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
	r, dS, _, _, qR, _, _ := setup()
	message := []byte("this is a message")
	b.ReportAllocs()
	for b.Loop() {
		signcrypt.Seal("signcrypt", dS, qR, r, message)
	}
}

func BenchmarkOpen(b *testing.B) {
	r, dS, qS, dR, qR, _, _ := setup()
	ciphertext := signcrypt.Seal("signcrypt", dS, qR, r, []byte("this is a message"))

	b.ReportAllocs()
	for b.Loop() {
		_, _ = signcrypt.Open("signcrypt", dR, qS, ciphertext)
	}
}

func FuzzOpen(f *testing.F) {
	r, dS, qS, dR, qR, _, _ := setup()
	ciphertext := signcrypt.Seal("signcrypt", dS, qR, r, []byte("this is a message"))

	badQE := slices.Clone(ciphertext)
	badQE[0] ^= 1

	badCT := slices.Clone(ciphertext)
	badCT[33] ^= 1

	badI := slices.Clone(ciphertext)
	badI[len(badI)-60] ^= 1

	badS := slices.Clone(ciphertext)
	badS[len(badS)-20] ^= 1

	f.Add(badQE)
	f.Add(badCT)
	f.Add(badI)
	f.Add(badS)
	f.Fuzz(func(t *testing.T, modifiedCiphertext []byte) {
		if bytes.Equal(ciphertext, modifiedCiphertext) {
			t.Skip()
		}

		plaintext, err := signcrypt.Open("signcrypt", dR, qS, modifiedCiphertext)
		if !errors.Is(err, newplex.ErrInvalidCiphertext) {
			t.Errorf("decrypted invalid ciphertext: %x/%x/%v", ciphertext, plaintext, err)
		}
	})
}

func setup() ([]byte, *ristretto255.Scalar, *ristretto255.Element, *ristretto255.Scalar, *ristretto255.Element, *ristretto255.Scalar, *ristretto255.Element) {
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
	return r[:], dS, qS, dR, qR, dX, qX
}
