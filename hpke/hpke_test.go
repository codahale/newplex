package hpke_test

import (
	"bytes"
	"crypto/sha3"
	"slices"
	"testing"

	"github.com/codahale/newplex/hpke"
	"github.com/gtank/ristretto255"
)

func TestOpen(t *testing.T) {
	drbg := sha3.NewSHAKE128()
	_, _ = drbg.Write([]byte("newplex hpke"))

	var r [64]byte
	_, _ = drbg.Read(r[:])
	dR, _ := ristretto255.NewScalar().SetUniformBytes(r[:])
	qR := ristretto255.NewIdentityElement().ScalarBaseMult(dR)

	_, _ = drbg.Read(r[:])
	dS, _ := ristretto255.NewScalar().SetUniformBytes(r[:])
	qS := ristretto255.NewIdentityElement().ScalarBaseMult(dS)

	_, _ = drbg.Read(r[:])
	dX, _ := ristretto255.NewScalar().SetUniformBytes(r[:])
	qX := ristretto255.NewIdentityElement().ScalarBaseMult(dX)

	_, _ = drbg.Read(r[:])

	message := []byte("this is a message")
	ciphertext := hpke.Seal("hpke", qR, dS, r[:], message)

	t.Run("round trip", func(t *testing.T) {
		plaintext, err := hpke.Open("hpke", dR, qS, ciphertext)
		if err != nil {
			t.Fatal(err)
		}

		if got, want := plaintext, message; !bytes.Equal(plaintext, message) {
			t.Errorf("Open(Seal(%x)) = %x", want, got)
		}
	})

	t.Run("wrong receiver", func(t *testing.T) {
		plaintext, err := hpke.Open("hpke", dX, qS, ciphertext)
		if err == nil {
			t.Errorf("Open = %x, want = ErrInvalidCiphertext", plaintext)
		}
	})

	t.Run("wrong sender", func(t *testing.T) {
		plaintext, err := hpke.Open("hpke", dR, qX, ciphertext)
		if err == nil {
			t.Errorf("Open = %x, want = ErrInvalidCiphertext", plaintext)
		}
	})

	t.Run("bad qE", func(t *testing.T) {
		badQE := slices.Clone(ciphertext)
		badQE[2] ^= 1

		plaintext, err := hpke.Open("hpke", dR, qS, badQE)
		if err == nil {
			t.Errorf("Open = %x, want = ErrInvalidCiphertext", plaintext)
		}
	})

	t.Run("bad ciphertext", func(t *testing.T) {
		badCT := slices.Clone(ciphertext)
		badCT[34] ^= 1

		plaintext, err := hpke.Open("hpke", dR, qS, badCT)
		if err == nil {
			t.Errorf("Open = %x, want = ErrInvalidCiphertext", plaintext)
		}
	})

	t.Run("bad tag", func(t *testing.T) {
		badTag := slices.Clone(ciphertext)
		badTag[len(badTag)-2] ^= 1

		plaintext, err := hpke.Open("hpke", dR, qS, badTag)
		if err == nil {
			t.Errorf("Open = %x, want = ErrInvalidCiphertext", plaintext)
		}
	})
}

func FuzzOpen(f *testing.F) {
	drbg := sha3.NewSHAKE128()
	_, _ = drbg.Write([]byte("newplex hpke"))

	var r [64]byte
	_, _ = drbg.Read(r[:])
	dR, _ := ristretto255.NewScalar().SetUniformBytes(r[:])
	qR := ristretto255.NewIdentityElement().ScalarBaseMult(dR)

	_, _ = drbg.Read(r[:])
	dS, _ := ristretto255.NewScalar().SetUniformBytes(r[:])
	qS := ristretto255.NewIdentityElement().ScalarBaseMult(dS)

	_, _ = drbg.Read(r[:])

	ciphertext := hpke.Seal("hpke", qR, dS, r[:], []byte("this is a message"))

	badQE := slices.Clone(ciphertext)
	badQE[2] ^= 1
	f.Add(badQE)

	badCT := slices.Clone(ciphertext)
	badCT[34] ^= 1
	f.Add(badCT)

	badTag := slices.Clone(ciphertext)
	badTag[len(badTag)-2] ^= 1
	f.Add(badTag)

	f.Fuzz(func(t *testing.T, ct []byte) {
		if bytes.Equal(ct, ciphertext) {
			t.Skip()
		}

		plaintext, err := hpke.Open("hpke", dR, qS, ct)
		if err == nil {
			t.Errorf("Open = %x, want = ErrInvalidCiphertext", plaintext)
		}
	})
}
