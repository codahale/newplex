package vrf_test

import (
	"bytes"
	"crypto/sha3"
	"slices"
	"testing"

	"github.com/codahale/newplex/vrf"
	"github.com/gtank/ristretto255"
)

func TestVerify(t *testing.T) {
	drbg := sha3.NewSHAKE128()
	_, _ = drbg.Write([]byte("newplex vrf"))

	var r [64]byte
	_, _ = drbg.Read(r[:])
	d, _ := ristretto255.NewScalar().SetUniformBytes(r[:])
	q := ristretto255.NewIdentityElement().ScalarBaseMult(d)
	_, _ = drbg.Read(r[:])
	prf, proof := vrf.Prove("domain", d, r[:], []byte("message"), 32)

	t.Run("valid", func(t *testing.T) {
		valid, got := vrf.Verify("domain", q, []byte("message"), proof, 32)
		if !valid {
			t.Errorf("should have been valid")
		}

		if want := prf; !bytes.Equal(got, want) {
			t.Errorf("got = %x, want = %x", got, want)
		}
	})

	t.Run("wrong prover", func(t *testing.T) {
		_, _ = drbg.Read(r[:])
		q2, _ := ristretto255.NewIdentityElement().SetUniformBytes(r[:])

		valid, got := vrf.Verify("domain", q2, []byte("message"), proof, 32)
		if valid {
			t.Errorf("should not have been valid")
		}

		if got != nil {
			t.Errorf("got = %x, want = nil", got)
		}
	})

	t.Run("wrong domain", func(t *testing.T) {
		valid, got := vrf.Verify("other domain", q, []byte("message"), proof, 32)
		if valid {
			t.Errorf("should not have been valid")
		}

		if got != nil {
			t.Errorf("got = %x, want = nil", got)
		}
	})

	t.Run("wrong message", func(t *testing.T) {
		valid, got := vrf.Verify("domain", q, []byte("other message"), proof, 32)
		if valid {
			t.Errorf("should not have been valid")
		}

		if got != nil {
			t.Errorf("got = %x, want = nil", got)
		}
	})

	t.Run("wrong length", func(t *testing.T) {
		valid, got := vrf.Verify("domain", q, []byte("message"), proof, 22)
		if valid {
			t.Errorf("should not have been valid")
		}

		if got != nil {
			t.Errorf("got = %x, want = nil", got)
		}
	})

	t.Run("bad c", func(t *testing.T) {
		badC := slices.Clone(proof)
		badC[0] ^= 1

		valid, got := vrf.Verify("domain", q, []byte("message"), badC, 32)
		if valid {
			t.Errorf("should not have been valid")
		}

		if got != nil {
			t.Errorf("got = %x, want = nil", got)
		}
	})

	t.Run("bad r", func(t *testing.T) {
		badR := slices.Clone(proof)
		badR[33] ^= 1

		valid, got := vrf.Verify("domain", q, []byte("message"), badR, 32)
		if valid {
			t.Errorf("should not have been valid")
		}

		if got != nil {
			t.Errorf("got = %x, want = nil", got)
		}
	})

	t.Run("bad gamma", func(t *testing.T) {
		badGamma := slices.Clone(proof)
		badGamma[62] ^= 1

		valid, got := vrf.Verify("domain", q, []byte("message"), badGamma, 32)
		if valid {
			t.Errorf("should not have been valid")
		}

		if got != nil {
			t.Errorf("got = %x, want = nil", got)
		}
	})
}
