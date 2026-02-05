package sig_test

import (
	"crypto/sha3"
	"slices"
	"strings"
	"testing"

	"github.com/codahale/newplex/sig"
	"github.com/gtank/ristretto255"
)

func TestSign(t *testing.T) {
	drbg := sha3.NewSHAKE128()
	_, _ = drbg.Write([]byte("newplex digital signature"))

	var r [64]byte
	_, _ = drbg.Read(r[:])
	d, _ := ristretto255.NewScalar().SetUniformBytes(r[:])
	q := ristretto255.NewIdentityElement().ScalarBaseMult(d)

	_, _ = drbg.Read(r[:])
	signature, err := sig.Sign("sig", d, r[:], strings.NewReader("this is a message"))
	if err != nil {
		t.Fatal(err)
	}

	t.Run("valid", func(t *testing.T) {
		valid, err := sig.Verify("sig", q, signature, strings.NewReader("this is a message"))
		if err != nil {
			t.Fatal(err)
		}

		if !valid {
			t.Errorf("should have been valid")
		}
	})

	t.Run("wrong signer", func(t *testing.T) {
		q2, _ := ristretto255.NewIdentityElement().SetUniformBytes(r[:])
		valid, err := sig.Verify("sig", q2, signature, strings.NewReader("this is a message"))
		if err != nil {
			t.Fatal(err)
		}

		if valid {
			t.Errorf("should not have been valid")
		}
	})

	t.Run("wrong message", func(t *testing.T) {
		valid, err := sig.Verify("sig", q, signature, strings.NewReader("this is another message"))
		if err != nil {
			t.Fatal(err)
		}

		if valid {
			t.Errorf("should not have been valid")
		}
	})

	t.Run("wrong I", func(t *testing.T) {
		badI := slices.Clone(signature)
		badI[0] ^= 1
		valid, err := sig.Verify("sig", q, badI, strings.NewReader("this is a message"))
		if err != nil {
			t.Fatal(err)
		}

		if valid {
			t.Errorf("should not have been valid")
		}
	})

	t.Run("wrong s", func(t *testing.T) {
		badS := slices.Clone(signature)
		badS[34] ^= 1
		valid, err := sig.Verify("sig", q, badS, strings.NewReader("this is a message"))
		if err != nil {
			t.Fatal(err)
		}

		if valid {
			t.Errorf("should not have been valid")
		}
	})
}
