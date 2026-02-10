package sig_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/codahale/newplex/internal/testdata"
	"github.com/codahale/newplex/sig"
)

func TestSign(t *testing.T) {
	drbg := testdata.New("newplex digital signature")
	d, q := drbg.KeyPair()
	_, qX := drbg.KeyPair()

	signature, err := sig.Sign("sig", d, drbg.Data(64), strings.NewReader("this is a message"))
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
		valid, err := sig.Verify("sig", qX, signature, strings.NewReader("this is a message"))
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
