package oprf_test

import (
	"fmt"
	"testing"

	"github.com/codahale/newplex/internal/testdata"
	"github.com/codahale/newplex/oprf"
	"github.com/gtank/ristretto255"
)

func Example_voprf() {
	drbg := testdata.New("newplex voprf")

	// The server has a private key.
	d, q := drbg.KeyPair()

	// The client has a secret input and blinds it.
	input := []byte("this is a sensitive input")
	blind, blindedElement, err := oprf.Blind("example", input)
	if err != nil {
		panic(err)
	}

	// The server evaluates the blinded input and returns a proof.
	evaluatedElement, c, s, err := oprf.VerifiableBlindEvaluate("example", d, blindedElement)
	if err != nil {
		panic(err)
	}

	// The client verifies the proof, finalizes it and derives PRF output.
	clientPRF, err := oprf.VerifiableFinalize("example", input, blind, q, evaluatedElement, blindedElement, c, s, 16)
	if err != nil {
		panic(err)
	}
	fmt.Printf("client PRF = %x\n", clientPRF)

	// If the server gets the input, it can derive the same PRF output.
	serverPRF, err := oprf.Evaluate("example", d, input, 16)
	if err != nil {
		panic(err)
	}
	fmt.Printf("server PRF = %x\n", serverPRF)

	// Output:
	// client PRF = 6abebbd740bea2a56e52bb72ccf3c012
	// server PRF = 6abebbd740bea2a56e52bb72ccf3c012
}

func TestVerifiableFinalize(t *testing.T) {
	t.Run("identity points", func(t *testing.T) {
		input := []byte("this is a sensitive input")
		blind := ristretto255.NewScalar()
		q := ristretto255.NewIdentityElement()
		evaluatedElement := ristretto255.NewIdentityElement()
		blindedElement := ristretto255.NewIdentityElement()
		c := ristretto255.NewScalar()
		s := ristretto255.NewScalar()

		_, err := oprf.VerifiableFinalize("example", input, blind, q, evaluatedElement, blindedElement, c, s, 16)
		if err == nil {
			t.Error("should have failed with identity public key")
		}

		q = ristretto255.NewGeneratorElement()
		_, err = oprf.VerifiableFinalize("example", input, blind, q, evaluatedElement, blindedElement, c, s, 16)
		if err == nil {
			t.Error("should have failed with identity blinded/evaluated elements")
		}
	})
}

func TestVerifiableBlindEvaluate(t *testing.T) {
	t.Run("identity points", func(t *testing.T) {
		d := ristretto255.NewScalar()
		blindedElement := ristretto255.NewIdentityElement()

		_, _, _, err := oprf.VerifiableBlindEvaluate("example", d, blindedElement)
		if err == nil {
			t.Error("should have failed with identity blinded element")
		}
	})
}
