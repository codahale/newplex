package oprf_test

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/codahale/newplex/internal/testdata"
	"github.com/codahale/newplex/oprf"
	"github.com/gtank/ristretto255"
)

func Example_oprf() {
	drbg := testdata.New("newplex oprf")

	// The server has a private key.
	d, _ := drbg.KeyPair()

	// The client has a secret input and blinds it.
	input := []byte("this is a sensitive input")
	blind, blindedElement, err := oprf.Blind("example", input)
	if err != nil {
		panic(err)
	}

	// The server evaluates the blinded input.
	evaluatedElement, err := oprf.BlindEvaluate(d, blindedElement)
	if err != nil {
		panic(err)
	}

	// The client finalizes it and derives PRF output.
	clientPRF, err := oprf.Finalize("example", input, blind, evaluatedElement, 16)
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
	// client PRF = 50da8b6cc43e62e3ddb6330eeae200c5
	// server PRF = 50da8b6cc43e62e3ddb6330eeae200c5
}

func TestBlind(t *testing.T) {
	t.Run("basic", func(t *testing.T) {
		blind, blindedElement, err := oprf.Blind("example", []byte("input"))
		if err != nil {
			t.Fatal(err)
		}
		if blind.Equal(ristretto255.NewScalar()) == 1 {
			t.Error("blind should not be zero")
		}
		if blindedElement.Equal(ristretto255.NewIdentityElement()) == 1 {
			t.Error("blindedElement should not be identity")
		}
	})
}

func TestBlindEvaluate(t *testing.T) {
	t.Run("identity blinded element", func(t *testing.T) {
		d := ristretto255.NewScalar()
		blindedElement := ristretto255.NewIdentityElement()
		_, err := oprf.BlindEvaluate(d, blindedElement)
		if err == nil {
			t.Error("should have failed with identity blinded element")
		}
	})
}

func TestFinalize(t *testing.T) {
	t.Run("identity evaluated element", func(t *testing.T) {
		input := []byte("input")
		var b [64]byte
		b[0] = 1
		blind, _ := ristretto255.NewScalar().SetUniformBytes(b[:])
		evaluatedElement := ristretto255.NewIdentityElement()
		_, err := oprf.Finalize("example", input, blind, evaluatedElement, 16)
		if err == nil {
			t.Error("should have failed with identity evaluated element")
		}
	})

	t.Run("zero blind", func(t *testing.T) {
		input := []byte("input")
		blind := ristretto255.NewScalar() // zero
		evaluatedElement := ristretto255.NewGeneratorElement()
		_, err := oprf.Finalize("example", input, blind, evaluatedElement, 16)
		if err == nil {
			t.Error("should have failed with zero blind")
		}
	})
}

func TestEvaluate(t *testing.T) {
	t.Run("zero private key", func(t *testing.T) {
		d := ristretto255.NewScalar() // zero
		input := []byte("input")
		_, err := oprf.Evaluate("example", d, input, 16)
		if err == nil {
			t.Error("should have failed with zero private key (results in identity element)")
		}
	})

	t.Run("consistency", func(t *testing.T) {
		var b [64]byte
		b[0] = 1
		d, _ := ristretto255.NewScalar().SetUniformBytes(b[:])
		input := []byte("input")

		blind, blindedElement, err := oprf.Blind("example", input)
		if err != nil {
			t.Fatal(err)
		}

		evaluatedElement, err := oprf.BlindEvaluate(d, blindedElement)
		if err != nil {
			t.Fatal(err)
		}

		clientPRF, err := oprf.Finalize("example", input, blind, evaluatedElement, 16)
		if err != nil {
			t.Fatal(err)
		}

		serverPRF, err := oprf.Evaluate("example", d, input, 16)
		if err != nil {
			t.Fatal(err)
		}

		if !bytes.Equal(clientPRF, serverPRF) {
			t.Errorf("mismatched PRF: %x != %x", clientPRF, serverPRF)
		}
	})

	t.Run("zero length output", func(t *testing.T) {
		var b [64]byte
		b[0] = 1
		d, _ := ristretto255.NewScalar().SetUniformBytes(b[:])
		input := []byte("input")
		out, err := oprf.Evaluate("example", d, input, 0)
		if err != nil {
			t.Fatal(err)
		}
		if len(out) != 0 {
			t.Errorf("expected empty output, got %d bytes", len(out))
		}
	})

	t.Run("domain separation", func(t *testing.T) {
		var b [64]byte
		b[0] = 1
		d, _ := ristretto255.NewScalar().SetUniformBytes(b[:])
		input := []byte("input")

		out1, _ := oprf.Evaluate("domain1", d, input, 16)
		out2, _ := oprf.Evaluate("domain2", d, input, 16)

		if bytes.Equal(out1, out2) {
			t.Errorf("outputs should be different for different domains: %x == %x", out1, out2)
		}
	})
}
