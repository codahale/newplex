package oprf_test

import (
	"crypto/sha3"
	"fmt"

	"github.com/codahale/newplex/oprf"
	"github.com/gtank/ristretto255"
)

func Example_oprf() {
	drbg := sha3.NewSHAKE128()
	_, _ = drbg.Write([]byte("newplex oprf"))
	var r [64]byte
	_, _ = drbg.Read(r[:])

	// The server has a private key.
	d, _ := ristretto255.NewScalar().SetUniformBytes(r[:])

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
	// client PRF = ed927cc3f419a3875bb71fcae98d9a30
	// server PRF = ed927cc3f419a3875bb71fcae98d9a30
}
