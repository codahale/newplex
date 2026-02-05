package handshake_test

import (
	"crypto/sha3"
	"fmt"

	"github.com/codahale/newplex/handshake"
	"github.com/gtank/ristretto255"
)

func Example() {
	var r [64]byte
	drbg := sha3.NewSHAKE128()
	_, _ = drbg.Write([]byte("newplex handshake"))

	// Responder has a key pair.
	_, _ = drbg.Read(r[:])
	dRS, _ := ristretto255.NewScalar().SetUniformBytes(r[:])

	// Initiator has a key pair.
	_, _ = drbg.Read(r[:])
	dIS, _ := ristretto255.NewScalar().SetUniformBytes(r[:])

	// Initiator starts a handshake.
	initiatorFinish, out, err := handshake.Initiate("example", dIS, drbg)
	if err != nil {
		panic(err)
	}

	// Initiator sends out to the responder.

	// Responder accepts the handshake and responds.
	responderFinish, out, err := handshake.Respond("example", drbg, dRS, out)
	if err != nil {
		panic(err)
	}

	// Responder sends out to the initiator.

	// Initiator finishes the handshake.
	iSend, iRecv, qRS, out, err := initiatorFinish(out)
	if err != nil {
		panic(err)
	}
	fmt.Printf("responder: %x\n", qRS.Bytes())

	// Initiator sends out to the responder.

	// Responder finishes the handshake.
	rSend, rRecv, qIS, err := responderFinish(out)
	if err != nil {
		panic(err)
	}
	fmt.Printf("initiator: %x\n", qIS.Bytes())

	// Now both the initiator and sender have two synchronized protocols: one for sending, one for receiving.
	fmt.Printf("responder send: %x\n", rSend.Derive("test", nil, 16))
	fmt.Printf("initiator recv: %x\n", iRecv.Derive("test", nil, 16))
	fmt.Printf("initiator send: %x\n", iSend.Derive("test", nil, 16))
	fmt.Printf("responder recv: %x\n", rRecv.Derive("test", nil, 16))

	// Output:
	// responder: 8c7d6822f5ad36aebf115ef5c90ce95147f40ed6bf3dd4953cf92827fbf72c7c
	// initiator: 768d2a68dc4a6f3c8e8a7737044d3d80b6ece637da643bf61abc62893b364575
	// responder send: 6386a90d9772a426effd7e987577f3ff
	// initiator recv: 6386a90d9772a426effd7e987577f3ff
	// initiator send: 3bc57a5b4398169bffbef6a48d16af95
	// responder recv: 3bc57a5b4398169bffbef6a48d16af95
}
