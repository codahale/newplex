package pake_test

import (
	"crypto/sha3"
	"fmt"

	"github.com/codahale/newplex/pake"
)

func Example() {
	drbg := sha3.NewSHAKE128()
	_, _ = drbg.Write([]byte("newplex pake"))
	var r1, r2 [64]byte
	_, _ = drbg.Read(r1[:])
	_, _ = drbg.Read(r2[:])

	// The initiator begins the exchange, generating a callback function and a message to send.
	finish, initiate := pake.Initiate(
		"example",
		[]byte("client"),
		[]byte("server"),
		[]byte("session"),
		[]byte("the bravest toaster"),
		r1[:],
	)

	// The initiator sends `initiate` to the responder.

	// The responder receives the message and finishes their side of the exchange, establishing a fully keyed protocol
	// and generating a response message.
	pResponder, response, err := pake.Respond(
		"example",
		[]byte("client"),
		[]byte("server"),
		[]byte("session"),
		[]byte("the bravest toaster"),
		r2[:],
		initiate,
	)
	if err != nil {
		panic(err)
	}

	// The responder sends `response` to the initiator.

	// The initiator finishes their side of the exchange, establishing a fully keyed protocol.
	pInitiator, err := finish(response)
	if err != nil {
		panic(err)
	}

	// Both initiator and responder share a protocol state.
	fmt.Printf("responder: %x\n", pResponder.Derive("state", nil, 16))
	fmt.Printf("initiator: %x\n", pInitiator.Derive("state", nil, 16))

	// Output:
	// responder: 8465a5928381e57cf73d023e19ed4071
	// initiator: 8465a5928381e57cf73d023e19ed4071
}
