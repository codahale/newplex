package pake_test

import (
	"fmt"

	"github.com/codahale/newplex/internal/testdata"
	"github.com/codahale/newplex/pake"
)

func Example() {
	drbg := testdata.New("newplex pake")
	r1 := drbg.Data(64)
	r2 := drbg.Data(64)

	// The initiator begins the exchange, generating a callback function and a message to send.
	finish, initiate := pake.Initiate(
		"example",
		[]byte("client"),
		[]byte("server"),
		[]byte("session"),
		[]byte("the bravest toaster"),
		r1,
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
		r2,
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
