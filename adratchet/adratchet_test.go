package adratchet_test

import (
	"fmt"

	"github.com/codahale/newplex"
	"github.com/codahale/newplex/adratchet"
	"github.com/codahale/newplex/internal/testdata"
)

func Example() {
	drbg := testdata.New("newplex async double ratchet")

	// Alice has a private and public key.
	dA, qA := drbg.KeyPair()

	// Bea has a private and public key.
	dB, qB := drbg.KeyPair()

	// Alice and Bea have a shared protocol state, probably thanks to an ECDH handshake.
	p := newplex.NewProtocol("example")
	p.Mix("shared key", []byte("ok then"))

	// Alice forks the shared state into send/recv pairs.
	sendA, recvA := p.Clone(), p.Clone()
	sendA.Mix("sender", []byte("A"))
	recvA.Mix("sender", []byte("B"))

	// Bea forks the shared state into send/recv pairs, matching the inverse of Alice's.
	sendB, recvB := p.Clone(), p.Clone()
	sendB.Mix("sender", []byte("B"))
	recvB.Mix("sender", []byte("A"))

	// Alice sets up an asynchronous double ratchet with the send/recv protocols, her private key, and Bea's public key.
	a := &adratchet.Ratchet{
		Send:   &sendA,
		Recv:   &recvA,
		Local:  dA,
		Remote: qB,
	}

	// Bea sets up an asynchronous double ratchet with the send/recv protocols, her private key, and Alice's public key.
	b := &adratchet.Ratchet{
		Send:   &sendB,
		Recv:   &recvB,
		Local:  dB,
		Remote: qA,
	}

	// Alice sends Bea a message.
	msgA := a.SendMessage(nil, []byte("this is my first message"))

	// Bea sends Alice a message.
	msgB := b.SendMessage(nil, []byte("no, this is _my_ first message"))

	// Alice reads Bea's message.
	v, err := a.ReceiveMessage(nil, msgB)
	if err != nil {
		panic(err)
	}
	fmt.Printf("message from B: %q\n", v)

	// Bea reads Alice's message.
	v, err = b.ReceiveMessage(nil, msgA)
	if err != nil {
		panic(err)
	}
	fmt.Printf("message from A: %q\n", v)

	// Output:
	// message from B: "no, this is _my_ first message"
	// message from A: "this is my first message"
}
