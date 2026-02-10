package adratchet_test

import (
	"bytes"
	"errors"
	"fmt"
	"testing"

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

func TestSendMessage(t *testing.T) {
	t.Run("appends to dst", func(t *testing.T) {
		drbg := testdata.New("newplex async double ratchet")
		dA, _ := drbg.KeyPair()
		_, qB := drbg.KeyPair()

		p := newplex.NewProtocol("example")
		p.Mix("shared key", []byte("ok then"))
		sendA := p.Clone()
		sendA.Mix("sender", []byte("A"))
		recvA := p.Clone()
		recvA.Mix("sender", []byte("B"))

		a := &adratchet.Ratchet{
			Send:   &sendA,
			Recv:   &recvA,
			Local:  dA,
			Remote: qB,
		}

		dst := []byte("existing")
		msg := a.SendMessage(dst, []byte("hello"))
		if !bytes.HasPrefix(msg, dst) {
			t.Errorf("expected prefix %x, got %x", dst, msg)
		}
		expectedLen := len(dst) + len("hello") + adratchet.Overhead
		if len(msg) != expectedLen {
			t.Errorf("expected length %d, got %d", expectedLen, len(msg))
		}
	})
}

func TestReceiveMessage(t *testing.T) {
	setup := func() (*adratchet.Ratchet, *adratchet.Ratchet) {
		drbg := testdata.New("newplex async double ratchet")
		dA, qA := drbg.KeyPair()
		dB, qB := drbg.KeyPair()

		p := newplex.NewProtocol("example")
		p.Mix("shared key", []byte("ok then"))

		sendA, recvA := p.Clone(), p.Clone()
		sendA.Mix("sender", []byte("A"))
		recvA.Mix("sender", []byte("B"))

		sendB, recvB := p.Clone(), p.Clone()
		sendB.Mix("sender", []byte("B"))
		recvB.Mix("sender", []byte("A"))
		a := &adratchet.Ratchet{Send: &sendA, Recv: &recvA, Local: dA, Remote: qB}
		b := &adratchet.Ratchet{Send: &sendB, Recv: &recvB, Local: dB, Remote: qA}
		return a, b
	}

	t.Run("successful round trip", func(t *testing.T) {
		a, b := setup()
		msg := a.SendMessage(nil, []byte("hello"))
		out, err := b.ReceiveMessage(nil, msg)
		if err != nil {
			t.Fatalf("ReceiveMessage failed: %v", err)
		}
		if !bytes.Equal(out, []byte("hello")) {
			t.Errorf("expected %q, got %q", "hello", out)
		}
	})

	t.Run("short ciphertext", func(t *testing.T) {
		a, _ := setup()
		_, err := a.ReceiveMessage(nil, make([]byte, adratchet.Overhead-1))
		if !errors.Is(err, newplex.ErrInvalidCiphertext) {
			t.Errorf("expected ErrInvalidCiphertext, got %v", err)
		}
	})

	t.Run("invalid tag", func(t *testing.T) {
		a, b := setup()
		msg := a.SendMessage(nil, []byte("hello"))
		msg[len(msg)-1] ^= 1
		_, err := b.ReceiveMessage(nil, msg)
		if !errors.Is(err, newplex.ErrInvalidCiphertext) {
			t.Errorf("expected ErrInvalidCiphertext, got %v", err)
		}
	})

	t.Run("out of order", func(t *testing.T) {
		a, b := setup()
		_ = a.SendMessage(nil, []byte("first"))
		msg2 := a.SendMessage(nil, []byte("second"))

		_, err := b.ReceiveMessage(nil, msg2)
		if err == nil {
			t.Error("should have failed to receive out-of-order message")
		}
	})

	t.Run("wrong keys", func(t *testing.T) {
		a, b := setup()
		drbg := testdata.New("wrong keys")
		wrongD, _ := drbg.KeyPair()
		b.Local = wrongD // B has wrong local key

		msg := a.SendMessage(nil, []byte("hello"))
		_, err := b.ReceiveMessage(nil, msg)
		if err == nil {
			t.Error("should have failed with wrong local key")
		}
	})
}
