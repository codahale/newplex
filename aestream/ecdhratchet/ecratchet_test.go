package ecdhratchet_test

import (
	"bytes"
	"crypto/sha3"
	"io"
	"testing"

	"github.com/codahale/newplex"
	"github.com/codahale/newplex/aestream"
	"github.com/codahale/newplex/aestream/ecdhratchet"
	"github.com/gtank/ristretto255"
)

func TestRoundTrip(t *testing.T) {
	var z [64]byte
	drbg := sha3.NewSHAKE128()
	_, _ = drbg.Write([]byte("newplex ec Ratchet"))

	_, _ = drbg.Read(z[:])
	dA, _ := ristretto255.NewScalar().SetUniformBytes(z[:])
	qA := ristretto255.NewIdentityElement().ScalarBaseMult(dA)

	_, _ = drbg.Read(z[:])
	dB, _ := ristretto255.NewScalar().SetUniformBytes(z[:])
	qB := ristretto255.NewIdentityElement().ScalarBaseMult(dB)

	p1 := newplex.NewProtocol("example")
	p1.Mix("key", []byte("it's a key"))
	buf := bytes.NewBuffer(nil)
	w := aestream.NewWriter(&p1, buf, aestream.MaxBlockSize)
	var r2 aestream.Ratchet = &ecdhratchet.Ratchet{Receiver: dA, Sender: qB}
	w.Ratchet = r2
	if _, err := w.Write([]byte("here's one message; ")); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("and another")); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	p2 := newplex.NewProtocol("example")
	p2.Mix("key", []byte("it's a key"))
	r := aestream.NewReader(&p2, bytes.NewReader(buf.Bytes()), aestream.MaxBlockSize)
	var r3 aestream.Ratchet = &ecdhratchet.Ratchet{Receiver: dB, Sender: qA}
	r.Ratchet = r3
	b, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}

	if got, want := b, []byte("here's one message; and another"); !bytes.Equal(got, want) {
		t.Errorf("NewReader(NewWriter(%x)) = %x, want = %x", want, got, want)
	}
}
