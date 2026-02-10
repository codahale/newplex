package ecdhratchet_test

import (
	"bytes"
	"io"
	"testing"

	"github.com/codahale/newplex"
	"github.com/codahale/newplex/aestream"
	"github.com/codahale/newplex/aestream/ecdhratchet"
	"github.com/codahale/newplex/internal/testdata"
)

func TestRoundTrip(t *testing.T) {
	drbg := testdata.New("newplex ec ratchet")
	dA, qA := drbg.KeyPair()
	dB, qB := drbg.KeyPair()

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
