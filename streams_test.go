package newplex_test

import (
	"bytes"
	"io"
	"testing"

	"github.com/codahale/newplex"
)

func TestProtocol_MixReader(t *testing.T) {
	t.Parallel()

	p1 := newplex.NewProtocol("example")
	p1.Mix("key", []byte("onetwothree"))

	p2 := newplex.NewProtocol("example")
	r := p2.MixReader("key", bytes.NewBufferString("onetwothree"))
	buf := bytes.NewBuffer(nil)
	_, err := io.Copy(buf, r)
	if err != nil {
		t.Fatal(err)
	}

	if got, want := buf.String(), "onetwothree"; got != want {
		t.Errorf("Read got = %q, want = %q", got, want)
	}

	if err := r.Close(); err != nil {
		t.Fatal(err)
	}

	if got, want := p2.Derive("third", nil, 8), p1.Derive("third", nil, 8); !bytes.Equal(got, want) {
		t.Errorf("Derive('third') = %x, want = %x", got, want)
	}
}

func TestProtocol_MixWriter(t *testing.T) {
	t.Parallel()

	p1 := newplex.NewProtocol("example")
	p1.Mix("key", []byte("onetwothree"))

	p2 := newplex.NewProtocol("example")
	buf := bytes.NewBuffer(nil)
	w := p2.MixWriter("key", buf)
	if _, err := w.Write([]byte("one")); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("two")); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("three")); err != nil {
		t.Fatal(err)
	}

	if got, want := buf.String(), "onetwothree"; got != want {
		t.Errorf("Read got = %q, want = %q", got, want)
	}

	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	if got, want := p2.Derive("third", nil, 8), p1.Derive("third", nil, 8); !bytes.Equal(got, want) {
		t.Errorf("Derive('third') = %x, want = %x", got, want)
	}
}

func TestProtocol_EncryptReader(t *testing.T) {
	t.Parallel()

	p1 := newplex.NewProtocol("example")
	p1.Mix("key", []byte("onetwothree"))
	r := p1.EncryptReader("message", bytes.NewBufferString("onetwothree"))
	buf := bytes.NewBuffer(nil)
	if _, err := io.CopyBuffer(buf, r, make([]byte, 3)); err != nil {
		t.Fatal(err)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}

	p2 := newplex.NewProtocol("example")
	p2.Mix("key", []byte("onetwothree"))
	message := []byte("onetwothree")
	p2.Encrypt("message", message[:0], message)

	if got, want := buf.Bytes(), message; !bytes.Equal(got, want) {
		t.Errorf("EncryptReader(msg) = %x, want = %x", got, want)
	}

	if got, want := p2.Derive("third", nil, 8), p1.Derive("third", nil, 8); !bytes.Equal(got, want) {
		t.Errorf("Derive('third') = %x, want = %x", got, want)
	}
}

func TestProtocol_EncryptWriter(t *testing.T) {
	t.Parallel()

	p1 := newplex.NewProtocol("example")
	p1.Mix("key", []byte("onetwothree"))
	buf := bytes.NewBuffer(nil)
	w := p1.EncryptWriter("message", buf)
	if _, err := w.Write([]byte("one")); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("two")); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("three")); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	p2 := newplex.NewProtocol("example")
	p2.Mix("key", []byte("onetwothree"))
	message := []byte("onetwothree")
	p2.Encrypt("message", message[:0], message)

	if got, want := buf.Bytes(), message; !bytes.Equal(got, want) {
		t.Errorf("EncryptWriter(msg) = %x, want = %x", got, want)
	}

	if got, want := p2.Derive("third", nil, 8), p1.Derive("third", nil, 8); !bytes.Equal(got, want) {
		t.Errorf("Derive('third') = %x, want = %x", got, want)
	}
}

func TestProtocol_DecryptReader(t *testing.T) {
	p1 := newplex.NewProtocol("example")
	p1.Mix("key", []byte("it's a key"))
	message := []byte("it's a message")
	ciphertext := p1.Encrypt("message", nil, message)

	p2 := newplex.NewProtocol("example")
	p2.Mix("key", []byte("it's a key"))
	r := p2.DecryptReader("message", bytes.NewReader(ciphertext))
	buf := bytes.NewBuffer(nil)
	if _, err := io.CopyBuffer(buf, r, make([]byte, 3)); err != nil {
		t.Fatal(err)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}

	if got, want := buf.Bytes(), message; !bytes.Equal(got, want) {
		t.Errorf("DecryptReader(Encrypt(msg)) = %x, want = %x", got, want)
	}

	if got, want := p2.Derive("third", nil, 8), p1.Derive("third", nil, 8); !bytes.Equal(got, want) {
		t.Errorf("Derive('third') = %x, want = %x", got, want)
	}
}

func TestProtocol_DecryptWriter(t *testing.T) {
	p1 := newplex.NewProtocol("example")
	p1.Mix("key", []byte("it's a key"))
	message := []byte("it's a message")
	ciphertext := p1.Encrypt("message", nil, message)

	p2 := newplex.NewProtocol("example")
	p2.Mix("key", []byte("it's a key"))
	buf := bytes.NewBuffer(nil)
	w := p2.DecryptWriter("message", buf)
	if _, err := io.CopyBuffer(w, bytes.NewReader(ciphertext), make([]byte, 3)); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	if got, want := buf.Bytes(), message; !bytes.Equal(got, want) {
		t.Errorf("DecryptWriter(Encrypt(msg)) = %x, want = %x", got, want)
	}

	if got, want := p2.Derive("third", nil, 8), p1.Derive("third", nil, 8); !bytes.Equal(got, want) {
		t.Errorf("Derive('third') = %x, want = %x", got, want)
	}
}
