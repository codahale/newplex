package newplex_test

import (
	"bytes"
	"io"
	"testing"

	"github.com/codahale/newplex"
)

func TestProtocol_MixReader(t *testing.T) {
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
		t.Errorf("Read(MixReader(%q) = %q, want = %q", want, got, want)
	}

	if err := r.Close(); err != nil {
		t.Fatal(err)
	}

	if got, want := p2.Derive("final", nil, 8), p1.Derive("final", nil, 8); !bytes.Equal(got, want) {
		t.Errorf("Derive('final', 8) = %x, want = %x", got, want)
	}
}

func TestProtocol_MixWriter(t *testing.T) {
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
		t.Errorf("Read(MixWriter(%q) = %q, want = %q", want, got, want)
	}

	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	if got, want := p2.Derive("final", nil, 8), p1.Derive("final", nil, 8); !bytes.Equal(got, want) {
		t.Errorf("Derive('final', 8) = %x, want = %x", got, want)
	}
}

func TestProtocol_MaskReader(t *testing.T) {
	p1 := newplex.NewProtocol("example")
	p1.Mix("key", []byte("onetwothree"))
	r := p1.MaskReader("message", bytes.NewBufferString("onetwothree"))
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
	p2.Mask("message", message[:0], message)

	if got, want := buf.Bytes(), message; !bytes.Equal(got, want) {
		t.Errorf("MaskReader(msg) = %x, want = %x", got, want)
	}

	if got, want := p2.Derive("final", nil, 8), p1.Derive("final", nil, 8); !bytes.Equal(got, want) {
		t.Errorf("Derive('final', 8) = %x, want = %x", got, want)
	}
}

func TestProtocol_MaskWriter(t *testing.T) {
	t.Run("round trip", func(t *testing.T) {
		p1 := newplex.NewProtocol("example")
		p1.Mix("key", []byte("onetwothree"))
		buf := bytes.NewBuffer(nil)
		w := p1.MaskWriter("message", buf)
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
		p2.Mask("message", message[:0], message)

		if got, want := buf.Bytes(), message; !bytes.Equal(got, want) {
			t.Errorf("MaskWriter(msg) = %x, want = %x", got, want)
		}

		if got, want := p2.Derive("final", nil, 8), p1.Derive("final", nil, 8); !bytes.Equal(got, want) {
			t.Errorf("Derive('final', 8) = %x, want = %x", got, want)
		}
	})
}

func TestProtocol_UnmaskReader(t *testing.T) {
	p1 := newplex.NewProtocol("example")
	p1.Mix("key", []byte("it's a key"))
	message := []byte("it's a message")
	ciphertext := p1.Mask("message", nil, message)

	p2 := newplex.NewProtocol("example")
	p2.Mix("key", []byte("it's a key"))
	r := p2.UnmaskReader("message", bytes.NewReader(ciphertext))
	buf := bytes.NewBuffer(nil)
	if _, err := io.CopyBuffer(buf, r, make([]byte, 3)); err != nil {
		t.Fatal(err)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}

	if got, want := buf.Bytes(), message; !bytes.Equal(got, want) {
		t.Errorf("UnmaskReader(Mask(msg)) = %x, want = %x", got, want)
	}

	if got, want := p2.Derive("final", nil, 8), p1.Derive("final", nil, 8); !bytes.Equal(got, want) {
		t.Errorf("Derive('final', 8) = %x, want = %x", got, want)
	}
}

func TestProtocol_UnmaskWriter(t *testing.T) {
	t.Run("round trip", func(t *testing.T) {
		p1 := newplex.NewProtocol("example")
		p1.Mix("key", []byte("it's a key"))
		message := []byte("it's a message")
		ciphertext := p1.Mask("message", nil, message)

		p2 := newplex.NewProtocol("example")
		p2.Mix("key", []byte("it's a key"))
		buf := bytes.NewBuffer(nil)
		w := p2.UnmaskWriter("message", buf)
		if _, err := io.CopyBuffer(w, bytes.NewReader(ciphertext), make([]byte, 3)); err != nil {
			t.Fatal(err)
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}

		if got, want := buf.Bytes(), message; !bytes.Equal(got, want) {
			t.Errorf("UnmaskWriter(Mask(msg)) = %x, want = %x", got, want)
		}

		if got, want := p2.Derive("final", nil, 8), p1.Derive("final", nil, 8); !bytes.Equal(got, want) {
			t.Errorf("Derive('final', 8) = %x, want = %x", got, want)
		}
	})
}
