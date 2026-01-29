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

func TestProtocol_EncryptReader(t *testing.T) {
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

	if got, want := p2.Derive("final", nil, 8), p1.Derive("final", nil, 8); !bytes.Equal(got, want) {
		t.Errorf("Derive('final', 8) = %x, want = %x", got, want)
	}
}

func TestProtocol_EncryptWriter(t *testing.T) {
	t.Run("round trip", func(t *testing.T) {
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

		if got, want := p2.Derive("final", nil, 8), p1.Derive("final", nil, 8); !bytes.Equal(got, want) {
			t.Errorf("Derive('final', 8) = %x, want = %x", got, want)
		}
	})

	t.Run("short writes", func(t *testing.T) {
		msg := []byte("hello world")

		// 1. Successful write in one go
		p1 := newplex.NewProtocol("example")
		buf1 := bytes.NewBuffer(nil)
		w1 := p1.EncryptWriter("msg", buf1)
		_, _ = w1.Write(msg)
		_ = w1.Close()

		// 2. Short write handled internally by cryptWriter
		p2 := newplex.NewProtocol("example")
		buf2 := bytes.NewBuffer(nil)
		sw := &shortWriter{w: buf2, n: 5}
		w2 := p2.EncryptWriter("msg", sw)

		n, err := w2.Write(msg)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if n != len(msg) {
			t.Fatalf("expected n=%d, got %d", len(msg), n)
		}
		_ = w2.Close()

		if !bytes.Equal(buf1.Bytes(), buf2.Bytes()) {
			t.Errorf("Ciphertexts differ!\nWant: %x\nGot:  %x", buf1.Bytes(), buf2.Bytes())
		}

		if got, want := p2.Derive("final", nil, 8), p1.Derive("final", nil, 8); !bytes.Equal(got, want) {
			t.Errorf("Derive('final', 8) = %x, want = %x", got, want)
		}
	})
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

	if got, want := p2.Derive("final", nil, 8), p1.Derive("final", nil, 8); !bytes.Equal(got, want) {
		t.Errorf("Derive('final', 8) = %x, want = %x", got, want)
	}
}

func TestProtocol_DecryptWriter(t *testing.T) {
	t.Run("round trip", func(t *testing.T) {
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

		if got, want := p2.Derive("final", nil, 8), p1.Derive("final", nil, 8); !bytes.Equal(got, want) {
			t.Errorf("Derive('final', 8) = %x, want = %x", got, want)
		}
	})

	t.Run("short writes", func(t *testing.T) {
		msg := []byte("hello world")

		// 1. Successful write in one go
		p1 := newplex.NewProtocol("example")
		buf1 := bytes.NewBuffer(nil)
		w1 := p1.EncryptWriter("msg", buf1)
		_, _ = w1.Write(msg)
		_ = w1.Close()

		// 2. Short write handled internally by cryptWriter
		p2 := newplex.NewProtocol("example")
		buf2 := bytes.NewBuffer(nil)
		sw := &shortWriter{w: buf2, n: 5}
		w2 := p2.DecryptWriter("msg", sw)

		n, err := w2.Write(buf1.Bytes())
		if err != nil {
			t.Fatal(err)
		}
		if n != len(msg) {
			t.Errorf("Write() = %d, want = %d", n, len(msg))
		}
		_ = w2.Close()

		if !bytes.Equal(buf2.Bytes(), msg) {
			t.Errorf("Decrypt(Encrypt(%x)) = %x, want %x", msg, buf2.Bytes(), msg)
		}

		if got, want := p2.Derive("final", nil, 8), p1.Derive("final", nil, 8); !bytes.Equal(got, want) {
			t.Errorf("Derive('final', 8) = %x, want = %x", got, want)
		}
	})
}

type shortWriter struct {
	w io.Writer
	n int
}

func (s *shortWriter) Write(p []byte) (n int, err error) {
	if s.n > 0 {
		limit := min(len(p), s.n)
		n, _ = s.w.Write(p[:limit])
		s.n = 0
		return n, io.ErrShortWrite
	}
	return s.w.Write(p)
}
