package aestream_test

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"testing"

	"github.com/codahale/newplex"
	"github.com/codahale/newplex/aestream"
)

//nolint:gocognit // nested tests
func TestNewWriter(t *testing.T) {
	t.Run("round trip", func(t *testing.T) {
		p1 := newplex.NewProtocol("example")
		p1.Mix("key", []byte("it's a key"))
		buf := bytes.NewBuffer(nil)
		w := aestream.NewWriter(&p1, buf, aestream.MaxBlockSize)
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
		b, err := io.ReadAll(r)
		if err != nil {
			t.Fatal(err)
		}

		if got, want := b, []byte("here's one message; and another"); !bytes.Equal(got, want) {
			t.Errorf("NewReader(NewWriter(%x)) = %x, want = %x", want, got, want)
		}
	})

	t.Run("io.Copy", func(t *testing.T) {
		p1 := newplex.NewProtocol("example")
		p1.Mix("key", []byte("it's a key"))
		buf := bytes.NewBuffer(nil)
		w := aestream.NewWriter(&p1, buf, aestream.MaxBlockSize)
		message := make([]byte, 2345)
		n, err := io.CopyBuffer(w, bytes.NewReader(message), make([]byte, 100))
		if err != nil {
			t.Fatal(err)
		}
		if got, want := n, int64(len(message)); got != want {
			t.Errorf("Copy(aestream, buf) = %d bytes, want = %d", got, want)
		}
		err = w.Close()
		if err != nil {
			t.Fatal(err)
		}

		p2 := newplex.NewProtocol("example")
		p2.Mix("key", []byte("it's a key"))
		r := aestream.NewReader(&p2, bytes.NewReader(buf.Bytes()), aestream.MaxBlockSize)
		b, err := io.ReadAll(r)
		if err != nil {
			t.Fatal(err)
		}

		if got, want := b, message; !bytes.Equal(got, want) {
			t.Errorf("NewReader(NewWriter(%x)) = %x, want = %x", want, got, want)
		}
	})

	t.Run("empty write", func(t *testing.T) {
		p1 := newplex.NewProtocol("example")
		p1.Mix("key", []byte("it's a key"))
		buf := bytes.NewBuffer(nil)
		w := aestream.NewWriter(&p1, buf, aestream.MaxBlockSize)

		if _, err := w.Write([]byte("first")); err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte{}); err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte("second")); err != nil {
			t.Fatal(err)
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}

		p2 := newplex.NewProtocol("example")
		p2.Mix("key", []byte("it's a key"))
		r := aestream.NewReader(&p2, bytes.NewReader(buf.Bytes()), aestream.MaxBlockSize)
		b, err := io.ReadAll(r)
		if err != nil {
			t.Fatal(err)
		}

		if got, want := string(b), "firstsecond"; got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})

	t.Run("invalid block size", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Errorf("The code did not panic")
			}
		}()

		p := newplex.NewProtocol("example")
		aestream.NewWriter(&p, io.Discard, 0)
	})
}

func TestNewReader(t *testing.T) {
	t.Run("truncation", func(t *testing.T) {
		p1 := newplex.NewProtocol("example")
		p1.Mix("key", []byte("it's a key"))
		buf := bytes.NewBuffer(nil)
		w := aestream.NewWriter(&p1, buf, aestream.MaxBlockSize)
		if _, err := w.Write([]byte("message")); err != nil {
			t.Fatal(err)
		}
		// Do not close w, so no terminal block is written.

		p2 := newplex.NewProtocol("example")
		p2.Mix("key", []byte("it's a key"))
		r := aestream.NewReader(&p2, bytes.NewReader(buf.Bytes()), aestream.MaxBlockSize)
		_, err := io.ReadAll(r)
		if err == nil {
			t.Error("expected error on truncated stream, got nil")
		}
	})

	t.Run("partial header", func(t *testing.T) {
		p1 := newplex.NewProtocol("example")
		p1.Mix("key", []byte("it's a key"))
		buf := bytes.NewBuffer(nil)
		w := aestream.NewWriter(&p1, buf, aestream.MaxBlockSize)
		if _, err := w.Write([]byte("message")); err != nil {
			t.Fatal(err)
		}
		_ = w.Close()

		data := buf.Bytes()
		truncated := data[:len(data)-2]

		p2 := newplex.NewProtocol("example")
		p2.Mix("key", []byte("it's a key"))
		r := aestream.NewReader(&p2, bytes.NewReader(truncated), aestream.MaxBlockSize)
		_, err := io.ReadAll(r)
		if err == nil {
			t.Error("expected error on truncated header, got nil")
		}
		if err != nil && !errors.Is(err, newplex.ErrInvalidCiphertext) {
			t.Errorf("expected ErrInvalidCiphertext, got %v", err)
		}
	})

	t.Run("large block", func(t *testing.T) {
		p1 := newplex.NewProtocol("example")
		p1.Mix("key", []byte("it's a key"))
		buf := bytes.NewBuffer(nil)
		w := aestream.NewWriter(&p1, buf, aestream.MaxBlockSize)
		if _, err := w.Write([]byte("message")); err != nil {
			t.Fatal(err)
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}

		p2 := newplex.NewProtocol("example")
		p2.Mix("key", []byte("it's a key"))
		// Set max block size smaller than "message" length (7 bytes)
		r := aestream.NewReader(&p2, bytes.NewReader(buf.Bytes()), 6)
		_, err := io.ReadAll(r)
		if err == nil {
			t.Error("expected error on block too large, got nil")
		}
		if !errors.Is(err, aestream.ErrBlockTooLarge) {
			t.Errorf("expected ErrBlockTooLarge, got %v", err)
		}
	})
}

func BenchmarkNewWriter(b *testing.B) {
	for _, length := range lengths {
		b.Run(length.name, func(b *testing.B) {
			b.SetBytes(int64(length.n))
			b.ReportAllocs()

			p1 := newplex.NewProtocol("example")
			p1.Mix("key", []byte("it's a key"))
			w := aestream.NewWriter(&p1, io.Discard, aestream.MaxBlockSize)
			buf := make([]byte, length.n)

			for b.Loop() {
				if _, err := w.Write(buf); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkNewReader(b *testing.B) {
	// This is really only useful for compensating for the inability to remove setup costs from BenchmarkReader.
	for _, length := range lengths {
		b.Run(length.name, func(b *testing.B) {
			b.ReportAllocs()

			p1 := newplex.NewProtocol("example")
			p1.Mix("key", []byte("it's a key"))
			ciphertext := bytes.NewBuffer(make([]byte, 0, length.n))
			w := aestream.NewWriter(&p1, ciphertext, aestream.MaxBlockSize)
			buf := make([]byte, length.n)
			_, _ = w.Write(buf)
			_ = w.Close()

			p2 := newplex.NewProtocol("example")
			p2.Mix("key", []byte("it's a key"))

			var p3 newplex.Protocol
			for b.Loop() {
				p3 = p2.Clone()
				aestream.NewReader(&p3, bytes.NewReader(ciphertext.Bytes()), aestream.MaxBlockSize)
			}
		})
	}
}

func BenchmarkNewReader_Read(b *testing.B) {
	for _, length := range lengths {
		b.Run(length.name, func(b *testing.B) {
			b.SetBytes(int64(length.n))
			b.ReportAllocs()

			p1 := newplex.NewProtocol("example")
			p1.Mix("key", []byte("it's a key"))
			ciphertext := bytes.NewBuffer(make([]byte, 0, length.n))
			w := aestream.NewWriter(&p1, ciphertext, aestream.MaxBlockSize)
			buf := make([]byte, length.n)
			_, _ = w.Write(buf)
			_ = w.Close()

			p2 := newplex.NewProtocol("example")
			p2.Mix("key", []byte("it's a key"))

			var p3 newplex.Protocol
			for b.Loop() {
				p3 = p2.Clone()
				r := aestream.NewReader(&p3, bytes.NewReader(ciphertext.Bytes()), aestream.MaxBlockSize)
				if _, err := io.CopyBuffer(io.Discard, r, buf); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func Example() {
	encrypt := func(key, plaintext []byte) []byte {
		// Initialize a protocol with a domain string.
		p := newplex.NewProtocol("com.example.aestream")

		// Mix the key into the protocol.
		p.Mix("key", key)

		// Create a buffer to hold the ciphertext.
		ciphertext := bytes.NewBuffer(nil)

		// Create a streaming authenticated encryption writer.
		w := aestream.NewWriter(&p, ciphertext, aestream.MaxBlockSize)

		// Write the plaintext to the writer.
		if _, err := w.Write(plaintext); err != nil {
			panic(err)
		}

		// Close the writer to flush the final block.
		if err := w.Close(); err != nil {
			panic(err)
		}

		return ciphertext.Bytes()
	}

	decrypt := func(key, ciphertext []byte) ([]byte, error) {
		// Initialize a protocol with a domain string.
		p := newplex.NewProtocol("com.example.aestream")

		// Mix the key into the protocol.
		p.Mix("key", key)

		// Create a streaming authenticated encryption reader.
		r := aestream.NewReader(&p, bytes.NewReader(ciphertext), aestream.MaxBlockSize)

		// Read the plaintext from the reader.
		plaintext, err := io.ReadAll(r)
		if err != nil {
			return nil, err
		}

		// Finally, return the plaintext.
		return plaintext, nil
	}

	key := []byte("my-secret-key")
	plaintext := []byte("hello world")

	ciphertext := encrypt(key, plaintext)
	fmt.Printf("ciphertext = %x\n", ciphertext)

	plaintext, err := decrypt(key, ciphertext)
	if err != nil {
		panic(err)
	}
	fmt.Printf("plaintext  = %s\n", plaintext)

	// Output:
	// ciphertext = 7337be7238443b8e8791818c8f50c38f4856a50e265f9c3fdc5d5ab624babae5e8e35f2ba4e8ed522a5b63603490c69ea40402da9ca0362ad4c8ad9bbfd4a5d04096b4f09afadbc816c7d7cc660fad1fac
	// plaintext  = hello world
}

//nolint:gochecknoglobals // this is fine
var lengths = []struct {
	name string
	n    int
}{
	{"16B", 16},
	{"32B", 32},
	{"64B", 64},
	{"128B", 128},
	{"256B", 256},
	{"1KiB", 1024},
	{"16KiB", 16 * 1024},
	{"1MiB", 1024 * 1024},
}
