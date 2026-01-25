package aestream_test

import (
	"bytes"
	"errors"
	"io"
	"testing"

	"github.com/codahale/newplex"
	"github.com/codahale/newplex/aestream"
)

func TestRoundTrip(t *testing.T) {
	p1 := newplex.NewProtocol("example")
	p1.Mix("key", []byte("it's a key"))
	buf := bytes.NewBuffer(nil)
	w := aestream.NewWriter(&p1, buf)
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
	r := aestream.NewReader(&p2, bytes.NewReader(buf.Bytes()))
	b, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}

	if got, want := b, []byte("here's one message; and another"); !bytes.Equal(got, want) {
		t.Errorf("OpenReader(SealWriter(%x)) = %x, want = %x", want, got, want)
	}
}

func TestLargeBlock(t *testing.T) {
	p1 := newplex.NewProtocol("example")
	p1.Mix("key", []byte("it's a key"))
	buf := bytes.NewBuffer(nil)
	w := aestream.NewWriter(&p1, buf)

	data := make([]byte, aestream.MaxBlockSize)
	if _, err := w.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	p2 := newplex.NewProtocol("example")
	p2.Mix("key", []byte("it's a key"))
	r := aestream.NewReader(&p2, bytes.NewReader(buf.Bytes()))
	b, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}

	if len(b) != len(data) {
		t.Errorf("len(b) = %d, want %d", len(b), len(data))
	}
}

func TestTruncation(t *testing.T) {
	p1 := newplex.NewProtocol("example")
	p1.Mix("key", []byte("it's a key"))
	buf := bytes.NewBuffer(nil)
	w := aestream.NewWriter(&p1, buf)
	if _, err := w.Write([]byte("message")); err != nil {
		t.Fatal(err)
	}
	// Do not close w, so no terminal block is written.

	p2 := newplex.NewProtocol("example")
	p2.Mix("key", []byte("it's a key"))
	r := aestream.NewReader(&p2, bytes.NewReader(buf.Bytes()))
	_, err := io.ReadAll(r)
	if err == nil {
		t.Error("expected error on truncated stream, got nil")
	}
}

func TestPartialHeader(t *testing.T) {
	p1 := newplex.NewProtocol("example")
	p1.Mix("key", []byte("it's a key"))
	buf := bytes.NewBuffer(nil)
	w := aestream.NewWriter(&p1, buf)
	if _, err := w.Write([]byte("message")); err != nil {
		t.Fatal(err)
	}
	_ = w.Close()

	// Truncate the buffer so it only has 1 byte of the next block's header
	data := buf.Bytes()
	truncated := data[:len(data)-2] // Remove 2 bytes of the terminal block (which is 3+0+16 = 19 bytes)
	// Wait, terminal block is 3 bytes header + 16 bytes tag.
	// So truncated should have at least 1 byte of the terminal header.

	p2 := newplex.NewProtocol("example")
	p2.Mix("key", []byte("it's a key"))
	r := aestream.NewReader(&p2, bytes.NewReader(truncated))
	_, err := io.ReadAll(r)
	if err == nil {
		t.Error("expected error on truncated header, got nil")
	}
	if err != nil && !errors.Is(err, newplex.ErrInvalidCiphertext) {
		t.Errorf("expected ErrInvalidCiphertext, got %v", err)
	}
}

func BenchmarkWriter(b *testing.B) {
	for _, length := range lengths {
		b.Run(length.name, func(b *testing.B) {
			b.SetBytes(int64(length.n))
			b.ReportAllocs()

			p1 := newplex.NewProtocol("example")
			p1.Mix("key", []byte("it's a key"))
			w := aestream.NewWriter(&p1, io.Discard)
			buf := make([]byte, length.n)

			for b.Loop() {
				if _, err := w.Write(buf); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkReader(b *testing.B) {
	for _, length := range lengths {
		b.Run(length.name, func(b *testing.B) {
			b.SetBytes(int64(length.n))
			b.ReportAllocs()

			p1 := newplex.NewProtocol("example")
			p1.Mix("key", []byte("it's a key"))
			ciphertext := bytes.NewBuffer(make([]byte, 0, length.n))
			w := aestream.NewWriter(&p1, ciphertext)
			buf := make([]byte, length.n)
			_, _ = w.Write(buf)
			_ = w.Close()

			p2 := newplex.NewProtocol("example")
			p2.Mix("key", []byte("it's a key"))

			var p3 newplex.Protocol
			for b.Loop() {
				p3 = p2.Clone()
				r := aestream.NewReader(&p3, bytes.NewReader(ciphertext.Bytes()))
				if _, err := io.CopyBuffer(io.Discard, r, buf); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
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
