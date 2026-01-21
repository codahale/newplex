package newplex_test

import (
	"bytes"
	"testing"

	"github.com/codahale/newplex"
)

func TestDuplex_Encrypt(t *testing.T) {
	t.Parallel()

	a := []byte("hello world")
	b := make([]byte, len(a))
	c := make([]byte, len(a))

	var d1 newplex.Duplex
	d1.Absorb([]byte("it's a key"))
	d1.Key()
	d1.Encrypt(b, a)

	var d2 newplex.Duplex
	d2.Absorb([]byte("it's a key"))
	d2.Key()
	d2.Decrypt(c, b)

	if got, want := c, a; !bytes.Equal(got, want) {
		t.Errorf("crypt(crypt(%x)) = %x, want = %x", want, got, want)
	}

	if got, want := d2.String(), d1.String(); got != want {
		t.Errorf("state = %x, want = %x", got, want)
	}
}

func TestDuplex_Absorb(t *testing.T) {
	t.Parallel()

	var d1 newplex.Duplex

	d1.Absorb([]byte("one"))
	d1.Absorb([]byte("two"))
	d1.Absorb([]byte("three"))

	var d2 newplex.Duplex
	d2.Absorb([]byte("onetwothree"))

	if got, want := d1.String(), d2.String(); got != want {
		t.Errorf("Absorb('one', 'two', three') = %s, want %s", got, want)
	}
}

func BenchmarkDuplex_Absorb(b *testing.B) {
	for _, length := range lengths {
		b.Run(length.name, func(b *testing.B) {
			var d newplex.Duplex
			input := make([]byte, length.n)
			b.SetBytes(int64(length.n))
			b.ReportAllocs()
			for b.Loop() {
				d.Absorb(input)
			}
		})
	}
}

func BenchmarkDuplex_Squeeze(b *testing.B) {
	for _, length := range lengths {
		b.Run(length.name, func(b *testing.B) {
			var d newplex.Duplex
			output := make([]byte, length.n)
			b.SetBytes(int64(length.n))
			b.ReportAllocs()
			for b.Loop() {
				d.Squeeze(output)
			}
		})
	}
}

func BenchmarkDuplex_Encrypt(b *testing.B) {
	for _, length := range lengths {
		b.Run(length.name, func(b *testing.B) {
			var d newplex.Duplex
			d.Key()

			output := make([]byte, length.n)
			b.SetBytes(int64(length.n))
			b.ReportAllocs()
			for b.Loop() {
				d.Encrypt(output, output)
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
