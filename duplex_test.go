package newplex_test

import (
	"bytes"
	"fmt"
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
	d1.Permute()
	d1.Encrypt(b, a)

	var d2 newplex.Duplex
	d2.Absorb([]byte("it's a key"))
	d2.Permute()
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

func TestDuplex_Squeeze(t *testing.T) {
	t.Parallel()

	var d1 newplex.Duplex
	d1.Absorb([]byte("input"))
	out1 := make([]byte, 20)
	d1.Squeeze(out1)

	var d2 newplex.Duplex
	d2.Absorb([]byte("input"))
	out2 := make([]byte, 20)
	d2.Squeeze(out2[:10])
	d2.Squeeze(out2[10:])

	if !bytes.Equal(out1, out2) {
		t.Errorf("Squeeze(20) = %x, Squeeze(10)+Squeeze(10) = %x", out1, out2)
	}
}

func TestDuplex_MarshalBinary(t *testing.T) {
	t.Parallel()

	var d1 newplex.Duplex
	d1.Absorb([]byte("input"))

	data, err := d1.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}

	var d2 newplex.Duplex
	if err := d2.UnmarshalBinary(data); err != nil {
		t.Fatal(err)
	}

	if got, want := d2.String(), d1.String(); got != want {
		t.Errorf("UnmarshalBinary(MarshalBinary()) = %s, want %s", got, want)
	}

	// Verify continued operation matches
	out1 := make([]byte, 32)
	d1.Squeeze(out1)

	out2 := make([]byte, 32)
	d2.Squeeze(out2)

	if !bytes.Equal(out1, out2) {
		t.Errorf("Post-restore Squeeze mismatch: %x vs %x", out2, out1)
	}
}

func TestDuplex_UnmarshalBinary_Invalid(t *testing.T) {
	t.Parallel()

	var d newplex.Duplex
	if err := d.UnmarshalBinary([]byte{0x01}); err == nil {
		t.Error("UnmarshalBinary(short) should have failed")
	}
}

func TestDuplex_Decrypt_InPlace(t *testing.T) {
	t.Parallel()

	key := []byte("key")
	plaintext := []byte("hello world")

	// 1. Encrypt first to get valid ciphertext
	var dEnc newplex.Duplex
	dEnc.Absorb(key)
	dEnc.Permute()
	ciphertext := make([]byte, len(plaintext))
	dEnc.Encrypt(ciphertext, plaintext)

	// 2. Decrypt with separate buffers (Correct behavior)
	var dDec1 newplex.Duplex
	dDec1.Absorb(key)
	dDec1.Permute()
	out1 := make([]byte, len(ciphertext))
	dDec1.Decrypt(out1, ciphertext)

	// 3. Decrypt in-place
	var dDec2 newplex.Duplex
	dDec2.Absorb(key)
	dDec2.Permute()
	// Copy ciphertext because it will be overwritten
	buf := make([]byte, len(ciphertext))
	copy(buf, ciphertext)
	dDec2.Decrypt(buf, buf)

	// Verify plaintext recovery
	if !bytes.Equal(out1, plaintext) {
		t.Fatalf("Separate buffer decryption failed")
	}
	if !bytes.Equal(buf, plaintext) {
		t.Fatalf("In-place decryption failed to recover plaintext")
	}

	// Verify state consistency
	if dDec1.String() != dDec2.String() {
		t.Errorf("State mismatch after in-place decryption!\nSeparate: %s\nIn-place: %s", dDec1.String(), dDec2.String())
	}
}

func ExampleDuplex_Absorb() {
	var d newplex.Duplex
	d.Absorb([]byte("example input"))
	d.Permute()

	out := make([]byte, 16)
	d.Squeeze(out)

	fmt.Printf("%x\n", out)
	// Output: f358635df728f485fdd3165bc369fa7c
}

func ExampleDuplex_Encrypt() {
	var d newplex.Duplex
	d.Absorb([]byte("key"))
	d.Permute()

	plaintext := []byte("hello world")
	ciphertext := make([]byte, len(plaintext))
	d.Encrypt(ciphertext, plaintext)

	fmt.Printf("%x\n", ciphertext)

	// To decrypt, we need a fresh duplex state with the same key.
	var d2 newplex.Duplex
	d2.Absorb([]byte("key"))
	d2.Permute()

	decrypted := make([]byte, len(ciphertext))
	d2.Decrypt(decrypted, ciphertext)

	fmt.Printf("%s\n", decrypted)

	// Output:
	// 5d369b4ce12f16bbb778f5
	// hello world
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
			d.Permute()

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
