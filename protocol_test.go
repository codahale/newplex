package newplex_test

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/codahale/newplex"
)

func TestKnownAnswers(t *testing.T) {
	protocol := newplex.NewProtocol("com.example.kat")
	protocol.Mix("first", []byte("one"))
	protocol.Mix("second", []byte("two"))

	if got, want := hex.EncodeToString(protocol.Derive("third", nil, 8)), "05f09801216ea9d1"; got != want {
		t.Errorf("Derive('third') = %v, want = %v", got, want)
	}

	plaintext := []byte("this is an example")
	ciphertext := protocol.Encrypt("fourth", nil, plaintext)
	if got, want := hex.EncodeToString(ciphertext), "da0b8cacd3b9c16f0447b9ead5ededb11ae3"; got != want {
		t.Errorf("Encrypt('fourth') = %v, want = %v", got, want)
	}

	ciphertext = protocol.Seal("fifth", nil, []byte("this is an example"))
	if got, want := hex.EncodeToString(ciphertext), "fe05d9f43d40a8050650e9e203bff0728eba91583453b14aa3faa270254cdb2d6ba2"; got != want {
		t.Errorf("Seal('fifth') = %v, want = %v", got, want)
	}

	if got, want := hex.EncodeToString(protocol.Derive("sixth", nil, 8)), "58e60e022a1612fe"; got != want {
		t.Errorf("Derive('sixth') = %v, want = %v", got, want)
	}
}

func TestProtocol_EmptyInputs(t *testing.T) {
	p := newplex.NewProtocol("empty-test")
	p.Mix("", nil)
	p.Mix("label", nil)
	p.Mix("", []byte("value"))

	p1 := p.Clone()
	out := p1.Derive("", nil, 0)
	if len(out) != 0 {
		t.Errorf("Derive(0) returned %d bytes", len(out))
	}

	p2 := p.Clone()
	ct := p2.Encrypt("enc", nil, nil)
	if len(ct) != 0 {
		t.Errorf("Encrypt(nil) returned %d bytes", len(ct))
	}

	// Encrypt(nil) -> nil ciphertext.
	// Decrypt(nil) should work on that.
	p3 := p.Clone()
	pt := p3.Decrypt("enc", nil, nil)
	if len(pt) != 0 {
		t.Errorf("Decrypt(nil) returned %d bytes", len(pt))
	}

	pSeal := p.Clone()
	sealed := pSeal.Seal("seal", nil, nil)
	if len(sealed) != newplex.TagSize {
		t.Errorf("Seal(nil) returned %d bytes, want %d", len(sealed), newplex.TagSize)
	}

	// Open needs the state before Seal.
	pOpen := p.Clone()
	opened, err := pOpen.Open("seal", nil, sealed)
	if err != nil {
		t.Errorf("Open(Seal(nil)) failed: %v", err)
	}
	if len(opened) != 0 {
		t.Errorf("Open(Seal(nil)) returned %d bytes", len(opened))
	}
}

func TestProtocol_Clone(t *testing.T) {
	p1 := newplex.NewProtocol("example")
	p1.Mix("a thing", []byte("another thing"))
	p2 := p1.Clone()

	if got, want := p2.Derive("third", nil, 8), p1.Derive("third", nil, 8); !bytes.Equal(got, want) {
		t.Errorf("Derive('third') = %x, want = %x", got, want)
	}
}

func TestProtocol_MarshalBinary(t *testing.T) {
	p1 := newplex.NewProtocol("example")
	p1.Mix("a thing", []byte("another thing"))

	state, err := p1.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}

	var p2 newplex.Protocol
	if err := p2.UnmarshalBinary(state); err != nil {
		t.Fatal(err)
	}

	if got, want := p2.Derive("third", nil, 8), p1.Derive("third", nil, 8); !bytes.Equal(got, want) {
		t.Errorf("Derive('third') = %x, want = %x", got, want)
	}
}

func TestProtocol_UnmarshalBinary(t *testing.T) {
	p := newplex.NewProtocol("example")
	if err := p.UnmarshalBinary([]byte{}); err == nil {
		t.Error("UnmarshalBinary(initialized) should have failed")
	}
}

func TestProtocol_AppendBinary(t *testing.T) {
	p1 := newplex.NewProtocol("example")
	p1.Mix("a thing", []byte("another thing"))

	got, err := p1.AppendBinary(nil)
	if err != nil {
		t.Fatal(err)
	}

	want, err := p1.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(got, want) {
		t.Errorf("AppendBinary = %x, want %x", got, want)
	}
}

func TestProtocol_Derive_nonzero_output_slices(t *testing.T) {
	zero := make([]byte, 10)
	nonZero := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 0}

	p1 := newplex.NewProtocol("example")
	p2 := newplex.NewProtocol("example")

	if got, want := p1.Derive("test", nonZero[:0], 10), p2.Derive("test", zero[:0], 10); !bytes.Equal(got, want) {
		t.Errorf("Derive(nonZero) = %x, want = %x", got, want)
	}
}

func TestProtocol_Derive_negative_length(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("The code did not panic")
		}
	}()

	p := newplex.NewProtocol("example")
	p.Derive("test", nil, -200)
}

func TestProtocol_Encrypt_common_prefixes(t *testing.T) {
	short := make([]byte, 10)
	long := make([]byte, 16)

	p1 := newplex.NewProtocol("prefixes")
	p1.Encrypt("message", short, short)

	p2 := newplex.NewProtocol("prefixes")
	p2.Encrypt("message", long, long)

	if got, want := long[:len(short)], short; !bytes.Equal(got, want) {
		t.Errorf("Encrypt(16)[:10] = %x, want = %x", got, want)
	}

	if got, want := p1.Derive("test", nil, 8), p2.Derive("test", nil, 8); bytes.Equal(got, want) {
		t.Errorf("Encrypt(10) state = Encrypt(16) state = %x", got)
	}
}

func TestProtocol_Encrypt_same_slice(t *testing.T) {
	plaintext := []byte("hello world")
	p1 := newplex.NewProtocol("test")
	ciphertext := p1.Encrypt("message", nil, plaintext)

	p2 := newplex.NewProtocol("test")
	msg := make([]byte, len(plaintext))
	copy(msg, plaintext)
	p2.Encrypt("message", msg[:0], msg)

	if !bytes.Equal(msg, ciphertext) {
		t.Errorf("In-place encryption failed: %x vs %x", msg, ciphertext)
	}
}

func TestProtocol_Seal_same_slice(t *testing.T) {
	plaintext := []byte("hello world")
	p1 := newplex.NewProtocol("test")
	ciphertext := p1.Seal("message", nil, plaintext)

	p2 := newplex.NewProtocol("test")
	msg := make([]byte, len(plaintext)+newplex.TagSize)
	copy(msg, plaintext)
	p2.Seal("message", msg[:0], msg[:len(plaintext)])

	if !bytes.Equal(msg, ciphertext) {
		t.Errorf("In-place seal failed: %x vs %x", msg, ciphertext)
	}
}

func FuzzProtocol_Open_ciphertext_modification(f *testing.F) {
	f.Add([]byte("a message"), 4, byte(7))
	f.Fuzz(func(t *testing.T, plaintext []byte, idx int, mask byte) {
		if idx < 0 || idx >= len(plaintext)+newplex.TagSize || mask == 0 {
			t.Skip()
		}

		p := newplex.NewProtocol("fuzz-open")
		ciphertext := p.Seal("message", nil, plaintext)
		ciphertext[idx] ^= mask

		p = newplex.NewProtocol("fuzz-open")
		recovered, err := p.Open("message", nil, ciphertext)
		if err == nil {
			t.Fatalf("Open(Seal(%x)[%d] ^ %d) = %x", plaintext, idx, mask, recovered)
		}
	})
}

func TestProtocol_Open_unauthenticated_plaintext(t *testing.T) {
	p1 := newplex.NewProtocol("example")
	p1.Mix("key", []byte("I'm a key."))
	plaintext := []byte("I'm a message.")
	ciphertext := p1.Seal("message", nil, plaintext)

	ciphertext[0] ^= 1

	p2 := newplex.NewProtocol("example")
	p2.Mix("key", []byte("I'm a key."))
	_, _ = p2.Open("message", ciphertext[:0], ciphertext)

	if got, want := ciphertext[:len(plaintext)], make([]byte, len(plaintext)); !bytes.Equal(got, want) {
		t.Fatalf("Open(invalid) left reachable unauthenticated plaintext: %x vs %x", got, plaintext)
	}
}

func TestProtocol_Open_short_ciphertext(t *testing.T) {
	p := newplex.NewProtocol("example")
	_, err := p.Open("message", nil, make([]byte, newplex.TagSize-1))
	if err == nil {
		t.Error("Open(short) should have failed")
	}
}

func BenchmarkNewProtocol(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		newplex.NewProtocol("mix")
	}
}

func BenchmarkProtocol_Mix(b *testing.B) {
	p := newplex.NewProtocol("mix")
	label := "label"
	input := []byte("input")

	b.ReportAllocs()
	for b.Loop() {
		p.Mix(label, input)
	}
}

func BenchmarkProtocol_Derive(b *testing.B) {
	p := newplex.NewProtocol("derive")
	label := "label"
	output := make([]byte, 32)

	b.ReportAllocs()
	for b.Loop() {
		p.Derive(label, output[:0], len(output))
	}
}

func BenchmarkProtocol_Encrypt(b *testing.B) {
	p := newplex.NewProtocol("encrypt")
	label := "label"
	output := make([]byte, 32)

	b.ReportAllocs()
	for b.Loop() {
		p.Encrypt(label, output[:0], output)
	}
}

func BenchmarkProtocol_Decrypt(b *testing.B) {
	p := newplex.NewProtocol("decrypt")
	label := "label"
	output := make([]byte, 32)

	b.ReportAllocs()
	for b.Loop() {
		p.Decrypt(label, output[:0], output)
	}
}

func BenchmarkProtocol_Seal(b *testing.B) {
	p := newplex.NewProtocol("seal")
	label := "label"
	output := make([]byte, 32+newplex.TagSize)

	b.ReportAllocs()
	for b.Loop() {
		p.Seal(label, output[:0], output[:32])
	}
}

func BenchmarkProtocol_Open(b *testing.B) {
	output := make([]byte, 32)
	p := newplex.NewProtocol("open")
	ciphertext := p.Seal("label", nil, output)

	b.ReportAllocs()
	for b.Loop() {
		p := newplex.NewProtocol("open")
		if _, err := p.Open("label", output[:0], ciphertext); err != nil {
			b.Fatal(err)
		}
	}
}
