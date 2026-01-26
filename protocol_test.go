package newplex_test

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/codahale/newplex"
)

func TestKnownAnswers(t *testing.T) {
	t.Parallel()

	protocol := newplex.NewProtocol("com.example.kat")
	protocol.Mix("first", []byte("one"))
	protocol.Mix("second", []byte("two"))

	if got, want := hex.EncodeToString(protocol.Derive("third", nil, 8)), "8bd6d2b31db79e43"; got != want {
		t.Errorf("Derive('third') = %v, want = %v", got, want)
	}

	plaintext := []byte("this is an example")
	ciphertext := protocol.Encrypt("fourth", nil, plaintext)
	if got, want := hex.EncodeToString(ciphertext), "b38fb6945f96b43ce098a4fbfbd47dc28e65"; got != want {
		t.Errorf("Encrypt('fourth') = %v, want = %v", got, want)
	}

	ciphertext = protocol.Seal("fifth", nil, []byte("this is an example"))
	if got, want := hex.EncodeToString(ciphertext), "6c53438238e11859aadc445247e276a60d64c370fb9abc3876808b877de5e7122749"; got != want {
		t.Errorf("Seal('fifth') = %v, want = %v", got, want)
	}

	if got, want := hex.EncodeToString(protocol.Derive("sixth", nil, 8)), "3a5e88c2ef12bc6a"; got != want {
		t.Errorf("Derive('sixth') = %v, want = %v", got, want)
	}
}

func TestProtocol_EmptyInputs(t *testing.T) {
	t.Parallel()

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
	t.Parallel()

	p1 := newplex.NewProtocol("example")
	p1.Mix("a thing", []byte("another thing"))
	p2 := p1.Clone()

	if got, want := p2.Derive("third", nil, 8), p1.Derive("third", nil, 8); !bytes.Equal(got, want) {
		t.Errorf("Derive('third') = %x, want = %x", got, want)
	}
}

func TestProtocol_MarshalBinary(t *testing.T) {
	t.Parallel()

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
	t.Parallel()

	p := newplex.NewProtocol("example")
	if err := p.UnmarshalBinary([]byte{}); err == nil {
		t.Error("UnmarshalBinary(initialized) should have failed")
	}
}

func TestProtocol_AppendBinary(t *testing.T) {
	t.Parallel()

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
	t.Parallel()

	zero := make([]byte, 10)
	nonZero := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 0}

	p1 := newplex.NewProtocol("example")
	p2 := newplex.NewProtocol("example")

	if got, want := p1.Derive("test", nonZero[:0], 10), p2.Derive("test", zero[:0], 10); !bytes.Equal(got, want) {
		t.Errorf("Derive(nonZero) = %x, want = %x", got, want)
	}
}

func TestProtocol_Derive_negative_length(t *testing.T) {
	t.Parallel()

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
	msg := make([]byte, 16)
	p1 := newplex.NewProtocol("prefixes")
	p1.Encrypt("message", msg, msg)
	t.Log(msg)
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
	t.Parallel()

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
