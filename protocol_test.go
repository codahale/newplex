package newplex_test

import (
	"bytes"
	"testing"

	"github.com/codahale/newplex"
	"github.com/codahale/newplex/internal/testdata"
)

func TestNewProtocol(t *testing.T) {
	p1 := newplex.NewProtocol("example")
	if got, want := p1.Equal(newplex.NewProtocol("other")), 0; got != want {
		t.Errorf("Equal() = %v, want = %v (domain separation failure)", got, want)
	}
}

func TestProtocol_String(t *testing.T) {
	p := newplex.NewProtocol("example")

	for range 4 { // test multiple times for idempotency
		if got, want := p.String(), "Protocol(ac6d20e8c7fa819f)"; got != want {
			t.Errorf("String() = %s, want = %s", got, want)
		}
	}
}

func TestProtocol_Equal(t *testing.T) {
	t.Run("equal", func(t *testing.T) {
		p1 := newplex.NewProtocol("example")
		p1.Mix("one", []byte{1})
		p2 := newplex.NewProtocol("example")
		p2.Mix("one", []byte{1})

		if got, want := p1.Equal(p2), 1; got != want {
			t.Errorf("Equal = %v, want = %v", got, want)
		}
	})

	t.Run("not equal", func(t *testing.T) {
		p1 := newplex.NewProtocol("example")
		p1.Mix("one", []byte{1})
		p2 := newplex.NewProtocol("example")
		p2.Mix("one", []byte{2})

		if got, want := p1.Equal(p2), 0; got != want {
			t.Errorf("Equal = %v, want = %v", got, want)
		}
	})
}

func TestProtocol_Clone(t *testing.T) {
	p1 := newplex.NewProtocol("example")
	p1.Mix("one", []byte{1})

	if got, want := p1.Equal(p1.Clone()), 1; got != want {
		t.Errorf("Equal() = %v, want = %v (post-clone states should be equal)", got, want)
	}
}

func TestProtocol_Clear(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("The code did not panic")
		}
	}()

	p := newplex.NewProtocol("clear")
	p.Clear()
	p.Derive("test", nil, 8)
}

func TestProtocol_Fork(t *testing.T) {
	p := newplex.NewProtocol("fork")
	l, r := p.Fork("side", []byte("l"), []byte("r"))

	t.Run("left vs parent", func(t *testing.T) {
		if got, want := p.Equal(l), 0; got != want {
			t.Errorf("Equal() = %v, want = %v (left side of fork same as parent)", got, want)
		}
	})

	t.Run("right vs parent", func(t *testing.T) {
		if got, want := p.Equal(r), 0; got != want {
			t.Errorf("Equal() = %v, want = %v (right side of fork same as parent)", got, want)
		}
	})

	t.Run("left vs right", func(t *testing.T) {
		if got, want := l.Equal(r), 0; got != want {
			t.Errorf("Equal() = %v, want = %v (left side of fork same as right)", got, want)
		}
	})

	t.Run("commutativity", func(t *testing.T) {
		leftA, rightA := p.Fork("example", []byte("A"), []byte("B"))
		leftB, rightB := p.Fork("example", []byte("B"), []byte("A"))

		if got, want := leftA.String(), rightB.String(); got != want {
			t.Errorf("leftA.String() = %s, rightB.String() = %s", got, want)
		}

		if got, want := rightA.String(), leftB.String(); got != want {
			t.Errorf("rightA.String() = %s, leftB.String() = %s", got, want)
		}
	})
}

func TestProtocol_ForkN(t *testing.T) {
	p := newplex.NewProtocol("fork-n")

	t.Run("divergence", func(t *testing.T) {
		forks := p.ForkN("side", []byte("a"), []byte("b"), []byte("c"))

		if got, want := len(forks), 3; got != want {
			t.Errorf("len(forks) = %d, want %d", got, want)
		}

		for i := range forks {
			for j := range forks {
				if i == j {
					continue
				}
				if got, want := forks[i].Equal(forks[j]), 0; got != want {
					t.Errorf("forks[%d] == forks[%d]", i, j)
				}
			}
		}
	})

	t.Run("empty", func(t *testing.T) {
		forks := p.ForkN("empty")
		if len(forks) != 0 {
			t.Errorf("len(forks) = %d, want 0", len(forks))
		}
	})
}

func TestProtocol_Ratchet(t *testing.T) {
	p1 := newplex.NewProtocol("example")
	p1.Mix("a thing", []byte("another thing"))

	p2 := newplex.NewProtocol("example")
	p2.Mix("a thing", []byte("another thing"))
	p2.Ratchet("ratchet")

	if got, want := p1.Equal(p2), 0; got != want {
		t.Errorf("Equal() = %v, want = %v (post-ratchet states should not be equal)", got, want)
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

	if got, want := p2.Equal(p1), 1; got != want {
		t.Errorf("Equal() = %v, want = %v (unmarshaled state should be equal)", got, want)
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

func TestProtocol_Mix(t *testing.T) {
	t.Run("empty input", func(t *testing.T) {
		p1 := newplex.NewProtocol("empty-test")
		p1.Mix("", nil)

		p2 := newplex.NewProtocol("empty-test")
		p2.Mix("label", nil)

		if got, want := p1.Equal(p2), 0; got != want {
			t.Errorf("Equal() = %v, want = %v (Mix(''); Mix('label') should not be equal)", got, want)
		}
	})
}

func TestProtocol_Derive(t *testing.T) {
	t.Run("nonzero output slices", func(t *testing.T) {
		zero := make([]byte, 10)
		nonZero := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 0}

		p1 := newplex.NewProtocol("example")
		p2 := newplex.NewProtocol("example")

		if got, want := p1.Derive("test", nonZero[:0], 10), p2.Derive("test", zero[:0], 10); !bytes.Equal(got, want) {
			t.Errorf("Derive(nonZero) = %x, want = %x", got, want)
		}
	})

	t.Run("negative length", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Errorf("The code did not panic")
			}
		}()

		p := newplex.NewProtocol("example")
		p.Derive("test", nil, -200)
	})

	t.Run("empty input", func(t *testing.T) {
		p := newplex.NewProtocol("empty-test")
		out := p.Derive("", nil, 0)
		if len(out) != 0 {
			t.Errorf("Derive(0) returned %d bytes (%x)", len(out), out)
		}
	})
}

func TestProtocol_Mask(t *testing.T) {
	t.Run("common prefixes", func(t *testing.T) {
		short := make([]byte, 10)
		long := make([]byte, 16)

		p1 := newplex.NewProtocol("prefixes")
		p1.Mask("message", short, short)

		p2 := newplex.NewProtocol("prefixes")
		p2.Mask("message", long, long)

		if got, want := long[:len(short)], short; !bytes.Equal(got, want) {
			t.Errorf("Mask(16)[:10] = %x, want = %x", got, want)
		}

		if p1.Equal(p2) == 1 {
			t.Errorf("Mask(10) state and Mask(16) state should not be equal")
		}
	})

	t.Run("in place", func(t *testing.T) {
		plaintext := []byte("hello world")
		p1 := newplex.NewProtocol("test")
		ciphertext := p1.Mask("message", nil, plaintext)

		p2 := newplex.NewProtocol("test")
		msg := make([]byte, len(plaintext))
		copy(msg, plaintext)
		p2.Mask("message", msg[:0], msg)

		if !bytes.Equal(msg, ciphertext) {
			t.Errorf("In-place encryption failed: %x vs %x", msg, ciphertext)
		}
	})

	t.Run("empty input", func(t *testing.T) {
		p := newplex.NewProtocol("empty-test")
		out := p.Mask("enc", nil, nil)
		if len(out) != 0 {
			t.Errorf("Mask(nil) returned %d bytes (%x)", len(out), out)
		}
	})
}

func TestProtocol_Unmask(t *testing.T) {
	t.Run("round trip", func(t *testing.T) {
		p1 := newplex.NewProtocol("example")
		p1.Mix("key", []byte("this is a key"))
		plaintext := []byte("this is a message")
		ciphertext := p1.Mask("message", nil, plaintext)

		p2 := newplex.NewProtocol("example")
		p2.Mix("key", []byte("this is a key"))
		got := p2.Unmask("message", nil, ciphertext)

		if want := plaintext; !bytes.Equal(got, want) {
			t.Errorf("Unmask(Mask(%x)) = %x", want, got)
		}
	})

	t.Run("empty input", func(t *testing.T) {
		p := newplex.NewProtocol("empty-test")
		out := p.Unmask("enc", nil, nil)
		if len(out) != 0 {
			t.Errorf("Unmask(nil) returned %d bytes (%x)", len(out), out)
		}
	})
}

func TestProtocol_Seal(t *testing.T) {
	t.Run("in place", func(t *testing.T) {
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
	})

	t.Run("empty input", func(t *testing.T) {
		p := newplex.NewProtocol("empty-test")
		sealed := p.Seal("seal", nil, nil)
		if len(sealed) != newplex.TagSize {
			t.Errorf("Seal(nil) returned %d bytes (%x), want = %d", len(sealed), sealed, newplex.TagSize)
		}
	})
}

func TestProtocol_Open(t *testing.T) {
	t.Run("round trip", func(t *testing.T) {
		p1 := newplex.NewProtocol("example")
		p1.Mix("key", []byte("I'm a key."))
		plaintext := []byte("I'm a message.")
		ciphertext := p1.Seal("message", nil, plaintext)

		p2 := newplex.NewProtocol("example")
		p2.Mix("key", []byte("I'm a key."))
		got, err := p2.Open("message", ciphertext[:0], ciphertext)
		if err != nil {
			t.Fatal(err)
		}

		if want := plaintext; !bytes.Equal(got, want) {
			t.Fatalf("Open(Seal(%x)) = %x, want = %x", plaintext, got, plaintext)
		}
	})

	t.Run("unauthenticated plaintext", func(t *testing.T) {
		p1 := newplex.NewProtocol("example")
		p1.Mix("key", []byte("I'm a key."))
		plaintext := []byte("I'm a message.")
		ciphertext := p1.Seal("message", nil, plaintext)

		ciphertext[0] ^= 1

		p2 := newplex.NewProtocol("example")
		p2.Mix("key", []byte("I'm a key."))
		_, _ = p2.Open("message", ciphertext[:0], ciphertext)

		if got, want := ciphertext[:len(plaintext)], make([]byte, len(plaintext)); !bytes.Equal(got, want) {
			t.Fatalf("Open(invalid) left reachable unauthenticated plaintext: got = %x, want = %x", got, plaintext)
		}
	})

	t.Run("short ciphertext", func(t *testing.T) {
		p := newplex.NewProtocol("example")
		_, err := p.Open("message", nil, make([]byte, newplex.TagSize-1))
		if err == nil {
			t.Error("Open(short) should have failed")
		}
	})

	t.Run("empty ciphertext", func(t *testing.T) {
		p := newplex.NewProtocol("empty-test")
		sealed := p.Clone().Seal("seal", nil, nil)
		opened, err := p.Clone().Open("seal", nil, sealed)
		if err != nil {
			t.Errorf("Open(Seal(nil)) failed: %v", err)
		}
		if len(opened) != 0 {
			t.Errorf("Open(Seal(nil)) returned %d bytes (%x)", len(opened), opened)
		}
	})
}

func FuzzProtocol_Open(f *testing.F) {
	drbg := testdata.New("newplex protocol open fuzz")
	for range 10 {
		f.Add(drbg.Data(32), 4, byte(7))
	}

	// Ensure that any bit on any byte in the ciphertext, if changed, will fail to open.
	f.Fuzz(func(t *testing.T, plaintext []byte, idx int, mask byte) {
		if idx < 0 || idx >= len(plaintext)+newplex.TagSize || mask == 0 {
			t.Skip()
		}

		p1 := newplex.NewProtocol("fuzz-open")
		ciphertext := p1.Seal("message", nil, plaintext)
		ciphertext[idx] ^= mask

		p := newplex.NewProtocol("fuzz-open")
		recovered, err := p.Open("message", nil, ciphertext)
		if err == nil {
			t.Errorf("Open(ciphertext=%x) = plaintext=%x, want = err", ciphertext, recovered)
		}
	})
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

func BenchmarkProtocol_Mask(b *testing.B) {
	p := newplex.NewProtocol("mask")
	label := "label"
	output := make([]byte, 32)

	b.ReportAllocs()
	for b.Loop() {
		p.Mask(label, output[:0], output)
	}
}

func BenchmarkProtocol_Unmask(b *testing.B) {
	p := newplex.NewProtocol("unmask")
	label := "label"
	output := make([]byte, 32)

	b.ReportAllocs()
	for b.Loop() {
		p.Unmask(label, output[:0], output)
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
