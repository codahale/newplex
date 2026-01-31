package digest_test

import (
	"bytes"
	"testing"

	"github.com/codahale/newplex/digest"
)

func TestDigest_Size(t *testing.T) {
	t.Run("unkeyed", func(t *testing.T) {
		h := digest.New("test")
		if s := h.Size(); s != digest.UnkeyedSize {
			t.Errorf("UnkeyedSize() = %d, want %d", s, digest.UnkeyedSize)
		}
	})

	t.Run("keyed", func(t *testing.T) {
		h := digest.NewKeyed("test", []byte("key"))
		if s := h.Size(); s != digest.KeyedSize {
			t.Errorf("UnkeyedSize() = %d, want %d", s, digest.KeyedSize)
		}
	})
}

func TestDigest_BlockSize(t *testing.T) {
	h := digest.New("test")
	if bs := h.BlockSize(); bs != 96 {
		t.Errorf("BlockSize() = %d, want 96", bs)
	}
}

func TestDigest_Sum(t *testing.T) {
	h := digest.New("com.example.test")
	input := []byte("Hello, world!")
	h.Write(input)

	sum := h.Sum(nil)
	if len(sum) != 32 {
		t.Errorf("Sum length = %d, want 32", len(sum))
	}

	// Verify idempotency of Sum (it shouldn't reset the state)
	// Although our implementation reconstructs the state, so it naturally is idempotent w.r.t the buffer.
	sum2 := h.Sum(nil)
	if !bytes.Equal(sum, sum2) {
		t.Errorf("Sum() = %x, want %x", sum2, sum)
	}

	// Verify appending works
	h.Write(input) // "Hello, world!Hello, world!"
	sum3 := h.Sum(nil)
	if bytes.Equal(sum, sum3) {
		t.Error("Sum() should change after Write()")
	}
}

func TestDigest_Reset(t *testing.T) {
	h := digest.New("com.example.test")
	h.Write([]byte("data"))
	sum1 := h.Sum(nil)

	h.Reset()
	sumEmpty := h.Sum(nil)

	if bytes.Equal(sum1, sumEmpty) {
		t.Error("Reset() didn't clear the buffer")
	}

	h.Write([]byte("data"))
	sum2 := h.Sum(nil)

	if !bytes.Equal(sum1, sum2) {
		t.Errorf("Sum() after Reset+Write = %x, want %x", sum2, sum1)
	}
}
