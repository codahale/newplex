package simpira //nolint:testpackage // need access to generic impl

import (
	"bytes"
	"crypto/sha3"
	"testing"
)

func FuzzPermute2(f *testing.F) {
	const width = 32
	rng := sha3.NewSHAKE128()
	_, _ = rng.Write([]byte("simpira-2-v2"))

	for range 10 {
		state := make([]byte, width)
		_, _ = rng.Read(state)
		f.Add(state)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) != width {
			t.Skip()
		}

		var state1, state2 [width]byte
		copy(state1[:], data)
		copy(state2[:], data)
		Permute2(&state1)
		permute2Generic(&state2)

		if got, want := state2[:], state1[:]; !bytes.Equal(got, want) {
			t.Errorf("Permute2-ASM(%x) = %x, want = %x", data, got, want)
		}
	})
}

func FuzzPermute4(f *testing.F) {
	const width = 64
	rng := sha3.NewSHAKE128()
	_, _ = rng.Write([]byte("simpira-4-v2"))

	for range 10 {
		state := make([]byte, width)
		_, _ = rng.Read(state)
		f.Add(state)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) != width {
			t.Skip()
		}

		var state1, state2 [width]byte
		copy(state1[:], data)
		copy(state2[:], data)
		Permute4(&state1)
		permute4Generic(&state2)

		if got, want := state2[:], state1[:]; !bytes.Equal(got, want) {
			t.Errorf("Permute4-ASM(%x) = %x, want = %x", data, got, want)
		}
	})
}

func FuzzPermute6(f *testing.F) {
	const width = 96
	rng := sha3.NewSHAKE128()
	_, _ = rng.Write([]byte("simpira-6-v2"))

	for range 10 {
		state := make([]byte, width)
		_, _ = rng.Read(state)
		f.Add(state)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) != width {
			t.Skip()
		}

		var state1, state2 [width]byte
		copy(state1[:], data)
		copy(state2[:], data)
		Permute6(&state1)
		permute6Generic(&state2)

		if got, want := state2[:], state1[:]; !bytes.Equal(got, want) {
			t.Errorf("Permute6-ASM(%x) = %x, want = %x", data, got, want)
		}
	})
}

func FuzzPermute8(f *testing.F) {
	const width = 128
	rng := sha3.NewSHAKE128()
	_, _ = rng.Write([]byte("simpira-8-v2"))

	for range 10 {
		state := make([]byte, width)
		_, _ = rng.Read(state)
		f.Add(state)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) != width {
			t.Skip()
		}

		var state1, state2 [width]byte
		copy(state1[:], data)
		copy(state2[:], data)
		Permute8(&state1)
		permute8Generic(&state2)

		if got, want := state2[:], state1[:]; !bytes.Equal(got, want) {
			t.Errorf("Permute8-ASM(%x) = %x, want = %x", data, got, want)
		}
	})
}

func BenchmarkPermute2(b *testing.B) {
	var state [32]byte
	b.SetBytes(int64(len(state)))
	b.ReportAllocs()
	for b.Loop() {
		Permute2(&state)
	}
}

func BenchmarkPermute4(b *testing.B) {
	var state [64]byte
	b.SetBytes(int64(len(state)))
	b.ResetTimer()
	for b.Loop() {
		Permute4(&state)
	}
}

func BenchmarkPermute6(b *testing.B) {
	var state [96]byte
	b.SetBytes(int64(len(state)))
	b.ResetTimer()
	for b.Loop() {
		Permute6(&state)
	}
}

func BenchmarkPermute8(b *testing.B) {
	var state [128]byte
	b.SetBytes(int64(len(state)))
	b.ResetTimer()
	for b.Loop() {
		Permute8(&state)
	}
}
