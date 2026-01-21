package simpira //nolint:testpackage // need access to generic impl

import (
	"bytes"
	"testing"
)

func TestPermute2(t *testing.T) {
	state1 := [32]byte{}
	for i := range 32 {
		state1[i] = byte(i)
	}
	state2 := state1

	Permute2(&state1)
	permute2Generic(&state2)

	if !bytes.Equal(state1[:], state2[:]) {
		t.Errorf("Permute2 assembly results don't match generic implementation")
		t.Errorf("Asm: %x", state1)
		t.Errorf("Gen: %x", state2)
	}
}

func TestPermute4(t *testing.T) {
	state1 := [64]byte{}
	for i := range 64 {
		state1[i] = byte(i)
	}
	state2 := state1

	Permute4(&state1)
	permute4Generic(&state2)

	if !bytes.Equal(state1[:], state2[:]) {
		t.Errorf("Permute4 assembly results don't match generic implementation")
		t.Errorf("Asm: %x", state1)
		t.Errorf("Gen: %x", state2)
	}
}

func TestPermute6(t *testing.T) {
	state1 := [96]byte{}
	for i := range 96 {
		state1[i] = byte(i)
	}
	state2 := state1

	Permute6(&state1)
	permute6Generic(&state2)

	if !bytes.Equal(state1[:], state2[:]) {
		t.Errorf("Permute6 assembly results don't match generic implementation")
		t.Errorf("Asm: %x", state1)
		t.Errorf("Gen: %x", state2)
	}
}

func TestPermute8(t *testing.T) {
	state1 := [128]byte{}
	for i := range 128 {
		state1[i] = byte(i)
	}
	state2 := state1

	Permute8(&state1)
	permute8Generic(&state2)

	if !bytes.Equal(state1[:], state2[:]) {
		t.Errorf("Permute8 assembly results don't match generic implementation")
		t.Errorf("Asm: %x", state1)
		t.Errorf("Gen: %x", state2)
	}
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
