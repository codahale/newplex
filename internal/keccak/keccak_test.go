package keccak //nolint:testpackage // testing internals

import (
	"bytes"
	"math/rand"
	"testing"
	"time"
)

func TestCompliance(t *testing.T) {
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	var state1, state2 [200]byte

	for i := range 100 {
		rng.Read(state1[:])
		copy(state2[:], state1[:])

		F1600(&state1)                  // Should use ASM
		keccakF1600Generic(&state2, 24) // Reference

		if !bytes.Equal(state1[:], state2[:]) {
			t.Errorf("iteration %d: generic (24 rounds) mismatch ASM", i)
		}
	}
}

func TestCompliance12(t *testing.T) {
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	var state1, state2 [200]byte

	for i := range 100 {
		rng.Read(state1[:])
		copy(state2[:], state1[:])

		P1600(&state1)                  // Should use ASM
		keccakF1600Generic(&state2, 12) // Reference

		if !bytes.Equal(state1[:], state2[:]) {
			t.Errorf("iteration %d: generic (12 rounds) mismatch ASM", i)
		}
	}
}

func BenchmarkKeccakF1600(b *testing.B) {
	var state [200]byte
	b.SetBytes(int64(len(state)))
	b.ReportAllocs()
	for b.Loop() {
		F1600(&state)
	}
}

func BenchmarkKeccakF1600Rounds12(b *testing.B) {
	var state [200]byte
	b.SetBytes(int64(len(state)))
	b.ReportAllocs()
	for b.Loop() {
		P1600(&state)
	}
}
