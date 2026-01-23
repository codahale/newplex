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

		F1600(&state1)            // Should use ASM
		f1600Generic(&state2, 24) // Reference

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

		P1600(&state1)            // Should use ASM
		f1600Generic(&state2, 12) // Reference

		if !bytes.Equal(state1[:], state2[:]) {
			t.Errorf("iteration %d: generic (12 rounds) mismatch ASM", i)
		}
	}
}
