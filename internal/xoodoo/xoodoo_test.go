package xoodoo //nolint:testpackage // testing internals

import (
	"bytes"
	"encoding/hex"
	"math/rand"
	"testing"
	"time"
)

func TestPermute(t *testing.T) {
	state := [48]byte{}
	Permute(&state)

	// Test vector for Xoodoo-12(0)
	// Derived from reference implementation
	expectedHex := "8dd8d589bffc63a9192d231b14a0a5ff0681b136fec1c7afbe7ce5aebd4075a770e8862ec9b7f5fef2ad4f8b62404f5e"
	gotHex := hex.EncodeToString(state[:])

	if gotHex != expectedHex {
		t.Errorf("Permute(0) = %s, want %s", gotHex, expectedHex)
	}
}

func TestCompliance(t *testing.T) {
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	var state1, state2 [48]byte

	for i := range 100 {
		rng.Read(state1[:])
		copy(state2[:], state1[:])

		Permute(&state1)
		permuteGeneric(&state2)

		if !bytes.Equal(state1[:], state2[:]) {
			t.Errorf("iteration %d: Permute mismatch generic", i)
		}
	}
}
