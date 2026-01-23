package haraka //nolint:testpackage // testing unexported internals

import (
	"bytes"
	"testing"
)

func TestPermute512GenericConsistency(t *testing.T) {
	// Verify that the generic implementation matches the optimized one (if active).
	var state1, state2 [64]byte
	for i := range 64 {
		state1[i] = byte(i)
		state2[i] = byte(i)
	}

	Permute512(&state1)        // ASM (if available)
	permute512Generic(&state2) // Generic

	if !bytes.Equal(state1[:], state2[:]) {
		t.Errorf("Generic vs ASM mismatch:\nASM: %x\nGen: %x", state1[:], state2[:])
	}
}
