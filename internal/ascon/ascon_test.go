package ascon //nolint:testpackage // testing internals

import (
	"bytes"
	"encoding/hex"
	"math/rand"
	"testing"
	"time"
)

func TestPermute12(t *testing.T) {
	state := [40]byte{} // All zeros
	Permute12(&state)

	expectedHex := "78ea7ae5cfebb1089b9bfb8513b560f76937f83e03d11a503fe53f36f2c1178c045d648e4def12c9"
	gotHex := hex.EncodeToString(state[:])

	if gotHex != expectedHex {
		t.Errorf("Permute12(0) = %s, want %s", gotHex, expectedHex)
	}
}

func TestCompliance(t *testing.T) {
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	var state1, state2 [40]byte

	for i := range 100 {
		rng.Read(state1[:])
		copy(state2[:], state1[:])

		Permute8(&state1)
		permuteGeneric8(&state2)

		if !bytes.Equal(state1[:], state2[:]) {
			t.Errorf("iteration %d: Permute8 mismatch generic", i)
		}

		rng.Read(state1[:])
		copy(state2[:], state1[:])

		Permute12(&state1)
		permuteGeneric12(&state2)

		if !bytes.Equal(state1[:], state2[:]) {
			t.Errorf("iteration %d: Permute12 mismatch generic", i)
		}
	}
}
