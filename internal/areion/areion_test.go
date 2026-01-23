package areion //nolint:testpackage // testing unexported internals

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestPermute512Vectors(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		output string
	}{
		{
			name:  "Vector #1",
			input: "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
			output: "b2adb04fa91f901559367122cb3c96a9" +
				"78cf3ee4b73c6a543fe6dc85779102e7" +
				"e3f5501016ceed1dd2c48d0bc212fb07" +
				"ad168794bd96cff35909cdd8e2274928",
		},
		{
			name: "Vector #2",
			input: "000102030405060708090a0b0c0d0e0f" +
				"101112131415161718191a1b1c1d1e1f" +
				"202122232425262728292a2b2c2d2e2f" +
				"303132333435363738393a3b3c3d3e3f",
			output: "b690b88297ec470b07dda92b91959cff" +
				"135e9ac5fc3dc9b647a43f4daa8da7a4" +
				"e0afbdd8e6e255c24527736b298bd61d" +
				"e460bab9ea7915c6d6ddbe05fe8dde40",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			in, err := hex.DecodeString(tc.input)
			if err != nil {
				t.Fatalf("invalid hex input: %v", err)
			}
			out, err := hex.DecodeString(tc.output)
			if err != nil {
				t.Fatalf("invalid hex output: %v", err)
			}

			var state [64]byte
			copy(state[:], in)

			Permute512(&state)

			if !bytes.Equal(state[:], out) {
				t.Errorf("Permute512 mismatch:\nGot:  %x\nWant: %x", state[:], out)
			}
		})
	}
}

func TestPermute512GenericConsistency(t *testing.T) {
	// Verify that the generic implementation matches the optimized one (if active).
	// On generic-only builds, this tests self-consistency (vacuously true).
	// On AMD64/ARM64, this verifies assembly against Go.

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

func BenchmarkPermute512(b *testing.B) {
	var state [64]byte
	b.SetBytes(int64(len(state)))
	b.ReportAllocs()
	for b.Loop() {
		Permute512(&state)
	}
}
