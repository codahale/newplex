package gimli //nolint:testpackage // testing unexported internals

import (
	"bytes"
	"testing"
)

func TestGenericConsistency(t *testing.T) {
	var state1, state2 [48]byte
	for i := range 48 {
		state1[i] = byte(i)
		state2[i] = byte(i)
	}

	Permute(&state1)
	permuteGeneric(&state2)

	if !bytes.Equal(state1[:], state2[:]) {
		t.Errorf("Generic vs Optimized mismatch:\nOpt: %x\nGen: %x", state1, state2)
	}
}

func BenchmarkPermute(b *testing.B) {
	var state [48]byte
	b.SetBytes(int64(len(state)))
	b.ReportAllocs()
	for b.Loop() {
		Permute(&state)
	}
}
