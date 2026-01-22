package haraka

// Permute512 applies the Haraka-512 v2 permutation to a 512-bit state.
// This implementation uses 6 rounds for collision resistance.
func Permute512(state *[64]byte) {
	permute512(state)
}
