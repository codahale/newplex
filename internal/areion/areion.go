package areion

// Permute512 applies the Areion-512 permutation to a 512-bit state.
func Permute512(state *[64]byte) {
	permute512(state)
}
