package areion

// Permute512 applies the Areion-512 permutation to a 512-bit state.
func Permute512(state *[64]byte) {
	permute512(state)
}

// Permute1024 applies the Areion-1024 permutation to a 1024-bit state.
func Permute1024(state *[128]byte) {
	permute1024(state)
}
