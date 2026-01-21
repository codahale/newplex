package simpira

// Permute2 applies the Simpira v2 permutation to a 256-bit state (b=2).
func Permute2(state *[32]byte) {
	permute2(state)
}

// Permute4 applies the Simpira v2 permutation to a 512-bit state (b=4).
func Permute4(state *[64]byte) {
	permute4(state)
}

// Permute6 applies the Simpira v2 permutation to a 768-bit state (b=6).
func Permute6(state *[96]byte) {
	permute6(state)
}

// Permute8 applies the Simpira v2 permutation to a 1024-bit state (b=8).
func Permute8(state *[128]byte) {
	permute8(state)
}
