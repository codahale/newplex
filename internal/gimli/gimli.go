package gimli

// Permute applies the Gimli permutation to a 384-bit state.
func Permute(state *[48]byte) {
	permute(state)
}
