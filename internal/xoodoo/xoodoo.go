package xoodoo

// Permute applies the 12-round Xoodoo permutation to a 384-bit state.
func Permute(state *[48]byte) {
	permute(state)
}
