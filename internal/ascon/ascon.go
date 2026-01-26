package ascon

// Permute8 applies the 8-round Ascon permutation to a 320-bit state.
func Permute8(state *[40]byte) {
	permute8(state)
}

// Permute12 applies the 12-round Ascon permutation to a 320-bit state.
func Permute12(state *[40]byte) {
	permute12(state)
}
