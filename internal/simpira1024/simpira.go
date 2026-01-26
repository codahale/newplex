package simpira1024

const (
	Width = 128
)

// Permute applies the Simpira b=8 v2 permutation to a 1024-bit state.
func Permute(state *[Width]byte) {
	permute(state)
}
