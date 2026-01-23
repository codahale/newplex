package simpira

const (
	Width256  = 32
	Width512  = 64
	Width784  = 96
	Width1024 = 128
)

// Permute256 applies the Simpira v2 permutation to a 256-bit state (b=2).
func Permute256(state *[Width256]byte) {
	permute256(state)
}

// Permute512 applies the Simpira v2 permutation to a 512-bit state (b=4).
func Permute512(state *[Width512]byte) {
	permute512(state)
}

// Permute784 applies the Simpira v2 permutation to a 768-bit state (b=6).
func Permute784(state *[Width784]byte) {
	permute784(state)
}

// Permute1024 applies the Simpira v2 permutation to a 1024-bit state (b=8).
func Permute1024(state *[Width1024]byte) {
	permute1024(state)
}
