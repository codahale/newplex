package simpira

const (
	Permute256Width  = 32
	Permute512Width  = 64
	Permute768Width  = 96
	Permute1024Width = 128
)

// Permute256 applies the Simpira v2 permutation to a 256-bit state (b=2).
func Permute256(state *[Permute256Width]byte) {
	permute256(state)
}

// Permute512 applies the Simpira v2 permutation to a 512-bit state (b=4).
func Permute512(state *[Permute512Width]byte) {
	permute512(state)
}

// Permute768 applies the Simpira v2 permutation to a 768-bit state (b=6).
func Permute768(state *[Permute768Width]byte) {
	permute768(state)
}

// Permute1024 applies the Simpira v2 permutation to a 1024-bit state (b=8).
func Permute1024(state *[Permute1024Width]byte) {
	permute1024(state)
}
