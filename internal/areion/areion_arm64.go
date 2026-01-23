//go:build arm64 && !nosimd

package areion

func permute512(state *[64]byte) {
	permute512Asm(state)
}

//go:noescape
func permute512Asm(state *[64]byte)
