//go:build arm64 && !nosimd

package areion

//go:noescape
func permute512Asm(state *[64]byte)

func permute512(state *[64]byte) {
	permute512Asm(state)
}
