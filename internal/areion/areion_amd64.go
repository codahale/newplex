//go:build amd64 && !nosimd

package areion

//go:noescape
func permute512Asm(state *[64]byte)

func permute512(state *[64]byte) {
	// Fallback to generic until ASM is fixed
	permute512Generic(state)
	_ = permute512Asm // suppress unused warning
}
