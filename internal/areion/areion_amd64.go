//go:build amd64 && !nosimd

package areion

func permute512(state *[64]byte) {
	permute512Asm(state)
}

//go:noescape
func permute512Asm(state *[64]byte)

func permute1024(state *[128]byte) {
	permute1024Asm(state)
}

//go:noescape
func permute1024Asm(state *[128]byte)
