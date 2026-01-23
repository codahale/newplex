//go:build (!amd64 && !arm64) || nosimd

package simpira

func permute256(state *[32]byte) {
	permute256Generic(state)
}

func permute512(state *[64]byte) {
	permute512Generic(state)
}

func permute768(state *[96]byte) {
	permute768Generic(state)
}

func permute1024(state *[128]byte) {
	permute1024Generic(state)
}
