//go:build (!amd64 && !arm64) || nosimd

package simpira

func permute2(state *[32]byte) {
	permute2Generic(state)
}

func permute4(state *[64]byte) {
	permute4Generic(state)
}

func permute6(state *[96]byte) {
	permute6Generic(state)
}

func permute8(state *[128]byte) {
	permute8Generic(state)
}
