//go:build (!amd64 && !arm64) || nosimd

package areion

func permute512(state *[64]byte) {
	permute512Generic(state)
}

func permute1024(state *[128]byte) {
	permute1024Generic(state)
}
