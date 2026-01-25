//go:build (!amd64 && !arm64) || purego

package haraka

func permute512(state *[64]byte) {
	permute512Generic(state)
}
