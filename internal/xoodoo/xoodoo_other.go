//go:build (!amd64 && !arm64) || purego

package xoodoo

func permute(state *[48]byte) {
	permuteGeneric(state)
}
