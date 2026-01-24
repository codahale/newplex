//go:build (!amd64 && !arm64) || nosimd

package gimli

func permute(state *[48]byte) {
	permuteGeneric(state)
}
