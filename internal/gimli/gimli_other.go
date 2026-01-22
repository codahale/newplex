//go:build !amd64 && !arm64

package gimli

func permute(state *[48]byte) {
	permuteGeneric(state)
}
