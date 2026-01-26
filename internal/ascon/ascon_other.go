//go:build (!amd64 && !arm64) || purego

package ascon

func permute8(state *[40]byte) {
	permuteGeneric8(state)
}

func permute12(state *[40]byte) {
	permuteGeneric12(state)
}
