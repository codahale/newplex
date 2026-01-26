//go:build (!amd64 && !arm64) || purego

package simpira1024

func permute(state *[Width]byte) {
	permuteGeneric(state)
}
