//go:build arm64 && !purego

package ascon

//go:noescape
func permute8(state *[40]byte)

//go:noescape
func permute12(state *[40]byte)
