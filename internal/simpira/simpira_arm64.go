//go:build arm64 && !nosimd

package simpira

//go:noescape
func permute256(state *[32]byte)

//go:noescape
func permute512(state *[64]byte)

//go:noescape
func permute784(state *[96]byte)

//go:noescape
func permute1024(state *[128]byte)
