//go:build amd64 && !nosimd

package simpira

//go:noescape
func permute2(state *[32]byte)

//go:noescape
func permute4(state *[64]byte)

//go:noescape
func permute6(state *[96]byte)

//go:noescape
func permute8(state *[128]byte)
