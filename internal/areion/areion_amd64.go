//go:build amd64 && !nosimd

package areion

//go:noescape
//goland:noinspection GoUnusedParameter
func permute512(state *[64]byte)
