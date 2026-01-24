//go:build amd64 && !nosimd

package gimli

//go:noescape
//goland:noinspection GoUnusedParameter
func permute(state *[48]byte)
