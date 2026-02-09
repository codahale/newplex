//go:build arm64 && !purego

package simpira1024

//go:noescape
//goland:noinspection GoUnusedParameter
func permute(state *[Width]byte)
