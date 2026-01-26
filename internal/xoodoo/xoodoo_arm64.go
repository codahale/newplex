//go:build arm64 && !purego

package xoodoo

//go:noescape
func permute(state *[48]byte)
