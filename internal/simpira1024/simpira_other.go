//go:build (!amd64 && !arm64) || purego

package simpira1024

// UseAESNI is set if the current CPU supports AES instructions.
var UseAESNI = false //nolint:gochecknoglobals // should only check once

func permute(state *[Width]byte) {
	permuteGeneric(state)
}
