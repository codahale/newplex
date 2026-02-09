//go:build amd64 && !purego

package simpira1024

import "golang.org/x/sys/cpu"

// UseAESNI is set if the current CPU supports AES instructions.
var UseAESNI = cpu.X86.HasAES //nolint:gochecknoglobals // should only check once

//go:noescape
//goland:noinspection GoUnusedParameter
func permuteAsm(state *[Width]byte)

func permute(state *[Width]byte) {
	if UseAESNI {
		permuteAsm(state)
	} else {
		permuteGeneric(state)
	}
}
