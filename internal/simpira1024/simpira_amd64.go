//go:build amd64 && !purego

package simpira1024

//go:noescape
func permuteAsm(state *[Width]byte)

//go:noescape
func permuteAVX(state *[Width]byte)

//go:noescape
func hasAVXAES() bool

var permuteImpl func(state *[Width]byte) = permuteAsm

func permute(state *[Width]byte) {
	permuteImpl(state)
}

func init() {
	if hasAVXAES() {
		permuteImpl = permuteAVX
	}
}
