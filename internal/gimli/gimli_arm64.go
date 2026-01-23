package gimli

func permute(state *[48]byte) {
	permuteAsm(state)
}

//go:noescape
//goland:noinspection GoUnusedParameter
func permuteAsm(state *[48]byte)
