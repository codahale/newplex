package gimli

func permute(state *[48]byte) {
	permuteAsm(state)
}

//go:noescape
func permuteAsm(state *[48]byte)
