//go:build !amd64 || purego

package newplex

import "crypto/subtle"

func encryptBlock(dst, state, src []byte) {
	subtle.XORBytes(state, state, src)
	copy(dst, state)
}
