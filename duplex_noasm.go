//go:build (!amd64 && !arm64) || purego

package newplex

import "crypto/subtle"

func encryptBlock(dst, state, src []byte) {
	subtle.XORBytes(state, state, src)
	copy(dst, state)
}

func absorbBlock(state, src []byte) {
	subtle.XORBytes(state, state, src)
}

func decryptBlock(plaintext, state, ciphertext []byte) {
	// Process byte-by-byte so that ciphertext[i] is captured before plaintext[i]
	// is written, keeping this correct even when plaintext aliases ciphertext.
	for i := range len(state) {
		c := ciphertext[i]
		plaintext[i] = state[i] ^ c
		state[i] = c
	}
}
