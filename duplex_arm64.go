//go:build arm64 && !purego

package newplex

// encryptBlock performs a single-pass combined XOR and copy:
//
//	for i := range len(state) { state[i] ^= src[i]; dst[i] = state[i] }
//
//go:noescape
//goland:noinspection GoUnusedParameter
func encryptBlock(dst, state, src []byte)

// absorbBlock XORs src into state in place: state[i] ^= src[i].
//
//go:noescape
//goland:noinspection GoUnusedParameter
func absorbBlock(state, src []byte)

// decryptBlock recovers plaintext and updates the keystream state in a single
// pass: plaintext[i] = state[i] ^ ciphertext[i]; state[i] = ciphertext[i].
// Correct even when plaintext and ciphertext alias the same memory.
//
//go:noescape
//goland:noinspection GoUnusedParameter
func decryptBlock(plaintext, state, ciphertext []byte)
