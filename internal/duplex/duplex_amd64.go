//go:build amd64 && !purego

package duplex

// encryptBlock performs a single-pass combined XOR and copy:
//
//	for i := range len(state) { state[i] ^= src[i]; dst[i] = state[i] }
//
// This eliminates the store-forwarding stall that occurs when subtle.XORBytes
// (AVX2 256-bit stores) is followed by copy/memmove (different-width loads) on
// Intel micro-architectures.
//
//go:noescape
func encryptBlock(dst, state, src []byte)

// absorbBlock XORs src into state in place: state[i] ^= src[i].
// It bypasses subtle.XORBytes to avoid the alignment-based scalar fallback
// that fires for 94-byte (= rate) blocks on AMD64.
//
//go:noescape
func absorbBlock(state, src []byte)

// decryptBlock recovers plaintext and updates the keystream state in a single
// pass: plaintext[i] = state[i] ^ ciphertext[i]; state[i] = ciphertext[i].
// Correct even when plaintext and ciphertext alias the same memory.
//
//go:noescape
func decryptBlock(plaintext, state, ciphertext []byte)
