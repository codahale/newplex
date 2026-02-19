//go:build amd64 && !purego

package newplex

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
