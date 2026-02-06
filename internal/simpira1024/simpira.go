// Package simpira1024 provides an implementation of the Simpira-1204 permutation, also known as [Simpira b=8 V2].
//
// On amd64 and arm64 architectures, it uses a highly optimized assembly implementation using the AES-NI instruction set
// for constant-time operations and high performance. On other architectures, it uses a software implementation of the
// AES round which attempts to be constant time.
//
// [Simpira b=8 V2]: https://eprint.iacr.org/2016/122.pdf
package simpira1024

const (
	// Width is the permutation's width in bytes.
	Width = 128
)

// Permute applies the Simpira b=8 v2 permutation to a 1024-bit state.
func Permute(state *[Width]byte) {
	permute(state)
}
