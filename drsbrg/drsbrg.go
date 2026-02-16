// Package drsbrg implements a password-hashing scheme using DRSample+BRG, a data-independent memory-hard function.
//
// [DRSample+BRG] combines the [DRSample] algorithm with the Bit-Reversal Graph from the [Catana] construction,
// augmenting DRSample's cumulative memory complexity (CMC) with BRG's sustained space complexity (SSC). It is the
// current state-of-the-art in data-independent memory hard functions.
//
// [DRSample+BRG]: https://eprint.iacr.org/2018/944.pdf
// [DRSample]: https://eprint.iacr.org/2017/443.pdf
// [Catana]: https://eprint.iacr.org/2013/525
package drsbrg

import (
	"encoding/binary"
	"math/bits"

	"github.com/codahale/newplex"
)

// Hash calculates a memory-hard hash of the given password and salt using the DRSample+BRG construction. It appends n
// bytes of output to dst and returns the resulting slice.
//
// The total memory usage required is 2**(cost+10). For online operations (i.e., password validation), the cost
// parameter should be selected so that the total operation takes ~100ms; for offline operations (i.e., password-based
// encryption), the cost parameter should be selected to fully use all available memory.
func Hash(domain string, cost uint8, salt, password, dst []byte, n int) []byte {
	// Allocate the memory array of 2**cost blocks (each holding 1 KiB of Derive output).
	memory := make([][blockSize]byte, 1<<cost)

	// Mix in the common, public parameters: cost, salt.
	root := newplex.NewProtocol(domain)
	root.Mix("cost", []byte{cost})
	root.Mix("salt", salt)

	// Fork the root protocol into expander, evaluator, and indexer roles.
	branches := root.ForkN("role", []byte("expander"), []byte("evaluator"), []byte("indexer"))
	exp, eval, idx := branches[0], branches[1], branches[2]

	// Only mix the password into the expander branch, ensuring the rest of the algorithm is totally isolated from
	// secret data.
	exp.Mix("password", password)

	// Initialize the first block with the expander.
	exp.Derive("seed", memory[0][:0], blockSize)

	// Evaluate the graph sequentially with independent evaluator clones.
	for i := 1; i < len(memory); i++ {
		eval := eval.Clone()

		// 1. The Sequential Spine
		eval.Mix("last", memory[i-1][:])

		// 2. The BRG Edge (Sustained Space Complexity)
		eval.Mix("brg", memory[bitReverseEdge(i)][:])

		// 3. The DRSample Edges (Cumulative Memory Complexity)
		for k := 1; k <= d; k++ {
			eval.Mix("drsample", memory[sampleEdge(idx.Clone(), i, k)][:])
		}

		// Derive a new block from the evaluated values: cost, salt, sequential block, BRG block, back-edge blocks.
		eval.Derive("block", memory[i][:0], blockSize)
	}

	// Mix in the last block into the expander.
	exp.Mix("block", memory[len(memory)-1][:])

	// Finally, expand N bytes of output.
	return exp.Derive("output", dst, n)
}

// bitReverseEdge computes a target index using localized bit-reversal.
func bitReverseEdge(i int) int {
	// Edge case for the first elements.
	if i == 0 {
		return 0
	}

	// Find the largest power of 2 <= i.
	k := bits.Len(uint(i)) - 1
	offset := i - 1<<k

	// Reverse the exactly k bits of the offset.
	return int(bits.Reverse(uint(offset)) >> (bits.UintSize - k))
}

// sampleEdge computes a pseudorandom target index of a depth-robust back-edge using the block and edge indexes.
func sampleEdge(idx newplex.Protocol, i, k int) int {
	maxDist := i - 1
	if maxDist <= 0 {
		return 0
	}
	numBuckets := bits.Len(uint(maxDist))

	// Generate deterministic pseudo-randomness based on the salt (previously mixed in) and current position.
	var b [8]byte
	idx.Mix("i", binary.LittleEndian.AppendUint32(b[:0], uint32(i)))
	idx.Mix("k", binary.LittleEndian.AppendUint32(b[:0], uint32(k)))

	// Extract two separate 64-bit integers to use as uniform randomness.
	bucketR := binary.LittleEndian.Uint64(idx.Derive("bucket", b[:0], 8))
	distanceR := binary.LittleEndian.Uint64(idx.Derive("distance", b[:0], 8))

	// Uniformly select a bucket using the logarithmic distribution.
	bucketIndex := int(bucketR % uint64(numBuckets))

	// Define the distance boundaries for the chosen bucket.
	minDistance := 1 << bucketIndex
	maxDistance := min((1<<(bucketIndex+1))-1, maxDist)

	// Uniformly select a specific distance within the bucket.
	bucketSize := maxDistance - minDistance + 1
	chosenDistance := minDistance + int(distanceR%uint64(bucketSize))

	return i - chosenDistance
}

const (
	// The number of DRSample back-edges used. A low degree was selected to reduce CPU cache misses, allowing for
	// higher total memory usage within a given time.
	d = 3

	// The size of each block in the memory buffer. 1 KiB was selected to align with common CPU cache sizes while being
	// more costly to implement for ASIC attackers.
	blockSize = 1024
)
