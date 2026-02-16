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
	// Expand the domain into three, one for each required random oracle.
	expDomain := domain + ".exp"
	mixDomain := domain + ".mix"
	idxDomain := domain + ".idx"

	// Allocate the memory array of 2**cost blocks (each holding 1 KiB of Derive output).
	memory := make([][blockSize]byte, 1<<cost)

	// Initialize the first block.
	exp := newplex.NewProtocol(expDomain)
	exp.Mix("password", password)
	exp.Mix("salt", salt)
	exp.Mix("cost", []byte{cost})
	exp.Derive("seed", memory[0][:0], blockSize)

	// Evaluate the graph sequentially.
	for i := 1; i < len(memory); i++ {
		mix := newplex.NewProtocol(mixDomain)

		// 1. The Sequential Spine
		mix.Mix("last", memory[i-1][:])

		// 2. The BRG Edge (Sustained Space Complexity)
		mix.Mix("brg", memory[bitReverseEdge(i)][:])

		// 3. The DRSample Edges (Cumulative Memory Complexity)
		for k := 1; k <= d; k++ {
			mix.Mix("drsample", memory[sampleEdge(idxDomain, salt, i, k)][:])
		}

		// Hash all aggregated dependencies to create the new block
		mix.Derive("block", memory[i][:0], blockSize)
	}

	// Mix in the last block.
	exp.Mix("block", memory[len(memory)-1][:])
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

// sampleEdge computes a target index of a depth-robust back-edge using a PRNG seeded with the salt and indexes.
func sampleEdge(idxDomain string, salt []byte, i, k int) int {
	maxDist := i - 1
	if maxDist <= 0 {
		return 0
	}
	numBuckets := bits.Len(uint(maxDist))

	// Generate deterministic pseudo-randomness based on the salt and current position.
	var b [8]byte
	h := newplex.NewProtocol(idxDomain)
	h.Mix("salt", salt)
	h.Mix("i", binary.LittleEndian.AppendUint32(b[:0], uint32(i)))
	h.Mix("k", binary.LittleEndian.AppendUint32(b[:0], uint32(k)))

	// Extract two separate 64-bit integers to use as uniform randomness.
	bucketR := binary.LittleEndian.Uint64(h.Derive("bucket", b[:0], 8))
	distanceR := binary.LittleEndian.Uint64(h.Derive("distance", b[:0], 8))

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
