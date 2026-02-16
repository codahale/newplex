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

// Hash calculates a memory-hard hash of the given password and salt using the DRSample+BRG construction using the given
// degree and cost parameters. It appends n bytes of output to dst and returns the resulting slice.
//
// The total memory usage required is 2**(cost+10). For online operations (i.e., password validation), the cost
// parameter should be selected so that the total operation takes ~100ms; for offline operations (i.e., password-based
// encryption), the cost parameter should be selected to fully use all available memory.
//
// The degree parameter should be 3 unless specific analysis indicates a different value would provide more advantage
// to defenders. Too low of a degree results in a block dependency graph which is not complex enough to deter
// ASIC-enabled attackers; too high of a degree results in a block dependency graph which is so complex that performance
// on defender processors suffers and increases an attacker's advantage.
func Hash(domain string, degree, cost uint8, salt, password, dst []byte, n int) []byte {
	// Calculate block count, halfway point, and bit-width for BRG. If halfN = 2^k, the bitWidth we are reversing is k.
	N, halfN := 1<<cost, 1<<(cost-1) // 2**cost, 1/(2**cost)
	bitWidth := cost - 1

	// Allocate the block buffer.
	blocks := make([][blockSize]byte, N)

	// Hash the parameters in a root protocol, then fork into two branches: compression and DRBG. The root protocol is
	// used to mix in all parameters, including the salt, password, and final block, and used for the final derivation.
	// The compression protocol is used when building the graph to compress the parent blocks into a new block. The DRBG
	// protocol is used to pseudorandomly select parent blocks in DRSample based on the degree and cost of the graph.
	root := newplex.NewProtocol(domain)
	root.Mix("degree", binary.AppendUvarint(nil, uint64(degree)))
	root.Mix("cost", binary.AppendUvarint(nil, uint64(cost)))
	compression, drbg := root.Fork("role", []byte("compression"), []byte("drbg"))

	// Hash the salt and password in ONLY the root branch and derive an initial seed block.
	root.Mix("salt", salt)
	root.Mix("password", password)
	root.Derive("seed", blocks[0][:0], blockSize)

	// Generate the first half of the graph using DRSample.
	for v := 1; v < halfN; v++ {
		h := compression.Clone()

		// Parent 1: Sequential edge
		h.Mix("prev", blocks[v-1][:])

		// Parents 2 through degree: Depth-Robust edges
		for i := uint8(1); i < degree; i++ {
			p := getDRSampleParent(drbg.Clone(), v, i)
			h.Mix("drsample-edge", blocks[p][:])
		}

		// Add a new block depending on the previous block and the DRSample-selected blocks.
		h.Derive("block", blocks[v][:0], blockSize)
	}

	// Generate the second half of the graph using BRG.
	for v := halfN; v < N; v++ {
		h := compression.Clone()

		// Parent 1: Sequential edge
		h.Mix("prev", blocks[v-1][:])

		// Parent 2: Bit-Reversal edge pointing to the first half of the graph.
		p := int(bits.Reverse64(uint64(v%halfN)) >> (64 - bitWidth))
		h.Mix("brg-edge", blocks[p][:])

		// Add a new block depending on the previous block and the BRG-selected block.
		h.Derive("block", blocks[v][:0], blockSize)
	}

	// Mix the final block into the root protocol and derive an output.
	root.Mix("block", blocks[N-1][:])
	return root.Derive("output", dst, n)
}

// getDRSampleParent implements the math from Algorithm 3 to find a depth-robust parent.
func getDRSampleParent(drbg newplex.Protocol, v int, i uint8) int {
	// Base case: If v is too small to reach back far enough, just return 0.
	if v < 2 {
		return 0
	}

	// 1. Mix in the vertex index and the edge number.
	var b [binary.MaxVarintLen64]byte
	drbg.Mix("v", binary.AppendUvarint(b[:0], uint64(v)))
	drbg.Mix("i", binary.AppendUvarint(b[:0], uint64(i)))

	// 2. Derive two 64-bit integers to use as the pseudorandom values.
	gPrimeR := binary.LittleEndian.Uint64(drbg.Derive("g-prime", b[:0], 8))
	rR := binary.LittleEndian.Uint64(drbg.Derive("r", b[:0], 8))

	// 3. Calculate g' <- [1, floor(log2(v)) + 1]
	// The floor of log2(v) is identical to the bit length minus 1.
	log2v := bits.Len(uint(v)) - 1
	maxGPrime := uint64(log2v + 1)
	gPrime := 1 + int(gPrimeR%maxGPrime)

	// 4. Calculate g := min(v, 2^g')
	// Using bit shift (1 << gPrime) calculates powers of 2 using pure integer math.
	g := min(v, 1<<gPrime)

	// 5. Calculate r <- [max(floor(g/2), 2), g]
	minR := max(g/2, 2)
	r := minR + int(rR%uint64(g-minR+1))

	// Return the index of the parent vertex.
	return v - r
}

// The size of each block in the memory buffer. 1 KiB was selected to align with common defender CPU cache sizes while
// being more costly to implement for ASIC attackers.
const blockSize = 1024
