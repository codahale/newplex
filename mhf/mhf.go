// Package mhf implements a password-hashing scheme using [EGSample], a data-dependent memory-hard function.
//
// [EGSample]: https://arxiv.org/pdf/2508.06795
package mhf

import (
	"encoding/binary"
	"math/bits"

	"github.com/codahale/newplex"
)

// RecommendedDegree is the recommended degree parameter. Use this unless specific analysis indicates a different value
// would provide more advantage to defenders. Too low of a degree results in a block dependency graph which is not
// complex enough to deter ASIC-enabled attackers; too high of a degree results in a block dependency graph which is so
// complex that performance on defender processors suffers and increases an attacker's advantage.
const RecommendedDegree = 3

// Hash calculates a memory-hard hash of the given password and salt using the EGSample construction using the given
// degree, cost, and window parameters. It appends n bytes of output to dst and returns the resulting slice.
//
// The total memory usage required is 2**(cost+10). The window parameter must be less than the cost parameter.
//
// Callers should use RecommendedDegree unless they have specific reasons to do otherwise.
//
// For online operations (i.e., password validation), the cost parameter should be selected so that the total operation
// takes ~100ms; for offline operations (i.e., password-based encryption), the cost parameter should be selected to
// fully use all available memory.
//
// The window parameter should be selected such that 2**(window+10) is smaller than the target processor's L3 cache.
func Hash(domain string, degree, cost, window uint8, salt, password, dst []byte, n int) []byte {
	// Calculate block count and window size.
	N, w := 1<<cost, 1<<window // 2**cost, 2**window
	if w >= N {
		panic("mhf: window must be < cost")
	}

	// Allocate the block buffer.
	blocks := make([][blockSize]byte, N)

	// Hash the parameters in a root protocol, then fork into two branches: compression and DRBG. The root protocol is
	// used to mix in all parameters, including the salt, password, and final block, and used for the final derivation.
	// The compression protocol is used when building the graph to compress the parent blocks into a new block. The DRBG
	// protocol is used to pseudorandomly select parent blocks in DRSample based on the degree and cost of the graph.
	root := newplex.NewProtocol(domain)
	root.Mix("degree", binary.AppendUvarint(nil, uint64(degree)))
	root.Mix("cost", binary.AppendUvarint(nil, uint64(cost)))
	root.Mix("window", binary.AppendUvarint(nil, uint64(window)))
	compression, drbg := root.Fork("role", []byte("compression"), []byte("drbg"))

	// Hash the salt and password in ONLY the root branch and derive an initial seed block.
	root.Mix("salt", salt)
	root.Mix("password", password)
	root.Derive("seed", blocks[0][:0], blockSize)

	// Generate the Windowed EGSample Graph.
	var sigmaPrime [blockSize]byte
	for v := 1; v < N; v++ {
		h := compression.Clone()

		// Calculate the current window and relative position within the window.
		windowIndex := v / w
		windowStart := windowIndex * w
		relativeV := v - windowStart

		// --- TIER 1: Data-Independent Intra-Window Edges

		// Parent 1: Sequential edge
		h.Mix("prev", blocks[v-1][:])

		// Parents 2 through degree: Depth-Robust edges localized to the window
		for i := uint8(1); i < degree; i++ {
			// Pass relativeV so the DRSample math calculates a valid intra-window offset.
			pRel := getDRSampleParent(drbg.Clone(), relativeV, i)

			// Map the relative offset back to the absolute memory array.
			pAbs := windowStart + pRel
			h.Mix("drsample-edge", blocks[pAbs][:])
		}

		// Calculate the intermediate state (σ'_v in the paper).
		h.Derive("sigma-prime", sigmaPrime[:0], blockSize)

		// --- TIER 2: Data-Dependent Grate Inter-Window Edges

		// If this is in the first window (W_0), there are no previous windows to connect to, so the intermediate state
		// is the final state.
		if windowIndex == 0 {
			blocks[v] = sigmaPrime
			continue
		}

		// The intermediate state acts as the query to the Random Oracle.
		h = compression.Clone()
		h.Mix("sigma-prime", sigmaPrime[:])

		// Extract entropy from σ'_v to determine the inter-window edge.
		dependentSeed := binary.LittleEndian.Uint64(sigmaPrime[0:8])

		// Map the seed to the index space of ALL preceding windows (W_0 to W_{j-1}). windowStart represents exactly the
		// number of nodes computed in previous windows.
		u := int(dependentSeed % uint64(windowStart))

		// Add the unpredictable Grate parent (σ_u in the paper).
		h.Mix("grate-parent", blocks[u][:])

		// Finalize the block state (σ_v)
		h.Derive("block", blocks[v][:0], blockSize)
	}

	// Mix the final block into the root protocol and derive an output.
	root.Mix("block", blocks[N-1][:])
	return root.Derive("output", dst, n)
}

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
