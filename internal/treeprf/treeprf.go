// Package treeprf implements TreePRF, a tree-parallel pseudorandom function
// that produces arbitrary-length output from a fixed-size seed.
//
// TreePRF partitions the output into 8192-byte chunks, each computed as an
// independent TurboSHAKE128 evaluation keyed by the seed and domain-separated
// by the chunk index. All chunk computations are independent and execute in
// parallel using SIMD-accelerated Keccak-p[1600,12] permutations.
package treeprf

import (
	"encoding/binary"

	"github.com/codahale/permutation-city/keccak"
)

const (
	// SeedSize is the size of the seed in bytes.
	SeedSize = 32

	// ChunkSize is the size of each output chunk in bytes.
	ChunkSize = 8 * 1024

	rate   = 168  // TurboSHAKE128 rate (200 - 32).
	dsByte = 0x50 // Domain separation byte.
)

// Generate produces length pseudorandom bytes from the given seed.
func Generate(seed *[SeedSize]byte, length int) []byte {
	if length <= 0 {
		return nil
	}

	output := make([]byte, length)
	n := (length + ChunkSize - 1) / ChunkSize

	idx := 0
	off := 0

	for idx+4 <= n {
		end := min(off+4*ChunkSize, length)
		generateX4(seed, uint64(idx), output[off:end])
		idx += 4
		off = idx * ChunkSize
	}

	for idx+2 <= n {
		end := min(off+2*ChunkSize, length)
		generateX2(seed, uint64(idx), output[off:end])
		idx += 2
		off = idx * ChunkSize
	}

	for idx < n {
		end := min(off+ChunkSize, length)
		generateX1(seed, uint64(idx), output[off:end])
		idx++
		off = idx * ChunkSize
	}

	return output
}

// initState prepares a Keccak state for TurboSHAKE128(seed || LE64(index), 0x50).
// The message (40 bytes) fits within a single rate block, so absorption and
// padding are applied in one step before the first permutation.
func initState(state *[200]byte, seed *[SeedSize]byte, index uint64) {
	// Absorb seed (32 bytes) and index (8 bytes little-endian).
	copy(state[:SeedSize], seed[:])
	binary.LittleEndian.PutUint64(state[SeedSize:SeedSize+8], index)

	// TurboSHAKE padding: domain separation byte after message, 0x80 at rate-1.
	state[SeedSize+8] = dsByte
	state[rate-1] = 0x80
}

func generateX1(seed *[SeedSize]byte, index uint64, out []byte) {
	var s [200]byte
	initState(&s, seed, index)
	keccak.P1600(&s)

	for len(out) > 0 {
		n := copy(out, s[:rate])
		out = out[n:]
		if len(out) > 0 {
			keccak.P1600(&s)
		}
	}
}

func generateX2(seed *[SeedSize]byte, baseIndex uint64, out []byte) {
	var s0, s1 [200]byte
	initState(&s0, seed, baseIndex)
	initState(&s1, seed, baseIndex+1)
	keccak.P1600x2(&s0, &s1)

	states := [2]*[200]byte{&s0, &s1}
	outs := splitChunks(out, 2)

	for {
		done := true
		for i, s := range states {
			if len(outs[i]) > 0 {
				n := copy(outs[i], s[:rate])
				outs[i] = outs[i][n:]
				done = false
			}
		}
		if done {
			break
		}
		keccak.P1600x2(&s0, &s1)
	}
}

func generateX4(seed *[SeedSize]byte, baseIndex uint64, out []byte) {
	var s0, s1, s2, s3 [200]byte
	initState(&s0, seed, baseIndex)
	initState(&s1, seed, baseIndex+1)
	initState(&s2, seed, baseIndex+2)
	initState(&s3, seed, baseIndex+3)
	keccak.P1600x4(&s0, &s1, &s2, &s3)

	states := [4]*[200]byte{&s0, &s1, &s2, &s3}
	outs := splitChunks(out, 4)

	for {
		done := true
		for i, s := range states {
			if len(outs[i]) > 0 {
				n := copy(outs[i], s[:rate])
				outs[i] = outs[i][n:]
				done = false
			}
		}
		if done {
			break
		}
		keccak.P1600x4(&s0, &s1, &s2, &s3)
	}
}

func splitChunks(out []byte, n int) [4][]byte {
	var chunks [4][]byte
	for i := range n {
		start := i * ChunkSize
		if start >= len(out) {
			break
		}
		end := min(start+ChunkSize, len(out))
		chunks[i] = out[start:end]
	}
	return chunks
}
