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

	off := 0
	for {
		off += copy(out[off:], s[:rate])
		if off >= len(out) {
			break
		}
		keccak.P1600(&s)
	}
}

func generateX2(seed *[SeedSize]byte, baseIndex uint64, out []byte) {
	var s0, s1 [200]byte
	initState(&s0, seed, baseIndex)
	initState(&s1, seed, baseIndex+1)
	keccak.P1600x2(&s0, &s1)

	l0 := min(ChunkSize, len(out))
	l1 := min(ChunkSize, max(0, len(out)-ChunkSize))
	off := 0
	for {
		w := min(rate, l0-off)
		copy(out[off:off+w], s0[:w])
		if off < l1 {
			w1 := min(rate, l1-off)
			copy(out[ChunkSize+off:ChunkSize+off+w1], s1[:w1])
		}
		off += w
		if off >= l0 {
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

	l0 := min(ChunkSize, len(out))
	l1 := min(ChunkSize, max(0, len(out)-ChunkSize))
	l2 := min(ChunkSize, max(0, len(out)-2*ChunkSize))
	l3 := min(ChunkSize, max(0, len(out)-3*ChunkSize))
	off := 0
	for {
		w := min(rate, l0-off)
		copy(out[off:off+w], s0[:w])
		if off < l1 {
			w1 := min(w, l1-off)
			copy(out[ChunkSize+off:ChunkSize+off+w1], s1[:w1])
		}
		if off < l2 {
			w2 := min(w, l2-off)
			copy(out[2*ChunkSize+off:2*ChunkSize+off+w2], s2[:w2])
		}
		if off < l3 {
			w3 := min(w, l3-off)
			copy(out[3*ChunkSize+off:3*ChunkSize+off+w3], s3[:w3])
		}
		off += w
		if off >= l0 {
			break
		}
		keccak.P1600x4(&s0, &s1, &s2, &s3)
	}
}
