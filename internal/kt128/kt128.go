// Package kt128 implements KT128 (KangarooTwelve) as specified in RFC 9861.
//
// KT128 is a tree-hash eXtendable-Output Function (XOF) built on TurboSHAKE128.
// For messages larger than 8192 bytes, it splits input into chunks and computes
// leaf chain values in parallel using SIMD-accelerated Keccak permutations.
package kt128

import (
	"slices"

	"github.com/codahale/newplex/internal/mem"
	"github.com/codahale/newplex/internal/turboshake"
	"github.com/codahale/permutation-city/keccak"
)

const (
	// BlockSize is the KT128 chunk size in bytes.
	BlockSize = 8192

	rate   = 168 // TurboSHAKE128 rate (200 − 32).
	cvSize = 32  // Chain value size.
	leafDS = 0x0B
)

// Hasher is an incremental KT128 instance that implements hash.Hash and io.Reader.
type Hasher struct {
	suffix    []byte             // C || lengthEncode(|C|), precomputed at construction, immutable
	buf       []byte             // buffered message/leaf data
	ts        *turboshake.Hasher // final-node hasher, nil until tree mode entered or finalized
	leafCount int                // total leaf CVs written to ts so far
	treeMode  bool               // true once S_0 has been flushed to ts
}

// New returns a new Hasher with empty customization.
func New() *Hasher {
	return &Hasher{suffix: lengthEncode(0)}
}

// NewCustom returns a new Hasher with the given customization string.
func NewCustom(c []byte) *Hasher {
	suffix := make([]byte, 0, len(c)+9)
	suffix = append(suffix, c...)
	suffix = append(suffix, lengthEncode(uint64(len(c)))...)
	return &Hasher{suffix: suffix}
}

// Write absorbs message bytes. It must not be called after Read or Sum.
func (h *Hasher) Write(p []byte) (int, error) {
	n := len(p)
	h.buf = append(h.buf, p...)

	// Enter tree mode once we have more than one chunk of message data.
	if !h.treeMode && len(h.buf) > BlockSize {
		h.ts = turboshake.New(0x06)
		_, _ = h.ts.Write(h.buf[:BlockSize])
		_, _ = h.ts.Write(kt12Marker[:])
		remaining := copy(h.buf, h.buf[BlockSize:])
		h.buf = h.buf[:remaining]
		h.treeMode = true
	}

	if h.treeMode {
		h.flushLeaves()
	}
	return n, nil
}

// flushLeaves processes complete leaf chunks in SIMD-width batches.
func (h *Hasher) flushLeaves() {
	lanes := keccak.Lanes
	for {
		// Only process chunks we know are complete (at least 1 byte follows them).
		processable := (len(h.buf) - 1) / BlockSize
		nFlush := (processable / lanes) * lanes
		if nFlush == 0 {
			break
		}
		h.processLeafBatch(h.buf[:nFlush*BlockSize], nFlush)
		remaining := copy(h.buf, h.buf[nFlush*BlockSize:])
		h.buf = h.buf[:remaining]
	}
}

// processLeafBatch computes leaf CVs for nLeaves complete chunks using X4→X2→X1 cascade.
func (h *Hasher) processLeafBatch(data []byte, nLeaves int) {
	var cvBuf [4 * cvSize]byte
	idx := 0

	for idx+4 <= nLeaves {
		off := idx * BlockSize
		leafCVsX4(data[off:off+4*BlockSize], cvBuf[:])
		_, _ = h.ts.Write(cvBuf[:4*cvSize])
		idx += 4
	}

	for idx+2 <= nLeaves {
		off := idx * BlockSize
		leafCVsX2(data[off:off+2*BlockSize], cvBuf[:])
		_, _ = h.ts.Write(cvBuf[:2*cvSize])
		idx += 2
	}

	for idx < nLeaves {
		off := idx * BlockSize
		leafCVX1(data[off:off+BlockSize], cvBuf[:cvSize])
		_, _ = h.ts.Write(cvBuf[:cvSize])
		idx++
	}

	h.leafCount += nLeaves
}

// Read squeezes output from the XOF. On the first call, it finalizes absorption.
func (h *Hasher) Read(p []byte) (int, error) {
	h.finalize()
	return h.ts.Read(p)
}

// Sum appends the current 32-byte hash to b without changing the underlying state.
func (h *Hasher) Sum(b []byte) []byte {
	clone := &Hasher{
		suffix:    h.suffix,
		buf:       slices.Clone(h.buf),
		leafCount: h.leafCount,
		treeMode:  h.treeMode,
	}
	if h.ts != nil {
		clone.ts = new(*h.ts)
	}
	clone.finalize()

	out := make([]byte, 32)
	_, _ = clone.ts.Read(out)
	return append(b, out...)
}

// Reset resets the Hasher to its initial state, retaining the customization string.
func (h *Hasher) Reset() {
	h.buf = h.buf[:0]
	h.ts = nil
	h.leafCount = 0
	h.treeMode = false
}

// Size returns the default output size in bytes.
func (h *Hasher) Size() int { return 32 }

// BlockSize returns the KT128 chunk size.
func (h *Hasher) BlockSize() int { return BlockSize }

// finalize appends the suffix and computes the final hash.
func (h *Hasher) finalize() {
	if h.ts != nil && !h.treeMode {
		// Already finalized (single-node path was taken previously via Sum clone).
		return
	}

	// Append suffix to buffered data.
	h.buf = append(h.buf, h.suffix...)

	if !h.treeMode {
		if len(h.buf) <= BlockSize {
			// Single-node: TurboSHAKE128(S, 0x07, L).
			h.ts = turboshake.New(0x07)
			_, _ = h.ts.Write(h.buf)
			return
		}

		// Enter tree mode: flush S_0.
		h.ts = turboshake.New(0x06)
		_, _ = h.ts.Write(h.buf[:BlockSize])
		_, _ = h.ts.Write(kt12Marker[:])
		remaining := copy(h.buf, h.buf[BlockSize:])
		h.buf = h.buf[:remaining]
		h.treeMode = true
	}

	// Process all remaining leaves. The last chunk may be partial.
	nLeaves := (len(h.buf) + BlockSize - 1) / BlockSize
	if nLeaves > 0 {
		var cvBuf [4 * cvSize]byte
		idx := 0
		fullLeaves := len(h.buf) / BlockSize

		for idx+4 <= fullLeaves {
			off := idx * BlockSize
			leafCVsX4(h.buf[off:off+4*BlockSize], cvBuf[:])
			_, _ = h.ts.Write(cvBuf[:4*cvSize])
			idx += 4
		}

		for idx+2 <= fullLeaves {
			off := idx * BlockSize
			leafCVsX2(h.buf[off:off+2*BlockSize], cvBuf[:])
			_, _ = h.ts.Write(cvBuf[:2*cvSize])
			idx += 2
		}

		for idx < nLeaves {
			off := idx * BlockSize
			end := min(off+BlockSize, len(h.buf))
			leafCVX1(h.buf[off:end], cvBuf[:cvSize])
			_, _ = h.ts.Write(cvBuf[:cvSize])
			idx++
		}

		h.leafCount += nLeaves
	}

	// Terminator: lengthEncode(leafCount) || 0xFF || 0xFF.
	_, _ = h.ts.Write(lengthEncode(uint64(h.leafCount)))
	_, _ = h.ts.Write([]byte{0xFF, 0xFF})
}

// kt12Marker is the 8-byte KangarooTwelve marker written after S_0.
var kt12Marker = [8]byte{0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

// lengthEncode encodes x as in KangarooTwelve: big-endian with no leading zeros,
// followed by a byte giving the length of the encoding.
func lengthEncode(x uint64) []byte {
	if x == 0 {
		return []byte{0x00}
	}

	n := 0
	for v := x; v > 0; v >>= 8 {
		n++
	}

	buf := make([]byte, n+1)
	for i := n - 1; i >= 0; i-- {
		buf[i] = byte(x)
		x >>= 8
	}
	buf[n] = byte(n)

	return buf
}

// absorbParallel XORs chunk data into parallel Keccak states at the sponge rate,
// permuting when full. Returns the final position within the rate.
func absorbParallel(states [4]*[200]byte, lanes int, data []byte, chunkLen int, perm func()) int {
	pos := 0
	off := 0
	for off < chunkLen {
		w := min(rate-pos, chunkLen-off)
		for lane := range lanes {
			base := lane * chunkLen
			mem.XOR(states[lane][pos:pos+w], states[lane][pos:pos+w], data[base+off:base+off+w])
		}
		pos += w
		off += w
		if pos == rate {
			perm()
			pos = 0
		}
	}
	return pos
}

// leafCVX1 computes a single leaf CV using TurboSHAKE128(data, 0x0B, 32).
func leafCVX1(data []byte, cv []byte) {
	var s [200]byte
	pos := absorbParallel([4]*[200]byte{&s}, 1, data, len(data), func() { keccak.P1600(&s) })
	s[pos] ^= leafDS
	s[rate-1] ^= 0x80
	keccak.P1600(&s)
	copy(cv, s[:cvSize])
}

// leafCVsX2 computes 2 leaf CVs in parallel using P1600x2.
func leafCVsX2(data []byte, cv []byte) {
	var s0, s1 [200]byte
	pos := absorbParallel([4]*[200]byte{&s0, &s1}, 2, data, BlockSize, func() { keccak.P1600x2(&s0, &s1) })
	s0[pos] ^= leafDS
	s0[rate-1] ^= 0x80
	s1[pos] ^= leafDS
	s1[rate-1] ^= 0x80
	keccak.P1600x2(&s0, &s1)
	copy(cv[:cvSize], s0[:cvSize])
	copy(cv[cvSize:], s1[:cvSize])
}

// leafCVsX4 computes 4 leaf CVs in parallel using P1600x4.
func leafCVsX4(data []byte, cv []byte) {
	var s0, s1, s2, s3 [200]byte
	pos := absorbParallel([4]*[200]byte{&s0, &s1, &s2, &s3}, 4, data, BlockSize,
		func() { keccak.P1600x4(&s0, &s1, &s2, &s3) })
	for _, s := range []*[200]byte{&s0, &s1, &s2, &s3} {
		s[pos] ^= leafDS
		s[rate-1] ^= 0x80
	}
	keccak.P1600x4(&s0, &s1, &s2, &s3)
	copy(cv[:cvSize], s0[:cvSize])
	copy(cv[cvSize:2*cvSize], s1[:cvSize])
	copy(cv[2*cvSize:3*cvSize], s2[:cvSize])
	copy(cv[3*cvSize:], s3[:cvSize])
}
