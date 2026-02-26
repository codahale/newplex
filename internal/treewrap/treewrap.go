// Package treewrap implements TreeWrap, a tree-parallel authenticated encryption
// algorithm that uses a KangarooTwelve-like topology to enable SIMD acceleration
// on large inputs.
//
// Each leaf operates as an independent SpongeWrap instance using Keccak-p[1600,12],
// and leaf chain values are accumulated into a single authentication tag via
// TurboSHAKE128. All leaf operations are independent and execute in parallel
// using SIMD-accelerated permutations.
//
// TreeWrap is a pure function with no internal state. It is intended as a building
// block for duplex-based protocols, where key uniqueness and associated data are
// managed by the caller. The key MUST be unique per invocation.
package treewrap

import (
	"encoding/binary"

	"github.com/codahale/newplex/internal/mem"
	"github.com/codahale/newplex/internal/turboshake"
	"github.com/codahale/permutation-city/keccak"
)

const (
	// KeySize is the size of the key in bytes.
	KeySize = 32

	// TagSize is the size of the authentication tag in bytes.
	TagSize = 32

	// ChunkSize is the size of each leaf chunk in bytes.
	ChunkSize = 8 * 1024

	rate      = 168      // TurboSHAKE128 rate (200 − 32).
	cvSize    = 32       // Chain value size (= capacity).
	blockRate = rate - 1 // 167: usable data bytes per sponge block.
	leafDS    = 0x60     // Domain separation byte for leaf sponges.
	tagDS     = 0x61     // Domain separation byte for tag computation.
)

// Seal encrypts plaintext, appends the ciphertext to dst, and returns the resulting slice along with a TagSize-byte
// authentication tag. The key MUST be unique per invocation.
//
// To reuse plaintext's storage for the encrypted output, use plaintext[:0] as dst. Otherwise, the remaining capacity
// of dst must not overlap plaintext.
func Seal(dst []byte, key *[KeySize]byte, plaintext []byte) ([]byte, [TagSize]byte) {
	n := max(1, (len(plaintext)+ChunkSize-1)/ChunkSize)

	ret, ciphertext := mem.SliceForAppend(dst, len(plaintext))
	cvs := make([]byte, n*cvSize)

	fullChunks := len(plaintext) / ChunkSize
	idx := 0

	for idx+4 <= fullChunks {
		off := idx * ChunkSize
		sealX4(key, uint64(idx), plaintext[off:off+4*ChunkSize], ciphertext[off:off+4*ChunkSize], cvs[idx*cvSize:])
		idx += 4
	}

	for idx+2 <= fullChunks {
		off := idx * ChunkSize
		sealX2(key, uint64(idx), plaintext[off:off+2*ChunkSize], ciphertext[off:off+2*ChunkSize], cvs[idx*cvSize:])
		idx += 2
	}

	for idx < n {
		off := idx * ChunkSize
		end := min(off+ChunkSize, len(plaintext))
		sealX1(key, uint64(idx), plaintext[off:end], ciphertext[off:end], cvs[idx*cvSize:(idx+1)*cvSize])
		idx++
	}

	return ret, computeTag(cvs, n)
}

// Open decrypts ciphertext, appends the plaintext to dst, and returns the resulting slice along with the expected
// TagSize-byte authentication tag. The caller MUST verify the tag using constant-time comparison before using the
// plaintext.
//
// To reuse ciphertext's storage for the decrypted output, use ciphertext[:0] as dst. Otherwise, the remaining
// capacity of dst must not overlap ciphertext.
func Open(dst []byte, key *[KeySize]byte, ciphertext []byte) ([]byte, [TagSize]byte) {
	n := max(1, (len(ciphertext)+ChunkSize-1)/ChunkSize)

	ret, plaintext := mem.SliceForAppend(dst, len(ciphertext))
	cvs := make([]byte, n*cvSize)

	fullChunks := len(ciphertext) / ChunkSize
	idx := 0

	for idx+4 <= fullChunks {
		off := idx * ChunkSize
		openX4(key, uint64(idx), ciphertext[off:off+4*ChunkSize], plaintext[off:off+4*ChunkSize], cvs[idx*cvSize:])
		idx += 4
	}

	for idx+2 <= fullChunks {
		off := idx * ChunkSize
		openX2(key, uint64(idx), ciphertext[off:off+2*ChunkSize], plaintext[off:off+2*ChunkSize], cvs[idx*cvSize:])
		idx += 2
	}

	for idx < n {
		off := idx * ChunkSize
		end := min(off+ChunkSize, len(ciphertext))
		openX1(key, uint64(idx), ciphertext[off:end], plaintext[off:end], cvs[idx*cvSize:(idx+1)*cvSize])
		idx++
	}

	return ret, computeTag(cvs, n)
}

// computeTag builds the KangarooTwelve final node structure and computes the tag.
func computeTag(cvs []byte, n int) [TagSize]byte {
	le := lengthEncode(uint64(n - 1))
	totalLen := cvSize + 8 + cvSize*(n-1) + len(le) + 2

	input := make([]byte, 0, totalLen)
	input = append(input, cvs[:cvSize]...)                                // cv[0]
	input = append(input, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00) // KT12 marker
	for i := 1; i < n; i++ {
		input = append(input, cvs[i*cvSize:(i+1)*cvSize]...) // cv[1]..cv[n-1]
	}
	input = append(input, le...)      // length_encode(n-1)
	input = append(input, 0xFF, 0xFF) // terminator

	result := turboshake.Sum(input, tagDS, TagSize)

	var tag [TagSize]byte
	copy(tag[:], result)

	return tag
}

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

// leafSponge is a SpongeWrap instance for a single leaf.
type leafSponge struct {
	s   [200]byte
	pos int
}

func (l *leafSponge) padPermute() {
	l.s[l.pos] ^= leafDS
	l.s[rate-1] ^= 0x80
	keccak.P1600(&l.s)
	l.pos = 0
}

func (l *leafSponge) init(key *[KeySize]byte, index uint64) {
	// Absorb key || LE64(index) = 40 bytes (fits within one rate block).
	copy(l.s[:KeySize], key[:])
	binary.LittleEndian.PutUint64(l.s[KeySize:KeySize+8], index)
	l.pos = KeySize + 8
	l.padPermute()
}

func (l *leafSponge) encrypt(pt, ct []byte) {
	for len(pt) > 0 {
		n := min(blockRate-l.pos, len(pt))
		mem.XOR(ct[:n], pt[:n], l.s[l.pos:l.pos+n])
		copy(l.s[l.pos:l.pos+n], ct[:n])
		l.pos += n
		pt = pt[n:]
		ct = ct[n:]
		if l.pos == blockRate && len(pt) > 0 {
			l.padPermute()
		}
	}
}

func (l *leafSponge) decrypt(ct, pt []byte) {
	var tmp [blockRate]byte
	for len(ct) > 0 {
		n := min(blockRate-l.pos, len(ct))
		// Save ciphertext so we can handle aliased ct/pt.
		copy(tmp[:n], ct[:n])
		mem.XOR(pt[:n], ct[:n], l.s[l.pos:l.pos+n])
		copy(l.s[l.pos:l.pos+n], tmp[:n])
		l.pos += n
		ct = ct[n:]
		pt = pt[n:]
		if l.pos == blockRate && len(ct) > 0 {
			l.padPermute()
		}
	}
}

func (l *leafSponge) chainValue() []byte {
	l.padPermute()
	cv := make([]byte, cvSize)
	copy(cv, l.s[:cvSize])
	return cv
}

func sealX1(key *[KeySize]byte, index uint64, pt, ct, cvBuf []byte) {
	var l leafSponge
	l.init(key, index)
	l.encrypt(pt, ct)
	copy(cvBuf, l.chainValue())
}

func openX1(key *[KeySize]byte, index uint64, ct, pt, cvBuf []byte) {
	var l leafSponge
	l.init(key, index)
	l.decrypt(ct, pt)
	copy(cvBuf, l.chainValue())
}

// leafPad prepares a Keccak state for a leaf sponge init (absorb key || LE64(index)
// and apply padding). The caller must invoke the permutation.
func leafPad(s *[200]byte, key *[KeySize]byte, index uint64) {
	copy(s[:KeySize], key[:])
	binary.LittleEndian.PutUint64(s[KeySize:KeySize+8], index)
	s[KeySize+8] = leafDS
	s[rate-1] = 0x80
}

// finalPos returns the sponge position after encrypting/decrypting chunkLen bytes.
func finalPos(chunkLen int) int {
	if chunkLen == 0 {
		return 0
	}
	p := chunkLen % blockRate
	if p == 0 {
		return blockRate
	}
	return p
}

func sealX2(key *[KeySize]byte, baseIndex uint64, pt, ct, cvBuf []byte) {
	var s0, s1 [200]byte
	leafPad(&s0, key, baseIndex)
	leafPad(&s1, key, baseIndex+1)
	keccak.P1600x2(&s0, &s1)

	states := [2]*[200]byte{&s0, &s1}

	off := 0
	for off < ChunkSize {
		n := min(blockRate, ChunkSize-off)
		for lane := range 2 {
			s := states[lane]
			base := lane*ChunkSize + off
			mem.XOR(ct[base:base+n], pt[base:base+n], s[:n])
			copy(s[:n], ct[base:base+n])
		}
		off += n
		if off < ChunkSize {
			for _, s := range states {
				s[blockRate] ^= leafDS
				s[rate-1] ^= 0x80
			}
			keccak.P1600x2(&s0, &s1)
		}
	}

	pos := finalPos(ChunkSize)
	for _, s := range states {
		s[pos] ^= leafDS
		s[rate-1] ^= 0x80
	}
	keccak.P1600x2(&s0, &s1)

	for i, s := range states {
		copy(cvBuf[i*cvSize:(i+1)*cvSize], s[:cvSize])
	}
}

func openX2(key *[KeySize]byte, baseIndex uint64, ct, pt, cvBuf []byte) {
	var s0, s1 [200]byte
	leafPad(&s0, key, baseIndex)
	leafPad(&s1, key, baseIndex+1)
	keccak.P1600x2(&s0, &s1)

	states := [2]*[200]byte{&s0, &s1}

	var tmp [blockRate]byte
	off := 0
	for off < ChunkSize {
		n := min(blockRate, ChunkSize-off)
		for lane := range 2 {
			s := states[lane]
			base := lane*ChunkSize + off
			copy(tmp[:n], ct[base:base+n])
			mem.XOR(pt[base:base+n], ct[base:base+n], s[:n])
			copy(s[:n], tmp[:n])
		}
		off += n
		if off < ChunkSize {
			for _, s := range states {
				s[blockRate] ^= leafDS
				s[rate-1] ^= 0x80
			}
			keccak.P1600x2(&s0, &s1)
		}
	}

	pos := finalPos(ChunkSize)
	for _, s := range states {
		s[pos] ^= leafDS
		s[rate-1] ^= 0x80
	}
	keccak.P1600x2(&s0, &s1)

	for i, s := range states {
		copy(cvBuf[i*cvSize:(i+1)*cvSize], s[:cvSize])
	}
}

func sealX4(key *[KeySize]byte, baseIndex uint64, pt, ct, cvBuf []byte) {
	var s0, s1, s2, s3 [200]byte
	leafPad(&s0, key, baseIndex)
	leafPad(&s1, key, baseIndex+1)
	leafPad(&s2, key, baseIndex+2)
	leafPad(&s3, key, baseIndex+3)
	keccak.P1600x4(&s0, &s1, &s2, &s3)

	states := [4]*[200]byte{&s0, &s1, &s2, &s3}

	off := 0
	for off < ChunkSize {
		n := min(blockRate, ChunkSize-off)
		for lane := range 4 {
			s := states[lane]
			base := lane*ChunkSize + off
			mem.XOR(ct[base:base+n], pt[base:base+n], s[:n])
			copy(s[:n], ct[base:base+n])
		}
		off += n
		if off < ChunkSize {
			for _, s := range states {
				s[blockRate] ^= leafDS
				s[rate-1] ^= 0x80
			}
			keccak.P1600x4(&s0, &s1, &s2, &s3)
		}
	}

	pos := finalPos(ChunkSize)
	for _, s := range states {
		s[pos] ^= leafDS
		s[rate-1] ^= 0x80
	}
	keccak.P1600x4(&s0, &s1, &s2, &s3)

	for i, s := range states {
		copy(cvBuf[i*cvSize:(i+1)*cvSize], s[:cvSize])
	}
}

func openX4(key *[KeySize]byte, baseIndex uint64, ct, pt, cvBuf []byte) {
	var s0, s1, s2, s3 [200]byte
	leafPad(&s0, key, baseIndex)
	leafPad(&s1, key, baseIndex+1)
	leafPad(&s2, key, baseIndex+2)
	leafPad(&s3, key, baseIndex+3)
	keccak.P1600x4(&s0, &s1, &s2, &s3)

	states := [4]*[200]byte{&s0, &s1, &s2, &s3}

	var tmp [blockRate]byte
	off := 0
	for off < ChunkSize {
		n := min(blockRate, ChunkSize-off)
		for lane := range 4 {
			s := states[lane]
			base := lane*ChunkSize + off
			copy(tmp[:n], ct[base:base+n])
			mem.XOR(pt[base:base+n], ct[base:base+n], s[:n])
			copy(s[:n], tmp[:n])
		}
		off += n
		if off < ChunkSize {
			for _, s := range states {
				s[blockRate] ^= leafDS
				s[rate-1] ^= 0x80
			}
			keccak.P1600x4(&s0, &s1, &s2, &s3)
		}
	}

	pos := finalPos(ChunkSize)
	for _, s := range states {
		s[pos] ^= leafDS
		s[rate-1] ^= 0x80
	}
	keccak.P1600x4(&s0, &s1, &s2, &s3)

	for i, s := range states {
		copy(cvBuf[i*cvSize:(i+1)*cvSize], s[:cvSize])
	}
}
