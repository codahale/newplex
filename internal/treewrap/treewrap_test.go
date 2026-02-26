package treewrap

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/codahale/permutation-city/keccak"
)

func testKey() *[KeySize]byte {
	var key [KeySize]byte
	for i := range key {
		key[i] = byte(i)
	}
	return &key
}

func TestSealOpen(t *testing.T) {
	key := testKey()

	sizes := []struct {
		name string
		size int
	}{
		{"empty", 0},
		{"1 byte", 1},
		{"167 bytes", blockRate},
		{"168 bytes", blockRate + 1},
		{"one chunk", ChunkSize},
		{"one chunk plus one", ChunkSize + 1},
		{"two chunks", 2 * ChunkSize},
		{"three chunks", 3 * ChunkSize},
		{"four chunks", 4 * ChunkSize},
		{"five chunks", 5 * ChunkSize},
		{"four chunks plus one", 4*ChunkSize + 1},
		{"six chunks plus 100", 6*ChunkSize + 100},
	}

	for _, tt := range sizes {
		t.Run(tt.name, func(t *testing.T) {
			pt := make([]byte, tt.size)
			for i := range pt {
				pt[i] = byte(i)
			}

			ct, tag := Seal(nil, key, pt)

			if len(ct) != len(pt) {
				t.Fatalf("ciphertext length %d, want %d", len(ct), len(pt))
			}

			if tt.size > 0 && bytes.Equal(ct, pt) {
				t.Error("ciphertext equals plaintext")
			}

			got, err := Open(nil, key, ct, &tag)
			if err != nil {
				t.Fatalf("Open failed: %v", err)
			}

			if !bytes.Equal(got, pt) {
				t.Error("decrypted plaintext does not match original")
			}
		})
	}
}

func TestSealOpenInPlace(t *testing.T) {
	key := testKey()

	sizes := []struct {
		name string
		size int
	}{
		{"empty", 0},
		{"1 byte", 1},
		{"167 bytes", blockRate},
		{"one chunk", ChunkSize},
		{"one chunk plus one", ChunkSize + 1},
		{"two chunks", 2 * ChunkSize},
		{"four chunks", 4 * ChunkSize},
	}

	for _, tt := range sizes {
		t.Run(tt.name, func(t *testing.T) {
			pt := make([]byte, tt.size)
			for i := range pt {
				pt[i] = byte(i)
			}

			// Keep a copy of the original plaintext.
			orig := make([]byte, len(pt))
			copy(orig, pt)

			// In-place seal: reuse pt's storage.
			ct, tag := Seal(pt[:0], key, pt)

			// In-place open: reuse ct's storage.
			got, err := Open(ct[:0], key, ct, &tag)
			if err != nil {
				t.Fatalf("Open failed: %v", err)
			}

			if !bytes.Equal(got, orig) {
				t.Error("in-place round-trip failed")
			}
		})
	}
}

func TestOpenTagFailure(t *testing.T) {
	key := testKey()
	pt := []byte("hello world")

	ct, tag := Seal(nil, key, pt)

	// Flip a bit in the tag.
	badTag := tag
	badTag[0] ^= 1

	got, err := Open(nil, key, ct, &badTag)
	if err != ErrInvalidCiphertext {
		t.Errorf("Open error = %v, want ErrInvalidCiphertext", err)
	}
	if got != nil {
		t.Error("Open returned non-nil plaintext on failure")
	}
}

func TestOpenCiphertextModified(t *testing.T) {
	key := testKey()
	pt := make([]byte, ChunkSize)
	for i := range pt {
		pt[i] = byte(i)
	}

	ct, tag := Seal(nil, key, pt)

	// Flip a bit in the ciphertext.
	ct[0] ^= 1

	got, err := Open(nil, key, ct, &tag)
	if err != ErrInvalidCiphertext {
		t.Errorf("Open error = %v, want ErrInvalidCiphertext", err)
	}
	if got != nil {
		t.Error("Open returned non-nil plaintext on failure")
	}
}

func TestOpenChunkSwapped(t *testing.T) {
	key := testKey()
	pt := make([]byte, 2*ChunkSize)
	for i := range pt {
		pt[i] = byte(i)
	}

	ct, tag := Seal(nil, key, pt)

	// Swap the two chunks, keep the tag.
	swapped := make([]byte, len(ct))
	copy(swapped[:ChunkSize], ct[ChunkSize:])
	copy(swapped[ChunkSize:], ct[:ChunkSize])

	got, err := Open(nil, key, swapped, &tag)
	if err != ErrInvalidCiphertext {
		t.Errorf("Open error = %v, want ErrInvalidCiphertext", err)
	}
	if got != nil {
		t.Error("Open returned non-nil plaintext on failure")
	}
}

func TestOpenWrongKey(t *testing.T) {
	key := testKey()
	pt := []byte("hello world")

	ct, tag := Seal(nil, key, pt)

	var wrongKey [KeySize]byte
	for i := range wrongKey {
		wrongKey[i] = byte(i + 1)
	}

	got, err := Open(nil, &wrongKey, ct, &tag)
	if err != ErrInvalidCiphertext {
		t.Errorf("Open error = %v, want ErrInvalidCiphertext", err)
	}
	if got != nil {
		t.Error("Open returned non-nil plaintext on failure")
	}
}

func TestOpenEmpty(t *testing.T) {
	key := testKey()

	// Empty ciphertext with valid tag should succeed.
	ct, tag := Seal(nil, key, nil)
	got, err := Open(nil, key, ct, &tag)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("got %d bytes, want 0", len(got))
	}
}

func TestSealX2MatchesX1(t *testing.T) {
	key := testKey()

	// x1 path: two separate calls.
	cv1 := make([]byte, 2*cvSize)
	pt := make([]byte, 2*ChunkSize)
	for i := range pt {
		pt[i] = byte(i)
	}

	ct1 := make([]byte, 2*ChunkSize)
	sealX1(key, 0, pt[:ChunkSize], ct1[:ChunkSize], cv1[:cvSize])
	sealX1(key, 1, pt[ChunkSize:], ct1[ChunkSize:], cv1[cvSize:])

	// x2 path: single call.
	cv2 := make([]byte, 2*cvSize)
	ct2 := make([]byte, 2*ChunkSize)
	sealX2(key, 0, pt, ct2, cv2)

	if !bytes.Equal(ct1, ct2) {
		t.Error("sealX2 ciphertext does not match sealX1")
	}
	if !bytes.Equal(cv1, cv2) {
		t.Error("sealX2 chain values do not match sealX1")
	}
}

func TestSealX4MatchesX1(t *testing.T) {
	key := testKey()

	pt := make([]byte, 4*ChunkSize)
	for i := range pt {
		pt[i] = byte(i)
	}

	// x1 path.
	cv1 := make([]byte, 4*cvSize)
	ct1 := make([]byte, 4*ChunkSize)
	for i := range 4 {
		sealX1(key, uint64(i), pt[i*ChunkSize:(i+1)*ChunkSize], ct1[i*ChunkSize:(i+1)*ChunkSize], cv1[i*cvSize:(i+1)*cvSize])
	}

	// x4 path.
	cv4 := make([]byte, 4*cvSize)
	ct4 := make([]byte, 4*ChunkSize)
	sealX4(key, 0, pt, ct4, cv4)

	if !bytes.Equal(ct1, ct4) {
		t.Error("sealX4 ciphertext does not match sealX1")
	}
	if !bytes.Equal(cv1, cv4) {
		t.Error("sealX4 chain values do not match sealX1")
	}
}

func TestOpenX2MatchesX1(t *testing.T) {
	key := testKey()

	// First seal to get ciphertext.
	pt := make([]byte, 2*ChunkSize)
	for i := range pt {
		pt[i] = byte(i)
	}
	ct, _ := Seal(nil, key, pt)

	// x1 path.
	cv1 := make([]byte, 2*cvSize)
	pt1 := make([]byte, 2*ChunkSize)
	openX1(key, 0, ct[:ChunkSize], pt1[:ChunkSize], cv1[:cvSize])
	openX1(key, 1, ct[ChunkSize:], pt1[ChunkSize:], cv1[cvSize:])

	// x2 path.
	cv2 := make([]byte, 2*cvSize)
	pt2 := make([]byte, 2*ChunkSize)
	openX2(key, 0, ct, pt2, cv2)

	if !bytes.Equal(pt1, pt2) {
		t.Error("openX2 plaintext does not match openX1")
	}
	if !bytes.Equal(cv1, cv2) {
		t.Error("openX2 chain values do not match openX1")
	}
}

func TestOpenX4MatchesX1(t *testing.T) {
	key := testKey()

	pt := make([]byte, 4*ChunkSize)
	for i := range pt {
		pt[i] = byte(i)
	}
	ct, _ := Seal(nil, key, pt)

	// x1 path.
	cv1 := make([]byte, 4*cvSize)
	pt1 := make([]byte, 4*ChunkSize)
	for i := range 4 {
		openX1(key, uint64(i), ct[i*ChunkSize:(i+1)*ChunkSize], pt1[i*ChunkSize:(i+1)*ChunkSize], cv1[i*cvSize:(i+1)*cvSize])
	}

	// x4 path.
	cv4 := make([]byte, 4*cvSize)
	pt4 := make([]byte, 4*ChunkSize)
	openX4(key, 0, ct, pt4, cv4)

	if !bytes.Equal(pt1, pt4) {
		t.Error("openX4 plaintext does not match openX1")
	}
	if !bytes.Equal(cv1, cv4) {
		t.Error("openX4 chain values do not match openX1")
	}
}

func TestLengthEncode(t *testing.T) {
	tests := []struct {
		input uint64
		want  string
	}{
		{0, "00"},
		{1, "0101"},
		{255, "ff01"},
		{256, "010002"},
		{65535, "ffff02"},
	}
	for _, tt := range tests {
		got := hex.EncodeToString(lengthEncode(tt.input))
		if got != tt.want {
			t.Errorf("lengthEncode(%d) = %s, want %s", tt.input, got, tt.want)
		}
	}
}

func TestSealVectors(t *testing.T) {
	key := testKey()

	// Test vectors generated from the reference x1 implementation.
	// Each entry records the first min(32, len) bytes of ciphertext (hex) and the full tag (hex).
	tests := []struct {
		name    string
		ptSize  int
		wantCT  string
		wantTag string
	}{
		{"empty", 0, "", "4d74e724544a5498eb490e22778f990b91f4881abadf52aab863144ca037ee2d"},
		{"1 byte", 1, "f1", "11c7e612c89abd32f4f3421557b2e29614eda613b2bcb316a15d02099a867769"},
		{"one chunk", ChunkSize, "f13513b1112a5cf6cfd4fe007a73351cc808c4837321b9860843b2ef40c06163", "2550a32191dfa145cadc8364812821be06fd566472804df57be019629b911385"},
		{"one chunk plus one", ChunkSize + 1, "f13513b1112a5cf6cfd4fe007a73351cc808c4837321b9860843b2ef40c06163", "9ed701f2d71ab47bc8e2819e256cb922a46f05497c292c383663fdcf2d6c9877"},
		{"four chunks", 4 * ChunkSize, "f13513b1112a5cf6cfd4fe007a73351cc808c4837321b9860843b2ef40c06163", "ae07f24e71e77ee3bc3247bfb87b897cede60b35186a95f00ba089391cf668c0"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pt := make([]byte, tt.ptSize)
			for j := range pt {
				pt[j] = byte(j)
			}
			ct, tag := Seal(nil, key, pt)

			prefix := min(32, len(ct))
			if ctHex := hex.EncodeToString(ct[:prefix]); ctHex != tt.wantCT {
				t.Errorf("ct prefix = %s, want %s", ctHex, tt.wantCT)
			}
			if tagHex := hex.EncodeToString(tag[:]); tagHex != tt.wantTag {
				t.Errorf("tag = %s, want %s", tagHex, tt.wantTag)
			}
		})
	}
}

func BenchmarkSeal(b *testing.B) {
	b.Logf("Keccak lanes = %v", keccak.Lanes)
	key := testKey()

	benchmarks := []struct {
		name   string
		length int
	}{
		{"1B", 1},
		{"8KiB", 8 * 1024},
		{"32KiB", 32 * 1024},
		{"64KiB", 64 * 1024},
		{"1MiB", 1024 * 1024},
	}

	for _, bb := range benchmarks {
		pt := make([]byte, bb.length)
		output := make([]byte, bb.length)
		b.Run(fmt.Sprintf("Seal/%s", bb.name), func(b *testing.B) {
			b.SetBytes(int64(bb.length))
			b.ReportAllocs()
			for b.Loop() {
				Seal(output[:0], key, pt)
			}
		})
	}
}

func BenchmarkOpen(b *testing.B) {
	key := testKey()

	benchmarks := []struct {
		name   string
		length int
	}{
		{"1B", 1},
		{"8KiB", 8 * 1024},
		{"64KiB", 64 * 1024},
		{"1MiB", 1024 * 1024},
	}

	for _, bb := range benchmarks {
		pt := make([]byte, bb.length)
		ct, tag := Seal(nil, key, pt)
		output := make([]byte, bb.length)
		b.Run(fmt.Sprintf("Open/%s", bb.name), func(b *testing.B) {
			b.SetBytes(int64(bb.length))
			b.ReportAllocs()
			for b.Loop() {
				_, _ = Open(output[:0], key, ct, &tag)
			}
		})
	}
}
