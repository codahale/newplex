package treeprf

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func testSeed() *[SeedSize]byte {
	var seed [SeedSize]byte
	for i := range seed {
		seed[i] = byte(i)
	}

	return &seed
}

func TestGenerate(t *testing.T) {
	seed := testSeed()

	// Test vectors generated from a reference TurboSHAKE128 implementation.
	// Each entry records the first and last 32 bytes (hex) of the output.
	tests := []struct {
		name       string
		length     int
		wantPrefix string
		wantSuffix string
	}{
		{"1 byte", 1, "40", "40"},
		{"168 bytes", 168, "400d714755bd327fb3016a8ddc92d6a5ea855978502e044d0f3abccc8f517b93", "09c6828430076c0593c6c3b924c7f7ff2d324e6a96157fa778dabb6580332f55"},
		{"169 bytes", 169, "400d714755bd327fb3016a8ddc92d6a5ea855978502e044d0f3abccc8f517b93", "c6828430076c0593c6c3b924c7f7ff2d324e6a96157fa778dabb6580332f55d2"},
		{"one chunk", ChunkSize, "400d714755bd327fb3016a8ddc92d6a5ea855978502e044d0f3abccc8f517b93", "29b61650659ff57a37a3cf0c583c0b615fbc8f75036b20683474161558dea468"},
		{"one chunk plus one", ChunkSize + 1, "400d714755bd327fb3016a8ddc92d6a5ea855978502e044d0f3abccc8f517b93", "b61650659ff57a37a3cf0c583c0b615fbc8f75036b20683474161558dea4685f"},
		{"two chunks", 2 * ChunkSize, "400d714755bd327fb3016a8ddc92d6a5ea855978502e044d0f3abccc8f517b93", "32cc4903c61422438e47be76dd79d51c9affcd7c424907fec40cffb763baed57"},
		{"three chunks", 3 * ChunkSize, "400d714755bd327fb3016a8ddc92d6a5ea855978502e044d0f3abccc8f517b93", "8f81055782a7b214a832071b7780fb279ab42dd164f10e5ca50459866194714c"},
		{"four chunks", 4 * ChunkSize, "400d714755bd327fb3016a8ddc92d6a5ea855978502e044d0f3abccc8f517b93", "b75aae0ac6a16015b9a4227dd3b00e130c31f04a4ac5d8b77da3e1225de7e57e"},
		{"five chunks", 5 * ChunkSize, "400d714755bd327fb3016a8ddc92d6a5ea855978502e044d0f3abccc8f517b93", "6bccc8c98530cd9f168b29040a7a3a30e9a2742e9ee82f3c76e727f5959a5850"},
		{"four chunks plus one", 4*ChunkSize + 1, "400d714755bd327fb3016a8ddc92d6a5ea855978502e044d0f3abccc8f517b93", "5aae0ac6a16015b9a4227dd3b00e130c31f04a4ac5d8b77da3e1225de7e57e55"},
		{"six chunks plus 100", 6*ChunkSize + 100, "400d714755bd327fb3016a8ddc92d6a5ea855978502e044d0f3abccc8f517b93", "142769b35a6ad5b475a1b110ed3e30a9ec004727040dcae50447ec1a1c3411b4"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Generate(seed, tt.length)

			prefix := min(32, len(got))
			if p := hex.EncodeToString(got[:prefix]); p != tt.wantPrefix {
				t.Errorf("prefix: got %s, want %s", p, tt.wantPrefix)
			}

			suffixStart := max(0, len(got)-32)
			if s := hex.EncodeToString(got[suffixStart:]); s != tt.wantSuffix {
				t.Errorf("suffix: got %s, want %s", s, tt.wantSuffix)
			}
		})
	}
}

func TestGenerateZeroLength(t *testing.T) {
	seed := testSeed()

	if got := Generate(seed, 0); got != nil {
		t.Errorf("Generate(seed, 0) = %v, want nil", got)
	}

	if got := Generate(seed, -1); got != nil {
		t.Errorf("Generate(seed, -1) = %v, want nil", got)
	}
}

func TestGenerateX2MatchesX1(t *testing.T) {
	seed := testSeed()

	x2out := make([]byte, 2*ChunkSize)
	generateX2(seed, 0, x2out)

	x1out := make([]byte, 2*ChunkSize)
	generateX1(seed, 0, x1out[:ChunkSize])
	generateX1(seed, 1, x1out[ChunkSize:])

	if !bytes.Equal(x2out, x1out) {
		t.Error("generateX2 does not match generateX1")
	}
}

func TestGenerateX4MatchesX1(t *testing.T) {
	seed := testSeed()

	x4out := make([]byte, 4*ChunkSize)
	generateX4(seed, 0, x4out)

	x1out := make([]byte, 4*ChunkSize)
	for i := range 4 {
		generateX1(seed, uint64(i), x1out[i*ChunkSize:(i+1)*ChunkSize])
	}

	if !bytes.Equal(x4out, x1out) {
		t.Error("generateX4 does not match generateX1")
	}
}

func BenchmarkGenerate(b *testing.B) {
	seed := testSeed()

	//for i := 0; i <= 8*1024; i += 128 {
	//	n := max(i, 1)
	//	b.Run(fmt.Sprintf("%d", n), func(b *testing.B) {
	//		b.SetBytes(int64(n))
	//		b.ReportAllocs()
	//		for b.Loop() {
	//			Generate(seed, n)
	//		}
	//	})
	//}

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
		b.Run(bb.name, func(b *testing.B) {
			b.SetBytes(int64(bb.length))
			b.ReportAllocs()
			for b.Loop() {
				Generate(seed, bb.length)
			}
		})
	}
}
