package benchmarks_test

import (
	"testing"

	"github.com/codahale/newplex/internal/areion"
	"github.com/codahale/newplex/internal/ascon"
	"github.com/codahale/newplex/internal/gimli"
	"github.com/codahale/newplex/internal/haraka"
	"github.com/codahale/newplex/internal/keccak"
	"github.com/codahale/newplex/internal/simpira"
	"github.com/codahale/newplex/internal/xoodoo"
)

func BenchmarkAreion512(b *testing.B) {
	var state [64]byte
	b.SetBytes(int64(len(state)))
	b.ReportAllocs()
	for b.Loop() {
		areion.Permute512(&state)
	}
}

func BenchmarkAscon12(b *testing.B) {
	var state [40]byte
	b.SetBytes(int64(len(state)))
	b.ReportAllocs()
	for b.Loop() {
		ascon.Permute12(&state)
	}
}

func BenchmarkAscon8(b *testing.B) {
	var state [40]byte
	b.SetBytes(int64(len(state)))
	b.ReportAllocs()
	for b.Loop() {
		ascon.Permute8(&state)
	}
}

func BenchmarkGimli384(b *testing.B) {
	var state [48]byte
	b.SetBytes(int64(len(state)))
	b.ReportAllocs()
	for b.Loop() {
		gimli.Permute(&state)
	}
}

func BenchmarkHaraka512(b *testing.B) {
	var state [64]byte
	b.SetBytes(int64(len(state)))
	b.ReportAllocs()
	for b.Loop() {
		haraka.Permute512(&state)
	}
}

func BenchmarkKeccakF1600(b *testing.B) {
	var state [200]byte
	b.SetBytes(int64(len(state)))
	b.ReportAllocs()
	for b.Loop() {
		keccak.F1600(&state)
	}
}

func BenchmarkKeccakP1600(b *testing.B) {
	var state [200]byte
	b.SetBytes(int64(len(state)))
	b.ReportAllocs()
	for b.Loop() {
		keccak.P1600(&state)
	}
}

func BenchmarkSimpira256(b *testing.B) {
	var state [32]byte
	b.ReportAllocs()
	b.SetBytes(int64(len(state)))
	for b.Loop() {
		simpira.Permute256(&state)
	}
}

func BenchmarkSimpira512(b *testing.B) {
	var state [64]byte
	b.ReportAllocs()
	b.SetBytes(int64(len(state)))
	for b.Loop() {
		simpira.Permute512(&state)
	}
}

func BenchmarkSimpira768(b *testing.B) {
	var state [96]byte
	b.ReportAllocs()
	b.SetBytes(int64(len(state)))
	for b.Loop() {
		simpira.Permute768(&state)
	}
}

func BenchmarkSimpira1024(b *testing.B) {
	var state [128]byte
	b.ReportAllocs()
	b.SetBytes(int64(len(state)))
	for b.Loop() {
		simpira.Permute1024(&state)
	}
}

func BenchmarkXoodoo(b *testing.B) {
	var state [48]byte
	b.SetBytes(int64(len(state)))
	b.ReportAllocs()
	for b.Loop() {
		xoodoo.Permute(&state)
	}
}
