package newplex_test

import (
	"testing"

	"github.com/codahale/newplex"
)

func BenchmarkHashScheme(b *testing.B) {
	hash := func(message, dst []byte) []byte {
		protocol := newplex.NewProtocol("hash")
		protocol.Mix("message", message)
		return protocol.Derive("digest", dst, 32)
	}

	for _, length := range lengths {
		b.Run(length.name, func(b *testing.B) {
			input := make([]byte, length.n)
			digest := make([]byte, 32)
			b.ReportAllocs()
			b.SetBytes(int64(len(input)))
			for b.Loop() {
				hash(input, digest[:0])
			}
		})
	}
}

func BenchmarkPRFScheme(b *testing.B) {
	key := make([]byte, 32)
	prf := func(output []byte) []byte {
		protocol := newplex.NewProtocol("prf")
		protocol.Mix("key", key)
		return protocol.Derive("output", output[:0], len(output))
	}

	for _, length := range lengths {
		b.Run(length.name, func(b *testing.B) {
			output := make([]byte, length.n)
			b.ReportAllocs()
			b.SetBytes(int64(len(output)))
			for b.Loop() {
				prf(output)
			}
		})
	}
}

func BenchmarkStreamScheme(b *testing.B) {
	key := make([]byte, 32)
	nonce := make([]byte, 16)
	stream := func(message []byte) []byte {
		protocol := newplex.NewProtocol("stream")
		protocol.Mix("key", key)
		protocol.Mix("nonce", nonce)
		return protocol.Mask("message", message[:0], message)
	}

	for _, length := range lengths {
		b.Run(length.name, func(b *testing.B) {
			output := make([]byte, length.n)
			b.ReportAllocs()
			b.SetBytes(int64(len(output)))
			for b.Loop() {
				stream(output)
			}
		})
	}
}

func BenchmarkAEADScheme(b *testing.B) {
	key := make([]byte, 32)
	nonce := make([]byte, 16)
	ad := make([]byte, 32)
	aead := func(message []byte) []byte {
		protocol := newplex.NewProtocol("aead")
		protocol.Mix("key", key)
		protocol.Mix("nonce", nonce)
		protocol.Mix("ad", ad)
		return protocol.Seal("message", message[:0], message)
	}

	for _, length := range lengths {
		b.Run(length.name, func(b *testing.B) {
			output := make([]byte, length.n+newplex.TagSize)
			b.ReportAllocs()
			b.SetBytes(int64(len(output)))
			for b.Loop() {
				aead(output[:length.n])
			}
		})
	}
}

var lengths = []struct {
	name string
	n    int
}{
	{"16B", 16},
	{"32B", 32},
	{"64B", 64},
	{"128B", 128},
	{"256B", 256},
	{"1KiB", 1024},
	{"16KiB", 16 * 1024},
	{"1MiB", 1024 * 1024},
}
