package newplex_test

import (
	"testing"

	"github.com/codahale/newplex"
)

func BenchmarkInit(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		newplex.NewProtocol("mix")
	}
}

func BenchmarkMix(b *testing.B) {
	p := newplex.NewProtocol("mix")
	label := "label"
	input := []byte("input")

	b.ReportAllocs()
	for b.Loop() {
		p.Mix(label, input)
	}
}

func BenchmarkDerive(b *testing.B) {
	p := newplex.NewProtocol("derive")
	label := "label"
	output := make([]byte, 32)

	b.ReportAllocs()
	for b.Loop() {
		p.Derive(label, output[:0], len(output))
	}
}

func BenchmarkEncrypt(b *testing.B) {
	p := newplex.NewProtocol("encrypt")
	label := "label"
	output := make([]byte, 32)

	b.ReportAllocs()
	for b.Loop() {
		p.Encrypt(label, output[:0], output)
	}
}

func BenchmarkDecrypt(b *testing.B) {
	p := newplex.NewProtocol("decrypt")
	label := "label"
	output := make([]byte, 32)

	b.ReportAllocs()
	for b.Loop() {
		p.Decrypt(label, output[:0], output)
	}
}

func BenchmarkSeal(b *testing.B) {
	p := newplex.NewProtocol("seal")
	label := "label"
	output := make([]byte, 32+newplex.TagSize)

	b.ReportAllocs()
	for b.Loop() {
		p.Seal(label, output[:0], output[:32])
	}
}

func BenchmarkOpen(b *testing.B) {
	output := make([]byte, 32)
	p := newplex.NewProtocol("open")
	ciphertext := p.Seal("label", nil, output)

	b.ReportAllocs()
	for b.Loop() {
		p := newplex.NewProtocol("open")
		if _, err := p.Open("label", output[:0], ciphertext); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkHash(b *testing.B) {
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

func BenchmarkPRF(b *testing.B) {
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

func BenchmarkStream(b *testing.B) {
	key := make([]byte, 32)
	nonce := make([]byte, 16)
	stream := func(message []byte) []byte {
		protocol := newplex.NewProtocol("stream")
		protocol.Mix("key", key)
		protocol.Mix("nonce", nonce)
		return protocol.Encrypt("message", message[:0], message)
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

func BenchmarkAEAD(b *testing.B) {
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

func BenchmarkDuplex_Absorb(b *testing.B) {
	for _, length := range lengths {
		b.Run(length.name, func(b *testing.B) {
			var d newplex.Duplex
			input := make([]byte, length.n)
			b.SetBytes(int64(length.n))
			b.ReportAllocs()
			for b.Loop() {
				d.Absorb(input)
			}
		})
	}
}

func BenchmarkDuplex_Squeeze(b *testing.B) {
	for _, length := range lengths {
		b.Run(length.name, func(b *testing.B) {
			var d newplex.Duplex
			output := make([]byte, length.n)
			b.SetBytes(int64(length.n))
			b.ReportAllocs()
			for b.Loop() {
				d.Squeeze(output)
			}
		})
	}
}

func BenchmarkDuplex_Encrypt(b *testing.B) {
	for _, length := range lengths {
		b.Run(length.name, func(b *testing.B) {
			var d newplex.Duplex
			d.Permute()

			output := make([]byte, length.n)
			b.SetBytes(int64(length.n))
			b.ReportAllocs()
			for b.Loop() {
				d.Encrypt(output, output)
			}
		})
	}
}

func BenchmarkDuplex_Decrypt(b *testing.B) {
	for _, length := range lengths {
		b.Run(length.name, func(b *testing.B) {
			var d newplex.Duplex
			d.Permute()

			output := make([]byte, length.n)
			b.SetBytes(int64(length.n))
			b.ReportAllocs()
			for b.Loop() {
				d.Decrypt(output, output)
			}
		})
	}
}

//nolint:gochecknoglobals // this is fine
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
