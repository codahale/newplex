package newplex_test

import (
	"encoding/hex"
	"testing"

	"github.com/codahale/newplex"
)

func TestKnownAnswers(t *testing.T) {
	t.Parallel()

	protocol := newplex.NewProtocol("com.example.kat")
	protocol.Mix("first", []byte("one"))
	protocol.Mix("second", []byte("two"))

	if got, want := hex.EncodeToString(protocol.Derive("third", nil, 8)), "b3e84580eb6dd574"; got != want {
		t.Errorf("Derive('third') = %v, want = %v", got, want)
	}

	plaintext := []byte("this is an example")
	ciphertext := protocol.Encrypt("fourth", nil, plaintext)
	if got, want := hex.EncodeToString(ciphertext), "267cd4e78fc8200d36794993a4995beb5b53"; got != want {
		t.Errorf("Encrypt('fourth') = %v, want = %v", got, want)
	}

	ciphertext = protocol.Seal("fifth", nil, []byte("this is an example"))
	if got, want := hex.EncodeToString(ciphertext), "2e5a2970a54e078a68de4936b49cf817b29c18583269a25489efe951717975e78334"; got != want {
		t.Errorf("Seal('fifth') = %v, want = %v", got, want)
	}

	if got, want := hex.EncodeToString(protocol.Derive("sixth", nil, 8)), "b9a55ebe685ee94a"; got != want {
		t.Errorf("Derive('sixth') = %v, want = %v", got, want)
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
