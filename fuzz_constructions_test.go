package newplex_test

import (
	"bytes"
	"crypto/sha3"
	"encoding/binary"
	"testing"

	"github.com/codahale/newplex"
)

func FuzzStream(f *testing.F) {
	encrypt := func(key []byte, nonce []byte, message []byte) (ciphertext, state []byte) {
		protocol := newplex.NewProtocol("stream")
		protocol.Mix("key", key)
		protocol.Mix("nonce", nonce)
		return protocol.Mask("message", nil, message), protocol.Derive("state", nil, 8)
	}

	decrypt := func(key []byte, nonce []byte, message []byte) (plaintext, state []byte) {
		protocol := newplex.NewProtocol("stream")
		protocol.Mix("key", key)
		protocol.Mix("nonce", nonce)
		return protocol.Unmask("message", nil, message), protocol.Derive("state", nil, 8)
	}

	drbg := sha3.NewSHAKE128()
	_, _ = drbg.Write([]byte("newplex stream"))
	for range 10 {
		key := make([]byte, 16)
		nonce := make([]byte, 16)
		message := make([]byte, 32)
		_, _ = drbg.Read(key)
		_, _ = drbg.Read(nonce)
		_, _ = drbg.Read(message)
		f.Add(key, nonce, message)
	}

	f.Fuzz(func(t *testing.T, key []byte, nonce []byte, message []byte) {
		ciphertext, stateA := encrypt(key, nonce, message)
		plaintext, stateB := decrypt(key, nonce, ciphertext)
		if got, want := plaintext, message; !bytes.Equal(got, want) {
			t.Errorf("decrypt(key, nonce, ciphertext) = %v, want = %v", got, want)
		}
		if !bytes.Equal(stateA, stateB) {
			t.Errorf("divergent posterior protocol states: %v != %v", stateA, stateB)
		}
	})
}

func FuzzAEAD(f *testing.F) {
	encrypt := func(key []byte, nonce []byte, message []byte) (ciphertext, state []byte) {
		protocol := newplex.NewProtocol("aead")
		protocol.Mix("key", key)
		protocol.Mix("nonce", nonce)
		return protocol.Seal("message", nil, message), protocol.Derive("state", nil, 8)
	}

	decrypt := func(key []byte, nonce []byte, message []byte) (plaintext, state []byte, err error) {
		protocol := newplex.NewProtocol("aead")
		protocol.Mix("key", key)
		protocol.Mix("nonce", nonce)
		plaintext, err = protocol.Open("message", nil, message)
		if err != nil {
			return nil, nil, err
		}
		return plaintext, protocol.Derive("state", nil, 8), nil
	}

	drbg := sha3.NewSHAKE128()
	_, _ = drbg.Write([]byte("newplex stream"))
	for range 10 {
		key := make([]byte, 16)
		nonce := make([]byte, 16)
		message := make([]byte, 32)
		idx := make([]byte, 4)
		mask := make([]byte, 1)
		_, _ = drbg.Read(key)
		_, _ = drbg.Read(nonce)
		_, _ = drbg.Read(message)
		_, _ = drbg.Read(idx)
		_, _ = drbg.Read(mask)
		f.Add(key, nonce, message, uint(binary.LittleEndian.Uint32(idx))%uint(len(message)), mask[0])
	}

	f.Fuzz(func(t *testing.T, key []byte, nonce []byte, plaintext []byte, idx uint, mask byte) {
		if mask == 0 {
			t.Skip()
		}

		c, stateA := encrypt(key, nonce, plaintext)

		// check for decryption of authentic ciphertext
		p2, stateB, err := decrypt(key, nonce, c)
		if err != nil {
			t.Fatal(err)
		}
		if got, want := p2, plaintext; !bytes.Equal(got, want) {
			t.Errorf("decrypt(key, nonce, c) = %v, want = %v", got, want)
		}

		if !bytes.Equal(stateA, stateB) {
			t.Errorf("divergent posterior protocol states: %v != %v", stateA, stateB)
		}

		// check for non-decryption of inauthentic ciphertext
		c[int(idx)%len(c)] ^= mask

		if got, _, err := decrypt(key, nonce, c); err == nil {
			t.Errorf("decrypt(key, nonce, c) = %v, want = nil", got)
		}
	})
}
