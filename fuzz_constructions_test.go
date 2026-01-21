package newplex_test

import (
	"bytes"
	"testing"

	"github.com/codahale/newplex"
)

func FuzzStream(f *testing.F) {
	encrypt := func(key []byte, nonce []byte, message []byte) (ciphertext, state []byte) {
		protocol := newplex.NewProtocol("stream")
		protocol.Mix("key", key)
		protocol.Mix("nonce", nonce)
		return protocol.Encrypt("message", nil, message), protocol.Derive("state", nil, 8)
	}

	decrypt := func(key []byte, nonce []byte, message []byte) (plaintext, state []byte) {
		protocol := newplex.NewProtocol("stream")
		protocol.Mix("key", key)
		protocol.Mix("nonce", nonce)
		return protocol.Decrypt("message", nil, message), protocol.Derive("state", nil, 8)
	}

	f.Add([]byte("yellow submarine"), []byte("12345678"), []byte("hello world"))
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

	f.Add([]byte("yellow submarine"), []byte("12345678"), []byte("hello world"), uint(2), byte(100))
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
