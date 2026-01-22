package newplex_test

import (
	"crypto/ecdh"
	"encoding/hex"
	"fmt"

	"github.com/codahale/newplex"
)

func ExampleProtocol_mac() {
	// Initialize a protocol with a domain string.
	mac := newplex.NewProtocol("com.example.mac")

	// Mix the key into the protocol.
	key := []byte("my-secret-key")
	mac.Mix("key", key)

	// Mix the message into the protocol.
	message := []byte("hello world")
	mac.Mix("message", message)

	// Derive 16 bytes of output.
	// Note: The output length (128 bits) is encoded into the derivation, so
	// changing the length will change the output.
	tag := mac.Derive("tag", nil, 16)

	fmt.Printf("%x\n", tag)
	// Output: d389fa15b67663731325ff2d410dc0e4
}

func ExampleProtocol_stream() {
	var ciphertext, nonce []byte
	{
		// Initialize a protocol with a domain string.
		stream := newplex.NewProtocol("com.example.stream")

		// Mix the key into the protocol.
		key := []byte("my-secret-key")
		stream.Mix("key", key)

		// Mix a nonce into the protocol.
		nonce = []byte("actually random")
		stream.Mix("nonce", nonce)

		// Encrypt the plaintext.
		plaintext := []byte("hello world")
		ciphertext = stream.Encrypt("message", nil, plaintext)
		fmt.Printf("%x\n", ciphertext)
	}

	{
		// Initialize a protocol with a domain string.
		stream := newplex.NewProtocol("com.example.stream")

		// Mix the key into the protocol.
		key := []byte("my-secret-key")
		stream.Mix("key", key)

		// Mix a nonce into the protocol.
		nonce = []byte("actually random")
		stream.Mix("nonce", nonce)

		// Decrypt the ciphertext.
		plaintext := stream.Decrypt("message", nil, ciphertext)
		fmt.Printf("%s\n", plaintext)
	}

	// Output:
	// 8a3bda4589bcef6d0cac2f
	// hello world
}

func ExampleProtocol_aead() {
	var ciphertext []byte
	{
		// Initialize a protocol with a domain string.
		aead := newplex.NewProtocol("com.example.aead")

		// Mix the key into the protocol.
		key := []byte("my-secret-key")
		aead.Mix("key", key)

		// Mix the authenticated data into the protocol.
		ad := []byte("some authenticated data")
		aead.Mix("ad", ad)

		// Seal the plaintext.
		plaintext := []byte("hello world")
		ciphertext = aead.Seal("message", nil, plaintext)
		fmt.Printf("%x\n", ciphertext)
	}

	{
		// Initialize a protocol with a domain string.
		aead := newplex.NewProtocol("com.example.aead")

		// Mix the key into the protocol.
		key := []byte("my-secret-key")
		aead.Mix("key", key)

		// Mix the authenticated data into the protocol.
		ad := []byte("some authenticated data")
		aead.Mix("ad", ad)

		// Open the ciphertext.
		plaintext, err := aead.Open("message", nil, ciphertext)
		if err != nil {
			panic(err)
		}
		fmt.Printf("%s\n", plaintext)
	}

	// Output:
	// bc4b7bcc256e7be3420f9ff3e587c3b2ac13f9ed20536a1b4414ef
	// hello world
}

func Example_hpke() {
	receiverPrivBuf, _ := hex.DecodeString("c3a9b89b9a9a15da3c7a7e8ce9c96a828744abf52c0239f4180b0948fa3b1c74")
	receiver, _ := ecdh.X25519().NewPrivateKey(receiverPrivBuf)

	var ciphertext []byte
	{
		// This should be randomly generated, but it would make the test always fail.
		ephemeralPrivBuf, _ := hex.DecodeString("a0b9a9ea71d45df9a8c7cf7da798c4394342993b21f24c7bb3612e573e8a58df")
		ephemeral, _ := ecdh.X25519().NewPrivateKey(ephemeralPrivBuf)

		hpke := newplex.NewProtocol("com.example.hpke")
		hpke.Mix("receiver", receiver.PublicKey().Bytes())
		hpke.Mix("ephemeral", ephemeral.PublicKey().Bytes())
		ss, err := ephemeral.ECDH(receiver.PublicKey())
		if err != nil {
			panic(err)
		}
		hpke.Mix("ecdh", ss)
		ciphertext = hpke.Seal("message", ephemeral.PublicKey().Bytes(), []byte("hello world"))
		fmt.Printf("%x\n", ciphertext)
	}

	{
		ephemeral, err := ecdh.X25519().NewPublicKey(ciphertext[:32])
		if err != nil {
			panic(err)
		}

		hpke := newplex.NewProtocol("com.example.hpke")
		hpke.Mix("receiver", receiver.PublicKey().Bytes())
		hpke.Mix("ephemeral", ephemeral.Bytes())
		ss, err := receiver.ECDH(ephemeral)
		if err != nil {
			panic(err)
		}
		hpke.Mix("ecdh", ss)
		plaintext, err := hpke.Open("message", nil, ciphertext[32:])
		if err != nil {
			panic(err)
		}
		fmt.Printf("%s\n", plaintext)
	}
	// Output:
	// 672e904ba78b50b56f896d4b9c2f8018aecfd34038523a6faa4e82e37be4281f596dc142472d519b2fdcd11004ee9435447ac88aa9c422abc95d11
	// hello world
}
