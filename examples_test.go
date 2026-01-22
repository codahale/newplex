package newplex_test

import (
	"crypto/ecdh"
	"crypto/sha3"
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
	rng := sha3.NewSHAKE128()
	_, _ = rng.Write([]byte("newplex hpke example"))

	receiver, err := ecdh.P256().GenerateKey(rng)
	if err != nil {
		panic(err)
	}

	var ciphertext []byte
	{
		ephemeral, err := ecdh.P256().GenerateKey(rng)
		if err != nil {
			panic(err)
		}

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
		ephemeral, err := ecdh.P256().NewPublicKey(ciphertext[:65])
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
		plaintext, err := hpke.Open("message", nil, ciphertext[65:])
		if err != nil {
			panic(err)
		}
		fmt.Printf("%s\n", plaintext)
	}
	// Output:
	// 040b848704e689d88b8a85438297e444941fd8a783329cab7ea28e63511394da76067d6b42ba81c544a2cba13319c133f2351d732396b9603f30289e7d308e23f6ae53f7ba497928288292c1e0d361a2ac3c0aa3a591dede8b42d1d8
	// hello world
}
