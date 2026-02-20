package aead_test

import (
	"fmt"

	"github.com/codahale/newplex/aead"
)

func Example() {
	key := []byte("a very secret key, 32 bytes long")
	nonce := []byte("a 16-byte nonce!")
	ad := []byte("some additional data")
	plaintext := []byte("hello world")

	// Create a new AEAD instance with a 16-byte nonce.
	c := aead.New("com.example.aead", key, 16)

	// Seal the plaintext.
	ciphertext := c.Seal(nil, nonce, plaintext, ad)
	fmt.Printf("ciphertext = %x\n", ciphertext)

	// Open the ciphertext.
	decrypted, err := c.Open(nil, nonce, ciphertext, ad)
	if err != nil {
		panic(err)
	}
	fmt.Printf("plaintext  = %s\n", decrypted)

	// Output:
	// ciphertext = 5cbd82ac3cdc5b1c7c0fc1a0f969533d51081739379e6e500cfbeb
	// plaintext  = hello world
}
