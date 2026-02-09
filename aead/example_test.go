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
	// ciphertext = 17b7c21b5224c33a6af6d723dbdc8ded3ada07959dfb5b4bc7c610
	// plaintext  = hello world
}
