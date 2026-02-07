//go:build !purego

package balloon_test

import (
	"crypto/sha3"
	"fmt"

	"github.com/codahale/newplex/balloon"
)

func ExampleHash() {
	drbg := sha3.NewSHAKE128()
	_, _ = drbg.Write([]byte("newplex balloon"))

	password := []byte("secret stuff")
	salt := make([]byte, 16)
	_, _ = drbg.Read(salt)

	hash := balloon.Hash("example", password, salt, 10*1024, 50, 4)
	fmt.Printf("%x\n", hash)
	// Output:
	// f96ccea2ba507694406d99915f9ab72b5090b6e5b32b5c358eb9cfd8686587e3
}
