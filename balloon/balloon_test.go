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
	// 13a06d498574b4dedd15b70507874f49d2e4b55365b4031bda47733478bfb508
}
