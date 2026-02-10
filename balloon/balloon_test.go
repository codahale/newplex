//go:build !purego

package balloon_test

import (
	"fmt"

	"github.com/codahale/newplex/balloon"
	"github.com/codahale/newplex/internal/testdata"
)

func ExampleHash() {
	drbg := testdata.New("newplex balloon")

	password := []byte("secret stuff")
	salt := drbg.Data(16)

	hash := balloon.Hash("example", password, salt, 10*1024, 50, 4)
	fmt.Printf("%x\n", hash)
	// Output:
	// 13a06d498574b4dedd15b70507874f49d2e4b55365b4031bda47733478bfb508
}
