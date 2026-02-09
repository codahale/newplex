package digest_test

import (
	"fmt"
	"io"

	"github.com/codahale/newplex/digest"
)

func Example_unkeyed() {
	h := digest.New("com.example.digest")
	_, _ = io.WriteString(h, "hello")
	_, _ = io.WriteString(h, " world")

	sum := h.Sum(nil)
	fmt.Printf("%x\n", sum)

	// Output:
	// f8953ef674fbd5ac23ae7b1475df0e0b44c1d2fbbb2b72d236bcc2648d4d43e3
}

func Example_keyed() {
	h := digest.NewKeyed("com.example.mac", []byte("a secret key"))
	_, _ = io.WriteString(h, "hello")
	_, _ = io.WriteString(h, " world")

	sum := h.Sum(nil)
	fmt.Printf("%x\n", sum)

	// Output:
	// 3104cbff524195a4428b5072a7a0f75c
}
