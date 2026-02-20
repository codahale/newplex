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
	// 7a62e5e1e9970881a422b236695fff99eb965d46b7fe717f2ed5b146ab9f4b4a
}

func Example_keyed() {
	h := digest.NewKeyed("com.example.mac", []byte("a secret key"))
	_, _ = io.WriteString(h, "hello")
	_, _ = io.WriteString(h, " world")

	sum := h.Sum(nil)
	fmt.Printf("%x\n", sum)

	// Output:
	// 338ac1840399da698161501d06d307a8
}
