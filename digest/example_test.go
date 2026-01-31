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
	// 6ba59cc7a456b062ca13f189ae7271bdce34506067f70d480f8d9c66bfcba8ce
}

func Example_keyed() {
	h := digest.NewKeyed("com.example.mac", []byte("a secret key"))
	_, _ = io.WriteString(h, "hello")
	_, _ = io.WriteString(h, " world")

	sum := h.Sum(nil)
	fmt.Printf("%x\n", sum)

	// Output:
	// 03927b1b8a4ab6c162aa8a2e2df003ad
}
