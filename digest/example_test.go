package digest_test

import (
	"fmt"
	"io"

	"github.com/codahale/newplex/digest"
)

func Example() {
	h := digest.New("com.example.digest")
	_, _ = io.WriteString(h, "hello")
	_, _ = io.WriteString(h, " world")

	sum := h.Sum(nil)
	fmt.Printf("%x\n", sum)

	// Output:
	// 6ba59cc7a456b062ca13f189ae7271bdce34506067f70d480f8d9c66bfcba8ce
}
