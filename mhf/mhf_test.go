//go:build !purego

package mhf_test

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/codahale/newplex/mhf"
)

func ExampleHash() {
	const degree = mhf.RecommendedDegree
	domain := "example passwords"
	cost := uint8(10)
	window := uint8(6)
	password := []byte("C'est moi, le Mario")
	salt := []byte("a yellow submarine")
	n := 32
	hash := mhf.Hash(domain, degree, cost, window, salt, password, nil, n)
	fmt.Printf("hash = %x\n", hash)
	// Output:
	// hash = 20976f26e309b95cdb88de285cd15a114acf436afacfed3b66976c398a2e413e
}

func TestHash(t *testing.T) {
	const degree = mhf.RecommendedDegree
	domain := "example passwords"
	cost := uint8(10)
	window := uint8(6)
	password := []byte("C'est moi, le Mario")
	salt := []byte("a yellow submarine")
	n := 32
	hash := mhf.Hash(domain, degree, cost, window, salt, password, nil, n)

	t.Run("happy path", func(t *testing.T) {
		if got, want := mhf.Hash(domain, degree, cost, window, salt, password, nil, n), hash; !bytes.Equal(got, want) {
			t.Errorf("Hash = %x, want = %x", got, want)
		}
	})

	t.Run("wrong domain", func(t *testing.T) {
		wrongDomain := "example crosswords"
		if got, want := mhf.Hash(wrongDomain, degree, cost, window, salt, password, nil, n), hash; bytes.Equal(got, want) {
			t.Errorf("Hash = %x, want != %x", got, want)
		}
	})

	t.Run("wrong degree", func(t *testing.T) {
		wrongDegree := uint8(5)
		if got, want := mhf.Hash(domain, wrongDegree, cost, window, salt, password, nil, n), hash; bytes.Equal(got, want) {
			t.Errorf("Hash = %x, want != %x", got, want)
		}
	})

	t.Run("wrong cost", func(t *testing.T) {
		wrongCost := uint8(8)
		if got, want := mhf.Hash(domain, degree, wrongCost, window, salt, password, nil, n), hash; bytes.Equal(got, want) {
			t.Errorf("Hash = %x, want != %x", got, want)
		}
	})

	t.Run("wrong window", func(t *testing.T) {
		wrongWindow := uint8(4)
		if got, want := mhf.Hash(domain, degree, cost, wrongWindow, salt, password, nil, n), hash; bytes.Equal(got, want) {
			t.Errorf("Hash = %x, want != %x", got, want)
		}
	})

	t.Run("wrong salt", func(t *testing.T) {
		wrongSalt := []byte("okay")
		if got, want := mhf.Hash(domain, degree, cost, window, wrongSalt, password, nil, n), hash; bytes.Equal(got, want) {
			t.Errorf("Hash = %x, want != %x", got, want)
		}
	})

	t.Run("wrong password", func(t *testing.T) {
		wrongPassword := []byte("It is I, Mario")
		if got, want := mhf.Hash(domain, degree, cost, window, salt, wrongPassword, nil, n), hash; bytes.Equal(got, want) {
			t.Errorf("Hash = %x, want != %x", got, want)
		}
	})

	t.Run("wrong output length", func(t *testing.T) {
		wrongN := 22
		if got, want := mhf.Hash(domain, degree, cost, window, salt, password, nil, wrongN), hash; bytes.Equal(got, want) {
			t.Errorf("Hash = %x, want != %x", got, want)
		}
	})
}
