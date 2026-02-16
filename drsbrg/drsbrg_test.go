package drsbrg_test

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/codahale/newplex/drsbrg"
)

func ExampleHash() {
	domain := "example passwords"
	degree := uint8(3)
	cost := uint8(10)
	password := []byte("C'est moi, le Mario")
	salt := []byte("a yellow submarine")
	n := 32
	hash := drsbrg.Hash(domain, degree, cost, salt, password, nil, n)
	fmt.Printf("hash = %x\n", hash)
	// Output:
	// hash = cc5b6f361c4977429eaabd6ebc39f875f20fec104265200321ed92955d0f8bfe
}

func TestHash(t *testing.T) {
	domain := "example passwords"
	degree := uint8(3)
	cost := uint8(10)
	password := []byte("C'est moi, le Mario")
	salt := []byte("a yellow submarine")
	n := 32
	hash := drsbrg.Hash(domain, degree, cost, salt, password, nil, n)

	t.Run("happy path", func(t *testing.T) {
		if got, want := drsbrg.Hash(domain, degree, cost, salt, password, nil, n), hash; !bytes.Equal(got, want) {
			t.Errorf("Hash = %x, want = %x", got, want)
		}
	})

	t.Run("wrong domain", func(t *testing.T) {
		wrongDomain := "example crosswords"
		if got, want := drsbrg.Hash(wrongDomain, degree, cost, salt, password, nil, n), hash; bytes.Equal(got, want) {
			t.Errorf("Hash = %x, want != %x", got, want)
		}
	})

	t.Run("wrong degree", func(t *testing.T) {
		wrongDegree := uint8(5)
		if got, want := drsbrg.Hash(domain, wrongDegree, cost, salt, password, nil, n), hash; bytes.Equal(got, want) {
			t.Errorf("Hash = %x, want != %x", got, want)
		}
	})

	t.Run("wrong cost", func(t *testing.T) {
		wrongCost := uint8(8)
		if got, want := drsbrg.Hash(domain, degree, wrongCost, salt, password, nil, n), hash; bytes.Equal(got, want) {
			t.Errorf("Hash = %x, want != %x", got, want)
		}
	})

	t.Run("wrong salt", func(t *testing.T) {
		wrongSalt := []byte("okay")
		if got, want := drsbrg.Hash(domain, degree, cost, wrongSalt, password, nil, n), hash; bytes.Equal(got, want) {
			t.Errorf("Hash = %x, want != %x", got, want)
		}
	})

	t.Run("wrong password", func(t *testing.T) {
		wrongPassword := []byte("It is I, Mario")
		if got, want := drsbrg.Hash(domain, degree, cost, salt, wrongPassword, nil, n), hash; bytes.Equal(got, want) {
			t.Errorf("Hash = %x, want != %x", got, want)
		}
	})

	t.Run("wrong output length", func(t *testing.T) {
		wrongN := 22
		if got, want := drsbrg.Hash(domain, degree, cost, salt, password, nil, wrongN), hash; bytes.Equal(got, want) {
			t.Errorf("Hash = %x, want != %x", got, want)
		}
	})
}
