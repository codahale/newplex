//go:build !purego

package mhf_test

import (
	"bytes"
	"fmt"
	"testing"

	mhf_busted "github.com/codahale/newplex/mhf"
)

func ExampleHash() {
	domain := "example passwords"
	cost := uint8(10)
	password := []byte("C'est moi, le Mario")
	salt := []byte("a yellow submarine")
	n := 32
	hash := mhf_busted.Hash(domain, cost, salt, password, nil, n)
	fmt.Printf("hash = %x\n", hash)
	// Output:
	// hash = 81b0398987c396b2e894735beab0f99106705691b04683fca1197fa98ec7ac2d
}

func TestHash(t *testing.T) {
	domain := "example passwords"
	cost := uint8(10)
	password := []byte("C'est moi, le Mario")
	salt := []byte("a yellow submarine")
	n := 32
	hash := mhf_busted.Hash(domain, cost, salt, password, nil, n)

	t.Run("happy path", func(t *testing.T) {
		if got, want := mhf_busted.Hash(domain, cost, salt, password, nil, n), hash; !bytes.Equal(got, want) {
			t.Errorf("Hash = %x, want = %x", got, want)
		}
	})

	t.Run("wrong domain", func(t *testing.T) {
		wrongDomain := "example crosswords"
		if got, want := mhf_busted.Hash(wrongDomain, cost, salt, password, nil, n), hash; bytes.Equal(got, want) {
			t.Errorf("Hash = %x, want != %x", got, want)
		}
	})

	t.Run("wrong cost", func(t *testing.T) {
		wrongCost := uint8(8)
		if got, want := mhf_busted.Hash(domain, wrongCost, salt, password, nil, n), hash; bytes.Equal(got, want) {
			t.Errorf("Hash = %x, want != %x", got, want)
		}
	})

	t.Run("wrong salt", func(t *testing.T) {
		wrongSalt := []byte("okay")
		if got, want := mhf_busted.Hash(domain, cost, wrongSalt, password, nil, n), hash; bytes.Equal(got, want) {
			t.Errorf("Hash = %x, want != %x", got, want)
		}
	})

	t.Run("wrong password", func(t *testing.T) {
		wrongPassword := []byte("It is I, Mario")
		if got, want := mhf_busted.Hash(domain, cost, salt, wrongPassword, nil, n), hash; bytes.Equal(got, want) {
			t.Errorf("Hash = %x, want != %x", got, want)
		}
	})

	t.Run("wrong output length", func(t *testing.T) {
		wrongN := 22
		if got, want := mhf_busted.Hash(domain, cost, salt, password, nil, wrongN), hash; bytes.Equal(got, want) {
			t.Errorf("Hash = %x, want != %x", got, want)
		}
	})
}
