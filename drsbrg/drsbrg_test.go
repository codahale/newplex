package drsbrg_test

import (
	"bytes"
	"testing"

	"github.com/codahale/newplex/drsbrg"
)

func TestHash(t *testing.T) {
	domain := "example passwords"
	cost := uint8(10)
	password := []byte("C'est moi, le Mario")
	salt := []byte("a yellow submarine")
	n := 32
	hash := drsbrg.Hash(domain, cost, salt, password, nil, n)

	t.Run("happy path", func(t *testing.T) {
		if got, want := drsbrg.Hash(domain, cost, salt, password, nil, n), hash; !bytes.Equal(got, want) {
			t.Errorf("Hash = %x, want = %x", got, want)
		}
	})

	t.Run("wrong domain", func(t *testing.T) {
		wrongDomain := "example crosswords"
		if got, want := drsbrg.Hash(wrongDomain, cost, salt, password, nil, n), hash; bytes.Equal(got, want) {
			t.Errorf("Hash = %x, want != %x", got, want)
		}
	})

	t.Run("wrong cost", func(t *testing.T) {
		wrongCost := uint8(8)
		if got, want := drsbrg.Hash(domain, wrongCost, salt, password, nil, n), hash; bytes.Equal(got, want) {
			t.Errorf("Hash = %x, want != %x", got, want)
		}
	})

	t.Run("wrong salt", func(t *testing.T) {
		wrongSalt := []byte("okay")
		if got, want := drsbrg.Hash(domain, cost, wrongSalt, password, nil, n), hash; bytes.Equal(got, want) {
			t.Errorf("Hash = %x, want != %x", got, want)
		}
	})

	t.Run("wrong password", func(t *testing.T) {
		wrongPassword := []byte("It is I, Mario")
		if got, want := drsbrg.Hash(domain, cost, salt, wrongPassword, nil, n), hash; bytes.Equal(got, want) {
			t.Errorf("Hash = %x, want != %x", got, want)
		}
	})

	t.Run("wrong output length", func(t *testing.T) {
		wrongN := 22
		if got, want := drsbrg.Hash(domain, cost, salt, password, nil, wrongN), hash; bytes.Equal(got, want) {
			t.Errorf("Hash = %x, want != %x", got, want)
		}
	})
}
