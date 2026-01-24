package aesni_test

import (
	"bytes"
	"testing"

	"github.com/codahale/newplex/internal/aesni"
)

func TestAESEnc(t *testing.T) {
	// Test vector: Input all zeros, Key all zeros.
	// SubBytes(0) = 0x63
	// ShiftRows(all 0x63) = all 0x63
	// MixColumns(all 0x63) -> all 0x63 (because 2*x + 3*x + x + x = x in GF(2^8))
	// AddRoundKey(0) -> all 0x63
	var state, key [16]byte
	want := [16]byte{
		0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63,
		0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63,
	}

	got := aesni.AESENC(state, key)
	if !bytes.Equal(got[:], want[:]) {
		t.Errorf("AESENC(0, 0) = %x, want %x", got, want)
	}
}

func TestAESEncLast(t *testing.T) {
	// Test vector: Input all zeros, Key all zeros.
	// SubBytes(0) = 0x63
	// ShiftRows(all 0x63) = all 0x63
	// MixColumns skipped
	// AddRoundKey(0) -> all 0x63
	var state, key [16]byte
	want := [16]byte{
		0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63,
		0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63,
	}

	got := aesni.AESENC(state, key)
	if !bytes.Equal(got[:], want[:]) {
		t.Errorf("AESENCLAST(0, 0) = %x, want %x", got, want)
	}
}
