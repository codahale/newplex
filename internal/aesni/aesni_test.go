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

	got := aesni.AESENCLAST(state, key)
	if !bytes.Equal(got[:], want[:]) {
		t.Errorf("AESENCLAST(0, 0) = %x, want %x", got, want)
	}
}

func TestSBoxVectors(t *testing.T) {
	// Table of (input index, input value, output index, output value)
	// Assuming Key=0, other bytes=0.
	// Base output for 0 is 0x63.

	// Case 1: Input[0]=0x01. Sbox(0x01)=0x7c. ShiftRows: 0->0. Output[0]=0x7c.
	// Case 2: Input[1]=0x01. Sbox(0x01)=0x7c. ShiftRows: 1<-5. We want where 1 goes?
	// ShiftRows: state[1] gets old[5]. state[13] gets old[1].
	// So Input[1] (which becomes 7c) moves to 13. Output[13]=0x7c.
	// Case 3: Input[0]=0xff. Sbox(0xff)=0x16. Output[0]=0x16.

	tests := []struct {
		inIdx  int
		inVal  byte
		outIdx int
		outVal byte
	}{
		{0, 0x01, 0, 0x7c},
		{1, 0x01, 13, 0x7c}, // Row 1 shift: 1->13
		{5, 0x01, 1, 0x7c},  // Row 1 shift: 5->1
		{2, 0x01, 10, 0x7c}, // Row 2 shift: 2->10
		{3, 0x01, 7, 0x7c},  // Row 3 shift: 3->7 (3->15->11->7)
		{0, 0xff, 0, 0x16},
	}

	for _, tc := range tests {
		var state, key [16]byte
		state[tc.inIdx] = tc.inVal

		// Fill others with 0 -> should become 0x63
		// We expect 0x63 everywhere except outIdx

		got := aesni.AESENCLAST(state, key)

		if got[tc.outIdx] != tc.outVal {
			t.Errorf("In[%d]=%x: Out[%d] = %x, want %x", tc.inIdx, tc.inVal, tc.outIdx, got[tc.outIdx], tc.outVal)
		}

		// Check others are 0x63
		for i := range 16 {
			if i != tc.outIdx {
				if got[i] != 0x63 {
					t.Errorf("In[%d]=%x: Out[%d] = %x, want 0x63", tc.inIdx, tc.inVal, i, got[i])
				}
			}
		}
	}
}
