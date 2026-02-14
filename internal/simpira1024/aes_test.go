package simpira1024

import (
	"encoding/hex"
	"testing"
)

func TestAES128(t *testing.T) {
	tests := []struct {
		key string
		pt  string
		ct  string
	}{
		// NIST FIPS 197 Appendix A.1 & B
		{"2b7e151628aed2a6abf7158809cf4f3c", "3243f6a8885a308d313198a2e0370734", "3925841d02dc09fbdc118597196a0b32"},
		// https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_Core128.pdf
		{"2b7e151628aed2a6abf7158809cf4f3c", "6bc1bee22e409f96e93d7e117393172a", "3ad77bb40d7a3660a89ecaf32466ef97"},
		{"2b7e151628aed2a6abf7158809cf4f3c", "ae2d8a571e03ac9c9eb76fac45af8e51", "f5d3d58503b9699de785895a96fdbaaf"},
		{"2b7e151628aed2a6abf7158809cf4f3c", "30c81c46a35ce411e5fbc1191a0a52ef", "43b1cd7f598ece23881b00e3ed030688"},
		{"2b7e151628aed2a6abf7158809cf4f3c", "f69f2445df4f9b17ad2b417be66c3710", "7b0c785e27e8ad3f8223207104725dd4"},
	}

	for _, tt := range tests {
		var key, pt [16]byte
		_, _ = hex.Decode(key[:], []byte(tt.key))
		_, _ = hex.Decode(pt[:], []byte(tt.pt))

		roundKeys := expandKey128(key)
		ct := aes128(pt, roundKeys)

		if hex.EncodeToString(ct[:]) != tt.ct {
			t.Errorf("AES-128(%s, %s) = %s, want = %x", tt.key, tt.pt, tt.ct, hex.EncodeToString(ct[:]))
		}
	}
}

func aes128(state [16]byte, roundKeys [11][16]byte) [16]byte {
	// Initial AddRoundKey
	for i := range 16 {
		state[i] ^= roundKeys[0][i]
	}
	// 9 rounds of AESENC
	for i := 1; i <= 9; i++ {
		state = aesEnc(state, roundKeys[i])
	}
	// Final round AESENCLAST
	state = aesEncLast(state, roundKeys[10])
	return state
}

func aesEncLast(state, key [16]byte) [16]byte {
	q := pack(state)
	q = sbox(q)
	q = shiftRows(q)
	state = unpack(q)
	for i := range 16 {
		state[i] ^= key[i]
	}
	return state
}

func expandKey128(key [16]byte) [11][16]byte {
	var w [44][4]byte
	for i := range 4 {
		w[i][0] = key[4*i]
		w[i][1] = key[4*i+1]
		w[i][2] = key[4*i+2]
		w[i][3] = key[4*i+3]
	}

	rcon := [10]byte{0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36}

	for i := 4; i < 44; i++ {
		temp := w[i-1]
		if i%4 == 0 {
			// RotWord
			temp[0], temp[1], temp[2], temp[3] = temp[1], temp[2], temp[3], temp[0]
			// SubWord
			temp[0] = subByte(temp[0])
			temp[1] = subByte(temp[1])
			temp[2] = subByte(temp[2])
			temp[3] = subByte(temp[3])
			// Rcon
			temp[0] ^= rcon[i/4-1]
		}
		for j := range 4 {
			w[i][j] = w[i-4][j] ^ temp[j]
		}
	}

	var roundKeys [11][16]byte
	for i := range 11 {
		for j := range 4 {
			copy(roundKeys[i][4*j:4*j+4], w[4*i+j][:])
		}
	}
	return roundKeys
}

func subByte(b byte) byte {
	var s [16]byte
	s[0] = b
	q := pack(s)
	q = sbox(q)
	s = unpack(q)
	return s[0]
}
