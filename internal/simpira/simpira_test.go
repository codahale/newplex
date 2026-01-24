package simpira //nolint:testpackage // need access to generic impl

import (
	"bytes"
	"crypto/sha3"
	"encoding/hex"
	"testing"
)

func TestPermute256(t *testing.T) {
	var state [32]byte
	Permute256(&state)

	// from reference implementation at https://mouha.be/wp-content/uploads/simpira_v2.zip, corrected for endianness
	if got, want := hex.EncodeToString(state[:]), "6b95ca7d8cda46cf97ab4430a8ef27c631b464a6ed106a553e30a83ba08c14c2"; got != want {
		t.Errorf("Permute256(0x00) = %s, want = %s", got, want)
	}
}

func TestPermute512(t *testing.T) {
	var state [64]byte
	Permute512(&state)

	// from reference implementation at https://mouha.be/wp-content/uploads/simpira_v2.zip, corrected for endianness
	if got, want := hex.EncodeToString(state[:]), "085727e5a09556892f95f629ae534ba18316ac501e85a4cf1b574e605d1b215ebcd7835744f8c880cdd054e7f3438c1a460ca6c24bdb0779068ed270cd9d9bdb"; got != want {
		t.Errorf("Permute512(0x00) = %s, want = %s", got, want)
	}
}

func TestPermute768(t *testing.T) {
	var state [96]byte
	Permute768(&state)

	// from reference implementation at https://mouha.be/wp-content/uploads/simpira_v2.zip, corrected for endianness
	if got, want := hex.EncodeToString(state[:]), "9236688b9d98eaa569e690f11fb7cfa1f555e8977e67cbd0efb3955652b93211d2d8626b344530429aac0ce4ee42779a2885662f63c16414631f516b0b9a6492bb356d9e8e5d356f7ee92dbab7a9b2a449e7f2686b68afb60cdfaebdce1e5a22"; got != want {
		t.Errorf("Permute768(0x00) = %s, want = %s", got, want)
	}
}

func TestPermute1024(t *testing.T) {
	var state [128]byte
	Permute1024(&state)

	// from reference implementation at https://mouha.be/wp-content/uploads/simpira_v2.zip, corrected for endianness
	if got, want := hex.EncodeToString(state[:]), "5a7d4c12b2c4483055c5125c73c98edd8ae680baed946a6a42d52bc714f08c5f86d37c6b2e1840f17c8872add1068f5d17d120e2b00ffa0e5513874e92db2c29a4254192dd6eea69e00c38c7240606d8e92c475ee701b669138309d96f93ff2d9313436f5ec7655c26d9674a98fe583974fc76ddc75185816cd3121104a87778"; got != want {
		t.Errorf("Permute1024(0x00) = %s, want = %s", got, want)
	}
}

func FuzzPermute256(f *testing.F) {
	const width = 32

	drbg := sha3.NewSHAKE128()
	_, _ = drbg.Write([]byte("simpira-256-v2"))
	for range 10 {
		state := make([]byte, width)
		_, _ = drbg.Read(state)
		f.Add(state)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) != width {
			t.Skip()
		}

		var state1, state2 [width]byte
		copy(state1[:], data)
		copy(state2[:], data)
		Permute256(&state1)
		permute256Generic(&state2)

		if got, want := state2[:], state1[:]; !bytes.Equal(got, want) {
			t.Errorf("Permute256-ASM(%x) = %x, want = %x", data, got, want)
		}
	})
}

func FuzzPermute512(f *testing.F) {
	const width = 64

	drbg := sha3.NewSHAKE128()
	_, _ = drbg.Write([]byte("simpira-512-v2"))
	for range 10 {
		state := make([]byte, width)
		_, _ = drbg.Read(state)
		f.Add(state)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) != width {
			t.Skip()
		}

		var state1, state2 [width]byte
		copy(state1[:], data)
		copy(state2[:], data)
		Permute512(&state1)
		permute512Generic(&state2)

		if got, want := state2[:], state1[:]; !bytes.Equal(got, want) {
			t.Errorf("Permute512-ASM(%x) = %x, want = %x", data, got, want)
		}
	})
}

func FuzzPermute768(f *testing.F) {
	const width = 96

	drbg := sha3.NewSHAKE128()
	_, _ = drbg.Write([]byte("simpira-768-v2"))
	for range 10 {
		state := make([]byte, width)
		_, _ = drbg.Read(state)
		f.Add(state)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) != width {
			t.Skip()
		}

		var state1, state2 [width]byte
		copy(state1[:], data)
		copy(state2[:], data)
		Permute768(&state1)
		permute768Generic(&state2)

		if got, want := state2[:], state1[:]; !bytes.Equal(got, want) {
			t.Errorf("Permute768-ASM(%x) = %x, want = %x", data, got, want)
		}
	})
}

func FuzzPermute1024(f *testing.F) {
	const width = 128

	drbg := sha3.NewSHAKE128()
	_, _ = drbg.Write([]byte("simpira-1024-v2"))
	for range 10 {
		state := make([]byte, width)
		_, _ = drbg.Read(state)
		f.Add(state)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) != width {
			t.Skip()
		}

		var state1, state2 [width]byte
		copy(state1[:], data)
		copy(state2[:], data)
		Permute1024(&state1)
		permute1024Generic(&state2)

		if got, want := state2[:], state1[:]; !bytes.Equal(got, want) {
			t.Errorf("Permute1024-ASM(%x) = %x, want = %x", data, got, want)
		}
	})
}
