package simpira //nolint:testpackage // need access to generic impl

import (
	"bytes"
	"crypto/sha3"
	"encoding/hex"
	"testing"
)

func TestPermute2(t *testing.T) {
	var state [32]byte
	Permute256(&state)

	// from reference implementation at https://mouha.be/wp-content/uploads/simpira_v2.zip, corrected for endianness
	if got, want := hex.EncodeToString(state[:]), "6b95ca7d8cda46cf97ab4430a8ef27c631b464a6ed106a553e30a83ba08c14c2"; got != want {
		t.Errorf("Permute256(0x00) = %s, want = %s", got, want)
	}
}

func TestPermute4(t *testing.T) {
	var state [64]byte
	Permute512(&state)

	// from reference implementation at https://mouha.be/wp-content/uploads/simpira_v2.zip, corrected for endianness
	if got, want := hex.EncodeToString(state[:]), "085727e5a09556892f95f629ae534ba18316ac501e85a4cf1b574e605d1b215ebcd7835744f8c880cdd054e7f3438c1a460ca6c24bdb0779068ed270cd9d9bdb"; got != want {
		t.Errorf("Permute512(0x00) = %s, want = %s", got, want)
	}
}

func TestPermute6(t *testing.T) {
	var state [96]byte
	Permute784(&state)

	// from reference implementation at https://mouha.be/wp-content/uploads/simpira_v2.zip, corrected for endianness
	if got, want := hex.EncodeToString(state[:]), "9236688b9d98eaa569e690f11fb7cfa1f555e8977e67cbd0efb3955652b93211d2d8626b344530429aac0ce4ee42779a2885662f63c16414631f516b0b9a6492bb356d9e8e5d356f7ee92dbab7a9b2a449e7f2686b68afb60cdfaebdce1e5a22"; got != want {
		t.Errorf("Permute784(0x00) = %s, want = %s", got, want)
	}
}

func TestPermute8(t *testing.T) {
	var state [128]byte
	Permute1024(&state)

	// from reference implementation at https://mouha.be/wp-content/uploads/simpira_v2.zip, corrected for endianness
	if got, want := hex.EncodeToString(state[:]), "5a7d4c12b2c4483055c5125c73c98edd8ae680baed946a6a42d52bc714f08c5f86d37c6b2e1840f17c8872add1068f5d17d120e2b00ffa0e5513874e92db2c29a4254192dd6eea69e00c38c7240606d8e92c475ee701b669138309d96f93ff2d9313436f5ec7655c26d9674a98fe583974fc76ddc75185816cd3121104a87778"; got != want {
		t.Errorf("Permute1024(0x00) = %s, want = %s", got, want)
	}
}

func FuzzPermute2(f *testing.F) {
	const width = 32

	drbg := sha3.NewSHAKE128()
	_, _ = drbg.Write([]byte("simpira-2-v2"))
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

func FuzzPermute4(f *testing.F) {
	const width = 64

	drbg := sha3.NewSHAKE128()
	_, _ = drbg.Write([]byte("simpira-4-v2"))
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

func FuzzPermute6(f *testing.F) {
	const width = 96

	drbg := sha3.NewSHAKE128()
	_, _ = drbg.Write([]byte("simpira-6-v2"))
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
		Permute784(&state1)
		permute784Generic(&state2)

		if got, want := state2[:], state1[:]; !bytes.Equal(got, want) {
			t.Errorf("Permute784-ASM(%x) = %x, want = %x", data, got, want)
		}
	})
}

func FuzzPermute8(f *testing.F) {
	const width = 128

	drbg := sha3.NewSHAKE128()
	_, _ = drbg.Write([]byte("simpira-8-v2"))
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

func BenchmarkPermute2(b *testing.B) {
	var state [32]byte
	b.SetBytes(int64(len(state)))
	b.ReportAllocs()
	for b.Loop() {
		Permute256(&state)
	}
}

func BenchmarkPermute4(b *testing.B) {
	var state [64]byte
	b.SetBytes(int64(len(state)))
	b.ResetTimer()
	for b.Loop() {
		Permute512(&state)
	}
}

func BenchmarkPermute6(b *testing.B) {
	var state [96]byte
	b.SetBytes(int64(len(state)))
	b.ResetTimer()
	for b.Loop() {
		Permute784(&state)
	}
}

func BenchmarkPermute8(b *testing.B) {
	var state [128]byte
	b.SetBytes(int64(len(state)))
	b.ResetTimer()
	for b.Loop() {
		Permute1024(&state)
	}
}
