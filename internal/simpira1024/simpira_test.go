package simpira1024

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/codahale/newplex/internal/testdata"
)

func TestPermute(t *testing.T) {
	var state [128]byte
	Permute(&state)

	// from reference implementation at https://mouha.be/wp-content/uploads/simpira_v2.zip, corrected for endianness
	if got, want := hex.EncodeToString(state[:]), "5a7d4c12b2c4483055c5125c73c98edd8ae680baed946a6a42d52bc714f08c5f86d37c6b2e1840f17c8872add1068f5d17d120e2b00ffa0e5513874e92db2c29a4254192dd6eea69e00c38c7240606d8e92c475ee701b669138309d96f93ff2d9313436f5ec7655c26d9674a98fe583974fc76ddc75185816cd3121104a87778"; got != want {
		t.Errorf("Permute(0x00) = %s, want = %s", got, want)
	}
}

func FuzzPermute(f *testing.F) {
	drbg := testdata.New("simpira-1024-v2")
	for range 10 {
		f.Add(drbg.Data(Width))
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) != Width {
			t.Skip()
		}

		var state1, state2 [Width]byte
		copy(state1[:], data)
		copy(state2[:], data)
		Permute(&state1)
		permuteGeneric(&state2)

		if got, want := state1[:], state2[:]; !bytes.Equal(got, want) {
			t.Errorf("Permute-ASM(%x) = %x, want = %x", data, got, want)
		}
	})
}

func BenchmarkPermute(b *testing.B) {
	var state [128]byte
	b.ReportAllocs()
	b.SetBytes(int64(len(state)))
	for b.Loop() {
		Permute(&state)
	}
}
