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

func TestPermute1536(t *testing.T) {
	var state [192]byte
	Permute1536(&state)

	if got, want := hex.EncodeToString(state[:]), "6a8eb4fbe5176447d2c317efa3f1a847f3353cdbb4923c13e91477f5abdf14892e97ee6a96721f2a2dc2b8166f16f886d66250d12588c92a62df3fecf7047605119fafac8c74a1aab7f2f463277df2c92903671ebd1351e6e2e6c95f6d9827b82b7acef3b626eb684fed1c6435c2716917eda93eb5df312527ca58c726fe45b5e9a57a376a97e5705bf5689c35c106c4e5787efb3d8705be728b07d501c53554f1130d5c1a2ec70014b935923af4cc8715c9c502657d26093d5e931786e5bdbe"; got != want {
		t.Errorf("Permute1536(0x00) = %s, want = %s", got, want)
	}
}

func TestPermute2048(t *testing.T) {
	var state [256]byte
	Permute2048(&state)

	if got, want := hex.EncodeToString(state[:]), "085bfe50c91fef830db23fd0b1b26310f512b2e016f8b63cede55469c61a37418ec769175c62f41710530b4905307c1541aeb0be7e39587715c223ca4b954449a5eeb32b55635b1268e6a3491896a29e20b40b6634ca1fcc51073deab8ae0db1e18d65a0567b3bc6082f0e06c1df54dfd835e248f123ab932cce0a6683cea63bd61adcc310e8e1e755c5ced9fd2e2276c67d27ef2e757bd0b395581d20143c5412649c165e3ef6a0d1c342f94a37770f15060bb0fa949f4c556e2ce6cbb4514d868242aec3c31043238407c9d111019df239b337f27183958440025008d0f936f5b9d198a0311e3454891db7336109d7561edb9d7eeeea03d22aede1747afda5"; got != want {
		t.Errorf("Permute2048(0x00) = %s, want = %s", got, want)
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

func FuzzPermute1536(f *testing.F) {
	const width = 192

	drbg := sha3.NewSHAKE128()
	_, _ = drbg.Write([]byte("simpira-1536-v2"))
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
		Permute1536(&state1)
		permute1536Generic(&state2)

		if got, want := state2[:], state1[:]; !bytes.Equal(got, want) {
			t.Errorf("Permute1536-ASM(%x) = %x, want = %x", data, got, want)
		}
	})
}

func FuzzPermute2048(f *testing.F) {
	const width = 256

	drbg := sha3.NewSHAKE128()
	_, _ = drbg.Write([]byte("simpira-2048-v2"))
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
		Permute2048(&state1)
		permute2048Generic(&state2)

		if got, want := state2[:], state1[:]; !bytes.Equal(got, want) {
			t.Errorf("Permute2048-ASM(%x) = %x, want = %x", data, got, want)
		}
	})
}
