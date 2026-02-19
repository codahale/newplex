package duplex

import (
	"encoding/hex"
	"fmt"
	"slices"
	"testing"
)

func TestDuplex_Frame(t *testing.T) {
	var d State
	d.Frame()
	d.Absorb([]byte{0xDE, 0xAD})

	if got, want := debugDuplex(&d), "1_3_00dead0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"; got != want {
		t.Errorf("state = %s, want = %s", got, want)
	}

	d.Frame()
	d.Absorb([]byte{0xCA, 0xFE})

	if got, want := debugDuplex(&d), "4_6_00dead01cafe0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"; got != want {
		t.Errorf("state = %s, want = %s", got, want)
	}

	d.Frame()
	d.Absorb([]byte{0xBA, 0xBE})

	if got, want := debugDuplex(&d), "7_9_00dead01cafe04babe0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"; got != want {
		t.Errorf("state = %s, want = %s", got, want)
	}
}

func TestDuplex_AbsorbLEB128(t *testing.T) {
	tests := []struct {
		name  string
		input uint64
		want  string
	}{
		{
			name:  "0x2003cb",
			input: 0x2003cb,
			want:  "0_4_cb87800100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var d State
			d.AbsorbLEB128(tt.input)

			if got := debugDuplex(&d); got != tt.want {
				t.Errorf("state = %s, want = %s", got, tt.want)
			}
		})
	}
}

func TestDuplex_Absorb(t *testing.T) {
	t.Run("simple", func(t *testing.T) {
		if got, want := debugDuplex(new(exampleDuplex())), "0_10_0102030405060708090a00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"; got != want {
			t.Errorf("state = %s, want = %s", got, want)
		}
	})

	t.Run("multi-block", func(t *testing.T) {
		var d State
		d.Absorb(slices.Repeat([]byte{0xde, 0xad, 0xbe, 0xef}, 340))

		if got, want := debugDuplex(&d), "0_44_3b4d7442225e01fcd042cfe773cd9bee1ce542978c1fc55889a002bdd526fa40a205809ab56291534bda796addde4d06e43ff891011b4c486224ace12bf876a47f4dccaaba33dd7cc2c59f11241097d8d994798f7186c73b7d7f9e2b7b882409f20dad4b96d1a54adeaf32ea7abccc5e9cb9b6837010ec826e82e90d441719c8"; got != want {
			t.Errorf("state = %s, want = %s", got, want)
		}
	})
}

func TestDuplex_Squeeze(t *testing.T) {
	t.Run("simple", func(t *testing.T) {
		var d State
		d.Permute()

		if got, want := debugDuplex(&d), "0_0_d768fa7909cf75f1d1dbfedbc27b2bd0912bb283ec8f5ff7ecb89400d98a083201a3d3ff76087915a51326ef181801bd5c7c2f4685eb3a4839be3b392b8632465f6b184743d9bff9ad923e16f45f486bf04664ed1d9ad186abc39d35456ad0f32f72f740b12330460259c73e0e3bf908cdd6b1b09af91884e04595998c89e6df"; got != want {
			t.Errorf("state = %s, want = %s", got, want)
		}

		out := make([]byte, 10)
		d.Squeeze(out)

		if got, want := debugDuplex(&d), "0_10_d768fa7909cf75f1d1dbfedbc27b2bd0912bb283ec8f5ff7ecb89400d98a083201a3d3ff76087915a51326ef181801bd5c7c2f4685eb3a4839be3b392b8632465f6b184743d9bff9ad923e16f45f486bf04664ed1d9ad186abc39d35456ad0f32f72f740b12330460259c73e0e3bf908cdd6b1b09af91884e04595998c89e6df"; got != want {
			t.Errorf("state = %s, want = %s", got, want)
		}

		if got, want := hex.EncodeToString(out), "d768fa7909cf75f1d1db"; got != want {
			t.Errorf("Squeeze = %s, want = %s", got, want)
		}
	})

	t.Run("multi-block", func(t *testing.T) {
		var d State
		d.Permute()

		out := make([]byte, 2000)
		d.Squeeze(out)

		if got, want := debugDuplex(&d), "0_26_ba6fce95189d9ab473df173085129cc31c5bcaee3fac1ff754366c43769d0e70f41a7a8f378cdd5df04d9ed74f21a06410240c558582742112dbf09249db29ec710f14ec86d411ad55bfbd1781523574161587c332d27fa474cf377051d5ef8e99f9846046063e43882d747c16ec4242169080d9b2d6e3f1facec4f3422c95b8"; got != want {
			t.Errorf("state = %s, want = %s", got, want)
		}

		if got, want := hex.EncodeToString(out[:10]), "d768fa7909cf75f1d1db"; got != want {
			t.Errorf("Squeeze = %s, want = %s", got, want)
		}
	})
}

func TestDuplex_Permute(t *testing.T) {
	d := exampleDuplex()

	if got, want := debugDuplex(&d), "0_10_0102030405060708090a00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"; got != want {
		t.Errorf("state = %s, want = %s", got, want)
	}

	d.Permute()

	if got, want := debugDuplex(&d), "0_0_559c1ff8adef4306a244c2d8bdd743082eab0c7fc14aff639d44f12a5a115b3a9dec0ec7c0387844c457a350bec4aa082666e7b6244921a9384166b0f221775110ccbbc6b4e961fe958eb69c8e94d05456a725e719380df22818be7f280ed597e6d888effb221783ab029666d817c64d84f4ea0da7f1fa0ee7001a0fc48659bc"; got != want {
		t.Errorf("state = %s, want = %s", got, want)
	}
}

func TestDuplex_Ratchet(t *testing.T) {
	t.Run("simple", func(t *testing.T) {
		d := exampleDuplex()

		if got, want := debugDuplex(&d), "0_10_0102030405060708090a00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"; got != want {
			t.Errorf("state = %s, want = %s", got, want)
		}

		d.Ratchet()

		if got, want := debugDuplex(&d), "0_32_00000000000000000000000000000000000000000000000000000000000000009dec0ec7c0387844c457a350bec4aa082666e7b6244921a9384166b0f221775110ccbbc6b4e961fe958eb69c8e94d05456a725e719380df22818be7f280ed597e6d888effb221783ab029666d817c64d84f4ea0da7f1fa0ee7001a0fc48659bc"; got != want {
			t.Errorf("state = %s, want = %s", got, want)
		}
	})

	t.Run("freshly permuted", func(t *testing.T) {
		d := exampleDuplex()
		d.Permute()

		if got, want := debugDuplex(&d), "0_0_559c1ff8adef4306a244c2d8bdd743082eab0c7fc14aff639d44f12a5a115b3a9dec0ec7c0387844c457a350bec4aa082666e7b6244921a9384166b0f221775110ccbbc6b4e961fe958eb69c8e94d05456a725e719380df22818be7f280ed597e6d888effb221783ab029666d817c64d84f4ea0da7f1fa0ee7001a0fc48659bc"; got != want {
			t.Errorf("state = %s, want = %s", got, want)
		}

		d.Ratchet()

		if got, want := debugDuplex(&d), "0_32_00000000000000000000000000000000000000000000000000000000000000009dec0ec7c0387844c457a350bec4aa082666e7b6244921a9384166b0f221775110ccbbc6b4e961fe958eb69c8e94d05456a725e719380df22818be7f280ed597e6d888effb221783ab029666d817c64d84f4ea0da7f1fa0ee7001a0fc48659bc"; got != want {
			t.Errorf("state = %s, want = %s", got, want)
		}
	})
}

func TestDuplex_Encrypt(t *testing.T) {
	t.Run("simple", func(t *testing.T) {
		d := exampleDuplex()

		if got, want := debugDuplex(&d), "0_10_0102030405060708090a00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"; got != want {
			t.Errorf("state = %s, want = %s", got, want)
		}

		d.Permute()

		plaintext := []byte("this is a message")
		ciphertext := make([]byte, len(plaintext))
		d.Encrypt(ciphertext, plaintext)

		if got, want := debugDuplex(&d), "0_17_21f4768b8d863026c364afbdcea4226f4bab0c7fc14aff639d44f12a5a115b3a9dec0ec7c0387844c457a350bec4aa082666e7b6244921a9384166b0f221775110ccbbc6b4e961fe958eb69c8e94d05456a725e719380df22818be7f280ed597e6d888effb221783ab029666d817c64d84f4ea0da7f1fa0ee7001a0fc48659bc"; got != want {
			t.Errorf("state = %s, want = %s", got, want)
		}

		if got, want := hex.EncodeToString(ciphertext), "21f4768b8d863026c364afbdcea4226f4b"; got != want {
			t.Errorf("ciphertext = %s, want = %s", got, want)
		}
	})

	t.Run("in place", func(t *testing.T) {
		d := exampleDuplex()

		if got, want := debugDuplex(&d), "0_10_0102030405060708090a00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"; got != want {
			t.Errorf("debugDuplex() = %s, want = %s", got, want)
		}

		d.Permute()

		inout := []byte("this is a message")
		d.Encrypt(inout, inout)

		if got, want := debugDuplex(&d), "0_17_21f4768b8d863026c364afbdcea4226f4bab0c7fc14aff639d44f12a5a115b3a9dec0ec7c0387844c457a350bec4aa082666e7b6244921a9384166b0f221775110ccbbc6b4e961fe958eb69c8e94d05456a725e719380df22818be7f280ed597e6d888effb221783ab029666d817c64d84f4ea0da7f1fa0ee7001a0fc48659bc"; got != want {
			t.Errorf("debugDuplex() = %s, want = %s", got, want)
		}

		if got, want := hex.EncodeToString(inout), "21f4768b8d863026c364afbdcea4226f4b"; got != want {
			t.Errorf("ciphertext = %s, want = %s", got, want)
		}
	})

	t.Run("multi-block", func(t *testing.T) {
		d := exampleDuplex()

		plaintext := make([]byte, 11*77*43)
		ciphertext := make([]byte, len(plaintext))
		d.Encrypt(ciphertext, plaintext)

		if got, want := debugDuplex(&d), "0_53_68cc9a651c13768b12b375b957f930d2766ebe31c61664d8f45ddf8c781f17a54563db076aab96b78602d862558b8c6393167e80dfa96514140f6934c7fbe8373099375f801b14f4ac0da798d11636b2043e40c637705c6c4ed894e1ff5bffc20f4dbf15e807e174d5c84195224eba033d08b08f9db3edd35f15747ddfe47a03"; got != want {
			t.Errorf("state = %s, want = %s", got, want)
		}
	})
}

func TestDuplex_Decrypt(t *testing.T) {
	t.Run("simple", func(t *testing.T) {
		d := exampleDuplex()

		if got, want := debugDuplex(&d), "0_10_0102030405060708090a00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"; got != want {
			t.Errorf("state = %s, want = %s", got, want)
		}

		d.Permute()

		ciphertext, _ := hex.DecodeString("21f4768b8d863026c364afbdcea4226f4b")
		plaintext := make([]byte, len(ciphertext))
		d.Decrypt(plaintext, ciphertext)

		if got, want := debugDuplex(&d), "0_17_21f4768b8d863026c364afbdcea4226f4bab0c7fc14aff639d44f12a5a115b3a9dec0ec7c0387844c457a350bec4aa082666e7b6244921a9384166b0f221775110ccbbc6b4e961fe958eb69c8e94d05456a725e719380df22818be7f280ed597e6d888effb221783ab029666d817c64d84f4ea0da7f1fa0ee7001a0fc48659bc"; got != want {
			t.Errorf("state = %s, want = %s", got, want)
		}

		if got, want := string(plaintext), "this is a message"; got != want {
			t.Errorf("plaintext = %s, want = %s", got, want)
		}
	})

	t.Run("in place", func(t *testing.T) {
		d := exampleDuplex()

		if got, want := debugDuplex(&d), "0_10_0102030405060708090a00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"; got != want {
			t.Errorf("state = %s, want = %s", got, want)
		}

		d.Permute()

		inout, _ := hex.DecodeString("21f4768b8d863026c364afbdcea4226f4b")
		d.Decrypt(inout, inout)

		if got, want := debugDuplex(&d), "0_17_21f4768b8d863026c364afbdcea4226f4bab0c7fc14aff639d44f12a5a115b3a9dec0ec7c0387844c457a350bec4aa082666e7b6244921a9384166b0f221775110ccbbc6b4e961fe958eb69c8e94d05456a725e719380df22818be7f280ed597e6d888effb221783ab029666d817c64d84f4ea0da7f1fa0ee7001a0fc48659bc"; got != want {
			t.Errorf("state = %s, want = %s", got, want)
		}

		if got, want := string(inout), "this is a message"; got != want {
			t.Errorf("inout = %s, want = %s", got, want)
		}
	})

	t.Run("multi-block", func(t *testing.T) {
		d := exampleDuplex()

		ciphertext := make([]byte, 11*77*43)
		plaintext := make([]byte, len(ciphertext))
		d.Decrypt(plaintext, ciphertext)

		if got, want := debugDuplex(&d), "0_53_00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006c05c088577ad2503a7d870b9311be3ef27fa6164a6174b90158b152386976352689b26d782c31489df34ecbb3799e9fa644eef9e097881d2ecce5fbb270d3d93d2e81eb25cc1557a1be00"; got != want {
			t.Errorf("state = %s, want = %s", got, want)
		}
	})
}

func TestDuplex_Clear(t *testing.T) {
	var d1, d2 State
	d1.Absorb([]byte("input input input"))
	d1.Permute()
	d1.Clear()

	if got, want := d1.Equal(&d2), 1; got != want {
		t.Errorf("Equal() = %d, want = %d (cleared duplex not equal to uninitialized duplex)", got, want)
	}
}

func TestDuplex_Equal(t *testing.T) {
	t.Run("Equal", func(t *testing.T) {
		var d1, d2 State
		if got, want := d1.Equal(&d2), 1; got != want {
			t.Errorf("Equal() = %d, want = %d", got, want)
		}
	})

	t.Run("different states", func(t *testing.T) {
		var d1, d2 State
		d1.state[0] = 200

		if got, want := d1.Equal(&d2), 0; got != want {
			t.Errorf("Equal() = %d, want = %d", got, want)
		}
	})

	t.Run("different rate indexes", func(t *testing.T) {
		var d1, d2 State
		d1.rateIdx = 23

		if got, want := d1.Equal(&d2), 0; got != want {
			t.Errorf("Equal() = %d, want = %d", got, want)
		}
	})

	t.Run("different Frame indexes", func(t *testing.T) {
		var d1, d2 State
		d1.frameIdx = 23

		if got, want := d1.Equal(&d2), 0; got != want {
			t.Errorf("Equal() = %d, want = %d", got, want)
		}
	})
}

func TestDuplex_AppendBinary(t *testing.T) {
	d := exampleDuplex()

	b, err := d.AppendBinary([]byte{22, 23})
	if err != nil {
		t.Fatal(err)
	}

	if got, want := hex.EncodeToString(b), "16170a000102030405060708090a00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"; got != want {
		t.Errorf("AppendBinary() = %s, want = %s", got, want)
	}
}

func TestDuplex_MarshalBinary(t *testing.T) {
	d := exampleDuplex()

	b, err := d.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}

	if got, want := hex.EncodeToString(b), "0a000102030405060708090a00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"; got != want {
		t.Errorf("MarshalBinary() = %s, want = %s", got, want)
	}
}

func TestDuplex_UnmarshalBinary(t *testing.T) {
	tests := []struct {
		name    string
		data    string
		want    string
		wantErr bool
	}{
		{
			name: "valid state",
			data: "0a0b0102030405060708090a00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
			want: "11_10_0102030405060708090a00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
		},
		{
			name:    "short state",
			data:    "0a000102030405060708090a00000000",
			wantErr: true,
		},
		{
			name:    "invalid rateIdx",
			data:    "ff000102030405060708090a00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
			wantErr: true,
		},
		{
			name:    "invalid frameIdx",
			data:    "00ff0102030405060708090a00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var d State
			data, _ := hex.DecodeString(tt.data)
			err := d.UnmarshalBinary(data)

			if (err != nil) != tt.wantErr {
				t.Errorf("UnmarshalBinary() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				if got := debugDuplex(&d); got != tt.want {
					t.Errorf("debugDuplex() = %s, want = %s", got, tt.want)
				}
			}
		})
	}
}

func debugDuplex(d *State) string {
	return fmt.Sprintf("%d_%d_%x", d.frameIdx, d.rateIdx, d.state[:])
}

func exampleDuplex() State {
	var d State
	d.Absorb([]byte{1, 2, 3, 4, 5})
	d.Absorb([]byte{6, 7, 8, 9, 10})
	return d
}

func BenchmarkDuplex_Absorb(b *testing.B) {
	for _, length := range lengths {
		b.Run(length.name, func(b *testing.B) {
			var d State
			input := make([]byte, length.n)
			b.SetBytes(int64(length.n))
			b.ReportAllocs()
			for b.Loop() {
				d.Absorb(input)
			}
		})
	}
}

func BenchmarkDuplex_Squeeze(b *testing.B) {
	for _, length := range lengths {
		b.Run(length.name, func(b *testing.B) {
			var d State
			output := make([]byte, length.n)
			b.SetBytes(int64(length.n))
			b.ReportAllocs()
			for b.Loop() {
				d.Squeeze(output)
			}
		})
	}
}

func BenchmarkDuplex_Encrypt(b *testing.B) {
	for _, length := range lengths {
		b.Run(length.name, func(b *testing.B) {
			var d State
			d.Permute()

			output := make([]byte, length.n)
			b.SetBytes(int64(length.n))
			b.ReportAllocs()
			for b.Loop() {
				d.Encrypt(output, output)
			}
		})
	}
}

func BenchmarkDuplex_Decrypt(b *testing.B) {
	for _, length := range lengths {
		b.Run(length.name, func(b *testing.B) {
			var d State
			d.Permute()

			output := make([]byte, length.n)
			b.SetBytes(int64(length.n))
			b.ReportAllocs()
			for b.Loop() {
				d.Decrypt(output, output)
			}
		})
	}
}

var lengths = []struct {
	name string
	n    int
}{
	{"16B", 16},
	{"32B", 32},
	{"64B", 64},
	{"128B", 128},
	{"256B", 256},
	{"1KiB", 1024},
	{"16KiB", 16 * 1024},
	{"1MiB", 1024 * 1024},
}
