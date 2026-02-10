package newplex //nolint:testpackage // testing duplex internals

import (
	"encoding/hex"
	"fmt"
	"slices"
	"testing"
)

func TestDuplex_Frame(t *testing.T) {
	var d duplex
	d.frame()
	d.absorb([]byte{0xDE, 0xAD})

	if got, want := debugDuplex(&d), "1_3_00dead0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"; got != want {
		t.Errorf("state = %s, want = %s", got, want)
	}

	d.frame()
	d.absorb([]byte{0xCA, 0xFE})

	if got, want := debugDuplex(&d), "4_6_00dead01cafe0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"; got != want {
		t.Errorf("state = %s, want = %s", got, want)
	}

	d.frame()
	d.absorb([]byte{0xBA, 0xBE})

	if got, want := debugDuplex(&d), "7_9_00dead01cafe04babe0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"; got != want {
		t.Errorf("state = %s, want = %s", got, want)
	}
}

func TestDuplex_AbsorbLEB128(t *testing.T) {
	var d duplex
	d.absorbLEB128(0x2003cb)

	if got, want := debugDuplex(&d), "0_4_cb87800100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"; got != want {
		t.Errorf("state = \n%s\nwant  = \n%s", got, want)
	}
}

func TestDuplex_Absorb(t *testing.T) {
	t.Run("simple", func(t *testing.T) {
		d := exampleDuplex()

		if got, want := debugDuplex(&d), "0_10_0102030405060708090a00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"; got != want {
			t.Errorf("state = \n%s\nwant  = \n%s", got, want)
		}
	})

	t.Run("multi-block", func(t *testing.T) {
		var d duplex
		d.absorb(slices.Repeat([]byte{0xde, 0xad, 0xbe, 0xef}, 340))

		if got, want := debugDuplex(&d), "0_44_3b4d7442225e01fcd042cfe773cd9bee1ce542978c1fc55889a002bdd526fa40a205809ab56291534bda796addde4d06e43ff891011b4c486224ace12bf876a47f4dccaaba33dd7cc2c59f11241097d8d994798f7186c73b7d7f9e2b7b882409f20dad4b96d1a54adeaf32ea7abccc5e9cb9b6837010ec826e82e90d441719c8"; got != want {
			t.Errorf("state = \n%s\nwant  = \n%s", got, want)
		}
	})
}

func TestDuplex_Squeeze(t *testing.T) {
	t.Run("simple", func(t *testing.T) {
		var d duplex
		d.permute()

		if got, want := debugDuplex(&d), "0_0_d768fa7909cf75f1d1dbfedbc27b2bd0912bb283ec8f5ff7ecb89400d98a083201a3d3ff76087915a51326ef181801bd5c7c2f4685eb3a4839be3b392b8632465f6b184743d9bff9ad923e16f45f486bf04664ed1d9ad186abc39d35456ad0f32f72f740b12330460259c73e0e3bf908cdd6b1b09af91884e04595998c89e6df"; got != want {
			t.Errorf("state = \n%s\nwant  = \n%s", got, want)
		}

		out := make([]byte, 10)
		d.squeeze(out)

		if got, want := debugDuplex(&d), "0_10_d768fa7909cf75f1d1dbfedbc27b2bd0912bb283ec8f5ff7ecb89400d98a083201a3d3ff76087915a51326ef181801bd5c7c2f4685eb3a4839be3b392b8632465f6b184743d9bff9ad923e16f45f486bf04664ed1d9ad186abc39d35456ad0f32f72f740b12330460259c73e0e3bf908cdd6b1b09af91884e04595998c89e6df"; got != want {
			t.Errorf("state = \n%s\nwant  = \n%s", got, want)
		}

		if got, want := hex.EncodeToString(out), "d768fa7909cf75f1d1db"; got != want {
			t.Errorf("squeeze = %s, want = %s", got, want)
		}
	})

	t.Run("multi-block", func(t *testing.T) {
		var d duplex
		d.permute()

		out := make([]byte, 2000)
		d.squeeze(out)

		if got, want := debugDuplex(&d), "0_26_ba6fce95189d9ab473df173085129cc31c5bcaee3fac1ff754366c43769d0e70f41a7a8f378cdd5df04d9ed74f21a06410240c558582742112dbf09249db29ec710f14ec86d411ad55bfbd1781523574161587c332d27fa474cf377051d5ef8e99f9846046063e43882d747c16ec4242169080d9b2d6e3f1facec4f3422c95b8"; got != want {
			t.Errorf("state = \n%s\nwant  = \n%s", got, want)
		}

		if got, want := hex.EncodeToString(out[:10]), "d768fa7909cf75f1d1db"; got != want {
			t.Errorf("squeeze = %s, want = %s", got, want)
		}
	})
}

func TestDuplex_Permute(t *testing.T) {
	d := exampleDuplex()

	if got, want := debugDuplex(&d), "0_10_0102030405060708090a00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"; got != want {
		t.Errorf("state = \n%s\nwant  = \n%s", got, want)
	}

	d.permute()

	if got, want := debugDuplex(&d), "0_0_559c1ff8adef4306a244c2d8bdd743082eab0c7fc14aff639d44f12a5a115b3a9dec0ec7c0387844c457a350bec4aa082666e7b6244921a9384166b0f221775110ccbbc6b4e961fe958eb69c8e94d05456a725e719380df22818be7f280ed597e6d888effb221783ab029666d817c64d84f4ea0da7f1fa0ee7001a0fc48659bc"; got != want {
		t.Errorf("state = \n%s\nwant  = \n%s", got, want)
	}
}

func TestDuplex_Ratchet(t *testing.T) {
	t.Run("simple", func(t *testing.T) {
		d := exampleDuplex()

		if got, want := debugDuplex(&d), "0_10_0102030405060708090a00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"; got != want {
			t.Errorf("state = \n%s\nwant  = \n%s", got, want)
		}

		d.ratchet()

		if got, want := debugDuplex(&d), "0_32_00000000000000000000000000000000000000000000000000000000000000009dec0ec7c0387844c457a350bec4aa082666e7b6244921a9384166b0f221775110ccbbc6b4e961fe958eb69c8e94d05456a725e719380df22818be7f280ed597e6d888effb221783ab029666d817c64d84f4ea0da7f1fa0ee7001a0fc48659bc"; got != want {
			t.Errorf("state = \n%s\nwant  = \n%s", got, want)
		}
	})

	t.Run("freshly permuted", func(t *testing.T) {
		d := exampleDuplex()
		d.permute()

		if got, want := debugDuplex(&d), "0_0_559c1ff8adef4306a244c2d8bdd743082eab0c7fc14aff639d44f12a5a115b3a9dec0ec7c0387844c457a350bec4aa082666e7b6244921a9384166b0f221775110ccbbc6b4e961fe958eb69c8e94d05456a725e719380df22818be7f280ed597e6d888effb221783ab029666d817c64d84f4ea0da7f1fa0ee7001a0fc48659bc"; got != want {
			t.Errorf("state = \n%s\nwant  = \n%s", got, want)
		}

		d.ratchet()

		if got, want := debugDuplex(&d), "0_32_00000000000000000000000000000000000000000000000000000000000000009dec0ec7c0387844c457a350bec4aa082666e7b6244921a9384166b0f221775110ccbbc6b4e961fe958eb69c8e94d05456a725e719380df22818be7f280ed597e6d888effb221783ab029666d817c64d84f4ea0da7f1fa0ee7001a0fc48659bc"; got != want {
			t.Errorf("state = \n%s\nwant  = \n%s", got, want)
		}
	})
}

func TestDuplex_Encrypt(t *testing.T) {
	t.Run("simple", func(t *testing.T) {
		d := exampleDuplex()

		if got, want := debugDuplex(&d), "0_10_0102030405060708090a00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"; got != want {
			t.Errorf("state = \n%s\nwant  = \n%s", got, want)
		}

		d.permute()

		plaintext := []byte("this is a message")
		ciphertext := make([]byte, len(plaintext))
		d.encrypt(ciphertext, plaintext)

		if got, want := debugDuplex(&d), "0_17_21f4768b8d863026c364afbdcea4226f4bab0c7fc14aff639d44f12a5a115b3a9dec0ec7c0387844c457a350bec4aa082666e7b6244921a9384166b0f221775110ccbbc6b4e961fe958eb69c8e94d05456a725e719380df22818be7f280ed597e6d888effb221783ab029666d817c64d84f4ea0da7f1fa0ee7001a0fc48659bc"; got != want {
			t.Errorf("state = \n%s\nwant  = \n%s", got, want)
		}

		if got, want := hex.EncodeToString(ciphertext), "21f4768b8d863026c364afbdcea4226f4b"; got != want {
			t.Errorf("ciphertext = %s, want = %x", got, want)
		}
	})

	t.Run("in place", func(t *testing.T) {
		d := exampleDuplex()

		if got, want := debugDuplex(&d), "0_10_0102030405060708090a00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"; got != want {
			t.Errorf("state = \n%s\nwant  = \n%s", got, want)
		}

		d.permute()

		inout := []byte("this is a message")
		d.encrypt(inout, inout)

		if got, want := debugDuplex(&d), "0_17_21f4768b8d863026c364afbdcea4226f4bab0c7fc14aff639d44f12a5a115b3a9dec0ec7c0387844c457a350bec4aa082666e7b6244921a9384166b0f221775110ccbbc6b4e961fe958eb69c8e94d05456a725e719380df22818be7f280ed597e6d888effb221783ab029666d817c64d84f4ea0da7f1fa0ee7001a0fc48659bc"; got != want {
			t.Errorf("state = \n%s\nwant  = \n%s", got, want)
		}

		if got, want := hex.EncodeToString(inout), "21f4768b8d863026c364afbdcea4226f4b"; got != want {
			t.Errorf("ciphertext = %s, want = %s", got, want)
		}
	})

	t.Run("multi-block", func(t *testing.T) {
		d := exampleDuplex()

		plaintext := make([]byte, 11*77*43)
		ciphertext := make([]byte, len(plaintext))
		d.encrypt(ciphertext, plaintext)

		if got, want := debugDuplex(&d), "0_53_68cc9a651c13768b12b375b957f930d2766ebe31c61664d8f45ddf8c781f17a54563db076aab96b78602d862558b8c6393167e80dfa96514140f6934c7fbe8373099375f801b14f4ac0da798d11636b2043e40c637705c6c4ed894e1ff5bffc20f4dbf15e807e174d5c84195224eba033d08b08f9db3edd35f15747ddfe47a03"; got != want {
			t.Errorf("state = \n%s\nwant  = \n%s", got, want)
		}
	})
}

func TestDuplex_Decrypt(t *testing.T) {
	t.Run("simple", func(t *testing.T) {
		d := exampleDuplex()

		if got, want := debugDuplex(&d), "0_10_0102030405060708090a00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"; got != want {
			t.Errorf("state = \n%s\nwant  = \n%s", got, want)
		}

		d.permute()

		ciphertext, _ := hex.DecodeString("21f4768b8d863026c364afbdcea4226f4b")
		plaintext := make([]byte, len(ciphertext))
		d.decrypt(plaintext, ciphertext)

		if got, want := debugDuplex(&d), "0_17_21f4768b8d863026c364afbdcea4226f4bab0c7fc14aff639d44f12a5a115b3a9dec0ec7c0387844c457a350bec4aa082666e7b6244921a9384166b0f221775110ccbbc6b4e961fe958eb69c8e94d05456a725e719380df22818be7f280ed597e6d888effb221783ab029666d817c64d84f4ea0da7f1fa0ee7001a0fc48659bc"; got != want {
			t.Errorf("state = \n%s\nwant  = \n%s", got, want)
		}

		if got, want := string(plaintext), "this is a message"; got != want {
			t.Errorf("plaintext = %s, want = %s", got, want)
		}
	})

	t.Run("in place", func(t *testing.T) {
		d := exampleDuplex()

		if got, want := debugDuplex(&d), "0_10_0102030405060708090a00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"; got != want {
			t.Errorf("state = \n%s\nwant  = \n%s", got, want)
		}

		d.permute()

		inout, _ := hex.DecodeString("21f4768b8d863026c364afbdcea4226f4b")
		d.decrypt(inout, inout)

		if got, want := debugDuplex(&d), "0_17_21f4768b8d863026c364afbdcea4226f4bab0c7fc14aff639d44f12a5a115b3a9dec0ec7c0387844c457a350bec4aa082666e7b6244921a9384166b0f221775110ccbbc6b4e961fe958eb69c8e94d05456a725e719380df22818be7f280ed597e6d888effb221783ab029666d817c64d84f4ea0da7f1fa0ee7001a0fc48659bc"; got != want {
			t.Errorf("state = \n%s\nwant  = \n%s", got, want)
		}

		if got, want := string(inout), "this is a message"; got != want {
			t.Errorf("inout = %s, want = %x", got, want)
		}
	})

	t.Run("multi-block", func(t *testing.T) {
		d := exampleDuplex()

		ciphertext := make([]byte, 11*77*43)
		plaintext := make([]byte, len(ciphertext))
		d.decrypt(plaintext, ciphertext)

		if got, want := debugDuplex(&d), "0_53_00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006c05c088577ad2503a7d870b9311be3ef27fa6164a6174b90158b152386976352689b26d782c31489df34ecbb3799e9fa644eef9e097881d2ecce5fbb270d3d93d2e81eb25cc1557a1be00"; got != want {
			t.Errorf("state = \n%s\nwant  = \n%s", got, want)
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
		t.Errorf("AppendBinary() = %s, want = %s", got, want)
	}
}

func TestDuplex_UnmarshalBinary(t *testing.T) {
	t.Run("valid state", func(t *testing.T) {
		var d duplex

		b, _ := hex.DecodeString("0a0b0102030405060708090a00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
		if err := d.UnmarshalBinary(b); err != nil {
			t.Fatal(err)
		}

		if got, want := debugDuplex(&d), "11_10_0102030405060708090a00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"; got != want {
			t.Errorf("state = %s,\nwant  = %s", got, want)
		}
	})

	t.Run("short state", func(t *testing.T) {
		var d duplex
		b, _ := hex.DecodeString("0a000102030405060708090a00000000")
		if err := d.UnmarshalBinary(b); err == nil {
			t.Errorf("error expected but none returned")
		}
	})

	t.Run("invalid rateIdx", func(t *testing.T) {
		var d duplex
		b, _ := hex.DecodeString("ff000102030405060708090a00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
		if err := d.UnmarshalBinary(b); err == nil {
			t.Errorf("error expected but none returned")
		}
	})

	t.Run("invalid frameIdx", func(t *testing.T) {
		var d duplex
		b, _ := hex.DecodeString("00ff0102030405060708090a00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
		if err := d.UnmarshalBinary(b); err == nil {
			t.Errorf("error expected but none returned")
		}
	})
}

func debugDuplex(d *duplex) string {
	return fmt.Sprintf("%d_%d_%x", d.frameIdx, d.rateIdx, d.state[:])
}

func exampleDuplex() duplex {
	var d duplex
	d.absorb([]byte{1, 2, 3, 4, 5})
	d.absorb([]byte{6, 7, 8, 9, 10})
	return d
}

func BenchmarkDuplex_Absorb(b *testing.B) {
	for _, length := range lengths {
		b.Run(length.name, func(b *testing.B) {
			var d duplex
			input := make([]byte, length.n)
			b.SetBytes(int64(length.n))
			b.ReportAllocs()
			for b.Loop() {
				d.absorb(input)
			}
		})
	}
}

func BenchmarkDuplex_Squeeze(b *testing.B) {
	for _, length := range lengths {
		b.Run(length.name, func(b *testing.B) {
			var d duplex
			output := make([]byte, length.n)
			b.SetBytes(int64(length.n))
			b.ReportAllocs()
			for b.Loop() {
				d.squeeze(output)
			}
		})
	}
}

func BenchmarkDuplex_Encrypt(b *testing.B) {
	for _, length := range lengths {
		b.Run(length.name, func(b *testing.B) {
			var d duplex
			d.permute()

			output := make([]byte, length.n)
			b.SetBytes(int64(length.n))
			b.ReportAllocs()
			for b.Loop() {
				d.encrypt(output, output)
			}
		})
	}
}

func BenchmarkDuplex_Decrypt(b *testing.B) {
	for _, length := range lengths {
		b.Run(length.name, func(b *testing.B) {
			var d duplex
			d.permute()

			output := make([]byte, length.n)
			b.SetBytes(int64(length.n))
			b.ReportAllocs()
			for b.Loop() {
				d.decrypt(output, output)
			}
		})
	}
}

//nolint:gochecknoglobals // this is fine
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
