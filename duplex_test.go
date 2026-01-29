package newplex_test

import (
	"encoding/hex"
	"slices"
	"testing"

	"github.com/codahale/newplex"
)

func TestDuplex_Permute(t *testing.T) {
	var d newplex.Duplex
	d.Absorb([]byte{1, 2, 3, 4, 5})
	d.Absorb([]byte{6, 7, 8, 9, 10})

	if got, want := newplex.State(&d), "0102030405060708090a^0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000|0000000000000000000000000000000000000000000000000000000000000000"; got != want {
		t.Errorf("state = \n%s\nwant  = \n%s", got, want)
	}

	d.Permute()

	if got, want := newplex.State(&d), "^833a396d75b724a025afa7efda2c35beef0c7ab0f468874d1556fc1f92989fa76f36adc5a0f68f3d2da03d19a84ae4380528de5800187836dd604febeb3321a25fc4e1096e95dc6c17c806b81911c3d76624b8df38ff8ee2b6aa7727af63ce5e|7842524c4c22b359a254f465950454a26607efd25b116f83b4da2aafb89fd388"; got != want {
		t.Errorf("state = \n%s\nwant  = \n%s", got, want)
	}
}

func TestDuplex_Absorb(t *testing.T) {
	var d newplex.Duplex
	d.Absorb([]byte{1, 2, 3, 4, 5})
	d.Absorb([]byte{6, 7, 8, 9, 10})

	if got, want := newplex.State(&d), "0102030405060708090a^0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000|0000000000000000000000000000000000000000000000000000000000000000"; got != want {
		t.Errorf("state = %s,\nwant  = %s", got, want)
	}

	d.Absorb(slices.Repeat[[]byte]([]byte{22}, 423))

	if got, want := newplex.State(&d), "e9346d5b67a5a50fdc584d24e34848f8929669e865d7565ca80cde062c2f1a7e4fd8a493ed16457db8f7ad374a1bdc63b9^4d0dabfe77487ccabe1c98c052795f076cc090c97e36fbb84818bfe9457bedc6488b4331b8d971e4fc38a1184b4b7c|88a5aad01cff897fe47d56e845a8730eb5c4a7239fabc12c5d41caaa6f7a78e5"; got != want {
		t.Errorf("state = %s,\nwant  = %s", got, want)
	}
}

func TestDuplex_Squeeze(t *testing.T) {
	var d newplex.Duplex
	d.Absorb([]byte{1, 2, 3, 4, 5})
	d.Absorb([]byte{6, 7, 8, 9, 10})

	if got, want := newplex.State(&d), "0102030405060708090a^0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000|0000000000000000000000000000000000000000000000000000000000000000"; got != want {
		t.Errorf("state = \n%s\nwant  = \n%s", got, want)
	}

	d.Permute()

	if got, want := newplex.State(&d), "^833a396d75b724a025afa7efda2c35beef0c7ab0f468874d1556fc1f92989fa76f36adc5a0f68f3d2da03d19a84ae4380528de5800187836dd604febeb3321a25fc4e1096e95dc6c17c806b81911c3d76624b8df38ff8ee2b6aa7727af63ce5e|7842524c4c22b359a254f465950454a26607efd25b116f83b4da2aafb89fd388"; got != want {
		t.Errorf("state = \n%s\nwant  = \n%s", got, want)
	}

	out := make([]byte, 10)
	d.Squeeze(out)

	if got, want := newplex.State(&d), "833a396d75b724a025af^a7efda2c35beef0c7ab0f468874d1556fc1f92989fa76f36adc5a0f68f3d2da03d19a84ae4380528de5800187836dd604febeb3321a25fc4e1096e95dc6c17c806b81911c3d76624b8df38ff8ee2b6aa7727af63ce5e|7842524c4c22b359a254f465950454a26607efd25b116f83b4da2aafb89fd388"; got != want {
		t.Errorf("state = \n%s\nwant  = \n%s", got, want)
	}

	if got, want := hex.EncodeToString(out), "833a396d75b724a025af"; got != want {
		t.Errorf("squeeze = %s, want = %x", got, want)
	}
}

func TestDuplex_Ratchet(t *testing.T) {
	var d newplex.Duplex
	d.Absorb([]byte{1, 2, 3, 4, 5})
	d.Absorb([]byte{6, 7, 8, 9, 10})

	if got, want := newplex.State(&d), "0102030405060708090a^0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000|0000000000000000000000000000000000000000000000000000000000000000"; got != want {
		t.Errorf("state = \n%s\nwant  = \n%s", got, want)
	}

	d.Ratchet()

	if got, want := newplex.State(&d), "0000000000000000000000000000000000000000000000000000000000000000^6f36adc5a0f68f3d2da03d19a84ae4380528de5800187836dd604febeb3321a25fc4e1096e95dc6c17c806b81911c3d76624b8df38ff8ee2b6aa7727af63ce5e|7842524c4c22b359a254f465950454a26607efd25b116f83b4da2aafb89fd388"; got != want {
		t.Errorf("state = \n%s\nwant  = \n%s", got, want)
	}
}

func TestDuplex_Encrypt(t *testing.T) {
	t.Run("simple", func(t *testing.T) {
		var d newplex.Duplex
		d.Absorb([]byte{1, 2, 3, 4, 5})
		d.Absorb([]byte{6, 7, 8, 9, 10})

		if got, want := newplex.State(&d), "0102030405060708090a^0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000|0000000000000000000000000000000000000000000000000000000000000000"; got != want {
			t.Errorf("state = \n%s\nwant  = \n%s", got, want)
		}

		d.Permute()

		plaintext := []byte("this is a message")
		ciphertext := make([]byte, len(plaintext))
		d.Encrypt(ciphertext, plaintext)

		if got, want := newplex.State(&d), "f752501e55de5780448fca8aa95f54d98a^0c7ab0f468874d1556fc1f92989fa76f36adc5a0f68f3d2da03d19a84ae4380528de5800187836dd604febeb3321a25fc4e1096e95dc6c17c806b81911c3d76624b8df38ff8ee2b6aa7727af63ce5e|7842524c4c22b359a254f465950454a26607efd25b116f83b4da2aafb89fd388"; got != want {
			t.Errorf("state = \n%s\nwant  = \n%s", got, want)
		}

		if got, want := hex.EncodeToString(ciphertext), "f752501e55de5780448fca8aa95f54d98a"; got != want {
			t.Errorf("ciphertext = %s, want = %x", got, want)
		}
	})

	t.Run("in place", func(t *testing.T) {
		var d newplex.Duplex
		d.Absorb([]byte{1, 2, 3, 4, 5})
		d.Absorb([]byte{6, 7, 8, 9, 10})

		if got, want := newplex.State(&d), "0102030405060708090a^0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000|0000000000000000000000000000000000000000000000000000000000000000"; got != want {
			t.Errorf("state = \n%s\nwant  = \n%s", got, want)
		}

		d.Permute()

		inout := []byte("this is a message")
		d.Encrypt(inout, inout)

		if got, want := newplex.State(&d), "f752501e55de5780448fca8aa95f54d98a^0c7ab0f468874d1556fc1f92989fa76f36adc5a0f68f3d2da03d19a84ae4380528de5800187836dd604febeb3321a25fc4e1096e95dc6c17c806b81911c3d76624b8df38ff8ee2b6aa7727af63ce5e|7842524c4c22b359a254f465950454a26607efd25b116f83b4da2aafb89fd388"; got != want {
			t.Errorf("state = \n%s\nwant  = \n%s", got, want)
		}

		if got, want := hex.EncodeToString(inout), "f752501e55de5780448fca8aa95f54d98a"; got != want {
			t.Errorf("ciphertext = %s, want = %x", got, want)
		}
	})

	t.Run("multi-block", func(t *testing.T) {
		var d newplex.Duplex
		plaintext := make([]byte, 11*77*43)
		ciphertext := make([]byte, len(plaintext))
		d.Encrypt(ciphertext, plaintext)

		if got, want := newplex.State(&d), "ec7429017e7a04ad165f81b1396326c99fb662198601602641e040cbe19d79e915308d019e^350e7bcd2c58fd137e5c9659ef0affd3ff2f4cbe1f4f98ba7a1e86af98a188db470a90dddeeda556cf86a3e33f288a346946dc7c33a8e1ffc7606d|ee9b15b98b1867d08b1024f107ce0d516bd03b4dc09c1e882f3b9136c584580a"; got != want {
			t.Errorf("state = \n%s\nwant  = \n%s", got, want)
		}
	})
}

func TestDuplex_Decrypt(t *testing.T) {
	t.Run("simple", func(t *testing.T) {
		var d newplex.Duplex
		d.Absorb([]byte{1, 2, 3, 4, 5})
		d.Absorb([]byte{6, 7, 8, 9, 10})

		if got, want := newplex.State(&d), "0102030405060708090a^0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000|0000000000000000000000000000000000000000000000000000000000000000"; got != want {
			t.Errorf("state = \n%s\nwant  = \n%s", got, want)
		}

		d.Permute()

		ciphertext, _ := hex.DecodeString("f752501e55de5780448fca8aa95f54d98a")
		plaintext := make([]byte, len(ciphertext))
		d.Decrypt(plaintext, ciphertext)

		if got, want := newplex.State(&d), "f752501e55de5780448fca8aa95f54d98a^0c7ab0f468874d1556fc1f92989fa76f36adc5a0f68f3d2da03d19a84ae4380528de5800187836dd604febeb3321a25fc4e1096e95dc6c17c806b81911c3d76624b8df38ff8ee2b6aa7727af63ce5e|7842524c4c22b359a254f465950454a26607efd25b116f83b4da2aafb89fd388"; got != want {
			t.Errorf("state = \n%s\nwant  = \n%s", got, want)
		}

		if got, want := string(plaintext), "this is a message"; got != want {
			t.Errorf("plaintext = %s, want = %x", got, want)
		}
	})

	t.Run("in place", func(t *testing.T) {
		var d newplex.Duplex
		d.Absorb([]byte{1, 2, 3, 4, 5})
		d.Absorb([]byte{6, 7, 8, 9, 10})

		if got, want := newplex.State(&d), "0102030405060708090a^0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000|0000000000000000000000000000000000000000000000000000000000000000"; got != want {
			t.Errorf("state = \n%s\nwant  = \n%s", got, want)
		}

		d.Permute()

		inout, _ := hex.DecodeString("f752501e55de5780448fca8aa95f54d98a")
		d.Decrypt(inout, inout)

		if got, want := newplex.State(&d), "f752501e55de5780448fca8aa95f54d98a^0c7ab0f468874d1556fc1f92989fa76f36adc5a0f68f3d2da03d19a84ae4380528de5800187836dd604febeb3321a25fc4e1096e95dc6c17c806b81911c3d76624b8df38ff8ee2b6aa7727af63ce5e|7842524c4c22b359a254f465950454a26607efd25b116f83b4da2aafb89fd388"; got != want {
			t.Errorf("state = \n%s\nwant  = \n%s", got, want)
		}

		if got, want := string(inout), "this is a message"; got != want {
			t.Errorf("inout = %s, want = %x", got, want)
		}
	})

	t.Run("multi-block", func(t *testing.T) {
		var d newplex.Duplex
		ciphertext := make([]byte, 11*77*43)
		plaintext := make([]byte, len(ciphertext))
		d.Decrypt(plaintext, ciphertext)

		if got, want := newplex.State(&d), "00000000000000000000000000000000000000000000000000000000000000000000000000^255a6cfcb14b0bdf8303379a789228e0e03cade68372657ba5659791cbb897ac9f64a0ca9351542d233edf4794d870b425e3ea44ac984ca1a25b77|c4ea4cb7762766db4e85dd39a2ffa17d2a19da1468473f92b55da2c8c0d5d805"; got != want {
			t.Errorf("state = \n%s\nwant  = \n%s", got, want)
		}
	})
}

func TestDuplex_AppendBinary(t *testing.T) {
	var d newplex.Duplex
	d.Absorb([]byte{1, 2, 3, 4, 5})
	d.Absorb([]byte{6, 7, 8, 9, 10})

	b, err := d.AppendBinary([]byte{22, 23})
	if err != nil {
		t.Fatal(err)
	}

	if got, want := hex.EncodeToString(b), "16170a000102030405060708090a00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"; got != want {
		t.Errorf("AppendBinary() = %s, want = %s", got, want)
	}
}

func TestDuplex_MarshalBinary(t *testing.T) {
	var d newplex.Duplex
	d.Absorb([]byte{1, 2, 3, 4, 5})
	d.Absorb([]byte{6, 7, 8, 9, 10})

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
		var d newplex.Duplex

		b, _ := hex.DecodeString("0a000102030405060708090a00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
		if err := d.UnmarshalBinary(b); err != nil {
			t.Fatal(err)
		}

		if got, want := newplex.State(&d), "0102030405060708090a^0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000|0000000000000000000000000000000000000000000000000000000000000000"; got != want {
			t.Errorf("state = %s,\nwant  = %s", got, want)
		}
	})

	t.Run("short state", func(t *testing.T) {
		var d newplex.Duplex
		b, _ := hex.DecodeString("0a000102030405060708090a00000000")
		if err := d.UnmarshalBinary(b); err == nil {
			t.Errorf("error expected but none returned")
		}
	})

	t.Run("invalid pos", func(t *testing.T) {
		var d newplex.Duplex
		b, _ := hex.DecodeString("0aff0102030405060708090a00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
		if err := d.UnmarshalBinary(b); err == nil {
			t.Errorf("error expected but none returned")
		}
	})
}

func BenchmarkDuplex_Absorb(b *testing.B) {
	for _, length := range lengths {
		b.Run(length.name, func(b *testing.B) {
			var d newplex.Duplex
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
			var d newplex.Duplex
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
			var d newplex.Duplex
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
			var d newplex.Duplex
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
