package newplex_test

import (
	"encoding/hex"
	"slices"
	"testing"

	"github.com/codahale/newplex"
)

func TestDuplex_Absorb(t *testing.T) {
	t.Run("simple", func(t *testing.T) {
		d := exampleDuplex()

		if got, want := newplex.State(&d), "0102030405060708090a^0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000|0000000000000000000000000000000000000000000000000000000000000000"; got != want {
			t.Errorf("state = \n%s\nwant  = \n%s", got, want)
		}
	})

	t.Run("multi-block", func(t *testing.T) {
		var d newplex.Duplex
		d.Absorb(slices.Repeat([]byte{0xde, 0xad, 0xbe, 0xef}, 340))

		if got, want := newplex.State(&d), "9410c2dd059c2248b94cf4d727eb4094^f92fe19f82b841d41897bec9c86d2c6d8e49e60b3955f3015d83b9f9f30f61cd7410f43a50a7b1c2677e668decf3ed481bad40668c095998ea74fabeb8f9acbefd25b2c39ada05c405754611ad84a821|a1866172c3af451fa218257e3147e3678227ed4ffeef6ae2ede968086bf121f1"; got != want {
			t.Errorf("state = \n%s\nwant  = \n%s", got, want)
		}
	})
}

func TestDuplex_Squeeze(t *testing.T) {
	t.Run("simple", func(t *testing.T) {
		var d newplex.Duplex
		d.Permute()

		if got, want := newplex.State(&d), "^5a7d4c12b2c4483055c5125c73c98edd8ae680baed946a6a42d52bc714f08c5f86d37c6b2e1840f17c8872add1068f5d17d120e2b00ffa0e5513874e92db2c29a4254192dd6eea69e00c38c7240606d8e92c475ee701b669138309d96f93ff2d|9313436f5ec7655c26d9674a98fe583974fc76ddc75185816cd3121104a87778"; got != want {
			t.Errorf("state = \n%s\nwant  = \n%s", got, want)
		}

		out := make([]byte, 10)
		d.Squeeze(out)

		if got, want := newplex.State(&d), "5a7d4c12b2c4483055c5^125c73c98edd8ae680baed946a6a42d52bc714f08c5f86d37c6b2e1840f17c8872add1068f5d17d120e2b00ffa0e5513874e92db2c29a4254192dd6eea69e00c38c7240606d8e92c475ee701b669138309d96f93ff2d|9313436f5ec7655c26d9674a98fe583974fc76ddc75185816cd3121104a87778"; got != want {
			t.Errorf("state = \n%s\nwant  = \n%s", got, want)
		}

		if got, want := hex.EncodeToString(out), "5a7d4c12b2c4483055c5"; got != want {
			t.Errorf("squeeze = %s, want = %x", got, want)
		}
	})

	t.Run("multi-block", func(t *testing.T) {
		var d newplex.Duplex
		d.Permute()

		out := make([]byte, 2000)
		d.Squeeze(out)

		if got, want := newplex.State(&d), "f3ca4a1b698d5c0565c36cb863e6603582b8a5268878b636bef4badfa13138a88c46ba8f1a073d0798403782ac494e428d2c87dec1604138eee0ad1d5d7adc3943d4b507f662dfd90f9d9651244e5bc2^33d71d8fd721d40512415a1fb5af7f38|122060abae78e8a7d482283aa4c7a2e3041f649eb5cc92f615d12a46e51bd399"; got != want {
			t.Errorf("state = \n%s\nwant  = \n%s", got, want)
		}

		if got, want := hex.EncodeToString(out[:10]), "5a7d4c12b2c4483055c5"; got != want {
			t.Errorf("squeeze = %s, want = %x", got, want)
		}
	})
}

func TestDuplex_Permute(t *testing.T) {
	d := exampleDuplex()

	if got, want := newplex.State(&d), "0102030405060708090a^0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000|0000000000000000000000000000000000000000000000000000000000000000"; got != want {
		t.Errorf("state = \n%s\nwant  = \n%s", got, want)
	}

	d.Permute()

	if got, want := newplex.State(&d), "^833a396d75b724a025afa7efda2c35beef0c7ab0f468874d1556fc1f92989fa76f36adc5a0f68f3d2da03d19a84ae4380528de5800187836dd604febeb3321a25fc4e1096e95dc6c17c806b81911c3d76624b8df38ff8ee2b6aa7727af63ce5e|7842524c4c22b359a254f465950454a26607efd25b116f83b4da2aafb89fd388"; got != want {
		t.Errorf("state = \n%s\nwant  = \n%s", got, want)
	}
}

func TestDuplex_Ratchet(t *testing.T) {
	d := exampleDuplex()

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
		d := exampleDuplex()

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
		d := exampleDuplex()

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
		d := exampleDuplex()

		plaintext := make([]byte, 11*77*43)
		ciphertext := make([]byte, len(plaintext))
		d.Encrypt(ciphertext, plaintext)

		if got, want := newplex.State(&d), "dce165b92db9242f0f61a503eee4377e2c39d212d2f5e44ffe72630e71fb56c60442579ba16fcdf1bc7b3fbc7fb6a1^3ef961ead2db50d98df2102b091982ce86e8af62d26f10df60f5c0bee347b19dee8dde016145786f3fb773501b810d116b|20876f28e9f617c047b2d698c080c5ca437b5d5a763bc97958030a1577b5f0b8"; got != want {
			t.Errorf("state = \n%s\nwant  = \n%s", got, want)
		}
	})
}

func TestDuplex_Decrypt(t *testing.T) {
	t.Run("simple", func(t *testing.T) {
		d := exampleDuplex()

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
		d := exampleDuplex()

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
		d := exampleDuplex()

		ciphertext := make([]byte, 11*77*43)
		plaintext := make([]byte, len(ciphertext))
		d.Decrypt(plaintext, ciphertext)

		if got, want := newplex.State(&d), "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000^fb2ca6cfa48194c3a56d68a96837af071e313a6dfa1e7d72e26fb4c4c1d57f162460f5907b0d9da53806135aa9fb8a216e|fd16957704e45cdcb0d8f9bd09cfb08e1bfa1a924ae3747dbd8304bc0e9b2a6d"; got != want {
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

func exampleDuplex() newplex.Duplex {
	var d newplex.Duplex
	d.Absorb([]byte{1, 2, 3, 4, 5})
	d.Absorb([]byte{6, 7, 8, 9, 10})
	return d
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
