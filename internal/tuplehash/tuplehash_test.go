package tuplehash_test

import (
	"bytes"
	"testing"

	"github.com/codahale/newplex/internal/tuplehash"
)

func TestAppendLeftEncode(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		value uint64
		want  []byte
	}{
		{value: 0, want: []byte{1, 0}},
		{value: 128, want: []byte{1, 128}},
		{value: 65536, want: []byte{3, 1, 0, 0}},
		{value: 4096, want: []byte{2, 16, 0}},
		{value: 18446744073709551615, want: []byte{8, 255, 255, 255, 255, 255, 255, 255, 255}},
		{value: 12345, want: []byte{2, 48, 57}},
	} {
		if got, want := tuplehash.AppendLeftEncode(nil, test.value), test.want; !bytes.Equal(got, want) {
			t.Errorf("LeftEncode(%d) = %v, want = %v", test.value, got, want)
		}
	}
}

func TestAppendRightEncode(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		value uint64
		want  []byte
	}{
		{value: 0, want: []byte{0, 1}},
		{value: 128, want: []byte{128, 1}},
		{value: 65536, want: []byte{1, 0, 0, 3}},
		{value: 4096, want: []byte{16, 0, 2}},
		{value: 18446744073709551615, want: []byte{255, 255, 255, 255, 255, 255, 255, 255, 8}},
		{value: 12345, want: []byte{48, 57, 2}},
	} {
		if got, want := tuplehash.AppendRightEncode(nil, test.value), test.want; !bytes.Equal(got, want) {
			t.Errorf("RightEncode(%d) = %v, want = %v", test.value, got, want)
		}
	}
}

func FuzzLeftEncode(f *testing.F) {
	f.Add(uint64(2), uint64(3))
	f.Fuzz(func(t *testing.T, a uint64, b uint64) {
		ab := tuplehash.AppendLeftEncode(nil, a)
		bb := tuplehash.AppendLeftEncode(nil, b)

		if a == b && !bytes.Equal(ab, bb) {
			t.Errorf("tuplehash.LeftEncode(%v) = %v, tuplehash.LeftEncode(%v) = %v", a, ab, b, bb)
		} else if a != b && bytes.Equal(ab, bb) {
			t.Errorf("tuplehash.LeftEncode(%v) = tuplehash.LeftEncode(%v) = %v", a, b, ab)
		}
	})
}

func FuzzRightEncode(f *testing.F) {
	f.Add(uint64(2), uint64(3))
	f.Fuzz(func(t *testing.T, a uint64, b uint64) {
		ab := tuplehash.AppendRightEncode(nil, a)
		bb := tuplehash.AppendRightEncode(nil, b)

		if a == b && !bytes.Equal(ab, bb) {
			t.Errorf("tuplehash.RightEncode(%v) = %v, tuplehash.RightEncode(%v) = %v", a, ab, b, bb)
		} else if a != b && bytes.Equal(ab, bb) {
			t.Errorf("tuplehash.RightEncode(%v) = tuplehash.RightEncode(%v) = %v", a, b, ab)
		}
	})
}

func BenchmarkLeftEncode(b *testing.B) {
	out := make([]byte, tuplehash.MaxSize)

	b.ReportAllocs()
	for b.Loop() {
		tuplehash.AppendLeftEncode(out[:0], 2408234)
	}
}

func BenchmarkRightEncode(b *testing.B) {
	out := make([]byte, tuplehash.MaxSize)

	b.ReportAllocs()
	for b.Loop() {
		tuplehash.AppendRightEncode(out[:0], 2408234)
	}
}
