// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build (!amd64 && !arm64) || nosimd

package keccak

func f1600(a *[200]byte) {
	f1600Generic(a, 24)
}

func p1600(a *[200]byte) {
	f1600Generic(a, 12)
}
