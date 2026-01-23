// Copyright 2025 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !purego

package keccak

//go:noescape
func keccakF1600NEON(a *[200]byte)

//go:noescape
func keccakF1600Rounds12NEON(a *[200]byte)

func keccakF1600(a *[200]byte) {
	keccakF1600NEON(a)
}

func keccakF1600Rounds12(a *[200]byte) {
	keccakF1600Rounds12NEON(a)
}
