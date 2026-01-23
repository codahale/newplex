// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package keccak

// F1600 applies the Keccak-f[1600] permutation to the state (24 rounds).
func F1600(state *[200]byte) {
	f1600(state)
}

// P1600 applies the Keccak-p[1600, 12] permutation to the state (12 rounds).
func P1600(state *[200]byte) {
	p1600(state)
}
