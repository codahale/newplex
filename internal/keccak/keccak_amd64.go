// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !purego

package keccak

//go:noescape
//goland:noinspection GoUnusedParameter
func f1600(a *[200]byte)

//go:noescape
//goland:noinspection GoUnusedParameter
func p1600(a *[200]byte)
