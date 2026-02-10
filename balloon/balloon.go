// Package balloon implements [balloon hashing], a memory-hard algorithm suitable for use with low-entropy secrets,
// like passwords.
//
// [balloon hashing]: https://eprint.iacr.org/2016/027.pdf
package balloon

import (
	"crypto/subtle"
	"encoding/binary"
	"sync"

	"github.com/codahale/newplex"
)

// Hash returns a 32-byte digest of the password using the given domain separation string, random salt, cost parameters,
// and parallelism.
func Hash(domain string, password, salt []byte, spaceCost, timeCost, parallelism uint32) []byte {
	res := make([][32]byte, parallelism)
	var wg sync.WaitGroup
	for p := range parallelism {
		wg.Go(func() {
			const delta = 3
			buf := make([][32]byte, spaceCost)
			cnt := uint32(0)

			h := newplex.NewProtocol(domain)
			h.Mix("password", password)
			h.Mix("salt", salt)
			h.Mix("space-cost", binary.LittleEndian.AppendUint32(nil, spaceCost))
			h.Mix("time-cost", binary.LittleEndian.AppendUint32(nil, timeCost))
			h.Mix("parallelism", binary.LittleEndian.AppendUint32(nil, parallelism))
			h.Mix("parallelism-index", binary.LittleEndian.AppendUint32(nil, p))

			// Step 1. Expand input into the buffer.
			hash(h, &cnt, password, salt, buf[0][:])
			for m := range buf[1:] {
				cnt++
				hash(h, &cnt, buf[m][:], nil, buf[m+1][:])
			}

			// Step 2. Mix buffer contents.
			for t := range timeCost {
				for m := range spaceCost {
					// Step 2a. Hash last and current blocks.
					hash(h, &cnt, buf[(m-1)%spaceCost][:], buf[m][:], buf[m][:])

					// Step 2b. Hash in pseudorandomly chosen blocks.
					var (
						b [4 + 4 + 4]byte
					)
					for i := range delta {
						idxBlock := b[:0]
						idxBlock = binary.LittleEndian.AppendUint32(idxBlock, t)
						idxBlock = binary.LittleEndian.AppendUint32(idxBlock, m)
						idxBlock = binary.LittleEndian.AppendUint32(idxBlock, uint32(i)) //nolint:gosec // i < 3
						hash(h, &cnt, salt, idxBlock, idxBlock[:4])
						other := binary.LittleEndian.Uint32(idxBlock) % spaceCost
						hash(h, &cnt, buf[m][:], buf[other][:], buf[m][:])
					}
				}
			}

			// Step 3. Extract output from the buffer.
			res[p] = buf[spaceCost-1]
		})
	}
	wg.Wait()

	// XOR all the final output values together.
	for _, r := range res[1:] {
		subtle.XORBytes(res[0][:], res[0][:], r[:])
	}
	return res[0][:]
}

func hash(p newplex.Protocol, cnt *uint32, left, right, out []byte) {
	*cnt++
	p.Mix("counter", binary.LittleEndian.AppendUint32(nil, *cnt))
	if len(left) != 0 {
		p.Mix("left", left)
	}
	if len(right) != 0 {
		p.Mix("right", right)
	}
	p.Derive("out", out[:0], len(out))
}
