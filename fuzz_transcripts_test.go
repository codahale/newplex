package newplex_test

import (
	"bytes"
	"crypto/sha3"
	"fmt"
	"testing"

	"github.com/codahale/newplex"
	fuzz "github.com/trailofbits/go-fuzz-utils"
)

// FuzzProtocolDivergence generates a random transcript of operations and performs them in on two separate protocol
// objects in parallel, checking to see that all outputs are the same.
//
//nolint:gocognit // It's fine if this is complicated.
func FuzzProtocolDivergence(f *testing.F) {
	drbg := sha3.NewSHAKE128()
	_, _ = drbg.Write([]byte("newplex divergence"))

	for range 10 {
		seed := make([]byte, 1024)
		_, _ = drbg.Read(seed)
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		tp, err := fuzz.NewTypeProvider(data)
		if err != nil {
			t.Skip(err)
		}

		opCount, err := tp.GetUint16()
		if err != nil {
			t.Skip(err)
		}

		p1 := newplex.NewProtocol("divergence")
		p2 := newplex.NewProtocol("divergence")

		for range opCount % 50 {
			opTypeRaw, err := tp.GetByte()
			if err != nil {
				t.Skip(err)
			}

			label, err := tp.GetString()
			if err != nil {
				t.Skip(err)
			}

			const opTypeCount = 4 // Mix, Derive, UnauthenticatedEncrypt, Seal
			switch opType := opTypeRaw % opTypeCount; opType {
			case 0: // Mix
				input, err := tp.GetBytes()
				if err != nil {
					t.Skip(err)
				}

				p1.Mix(label, input)
				p2.Mix(label, input)
			case 1: // Derive
				n, err := tp.GetUint16()
				if err != nil || n == 0 {
					t.Skip(err)
				}

				res1, res2 := p1.Derive(label, nil, int(n)), p2.Derive(label, nil, int(n))
				if !bytes.Equal(res1, res2) {
					t.Fatalf("Divergent Derive outputs: %x != %x", res1, res2)
				}
			case 2: // UnauthenticatedEncrypt
				input, err := tp.GetBytes()
				if err != nil {
					t.Skip(err)
				}

				res1, res2 := p1.UnauthenticatedEncrypt(label, nil, input), p2.UnauthenticatedEncrypt(label, nil, input)
				if !bytes.Equal(res1, res2) {
					t.Fatalf("Divergent UnauthenticatedEncrypt outputs: %x != %x", res1, res2)
				}
			case 3: // Seal
				input, err := tp.GetBytes()
				if err != nil {
					t.Skip(err)
				}

				res1, res2 := p1.Seal(label, nil, input), p2.Seal(label, nil, input)
				if !bytes.Equal(res1, res2) {
					t.Fatalf("Divergent Seal outputs: %x != %x", res1, res2)
				}
			default:
				panic(fmt.Sprintf("unknown operation type: %v", opType))
			}
		}

		final1, final2 := p1.Derive("final", nil, 8), p2.Derive("final", nil, 8)
		if !bytes.Equal(final1, final2) {
			t.Fatalf("Divergent final states: %x != %x", final1, final2)
		}
	})
}

// FuzzProtocolReversibility generates a transcript of reversible operations (Mix, Derive, UnauthenticatedEncrypt, and Seal) and
// performs them on a protocol, recording the outputs. It then runs the transcript's duals (Mix, Derive, UnauthenticatedDecrypt, and
// Open) on another protocol object, ensuring the outputs are the same as the inputs.
//
//nolint:gocognit // It's fine if this is complicated.
func FuzzProtocolReversibility(f *testing.F) {
	drbg := sha3.NewSHAKE128()
	_, _ = drbg.Write([]byte("newplex reversibility"))

	for range 10 {
		seed := make([]byte, 1024)
		_, _ = drbg.Read(seed)
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		tp, err := fuzz.NewTypeProvider(data)
		if err != nil {
			t.Skip(err)
		}

		opCount, err := tp.GetUint16()
		if err != nil {
			t.Skip(err)
		}

		p1 := newplex.NewProtocol("reversibility")

		var operations []operation
		for range opCount % 50 {
			opTypeRaw, err := tp.GetByte()
			if err != nil {
				t.Skip(err)
			}

			label, err := tp.GetString()
			if err != nil {
				t.Skip(err)
			}

			const opTypeCount = 4 // Mix, Derive, UnauthenticatedEncrypt, Seal
			switch opType := opTypeRaw % opTypeCount; opType {
			case 0: // Mix
				input, err := tp.GetBytes()
				if err != nil {
					t.Skip(err)
				}

				p1.Mix(label, input)

				operations = append(operations, operation{ //nolint:exhaustruct // it's fine
					opType: 0,
					label:  label,
					input:  input,
				})
			case 1: // Derive
				n, err := tp.GetUint16()
				if err != nil || n == 0 {
					t.Skip(err)
				}

				output := p1.Derive(label, nil, int(n))

				operations = append(operations, operation{ //nolint:exhaustruct // it's fine
					opType: 1,
					label:  label,
					n:      int(n),
					output: output,
				})
			case 2: // UnauthenticatedEncrypt
				input, err := tp.GetBytes()
				if err != nil {
					t.Skip(err)
				}

				output := p1.UnauthenticatedEncrypt(label, nil, input)

				operations = append(operations, operation{ //nolint:exhaustruct // it's fine
					opType: 2,
					label:  label,
					input:  input,
					output: output,
				})
			case 3: // Seal
				input, err := tp.GetBytes()
				if err != nil {
					t.Skip(err)
				}

				output := p1.Seal(label, nil, input)

				operations = append(operations, operation{ //nolint:exhaustruct // it's fine
					opType: 3,
					label:  label,
					input:  input,
					output: output,
				})
			default:
				panic(fmt.Sprintf("unknown operation type: %v", opType))
			}
		}

		p2 := newplex.NewProtocol("reversibility")
		for _, op := range operations {
			switch op.opType {
			case 0: // Mix
				p2.Mix(op.label, op.input)
			case 1: // Derive
				output := p2.Derive(op.label, nil, op.n)
				if !bytes.Equal(output, op.output) {
					t.Fatalf("Divergent Derive outputs: %x != %x", output, op.output)
				}
			case 2: // UnauthenticatedDecrypt
				plaintext := p2.UnauthenticatedDecrypt(op.label, nil, op.output)
				if !bytes.Equal(plaintext, op.input) {
					t.Fatalf("Invalid UnauthenticatedDecrypt output: %x != %x", plaintext, op.input)
				}
			case 3: // Open
				plaintext, err := p2.Open(op.label, nil, op.output)
				if err != nil {
					t.Fatalf("Invalid Open operation: %v", err)
				}
				if !bytes.Equal(plaintext, op.input) {
					t.Fatalf("Invalid Open output: %x != %x", plaintext, op.input)
				}
			default:
				panic(fmt.Sprintf("unknown operation type: %v", op.opType))
			}
		}

		final1, final2 := p1.Derive("final", nil, 8), p2.Derive("final", nil, 8)
		if !bytes.Equal(final1, final2) {
			t.Fatalf("Divergent final states: %x != %x", final1, final2)
		}
	})
}

type operation struct {
	opType        byte
	label         string
	input, output []byte
	n             int
}
