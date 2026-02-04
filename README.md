# Newplex

Newplex provides an incremental, stateful cryptographic primitive for symmetric-key cryptographic operations (e.g.,
hashing, encryption, message authentication codes, and authenticated encryption) in complex protocols. Inspired
by [TupleHash], [STROBE], [Noise Protocol]'s stateful objects, [Merlin] transcripts, [DuplexWrap], and [Xoodyak]'s
Cyclist mode, Newplex uses the [Simpira-1024] permutation to provide 10+ Gb/second performance on modern processors at a
128-bit security level.

[TupleHash]: https://www.nist.gov/publications/sha-3-derived-functions-cshake-kmac-tuplehash-and-parallelhash

[STROBE]: https://strobe.sourceforge.io

[Noise Protocol]: http://www.noiseprotocol.org

[Merlin]: https://merlin.cool

[DuplexWrap]: https://competitions.cr.yp.to/round1/keyakv1.pdf

[Xoodyak]: https://keccak.team/xoodyak.html

[Simpira-1024]: https://eprint.iacr.org/2016/122.pdf

## ⚠️ Security Warning

**This code has not been audited. This design has not been analyzed.** The design is documented in [
`design.md`](design.md); read it and see if the arguments therein are convincing. It is experimental and should not be
used for production systems or critical security applications.
Use at your own risk.

## Installation

```bash
go get github.com/codahale/newplex
```

## Usage

On AMD64 and ARM64 architectures, newplex uses the AES-NI instruction set to achieve this level of performance. On other
architectures, or if the `purego` build tag is used, it uses a much-slower Go implementation with a bitsliced,
constant-time AES round implementation.

The AMD64 implementation requires the AES-NI and SSE2 instructions sets, which are ubiquitous.

The ARM64 implementation requires the ARMv8 Crypto Extensions and ASIMD (NEON) support.

To force the use of the portable implementation, use the `purego` build tag:

```bash
go build -tags purego ./...
```

### Protocol

`Protocol` is a high-level API, designed for easily building complex cryptographic constructions (e.g., hash functions,
MACs, stream ciphers, AEADs, sessions) with domain separation and state management.

```go
// Initialize a protocol with a domain separation string.
p := newplex.NewProtocol("my-app.my-protocol")

// Mix key material and other data into the state.
p.Mix("key", []byte("secret-key-material"))
p.Mix("nonce", []byte("unique-nonce"))

// Mask a message (provides confidentiality only).
plaintext := []byte("Hello, World!")
ciphertext := p.Mask("message", nil, plaintext)

// Or Seal a message (provides confidentiality + authenticity).
sealed := p.Seal("secure-message", nil, plaintext)

// Derive pseudorandom output (like a KDF or Hash).
tag := p.Derive("tag", nil, 32)
```

### Standard Packages

Newplex includes several standard cryptographic constructions implemented as sub-packages:

* [`newplex/aead`](aead): Implements `cipher.AEAD` with support for additional data.
* [`newplex/aestream`](aestream): Implements a streaming authenticated encryption scheme.
* [`newplex/digest`](digest): Implements `hash.Hash` (both keyed and unkeyed).
* [`newplex/hpke`](hpke): Implements a hybrid public-key encryption scheme.
* [`newplex/sig`](sig): Implements EdDSA-style Schnorr digital signatures.
* [`newplex/signcrypt`](signcrypt): Implements integrated public-key encryption and signing.
* [`newplex/siv`](siv): Implements a SIV-style deterministic authentication scheme.

Design details for these are included in [`design.md`](design.md).

## License

MIT or Apache 2.0.