# Newplex

Newplex provides an incremental, stateful cryptographic primitive for symmetric-key cryptographic operations (e.g.,
hashing, encryption, message authentication codes, and authenticated encryption) in complex protocols. Inspired
by [TupleHash], [STROBE], [Noise Protocol]'s stateful objects, [Merlin] transcripts, [SpongeWrap], and [Xoodyak]'s
Cyclist mode, Newplex uses the [Simpira-1024] permutation to provide 10+ Gb/second performance on modern processors at a
128-bit security level.

[TupleHash]: https://www.nist.gov/publications/sha-3-derived-functions-cshake-kmac-tuplehash-and-parallelhash

[STROBE]: https://strobe.sourceforge.io

[Noise Protocol]: http://www.noiseprotocol.org

[Merlin]: https://merlin.cool

[SpongeWrap]: https://eprint.iacr.org/2011/499.pdf

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

### Protocol

`Protocol` is the high-level API, designed for constructing complex cryptographic protocols (e.g., transcripts,
sessions) with domain separation and state management.

```go
// Initialize a protocol with a domain separation string.
p := newplex.NewProtocol("my-app.my-protocol")

// Mix key material and other data into the state.
p.Mix("key", []byte("secret-key-material"))
p.Mix("nonce", []byte("unique-nonce"))

// Encrypt a message (provides confidentiality).
plaintext := []byte("Hello, World!")
ciphertext := p.Encrypt("message", nil, plaintext)

// Or Seal a message (provides confidentiality + authenticity).
sealed := p.Seal("secure-message", nil, plaintext)

// Derive pseudorandom output (like a KDF or Hash).
tag := p.Derive("tag", nil, 32)
```

### Duplex

`Duplex` is the low-level primitive using the Simpira-1024 V2 permutation. It supports `Absorb`, `Squeeze`, `Encrypt`,
and `Decrypt` operations directly on the state.

```go
var d newplex.Duplex
d.Absorb([]byte("input data"))
output := make([]byte, 32)
d.Squeeze(output)
```

## Performance

## Permutation Implementations

This repo contains implementations of the following permutations with full optimization for both `amd64` and `arm64`
architectures:

* Areion-512
* Ascon-8
* Ascon-12
* Gimli-384
* Haraka-512 V2
* Keccak-f\[1600\]
* Keccak-p\[1600, 12\]
* Simpira-256 V2
* Simpira-512 V2
* Simpira-768 V2
* Simpira-1024 V2
* Simpira-1536 V2
* Xoodoo

Of these, Simpira-1024 provides the best performance across both platforms. Areion-512 has better performance as a pure
permutation, but its small width means a 256-bit capacity duplex can only process 256 bits at a time, vs. 768 with
Simpira-1024.

### arm64

```text
goos: darwin                                                                                                                                                                                                                                         
goarch: arm64
pkg: github.com/codahale/newplex/internal/benchmarks
cpu: Apple M4 Pro
BenchmarkAreion512-14           271043318               21.95 ns/op     2915.82 MB/s           0 B/op          0 allocs/op
BenchmarkAscon12-14             223411255               26.85 ns/op     1489.95 MB/s           0 B/op          0 allocs/op
BenchmarkAscon8-14              324286826               18.48 ns/op     2164.12 MB/s           0 B/op          0 allocs/op
BenchmarkGimli384-14            85662225                68.28 ns/op      702.96 MB/s           0 B/op          0 allocs/op
BenchmarkHaraka512-14           255149623               23.58 ns/op     2713.60 MB/s           0 B/op          0 allocs/op
BenchmarkKeccakF1600-14         51540948               115.9 ns/op      1725.70 MB/s           0 B/op          0 allocs/op
BenchmarkKeccakP1600-14         99095204                59.65 ns/op     3352.89 MB/s           0 B/op          0 allocs/op
BenchmarkSimpira256-14          174793746               34.35 ns/op      931.66 MB/s           0 B/op          0 allocs/op
BenchmarkSimpira512-14          173078990               34.58 ns/op     1850.67 MB/s           0 B/op          0 allocs/op
BenchmarkSimpira768-14          172720959               34.72 ns/op     2765.11 MB/s           0 B/op          0 allocs/op
BenchmarkSimpira1024-14         137034960               43.77 ns/op     2924.63 MB/s           0 B/op          0 allocs/op
BenchmarkSimpira1536-14         98830436                59.78 ns/op     3211.69 MB/s           0 B/op          0 allocs/op
BenchmarkXoodoo-14              170471202               35.19 ns/op     1364.06 MB/s           0 B/op          0 allocs/op
PASS
ok      github.com/codahale/newplex/internal/benchmarks 77.745s
```

### amd64

```text
goos: linux
goarch: amd64
pkg: github.com/codahale/newplex/internal/benchmarks
cpu: INTEL(R) XEON(R) PLATINUM 8581C CPU @ 2.30GHz
BenchmarkAreion512-4            52033068                22.97 ns/op     2786.78 MB/s           0 B/op          0 allocs/op
BenchmarkAscon12-4              19412529                61.71 ns/op      648.20 MB/s           0 B/op          0 allocs/op
BenchmarkAscon8-4               26767323                44.92 ns/op      890.44 MB/s           0 B/op          0 allocs/op
BenchmarkGimli384-4             14779448                81.16 ns/op      591.44 MB/s           0 B/op          0 allocs/op
BenchmarkHaraka512-4            38345859                31.27 ns/op     2046.63 MB/s           0 B/op          0 allocs/op
BenchmarkKeccakF1600-4           3490239               344.0 ns/op       581.39 MB/s           0 B/op          0 allocs/op
BenchmarkKeccakP1600-4           6985438               172.2 ns/op      1161.30 MB/s           0 B/op          0 allocs/op
BenchmarkSimpira256-4           28108608                42.56 ns/op      751.85 MB/s           0 B/op          0 allocs/op
BenchmarkSimpira512-4           27781494                43.01 ns/op     1488.03 MB/s           0 B/op          0 allocs/op
BenchmarkSimpira768-4           27188736                44.16 ns/op     2173.69 MB/s           0 B/op          0 allocs/op
BenchmarkSimpira1024-4          20686183                57.99 ns/op     2207.26 MB/s           0 B/op          0 allocs/op
BenchmarkSimpira1536-4          11535240               104.5 ns/op      1837.51 MB/s           0 B/op          0 allocs/op
BenchmarkXoodoo-4               11924196               100.9 ns/op       475.85 MB/s           0 B/op          0 allocs/op
```

## License

MIT or Apache 2.0.