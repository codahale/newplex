# Newplex

Newplex provides an incremental, stateful cryptographic primitive for symmetric-key cryptographic operations (e.g.,
hashing, encryption, message authentication codes, and authenticated encryption) in complex protocols. Inspired
by [TupleHash], [STROBE], [Noise Protocol]'s stateful objects, [Merlin] transcripts, and [Xoodyak]'s Cyclist mode,
Newplex uses the [Simpira] V2 permutation to provide 10+ Gb/sec performance on modern processors at a 128-bit security
level.

[TupleHash]: https://www.nist.gov/publications/sha-3-derived-functions-cshake-kmac-tuplehash-and-parallelhash

[STROBE]: https://strobe.sourceforge.io

[Noise Protocol]: http://www.noiseprotocol.org

[Merlin]: https://merlin.cool

[Xoodyak]: https://keccak.team/xoodyak.html

[Simpira]: https://eprint.iacr.org/2016/122.pdf

## ⚠️ Security Warning

**This code has not been audited.** It is experimental and should not be used for production systems or critical
security applications. Use at your own risk.

## Installation

```bash
go get github.com/codahale/newplex
```

## Usage

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
* Gimli-384
* Haraka-512 V2
* Keccak-f\[1600\]
* Keccak-p\[1600, 12\]
* Simpira-256 V2
* Simpira-512 V2
* Simpira-784 V2
* Simpira-1024 V2

Of these, Simpira-1024 provides the best performance across both platforms. Areion-512 has better performance as a pure
permutation, but its small width means a 256-bit capacity duplex can only process 256 bits at a time, vs. 784 with
Simpira-1024.

### arm64

```text
goos: darwin                                                                                                                                                                                                                                         
goarch: arm64
pkg: github.com/codahale/newplex/internal/benchmarks
cpu: Apple M4 Pro
BenchmarkAreion512-14           52033636                22.56 ns/op     2836.91 MB/s           0 B/op          0 allocs/op
BenchmarkGimli384-14            17204002                68.57 ns/op      700.03 MB/s           0 B/op          0 allocs/op
BenchmarkHaraka512-14           48473830                23.71 ns/op     2699.46 MB/s           0 B/op          0 allocs/op
BenchmarkKeccakF1600-14         10313076               116.2 ns/op      1721.23 MB/s           0 B/op          0 allocs/op
BenchmarkKeccakP1600-14         19886576                59.85 ns/op     3341.83 MB/s           0 B/op          0 allocs/op
BenchmarkSimpira256-14          34086267                34.62 ns/op      924.35 MB/s           0 B/op          0 allocs/op
BenchmarkSimpira512-14          34091756                34.66 ns/op     1846.25 MB/s           0 B/op          0 allocs/op
BenchmarkSimpira784-14          33838640                34.77 ns/op     2760.77 MB/s           0 B/op          0 allocs/op
BenchmarkSimpira1024-14         27197598                43.55 ns/op     2938.97 MB/s           0 B/op          0 allocs/op
PASS
ok      github.com/codahale/newplex/internal/benchmarks 10.828s
```

### amd64

```text
goos: linux
goarch: amd64
pkg: github.com/codahale/newplex/internal/benchmarks
cpu: INTEL(R) XEON(R) PLATINUM 8581C CPU @ 2.30GHz
BenchmarkAreion512-4            55425592                21.76 ns/op     2941.06 MB/s           0 B/op          0 allocs/op
BenchmarkGimli384-4             15715965                76.63 ns/op      626.40 MB/s           0 B/op          0 allocs/op
BenchmarkHaraka512-4            40959205                29.44 ns/op     2173.84 MB/s           0 B/op          0 allocs/op
BenchmarkKeccakF1600-4           3677113               327.6 ns/op       610.42 MB/s           0 B/op          0 allocs/op
BenchmarkKeccakP1600-4           7366798               163.0 ns/op      1227.36 MB/s           0 B/op          0 allocs/op
BenchmarkSimpira256-4           29939313                40.29 ns/op      794.22 MB/s           0 B/op          0 allocs/op
BenchmarkSimpira512-4           29543602                40.77 ns/op     1569.60 MB/s           0 B/op          0 allocs/op
BenchmarkSimpira784-4           28870940                41.90 ns/op     2291.35 MB/s           0 B/op          0 allocs/op
BenchmarkSimpira1024-4          21799807                55.25 ns/op     2316.78 MB/s           0 B/op          0 allocs/op
PASS
ok      github.com/codahale/newplex/internal/benchmarks 10.851s
```

## License

MIT or Apache 2.0.