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

Of these, Simpira-1024 provides the best performance across both platforms at a wider size.

### arm64

```text
goos: darwin                                                                                                                                                                                                                                         
goarch: arm64
pkg: github.com/codahale/newplex/internal/benchmarks
cpu: Apple M4 Pro
BenchmarkAreion512-14           52577181                22.49 ns/op     2845.10 MB/s           0 B/op          0 allocs/op
BenchmarkGimli384-14            16989957                69.22 ns/op      693.48 MB/s           0 B/op          0 allocs/op
BenchmarkHaraka512-14           49320556                23.52 ns/op     2721.22 MB/s           0 B/op          0 allocs/op
BenchmarkKeccakF1600-14         10240404               116.5 ns/op      1716.78 MB/s           0 B/op          0 allocs/op
BenchmarkKeccakP1600-14         19830312                59.96 ns/op     3335.69 MB/s           0 B/op          0 allocs/op
BenchmarkSimpira256-14          33783981                34.41 ns/op      930.02 MB/s           0 B/op          0 allocs/op
BenchmarkSimpira512-14          33429597                34.70 ns/op     1844.23 MB/s           0 B/op          0 allocs/op
BenchmarkSimpira784-14          33738348                34.76 ns/op     2761.75 MB/s           0 B/op          0 allocs/op
BenchmarkSimpira1024-14         27184224                43.65 ns/op     2932.33 MB/s           0 B/op          0 allocs/op
PASS
ok      github.com/codahale/newplex/internal/benchmarks 10.868s
```

### amd64

```text
goos: linux
goarch: amd64
pkg: github.com/codahale/newplex/internal/benchmarks
cpu: INTEL(R) XEON(R) PLATINUM 8581C CPU @ 2.30GHz
BenchmarkAreion512-4            53262529                22.59 ns/op     2833.11 MB/s           0 B/op          0 allocs/op
BenchmarkGimli384-4             14807415                80.95 ns/op      592.94 MB/s           0 B/op          0 allocs/op
BenchmarkHaraka512-4            38889375                30.98 ns/op     2065.76 MB/s           0 B/op          0 allocs/op
BenchmarkKeccakF1600-4           3501240               343.7 ns/op       581.96 MB/s           0 B/op          0 allocs/op
BenchmarkKeccakP1600-4           6999891               171.1 ns/op      1168.62 MB/s           0 B/op          0 allocs/op
BenchmarkSimpira256-4           28396915                42.43 ns/op      754.10 MB/s           0 B/op          0 allocs/op
BenchmarkSimpira512-4           27792969                42.85 ns/op     1493.63 MB/s           0 B/op          0 allocs/op
BenchmarkSimpira784-4           27120734                44.08 ns/op     2177.66 MB/s           0 B/op          0 allocs/op
BenchmarkSimpira1024-4          20634771                57.97 ns/op     2208.19 MB/s           0 B/op          0 allocs/op
PASS
ok      github.com/codahale/newplex/internal/benchmarks 10.800s
```

## License

MIT or Apache 2.0.