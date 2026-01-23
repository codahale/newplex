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

`Duplex` is the low-level primitive using the Simpira-8 v2 permutation (1024-bit state). It supports `Absorb`,
`Squeeze`, `Encrypt`, and `Decrypt` operations directly on the state.

```go
var d newplex.Duplex
d.Absorb([]byte("input data"))
output := make([]byte, 32)
d.Squeeze(output)
```

## Performance

Newplex uses the Simpira-8 v2 permutation (128-bit width, AES-NI accelerated) to achieve high performance on modern
AMD64 and ARM64 processors.

## Permutation Implementations

### arm64

```text
goos: darwin                                                                                                                                                                                                                                         
goarch: arm64
pkg: github.com/codahale/newplex/internal/areion
cpu: Apple M4 Pro
BenchmarkPermute512-14          52485667                22.38 ns/op     2859.76 MB/s           0 B/op          0 allocs/op
PASS
ok      github.com/codahale/newplex/internal/areion     2.666s

goos: darwin
goarch: arm64
pkg: github.com/codahale/newplex/internal/gimli
cpu: Apple M4 Pro
BenchmarkPermute-14     17031936                70.03 ns/op      685.37 MB/s           0 B/op          0 allocs/op
PASS
ok      github.com/codahale/newplex/internal/gimli      1.367s

goos: darwin
goarch: arm64
pkg: github.com/codahale/newplex/internal/haraka
cpu: Apple M4 Pro
BenchmarkPermute512-14          48967584                24.29 ns/op     2634.78 MB/s           0 B/op          0 allocs/op
PASS
ok      github.com/codahale/newplex/internal/haraka     1.368s

goos: darwin
goarch: arm64
pkg: github.com/codahale/newplex/internal/keccak
cpu: Apple M4 Pro
BenchmarkF1600-14                  8667880               119.2 ns/op      1677.80 MB/s           0 B/op          0 allocs/op
BenchmarkP1600-14                 19857316                60.01 ns/op      3332.78 MB/s           0 B/op          0 allocs/op
PASS
ok      github.com/codahale/newplex/internal/keccak     2.395s

goos: darwin
goarch: arm64
pkg: github.com/codahale/newplex/internal/simpira
cpu: Apple M4 Pro
BenchmarkPermute2-14            33610927                35.39 ns/op      904.14 MB/s           0 B/op          0 allocs/op
BenchmarkPermute4-14            34202080                34.86 ns/op     1835.72 MB/s
BenchmarkPermute6-14            34018386                34.86 ns/op     2753.96 MB/s
BenchmarkPermute8-14            27187585                43.73 ns/op     2927.35 MB/s
PASS
ok      github.com/codahale/newplex/internal/simpira    4.994s
```

### arm64

```text
goos: linux
goarch: amd64
pkg: github.com/codahale/newplex/internal/areion
cpu: INTEL(R) XEON(R) PLATINUM 8581C CPU @ 2.30GHz
BenchmarkPermute512-4           57479552                21.38 ns/op     2992.92 MB/s           0 B/op          0 allocs/op
PASS
ok      github.com/codahale/newplex/internal/areion     1.231s

goos: linux
goarch: amd64
pkg: github.com/codahale/newplex/internal/gimli
cpu: INTEL(R) XEON(R) PLATINUM 8581C CPU @ 2.30GHz
BenchmarkPermute-4      15694228                76.49 ns/op      627.56 MB/s           0 B/op          0 allocs/op
PASS
ok      github.com/codahale/newplex/internal/gimli      1.203s

goos: linux
goarch: amd64
pkg: github.com/codahale/newplex/internal/haraka
cpu: INTEL(R) XEON(R) PLATINUM 8581C CPU @ 2.30GHz
BenchmarkPermute512-4           40973859                29.24 ns/op     2188.89 MB/s           0 B/op          0 allocs/op
PASS
ok      github.com/codahale/newplex/internal/haraka     1.200s

goos: linux
goarch: amd64
pkg: github.com/codahale/newplex/internal/keccak
cpu: INTEL(R) XEON(R) PLATINUM 8581C CPU @ 2.30GHz
BenchmarF1600-4                   3676816               326.9 ns/op       611.84 MB/s           0 B/op          0 allocs/op
BenchmarP1600-4                   7275388               162.7 ns/op      1229.02 MB/s           0 B/op          0 allocs/op
PASS
ok      github.com/codahale/newplex/internal/keccak     2.389s

goos: linux
goarch: amd64
pkg: github.com/codahale/newplex/internal/simpira
cpu: INTEL(R) XEON(R) PLATINUM 8581C CPU @ 2.30GHz
BenchmarkPermute2-4     29862538                40.24 ns/op      795.17 MB/s           0 B/op          0 allocs/op
BenchmarkPermute4-4     29536484                40.59 ns/op     1576.73 MB/s           0 B/op          0 allocs/op
BenchmarkPermute6-4     30012813                41.55 ns/op     2310.47 MB/s           0 B/op          0 allocs/op
BenchmarkPermute8-4     21942882                54.00 ns/op     2370.33 MB/s           0 B/op          0 allocs/op
PASS
ok      github.com/codahale/newplex/internal/simpira    4.836s
```

## License

MIT or Apache 2.0.