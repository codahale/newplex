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
BenchmarkAreion512-14           52679250                22.40 ns/op     2857.00 MB/s           0 B/op          0 allocs/op
BenchmarkAscon12-14             42512047                27.18 ns/op     1471.61 MB/s           0 B/op          0 allocs/op
BenchmarkAscon8-14              61347211                18.81 ns/op     2126.69 MB/s           0 B/op          0 allocs/op
BenchmarkGimli384-14            17059296                69.27 ns/op      692.97 MB/s           0 B/op          0 allocs/op
BenchmarkHaraka512-14           47788773                23.80 ns/op     2688.52 MB/s           0 B/op          0 allocs/op
BenchmarkKeccakF1600-14         10146657               119.3 ns/op      1676.13 MB/s           0 B/op          0 allocs/op
BenchmarkKeccakP1600-14         19530189                60.14 ns/op     3325.64 MB/s           0 B/op          0 allocs/op
BenchmarkSimpira256-14          33790996                34.69 ns/op      922.38 MB/s           0 B/op          0 allocs/op
BenchmarkSimpira512-14          33207919                34.81 ns/op     1838.79 MB/s           0 B/op          0 allocs/op
BenchmarkSimpira768-14          33497368                34.91 ns/op     2750.22 MB/s           0 B/op          0 allocs/op
BenchmarkSimpira1024-14         26684974                43.91 ns/op     2915.01 MB/s           0 B/op          0 allocs/op
BenchmarkXoodoo-14              33025855                36.70 ns/op     1307.82 MB/s           0 B/op          0 allocs/op
PASS
ok      github.com/codahale/newplex/internal/benchmarks 14.340s
```

### amd64

```text
goos: linux
goarch: amd64
pkg: github.com/codahale/newplex/internal/benchmarks
cpu: INTEL(R) XEON(R) PLATINUM 8581C CPU @ 2.30GHz
BenchmarkAreion512-4     	52504920	        22.76 ns/op	2811.70 MB/s	       0 B/op	       0 allocs/op
BenchmarkAscon12-4       	19433097	        61.16 ns/op	 654.05 MB/s	       0 B/op	       0 allocs/op
BenchmarkAscon8-4        	26815138	        44.47 ns/op	 899.47 MB/s	       0 B/op	       0 allocs/op
BenchmarkGimli384-4      	14961410	        80.40 ns/op	 597.01 MB/s	       0 B/op	       0 allocs/op
BenchmarkHaraka512-4     	38832696	        31.02 ns/op	2063.41 MB/s	       0 B/op	       0 allocs/op
BenchmarkKeccakF1600-4   	 3504847	       341.0 ns/op	 586.58 MB/s	       0 B/op	       0 allocs/op
BenchmarkKeccakP1600-4   	 7024897	       171.4 ns/op	1166.77 MB/s	       0 B/op	       0 allocs/op
BenchmarkSimpira256-4    	28116415	        42.20 ns/op	 758.33 MB/s	       0 B/op	       0 allocs/op
BenchmarkSimpira512-4    	27862384	        42.65 ns/op	1500.66 MB/s	       0 B/op	       0 allocs/op
BenchmarkSimpira768-4    	27450266	        43.70 ns/op	2196.67 MB/s	       0 B/op	       0 allocs/op
BenchmarkSimpira1024-4   	21049959	        57.63 ns/op	2220.99 MB/s	       0 B/op	       0 allocs/op
BenchmarkXoodoo-4        	12119104	        99.15 ns/op	 484.10 MB/s	       0 B/op	       0 allocs/op
PASS
ok  	github.com/codahale/newplex/internal/benchmarks	14.377s```

## License

MIT or Apache 2.0.