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
BenchmarkAreion512-14           52600370                22.48 ns/op     2846.37 MB/s           0 B/op          0 allocs/op
BenchmarkAscon12-14             43652568                26.87 ns/op     1488.44 MB/s           0 B/op          0 allocs/op
BenchmarkAscon8-14              63433747                18.52 ns/op     2160.05 MB/s           0 B/op          0 allocs/op
BenchmarkGimli384-14            17336467                68.57 ns/op      700.03 MB/s           0 B/op          0 allocs/op
BenchmarkHaraka512-14           50425906                23.73 ns/op     2697.05 MB/s           0 B/op          0 allocs/op
BenchmarkKeccakF1600-14         10239504               117.3 ns/op      1705.51 MB/s           0 B/op          0 allocs/op
BenchmarkKeccakP1600-14         19797596                60.12 ns/op     3326.52 MB/s           0 B/op          0 allocs/op
BenchmarkSimpira256-14          34283877                34.44 ns/op      929.20 MB/s           0 B/op          0 allocs/op
BenchmarkSimpira512-14          34415426                34.59 ns/op     1850.27 MB/s           0 B/op          0 allocs/op
BenchmarkSimpira768-14          34143124                34.75 ns/op     2762.43 MB/s           0 B/op          0 allocs/op
BenchmarkSimpira1024-14         27120942                43.66 ns/op     2931.59 MB/s           0 B/op          0 allocs/op
BenchmarkSimpira1536-14         19912922                60.16 ns/op     3191.31 MB/s           0 B/op          0 allocs/op
BenchmarkXoodoo-14              33420055                36.29 ns/op     1322.66 MB/s           0 B/op          0 allocs/op
```

### amd64

```text
goos: linux
goarch: amd64
pkg: github.com/codahale/newplex/internal/benchmarks
cpu: INTEL(R) XEON(R) PLATINUM 8581C CPU @ 2.30GHz
BenchmarkAreion512-4     	52104738	        22.96 ns/op	2786.85 MB/s	       0 B/op	       0 allocs/op
BenchmarkAscon12-4       	19420005	        61.47 ns/op	 650.70 MB/s	       0 B/op	       0 allocs/op
BenchmarkAscon8-4        	26723434	        44.80 ns/op	 892.87 MB/s	       0 B/op	       0 allocs/op
BenchmarkGimli384-4      	14804593	        80.93 ns/op	 593.12 MB/s	       0 B/op	       0 allocs/op
BenchmarkHaraka512-4     	38422870	        31.23 ns/op	2049.56 MB/s	       0 B/op	       0 allocs/op
BenchmarkKeccakF1600-4   	 3471152	       346.0 ns/op	 577.99 MB/s	       0 B/op	       0 allocs/op
BenchmarkKeccakP1600-4   	 6978556	       172.1 ns/op	1162.12 MB/s	       0 B/op	       0 allocs/op
BenchmarkSimpira256-4    	28095674	        42.66 ns/op	 750.12 MB/s	       0 B/op	       0 allocs/op
BenchmarkSimpira512-4    	27757052	        43.05 ns/op	1486.63 MB/s	       0 B/op	       0 allocs/op
BenchmarkSimpira768-4    	27291609	        44.12 ns/op	2175.75 MB/s	       0 B/op	       0 allocs/op
BenchmarkSimpira1024-4   	20610908	        58.13 ns/op	2201.86 MB/s	       0 B/op	       0 allocs/op
BenchmarkSimpira1536-4   	11461620	       104.4 ns/op	1838.92 MB/s	       0 B/op	       0 allocs/op
BenchmarkXoodoo-4        	11781493	       100.2 ns/op	 478.93 MB/s	       0 B/op	       0 allocs/op
```

## License

MIT or Apache 2.0.