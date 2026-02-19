# Newplex

Newplex is a cryptographic framework that provides a unified interface for unkeyed and symmetric-key operations. It is
built on a duplex construction using the [Simpira-1024] permutation. Inspired by [STROBE], [Noise Protocol],
and [Xoodyak], Newplex is optimized for 64-bit architectures (x86-64 and ARM64) to provide 10+ Gb/second performance on
modern processors at a 128-bit security level.

Two design principles guide the framework. First, replacing separate hash functions, MACs, stream ciphers, and KDFs with
a single duplex construction simplifies the design and implementation of cryptographic schemes--from basic AEAD to
multi-party protocols like OPRFs and handshakes. Second, the security of every scheme reduces to the properties of the
underlying duplex (indifferentiability from a random oracle, pseudorandom function security, and collision resistance),
all bounded by the 256-bit capacity (`2**128` against generic attacks). A single security analysis of the duplex and
permutation layers covers the entire framework.

[Simpira-1024]: https://eprint.iacr.org/2016/122.pdf

[STROBE]: https://strobe.sourceforge.io

[Noise Protocol]: http://www.noiseprotocol.org

[Xoodyak]: https://keccak.team/xoodyak.html

## ⚠️ Security Warning

> [!WARNING]
> **This code has not been audited. This design has not been analyzed.** The design is documented
> in [`design.md`](design.md); read it and see if the arguments therein are convincing. It is experimental and should
> not be used for production systems or critical security applications. Use at your own risk.

## Installation

```bash
go get github.com/codahale/newplex
```

## Usage

On AMD64 and ARM64 architectures, newplex uses hardware AES instructions for performance. On other architectures, or if
the `purego` build tag is used, it falls back to a slower Go implementation with a bit-sliced, constant-time AES round
implementation.

The AMD64 implementation requires AES-NI and SSE2. The ARM64 implementation requires ARMv8 Crypto Extensions and
ASIMD (NEON).

To force the portable implementation, use the `purego` build tag:

```bash
go build -tags purego ./...
```

### Protocol

`Protocol` is a high-level API for building cryptographic schemes (e.g., hash functions, MACs, stream ciphers, AEADs,
sessions) with built-in domain separation and state management.

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

Newplex includes the following cryptographic schemes as sub-packages:

* [`newplex/adratchet`](adratchet): Implements a Signal-like asynchronous double ratchet.
* [`newplex/aead`](aead): Implements `cipher.AEAD` with support for additional data.
* [`newplex/aestream`](aestream): Implements a streaming authenticated encryption scheme.
* [`newplex/digest`](digest): Implements `hash.Hash` (both keyed and unkeyed).
* [`newplex/frost`](frost): Implements FROST threshold Schnorr signatures.
* [`newplex/handshake`](handshake): Implements a mutually authenticated handshake.
* [`newplex/hpke`](hpke): Implements a hybrid public-key encryption scheme.
* [`newplex/mhf`](mhf): Implements the DEGSample data-dependent memory-hard hash function for password hashing.
* [`newplex/oprf`](oprf): Implements an RFC 9497-style Oblivious Pseudorandom Function (OPRF) and Verifiable OPRF
  (VOPRF).
* [`newplex/pake`](pake): Implements a CPace-style password-authenticated key exchange (PAKE).
* [`newplex/sig`](sig): Implements EdDSA-style Schnorr digital signatures.
* [`newplex/signcrypt`](signcrypt): Implements integrated public-key encryption and signing.
* [`newplex/siv`](siv): Implements a SIV-style deterministic authentication scheme.
* [`newplex/vrf`](vrf): Implements a verifiable random function.

Design details are in [`design.md`](design.md).

## Performance

Newplex targets 10+ Gbp/sec performance on modern server processors.

### AMD64

```text
goos: linux
goarch: amd64
pkg: github.com/codahale/newplex
cpu: INTEL(R) XEON(R) PLATINUM 8581C CPU @ 2.30GHz
BenchmarkHashScheme/16B                 12040262               100.3 ns/op       159.59 MB/s           0 B/op          0 allocs/op
BenchmarkHashScheme/32B                 12383924                97.94 ns/op      326.72 MB/s           0 B/op          0 allocs/op
BenchmarkHashScheme/64B                 12391802                96.91 ns/op      660.43 MB/s           0 B/op          0 allocs/op
BenchmarkHashScheme/128B                 8559896               143.5 ns/op       892.19 MB/s           0 B/op          0 allocs/op
BenchmarkHashScheme/256B                 5004840               236.5 ns/op      1082.58 MB/s           0 B/op          0 allocs/op
BenchmarkHashScheme/1KiB                 1935332               620.4 ns/op      1650.50 MB/s           0 B/op          0 allocs/op
BenchmarkHashScheme/16KiB                 142461              8313 ns/op        1970.96 MB/s           0 B/op          0 allocs/op
BenchmarkHashScheme/1MiB                    2323            521616 ns/op        2010.24 MB/s           0 B/op          0 allocs/op
BenchmarkPRFScheme/16B                  12368185                97.01 ns/op      164.93 MB/s           0 B/op          0 allocs/op
BenchmarkPRFScheme/32B                  11872790                99.43 ns/op      321.82 MB/s           0 B/op          0 allocs/op
BenchmarkPRFScheme/64B                  12190263                98.16 ns/op      652.01 MB/s           0 B/op          0 allocs/op
BenchmarkPRFScheme/128B                  7932213               149.6 ns/op       855.64 MB/s           0 B/op          0 allocs/op
BenchmarkPRFScheme/256B                  5986339               200.7 ns/op      1275.61 MB/s           0 B/op          0 allocs/op
BenchmarkPRFScheme/1KiB                  1988391               607.1 ns/op      1686.61 MB/s           0 B/op          0 allocs/op
BenchmarkPRFScheme/16KiB                  137037              8758 ns/op        1870.68 MB/s           0 B/op          0 allocs/op
BenchmarkPRFScheme/1MiB                     2091            560482 ns/op        1870.85 MB/s           0 B/op          0 allocs/op
BenchmarkStreamScheme/16B                9501328               124.3 ns/op       128.76 MB/s           0 B/op          0 allocs/op
BenchmarkStreamScheme/32B                9802387               123.3 ns/op       259.56 MB/s           0 B/op          0 allocs/op
BenchmarkStreamScheme/64B               10008786               121.7 ns/op       525.88 MB/s           0 B/op          0 allocs/op
BenchmarkStreamScheme/128B               6941865               172.2 ns/op       743.39 MB/s           0 B/op          0 allocs/op
BenchmarkStreamScheme/256B               5363806               221.7 ns/op      1154.50 MB/s           0 B/op          0 allocs/op
BenchmarkStreamScheme/1KiB               1879706               641.2 ns/op      1596.93 MB/s           0 B/op          0 allocs/op
BenchmarkStreamScheme/16KiB               129224              9273 ns/op        1766.90 MB/s           0 B/op          0 allocs/op
BenchmarkStreamScheme/1MiB                  2012            584774 ns/op        1793.13 MB/s           0 B/op          0 allocs/op
BenchmarkAEADScheme/16B                  5032033               242.6 ns/op       131.91 MB/s           0 B/op          0 allocs/op
BenchmarkAEADScheme/32B                  4939018               241.1 ns/op       199.07 MB/s           0 B/op          0 allocs/op
BenchmarkAEADScheme/64B                  4890608               244.1 ns/op       327.70 MB/s           0 B/op          0 allocs/op
BenchmarkAEADScheme/128B                 4093395               295.3 ns/op       487.67 MB/s           0 B/op          0 allocs/op
BenchmarkAEADScheme/256B                 3391336               356.6 ns/op       762.71 MB/s           0 B/op          0 allocs/op
BenchmarkAEADScheme/1KiB                 1559380               772.3 ns/op      1346.67 MB/s           0 B/op          0 allocs/op
BenchmarkAEADScheme/16KiB                 127945              9371 ns/op        1750.11 MB/s           0 B/op          0 allocs/op
BenchmarkAEADScheme/1MiB                    2013            583608 ns/op        1796.74 MB/s           0 B/op          0 allocs/op
```

### ARM64

```text
goos: darwin                                                                                                                                                                                                                                                             
goarch: arm64                                                                                                                                                                                                                                                            
pkg: github.com/codahale/newplex                                                                                                                                                                                                                                         
cpu: Apple M4 Pro                                                                                                                                                                                                                                                        
BenchmarkHashScheme/16B                 20705578                57.71 ns/op      277.23 MB/s           0 B/op          0 allocs/op                                                                                                                                       
BenchmarkHashScheme/32B                 22098853                53.93 ns/op      593.32 MB/s           0 B/op          0 allocs/op                                                                                                                                       
BenchmarkHashScheme/64B                 21734372                54.93 ns/op     1165.12 MB/s           0 B/op          0 allocs/op                                                                                                                                       
BenchmarkHashScheme/128B                13497021                88.48 ns/op     1446.59 MB/s           0 B/op          0 allocs/op                                                                                                                                       
BenchmarkHashScheme/256B                 7603873               157.3 ns/op      1627.84 MB/s           0 B/op          0 allocs/op                                                                                                                                       
BenchmarkHashScheme/1KiB                 2694968               445.0 ns/op      2301.27 MB/s           0 B/op          0 allocs/op                                                                                                                                       
BenchmarkHashScheme/16KiB                 190098              6272 ns/op        2612.37 MB/s           0 B/op          0 allocs/op                                                                                                                                       
BenchmarkHashScheme/1MiB                    2961            399703 ns/op        2623.39 MB/s           0 B/op          0 allocs/op                                                                                                                                       
BenchmarkPRFScheme/16B                  20697609                57.13 ns/op      280.07 MB/s           0 B/op          0 allocs/op                                                                                                                                       
BenchmarkPRFScheme/32B                  21585451                55.05 ns/op      581.25 MB/s           0 B/op          0 allocs/op                                                                                                                                       
BenchmarkPRFScheme/64B                  21558080                55.18 ns/op     1159.86 MB/s           0 B/op          0 allocs/op                                                                                                                                       
BenchmarkPRFScheme/128B                 13316527                89.84 ns/op     1424.81 MB/s           0 B/op          0 allocs/op                                                                                                                                       
BenchmarkPRFScheme/256B                  9715753               123.1 ns/op      2080.31 MB/s           0 B/op          0 allocs/op                                                                                                                                       
BenchmarkPRFScheme/1KiB                  3111435               385.6 ns/op      2655.78 MB/s           0 B/op          0 allocs/op                                                                                                                                       
BenchmarkPRFScheme/16KiB                  206236              5798 ns/op        2825.93 MB/s           0 B/op          0 allocs/op                                                                                                                                       
BenchmarkPRFScheme/1MiB                     3206            375638 ns/op        2791.45 MB/s           0 B/op          0 allocs/op                                                                                                                                       
BenchmarkStreamScheme/16B               16954888                70.21 ns/op      227.88 MB/s           0 B/op          0 allocs/op                                                                                                                                       
BenchmarkStreamScheme/32B               17085883                70.31 ns/op      455.14 MB/s           0 B/op          0 allocs/op                                                                                                                                       
BenchmarkStreamScheme/64B               16449922                71.60 ns/op      893.84 MB/s           0 B/op          0 allocs/op                                                                                                                                       
BenchmarkStreamScheme/128B              11257392               108.6 ns/op      1178.95 MB/s           0 B/op          0 allocs/op                                                                                                                                       
BenchmarkStreamScheme/256B               8345169               146.1 ns/op      1751.64 MB/s           0 B/op          0 allocs/op                                                                                                                                       
BenchmarkStreamScheme/1KiB               2718831               441.4 ns/op      2320.04 MB/s           0 B/op          0 allocs/op                                                                                                                                       
BenchmarkStreamScheme/16KiB               184890              6514 ns/op        2515.28 MB/s           0 B/op          0 allocs/op                                                                                                                                       
BenchmarkStreamScheme/1MiB                  2780            422931 ns/op        2479.31 MB/s           0 B/op          0 allocs/op                                                                                                                                       
BenchmarkAEADScheme/16B                  7811796               156.5 ns/op       204.47 MB/s           0 B/op          0 allocs/op                                                                                                                                       
BenchmarkAEADScheme/32B                  7802522               153.5 ns/op       312.73 MB/s           0 B/op          0 allocs/op                                                                                                                                       
BenchmarkAEADScheme/64B                  7799248               154.5 ns/op       517.70 MB/s           0 B/op          0 allocs/op                                                                                                                                       
BenchmarkAEADScheme/128B                 6290869               196.5 ns/op       732.93 MB/s           0 B/op          0 allocs/op                                                                                                                                       
BenchmarkAEADScheme/256B                 4994802               236.1 ns/op      1152.09 MB/s           0 B/op          0 allocs/op                                                                                                                                       
BenchmarkAEADScheme/1KiB                 2260888               523.3 ns/op      1987.22 MB/s           0 B/op          0 allocs/op
BenchmarkAEADScheme/16KiB                 184443              6460 ns/op        2538.68 MB/s           0 B/op          0 allocs/op
BenchmarkAEADScheme/1MiB                    2961            410017 ns/op        2557.43 MB/s           0 B/op          0 allocs/op
```

## License

MIT or Apache 2.0.