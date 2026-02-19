# Newplex

Newplex is a cryptographic framework that provides a unified interface for unkeyed and symmetric-key operations. It is
built on a duplex construction using the [Simpira-1024] permutation. Inspired by [STROBE], [Noise Protocol],
and [Xoodyak], Newplex is optimized for 64-bit architectures (x86-64 and ARM64) to provide 10+ Gb/second performance on
modern processors at a 128-bit security level.

The framework is guided by two central design principles. First, by replacing the traditional suite of separate hash
functions, MACs, stream ciphers, and KDFs with a single duplex construction, Newplex drastically simplifies the design
and implementation of cryptographic schemes--from basic AEAD to complex multi-party protocols like OPRFs and handshakes.
Second, the security of every scheme built on Newplex reduces to the well-studied properties of the underlying duplex
(indifferentiability from a random oracle, pseudorandom function security, and collision resistance), all bounded by the
256-bit capacity (`2**128` against generic attacks). This tight reduction means that a single, focused security analysis
of the duplex and permutation layers provides assurance for the entire framework.

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

On AMD64 and ARM64 architectures, newplex uses the AES-NI instruction set to achieve this level of performance. On other
architectures, or if the `purego` build tag is used, it uses a much-slower Go implementation with a bitsliced,
constant-time AES round implementation.

The AMD64 implementation requires the AES-NI and SSE2 instruction sets, which are ubiquitous.

The ARM64 implementation requires the ARMv8 Crypto Extensions and ASIMD (NEON) support.

To force the use of the portable implementation, use the `purego` build tag:

```bash
go build -tags purego ./...
```

### Protocol

`Protocol` is a high-level API, designed for easily building complex cryptographic schemes (e.g., hash functions, MACs,
stream ciphers, AEADs, sessions) with built-in domain separation and state management.

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

Newplex includes many cryptographic schemes implemented as sub-packages:

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

Design details for these are included in [`design.md`](design.md).

## Performance

Newplex targets 10+ Gbp/sec performance on modern server processors.

### AMD64

```text
goos: linux
goarch: amd64
pkg: github.com/codahale/newplex
cpu: INTEL(R) XEON(R) PLATINUM 8581C CPU @ 2.30GHz
BenchmarkHashScheme/16B                 10554235               113.5 ns/op       140.94 MB/s           0 B/op          0 allocs/op
BenchmarkHashScheme/32B                 10530486               112.3 ns/op       284.85 MB/s           0 B/op          0 allocs/op
BenchmarkHashScheme/64B                 10594501               112.5 ns/op       568.80 MB/s           0 B/op          0 allocs/op
BenchmarkHashScheme/128B                 7222648               165.2 ns/op       774.86 MB/s           0 B/op          0 allocs/op
BenchmarkHashScheme/256B                 4608260               260.6 ns/op       982.44 MB/s           0 B/op          0 allocs/op
BenchmarkHashScheme/1KiB                 1830760               656.4 ns/op      1560.01 MB/s           0 B/op          0 allocs/op
BenchmarkHashScheme/16KiB                 139580              8431 ns/op        1943.39 MB/s           0 B/op          0 allocs/op
BenchmarkHashScheme/1MiB                    2212            537377 ns/op        1951.29 MB/s           0 B/op          0 allocs/op
BenchmarkPRFScheme/16B                  10302806               117.0 ns/op       136.75 MB/s           0 B/op          0 allocs/op
BenchmarkPRFScheme/32B                  10319643               117.5 ns/op       272.27 MB/s           0 B/op          0 allocs/op
BenchmarkPRFScheme/64B                  10389806               116.7 ns/op       548.35 MB/s           0 B/op          0 allocs/op
BenchmarkPRFScheme/128B                  7057303               167.1 ns/op       766.03 MB/s           0 B/op          0 allocs/op
BenchmarkPRFScheme/256B                  5569346               217.6 ns/op      1176.42 MB/s           0 B/op          0 allocs/op
BenchmarkPRFScheme/1KiB                  1974172               609.8 ns/op      1679.35 MB/s           0 B/op          0 allocs/op
BenchmarkPRFScheme/16KiB                  139544              8682 ns/op        1887.22 MB/s           0 B/op          0 allocs/op
BenchmarkPRFScheme/1MiB                     2151            554635 ns/op        1890.57 MB/s           0 B/op          0 allocs/op
BenchmarkStreamScheme/16B                8625686               137.1 ns/op       116.70 MB/s           0 B/op          0 allocs/op
BenchmarkStreamScheme/32B                8799950               137.3 ns/op       233.08 MB/s           0 B/op          0 allocs/op
BenchmarkStreamScheme/64B                8776183               137.2 ns/op       466.40 MB/s           0 B/op          0 allocs/op
BenchmarkStreamScheme/128B               6099103               198.2 ns/op       645.74 MB/s           0 B/op          0 allocs/op
BenchmarkStreamScheme/256B               4699260               255.8 ns/op      1000.90 MB/s           0 B/op          0 allocs/op
BenchmarkStreamScheme/1KiB               1656283               723.4 ns/op      1415.46 MB/s           0 B/op          0 allocs/op
BenchmarkStreamScheme/16KiB               120487              9974 ns/op        1642.71 MB/s           0 B/op          0 allocs/op
BenchmarkStreamScheme/1MiB                  1878            630572 ns/op        1662.90 MB/s           0 B/op          0 allocs/op
BenchmarkAEADScheme/16B                  4369694               273.0 ns/op       117.23 MB/s           0 B/op          0 allocs/op
BenchmarkAEADScheme/32B                  4355893               273.9 ns/op       175.25 MB/s           0 B/op          0 allocs/op
BenchmarkAEADScheme/64B                  4335715               272.4 ns/op       293.69 MB/s           0 B/op          0 allocs/op
BenchmarkAEADScheme/128B                 3545064               337.4 ns/op       426.83 MB/s           0 B/op          0 allocs/op
BenchmarkAEADScheme/256B                 3020806               397.0 ns/op       685.06 MB/s           0 B/op          0 allocs/op
BenchmarkAEADScheme/1KiB                 1385412               863.1 ns/op      1205.01 MB/s           0 B/op          0 allocs/op
BenchmarkAEADScheme/16KiB                 118933             10178 ns/op        1611.35 MB/s           0 B/op          0 allocs/op
BenchmarkAEADScheme/1MiB                    1868            634817 ns/op        1651.80 MB/s           0 B/op          0 allocs/op
```

### ARM64

```text
goos: darwin                                                                                                                                                                                                                                                             
goarch: arm64                                                                                                                                                                                                                                                            
pkg: github.com/codahale/newplex                                                                                                                                                                                                                                         
cpu: Apple M4 Pro                                                                                                                                                                                                                                                        
BenchmarkHashScheme/16B                 16814496                71.16 ns/op      224.84 MB/s           0 B/op          0 allocs/op                                                                                                                                       
BenchmarkHashScheme/32B                 17018922                69.76 ns/op      458.69 MB/s           0 B/op          0 allocs/op                                                                                                                                       
BenchmarkHashScheme/64B                 16943547                70.24 ns/op      911.19 MB/s           0 B/op          0 allocs/op                                                                                                                                       
BenchmarkHashScheme/128B                11145199               106.8 ns/op      1198.96 MB/s           0 B/op          0 allocs/op                                                                                                                                       
BenchmarkHashScheme/256B                 7020832               170.9 ns/op      1497.66 MB/s           0 B/op          0 allocs/op                                                                                                                                       
BenchmarkHashScheme/1KiB                 2614765               458.2 ns/op      2234.65 MB/s           0 B/op          0 allocs/op                                                                                                                                       
BenchmarkHashScheme/16KiB                 185260              6297 ns/op        2601.91 MB/s           0 B/op          0 allocs/op                                                                                                                                       
BenchmarkHashScheme/1MiB                    2960            398518 ns/op        2631.19 MB/s           0 B/op          0 allocs/op                                                                                                                                       
BenchmarkPRFScheme/16B                  16242884                73.58 ns/op      217.44 MB/s           0 B/op          0 allocs/op                                                                                                                                       
BenchmarkPRFScheme/32B                  16184976                73.61 ns/op      434.71 MB/s           0 B/op          0 allocs/op                                                                                                                                       
BenchmarkPRFScheme/64B                  14451120                76.45 ns/op      837.12 MB/s           0 B/op          0 allocs/op                                                                                                                                       
BenchmarkPRFScheme/128B                 10966674               108.4 ns/op      1181.29 MB/s           0 B/op          0 allocs/op                                                                                                                                       
BenchmarkPRFScheme/256B                  8437740               141.1 ns/op      1814.75 MB/s           0 B/op          0 allocs/op                                                                                                                                       
BenchmarkPRFScheme/1KiB                  2960836               405.0 ns/op      2528.31 MB/s           0 B/op          0 allocs/op                                                                                                                                       
BenchmarkPRFScheme/16KiB                  186369              5891 ns/op        2781.30 MB/s           0 B/op          0 allocs/op                                                                                                                                       
BenchmarkPRFScheme/1MiB                     3190            374978 ns/op        2796.37 MB/s           0 B/op          0 allocs/op                                                                                                                                       
BenchmarkStreamScheme/16B               13117477                92.18 ns/op      173.57 MB/s           0 B/op          0 allocs/op                                                                                                                                       
BenchmarkStreamScheme/32B               12834481                92.71 ns/op      345.17 MB/s           0 B/op          0 allocs/op                                                                                                                                       
BenchmarkStreamScheme/64B               12596391                93.35 ns/op      685.56 MB/s           0 B/op          0 allocs/op                                                                                                                                       
BenchmarkStreamScheme/128B               9155252               131.3 ns/op       974.97 MB/s           0 B/op          0 allocs/op                                                                                                                                       
BenchmarkStreamScheme/256B               7110429               168.3 ns/op      1521.34 MB/s           0 B/op          0 allocs/op                                                                                                                                       
BenchmarkStreamScheme/1KiB               2628403               456.4 ns/op      2243.57 MB/s           0 B/op          0 allocs/op                                                                                                                                       
BenchmarkStreamScheme/16KiB               182524              6370 ns/op        2571.91 MB/s           0 B/op          0 allocs/op                                                                                                                                       
BenchmarkStreamScheme/1MiB                  2930            403863 ns/op        2596.37 MB/s           0 B/op          0 allocs/op                                                                                                                                       
BenchmarkAEADScheme/16B                  6736288               177.8 ns/op       179.99 MB/s           0 B/op          0 allocs/op                                                                                                                                       
BenchmarkAEADScheme/32B                  6762585               178.1 ns/op       269.58 MB/s           0 B/op          0 allocs/op                                                                                                                                       
BenchmarkAEADScheme/64B                  6662682               178.4 ns/op       448.50 MB/s           0 B/op          0 allocs/op                                                                                                                                       
BenchmarkAEADScheme/128B                 5518846               216.6 ns/op       664.85 MB/s           0 B/op          0 allocs/op                                                                                                                                       
BenchmarkAEADScheme/256B                 4750824               252.5 ns/op      1077.18 MB/s           0 B/op          0 allocs/op                                                                                                                                       
BenchmarkAEADScheme/1KiB                 2210043               543.5 ns/op      1913.64 MB/s           0 B/op          0 allocs/op                                                                                                                                       
BenchmarkAEADScheme/16KiB                 183354              6501 ns/op        2522.50 MB/s           0 B/op          0 allocs/op                                                                                                                                       
BenchmarkAEADScheme/1MiB                    2937            409442 ns/op        2561.03 MB/s           0 B/op          0 allocs/op  
```

## License

MIT or Apache 2.0.