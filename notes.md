# Notes

These are some free-form notes on things that have come up while working on this project.

## Permutation Choice

All things being equal, I would prefer to use Keccak as the permutation for this. It's better-studied, actually adopted
in a wide variety of cryptographic standards, and it's fast in software. The big drawback to Keccak is that it's really
only fast on ARM64 processors and even then only the 12-round Turbo variant can handle 10 Gbps+ speeds.

Keccak on AMD64 is kind of just stuck. Throwing vectorization at it doesn't help, and the most optimized scalar
implementation tops out at around 4.5 Gbps for 24 rounds and 9.8 Gbps for 12. Once you factor in the overhead of a
duplex's capacity, there's no way of hitting 10 Gbps+. On ARM64, Keccak is really fast, especially with FEAT_SHA3. It
can hit 10 Gbps+ easily with 24 rounds. But it's not a widely-used architecture for servers.

Simpira-1024, on the other hand, can do 25 Gbps+ on ARM64 and 15 Gbps+ on AMD64. It has a smaller width, but 768 bits of
rate is sufficient to allow for vectorization of all duplex operations. The main drawback for Simpira-1024 is that if
the host machine doesn't have AES-NI, performance drops by three orders of magnitude, down to ~10 Mbps. That said, the
vast majority of non-IoT hardware in 2026 has AES-NI support.

## Optimizing Simpira-1024

I've leaned very heavily on Gemini 3 Pro to implement and optimize the assembly versions of Simpira-1024. This is a
summary of the various optimization attempts and how they've panned out.

At this point, it seems like the implementation on both platforms is limited by the AES pipeline and not by
implementation choices. Both Intel's Emerald Rapids and Apple's M4 processors can fully pipeline the AES rounds in the
permutation, and using wider instructions like `VAESENC` do not seem to improve throughput.

### AMD64

* **Pipelining & Table Lookups**: Moved round constants to a lookup table and used additional registers to try to
  improve `AESENC` pipelining. I initially thought this was a performance win, but having tested it pretty extensively
  on both AMD64 and ARM64 platforms, it's a total wash in performance. I think the size of the data section outweighs
  the slight penalty of calculating the round constants dynamically. I went with the more compact implementation.
* **Instruction Encoding**: Switched to using register-relative addressing for round constants, reducing the encoding
  size for `AESENC` operations. Small performance win.
* **VAES/AVX-512**: Used VEX-encoded instructions to avoid unnecessary moves. Required an entirely new implementation,
  as AVX-512 isn't widely deployed yet. ~1% improvement in performance. I reverted this one because the
  maintenance/testing overhead wasn't worth the benefit.
* **More Pipelining**: The really significant improvement came from pointing Gemini at the Simpira reference code and
  telling it to look for optimization strategies. It batched more rounds into a combined operation, which resulted in
  hitting the same performance as the ARM64 implementation post-fusion optimizations.

### ARM64

* **Pipelining & Table Lookups**: Moved round constants to a lookup table and used additional registers to try to
  improve `AESE` pipelining. Again, like on AMD64, this seemed like a win initially but did not pan out.
* **Instruction Fusion**: Fused the addition of round constants directly into the `AESE` operation. Unlike `AESENC` on
  AMD64, `AESE` includes the XOR of the round key. This removed 4 `VEOR` operations per round and improved performance
  by 19%.

## Serial vs Parallel

One of the newer approaches to coaxing more speed out of a duplex -- an inherently serial data structure in which every
processed block depends on the previous one -- is the use of parallel sponges/duplexes. KangarooTwelve and Farfalle take
this approach for hashing and authenticated encryption, respectively, with large blocks of inputs being processed by
parallel lanes of sponges, then using vectorization to permute all the lanes in parallel. This allows for Keccak-based
constructions to achieve higher performance.

The problem with these approaches is twofold. First, they aren't faster than Simpira-1024. An AVX-512-based
implementation which permutes 4 1600-bit states in parallel can expect to achieve around 16 Gbps across all four states.
That's dramatically better than an optimized scalar implementation working on a single state value, but it's still well
short of Simpira-1024. Second, ensuring that the leaf states are sufficiently domain-separated and the root state is
unambiguously dependent on the leaf states is very complex. KT128 and Farfalle are single-pass constructions which are
structured to allow for parallel states on large inputs but which are semantically equivalent to a single root state and
a single leaf state. This is a tremendously cool design, but extending it to a stateful duplex would mean designing a
feed-forward mechanism to complement the feed-backward mechanism which updates the root state. That would introduce
additional complexity as well as additional overhead both in latency and memory usage.

Unless we start with Keccak as a fixed choice of permutation, it's difficult to justify that complexity in the absence
of a significant performance benefit.

## Padding Schemes

I spent a lot of time considering additional padding schemes for the duplex. SHA-3 uses a combination of domain
separation bits and `10*1` padding on inputs. Cyclist uses a specific byte of the duplex's rate for domain separation
and has an up/down flag to control permutation which it inherited from Motorist. Ascon appends a single bit and pads to
a full block with zeros. All of these ensure domain separation for the various inputs and are space-efficient.

The design of Newplex is more complex than those due to the introduction of input labels. Considering only the case of
a `Mix` operations, there are three distinct inputs to the duplex's state:

1. The operation code, uniquely identifying the inputs as being from a `Mix` operation.
2. The label, which is variable-length.
3. The input, which is variable-length and whose length may not be known in advance.

The operation code functions essentially the same way at the mode byte which Cyclist allocates from the duplex's rate.
It's fixed length and present in each operation. It doesn't present much of a problem.

The label and input, however, do present an issue when it comes to unambiguous encodings. A simple solution would be to
adopt one of the existing sponge padding schemes, pad the label to full-sized blocks, absorb it into the state, ensure
the state is permuted, then repeat the process for the input. This is a sound design, but at a very high performance
cost. Each `Mix` operation would require a minimum of two permutations, even for short inputs. Even initializing a
protocol would require a permutation to ensure the `Init` operation was separated from the next operation. This design
approach is excellent for narrower permutations, like Ascon, and for single-pass sponge constructions which use a
fully-keyed sponge design that initializes the state with the concatenation of a fixed-length key and IV. It is a poor
design for a wide permutation which is expected to take a number of distinct inputs before beginning a high-throughput
phase like encryption.

I also looked at non-linear modifications to the duplex state as a potential marking mechanism, but the number of
distinct operations which would need to unambiguously modify the state is high.

For a while, adopting the TupleHash design of using a recoverable encoding to unambiguously structure the inputs as a
single input string seemed like the best approach. This adds a small amount of overhead, with each label and input
requiring a pre- or appended length. It preserves the distinction between label and input spatially in the duplex's
state, which is nice, but the fact that `left_encode`/`right_encode` have common ambiguous encoded forms makes this
not viable. In the context of TupleHash, it's fine -- `right_encode` is used exclusively for the desired output length,
and the standard SHA-3 `pad10*1` padding scheme prevents in-block collisions. In the context of an unpadded duplex, it
allows for a significant degree of unwanted ambiguity. It's _probably_ fine, but I'd rather build on a sturdier
foundation.

Instead, I landed on the way STROBE handles operations. It reserves two bytes of the rate for padding. When an operation
begins, it records the duplex's position. When it permutes, it includes the operation's position in the input and uses
the `pad10*1` scheme to avoid zero-appending attacks. This design records operation boundaries in the duplex's state
spatially. Operations with multiple inputs (i.e., everything but `Init`) get separated into two sub-operations: one with
an operation code with its high bit cleared (e.g., `0x02`) for the label, and one with the high bit set (e.g.,
`0x02|0x80`) for the input. This ensures that labels and inputs cannot collide, even when encoded in the same block. The
resulting code is very simple, albeit a little slower. To encode lengths in `Derive`, `Seal`, etc., I initially went
with a little-endian representation that strips leading zeros, but realized that wasn't prefix-free (e.g.,
`absorbLE(0xAD)` is a prefix of `absorbLE(0xDEAD)`). Given that it's always followed with a `permute` call, that was
OK, but I switched that to LEB128 because a) it's prefix-free and b) it's an existing standard.

The use of a padding scheme also allows Newplex to hew closely to the existing security proofs for sponges and duplexes,
most of which depend on the specifics of the padding.

## Varint Encodings

I spent a long time looking at various space-efficient integer encoding schemes.

### QUIC

QUIC has an encoding scheme which uses the two most-significant bits of the first encoded byte as the base-2 logarithm
of the total number of encoded bytes. Values from `0b00000000` to `0b00111111` are encoded as single bytes, with the MSB
prefix of `00` indicating a single byte; values from `0b01000000` to `0b01111111_11111111` are encoded as two bytes,
with the MSB prefix of `01` indicated two bytes, etc. This is fast and space-efficient for very small numbers, which
can be encoded with a single byte, and for medium-sized numbers, which can be encoded with two.

The main problem is that Newplex needs two distinct encoding mechanisms which don't overlap at all in the way they
encode numbers: one to encode values whose lengths are known in advance, another to encode values who lengths are only
known after processing. If we consider the specified QUIC encoding to be one of those, it's not clear how we can modify
it to achieve another, entirely distinct encoding. Using the least-significant bits of the last byte occurred to me,
which produces a right-to-left decodable format, but an encoded value like `0b01111111_11111101` is ambiguous in terms
of which encoding scheme was used.

Given that our only purpose is domain separation, that rules QUIC out.

### LEB128

LEB128 uses the MSB of each byte to indicate whether the current byte is the final one of the encoding. It's fast, it
works well for numbers of all sizes, and it's widely adopted. The primary difficulty is that the encoding itself permits
multiple encodings for a single number. `0b01000000` can be encoded as `0b01000000` or `0b00000000_01000000`. That could
be mitigated by simply promising not to encode numbers like that, but the fact that it's an ambiguous encoding to begin
with is a rough start.

To make a distinct second encoding, we could simply invert the continuation bits. This is fairly space-efficient, but
ends up having a slightly slower runtime than TupleHash due to the conditional in the hot loop. It's also very difficult
to make an implementation of it which plays nicely with Go's escape analysis.

### TupleHash

TupleHash uses two functions, `left_encode` and `right_encode`, which are just the big-endian encoding of an integer,
stripped of the leading zeros, and with the byte length either prepended or appended. It uses a minimum of two bytes to
encode a value, but can be implemented in a very concise and branchless form.

It still contains a category of ambiguously-encoded forms. To begin, the mapping from integer to big-endian bytestring
is perfectly bijective. The only remaining possible ambiguity, then, are encoded forms which are palindromic:

```text
[1, 1]     // left_encode(1) | right_encode(1)
[2, 3, 2]  // left_encode(770) | right_encode(515)
```