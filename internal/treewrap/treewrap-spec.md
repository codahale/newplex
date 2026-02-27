# TreeWrap: Tree-Parallel Stream Cipher and MAC

**Status:** Draft  
**Version:** 0.2  
**Date:** 2026-02-27  
**Security Target:** 128-bit

## 1. Introduction

TreeWrap is a deterministic stream cipher with a MAC tag, using a tree-parallel topology based on KangarooTwelve to
enable SIMD acceleration (NEON, AVX2, AVX-512) on large inputs. Each leaf operates as an independent overwrite duplex
cipher in the style of Daemen et al.'s DWrap mode, and leaf chain values are accumulated into a single MAC tag via
TurboSHAKE128.

TreeWrap is not an AEAD scheme. It does not perform tag verification internally. Instead, it exposes two
operations—**EncryptAndMAC** and **DecryptAndMAC**—which both return the computed tag to the caller. The caller is
responsible for tag comparison, transmission, and any policy decisions around verification failure. This design supports
protocol frameworks that need to absorb the tag into an ongoing state regardless of verification outcome, or that
authenticate ciphertext through external mechanisms such as signatures.

TreeWrap is a pure function with no internal state. The caller manages key uniqueness and associated data.

## 2. Parameters

| Symbol | Value             | Description                                        |
|--------|-------------------|----------------------------------------------------|
| f      | Keccak-p[1600,12] | Underlying permutation (1600-bit state, 12 rounds) |
| R      | 168               | Rate (bytes)                                       |
| C      | 32                | Capacity (bytes); key, chain value, and tag size   |
| B      | 8192              | Chunk size (bytes), matching KangarooTwelve        |

## 3. Dependencies

**TurboSHAKE128(M, D, ℓ):** As specified in RFC 9861. Takes a message `M`, a domain separation byte `D` (0x01 – 0x7F),
and an output length `ℓ` in bytes.

## 4. Leaf Cipher

A leaf cipher is an overwrite duplex cipher using the same permutation and rate/capacity parameters as TurboSHAKE128. It
uses domain separation byte `0x60` in place of TurboSHAKE128's caller-specified byte.

The overwrite duplex differs from the traditional XOR-absorb duplex (SpongeWrap) in that the encrypt operation
overwrites the rate with ciphertext rather than XORing plaintext into it. This has two consequences: first, it enables a
clean security reduction to TurboSHAKE128 via the equivalence shown by Daemen et al. for the overwrite duplex
construction; second, for full-rate blocks, overwrite is faster than XOR on most architectures (write-only vs.
read-XOR-write).

A leaf cipher consists of a 200-byte state `S`, initialized to all zeros, and a rate index `pos`, initialized to zero.

**`pad_permute()`:**  
&emsp; `S[pos] ^= 0x60`  
&emsp; `S[R-1] ^= 0x80`  
&emsp; `S ← f(S)`  
&emsp; `pos ← 0`

**init(key, index):**  
&emsp; For each byte of `key ‖ [index]₆₄LE`, XOR it into `S[pos]` and increment `pos`. When `pos` reaches R−1 and more
input remains, call `pad_permute()`.  
&emsp; Call `pad_permute()`.

After `init`, the cipher has absorbed the key and index and is ready for encryption.

**encrypt(P) → C:** For each plaintext byte `Pⱼ`:  
&emsp; `Cⱼ ← Pⱼ ⊕ S[pos]`  
&emsp; `S[pos] ← Cⱼ` (overwrite with ciphertext)  
&emsp; Increment `pos`. When `pos` reaches R−1 and more plaintext remains, call `pad_permute()`.  
Return concatenated ciphertext bytes.

**decrypt(C) → P:** For each ciphertext byte `Cⱼ`:  
&emsp; `Pⱼ ← Cⱼ ⊕ S[pos]`  
&emsp; `S[pos] ← Cⱼ` (overwrite with ciphertext)  
&emsp; Increment `pos`. When `pos` reaches R−1 and more ciphertext remains, call `pad_permute()`.  
Return concatenated plaintext bytes.

Note: both encrypt and decrypt overwrite the rate with ciphertext. This ensures the state evolution is identical
regardless of direction, which is required for EncryptAndMAC/DecryptAndMAC consistency.

**chain_value() → cv:**  
&emsp; Call `pad_permute()`.  
&emsp; Output C bytes: for each byte, output `S[pos]` and increment `pos`. When `pos` reaches R−1 and more output
remains, call `pad_permute()`.

`chain_value()` always begins with `pad_permute()` to ensure all encrypted data is fully mixed before the chain value is
derived.

## 5. TreeWrap

### Notation

- `‖`: Byte string concatenation.
- `[i]₆₄LE`: The 8-byte little-endian encoding of integer `i`.
- `length_encode(x)`: The encoding used by KangarooTwelve: `x` as a big-endian byte string with no leading zeros,
  followed by a single byte indicating the length of that byte string. `length_encode(0)` is `0x00`.

### 5.1 EncryptAndMAC

**TreeWrap.EncryptAndMAC(key, plaintext) → (ciphertext, tag)**

*Inputs:*

- `key`: A C-byte key. MUST be unique per invocation (see §6.1).
- `plaintext`: Plaintext of any length (may be empty).

*Outputs:*

- `ciphertext`: Same length as `plaintext`.
- `tag`: A C-byte MAC tag.

*Procedure:*

Partition `plaintext` into `n = max(1, ⌈len(plaintext) / B⌉)` chunks. Chunk `i` (0-indexed) has size
`ℓᵢ = min(B, len(plaintext) − i·B)`. If plaintext is empty, `n = 1` and the single chunk is empty.

For each chunk `i`:  
&emsp; Create a leaf cipher `L`.  
&emsp; `L.init(key, i)`  
&emsp; `ciphertext[i] ← L.encrypt(plaintext_chunk[i])`  
&emsp; `cv[i] ← L.chain_value()`

Compute the tag using the KangarooTwelve final node structure:

&emsp; `final_input ← cv[0] ‖ 0x03 0x00 0x00 0x00 0x00 0x00 0x00 0x00`  
&emsp; `final_input ← final_input ‖ cv[1] ‖ ... ‖ cv[n−1]`  
&emsp; `final_input ← final_input ‖ length_encode(n−1)`  
&emsp; `final_input ← final_input ‖ 0xFF 0xFF`  
&emsp; `tag ← TurboSHAKE128(final_input, 0x61, C)`

When `n = 1`, the final input reduces to
`cv[0] ‖ 0x03 0x00 0x00 0x00 0x00 0x00 0x00 0x00 ‖ length_encode(0) ‖ 0xFF 0xFF`.

Return `(ciphertext[0] ‖ ... ‖ ciphertext[n−1], tag)`.

All leaf operations are independent and may execute in parallel. Tag computation begins as soon as all chain values are
available.

### 5.2 DecryptAndMAC

**TreeWrap.DecryptAndMAC(key, ciphertext) → (plaintext, tag)**

*Inputs:*

- `key`: A C-byte key.
- `ciphertext`: Ciphertext of any length (may be empty).

*Outputs:*

- `plaintext`: Same length as `ciphertext`.
- `tag`: A C-byte MAC tag.

*Procedure:*

Partition `ciphertext` into chunks identically to EncryptAndMAC.

For each chunk `i`:  
&emsp; Create a leaf cipher `L`.  
&emsp; `L.init(key, i)`  
&emsp; `plaintext[i] ← L.decrypt(ciphertext_chunk[i])`  
&emsp; `cv[i] ← L.chain_value()`

Compute the tag using the same final node structure as EncryptAndMAC:

&emsp; `final_input ← cv[0] ‖ 0x03 0x00 0x00 0x00 0x00 0x00 0x00 0x00`  
&emsp; `final_input ← final_input ‖ cv[1] ‖ ... ‖ cv[n−1]`  
&emsp; `final_input ← final_input ‖ length_encode(n−1)`  
&emsp; `final_input ← final_input ‖ 0xFF 0xFF`  
&emsp; `tag ← TurboSHAKE128(final_input, 0x61, C)`

Return `(plaintext[0] ‖ ... ‖ plaintext[n−1], tag)`.

The caller is responsible for comparing the returned tag against an expected value. TreeWrap does not perform tag
verification.

## 6. Security Properties

TreeWrap provides the following security properties under the assumption that the key is unique per invocation and that
Keccak-p[1600,12] is indistinguishable from a random permutation. Each property reduces to the Keccak sponge claim via
TurboSHAKE128's indifferentiability from a random oracle.

### 6.1 Key Uniqueness

TreeWrap is a deterministic algorithm. Encrypting two different plaintexts with the same key produces ciphertext XOR
differences equal to the plaintext XOR differences, fully compromising confidentiality. The key MUST be unique per
invocation. When used within a protocol framework, this is typically ensured by deriving the key from transcript state
that includes a nonce or counter.

### 6.2 Confidentiality (IND-CPA under a Random Key)

Under a uniformly random key, TreeWrap ciphertext is indistinguishable from a random string of the same length. The
argument:

Each leaf cipher, after `init(key, i)`, produces a keystream by squeezing the overwrite duplex. When the key is random,
the `init` call is a TurboSHAKE128 evaluation on a random input, and the resulting sponge state is indistinguishable
from random (by sponge indifferentiability). The keystream squeezed from this state is therefore pseudorandom.

Since the ciphertext is `plaintext ⊕ keystream` (for each leaf independently), the ciphertext is indistinguishable from
random under a random key. Different leaves use different indices, so their keystreams are independent.

The IND-CPA advantage is bounded by:

&emsp; ε\_cpa ≤ n · (t + σ)² / 2^(c+1)

where `n` is the number of leaves, `t` is the adversary's offline computation, `σ` is the data complexity in Keccak-p
blocks, and c = 256.

### 6.3 Tag PRF Security

Under a uniformly random key, the TreeWrap tag is a pseudorandom function of the ciphertext. Specifically, for any fixed
ciphertext, the tag output of EncryptAndMAC (or DecryptAndMAC) is indistinguishable from a uniformly random C-byte
string.

The argument:

1. Each leaf's chain value is the output of an overwrite duplex (a sponge evaluation) keyed by the random key and
   indexed by the leaf position. Under the sponge indifferentiability claim, each chain value is pseudorandom and
   independent across leaves.

2. The tag is `TurboSHAKE128(final_input, 0x61, C)` where `final_input` is a deterministic, injective encoding of the
   chain values. Since the chain values are pseudorandom, `final_input` is a pseudorandom input to an independent random
   oracle (domain byte 0x61 separates the tag computation from leaf ciphers at 0x60 and other uses of TurboSHAKE128).

3. A random oracle on a pseudorandom input produces a pseudorandom output.

The tag PRF advantage is bounded by:

&emsp; ε\_prf ≤ n · (t + σ)² / 2^(c+1) + (t + σ)² / 2^(c+1)

The first term covers the leaf chain value pseudorandomness; the second covers the tag accumulation TurboSHAKE128
evaluation.

This property is required by the protocol framework (§13.4 of the protocol specification) to ensure that absorbing a
TreeWrap tag into the protocol transcript does not compromise the independence of the chain value derived from the same
transcript instance.

### 6.4 Tag Collision Resistance

For any two distinct `(key, ciphertext)` pairs, the probability that EncryptAndMAC (or DecryptAndMAC) produces the same
tag is bounded by the collision resistance of TurboSHAKE128:

&emsp; ε\_coll ≤ (t + σ)² / 2^(c+1)

This is because distinct `(key, ciphertext)` pairs produce distinct sequences of leaf inputs
`(key, index, ciphertext_chunk)`. The leaf cipher's injective encoding ensures distinct sponge inputs, producing
distinct chain values (except with probability bounded by the sponge claim). Distinct chain value sequences produce
distinct `final_input` values (the encoding is injective). Distinct inputs to TurboSHAKE128 collide with probability
bounded by the sponge claim.

### 6.5 Committing Security (CMT-4)

TreeWrap provides CMT-4 committing security: the ciphertext and tag together commit to the key and plaintext. This is
the strongest committing security notion defined by Bellare and Hoang.

The argument is as follows. The tag is a collision-resistant function of `(key, ciphertext)` (§6.4). Since the
encryption within each leaf is invertible for a given key (the overwrite duplex encrypt/decrypt operations are
inverses), committing to `(key, ciphertext)` is equivalent to committing to `(key, plaintext)`. An adversary who
produces two distinct tuples `(key, plaintext)` and `(key', plaintext')` that yield the same `(ciphertext, tag)` has
found a collision in the tag computation.

This committing property is inherent to the construction — it does not require any additional processing or a second
pass over the data, unlike generic CMT-4 transforms applied to non-committing AE schemes.

### 6.6 Forgery Resistance

An adversary who does not know the key and attempts to produce a valid `(ciphertext, tag)` pair succeeds with
probability at most:

&emsp; ε\_forge ≤ S / 2^(C×8) = S / 2^256

for S forgery attempts against the full C-byte tag. When the caller truncates the tag to T bytes (as in the protocol
framework's Seal/Open), the forgery bound becomes S / 2^(T×8).

Note that forgery resistance is a consequence of tag PRF security (§6.3): the tag on any ciphertext the adversary has
not queried is indistinguishable from random, and guessing a random C-byte value succeeds with probability 1 / 2^(C×8).

### 6.7 Chunk Reordering

Each leaf is initialized with `key ‖ [index]₆₄LE`, binding it to its position. Reordering ciphertext chunks changes
which leaf decrypts which data, producing different chain values and a different tag. Additionally, since leaf indices
are bound at initialization, an attacker cannot cause chunk `i`'s ciphertext to be decrypted as chunk `j` — the
decryption will produce garbage and the chain value will not match.

### 6.8 Empty Plaintext

When plaintext is empty, a single leaf is still created. The chain value is derived from the cipher state after `init`
(with a `pad_permute` but no encrypt calls). The final node input is
`cv[0] ‖ 0x03 0x00 0x00 0x00 0x00 0x00 0x00 0x00 ‖ 0x00 ‖ 0xFF 0xFF`, producing a valid tag that authenticates the key.
This ensures DecryptAndMAC with an empty ciphertext computes the same tag as EncryptAndMAC with an empty plaintext.

### 6.9 Tag Accumulation Structure

Chain values are accumulated using the KangarooTwelve final node structure: `cv[0]` is absorbed as the "first chunk" of
the final node, followed by the 8-byte marker `0x03 0x00...`, then chain values `cv[1]` through `cv[n−1]` as "leaf"
contributions, followed by `length_encode(n−1)` and the terminator `0xFF 0xFF`. This is processed by TurboSHAKE128 with
domain separation byte `0x61`, separating TreeWrap tag computation from both KT128 hashing (`0x07`) and TreeWrap leaf
ciphers (`0x60`).

The structure is unambiguous: chain values are fixed-size (C bytes each), `length_encode` encodes the number of leaf
chain values, and the terminator marks the end. The number of chunks is determined by the ciphertext length, which is
assumed to be public.

### 6.10 Side Channels

All leaves process the same key. Implementations MUST ensure constant-time processing regardless of key and plaintext
values. The chunk index is not secret and does not require side-channel protection.

### 6.11 Concrete Security Reduction

Each leaf cipher is an overwrite duplex operating on the Keccak-p[1600,12] permutation with capacity c = 256 bits. The
security argument proceeds in three steps.

**Step 1: Leaf PRF security.** The `init` call is exactly a TurboSHAKE128 evaluation:
`TurboSHAKE128(key ‖ [index]₆₄LE, 0x60)`, since the 40-byte input fits within one sponge block and TreeWrap's padding
(domain byte after data, `0x80` at position R−1) matches TurboSHAKE128's padding format. Subsequent encrypt blocks use a
simplified padding (domain byte `0x60` and frame byte `0x80` both at position R−1, collapsing to `0xE0`) that does not
correspond to TurboSHAKE128's multi-block structure. However, the leaf's outputs can be expressed as evaluations of the
Keccak[256] sponge function (with Keccak-p[1600,12]) on an injective encoding of the leaf's inputs, following the same
overwrite-to-XOR equivalence used by Daemen et al. in Lemma 2 of the overwrite duplex construction. The injectivity
holds because: (a) the ciphertext overwrite is injective for a given keystream, (b) block boundaries are determined by
the public plaintext length, and (c) the `pad_permute` domain byte position distinguishes blocks of different lengths.

Assuming the Keccak sponge claim holds for Keccak-p[1600,12], the advantage of distinguishing a TreeWrap leaf from an
ideal cipher is at most `(t + σ)² / 2^(c+1)` where `t` is the computational complexity and `σ` is the data complexity in
blocks. For c = 256, this term is negligible for practical workloads.

**Step 2: Tag PRF and collision resistance.** The tag is a TurboSHAKE128 evaluation (domain byte `0x61`) over the
concatenation of leaf chain values. Since each chain value is pseudorandom under the key (by Step 1), the tag inherits
both the PRF security and the collision resistance of TurboSHAKE128. The tag computation adds one additional sponge
indifferentiability term.

**Step 3: Combined bound.** Summing all terms for a TreeWrap invocation with n leaves:

    ε\_treewrap ≤ (n + 1) · (t + σ)² / 2^(c+1)

where the (n + 1) factor accounts for n leaf cipher evaluations plus one tag accumulation evaluation. For typical
parameters (n ≤ 2^32 leaves, t + σ ≤ 2^64), this is (2^32 + 1) · 2^128 / 2^257 ≈ 2^-97, well within the 128-bit security
target for any single invocation. Multi-invocation security is the responsibility of the calling protocol, which must
ensure key uniqueness.

## 7. Comparison with Traditional AEAD

TreeWrap differs from traditional AEAD in several respects:

**No internal tag verification.** Traditional AEAD schemes (AES-GCM, ChaCha20-Poly1305, etc.) perform tag comparison
inside the Open/Decrypt function and return ⊥ on failure, ensuring plaintext is never released before authentication.
TreeWrap's DecryptAndMAC always returns both plaintext and tag, leaving verification to the caller. This is intentional:
the protocol framework needs the tag for transcript state advancement regardless of verification outcome (see protocol
specification §10.8).

**Deterministic, no nonce input.** TreeWrap takes only a key and plaintext. It does not accept a nonce or associated
data. These are the protocol framework's responsibility. The key MUST be unique per invocation.

**Tag is a PRF output, not just a MAC.** Traditional AEAD tags are MACs — they prove authenticity but are not
necessarily pseudorandom. TreeWrap's tag is a full PRF: under a random key, the tag is indistinguishable from a random
string. This stronger property is required by the protocol framework's composition argument.

## 8. References

- Daemen, J., Hoffert, S., Mella, S., Van Assche, G., and Van Keer, R. "Shaking up authenticated encryption." IACR
  ePrint 2024/1618. Defines the overwrite duplex (OD) construction and proves its security equivalence to (Turbo)SHAKE.
- RFC 9861: TurboSHAKE and KangarooTwelve.
- Bellare, M. and Hoang, V. T. "Efficient schemes for committing authenticated encryption." Defines the CMT-4 committing
  security notion.

## 9. Test Vectors

(To be generated from a reference implementation.)

Recommended test cases:

- Empty plaintext (MAC-only)
- 1-byte plaintext (minimal, single leaf)
- B-byte plaintext (exactly one chunk)
- B+1-byte plaintext (two chunks, minimal second)
- 4·B-byte plaintext (four full chunks, exercises 4-way SIMD)
- EncryptAndMAC followed by DecryptAndMAC: tag equality
- Single bit flip in each chunk position (tag mismatch)
- Chunk-swapped ciphertext (tag mismatch)
