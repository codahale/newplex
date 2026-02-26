# TreeWrap: Tree-Parallel Authenticated Encryption

**Status:** Draft
**Version:** 0.2
**Date:** 2026-02-26
**Security Target:** 128-bit

## 1. Introduction

TreeWrap is an authenticated encryption algorithm that uses a tree-parallel topology based on KangarooTwelve to enable
SIMD acceleration (NEON, AVX2, AVX-512) on large inputs. Each leaf operates as an independent overwrite duplex cipher in
the style of Daemen et al.'s DWrap mode, and leaf chain values are accumulated into a single authentication tag via
TurboSHAKE128. The tag provides both authentication and CMT-4 committing security.

TreeWrap is a pure function with no internal state. It is intended as a building block for duplex-based protocols, where
key uniqueness and associated data are managed by the caller.

## 2. Parameters

| Symbol | Value               | Description                                        |
|--------|---------------------|----------------------------------------------------|
| f      | Keccak-p\[1600,12\] | Underlying permutation (1600-bit state, 12 rounds) |
| R      | 168                 | Rate (bytes)                                       |
| C      | 32                  | Capacity (bytes); key, chain value, and tag size   |
| B      | 8192                | Chunk size (bytes), matching KangarooTwelve        |

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
regardless of direction, which is required for Seal/Open consistency.

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

### 5.1 Seal

**TreeWrap.Seal(key, plaintext) → (ciphertext, tag)**

*Inputs:*

- `key`: A C-byte key. MUST be unique per invocation (see §6.1).
- `plaintext`: Plaintext of any length (may be empty).

*Outputs:*

- `ciphertext`: Same length as `plaintext`.
- `tag`: A C-byte authentication tag.

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

### 5.2 Open

**TreeWrap.Open(key, ciphertext, tag) → plaintext or ⊥**

*Procedure:*

Partition `ciphertext` into chunks identically to Seal.

For each chunk `i`:  
&emsp; Create a leaf cipher `L`.  
&emsp; `L.init(key, i)`  
&emsp; `plaintext[i] ← L.decrypt(ciphertext_chunk[i])`  
&emsp; `cv[i] ← L.chain_value()`

Compute the expected tag using the same final node structure as Seal:

&emsp; `final_input ← cv[0] ‖ 0x03 0x00 0x00 0x00 0x00 0x00 0x00 0x00`  
&emsp; `final_input ← final_input ‖ cv[1] ‖ ... ‖ cv[n−1]`  
&emsp; `final_input ← final_input ‖ length_encode(n−1)`  
&emsp; `final_input ← final_input ‖ 0xFF 0xFF`  
&emsp; `expected ← TurboSHAKE128(final_input, 0x61, C)`

If `expected ≠ tag` (constant-time comparison), return ⊥ and discard all plaintext.

Return `plaintext[0] ‖ ... ‖ plaintext[n−1]`.

## 6. Security Considerations

### 6.1 Key Uniqueness

TreeWrap is a deterministic algorithm. Encrypting two different plaintexts with the same key produces ciphertext XOR
differences equal to the plaintext XOR differences, fully compromising confidentiality. The key MUST be unique per
invocation. When used within a duplex protocol, this is typically ensured by deriving the key from session state that
includes a nonce or counter.

### 6.2 Ciphertext Integrity

Each leaf cipher is an overwrite duplex instance. The `init` call is a TurboSHAKE128 evaluation; subsequent encrypt
blocks operate as a Keccak[256] sponge with an injective input encoding (via the overwrite-to-XOR equivalence of Daemen
et al.). The chain value squeezed after encryption therefore commits to the full ciphertext of that chunk under the
Keccak sponge claim.

Modifying any byte of ciphertext in any chunk changes that chunk's chain value, which changes the tag. An attacker must
find a TurboSHAKE128 collision or second preimage on C-byte outputs (requiring 2^128 work) to forge a valid tag. The
forgery probability after `q` attempts is at most `q / 2^(8·C)`.

### 6.3 Chunk Reordering

Each leaf is initialized with `key ‖ [index]₆₄LE`, binding it to its position. Reordering ciphertext chunks changes
which leaf decrypts which data, producing different chain values and a different tag. Chunk reordering is detected by
tag verification.

Additionally, since leaf indices are bound at initialization, an attacker cannot cause chunk `i`'s ciphertext to be
decrypted as chunk `j` — the decryption will produce garbage and the chain value will not match.

### 6.4 Committing Security (CMT-4)

TreeWrap provides CMT-4 committing security: the ciphertext commits to the key, plaintext, and (implicitly via the
calling protocol) associated data. This is the strongest committing security notion defined by Bellare and Hoang.

The argument is as follows. Each leaf's chain value is the output of an overwrite duplex cipher whose inputs are
injectively encoded into the Keccak\[256\] sponge (the `init` call via TurboSHAKE128, subsequent encrypt blocks via the
overwrite-to-XOR equivalence). The tag is a TurboSHAKE128 hash of the concatenated chain values. Therefore, the tag is a
collision-resistant function of `(key, ciphertext)`.

Since the encryption within each leaf is a permutation of plaintext for a given key (the overwrite duplex encrypt is
invertible), committing to `(key, ciphertext)` is equivalent to committing to `(key, plaintext)`. An adversary who
produces two distinct tuples `(key, plaintext)` and `(key', plaintext')` that yield the same `(ciphertext, tag)` has
found a collision in the tag computation, requiring 2^min(128, 8·C/2) = 2^128 work.

This committing property is inherent to the construction — it does not require any additional processing or a second
pass over the data, unlike generic CMT-4 transforms applied to non-committing AE schemes.

### 6.5 Empty Plaintext

When plaintext is empty, a single leaf is still created. The chain value is derived from the cipher state after `init` (
with a `pad_permute` but no encrypt calls). The final node input is
`cv[0] ‖ 0x03 0x00 0x00 0x00 0x00 0x00 0x00 0x00 ‖ 0x00 ‖ 0xFF 0xFF`, producing a valid tag that authenticates the key.
This ensures `TreeWrap.Open` with an empty ciphertext and valid tag succeeds, while any non-empty ciphertext with that
tag fails.

### 6.6 Tag Accumulation

Chain values are accumulated using the KangarooTwelve final node structure: `cv[0]` is absorbed as the "first chunk" of
the final node, followed by the 8-byte marker `0x03 0x00...`, then chain values `cv[1]` through `cv[n−1]` as "leaf"
contributions, followed by `length_encode(n−1)` and the terminator `0xFF 0xFF`. This is processed by TurboSHAKE128 with
domain separation byte `0x61`, separating TreeWrap tag computation from both KT128 hashing (`0x07`) and TreeWrap leaf
ciphers (`0x60`).

The structure is unambiguous: chain values are fixed-size (C bytes each), `length_encode` encodes the number of leaf
chain values, and the terminator marks the end. The number of chunks is determined by the ciphertext length, which is
assumed to be public.

### 6.7 Side Channels

All leaves process the same key. Implementations MUST ensure constant-time processing regardless of key and plaintext
values. The chunk index is not secret and does not require side-channel protection.

### 6.8 Security Reduction

Each leaf cipher is an overwrite duplex operating on the Keccak-p\[1600,12\] permutation with capacity c = 256 bits. The
security argument proceeds in two parts.

**Leaf PRF security.** The `init` call is exactly a TurboSHAKE128 evaluation: `TurboSHAKE128(key ‖ [index]₆₄LE, 0x60)`,
since the 40-byte input fits within one sponge block and TreeWrap's padding (domain byte after data, `0x80` at position
R−1) matches TurboSHAKE128's padding format. Subsequent encrypt blocks use a simplified padding (domain byte `0x60` and
frame byte `0x80` both at position R−1, collapsing to `0xE0`) that does not correspond to TurboSHAKE128's multi-block
structure. However, the leaf's outputs can be expressed as evaluations of the Keccak\[256\] sponge function (with
Keccak-p\[1600,12\]) on an injective encoding of the leaf's inputs, following the same overwrite-to-XOR equivalence used
by Daemen et al. in Lemma 2 of the overwrite duplex construction. The injectivity holds because: (a) the ciphertext
overwrite is injective for a given keystream, (b) block boundaries are determined by the public plaintext length, and (
c) the `pad_permute` domain byte position distinguishes blocks of different lengths.

Assuming the Keccak sponge claim holds for Keccak-p\[1600,12\], the advantage of distinguishing a TreeWrap leaf from an
ideal cipher is at most `(t + σ)² / 2^(c+1)` where `t` is the computational complexity and `σ` is the data complexity in
blocks. For c = 256, this term is negligible for practical workloads.

**Tag accumulation.** The tag is a TurboSHAKE128 evaluation (domain byte `0x61`) over the concatenation of leaf chain
values. Since each chain value is pseudorandom under the key (by leaf PRF security), the tag inherits both the PRF
security and the collision resistance of TurboSHAKE128. The tag computation adds no additional security loss beyond the
TurboSHAKE128 sponge claim term.

## 7. References

- Daemen, J., Hoffert, S., Mella, S., Van Assche, G., and Van Keer, R. "Shaking up authenticated encryption." IACR
  ePrint 2024/1618. Defines the overwrite duplex (OD) construction and proves its security equivalence to (Turbo)SHAKE.
- RFC 9861: TurboSHAKE. Defines TurboSHAKE128 and TurboSHAKE256.
- Bertoni, G. et al. "KangarooTwelve: Fast hashing based on Keccak-p." Defines the tree topology, chunk size, and final
  node structure reused by TreeWrap.
- Bellare, M. and Hoang, V. T. "Efficient schemes for committing authenticated encryption." Defines the CMT-4 committing
  security notion.

## 8. Test Vectors

(To be generated from a reference implementation.)

Recommended test cases:

- Empty plaintext (MAC-only)
- 1-byte plaintext (minimal, single leaf)
- B-byte plaintext (exactly one chunk)
- B+1-byte plaintext (two chunks, minimal second)
- 4·B-byte plaintext (four full chunks, exercises 4-way SIMD)
- Single bit flip in each chunk position (tag verification failure)
- Chunk-swapped ciphertext (tag verification failure)
