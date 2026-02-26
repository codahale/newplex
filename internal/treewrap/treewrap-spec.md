# TreeWrap: Tree-Parallel Authenticated Encryption

**Status:** Draft  
**Version:** 0.1  
**Date:** 2026-02-25  
**Security Target:** 128-bit

## 1. Introduction

TreeWrap is an authenticated encryption algorithm that uses a tree-parallel topology based on KangarooTwelve to enable SIMD acceleration (NEON, AVX2, AVX-512) on large inputs. Each leaf operates as an independent SpongeWrap instance, and leaf chain values are accumulated into a single authentication tag via TurboSHAKE128.

TreeWrap is a pure function with no internal state. It is intended as a building block for duplex-based protocols, where key uniqueness and associated data are managed by the caller.

## 2. Parameters

| Symbol | Value | Description |
|--------|-------|-------------|
| f | Keccak-p[1600,12] | Underlying permutation (1600-bit state, 12 rounds) |
| R | 168 | Rate (bytes) |
| C | 32 | Capacity (bytes); key, chain value, and tag size |
| B | 8192 | Chunk size (bytes), matching KangarooTwelve |

## 3. Dependencies

**TurboSHAKE128(M, D, ℓ):** As specified in RFC 9861. Takes a message `M`, a domain separation byte `D` (0x01–0x7F), and an output length `ℓ` in bytes.

## 4. Leaf Sponge

A leaf sponge uses the same permutation and rate/capacity parameters as TurboSHAKE128 but operates in SpongeWrap mode. It uses domain separation byte `0x60` in place of TurboSHAKE128's caller-specified byte.

A leaf sponge consists of a 200-byte state `S`, initialized to all zeros, and a rate index `pos`, initialized to zero.

**`pad_permute()`:**  
&emsp; `S[pos] ^= 0x60`  
&emsp; `S[R-1] ^= 0x80`  
&emsp; `S ← f(S)`  
&emsp; `pos ← 0`

**init(key, index):**  
&emsp; For each byte of `key ‖ [index]₆₄LE`, XOR it into `S[pos]` and increment `pos`. When `pos` reaches R−1 and more input remains, call `pad_permute()`.  
&emsp; Call `pad_permute()`.

After `init`, the sponge has absorbed the key and index and is ready for SpongeWrap operations.

**encrypt(P) → C:** For each plaintext byte `Pⱼ`:  
&emsp; `Cⱼ ← Pⱼ ⊕ S[pos]`  
&emsp; `S[pos] ← Cⱼ`  
&emsp; Increment `pos`. When `pos` reaches R−1 and more plaintext remains, call `pad_permute()`.  
Return concatenated ciphertext bytes.

**decrypt(C) → P:** For each ciphertext byte `Cⱼ`:  
&emsp; `Pⱼ ← Cⱼ ⊕ S[pos]`  
&emsp; `S[pos] ← Cⱼ`  
&emsp; Increment `pos`. When `pos` reaches R−1 and more ciphertext remains, call `pad_permute()`.  
Return concatenated plaintext bytes.

**chain_value() → cv:**  
&emsp; Call `pad_permute()`.  
&emsp; Output C bytes: for each byte, output `S[pos]` and increment `pos`. When `pos` reaches R−1 and more output remains, call `pad_permute()`.

Note: `chain_value()` always begins with `pad_permute()` to ensure encrypted data is fully mixed before the chain value is derived.

## 5. TreeWrap

### Notation

- `‖`: Byte string concatenation.
- `[i]₆₄LE`: The 8-byte little-endian encoding of integer `i`.
- `length_encode(x)`: The encoding used by KangarooTwelve: `x` as a big-endian byte string with no leading zeros, followed by a single byte indicating the length of that byte string. `length_encode(0)` is `0x00`.

### 5.1 Seal

**TreeWrap.Seal(key, plaintext) → (ciphertext, tag)**

*Inputs:*
- `key`: A C-byte key. MUST be unique per invocation (see §6.1).
- `plaintext`: Plaintext of any length (may be empty).

*Outputs:*
- `ciphertext`: Same length as `plaintext`.
- `tag`: A C-byte authentication tag.

*Procedure:*

Partition `plaintext` into `n = max(1, ⌈len(plaintext) / B⌉)` chunks. Chunk `i` (0-indexed) has size `ℓᵢ = min(B, len(plaintext) − i·B)`. If plaintext is empty, `n = 1` and the single chunk is empty.

For each chunk `i`:  
&emsp; Create a leaf sponge `L`.  
&emsp; `L.init(key, i)`  
&emsp; `ciphertext[i] ← L.encrypt(plaintext_chunk[i])`  
&emsp; `cv[i] ← L.chain_value()`

Compute the tag using the KangarooTwelve final node structure:

&emsp; `final_input ← cv[0] ‖ 0x03 0x00 0x00 0x00 0x00 0x00 0x00 0x00`  
&emsp; `final_input ← final_input ‖ cv[1] ‖ ... ‖ cv[n−1]`  
&emsp; `final_input ← final_input ‖ length_encode(n−1)`  
&emsp; `final_input ← final_input ‖ 0xFF 0xFF`  
&emsp; `tag ← TurboSHAKE128(final_input, 0x61, C)`

When `n = 1`, the final input reduces to `cv[0] ‖ 0x03 0x00 0x00 0x00 0x00 0x00 0x00 0x00 ‖ length_encode(0) ‖ 0xFF 0xFF`.

Return `(ciphertext[0] ‖ ... ‖ ciphertext[n−1], tag)`.

All leaf operations are independent and may execute in parallel. Tag computation begins as soon as all chain values are available.

### 5.2 Open

**TreeWrap.Open(key, ciphertext, tag) → plaintext or ⊥**

*Procedure:*

Partition `ciphertext` into chunks identically to Seal.

For each chunk `i`:  
&emsp; Create a leaf sponge `L`.  
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

TreeWrap is a deterministic algorithm. Encrypting two different plaintexts with the same key produces ciphertext XOR differences equal to the plaintext XOR differences, fully compromising confidentiality. The key MUST be unique per invocation. When used within a duplex protocol, this is typically ensured by deriving the key from session state that includes a nonce or counter.

### 6.2 Ciphertext Integrity

Each leaf's chain value commits to the ciphertext it produced, since `encrypt` absorbs ciphertext into the sponge state and `chain_value` derives from the post-encryption state. The tag commits to all chain values via TurboSHAKE128.

Modifying any byte of ciphertext in any chunk changes that chunk's chain value, which changes the tag. An attacker must find a TurboSHAKE128 collision or second preimage on C-byte outputs (requiring 2^128 work) to forge a valid tag.

### 6.3 Chunk Reordering

Each leaf is initialized with `key ‖ [index]₆₄LE`, binding it to its position. Reordering ciphertext chunks changes which leaf decrypts which data, producing different chain values and a different tag. Chunk reordering is detected by tag verification.

Additionally, since leaf indices are bound at initialization, an attacker cannot cause chunk `i`'s ciphertext to be decrypted as chunk `j` — the decryption will produce garbage and the chain value will not match.

### 6.4 Plaintext Commitment

The tag commits to the plaintext indirectly: the chain value is a function of the sponge state after encrypting, which is a function of both the key and the plaintext. Two different plaintexts encrypted under the same key produce different sponge states and therefore different chain values. This provides plaintext commitment (key-dependent) without requiring a separate pass over the data.

### 6.5 Empty Plaintext

When plaintext is empty, a single leaf is still created. The chain value is derived from the sponge state after `init` (with a `pad_permute` but no encrypt calls). The final node input is `cv[0] ‖ 0x03 0x00 0x00 0x00 0x00 0x00 0x00 0x00 ‖ 0x00 ‖ 0xFF 0xFF`, producing a valid tag that authenticates the key. This ensures `TreeWrap.Open` with an empty ciphertext and valid tag succeeds, while any non-empty ciphertext with that tag fails.

### 6.6 Tag Accumulation

Chain values are accumulated using the KangarooTwelve final node structure: `cv[0]` is absorbed as the "first chunk" of the final node, followed by the 8-byte marker `0x03 0x00...`, then chain values `cv[1]` through `cv[n−1]` as "leaf" contributions, followed by `length_encode(n−1)` and the terminator `0xFF 0xFF`. This is processed by TurboSHAKE128 with domain separation byte `0x61`, separating TreeWrap tag computation from both KT128 hashing (`0x07`) and TreeWrap leaf sponges (`0x60`).

The structure is unambiguous: chain values are fixed-size (C bytes each), `length_encode` encodes the number of leaf chain values, and the terminator marks the end. The number of chunks is determined by the ciphertext length, which is assumed to be public.

### 6.7 Side Channels

All leaves process the same key. Implementations MUST ensure constant-time processing regardless of key and plaintext values. The chunk index is not secret and does not require side-channel protection.

### 6.8 Reduced-Round Margin

The security argument from KangarooTwelve extends to TreeWrap. Each leaf applies Keccak-p[1600,12] multiple times per chunk, and the tag accumulation applies it again via TurboSHAKE128. An attack on the construction requires breaking either an individual leaf's SpongeWrap security or the tag accumulation, which are independent attack surfaces composed in series.

## 7. Test Vectors

(To be generated from a reference implementation.)

Recommended test cases:
- Empty plaintext (MAC-only)
- 1-byte plaintext (minimal, single leaf)
- B-byte plaintext (exactly one chunk)
- B+1-byte plaintext (two chunks, minimal second)
- 4·B-byte plaintext (four full chunks, exercises 4-way SIMD)
- Single bit flip in each chunk position (tag verification failure)
- Chunk-swapped ciphertext (tag verification failure)
