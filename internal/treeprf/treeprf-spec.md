# TreePRF: A Tree-Parallel Pseudorandom Function

**Status:** Draft  
**Version:** 0.2  
**Date:** 2026-02-25  
**Security Target:** 128-bit

## 1. Introduction

TreePRF is a pseudorandom function that produces arbitrary-length output from a fixed-size seed, using a tree-parallel
topology based on KangarooTwelve to enable SIMD acceleration (NEON, AVX2, AVX-512) on large outputs.

TreePRF is a pure, deterministic function with no internal state.

## 2. Parameters

| Symbol | Value | Description                                  |
|--------|-------|----------------------------------------------|
| C      | 32    | Seed size (bytes); capacity of TurboSHAKE128 |
| B      | 8192  | Chunk size (bytes), matching KangarooTwelve  |

## 3. Dependency

**TurboSHAKE128(M, D, ℓ):** As specified in RFC 9861. Takes a message `M`, a domain separation byte `D` (0x01–0x7F), and
an output length `ℓ` in bytes.

## 4. Definition

**TreePRF(seed, length) → output**

*Inputs:*

- `seed`: A C-byte value.
- `length`: Requested output length in bytes (≥ 1).

*Output:*

- `output`: `length` pseudorandom bytes.

*Procedure:*

Partition the output into `n = ⌈length / B⌉` chunks. Chunk `i` (0-indexed) has size `ℓᵢ = min(B, length − i·B)`.

For each chunk `i`:  
&emsp; `output[i] ← TurboSHAKE128(seed ‖ [i]₆₄LE, 0x50, ℓᵢ)`

Return `output[0] ‖ output[1] ‖ ... ‖ output[n−1]`.

All chunk computations are independent and may execute in parallel.

### Notation

- `‖`: Byte string concatenation.
- `[i]₆₄LE`: The 8-byte little-endian encoding of integer `i`.

## 5. Security Considerations

### 5.1 PRF Security

TreePRF's security reduces to the PRF security of TurboSHAKE128. Each chunk is an independent TurboSHAKE128 evaluation
keyed by `seed` and domain-separated by `index`. An adversary who does not know the seed cannot distinguish any chunk's
output from random.

The 8-byte little-endian index supports up to 2^64 chunks (128 PiB of output at B = 8192), well beyond practical use.

### 5.2 Seed Confidentiality

The seed MUST be kept secret for PRF security. An attacker who learns the seed can reconstruct the full output for any
length. TreePRF provides no forward secrecy; seed lifecycle management is the caller's responsibility.

### 5.3 Side Channels

All chunks process the same seed. Implementations MUST ensure constant-time processing regardless of seed value.

## 6. Test Vectors

(To be generated from a reference implementation.)

Recommended test cases:

- `length = 1` (minimal, single chunk)
- `length = B` (exactly one chunk)
- `length = B + 1` (two chunks, minimal second)
- `length = 4·B` (four full chunks, exercises 4-way SIMD)
