# The Design Of Newplex

<!-- TOC -->
* [The Design Of Newplex](#the-design-of-newplex)
  * [What is Newplex?](#what-is-newplex)
    * [What's The Point?](#whats-the-point)
  * [The Permutation](#the-permutation)
  * [The Duplex](#the-duplex)
    * [`Permute`](#permute)
    * [`Absorb`](#absorb)
    * [`BeginOp`](#beginop)
    * [`Squeeze`](#squeeze)
    * [`Ratchet`](#ratchet)
    * [`Encrypt`/`Decrypt`](#encryptdecrypt)
  * [The Protocol](#the-protocol)
    * [`Init`](#init)
    * [`Mix`](#mix)
    * [`Derive`](#derive)
      * [KDF Security](#kdf-security)
      * [KDF Chains](#kdf-chains)
    * [`Mask`/`Unmask`](#maskunmask)
    * [`Seal`/`Open`](#sealopen)
    * [`Clone`](#clone)
  * [Basic Schemes](#basic-schemes)
    * [Message Digest](#message-digest)
    * [Message Authentication Code](#message-authentication-code)
    * [Stream Cipher](#stream-cipher)
    * [Authenticated Encryption with Associated Data (AEAD)](#authenticated-encryption-with-associated-data-aead)
    * [Deterministic Authenticated Encryption](#deterministic-authenticated-encryption)
  * [Complex Schemes](#complex-schemes)
    * [Streaming Authenticated Encryption](#streaming-authenticated-encryption)
      * [Dual Ratchet](#dual-ratchet)
      * [Bidirectional Streaming](#bidirectional-streaming)
    * [Mutually Authenticated Handshake](#mutually-authenticated-handshake)
    * [Asynchronous Double Ratchet](#asynchronous-double-ratchet)
    * [Hybrid Public-Key Encryption](#hybrid-public-key-encryption)
    * [Digital Signatures](#digital-signatures)
    * [Signcryption](#signcryption)
    * [Verifiable Random Function](#verifiable-random-function)
    * [Password-Authenticated Key Exchange](#password-authenticated-key-exchange)
<!-- TOC -->

## What is Newplex?

Newplex provides an incremental, stateful cryptographic primitive for symmetric-key cryptographic operations (e.g.,
hashing, encryption, message authentication codes, and authenticated encryption) in complex schemes. Inspired
by [TupleHash], [STROBE], [Noise Protocol]'s stateful objects, [Merlin] transcripts, [DuplexWrap], and [Xoodyak]'s
Cyclist mode, Newplex uses the [Simpira-1024] permutation to provide 10+ Gb/second performance on modern processors at a
128-bit security level.

[TupleHash]: https://www.nist.gov/publications/sha-3-derived-functions-cshake-kmac-tuplehash-and-parallelhash

[STROBE]: https://strobe.sourceforge.io

[Noise Protocol]: http://www.noiseprotocol.org

[Merlin]: https://merlin.cool

[DuplexWrap]: https://competitions.cr.yp.to/round1/keyakv1.pdf

[Xoodyak]: https://keccak.team/xoodyak.html

[Simpira-1024]: https://eprint.iacr.org/2016/122.pdf

### What's The Point?

There are two major benefits to using an approach like Newplex to implement a cryptographic scheme or protocol:

1. **Simplicity.** Instead of having to select a set of primitives (e.g., hash functions, KDFs, AEADs, polynomial MACs,
   etc.), figure out the various requirements and restrictions of each, and carefully connect them together to ensure
   none are being misused, Newplex provides a single primitive with a core set of distinct operations.
2. **Soundness.** Newplex has cryptographic practices like domain separation built-in, and the fact that a Newplex
   protocol is stateful establishes a clear forward flow of data within a scheme. This eliminates vulnerabilities in
   which output values don't depend on the full set of inputs (e.g., [MQV], [HMQV], and many [Fiat-Shamir] transforms).

[MQV]: https://dl.acm.org/doi/10.1145/501978.501981

[HMQV]: https://eprint.iacr.org/2010/136.pdf

[Fiat-Shamir]: https://blog.trailofbits.com/2022/04/13/part-1-coordinated-disclosure-of-vulnerabilities-affecting-girault-bulletproofs-and-plonk/

## The Permutation

[Simpira-1024] was chosen as the core of Newplex for a number of reasons:

1. The designers claim security against structural distinguishers with complexity up to 2^128, which aligns with the
   security level goals of this project.

2. It has a width of 1024 bits, allowing for a duplex with a 256-bit capacity to have 768 bits of rate. This
   significantly improves throughput without increasing the latency on small inputs.

3. It benefits from the nearly ubiquitous AES-NI instruction set, making it equally performant on both AMD64 and ARM64
   architectures. The only faster permutation on modern ARM64 processors is Keccak-p\[1600,24\], which benefits from the
   `FEAT_SHA3` extensions, but no such instruction set exists for AMD64 processors. Further, Simpira-1024 allows for up
   to 8 pipelined `AESENC` instructions, maximizing throughput on modern processors.

4. In the ten years since the publication of [Simpira V2][Simpira-1024], the main cryptanalytical results on it have
   been on round-reduced versions of the smaller permutations:

   | Variant            | Total Rounds | Max Rounds Attacked | % Rounds Broken | Security Margin       |
   |--------------------|--------------|---------------------|-----------------|-----------------------|
   | Simpira-256 (b=2)  | 15           | 9                   | 60%             | Safe (6 rounds left)  |
   | Simpira-384 (b=3)  | 21           | 10                  | 48%             | Safe (11 rounds left) |
   | Simpira-512 (b=4)  | 15           | 8                   | 53%             | Safe (7 rounds left)  |
   | Simpira-768 (b=6)  | 15           | 8                   | 53%             | Safe (7 rounds left)  |
   | Simpira-1024 (b=8) | 18           | 0                   | 0%              | Safe (18 rounds left) |

   No attacks have been found on the full-round specifications, and no attacks at all have been found for Simpira-1024.
   It should be noted that Simpira-1024 has not received the same degree of scrutiny as the smaller Simpira variants.
   This design would accommodate Keccak-f\[1600\] for contexts which require a higher security margin or where
   Keccak-f\[1600\] or Keccak-p\[1600,12\] would yield better performance (e.g., ARM64 processors with `FEAT_SHA3`
   instructions or low-powered processors without `AES-NI` instructions).

5. Its non-linear component is the AES round, which has been extensively studied, and its shuffling layer achieves full
   diffusion after very few rounds.

## The Duplex

The core of Newplex is a relatively basic [cryptographic duplex][duplex], with a width of 1024 bits, a capacity of 256
bits, 16 bits of padding, and an effective rate of 752 bits (i.e. `B=1024`, `C=256`, `P=16` `R=752`).

[duplex]: https://keccak.team/sponge_duplex.html

This provides the following security levels:

| Security Metric      | Level (Bits) | Formula | Condition        |
|----------------------|--------------|---------|------------------|
| Collision Resistance | 128          | `c/2`   | public/hash mode |
| State/Key Recovery   | 256          | `c`     | (assuming K≥256) |
| Indistinguishability | 128          | `c/2`   | birthday bound   |

The duplex provides a small number of operations: `Permute`, `Absorb`, `BeginOp`, `Squeeze`, `Ratchet`, and `Encrypt`/
`Decrypt`. It reserves two bytes of the rate for padding, so inputs and outputs are processed in blocks of at most 752
bits.

The duplex is initialized with a 1024-bit state, a position index `pos` which is always in the range `[0, R)`, and an
operation position index `posBegin`, all of which begin with zero values.

### `Permute`

The `Permute` operation absorbs the `posBegin` index, pads the rate with SHA-3's `pad10*1` scheme, runs
the [Simpira-1024] permutation, and resets both position indexes:

```text
function Permute():
  state[pos] ^= posBegin
  state[pos+1] ^= 0x01
  state[R+1] ^= 0x80
  Simpira1024(state)
  pos = posBegin = 0
```

### `Absorb`

The `Absorb` operation XORs the duplex's remaining rate with the input in blocks of up to 752 bits. When the duplex's
rate is exhausted, it calls `Permute`.

**N.B.:** `Absorb` does not call `Permute` at the end of the operation, therefore a sequence of `Absorb` operations are
equivalent to a single `Absorb` operation with the concatenation of the sequence's inputs (e.g.
`Absorb('A'); Absorb('B')` is equivalent to `Absorb('AB')`).

### `BeginOp`

The `BeginOp` operation absorbs the `posBegin` index, sets `posBegin` to the current position, and absorbs an operation
code:

```text
function BeginOp(op):
  v = posBegin
  posBegin = pos + 1
  Absorb(v)
  Absorb(op)
```

This technique, borrowed from the [STROBE] framework, allows for variable-length inputs without delimiters or length
encodings. Absorbing the position of the previous operation into the duplex's state eliminates collisions within a
single block, and the `Permute` function carries the `posBegin` value into the next block.

### `Squeeze`

The `Squeeze` operation returns the duplex's remaining rate in blocks of up to 752 bits. When the duplex's rate is
exhausted, it calls `Permute`.

**N.B.:** `Squeeze` does not call `Permute` at the end of the operation, therefore a sequence of `Squeeze` operations
are equivalent to a single `Squeeze` operation with the concatenation of the sequence's outputs (e.g.
`Squeeze(10); Squeeze(6)` is equivalent to `Squeeze(16)`).

### `Ratchet`

The `Ratchet` operation calls `Permute` if any of the rate has been used, then overwrites the first 256 bits of the
duplex's rate with zeros, and advances the rate position past them. This irreversibly modifies the duplex's state,
preventing potential rollback attacks and establishing forward secrecy. An attacker who recovers the post-ratchet state
will be unable to reconstruct the missing 256 bits and thus unable to invert the permutation to recover prior states.

### `Encrypt`/`Decrypt`

The `Encrypt` operation XORs the duplex's remaining rate with the input in blocks of up to 752 bits, returning the
result as the ciphertext. When the duplex's rate is exhausted, it calls `Permute`.

The `Decrypt` operation XORs the ciphertext with the duplex's remaining rate in blocks of up to 752 bits, returning the
result as the plaintext. It then replaces the duplex's rate with the ciphertext. When the duplex's rate is exhausted, it
calls `Permute`.

This is functionally the same as the [DuplexWrap] construction, combining an `Absorb` operation of the plaintext with a
`Squeeze` operation for a keystream.

**N.B.:** Neither `Encrypt` nor `Decrypt` call `Permute` at the end of the operation, therefore a sequence of `Encrypt`
operations are equivalent to a single `Encrypt` operation with the concatenation of the sequence's outputs (e.g.
`Encrypt('A'); Encrypt('B')` is equivalent to `Encrypt('AB')`).

## The Protocol

The interface of Newplex is the protocol, which encapsulates a duplex, providing domain separation and higher-level
operations with clear boundaries.

A protocol supports the following operations:

* `Init`: Initialize a protocol with a domain separation string.
* `Mix`: Mix a labeled input into the protocol's state, making all future outputs cryptographically dependent on it.
* `Derive`: Generate a pseudo-random bitstring of arbitrary length that is cryptographically dependent on the protocol's
  state.
* `Mask`/`Unmask`: Encrypt and decrypt a message with no authenticity protection, using the protocol's current state as
  a key.
* `Seal`/`Open`: Encrypt and decrypt a message, using an authenticator tag to ensure the ciphertext has not been
  modified.
* `Clone`: Create a copy of the protocol's current state.

Labels are used for all protocol operations (except `Init`) to provide domain separation of inputs and outputs. This
ensures that semantically distinct values with identical encodings (e.g., public keys or ECDH shared secrets) result in
distinctly encoded operations as long as the labels are distinct. Labels should be human-readable values that
communicate the source of the input or the intended use of the output. The label `server-r255-public-key` is good;
`step-3a` is a bad label.

### `Init`

An `Init` operation initializes a new, all-zero duplex, segments it with an initialization operation code, and absorbs a
domain separation string.

```text
function Init(domain):
  duplex.BeginOp(op=0x01)
  duplex.Absorb(domain)
``` 

The `Init` operation is only performed once, when a protocol is initialized.

The BLAKE3 recommendations for KDF context strings apply equally to Newplex protocol domains:

> The context string should be hardcoded, globally unique, and application-specific. … The context string should not
> contain variable data, like salts, IDs, or the current time. (If needed, those can be part of the key material, or
> mixed with the derived key afterwards.) … The purpose of this requirement is to ensure that there is no way for an
> attacker in any scenario to cause two different applications or components to inadvertently use the same context
> string. The safest way to guarantee this is to prevent the context string from including input of any kind.

### `Mix`

A `Mix` operation accepts a label and an input and makes the protocol's state (and all future output) cryptographically
dependent on them.

```text
function Mix(label, input):
  duplex.BeginOp(op=0x02)
  duplex.Absorb(label)
  duplex.BeginOp(op=0x02|0x80)
  duplex.Absorb(input)
```

`Mix` structures the operation as two sub-operations: one for the operation label, another for the operation input. To
distinguish between the two, the operation code of the first sub-operation has its low bit cleared; the second has its
high bit set.

### `Derive`

A `Derive` operation accepts a label and an output length and returns pseudorandom data derived from the protocol's
state, the label, and the output length.

```text
function Derive(label, n):
  duplex.BeginOp(op=0x03)
  duplex.Absorb(label)
  duplex.BeginOp(op=0x03|0x80)
  duplex.Absorb(LEB128(n))
  duplex.Permute()
  prf = duplex.Squeeze(n)
  duplex.Ratchet()
  return prf
```

Like `Mix`, `Derive` is structured as two sub-operations with distinct operation codes. The first absorbs the label, the
second absorbs the length `n`, encoded with LEB128. To ensure the duplex's state is indistinguishable from random, it
permutes the duplex and squeezes the requested output from the duplex. Finally, the duplex's state is ratcheted to
prevent rollback.

**N.B.:** A `Derive` operation's output depends on both the label and the output length.

#### KDF Security

A sequence of `Mix` operations followed by an operation which produces output (e.g., `Derive`, `Mask`, `Seal`, etc.)
is equivalent to constructing a string using a recoverable encoding, absorbing it into a duplex, then squeezing an
output string. [As long as the Simpira-1024 permutation is indistinguishable from a random permutation, the duplex is
indistinguishable from a random oracle.][duplex security] Therefore, the `Absorb`/`Permute`/`Squeeze` sequence maps
directly to [Backendal et al.'s RO-KDF construction][n-KDFs] and is a KDF-secure XOF-n-KDF (for 0 < ℓ <= 16).

[n-KDFs]: https://eprint.iacr.org/2025/657.pdf

[duplex security]: https://eprint.iacr.org/2022/1340.pdf

#### KDF Chains

Given that `Derive` is KDF-secure with respect to the protocol's state and replaces the protocol's state with
KDF-derived output, sequences of operations which accept input and output in a protocol form a [KDF chain].
Consequently, Newplex protocols have the following security properties:

[KDF chain]: https://signal.org/docs/specifications/doubleratchet/doubleratchet.pdf

* **Resilience**: A protocol's outputs will appear random to an adversary as long as one of the inputs is secret, even
  if the other inputs to the protocol are adversary-controlled.
* **Forward Security**: A protocol's previous outputs will appear random to an adversary even if the protocol's state is
  disclosed at some point.
* **Break-in Recovery**: A protocol's future outputs will appear random to an adversary in possession of the protocol's
  state as long as one of the future inputs to the protocol is secret.

### `Mask`/`Unmask`

The `Mask` and `Unmask` operations accept a label and an input and encrypt or decrypt them using the protocol's
state and the label.

```text
function Mask(label, plaintext):
  duplex.BeginOp(op=0x04)
  duplex.Absorb(label)
  duplex.BeginOp(op=0x04|0x80)
  duplex.Permute()
  ciphertext = duplex.Encrypt(plaintext)
  duplex.Ratchet()
  return ciphertext
  
function Unmask(label, ciphertext):
  duplex.BeginOp(op=0x04)
  duplex.Absorb(label)
  duplex.BeginOp(op=0x04|0x80)
  duplex.Permute()
  plaintext = duplex.Decrypt(ciphertext)
  duplex.Ratchet()
  return plaintext
```

`Mask` absorbs the label in a sub-operation, begins a second sub-operation, then permutes the duplex's state to ensure
indistinguishability. It then encrypts the plaintext with the duplex's state. Finally, it ratchets the duplex's state to
prevent rollback. The `pad10*1` scheme in [`Permute`](#permute) ensures that the resulting state is dependent on the
plaintext's length once the operation has concluded.

`Unmask` is identical but uses the duplex to decrypt the data.

Three points bear mentioning about `Mask` and `Unmask`:

1. Unlike `Derive`, the output of an `Mask` operation does not depend on its input length, therefore `Mask('A')` and
   `Mask('AB')` will share a prefix. This allows for fully streaming operations, but usages which require the ciphertext
   to depend on the plaintext length must include that as the input to a prior `Mix` operation.
2. `Mask` operations offer EAV security (i.e., an entirely passive adversary will not be able to read plaintexts).
   IND-CPA security (i.e., an adversary with an encryption oracle) requires a prior `Mix` operation to include a value
   unique to the plaintext, like a nonce or a message ID.
3. `Mask` operations provide no authentication by themselves. An attacker can modify a ciphertext and the `Unmask`
   operation will return a plaintext which was never encrypted.

   That said, the divergent ciphertext input will result in divergent protocol state, as the protocol's state after an
   `Mask`/`Unmask` operation is cryptographically dependent on the plaintext of the operation.

   For IND-CCA security, use [`Seal`/`Open`](#sealopen).

### `Seal`/`Open`

`Seal` and `Open` operations extend the `Mask` and `Unmask` operations with the inclusion of a 16-byte
authentication tag. The `Open` operation verifies the tag, returning an error if the tag is invalid.

```text
function Seal(label, plaintext):
  duplex.BeginOp(op=0x05)
  duplex.Absorb(label)
  duplex.BeginOp(op=0x05|0x80)
  duplex.Absorb(LEB128(|plaintext|))
  duplex.Permute()
  ciphertext = duplex.Encrypt(plaintext)
  duplex.Permute()
  tag = duplex.Squeeze(16)
  duplex.Ratchet()
  return ciphertext || tag
  
function Open(label, ciphertext || tag):
  duplex.BeginOp(op=0x05)
  duplex.Absorb(label)
  duplex.BeginOp(op=0x05|0x80)
  duplex.Absorb(LEB128(|ciphertext|))
  duplex.Permute()
  plaintext = duplex.Decrypt(ciphertext)
  duplex.Permute()
  tag' = duplex.Squeeze(16)
  duplex.Ratchet()
  if tag != tag':
    return ErrInvalidCiphertext
  return plaintext
```

`Seal` absorbs the label in a sub-operation, begins a second sub-operation, absorbs the LEB128-encoded plaintext length,
then permutes the duplex's state to ensure indistinguishability. It then encrypts the plaintext with the duplex's state
and permutes the duplex's state again to make it fully dependent on the plaintext. Finally, it squeezes a 16-byte tag
and ratchets the duplex's state to prevent rollback.

`Open` is identical but uses the duplex to decrypt the data and compares the received tag to an expected tag derived
from the received plaintext. If the two are equal (using a constant-time comparison function), the plaintext is
returned. Otherwise, an error is returned.

`Seal` and `Open` provide IND-CCA2 security if one of the protocol's inputs includes a probabilistic value, like a
nonce.

**N.B.:** An attacker presenting a modified ciphertext will, as part of the duplex's `Decrypt` operation, be able to
insert data into the duplex's rate. This does not present a security problem, as the duplex's capacity remains
inaccessible. Any attack that successfully biases the duplex's state post-permutation would completely invalidate all
of [Simpira-1024]'s security claims.

**N.B.:** A modified ciphertext will result in the protocol having an entirely different state after an `Open`
operation. All future operations will result in different outputs and the inability to decrypt or open ciphertexts. This
is intentional. Because an active attacker is unable to control the duplex's post-permutation state, this does not
present an avenue for influence.

**N.B.:** Unlike `Mask`, `Seal` does not support streaming operations. This is an intentional choice to mitigate the
accidental disclosure of unauthenticated plaintext and follows the generally recommended practices for API design of
authenticated encryption. See the [Streaming Authenticated Encryption](#streaming-authenticated-encryption) scheme for
details on how to handle streaming data.

### `Clone`

The `Clone` operation returns a copy of the protocol's current state. This allows for the creation of divergent protocol
states from a common ancestor (e.g., for [forking a protocol](#bidirectional-streaming) or [deterministic
encryption](#deterministic-authenticated-encryption)).

## Basic Schemes

By combining operations, we can implement a wide variety of cryptographic schemes using a protocol.

### Message Digest

Calculating a message digest is as simple as a `Mix` and a `Derive`:

```text
function MessageDigest(message):
  protocol.Init("com.example.md")        // Initialize a protocol with a domain string.
  protocol.Mix("message", message)       // Mix the message into the protocol.
  digest = protocol.Derive("digest", 32) // Derive 32 bytes of output and return it.
  return digest
```

This scheme is indistinguishable from a random oracle if Simpira-1024 is indistinguishable from a random permutation.

### Message Authentication Code

Adding a key to the previous scheme makes it a MAC:

```text
function MAC(key, message):
  protocol.Init("com.example.mac") // Initialize a protocol with a domain string.
  protocol.Mix("key", key)         // Mix the key into the protocol.
  protocol.Mix("message", message) // Mix the message into the protocol.
  tag = protocol.Derive("tag", 16) // Derive 16 bytes of output and return it.
  return tag
```

The use of labels and the encoding of [`Mix` inputs](#mix) ensures that the key and the message will never overlap, even
if their lengths vary.

This scheme is sUF-CMA secure if Simpira-1024 is indistinguishable from a random permutation.

### Stream Cipher

A protocol can be used to create a stream cipher:

```text
function StreamEncrypt(key, nonce, plaintext):
  protocol.Init("com.example.stream")              // Initialize a protocol with a domain string.
  protocol.Mix("key", key)                         // Mix the key into the protocol.
  protocol.Mix("nonce", nonce)                     // Mix the nonce into the protocol.
  ciphertext = protocol.Mask("message", plaintext) // Encrypt the plaintext.
  return ciphertext

function StreamDecrypt(key, nonce, ciphertext):
  protocol.Init("com.example.stream")                // Initialize a protocol with a domain string.
  protocol.Mix("key", key)                           // Mix the key into the protocol.
  protocol.Mix("nonce", nonce)                       // Mix the nonce into the protocol.
  plaintext = protocol.Unmask("message", ciphertext) // Decrypt the ciphertext.
  return plaintext
```

This scheme is IND-CPA-secure under the following assumptions:

1. Simpira-1024 is indistinguishable from a random permutation.
2. At least one of the inputs to the protocol is a nonce (i.e., not used for multiple messages).

### Authenticated Encryption with Associated Data (AEAD)

A protocol can be used to create an AEAD:

```text
function AEADSeal(key, nonce, ad, plaintext):
  protocol.Init("com.example.aead")                       // Initialize a protocol with a domain string.
  protocol.Mix("key", key)                                // Mix the key into the protocol.
  protocol.Mix("nonce", nonce)                            // Mix the nonce into the protocol.
  protocol.Mix("ad", ad)                                  // Mix the associated data into the protocol.
  ciphertext || tag = protocol.Seal("message", plaintext) // Seal the plaintext.
  return ciphertext || tag
```

The introduction of a nonce makes the scheme probabilistic (which is required for IND-CCA security).

Unlike many standard AEADs (e.g., AES-GCM and ChaCha20Poly1305), it is fully context-committing: the tag is a strong
cryptographic commitment to all the inputs.

Also, unlike a standard AEAD, this can be easily extended to allow for multiple, independent pieces of associated data
without the risk of ambiguous inputs.

```text
function AEADOpen(key, nonce, ad, ciphertext || tag):
  protocol.Init("com.example.aead")                       // Initialize a protocol with a domain string.
  protocol.Mix("key", key)                                // Mix the key into the protocol.
  protocol.Mix("nonce", nonce)                            // Mix the nonce into the protocol.
  protocol.Mix("ad", ad)                                  // Mix the associated data into the protocol.
  plaintext = protocol.Open("message", ciphertext || tag) // Open the ciphertext.
  return plaintext                                        // Return the plaintext or an error.
```

This scheme is IND-CCA2-secure (i.e., both IND-CPA and INT-CTXT) under the following assumptions:

1. Simpira-1024 is indistinguishable from a random permutation.
2. At least one of the inputs to the protocol is a nonce (i.e., not used for multiple messages).

### Deterministic Authenticated Encryption

A protocol can be used to implement an SIV-style deterministic authenticated encryption scheme:

```text
function SIVSeal(key, nonce, ad, plaintext):
  protocol.Init("com.example.siv")                 // Initialize a protocol with a domain string.
  protocol.Mix("key", key)                         // Mix the key into the protocol.
  protocol.Mix("nonce", nonce)                     // Mix the nonce into the protocol.
  protocol.Mix("ad", ad)                           // Mix the associated data into the protocol.
  clone = protocol.Clone()                         // Clone the protocol.
  clone.Mix("message", plaintext)                  // Mix the plaintext into the clone.
  tag = clone.Derive("tag", 16)                    // Use the clone to derive a tag.
  protocol.Mix("tag", tag)                         // Mix the tag into the main protocol.
  ciphertext = protocol.Mask("message", plaintext) // Mask the plaintext.
  return ciphertext || tag
```

```text
function SIVOpen(key, nonce, ad, ciphertext || tag):
  protocol.Init("com.example.siv")                   // Initialize a protocol with a domain string.
  protocol.Mix("key", key)                           // Mix the key into the protocol.
  protocol.Mix("nonce", nonce)                       // Mix the nonce into the protocol.
  protocol.Mix("ad", ad)                             // Mix the associated data into the protocol.
  clone = protocol.Clone()                           // Clone the protocol to use later for tag verification.
  protocol.Mix("tag", tag)                           // Mix the received tag into the main protocol.
  plaintext = protocol.Unmask("message", ciphertext) // Unmask the protocol.
  clone.Mix("message", plaintext)                    // Mix the unmasked, unauthenticated plaintext into the clone.
  tag' = clone.Derive("tag", 16)                     // Derive an expected tag from the clone.
  if tag != tag':                                    // If the tags don't match, return an error. Otherwise, the plaintext.
    return ErrInvalidCiphertext
  return plaintext
```

This uses a two-pass approach to deterministic encryption and provides both nonce-misuse resistance (mrAE) and
deterministic authenticated encryption (DAE) without a nonce.

## Complex Schemes

### Streaming Authenticated Encryption

For streams of indeterminate length, authenticated encryption can be provided via a sequence of `Seal` calls. Each block
is limited to `2^24-1` bytes.

```text
function AEStreamSend(key, nonce, plaintext, ciphertext):
  protocol.Init("com.example.aestream")        // Establish a shared protocol state.
  protocol.Mix("key", key)
  protocol.Mix("nonce", nonce)
  while |plaintext| > 0:
    pblock = Read(plaintext)                   // Read a block of plaintext.
    pheader = BEU24(|pblock|)                  // Encode the block length as a 3-byte unsigned big endian integer.
    cheader = protocol.Seal("header", pheader) // Seal the header.
    cblock = protocol.Seal("block", pblock)    // Seal the block.
    Write(ciphertext, cheader || cblock)       // Write the sealed header and sealed block.
  pheader = BEU24(0)                           // Encode a zero-length block header.
  cheader = protocol.Seal("header", pheader)   // Seal the header.
  cblock = protocol.Seal("block", "")          // Seal a zero-length block.
  Write(ciphertext, cheader || cblock)         // Write the sealed header and sealed block.


function AEStreamRecv(key, nonce, ciphertext, plaintext):
  protocol.Init("com.example.aestream")
  protocol.Mix("key", key)
  protocol.Mix("nonce", nonce)
  while |ciphertext| > 0:
    cheader = Read(ciphertext, 3+16)           // Read a sealed 3-byte header and 16-byte tag.
    pheader = protocol.Open("header", cheader) // Open the sealed header.
    if pheader == ErrInvalidCiphertext:        // Error if the header is not authenticated.
      return ErrInvalidCiphertext
    msglen = BEU24(pheader)                    // Decode the block length.
    cblock = Read(ciphertext, msglen+16)       // Read the sealed block and 16-byte tag.
    pblock = protocol.Open("block", cblock)    // Open the sealed block.
    if pblock == ErrInvalidCiphertext:         // Error if the ciphertext is not authenticated.
      return ErrInvalidCiphertext
    if |pblock| == 0:                          // Return an EOF if the block is empty.
      return EOF
    Write(plaintext, pblock)                   // Otherwise, write the plaintext block.
  return ErrInvalidCiphertext                  // Error if the stream is truncated.
```

The sender encodes each block's length as a 3-byte big endian integer, seals that header, seals the block, and sends
both to the receiver. An empty block is used to mark the end of the stream. The receiver reads the encrypted header,
decrypts it, decodes it into a block length, reads an encrypted block of that length and its authentication tag, then
opens the sealed block. When it encounters the empty block, it returns EOF. If the stream terminates before that, an
invalid ciphertext error is returned.

#### Dual Ratchet

This scheme can be augmented with a public key ratchet by including a ratchet key with each header/block.

When sending:

```text
...
  while |plaintext| > 0:
    pblock = Read(plaintext)                   // Read a block of plaintext.
    pheader = BEU24(|pblock|)                  // Encode the block length as a 3-byte unsigned big endian integer.
    cheader = protocol.Seal("header", pheader) // Seal the header.
    dE = R255::ReduceScalar(rand(64))          // Generate an ephemeral Ristretto255 key pair.
    qE = [dE]G
    cratchet = protocol.Seal("ratchet", qE)    // Seal the ratchet key.
    protocol.Mix("ratchet-key", [dE]qS)        // Mix the shared secret into the protocol.
    cblock = protocol.Seal("block", pblock)    // Seal the block.
    Write(ciphertext, cheader || cblock)       // Write the sealed header and sealed block.
...
```

When receiving:

```text
...
  while |ciphertext| > 0:
    cheader = Read(ciphertext, 3+16)           // Read a sealed 3-byte header and 16-byte tag.
    pheader = protocol.Open("header", cheader) // Open the sealed header.
    if pheader == ErrInvalidCiphertext:        // Error if the header is not authenticated.
      return ErrInvalidCiphertext
    cratchet = Read(ciphertext, 32+16)         // Read a sealed ephemeral public key.
    qE = protocol.Open("ratchet", cratchet)    // Open and decode the ephemeral public key.
    if qE == ErrInvalidCiphertext:
      return ErrInvalidCiphertext
    protocol.Mix("ratchet-key", [dR]qE)        // Mix the shared secret into the protocol.
...
```

#### Bidirectional Streaming

For bidirectional communication, the sender and receiver should establish a shared protocol state (e.g., via ECDH key
agreement), then clone that protocol into two unidirectional protocols.

```text
// On the initiator's side:
send, recv = handshake.Clone(), handshake.Clone()
send.Mix("sender", "initiator")
recv.Mix("sender", "responder")

// On the responder's side:
send, recv = handshake.Clone(), handshake.Clone()
send.Mix("sender", "responder")
recv.Mix("sender", "initiator")
```

This ensures the protocols being used to send and receive data have different states and therefore different outputs.
For a concrete example, see the [Mutually Authenticated Handshake](#mutually-authenticated-handshake) scheme.

### Mutually Authenticated Handshake

Given an elliptic curve group like [Ristretto255], a protocol can be used to build more complex schemes which integrate
public- and symmetric-key operations.

[Ristretto255]: https://www.rfc-editor.org/rfc/rfc9496.html

A protocol can be used to implement a mutually-authenticated, forward-secure handshake with key-compromise impersonation
resistance (equivalent to the `XX` pattern in the [Noise Protocol Framework][Noise Protocol]):

```text
function HandshakeInitiator(initiator):
  iE = R255::KeyGen()                                 // Generate an ephemeral key pair.
  protocol.Init("com.example.handshake")              // Initialize the protocol.
  protocol.Mix("ie", iE.pub)                          // Mix the ephemeral public key into the protocol.
  Send(iE.pub)                                        // Send the ephemeral public key.
  
  response = Receive()                                // Receive the responder's message.
  rE.pub = R255::Element(response[:32])               // Decode the responder's ephemeral public key.
  protocol.Mix("re", rE.pub)                          // Mix the responder's ephemeral public key.
  protocol.Mix("ie-re", ECDH(rE.pub, iE.priv))        // Mix the ephemeral-ephemeral shared secret.
  rS.pub = protocol.Open("rs", response[32:])         // Open the responder's static public key.
  protocol.Mix("ie-rs", ECDH(rS.pub, iE.priv))        // Mix the ephemeral-static shared secret.
  confirmation = protocol.Seal("is", initiator.pub)   // Seal the initiator's static public key.
  Send(confirmation)                                  // Send the sealed static public key.
  
  protocol.Mix("is-re", ECDH(rE.pub, initiator.priv)) // Mix the static-ephemeral shared secret.
  send, recv = protocol.Clone(), protocol.Clone()     // Fork the protocol.
  send.Mix("sender", "initiator")                     // Mix the sender role.
  recv.Mix("sender", "responder")                     // Mix the sender role.
  return (send, recv, rS.pub)
```

```text
function HandshakeResponder(domain, responder):
  request = Receive()                                     // Receive the initiator's request.
  rE = R255::KeyGen()                                     // Generate an ephemeral key pair.
  iE.pub = R255::Element(request)                         // Decode the initiator's ephemeral public key.
  protocol.Init("com.example.handshake")                  // Initialize the protocol.
  protocol.Mix("ie", iE.pub)                              // Mix the ephemeral public key into the protocol.
  protocol.Mix("re", rE.pub)                              // Mix the responder's ephemeral public key.
  protocol.Mix("ie-re", ECDH(iE.pub, rE.priv))            // Mix the ephemeral-ephemeral shared secret.
  response = rE.pub || protocol.Seal("rs", responder.pub) // Seal the responder's static public key.
  Send(response)                                          // Send the ephemeral key and sealed static key.
  
  confirmation = Receive()                                // Receive the initiator's sealed static key.
  protocol.Mix("ie-rs", ECDH(iE.pub, responder.priv))     // Mix the ephemeral-static shared secret.
  iS.pub = protocol.Open("is", confirmation)              // Open the initiator's static public key.
  protocol.Mix("is-re", ECDH(iS.pub, rE.priv))            // Mix the static-ephemeral shared secret.
  send, recv = protocol.Clone(), protocol.Clone()         // Fork the protocol.
  send.Mix("sender", "responder")                         // Mix the sender roles.
  recv.Mix("sender", "initiator")                         // Mix the sender role.
  return (send, recv, iS.pub)
```

### Asynchronous Double Ratchet

A protocol can be used to implement an asynchronous double ratchet, similar to the Signal Protocol's [double ratchet],
but using Newplex's stateful nature for the symmetric ratchet. Bidirectional protocols (e.g., `send`, `recv`) can be
established [by forking a shared state protocol](#bidirectional-streaming).

```text
function RatchetSend(send, remote.pub, plaintext):
  ephemeral = R255::KeyGen()                               // Generate an ephemeral key pair.
  ciphertext = send.Mask("ratchet-pk", ephemeral.pub)      // Mask the ephemeral public key.
  send.Mix("ratchet-ss", ECDH(remote.pub, ephemeral.priv)) // Mix the shared secret into the protocol.
  return send.Seal("message", ciphertext, plaintext)       // Seal the message.
```

```text
function RatchetRecv(recv, local.priv, ciphertext):
  ephemeral.pub = recv.Unmask("ratchet-pk", ciphertext[:32]) // Unmask the ephemeral public key.
  recv.Mix("ratchet-ss", ECDH(ephemeral.pub, local.priv)     // Mix the shared secret into the protocol.
  return recv.Open("message", ciphertext[32:])               // Open the message.
```

This scheme provides forward secrecy and break-in recovery for asynchronous messaging. Each message carries a new
ephemeral public key, which is used to derive a shared secret with the recipient's static public key. This shared secret
is then mixed into the protocol state, ratcheting it forward.

[double ratchet]: https://signal.org/docs/specifications/doubleratchet/

### Hybrid Public-Key Encryption

A protocol can be used to build an integrated [HPKE]-style public key encryption scheme:

[HPKE]: https://www.rfc-editor.org/rfc/rfc9180.html

```text
function HPKESeal(receiver.pub, sender, plaintext):
  ephemeral = R255::KeyGen()                                         // Generate an ephemeral key pair.
  protocol.Init("com.example.hpke")                                  // Initialize a protocol with a domain string.
  protocol.Mix("sender", sender.pub)                                 // Mix the senders's public key into the protocol.
  protocol.Mix("receiver", receiver.pub)                             // Mix the receiver's public key into the protocol.
  protocol.Mix("ephemeral", ephemeral.pub)                           // Mix the ephemeral public key into the protocol.
  protocol.Mix("ephemeral ecdh", ECDH(receiver.pub, ephemeral.priv)) // Mix the ephemeral ECDH shared secret into the protocol.
  protocol.Mix("static ecdh", ECDH(receiver.pub, sender.priv))       // Mix the static ECDH shared secret into the protocol.
  ciphertext || tag = protocol.Seal("message", plaintext)            // Seal the plaintext.
  return (ephemeral.pub, ciphertext || tag)                          // Return the ephemeral public key, ciphertext, and tag.
```

```text
function HPKEOpen(receiver, sender.pub, ephemeral.pub, ciphertext || tag):
  protocol.Init("com.example.hpke")                                  // Initialize a protocol with a domain string.
  protocol.Mix("sender", sender.pub)                                 // Mix the senders's public key into the protocol.
  protocol.Mix("receiver", receiver.pub)                             // Mix the receiver's public key into the protocol.
  protocol.Mix("ephemeral", ephemeral.pub          )                 // Mix the ephemeral public key into the protocol.
  protocol.Mix("ephemeral ecdh", ECDH(ephemeral.pub, receiver.priv)) // Mix the ephemeral ECDH shared secret into the protocol.
  protocol.Mix("static ecdh", ECDH(sender.pub, receiver.priv))       // Mix the static ECDH shared secret into the protocol.
  plaintext = protocol.Open("message", ciphertext || tag)            // Open the ciphertext.
  return plaintext
```

This scheme is outsider-secure for both confidentiality and authenticity, but only insider-secure for authenticity. An
adversary not in possession of either the sender or receiver's private key will be unable to read plaintexts or forge
ciphertexts. An adversary in possession of the sender's private key will be unable to read plaintexts due to the use of
an ephemeral key. An adversary in possession of the receiver's private key will be able to forge arbitrary ciphertexts
using the sender's public key (i.e. Key Compromise Impersonation).

### Digital Signatures

A protocol can be used to implement EdDSA-style Schnorr digital signatures:

```text
function Sign(signer, message):
  protocol.Init("com.example.eddsa")                       // Initialize a protocol with a domain string.
  protocol.Mix("signer", signer.pub)                       // Mix the signer's public key into the protocol.
  protocol.Mix("message", message)                         // Mix the message into the protocol.
  (k, R) = R255::KeyGen()                                  // Generate a commitment scalar and point.
  protocol.Mix("commitment", R)                            // Mix the commitment point into the protocol.
  c = R255::ReduceScalar(protocol.Derive("challenge", 64)) // Derive a challenge scalar.
  s = signer.priv * c + k                                  // Calculate the proof scalar.
  return (R, s)                                            // Return the commitment point and proof scalar.
```

The resulting signature is strongly bound to both the message and the signer's public key, making it sUF-CMA secure. If
a non-prime order group like Edwards25519 is used instead of Ristretto255, the verification function must account for
co-factors to be strongly unforgeable.

```text
function Verify(signer.pub, message, R, s):
  protocol.Init("com.example.eddsa")                        // Initialize a protocol with a domain string.
  protocol.Mix("signer", signer.pub)                        // Mix the signer's public key into the protocol.
  protocol.Mix("message", message)                          // Mix the message into the protocol.
  protocol.Mix("commitment", R)                             // Mix the commitment point into the protocol.
  c' = R255::ReduceScalar(protocol.Derive("challenge", 64)) // Derive an expected challenge scalar.
  R' = [s]G - [c']signer.pub                                // Calculate the expected commitment point.
  return R = R'                                             // The signature is valid if both points are equal.
```

An additional variation on this scheme uses `Mask` instead of `Mix` to include the commitment point `R` in the
protocol's state. This makes it impossible to recover the signer's public key from a message and signature (which may be
desirable for privacy in some contexts) at the expense of making batch verification impossible.

To make this scheme deterministic (or hedged), the Ristretto255 commitment generation can be replaced with a derivation
function using a cloned protocol:

```text
function DetCommitment(signer):
  clone = protocol.Clone()
  clone.Mix("signer-private", signer.priv)
  k = R255::ReduceScalar(clone.Derive("scalar", 64))
  R = [k]G
  return (k, R)
```

This results in a commitment scalar which is derived from both the original protocol's state (i.e., domain string,
signer's public key, message) and the clone's later state (i.e., signer's private key).

A hedged variant would mix in a random value into the clone before derivation.

Finally, there is a short signature variant of this scheme in which the signature is `(c,s)` and the verifier
reconstructs `R = [s]G - [c]P` and then compares `c'` to `c` to verify.

### Signcryption

A protocol can be used to integrate a [HPKE](#hybrid-public-key-encryption) scheme and
a [digital signature](#digital-signatures) scheme to produce a signcryption scheme, providing both confidentiality and
strong authentication in the public key setting:

```text
function Signcrypt(sender, receiver.pub, plaintext):
  ephemeral = R255::KeyGen()                               // Generate an ephemeral key pair.
  protocol.Init("com.example.sc")                          // Initialize a protocol with a domain string.
  protocol.Mix("receiver", receiver.pub)                   // Mix the receiver's public key into the protocol.
  protocol.Mix("sender", sender.pub)                       // Mix the sender's public key into the protocol.
  protocol.Mix("ephemeral", ephemeral.pub)                 // Mix the ephemeral public key into the protocol.
  protocol.Mix("ecdh", ECDH(receiver.pub, ephemeral.priv)) // Mix the ECDH shared secret into the protocol.
  ciphertext = protocol.Mask("message", plaintext)         // Encrypt the plaintext.
  (k, R) = R255::KeyGen()                                  // Generate a commitment scalar and point.
  protocol.Mix("commitment", R)                            // Mix the commitment point into the protocol.
  c = R255::ReduceScalar(protocol.Derive("challenge", 64)) // Derive a challenge scalar.
  s = sender.priv * c + k                                  // Calculate the proof scalar.
  return (ephemeral.pub, ciphertext, R, s)                 // Return the ephemeral public key, ciphertext, and signature.
```

```text
function Unsigncrypt(receiver, sender.pub, ephemeral.pub, ciphertext, R, s):
  protocol.Init("com.example.sc")                           // Initialize a protocol with a domain string.
  protocol.Mix("receiver", receiver.pub)                    // Mix the receiver's public key into the protocol.
  protocol.Mix("sender", sender.pub)                        // Mix the sender's public key into the protocol.
  protocol.Mix("ephemeral", ephemeral.pub)                  // Mix the ephemeral public key into the protocol.
  protocol.Mix("ecdh", ECDH(receiver.priv, ephemeral.pub))  // Mix the ECDH shared secret into the protocol.
  plaintext = protocol.Unmask("message", ciphertext)        // Decrypt the ciphertext.
  protocol.Mix("commitment", R)                             // Mix the commitment point into the protocol.
  c' = R255::ReduceScalar(protocol.Derive("challenge", 64)) // Derive an expected challenge scalar.
  R' = [s]G - [c']sender.pub                                // Calculate the expected commitment point.
  if R == R':
    return plaintext                                        // If both points are equal, return the plaintext.
  else:
    return ErrInvalidCiphertext                             // Otherwise, return an error.
```

This scheme is both outsider- and insider-secure for both confidentiality and authenticity. An outsider adversary in
possession of both public keys will be unable to read plaintexts or forge ciphertexts. An insider adversary in
possession of the sender's private key will be unable to read plaintexts. An insider adversary in possession of the
receiver's private key will be unable to forge ciphertexts.

Because a Newplex protocol is an incremental, stateful way of building a cryptographic scheme, this integrated
signcryption scheme is stronger than generic schemes which combine separate public key encryption and digital signature
algorithms: Encrypt-Then-Sign (`EtS`) and Sign-then-Encrypt (`StE`).

An adversary attacking an `EtS` scheme can strip the signature from someone else's encrypted message and replace it with
their own, potentially allowing them to trick the recipient into decrypting the message for them. That's possible
because the signature is of the ciphertext itself, which the adversary knows. A standard Schnorr signature scheme like
Ed25519 derives the challenge scalar `r` from a hash of the signer's public key and the message being signed (i.e., the
ciphertext).

With this scheme, on the other hand, the digital signature isn't of the ciphertext alone, but of all inputs to the
protocol. The challenge scalar `r` is derived from the protocol's state, which depends on (among other things) the ECDH
shared secret. Unless the adversary already knows the shared secret (i.e., the secret key that the plaintext is
encrypted with), they can't create their own signature (which they're trying to do to trick someone into giving them the
plaintext).

An adversary attacking an `StE` scheme can decrypt a signed message sent to them and re-encrypt it for someone else,
allowing them to pose as the original sender. This scheme makes simple replay attacks impossible by including both the
intended sender and receiver's public keys in the protocol state. The
initial [HPKE-style](#hybrid-public-key-encryption) portion of the protocol can be trivially constructed by an adversary
with an ephemeral key pair of their choosing. However, the final portion is the sUF-CMA
secure [EdDSA-style Schnorr signature scheme](#digital-signatures) from the previous section and unforgeable without the
sender's private key.

### Verifiable Random Function

A protocol can be used to build a verifiable random function:

```text
function Prove(d, m, n):
  protocol.Init("com.example.vrf")                         // Initialize the protocol.
  protocol.Mix("prover", [d]G)                             // Mix in the prover's public key.
  protocol.Mix("input", m)                                 // Mix in the input.
  h = R255::DeriveElement(protocol.Derive("h", 64))        // Derive an element from the protocol state.
  Gamma = [d]H                                             // Calculate the gamma point.
  protocol.Mix("gamma", Gamma)                             // Mix in the gamma point.
  prf = protocol.Derive("prf", n)                          // Derive n bytes of PRF output.
  clone = protocol.Clone()                                 // Clone the protocol to generate a nonce.
  clone.Mix("prover-private", d)                           // Mix in the prover's private key.
  clone.Mix("rand", rand(32))                              // Mix in a random value.
  k = R255::ReduceScalar(clone.Derive("commitment", 64))   // Derive a nonce scalar.
  u = [k]G                                                 // Calculate the two commitment points.
  v = [k]H
  protocol.Mix("commitment-u", u)                          // Mix in the two commitment points.
  protocol.Mix("commitment-v", v)
  c = R255::ReduceScalar(protocol.Derive("challenge", 64)) // Derive a challenge scalar.
  s = k + c * d                                            // Calculate the response scalar.
  return (prf, Gamma || c || s)                            // Return the PRF output and the proof.
```

```text
function Verify(Q, m, n, Gamma || c || s):
  protocol.Init("com.example.vrf")                          // Initialize the protocol.
  protocol.Mix("prover", Q)                                 // Mix in the prover's public key.
  protocol.Mix("input", m)                                  // Mix in the input.
  h = R255::DeriveElement(protocol.Derive("h", 64))         // Derive an element from the protocol state.
  protocol.Mix("gamma", Gamma)                              // Mix in the gamma point.
  prf = protocol.Derive("prf", n)                           // Derive n bytes of PRF output.
  u' = [s]G - [c]Q                                          // Calculate the two expected commitment points.
  v' = [s]H - [c]Gamma 
  protocol.Mix("commitment-u", u')                          // Mix in the two expected commitment points.
  protocol.Mix("commitment-v", v')
  c' = R255::ReduceScalar(protocol.Derive("challenge", 64)) // Derive the expected challenge scalar.
  if c != c':                                               // If it's not the same as the expected challenge scalar, return an error.
    return ErrInvalidProof
  return prf                                                // If they're the same, return the PRF output.
```

This roughly follows the [RFC 9381] ECVRF scheme, but uses the stateful nature of the protocol as a running
transcript of all calculated and observed values.

[RFC 9381]: https://www.rfc-editor.org/rfc/rfc9381.html

### Password-Authenticated Key Exchange

A protocol can be used as the basis of a [CPace]-style password-authenticated key exchange:

```text
function PAKEInitiate(initiator, responder, session, password):
  protocol.Init("com.example.pake")                         // Initialize the protocol with the data.
  protocol.Mix("initiator", initiator)
  protocol.Mix("responder", responder)
  protocol.Mix("session", session)
  protocol.Mix("password", password)
  P = R255::DeriveElement(protocol.Derive("generator", 64)) // Derive an element from the data.
  a = R255::ReduceScalar(Rand(64))                          // Generate a random scalar.
  A = [a]P                                                  // Calculate and send the initiator element.
  Send(A)
  B = Receive()                                             // Receive the responder element.
  protocol.Mix("initiator-message", A)                      // Mix in the two exchanged elements as received.
  protocol.Mix("responder-message", B)
  K = [a]B                                                  // Calculate the key element.
  protocol.Mix("key-element", K)                            // Mix it into the protocol.
  return protocol
```

```text
function PAKERespond(initiator, responder, session, password):
  protocol.Init("com.example.pake")                         // Initialize the protocol with the data.
  protocol.Mix("initiator", initiator)
  protocol.Mix("responder", responder)
  protocol.Mix("session", session)
  protocol.Mix("password", password)
  P = R255::DeriveElement(protocol.Derive("generator", 64)) // Derive an element from the data.
  b = R255::ReduceScalar(Rand(64))                          // Generate a random scalar.
  B = [b]P                                                  // Calculate and send the responder element.
  Send(B)
  A = Receive()                                             // Receive the initiator element.
  protocol.Mix("initiator-message", A)                      // Mix in the two exchange elements as received.
  protocol.Mix("responder-message", B)
  K = [b]A                                                  // Calculate the key point.
  protocol.Mix("key-element", K)                            // Mix it into the protocol.
  return protocol
```

[Cpace]: https://www.ietf.org/archive/id/draft-irtf-cfrg-cpace-06.html