# The Design Of Newplex

<!-- TOC -->
* [The Design Of Newplex](#the-design-of-newplex)
  * [What is Newplex?](#what-is-newplex)
  * [The Permutation](#the-permutation)
  * [The Duplex](#the-duplex)
    * [`Permute`](#permute)
    * [`Absorb`](#absorb)
    * [`Squeeze`](#squeeze)
    * [`Ratchet`](#ratchet)
    * [`Encrypt`/`Decrypt`](#encryptdecrypt)
  * [The Protocol](#the-protocol)
    * [`Init`](#init)
    * [`Mix`](#mix)
    * [`Derive`](#derive)
      * [KDF Security](#kdf-security)
      * [KDF Chains](#kdf-chains)
    * [`Encrypt`/`Decrypt`](#encryptdecrypt-1)
    * [`Seal`/`Open`](#sealopen)
  * [Basic Constructions](#basic-constructions)
    * [Message Digests](#message-digests)
    * [Message Authentication Codes](#message-authentication-codes)
    * [Stream Ciphers](#stream-ciphers)
    * [Authenticated Encryption And Data (AEAD)](#authenticated-encryption-and-data-aead)
    * [Streaming Authenticated Encryption](#streaming-authenticated-encryption)
      * [Bidirectional Streaming](#bidirectional-streaming)
  * [Complex Constructions](#complex-constructions)
    * [Hybrid Public-Key Encryption](#hybrid-public-key-encryption)
    * [Digital Signatures](#digital-signatures)
    * [Signcryption](#signcryption)
<!-- TOC -->

## What is Newplex?

Newplex provides an incremental, stateful cryptographic primitive for symmetric-key cryptographic operations (e.g.,
hashing, encryption, message authentication codes, and authenticated encryption) in complex constructions. Inspired
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

## The Permutation

[Simpira-1024] was chosen as the core of Newplex for a number of reasons:

1. The designers claim security against structural distinguishers with complexity up to 2^128, which aligns with the
   security level goals of this project.
2. It has a width of 1024, allowing for a duplex with a 256-bit capacity to have 768 bits of rate. This significantly
   improves throughput without increasing the latency on small inputs.
3. It benefits from the nearly ubiquitous AES-NI instruction set, making it equally performant on both AMD64 and ARM64
   architectures. The only faster permutation on modern ARM64 processors is Keccak-p\[1600,24\], which benefits from the
   `FEAT_SHA3` extensions, but no such instruction set exists for AMD64 processors. Further, Simpira-1024 allows for up
   to 8 pipelined `AESENC` instructions, maximizing throughput on modern processors.
4. In the ten years since the publication of [Simpira V2][Simpira-1024], the main cryptanalytical results on it have
   been on round-reduced versions of the smaller permutations:

   | Variant     | Total Rounds | Max Rounds Attacked | % Rounds Broken | Security Margin       |
   |-------------|--------------|---------------------|-----------------|-----------------------|
   | Simpira-256 | 15           | 9                   | 60%             | Safe (6 rounds left)  |
   | Simpira-384 | 21           | 10                  | 48%             | Safe (11 rounds left) |
   | Simpira-512 | 15           | 8                   | 53%             | Safe (7 rounds left)  |
   | Simpira-768 | 15           | 8                   | 53%             | Safe (7 rounds left)  |

   No attacks have been found on the full-round specifications, and no attacks at all have been found for Simpira-1024.
   It should be noted that Simpira-1024 has not received the same degree of scrutiny as the smaller Simpira variants.
   This design would accommodate Keccak-f\[1600\] for contexts which require a higher security margin or where
   Keccak-f\[1600\] or Keccak-p\[1600,12\] would yield better performance (e.g., ARM64 processors with `FEAT_SHA3`
   instructions or low-powered processors without `AES-NI` instructions).

5. Its non-linear component is the AES round, which has been extensively studied, and its shuffling layer achieves full
   diffusion after very few rounds.


## The Duplex

The core of Newplex is a relatively basic [cryptographic duplex][duplex], with a width of 1024 bits, a capacity of 256
bits, and a rate of 768 bits (i.e. `b=1024`, `c=256`, `r=768`).

[duplex]: https://keccak.team/sponge_duplex.html

This provides the following security levels:

| Security Metric      | Level (Bits) | Formula | Condition        |
|----------------------|--------------|---------|------------------|
| Collision Resistance | 128          | `c/2`   | public/hash mode |
| State/Key Recovery   | 256          | `c`     | (assuming K≥256) |
| Indistinguishability | 128          | `c/2`   | birthday bound   |

The duplex provides a small number of operations: `Permute`, `Absorb`, `Squeeze`, `Ratchet`, and `Encrypt`/`Decrypt`. It
provides no padding or framing scheme and only permutes its state when an operation's input is larger than the duplex's
remaining rate. As such, it is a building block for higher level operations and should be considered cryptographic
hazmat.

### `Permute`

The `Permute` operation runs the [Simpira-1024] permutation on the duplex's entire state and resets its rate index to
zero.

### `Absorb`

The `Absorb` operation XORs the duplex's remaining rate with the input in blocks of up to 768 bits. When the duplex's
rate is exhausted, it calls `Permute`.

**N.B.:** `Absorb` does not call `Permute` at the end of the operation, therefore a sequence of `Absorb` operations are
equivalent to a single `Absorb` operation with the concatenation of the sequence's inputs (e.g.
`Absorb('A'); Absorb('B')` is equivalent to `Absorb('AB')`).

### `Squeeze`

The `Squeeze` operation returns the duplex's remaining rate in blocks of up to 768 bits. When the duplex's rate is
exhausted, it calls `Permute`.

**N.B.:** `Squeeze` does not call `Permute` at the end of the operation, therefore a sequence of `Squeeze` operations
are equivalent to a single `Squeeze` operation with the concatenation of the sequence's outputs (e.g.
`Squeeze(10); Squeeze(6)` is equivalent to `Squeeze(16)`).

### `Ratchet`

The `Ratchet` operation calls `Permute`, then overwrites the first 256 bits of the duplex's rate with zeros. This
irreversibly modifies the duplex's state, preventing potential rollback attacks and establishing forward secrecy. An
attacker who recovers the post-ratchet state will be unable to reconstruct the missing 256 bits and thus unable to
invert the permutation to recover prior states.

### `Encrypt`/`Decrypt`

The `Encrypt` operation XORs the duplex's remaining rate with the input in blocks of up to 768 bits, returning the
result as the ciphertext. When the duplex's rate is exhausted, it calls `Permute`.

The `Decrypt` operation XORs the ciphertext with the duplex's remaining rate in blocks of up to 768 bits, returning the
result as the plaintext. It then replaces the duplex's rate with the ciphertext. When the duplex's rate is exhausted, it
calls `Permute`.

This is functionally the same as the [SpongeWrap] construction, combining an `Absorb` operation of the plaintext with a
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
* `Encrypt`/`Decrypt`: Encrypt and decrypt a message, using the protocol's current state as a key.
* `Seal`/`Open`: Encrypt and decrypt a message, using an authenticator tag to ensure the ciphertext has not been
  modified.

Labels are used for all protocol operations (except `Init`) to provide domain separation of inputs and outputs. This
ensures that semantically distinct values with identical encodings (e.g., public keys or ECDH shared secrets) result in
distinctly encoded operations as long as the labels are distinct. Labels should be human-readable values that
communicate the source of the input or the intended use of the output. The label `server-p256-public-key` is good;
`step-3a` is a bad label.

### `Init`

An `Init` operation initializes a new, all-zero duplex, and absorbs a domain separation string with it.

```text
function Init(domain):
  Absorb(0x01 || left_encode(|domain|) || domain)
``` 

`Init` encodes the length of the domain in bits using the `left_encode` function from [NIST SP 800-185][TupleHash]. This
ensures an unambiguous and recoverable encoding for the data absorbed by the duplex. The `Init` operation is only
performed once, when a protocol is initialized.

The BLAKE3 recommendations for KDF context strings apply equally to Newplex protocol domains:

> The context string should be hardcoded, globally unique, and application-specific. … The context string should not
> contain variable data, like salts, IDs, or the current time. (If needed, those can be part of the key material, or
> mixed with the derived key afterwards.) … The purpose of this requirement is to ensure that there is no way for an
> attacker in any scenario to cause two different applications or components to inadvertently use the same context
> string. The safest way to guarantee this is to prevent the context string from including input of any kind.

**N.B.:** Unless otherwise noted, all sizes in this document are in bits. Most practical implementations, however, will
use byte-oriented APIs.

### `Mix`

A `Mix` operation accepts a label and an input and makes the protocol's state (and all future output) cryptographically
dependent on them.

```text
function Mix(label, input):
  Absorb(0x02 || left_encode(|label|) || label || input || right_encode(|input|))
```

`Mix` encodes the length of the label in bits and the length of the input in bits using the `left_encode` and
`right_encode` functions from [NIST SP 800-185], respectively. The use of `right_encode` allows `Mix` operations to
accept inputs of indeterminate length (i.e., streams).

### `Derive`

A `Derive` operation accepts a label and an output length and returns pseudorandom data derived from the protocol's
state, the label, and the output length.

```text
function Derive(label, n):
  Absorb(0x03 || left_encode(|label|) || label || right_encode(n))
  Permute()
  prf = Squeeze(n)
  Ratchet()
  return prf
```

`Derive` encodes the label and output length, absorbs it into the duplex, permutes the duplex to ensure the duplex's
state is indistinguishable from random, and squeezes the requested output from the duplex. Finally, the duplex's state
is ratcheted to prevent rollback.

**N.B.:** A `Derive` operation's output depends on both the label and the output length.

#### KDF Security

A sequence of `Mix` operations followed by an operation which produces output (e.g., `Derive`, `Encrypt`, `Seal`, etc.)
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

### `Encrypt`/`Decrypt`

The `Encrypt` and `Decrypt` operations accept a label and an input and encrypts or decrypts them using the protocol's
state and the label.

```text
function Encrypt(label, plaintext):
  Absorb(0x04 || left_encode(|label|) || label)
  Permute()
  ciphertext = Encrypt(plaintext)
  Absorb(right_encode(|plaintext|))
  Ratchet()
  return ciphertext
  
function Decrypt(label, ciphertext):
  Absorb(0x04 || left_encode(|label|) || label)
  Permute()
  plaintext = Decrypt(ciphertext)
  Absorb(right_encode(|plaintext|))
  Ratchet()
  return plaintext
```

`Encrypt` encodes the label and output length, absorbs it into the duplex, permutes the duplex to ensure the duplex's
state is indistinguishable from random, and encrypts the input with the duplex. The total length of the plaintext is
absorbed, and the duplex's state is permuted to ensure the duplex's capacity is dependent on the plaintext length.
Finally, the duplex's state is ratcheted to prevent rollback.

`Decrypt` is identical but uses the duplex to decrypt the data.

Three points bear mentioning about `Encrypt` and `Decrypt`:

1. Unlike `Derive`, the output of an `Encrypt` operation does not depend on its input length, therefore  `Encrypt('A')`
   and `Encrypt('AB')` will share a prefix. This allows for fully streaming operations, but usages which require the
   ciphertext to depend on the plaintext length must include that as the input to a prior `Mix` operation.
2. `Encrypt` operations offer EAV security (i.e., an entirely passive adversary will not be able to read plaintexts).
   IND-CPA security (i.e., an adversary with an encryption oracle) requires a prior `Mix` operation to include a value
   unique to the plaintext, like a nonce or a message ID.
3. `Encrypt` operations provide no authentication by themselves. An attacker can modify a ciphertext and the `Decrypt`
   operation will return a plaintext which was never encrypted.

   That said, the divergent ciphertext input will result in divergent protocol state, as the protocol's state after an
   `Encrypt`/`Decrypt` operation is cryptographically dependent on the plaintext of the operation.

   For IND-CCA security, use [`Seal`/`Open`](#sealopen).

### `Seal`/`Open`

`Seal` and `Open` operations extend the `Encrypt` and `Decrypt` operations with the inclusion of a 128-bit
authentication tag. The `Open` operation verifies the tag, returning an error if the tag is invalid.

```text
function Seal(label, plaintext):
  Absorb(0x05 || left_encode(|label|) || label || right_encode(|plaintext|))
  Permute()
  ciphertext = Encrypt(plaintext)
  Permute()
  tag = Squeeze(128)
  Ratchet()
  return ciphertext || tag
  
function Open(label, ciphertext || tag):
  Absorb(0x05 || left_encode(|label|) || label || right_encode(|ciphertext|))
  Permute()
  plaintext = Decrypt(ciphertext)
  Permute()
  tag' = Squeeze(128)
  Ratchet()
  if tag != tag':
    return ErrInvalidCiphertext
  return plaintext
```

`Seal` encodes the label and output length, absorbs it into the duplex, permutes the duplex to ensure the duplex's
state is indistinguishable from random, and encrypts the input with the duplex. Next, the duplex is permuted again, and
a 128-bit tag is squeezed from the duplex's state. Finally, the duplex's state ratcheted to prevent rollback.

`Open` is identical but uses the duplex to decrypt the data and compares the received tag to an expected tag derived
from the received plaintext. If the two are equal, the plaintext is returned. Otherwise, an error is returned.

`Seal` and `Open` provide IND-CCA2 security if one of the protocol's inputs includes a probabilistic value, like a
nonce.

**N.B.:** An attacker presenting a modified ciphertext will, as part of the duplex's `Decrypt` operation, be able to
insert data into the duplex's rate. This does not present a security problem, as the duplex's capacity remains
inaccessible. Any attack that successfully biases the duplex's state post-permutation would completely invalidate all
of [Simpira-1024]'s security claims.

**N.B.:** A modified ciphertext will result in the protocol having an entirely different state  after an `Open`
operation. All future operations will result in different outputs and the inability to decrypt or open ciphertexts. This
is intentional. Because an active attacker is unable to control the duplex's post-permutation state, this does not
present an avenue for influence.

**N.B.:** Unlike `Encrypt`, `Seal` does not support streaming operations. This is an intentional choice to mitigate the
accidental disclosure of unauthenticated plaintext and follows the generally recommended practices for API design of
authenticated encryption. See the [Streaming Authenticated Encryption](#streaming-authenticated-encryption) construction
for details on how to handle streaming data.

## Basic Constructions

By combining operations, we can construct a wide variety of cryptographic schemes using a single protocol.

### Message Digests

Calculating a message digest is as simple as a `Mix` and a `Derive`:

```text
function MessageDigest(message):
  Init("com.example.md")         // Initialize a protocol with a domain string.
  Mix("message", data)           // Mix the message into the protocol.
  digest = Derive("digest", 256) // Derive 256 bits of output and return it.
  return digest
```

This construction is indistinguishable from a random oracle if Simpira-1024 is indistinguishable from a random
permutation.

### Message Authentication Codes

Adding a key to the previous construction makes it a MAC:

```text
function MAC(key, message):
  Init("com.example.mac")  // Initialize a protocol with a domain string.
  Mix("key", key)          // Mix the key into the protocol.
  Mix("message", message)  // Mix the message into the protocol.
  tag = Derive("tag", 128) // Derive 128 bits of output and return it.
  return tag
```

The use of labels and the encoding of [`Mix` inputs](#mix) ensures that the key and the message will never overlap, even
if their lengths vary.

This construction is sUF-CMA secure if Simpira-1024 is indistinguishable from a random permutation.

### Stream Ciphers

A protocol can be used to create a stream cipher:

```text
function StreamEncrypt(key, nonce, plaintext):
  Init("com.example.stream")                 // Initialize a protocol with a domain string.
  Mix("key", key)                            // Mix the key into the protocol.
  Mix("nonce", nonce)                        // Mix the nonce into the protocol.
  ciphertext = Encrypt("message", plaintext) // Encrypt the plaintext.
  return ciphertext

function StreamDecrypt(key, nonce, ciphertext):
  Init("com.example.stream")                 // Initialize a protocol with a domain string.
  Mix("key", key)                            // Mix the key into the protocol.
  Mix("nonce", nonce)                        // Mix the nonce into the protocol.
  plaintext = Decrypt("message", ciphertext) // Decrypt the ciphertext.
  return plaintext
```

This construction is IND-CPA-secure under the following assumptions:

1. Simpira-1024 is indistinguishable from a random permutation.
2. At least one of the inputs to the protocol is a nonce (i.e., not used for multiple messages).

### Authenticated Encryption And Data (AEAD)

A protocol can be used to create an AEAD:

```text
function AEADSeal(key, nonce, ad, plaintext):
  Init("com.example.aead")                       // Initialize a protocol with a domain string.
  Mix("key", key)                                // Mix the key into the protocol.
  Mix("nonce", nonce)                            // Mix the nonce into the protocol.
  Mix("ad", ad)                                  // Mix the associated data into the protocol.
  ciphertext || tag = Seal("message", plaintext) // Seal the plaintext.
  return ciphertext || tag
```

The introduction of a nonce makes the scheme probabilistic (which is required for IND-CCA security).

Unlike many standard AEADs (e.g., AES-GCM and ChaCha20Poly1305), it is fully context-committing: the tag is a strong
cryptographic commitment to all the inputs.

Also, unlike a standard AEAD, this can be easily extended to allow for multiple, independent pieces of associated data
without the risk of ambiguous inputs.

```text
function AEADOpen(key, nonce, ad, ciphertext || tag):
  Init("com.example.aead")                       // Initialize a protocol with a domain string.
  Mix("key", key)                                // Mix the key into the protocol.
  Mix("nonce", nonce)                            // Mix the nonce into the protocol.
  Mix("ad", ad)                                  // Mix the associated data into the protocol.
  plaintext = Open("message", ciphertext || tag) // Open the ciphertext.
  return plaintext                               // Return the plaintext or an error.
```

This construction is IND-CCA2-secure (i.e., both IND-CPA and INT-CTXT) under the following assumptions:

1. Simpira-1024 is indistinguishable from a random permutation.
2. At least one of the inputs to the protocol is a nonce (i.e., not used for multiple messages).

### Streaming Authenticated Encryption

For streams of indeterminate length, authenticated encryption can be provided via a sequence of `Seal` calls. Each block
is limited to `2^32-1` bytes.

```text
function AEStreamSend(key, nonce, plaintext, ciphertext):
  Init("com.example.aestream")           // Establish a shared protocol state.
  Mix("key", key)
  Mix("nonce", nonce)
  while |plaintext| > 0:
    pblock = Read(plaintext)             // Read a block of plaintext.
    pheader = BEU32(|pblock|)            // Encode the block length as a 32-bit unsigned big endian integer.
    cheader = Seal("header", pheader)    // Seal the header.
    cblock = Seal("block", pblock)       // Seal the block.
    Write(ciphertext, cheader || cblock) // Write the sealed header and sealed block.
  pheader = BEU32(0)                     // Encode a zero-length block header.
  cheader = Seal("header", pheader)      // Seal the header.
  cblock = Seal("block", "")             // Seal a zero-length block.
  Write(ciphertext, cheader || cblock)   // Write the sealed header and sealed block.


function AEStreamRecv(key, nonce, ciphertext, plaintext):
  Init("com.example.aestream")
  Mix("key", key)
  Mix("nonce", nonce)
  while |ciphertext| > 0:
    cheader = Read(ciphertext, 32+128)    // Read a sealed 32-bit header and 128-bit tag.
    pheader = Open("header", cheader)     // Open the sealed header.
    if pheader == ErrInvalidCiphertext:   // Error if the header is not authenticated.
      return ErrInvalidCiphertext
    msglen = BEU32(pheader)               // Decode the block length.
    cblock = Read(ciphertext, msglen+128) // Read the sealed block and 128-bit tag.
    pblock = Open("block", cblock)        // Open the sealed block.
    if pblock == ErrInvalidCiphertext:    // Error if the ciphertext is not authenticated.
      return ErrInvalidCiphertext
    if |pblock| == 0:                     // Return an EOF if the block is empty.
      return EOF
    Write(plaintext, pblock)              // Otherwise, write the plaintext block.
  return ErrInvalidCiphertext             // Error if the stream is truncated.
```

The sender encodes each block's length as a 32-bit big endian integer, seals that header, seals the block, and sends
both to the receiver. An empty block is used to mark the end of the stream. The receiver reads the encrypted header,
decrypts it, decodes it into a block length, reads an encrypted block of that length and its authentication tag, then
opens the sealed block. When it encounters the empty block, it returns EOF. If the stream terminates before that, an
invalid ciphertext error is returned.

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

## Complex Constructions

Given an elliptic curve group like NIST P-256, a protocol can be used to build complex constructions which integrate
public- and symmetric-key operations.

### Hybrid Public-Key Encryption

A protocol can be used to build an integrated [ECIES]-style public key encryption scheme:

[ECIES]: https://en.wikipedia.org/wiki/Integrated_Encryption_Scheme

```text
function HPKEEncrypt(receiver.pub, plaintext):
  ephemeral = P256::KeyGen()                      // Generate an ephemeral key pair.
  Init("com.example.hpke")                        // Initialize a protocol with a domain string.
  Mix("receiver", receiver.pub)                   // Mix the receiver's public key into the protocol.
  Mix("ephemeral", ephemeral.pub)                 // Mix the ephemeral public key into the protocol.
  Mix("ecdh", ECDH(receiver.pub, ephemeral.priv)) // Mix the ephemeral ECDH shared secret into the protocol.
  ciphertext || tag = Seal("message", plaintext)  // Seal the plaintext.
  return (ephemeral.pub, ciphertext || tag)       // Return the ephemeral public key, ciphertext, and tag.
```

```text
function HPKEDecrypt(receiver, ephemeral.pub, ciphertext || tag):
  Init("com.example.hpke")                        // Initialize a protocol with a domain string.
  Mix("receiver", receiver.pub)                   // Mix the receiver's public key into the protocol.
  Mix("ephemeral", ephemeral.pub)                 // Mix the ephemeral public key into the protocol.
  Mix("ecdh", ECDH(receiver.priv, ephemeral.pub)) // Mix the ephemeral ECDH shared secret into the protocol.
  plaintext = Open("message", ciphertext || tag)  // Open the ciphertext.
  return plaintext
```

**WARNING:** This construction does not provide authentication in the public key setting. An adversary in possession of
the receiver's public key (i.e., anyone) can create ciphertexts which will decrypt as valid. In the symmetric key
setting (i.e., an adversary without the receiver's public key), this is IND-CCA secure, but that setting is not
realistic. As-is, the tag is more like a checksum than a MAC, preventing modifications only by adversaries who don't
have the recipient's public key.

Using a static ECDH shared secret (i.e. `ECDH(receiver.pub, sender.priv)`) would add implicit authentication but would
require a nonce or an ephemeral key to be IND-CCA secure. The resulting scheme would be outsider secure in the public
key setting (i.e., an adversary in possession of everyone's public keys would be unable to forge or decrypt ciphertexts)
but not insider secure (i.e., an adversary in possession of the receiver's private key could forge ciphertexts from
arbitrary senders, a.k.a. key compromise impersonation).

### Digital Signatures

A protocol can be used to implement EdDSA-style Schnorr digital signatures:

```text
function Sign(signer, message):
  Init("com.example.eddsa")                       // Initialize a protocol with a domain string.
  Mix("signer", signer.pub)                       // Mix the signer's public key into the protocol.
  Mix("message", message)                         // Mix the message into the protocol.
  (k, I) = P256::KeyGen()                         // Generate a commitment scalar and point.
  Mix("commitment", I)                            // Mix the commitment point into the protocol.
  (_, r) = P256::Scalar(Derive("challenge", 320)) // Derive a challenge scalar.
  s = signer.priv * r + k                         // Calculate the proof scalar.
  return (I, s)                                   // Return the commitment point and proof scalar.
```

The resulting signature is strongly bound to both the message and the signer's public key, making it sUF-CMA secure. If
a non-prime order group like Edwards25519 is used instead of NIST P-256, the verification function must account for
co-factors to be strongly unforgeable.

```text
function Verify(signer.pub, message, I, s):
  Init("com.example.eddsa")                        // Initialize a protocol with a domain string.
  Mix("signer", signer.pub)                        // Mix the signer's public key into the protocol.
  Mix("message", message)                          // Mix the message into the protocol.
  Mix("commitment", I)                             // Mix the commitment point into the protocol.
  (_, r') = P256::Scalar(Derive("challenge", 320)) // Derive an expected challenge scalar.
  I' = [s]G - [r']signer.pub                       // Calculate the expected commitment point.
  return I = I'                                    // The signature is valid if both points are equal.
```

An additional variation on this construction uses `Encrypt` instead of `Mix` to include the commitment point `I` in the
protocol's state. This makes it impossible to recover the signer's public key from a message and signature (which may be
desirable for privacy in some contexts) at the expense of making batch verification impossible.

To make this scheme deterministic (or hedged), the P-256 commitment generation can be replaced with a derivation
function using a cloned protocol:

```text
function DetCommitment(signer):
  clone = Clone()
  clone.Mix("signer-private", signer.priv)
  k = P256::Scalar(clone.Derive("scalar", 320))
  I = [k]G 
  return (k, I)
```

This results in a commitment scalar which is derived from both the original protocol's state (i.e., domain string,
signer's public key, message) and the clone's later state (i.e., signer's private key).

A hedged variant would mix in a random value into the clone before derivation.

### Signcryption

A protocol can be used to integrate a [HPKE](#hybrid-public-key-encryption) scheme and
a [digital signature](#digital-signatures) scheme to produce a signcryption scheme, providing both confidentiality and
strong authentication in the public key setting:

```text
function Signcrypt(sender, receiver.pub, plaintext):
  ephemeral = P256::KeyGen()                      // Generate an ephemeral key pair.
  Init("com.example.sc")                          // Initialize a protocol with a domain string.
  Mix("receiver", receiver.pub)                   // Mix the receiver's public key into the protocol.
  Mix("sender", sender.pub)                       // Mix the sender's public key into the protocol.
  Mix("ephemeral", ephemeral.pub)                 // Mix the ephemeral public key into the protocol.
  Mix("ecdh", ECDH(receiver.pub, ephemeral.priv)) // Mix the ECDH shared secret into the protocol.
  ciphertext = Encrypt("message", plaintext)      // Encrypt the plaintext.
  (k, I) = P256::KeyGen()                         // Generate a commitment scalar and point.
  Mix("commitment", I)                            // Mix the commitment point into the protocol.
  r = P256::Scalar(Derive("challenge", 320))      // Derive a challenge scalar.
  s = sender.priv * r + k                         // Calculate the proof scalar.
  return (ephemeral.pub, ciphertext, I, s)        // Return the ephemeral public key, ciphertext, and signature.
```

```text
function Unsigncrypt(receiver, sender.pub, ephemeral.pub, ciphertext, I, s):
  Init("com.example.sc")                           // Initialize a protocol with a domain string.
  Mix("receiver", receiver.pub)                    // Mix the receiver's public key into the protocol.
  Mix("sender", sender.pub)                        // Mix the sender's public key into the protocol.
  Mix("ephemeral", ephemeral.pub)                  // Mix the ephemeral public key into the protocol.
  Mix("ecdh", ECDH(receiver.priv, ephemeral.pub))  // Mix the ECDH shared secret into the protocol.
  plaintext = Decrypt("message", ciphertext)       // Decrypt the ciphertext.
  Mix("commitment", I)                             // Mix the commitment point into the protocol.
   r' = P256::Scalar(Derive("challenge", 320))     // Derive an expected challenge scalar.
  I' = [s]G - [r']sender.pub                       // Calculate the expected commitment point.
  if I == I':
    return plaintext                               // If both points are equal, return the plaintext.
  else:
    return ErrInvalidCiphertext                    // Otherwise, return an error.
```

Because a Newplex protocol is an incremental, stateful way of building a cryptographic construction, this integrated
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
