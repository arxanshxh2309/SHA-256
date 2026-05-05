# 🔨 Hashforge

> SHA-256 from scratch — paired with a Merkle tree, an HMAC, and a working **length-extension attack** against `H(secret ‖ message)`. Pure Python, every variable named to match FIPS 180-4, every NIST test vector passing.

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-35%20passing-brightgreen.svg)](tests/)
[![Spec: FIPS 180-4](https://img.shields.io/badge/spec-FIPS%20180--4-orange.svg)](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf)

---

## Why?

SHA-256 is the most-used cryptographic primitive on Earth. It hashes every Bitcoin block, every Git commit, every TLS certificate, every Linux package. Most people who *use* it have never seen it compute. This repo is a 200-line, byte-faithful walkthrough — plus three real applications that show what the hash function lets you build (and how it can betray you if you use it wrong).

```
                       ┌───────────────────────────────┐
       message  ──────►│  pad to multiple of 512 bits  │
                       └───────────────┬───────────────┘
                                       │
                                       ▼
                ┌────────────────────────────────────────┐
        H[0..7] │  for each 64-byte block:                 │
       (H0 fixed│   1. expand to 64-word message schedule  │
        IV)  ──►│   2. run 64 rounds of compression        │ ──► 32-byte digest
                │   3. mix into chaining value H           │
                └────────────────────────────────────────┘
```

---

## ✨ What's in the box

| Module | What it does |
|---|---|
| **`hashforge.sha256`** | The core algorithm. Streaming + one-shot API, optional **trace recorder** that captures every message-schedule word and every round of working variables `a..h`. |
| **`hashforge.hmac`** | HMAC-SHA256 (RFC 2104) from scratch + constant-time tag verification. |
| **`hashforge.merkle`** | Binary Merkle tree with O(log n) inclusion proofs. RFC 6962 domain separation (`0x00` for leaves, `0x01` for nodes). |
| **`hashforge.length_extension`** | Forges `SHA256(secret ‖ msg ‖ glue ‖ extension)` from `SHA256(secret ‖ msg)` *without knowing the secret*. The textbook crypto attack. |

All four modules pass against `hashlib` / Python's stdlib `hmac` on hundreds of random inputs.

---

## ⚡ Quick start

### Install

```bash
git clone https://github.com/yourname/hashforge.git
cd hashforge
pip install -e .
```

### Library

```python
from hashforge import sha256, hmac_sha256, MerkleTree

sha256(b'abc').hex()
# 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'

hmac_sha256(b'key', b'message').hex()
# '6e9ef29b75fffc5b7abae527d58fdadb2fe42e7219011976917343065f58ed4a'

tree = MerkleTree.build([b'tx-1', b'tx-2', b'tx-3', b'tx-4'])
proof = tree.proof(2)
from hashforge import verify_proof
verify_proof(b'tx-3', 2, proof, tree.root)   # True
```

### Trace mode — see every round

```python
from hashforge import sha256, Trace

t = Trace()
sha256(b'abc', trace=t)

# t.blocks[0].message_schedule  → list of 64 32-bit words
# t.blocks[0].rounds            → list of 64 RoundSnapshots with a..h
# t.blocks[0].H_in / H_out      → state before/after the block
```

Or via the CLI:

```bash
$ hashforge trace abc --no-rounds
Message    : 'abc'
Padded len : 64 bytes (1 blocks)
Digest     : ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad

── Block 0 ──
  H_in : 6a09e667 bb67ae85 3c6ef372 a54ff53a 510e527f 9b05688c 1f83d9ab 5be0cd19
  W[0..63]:
    61626380 00000000 00000000 00000000 00000000 00000000 00000000 00000000
    00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000018
    61626380 000f0000 7da86405 600003c6 3e9d7b78 0183fc00 12dcbfdb e2e2c38e
    ...
  H_out: ba7816bf 8f01cfea 414140de 5dae2223 b00361a3 96177a9c b410ff61 f20015ad
```

These values are exactly the ones in **FIPS 180-4 Appendix B**. Match them yourself with the spec open on a second monitor.

---

## 💥 The length-extension attack

A naive server: "your message is `m`, the auth tag is `t = SHA256(K ‖ m)`. Trust nothing without the right tag." Surely a forger needs the secret `K`?

```python
from hashforge import sha256
from hashforge.length_extension import forge_extension

# Server's situation (the secret is unknown to the attacker):
secret = b'super-secret-do-not-tell'
original_msg = b'amount=10&to=alice'
public_tag   = sha256(secret + original_msg)

# Attacker only sees: original_msg, public_tag, and guesses len(secret)=24.
forge = forge_extension(
    original_tag   = public_tag,
    original_msg   = original_msg,
    secret_length  = 24,
    extension      = b'&amount=999999&to=mallory',
)

# The server, recomputing from its still-secret secret:
sha256(secret + forge.forged_message) == forge.forged_tag    # True ⚠
```

Why it works: SHA-256 is Merkle–Damgård. Its internal state after hashing X is *exactly* the state from which it would continue if you handed it more data. Once you know `SHA256(secret ‖ m)` you can resume the hash and append anything.

**Why HMAC fixes it:** HMAC wraps the inner hash with an outer one whose state the attacker can never recover from a published tag. The attack simply doesn't apply. The repo includes a test (`test_attack_fails_against_hmac`) that proves it.

This is the [Flickr API signature bug from 2009](https://netifera.com/research/flickr_api_signature_forgery.pdf). Many APIs have shipped the same flaw. It's why HMAC exists.

---

## 🧬 SHA-256, the algorithm

For a 1-block (≤55-byte) message:

```
   ┌── M (16 words from the padded message) ──┐
   │                                          │
   ▼                                          │
   message schedule:    W[0..15] = M[0..15]   │
                        W[t] = σ₁(W[t-2]) + W[t-7] + σ₀(W[t-15]) + W[t-16]   for t in 16..63
                                          │
   working variables:   a..h ← H_in        │
                                          │
   for t in 0..63:                         │
     T1 = h + Σ₁(e) + Ch(e,f,g) + K[t] + W[t]
     T2 = Σ₀(a) + Maj(a,b,c)
     h ← g; g ← f; f ← e; e ← d + T1
     d ← c; c ← b; b ← a; a ← T1 + T2
                                          │
   chaining update:     H_out = H_in + (a..h)   ◄── 32-byte digest
```

The four bit-twiddling functions:

```
Ch(x, y, z)  = (x ∧ y) ⊕ (¬x ∧ z)            choose
Maj(x, y, z) = (x ∧ y) ⊕ (x ∧ z) ⊕ (y ∧ z)    majority
Σ₀(x) = ROTR²(x)  ⊕ ROTR¹³(x) ⊕ ROTR²²(x)
Σ₁(x) = ROTR⁶(x)  ⊕ ROTR¹¹(x) ⊕ ROTR²⁵(x)
σ₀(x) = ROTR⁷(x)  ⊕ ROTR¹⁸(x) ⊕ SHR³(x)
σ₁(x) = ROTR¹⁷(x) ⊕ ROTR¹⁹(x) ⊕ SHR¹⁰(x)
```

`Ch` and `Maj` are the only non-linear operations in the whole function. Everything else is rotation and XOR. The avalanche behavior — flipping one input bit changes ~half the output bits — is engineered out of those rotations and the round constants `K`, which are themselves the fractional parts of the cube roots of the first 64 primes.

---

## 🌳 Merkle trees

A binary tree of hashes where every internal node is the hash of its children. The root is a 32-byte fingerprint of the entire data set; an O(log n) **inclusion proof** lets anyone confirm a specific item is in there without seeing the others.

```
          root = H( H(0x01 ‖ H_AB ‖ H_CD) )
         /                              \
    H_AB = H(0x01 ‖ H_A ‖ H_B)    H_CD = H(0x01 ‖ H_C ‖ H_D)
     /          \                    /          \
   H_A         H_B                  H_C         H_D
   = H(0x00‖A) = H(0x00‖B)          = H(0x00‖C) = H(0x00‖D)
```

The `0x00` / `0x01` prefixes are **domain separation** (RFC 6962): without them, an attacker could present an internal node `H(L ‖ R)` as if it were a leaf — a classic second-preimage flaw.

To prove `C` is in the tree without revealing `A`, `B`, or `D`, send the verifier `H_D` (right sibling) and `H_AB` (left sibling). They re-hash up the path and check the result matches the published root. **`O(log n)` verification, no trust required.**

---

## 🧪 Tests

```bash
pip install pytest
pytest -v
```

Coverage:

- All 5 NIST FIPS 180-4 / CAVP test vectors, including the canonical 1-million-`a`s.
- 500 random fuzz inputs against `hashlib.sha256`.
- Streaming with chunk sizes 1, 7, 13, 63, 64, 65, 127, 128, 1000.
- HMAC against Python stdlib (which is the RFC 2104 reference) on 100+ inputs.
- Merkle trees of size 1, 2, 3, 4, 5, 7, 8, 16, 17, 33 — every leaf in each.
- Length-extension actually forges, *and* fails against HMAC.

---

## 🌐 Interactive demo

`docs/demo.html` — open in any browser, no server needed. Type a message, watch SHA-256 padding take shape, then step through all 64 rounds and watch `a..h` evolve.

---

## ⚠ Disclaimer

This is **not** a production hash. Use `hashlib.sha256` (~50× faster, written in C, audited). The point of this repo is understanding what's happening *inside* `hashlib.sha256` — and where it can betray you (length extension!) when used naively.

---

## 📚 References

1. NIST **FIPS 180-4** (2015). *Secure Hash Standard.*
2. RFC 2104 (1997). *HMAC: Keyed-Hashing for Message Authentication.*
3. RFC 6962 (2013). *Certificate Transparency* — the Merkle tree spec we follow.
4. Duong & Rizzo, *Flickr API Signature Forgery Vulnerability* (2009).
5. Bitcoin developer guide, *Block headers* — practical Merkle root usage.

## 📝 License

MIT — see [LICENSE](LICENSE).
