# verkle-pq

[![CI](https://github.com/nuwrldnf8r/pq_verkle/actions/workflows/ci.yml/badge.svg)](https://github.com/nuwrldnf8r/pq_verkle/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/verkle_pq.svg)](https://crates.io/crates/verkle_pq)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**PQ-authenticated Verkle commitments** — a post-quantum authentication layer
built on top of [`quilibrium-verkle`](https://crates.io/crates/quilibrium-verkle):

1. **Signed commitments** — every root commitment is signed with
   [CRYSTALS-Dilithium3 (ML-DSA-65)](https://pq-crystals.org/dilithium/), a
   NIST-standardised lattice-based signature scheme.
2. **Bound proofs** — every proof carries a 64-byte SHAKE-256 binding tag
   that ties it to the exact commitment it was produced for, preventing
   replay attacks.
3. **Canonical key ordering** — `prove_multiple` always sorts keys
   lexicographically, so proof binding tags are invariant to call-site ordering.

---

## ⚠️  Security Notice

This library adds post-quantum *authentication* and *proof-binding* layers on
top of a classical Verkle tree. **The underlying KZG polynomial commitments
(BLS48-581) are not quantum-safe.** A sufficiently powerful quantum computer
running Shor's algorithm could, in principle, attack the elliptic-curve
discrete logarithm that KZG relies on.

What the PQ layers *do* provide:

| Threat | Protected? |
|---|---|
| Classical commitment forgery | ✅ (Dilithium3 signature) |
| Proof replay against a different commitment | ✅ (SHAKE-256 binding tag) |
| Quantum attack on the KZG commitment itself | ❌ (not addressed) |

In short: this library is a meaningful hardening step, especially for
systems that need long-term authenticity guarantees, but it is **not** a
fully post-quantum Verkle scheme. A complete solution would require
replacing KZG with a lattice-based or hash-based polynomial commitment —
which remains an active research area.

---

## Key sizes (Dilithium3)

| Artefact | Size |
|---|---|
| Public key | 1952 bytes |
| Secret key | 4000 bytes |
| Signature | 3293 bytes |
| Proof binding tag (SHAKE-256) | 64 bytes |

---

## Quick start

```toml
[dependencies]
verkle_pq = "0.1"
bls48581   = "2.1"   # must be initialised once before any tree operations
```

```rust
// Required once per process — initialises the BLS48-581 pairing library.
verkle_pq::init();

use verkle_pq::{DilithiumPubKey, PQVerkleTree};

let mut tree = PQVerkleTree::new();

// The public key you will distribute to verifiers.
let trusted_pk: DilithiumPubKey = tree.dilithium_pubkey();

tree.insert(b"name".to_vec(),  b"alice".to_vec()).unwrap();
tree.insert(b"score".to_vec(), b"9001".to_vec()).unwrap();

// Commit — returns a Dilithium3-signed root commitment.
let commitment = tree.commit().unwrap();

// Authenticated verification: supply the trusted public key.
// This is the correct way to verify — it rejects commitments signed
// by keys you don't trust (returns Err(PubkeyMismatch) on key mismatch).
assert!(commitment.verify_against_pubkey(&trusted_pk).unwrap());

// Single-key proof.
let proof = tree.prove(b"name").unwrap().expect("key exists");
let values = proof.verify_and_extract_with_pubkey(&commitment, &trusted_pk).unwrap();
assert_eq!(values[0], b"alice");

// Multi-key proof — keys are sorted canonically internally.
let mp = tree.prove_multiple(&[b"score".to_vec(), b"name".to_vec()]).unwrap();
let all = mp.verify_and_extract_with_pubkey(&commitment, &trusted_pk).unwrap();
// Values are returned in canonical (lexicographic) key order.
assert_eq!(all[0], b"alice"); // "name" sorts before "score"
assert_eq!(all[1], b"9001");
```

> **Self-consistency vs. authenticated verification**  
> `verify_embedded_key()` only checks that the commitment's embedded key
> matches the signature — an attacker can satisfy this by stapling their own
> key. Always call `verify_against_pubkey(&trusted_pk)` (or
> `verify_with_pubkey`) when security matters.

### Reusing an existing keypair

```rust
use verkle_pq::{PQKeypair, PQVerkleTree, DilithiumPubKey};

let keypair = PQKeypair::generate();
// Distribute this to verifiers (e.g., publish in your PKI / on-chain).
let trusted_pk = DilithiumPubKey(keypair.public_key_bytes().to_vec());

let mut tree = PQVerkleTree::with_keypair(keypair);
tree.insert(b"token".to_vec(), b"0xdeadbeef".to_vec()).unwrap();
let commitment = tree.commit().unwrap();

// Verifiers authenticate with the trusted key:
assert!(commitment.verify_against_pubkey(&trusted_pk).unwrap());
```

### Optional serde support

Enable the `serde` feature to get `Serialize`/`Deserialize` on `PQCommitment`
and `PQProof`:

```toml
[dependencies]
verkle_pq = { version = "0.1", features = ["serde"] }
```

---

## Architecture

```
verkle_pq
├── error.rs       — PqVerkleError (thiserror)
├── pq_hash.rs     — SHAKE-256 domain-separated hashing
├── pq_sign.rs     — PQKeypair (Dilithium3 keygen / sign / verify)
└── pq_verkle.rs   — PQVerkleTree, PQCommitment, PQProof
```

The library is a thin, zero-copy wrapper around `quilibrium-verkle`. The
inner `TraversalProof` and `VectorCommitmentTrie` types are unchanged; all
PQ work happens in the wrapper layer.

---

## Running the benchmark

Compare classical `quilibrium-verkle` vs `verkle_pq` on performance, commitment
size, and proof size:

```sh
cargo test bench_classical_vs_pq -- --ignored --nocapture
```

Sample output (debug build, Apple M-series, 10 keys):

```
╔══════════════════════════════════════════════════════════════════════╗
║         classical quilibrium_verkle  vs  verkle_pq (PQ-safe)        ║
║  Dataset: 10 key-value pairs, one proof per key                     ║
╠═══════════════════════════════╦══════════════╦══════════════╦═══════╣
║ Phase                         ║  Classical   ║   PQ-safe    ║  ×    ║
╠═══════════════════════════════╬══════════════╬══════════════╬═══════╣
║ Insert (10 keys)               ║     0.115 ms ║     1.339 ms ║ 11.69×║
║ Commit                        ║   515.568 ms ║   521.896 ms ║  1.01×║
║ Prove/key (avg)               ║  2109.968 ms ║  2099.627 ms ║  1.00×║
║ Prove total (10 keys)          ║ 21099.684 ms ║ 20996.265 ms ║  1.00×║
║ Verify/key (avg)              ║  2459.330 ms ║  2444.658 ms ║  0.99×║
╠═══════════════════════════════╬══════════════╬══════════════╬═══════╣
║ Commitment (raw KZG bytes)    ║        74 B  ║        74 B  ║  1.00×║
║ PQ signature (Dilithium3)     ║            — ║      3309 B  ║   N/A ║
║ PQ public key (embedded)      ║            — ║      1952 B  ║   N/A ║
║ Total commitment package      ║        74 B  ║      5335 B  ║ 72.09×║
╠═══════════════════════════════╬══════════════╬══════════════╬═══════╣
║ Proof bytes/key (avg)         ║       608 B  ║       608 B  ║  1.00×║
║ PQ binding tag/key (avg)      ║            — ║        64 B  ║   N/A ║
║ Total proof package/key (avg) ║       608 B  ║       672 B  ║  1.11×║
╚═══════════════════════════════╩══════════════╩══════════════╩═══════╝
```

The BLS48-581 KZG operations dominate completely; the Dilithium3 signing
and SHAKE-256 hashing add no measurable overhead to prove/verify.

---

## Running tests

```sh
# Fast unit tests (27 tests, ~68 s dominated by BLS48-581 pairing)
cargo test --features serde -- --test-threads=1

# Full suite including slow 60-key exhaustive test
cargo test --features serde -- --include-ignored --test-threads=1
```

---

## License

MIT — see [LICENSE](LICENSE).
