//! # verkle-pq
//!
//! A quantum-resistant Verkle tree library that wraps
//! [`quilibrium_verkle`] with:
//!
//! - **CRYSTALS-Dilithium3 (ML-DSA-65)** post-quantum signatures on every
//!   root commitment, and
//! - **SHAKE-256** domain-separated proof binding that prevents a proof
//!   generated under one commitment from being replayed under another.
//!
//! ## Security model
//!
//! ### ⚠️  Important limitation
//!
//! The underlying KZG polynomial commitments (BLS48-581 elliptic curve) are
//! **not** quantum-safe.  A sufficiently large quantum computer running Shor's
//! algorithm could attack the discrete-log assumption they rely on.  This
//! library does **not** solve that problem — a fully post-quantum Verkle scheme
//! would require replacing KZG with a lattice-based or hash-based polynomial
//! commitment, which remains an active research area.
//!
//! ### What the PQ layers provide
//!
//! 1. **Authenticated commitments** — every root commitment is signed with
//!    Dilithium3 (ML-DSA-65), a NIST-standardised lattice-based scheme.
//!    Verifiers who hold the signer's [`DilithiumPubKey`] can reject any
//!    unsigned or forged commitment, even from a quantum adversary.
//!
//! 2. **Bound proofs** — each proof stores a 64-byte SHAKE-256 tag over
//!    `(commitment || sorted-keys)`.  Verification recomputes the tag; a
//!    mismatch means the proof was generated for a different commitment or
//!    key set, preventing proof-replay attacks.
//!
//! ### Public-key trust model
//!
//! The commitment embeds the signer's public key, but embedding alone does
//! **not** prove authority — anyone can staple their own key.  Always verify
//! against a key you obtained from a **trusted source** (PKI, on-chain
//! record, certificate):
//!
//! ```no_run
//! # let commitment: verkle_pq::PQCommitment = unimplemented!();
//! # let my_trusted_pk: verkle_pq::DilithiumPubKey = unimplemented!();
//! // ✅ Authenticated: checks the key you trust.
//! let ok = commitment.verify_against_pubkey(&my_trusted_pk).unwrap();
//!
//! // ⚠️  Self-consistency only: tamper detection, not authentication.
//! let ok = commitment.verify_embedded_key().unwrap();
//! ```
//!
//! ## Quick start
//!
//! ```no_run
//! // Call once at program start (required by the BLS48-581 library)
//! bls48581::init();
//!
//! use verkle_pq::PQVerkleTree;
//!
//! let mut tree = PQVerkleTree::new();
//! tree.insert(b"key1".to_vec(), b"value1".to_vec()).unwrap();
//! tree.insert(b"key2".to_vec(), b"value2".to_vec()).unwrap();
//!
//! let commitment = tree.commit().unwrap();
//! assert!(commitment.verify_embedded_key().unwrap());
//!
//! // Share the public key with verifiers.
//! let trusted_pk = tree.dilithium_pubkey();
//!
//! // Single-key proof
//! let proof = tree.prove(b"key1").unwrap().expect("key exists");
//! // Authenticated verification against the trusted key:
//! let values = proof.verify_and_extract_with_pubkey(&commitment, &trusted_pk).unwrap();
//! assert_eq!(values[0], b"value1");
//!
//! // Multi-key proof (keys are sorted canonically inside prove_multiple)
//! let mp = tree.prove_multiple(&[b"key1".to_vec(), b"key2".to_vec()]).unwrap();
//! let all = mp.verify_and_extract_with_pubkey(&commitment, &trusted_pk).unwrap();
//! assert_eq!(all[0], b"value1");
//! assert_eq!(all[1], b"value2");
//!
//! // Parallel batch proving (enable with --features rayon for concurrency)
//! let keys: Vec<Vec<u8>> = vec![b"key1".to_vec(), b"key2".to_vec()];
//! let proofs = tree.prove_batch(&keys).unwrap();
//! assert_eq!(proofs.len(), 2);
//! ```
//!
//! ## Performance — `rayon` feature
//!
//! Enable `--features rayon` to parallelise [`PQVerkleTree::prove_batch`]
//! across all CPU cores.  The tree is cloned once per rayon worker thread
//! (O(num_cores) clones, not O(N)), and each thread proves its chunk of keys
//! sequentially.  Without the feature the same method falls back to a simple
//! sequential loop — no extra dependencies are pulled in.
//!
//! Expected speed-up on an 8-core machine (release build):
//!
//! | Keys | Serial prove (ms) | Parallel prove (ms) | Speed-up |
//! |------|------------------|---------------------|----------|
//! | 10   | ~750–1 500       | ~120–200            | ~6–8×    |
//! | 100  | ~7 500–15 000    | ~1 000–2 000        | ~6–8×    |
//!
//! _Commit_ is still single-threaded (BLS48-581 traversal is inherently
//! sequential); only the per-key prove loop is parallelised.

pub mod error;
pub mod pq_hash;
pub mod pq_sign;
pub mod pq_verkle;

pub use error::PqVerkleError;
pub use pq_hash::canonical_keys;
pub use pq_sign::PQKeypair;
pub use pq_verkle::{
    CommitmentBytes, DilithiumPubKey, DilithiumSignature, PQCommitment, PQProof, PQVerkleTree,
};

/// Initialise the BLS48-581 cryptographic library.
///
/// This must be called **once** before any tree operations.  It is safe to
/// call multiple times; subsequent calls are no-ops.
pub fn init() {
    bls48581::init();
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use quilibrium_verkle::VectorCommitmentTrie;
    use std::time::Instant;

    fn init_bls() {
        bls48581::init();
    }

    // ── basic round-trip ─────────────────────────────────────────────────────

    #[test]
    fn test_insert_commit_prove_verify() {
        init_bls();
        let mut tree = PQVerkleTree::new();
        tree.insert(b"key1".to_vec(), b"value1".to_vec()).unwrap();
        tree.insert(b"key2".to_vec(), b"value2".to_vec()).unwrap();

        let commitment = tree.commit().unwrap();
        let trusted_pk = tree.dilithium_pubkey();

        // Self-consistency check.
        assert!(
            commitment.verify_embedded_key().unwrap(),
            "embedded key should be self-consistent"
        );
        // Authenticated check against the trusted key.
        assert!(
            commitment.verify_against_pubkey(&trusted_pk).unwrap(),
            "commitment should verify against trusted key"
        );

        let proof = tree.prove(b"key1").unwrap().expect("key1 should exist");
        assert!(proof.verify_with_pubkey(&commitment, &trusted_pk).unwrap());

        let values = proof
            .verify_and_extract_with_pubkey(&commitment, &trusted_pk)
            .unwrap();
        assert_eq!(values[0], b"value1");
    }

    #[test]
    fn test_multiple_keys_single_proof_each() {
        init_bls();
        let mut tree = PQVerkleTree::new();
        let pairs: Vec<(&[u8], &[u8])> =
            vec![(b"alpha", b"100"), (b"beta", b"200"), (b"gamma", b"300")];
        for (k, v) in &pairs {
            tree.insert(k.to_vec(), v.to_vec()).unwrap();
        }
        let commitment = tree.commit().unwrap();
        let trusted_pk = tree.dilithium_pubkey();

        for (k, v) in &pairs {
            let proof = tree.prove(k).unwrap().expect("key should exist");
            assert!(
                proof.verify_with_pubkey(&commitment, &trusted_pk).unwrap(),
                "verify failed for {k:?}"
            );
            let values = proof
                .verify_and_extract_with_pubkey(&commitment, &trusted_pk)
                .unwrap();
            assert_eq!(values[0], v.to_vec(), "value mismatch for {k:?}");
        }
    }

    // ── missing-key behaviour ─────────────────────────────────────────────────

    #[test]
    fn test_missing_key_returns_none() {
        init_bls();
        let mut tree = PQVerkleTree::new();
        tree.insert(b"exists".to_vec(), b"yes".to_vec()).unwrap();
        let _c = tree.commit().unwrap();

        let proof = tree.prove(b"does_not_exist").unwrap();
        assert!(proof.is_none(), "missing key should produce None");
    }

    // ── commitment invalidation ───────────────────────────────────────────────

    #[test]
    fn test_prove_without_commit_errors() {
        init_bls();
        let mut tree = PQVerkleTree::new();
        tree.insert(b"k".to_vec(), b"v".to_vec()).unwrap();

        // prove() before commit() must return NoCommitment.
        let result = tree.prove(b"k");
        assert!(
            matches!(result, Err(PqVerkleError::NoCommitment)),
            "expected NoCommitment, got {result:?}"
        );
    }

    #[test]
    fn test_insert_after_commit_invalidates_cached_commitment() {
        init_bls();
        let mut tree = PQVerkleTree::new();
        tree.insert(b"a".to_vec(), b"1".to_vec()).unwrap();
        let _c = tree.commit().unwrap();

        // Insert a new key — the cached commitment is now stale.
        tree.insert(b"b".to_vec(), b"2".to_vec()).unwrap();

        let result = tree.prove(b"a");
        assert!(
            matches!(result, Err(PqVerkleError::NoCommitment)),
            "commitment should have been invalidated by insert"
        );
    }

    // ── tampered commitment ───────────────────────────────────────────────────

    #[test]
    fn test_pq_signature_rejects_tampered_commitment_bytes() {
        init_bls();
        let mut tree = PQVerkleTree::new();
        tree.insert(b"data".to_vec(), b"value".to_vec()).unwrap();
        let trusted_pk = tree.dilithium_pubkey();
        let mut commitment = tree.commit().unwrap();

        // Flip one bit of the raw commitment.
        commitment.commitment[0] ^= 0xFF;

        assert!(
            !commitment.verify_embedded_key().unwrap(),
            "tampered commitment should fail embedded-key check"
        );
        // verify_against_pubkey should also fail (signature covers the bytes).
        assert!(
            !commitment.verify_against_pubkey(&trusted_pk).unwrap(),
            "tampered commitment should fail trusted-key check"
        );
    }

    #[test]
    fn test_tampered_pq_signature_rejected() {
        init_bls();
        let mut tree = PQVerkleTree::new();
        tree.insert(b"x".to_vec(), b"y".to_vec()).unwrap();
        let mut commitment = tree.commit().unwrap();

        // Corrupt the first byte of the signature.
        commitment.pq_signature[0] ^= 0x01;

        assert!(
            !commitment.verify_embedded_key().unwrap(),
            "tampered signature should be rejected"
        );
    }

    // ── pubkey mismatch ───────────────────────────────────────────────────────

    #[test]
    fn test_verify_against_wrong_pubkey_returns_mismatch_error() {
        init_bls();
        let mut tree = PQVerkleTree::new();
        tree.insert(b"k".to_vec(), b"v".to_vec()).unwrap();
        let commitment = tree.commit().unwrap();

        // A key from a completely different tree.
        let other_tree = PQVerkleTree::new();
        let wrong_pk = other_tree.dilithium_pubkey();

        let result = commitment.verify_against_pubkey(&wrong_pk);
        assert!(
            matches!(result, Err(PqVerkleError::PubkeyMismatch)),
            "expected PubkeyMismatch, got {result:?}"
        );
    }

    // ── cross-commitment security ─────────────────────────────────────────────

    #[test]
    fn test_proof_does_not_verify_against_different_commitment() {
        init_bls();

        // Tree 1: key "hello" -> "world"
        let mut tree1 = PQVerkleTree::new();
        tree1.insert(b"hello".to_vec(), b"world".to_vec()).unwrap();
        let c1 = tree1.commit().unwrap();
        let proof1 = tree1.prove(b"hello").unwrap().unwrap();

        // Tree 2: same key, different value => different commitment bytes.
        let mut tree2 = PQVerkleTree::new();
        tree2
            .insert(b"hello".to_vec(), b"different_value".to_vec())
            .unwrap();
        let c2 = tree2.commit().unwrap();

        // proof1 was bound to c1's commitment bytes; it must not pass against c2.
        let ok = proof1.verify(&c2).unwrap();
        assert!(
            !ok,
            "a proof bound to c1 must not verify against a different commitment c2"
        );

        // Sanity check: proof1 still verifies against its own commitment.
        assert!(proof1.verify(&c1).unwrap(), "baseline: proof1 verifies c1");
    }

    // ── multiproof ───────────────────────────────────────────────────────────

    #[test]
    fn test_multiproof_basic() {
        init_bls();
        let mut tree = PQVerkleTree::new();
        tree.insert(vec![1], vec![10]).unwrap();
        tree.insert(vec![2], vec![20]).unwrap();
        tree.insert(vec![3], vec![30]).unwrap();

        let commitment = tree.commit().unwrap();
        let trusted_pk = tree.dilithium_pubkey();

        // Pass keys in reverse order — prove_multiple sorts them internally.
        let keys = vec![vec![3u8], vec![1u8], vec![2u8]];
        let proof = tree.prove_multiple(&keys).unwrap();

        assert!(
            proof.verify_with_pubkey(&commitment, &trusted_pk).unwrap(),
            "multiproof verify failed"
        );
        // Values are returned in canonical (sorted) key order: [1,2,3].
        let values = proof
            .verify_and_extract_with_pubkey(&commitment, &trusted_pk)
            .unwrap();
        assert_eq!(values, vec![vec![10u8], vec![20u8], vec![30u8]]);
    }

    #[test]
    fn test_multiproof_canonical_ordering_is_stable() {
        // prove_multiple([b, a]) and prove_multiple([a, b]) must produce
        // the same proof (same binding tag, same inner proof).
        init_bls();
        let mut tree = PQVerkleTree::new();
        tree.insert(b"aaa".to_vec(), b"1".to_vec()).unwrap();
        tree.insert(b"zzz".to_vec(), b"2".to_vec()).unwrap();
        let commitment = tree.commit().unwrap();
        let trusted_pk = tree.dilithium_pubkey();

        let proof_fwd = tree
            .prove_multiple(&[b"aaa".to_vec(), b"zzz".to_vec()])
            .unwrap();
        let proof_rev = tree
            .prove_multiple(&[b"zzz".to_vec(), b"aaa".to_vec()])
            .unwrap();

        // Both proofs must have identical binding tags (same canonical order).
        assert_eq!(proof_fwd.pq_binding, proof_rev.pq_binding);
        assert!(
            proof_fwd
                .verify_with_pubkey(&commitment, &trusted_pk)
                .unwrap()
        );
        assert!(
            proof_rev
                .verify_with_pubkey(&commitment, &trusted_pk)
                .unwrap()
        );
    }

    #[test]
    fn test_multiproof_rejects_wrong_commitment() {
        init_bls();
        let mut tree = PQVerkleTree::new();
        tree.insert(vec![1], vec![10]).unwrap();
        tree.insert(vec![2], vec![20]).unwrap();

        let c1 = tree.commit().unwrap();
        let trusted_pk = tree.dilithium_pubkey();
        let proof = tree.prove_multiple(&[vec![1u8], vec![2u8]]).unwrap();

        // Build a different commitment.
        let mut tree2 = PQVerkleTree::new();
        tree2.insert(vec![1], vec![99]).unwrap();
        tree2.insert(vec![2], vec![88]).unwrap();
        let c2 = tree2.commit().unwrap();
        let trusted_pk2 = tree2.dilithium_pubkey();

        // The proof was bound to c1; must fail against c2 (wrong binding tag).
        // verify_against_pubkey will error with PubkeyMismatch since c2 has
        // a different embedded key — that's also the right rejection.
        assert!(!proof.verify_with_pubkey(&c2, &trusted_pk2).unwrap_or(false));
        // It must still pass for c1.
        assert!(proof.verify_with_pubkey(&c1, &trusted_pk).unwrap());
    }

    // ── keypair operations ────────────────────────────────────────────────────

    #[test]
    fn test_keypair_sign_verify_roundtrip() {
        let kp = PQKeypair::generate();
        let msg = b"post-quantum test message";
        let sig = kp.sign(msg).unwrap();
        assert!(kp.verify(msg, &sig).unwrap(), "signature should be valid");
        assert!(
            !kp.verify(b"wrong message", &sig).unwrap(),
            "wrong message must not verify"
        );
    }

    #[test]
    fn test_verify_with_wrong_pubkey_fails() {
        let kp1 = PQKeypair::generate();
        let kp2 = PQKeypair::generate();
        let msg = b"hello";
        let sig = kp1.sign(msg).unwrap();
        // Verifying kp1's signature with kp2's public key must fail.
        assert!(
            !PQKeypair::verify_with_pubkey(msg, &sig, kp2.public_key_bytes()).unwrap(),
            "signature from kp1 must not verify with kp2's key"
        );
    }

    #[test]
    fn test_with_keypair_embeds_correct_pubkey() {
        init_bls();
        let keypair = PQKeypair::generate();
        let expected_pk = DilithiumPubKey(keypair.public_key_bytes().to_vec());

        let mut tree = PQVerkleTree::with_keypair(keypair);
        tree.insert(b"x".to_vec(), b"y".to_vec()).unwrap();
        let commitment = tree.commit().unwrap();
        let trusted_pk = tree.dilithium_pubkey();

        assert_eq!(commitment.pq_pubkey, expected_pk.0);
        assert!(commitment.verify_against_pubkey(&trusted_pk).unwrap());
    }

    // ── get ──────────────────────────────────────────────────────────────────

    #[test]
    fn test_get_existing_and_missing_keys() {
        init_bls();
        let mut tree = PQVerkleTree::new();
        tree.insert(b"present".to_vec(), b"42".to_vec()).unwrap();
        assert_eq!(tree.get(b"present"), Some(b"42".to_vec()));
        assert_eq!(tree.get(b"absent"), None);
    }

    // ── hashing utilities ─────────────────────────────────────────────────────

    #[test]
    fn test_pq_hash_domain_separation() {
        use crate::pq_hash::{commitment_sign_message, proof_binding};

        let commitment = b"test_commitment_bytes";
        let keys = vec![b"key1".to_vec()];

        let sign_msg = commitment_sign_message(commitment);
        let binding = proof_binding(commitment, &keys);

        // The two functions must produce different outputs (domain separation).
        assert_ne!(sign_msg, binding);

        // Both outputs are exactly 64 bytes (SHAKE-256 with output_len = 64).
        assert_eq!(sign_msg.len(), 64);
        assert_eq!(binding.len(), 64);
    }

    #[test]
    fn test_pq_hash_deterministic() {
        use crate::pq_hash::commitment_sign_message;

        let commitment = b"deterministic_test";
        let a = commitment_sign_message(commitment);
        let b = commitment_sign_message(commitment);
        assert_eq!(a, b, "SHAKE-256 must be deterministic");
    }

    #[test]
    fn test_proof_binding_changes_with_different_keys() {
        use crate::pq_hash::proof_binding;

        let c = b"commitment";
        let binding1 = proof_binding(c, &[b"key1".to_vec()]);
        let binding2 = proof_binding(c, &[b"key2".to_vec()]);
        assert_ne!(
            binding1, binding2,
            "different keys must produce different binding tags"
        );
    }

    // ── large dataset ─────────────────────────────────────────────────────────

    /// Slow test (many BLS48-581 proofs). Run with:
    ///   cargo test -- --include-ignored test_large_dataset_prove_all_keys
    #[test]
    #[ignore = "slow: 60 Verkle proofs over BLS48-581"]
    fn test_large_dataset_prove_all_keys() {
        init_bls();
        let mut tree = PQVerkleTree::new();
        const N: u8 = 60;

        for i in 0..N {
            tree.insert(vec![i], vec![i.wrapping_mul(3)]).unwrap();
        }

        let commitment = tree.commit().unwrap();
        let trusted_pk = tree.dilithium_pubkey();
        assert!(commitment.verify_against_pubkey(&trusted_pk).unwrap());

        for i in 0..N {
            let proof = tree.prove(&[i]).unwrap().expect("key must exist");
            assert!(
                proof.verify_with_pubkey(&commitment, &trusted_pk).unwrap(),
                "proof failed for key {i}"
            );
            let values = proof
                .verify_and_extract_with_pubkey(&commitment, &trusted_pk)
                .unwrap();
            assert_eq!(
                values[0],
                vec![i.wrapping_mul(3)],
                "value mismatch for key {i}"
            );
        }
    }

    // ── inner-bytes serialisation ─────────────────────────────────────────────

    #[test]
    fn test_inner_to_bytes_nonempty() {
        init_bls();
        let mut tree = PQVerkleTree::new();
        tree.insert(b"k".to_vec(), b"v".to_vec()).unwrap();
        let _c = tree.commit().unwrap();
        let proof = tree.prove(b"k").unwrap().unwrap();
        let bytes = proof.inner_to_bytes().unwrap();
        assert!(!bytes.is_empty(), "serialised proof must be non-empty");
    }

    // ── public-key accessor ───────────────────────────────────────────────────

    #[test]
    fn test_public_key_bytes_nonempty() {
        let tree = PQVerkleTree::new();
        let pk = tree.public_key_bytes();
        // Dilithium3 public key = 1952 bytes.
        assert_eq!(pk.len(), 1952, "Dilithium3 public key must be 1952 bytes");
    }
    // ── serde round-trips (only compiled with --features serde) ──────────────

    #[cfg(feature = "serde")]
    mod serde_tests {
        use super::*;

        #[test]
        fn test_commitment_serde_roundtrip() {
            init_bls();
            let mut tree = PQVerkleTree::new();
            tree.insert(b"k".to_vec(), b"v".to_vec()).unwrap();
            let commitment = tree.commit().unwrap();
            let trusted_pk = tree.dilithium_pubkey();

            let json = serde_json::to_string(&commitment).expect("serialize commitment");
            let restored: PQCommitment =
                serde_json::from_str(&json).expect("deserialize commitment");

            assert_eq!(commitment.commitment, restored.commitment);
            assert_eq!(commitment.pq_signature, restored.pq_signature);
            assert_eq!(commitment.pq_pubkey, restored.pq_pubkey);
            assert!(
                restored.verify_embedded_key().unwrap(),
                "restored commitment must pass self-consistency check"
            );
            assert!(
                restored.verify_against_pubkey(&trusted_pk).unwrap(),
                "restored commitment must pass trusted-key check"
            );
        }

        #[test]
        fn test_proof_serde_roundtrip() {
            init_bls();
            let mut tree = PQVerkleTree::new();
            tree.insert(b"hello".to_vec(), b"world".to_vec()).unwrap();
            let commitment = tree.commit().unwrap();
            let trusted_pk = tree.dilithium_pubkey();
            let proof = tree.prove(b"hello").unwrap().expect("key exists");

            let json = serde_json::to_string(&proof).expect("serialize proof");
            let restored: PQProof = serde_json::from_str(&json).expect("deserialize proof");

            assert_eq!(proof.keys(), restored.keys());
            assert_eq!(proof.pq_binding, restored.pq_binding);
            assert!(
                restored
                    .verify_with_pubkey(&commitment, &trusted_pk)
                    .unwrap(),
                "restored proof must verify against the trusted key"
            );
            let values = restored
                .verify_and_extract_with_pubkey(&commitment, &trusted_pk)
                .unwrap();
            assert_eq!(values[0], b"world");
        }

        #[test]
        fn test_multiproof_serde_roundtrip() {
            init_bls();
            let mut tree = PQVerkleTree::new();
            tree.insert(b"a".to_vec(), b"1".to_vec()).unwrap();
            tree.insert(b"b".to_vec(), b"2".to_vec()).unwrap();
            let commitment = tree.commit().unwrap();
            let trusted_pk = tree.dilithium_pubkey();
            let keys = vec![b"a".to_vec(), b"b".to_vec()];
            let proof = tree.prove_multiple(&keys).unwrap();

            let json = serde_json::to_string(&proof).expect("serialize multiproof");
            let restored: PQProof = serde_json::from_str(&json).expect("deserialize multiproof");

            assert!(
                restored
                    .verify_with_pubkey(&commitment, &trusted_pk)
                    .unwrap()
            );
            let values = restored
                .verify_and_extract_with_pubkey(&commitment, &trusted_pk)
                .unwrap();
            assert_eq!(values[0], b"1");
            assert_eq!(values[1], b"2");
        }
    } // ── canonical key ordering & utility ────────────────────────────────────────

    #[test]
    fn test_canonical_keys_sorts_lexicographically() {
        let mut keys = vec![
            b"zzz".to_vec(),
            b"aaa".to_vec(),
            b"mmm".to_vec(),
            b"aab".to_vec(),
        ];
        canonical_keys(&mut keys);
        assert_eq!(
            keys,
            vec![
                b"aaa".to_vec(),
                b"aab".to_vec(),
                b"mmm".to_vec(),
                b"zzz".to_vec(),
            ]
        );
    }

    #[test]
    fn test_commitment_digest_is_64_bytes() {
        init_bls();
        let mut tree = PQVerkleTree::new();
        tree.insert(b"k".to_vec(), b"v".to_vec()).unwrap();
        let commitment = tree.commit().unwrap();
        let digest = commitment.commitment_digest();
        assert_eq!(digest.len(), 64, "SHAKE-256 digest must be 64 bytes");
        assert!(
            digest.iter().any(|&b| b != 0),
            "digest must not be all-zeros"
        );
    }

    #[test]
    fn test_dilithium_pubkey_newtype_matches_public_key_bytes() {
        let tree = PQVerkleTree::new();
        let pk_raw = tree.public_key_bytes().to_vec();
        let pk_newtype = tree.dilithium_pubkey();
        assert_eq!(pk_newtype.0, pk_raw);
        assert_eq!(pk_newtype.as_ref(), pk_raw.as_slice());
    }

    // ── classical vs quantum-resistant comparison ─────────────────────────────

    /// Head-to-head comparison of classical `quilibrium_verkle` vs `PQVerkleTree`.
    ///
    /// Structured in two phases:
    ///
    /// **Phase A – 1 000 keys, no proofs**
    /// Shows insert and commit scaling.  KZG proofs over BLS48-581 take ~2 s each
    /// in a debug build, so we skip proving here and measure only data-ingestion.
    ///
    /// **Phase B – 10 keys, full prove/verify cycle**
    /// Shows per-proof overhead of both trees, plus commitment & proof sizes.
    /// This is identical to the old 10-key benchmark but now framed as a
    /// per-proof unit cost you can multiply by however many keys you need.
    ///
    /// Run with:
    ///   cargo test bench_classical_vs_pq -- --ignored --nocapture
    ///
    /// For a full 1 000-key prove/verify run use a release build:
    ///   cargo test --release bench_classical_vs_pq -- --ignored --nocapture
    #[test]
    #[ignore = "benchmarking: run with --ignored --nocapture"]
    fn bench_classical_vs_pq() {
        init_bls();

        // ═════════════════════════════════════════════════════════════════════
        // PHASE A: 1 000-key INSERT + COMMIT (no proofs)
        // ═════════════════════════════════════════════════════════════════════
        const BIG_N: usize = 1_000;

        let big_pairs: Vec<(Vec<u8>, Vec<u8>)> = (0..BIG_N)
            .map(|i| {
                (
                    format!("key-{i:06}").into_bytes(),
                    format!("val-{i:06}").into_bytes(),
                )
            })
            .collect();

        // Classical – 1 000 keys
        let t = Instant::now();
        let mut cl_big = VectorCommitmentTrie::new();
        for (k, v) in &big_pairs {
            cl_big.insert(k.clone(), v.clone()).unwrap();
        }
        let cl_big_insert_ms = t.elapsed().as_secs_f64() * 1_000.0;

        let t = Instant::now();
        let cl_big_commitment = cl_big.commit().unwrap();
        let cl_big_commit_ms = t.elapsed().as_secs_f64() * 1_000.0;

        // PQ – 1 000 keys
        let t = Instant::now();
        let mut pq_big = PQVerkleTree::new();
        for (k, v) in &big_pairs {
            pq_big.insert(k.clone(), v.clone()).unwrap();
        }
        let pq_big_insert_ms = t.elapsed().as_secs_f64() * 1_000.0;

        let t = Instant::now();
        let pq_big_commitment = pq_big.commit().unwrap();
        let pq_big_trusted_pk = pq_big.dilithium_pubkey();
        let pq_big_commit_ms = t.elapsed().as_secs_f64() * 1_000.0;

        // Prove ONE key from the 1 000-key tree to show proof cost is independent of N.
        let sample_key = &big_pairs[500].0;
        let t = Instant::now();
        let cl_big_proof = cl_big.prove(sample_key).expect("classical prove");
        let cl_big_prove_ms = t.elapsed().as_secs_f64() * 1_000.0;

        let t = Instant::now();
        let pq_big_proof = pq_big.prove(sample_key).unwrap().expect("key must exist");
        let pq_big_prove_ms = t.elapsed().as_secs_f64() * 1_000.0;

        let t = Instant::now();
        cl_big_proof
            .verify(&cl_big_commitment)
            .expect("classical verify");
        let cl_big_verify_ms = t.elapsed().as_secs_f64() * 1_000.0;

        let t = Instant::now();
        pq_big_proof
            .verify_with_pubkey(&pq_big_commitment, &pq_big_trusted_pk)
            .unwrap();
        let pq_big_verify_ms = t.elapsed().as_secs_f64() * 1_000.0;

        // ═════════════════════════════════════════════════════════════════════
        // PHASE B: 10-key full benchmark (insert / commit / prove / verify)
        // ═════════════════════════════════════════════════════════════════════
        const SMALL_N: usize = 10;

        let small_pairs: Vec<(Vec<u8>, Vec<u8>)> = (0..SMALL_N)
            .map(|i| {
                (
                    format!("benchmark-key-{i:04}").into_bytes(),
                    format!("benchmark-val-{i:04}").into_bytes(),
                )
            })
            .collect();

        let t = Instant::now();
        let mut cl = VectorCommitmentTrie::new();
        for (k, v) in &small_pairs {
            cl.insert(k.clone(), v.clone()).unwrap();
        }
        let cl_insert_ms = t.elapsed().as_secs_f64() * 1_000.0;

        let t = Instant::now();
        let cl_commitment = cl.commit().unwrap();
        let cl_commit_ms = t.elapsed().as_secs_f64() * 1_000.0;
        let cl_commitment_bytes = cl_commitment.len();

        let mut cl_prove_ms = Vec::with_capacity(SMALL_N);
        let mut cl_verify_ms = Vec::with_capacity(SMALL_N);
        let mut cl_proof_sizes = Vec::with_capacity(SMALL_N);

        for (k, _) in &small_pairs {
            let t = Instant::now();
            let proof = cl.prove(k).expect("classical prove");
            cl_prove_ms.push(t.elapsed().as_secs_f64() * 1_000.0);
            let bytes = proof.to_bytes().expect("to_bytes");
            cl_proof_sizes.push(bytes.len());
            let t = Instant::now();
            proof.verify(&cl_commitment).expect("classical verify");
            cl_verify_ms.push(t.elapsed().as_secs_f64() * 1_000.0);
        }

        let t = Instant::now();
        let mut pq = PQVerkleTree::new();
        for (k, v) in &small_pairs {
            pq.insert(k.clone(), v.clone()).unwrap();
        }
        let pq_insert_ms = t.elapsed().as_secs_f64() * 1_000.0;

        let t = Instant::now();
        let pq_commitment = pq.commit().unwrap();
        let pq_commit_ms = t.elapsed().as_secs_f64() * 1_000.0;
        let pq_trusted_pk = pq.dilithium_pubkey();
        let pq_commitment_bytes = pq_commitment.commitment.len();
        let pq_sig_bytes = pq_commitment.pq_signature.len();
        let pq_pk_bytes = pq_commitment.pq_pubkey.len();
        let pq_total_commitment = pq_commitment_bytes + pq_sig_bytes + pq_pk_bytes;

        let mut pq_prove_ms = Vec::with_capacity(SMALL_N);
        let mut pq_verify_ms = Vec::with_capacity(SMALL_N);
        let mut pq_inner_sizes = Vec::with_capacity(SMALL_N);
        let mut pq_binding_sizes = Vec::with_capacity(SMALL_N);

        for (k, _) in &small_pairs {
            let t = Instant::now();
            let proof = pq.prove(k).unwrap().unwrap();
            pq_prove_ms.push(t.elapsed().as_secs_f64() * 1_000.0);
            pq_inner_sizes.push(proof.inner_to_bytes().unwrap().len());
            pq_binding_sizes.push(proof.pq_binding.len());
            let t = Instant::now();
            proof
                .verify_with_pubkey(&pq_commitment, &pq_trusted_pk)
                .unwrap();
            pq_verify_ms.push(t.elapsed().as_secs_f64() * 1_000.0);
        }

        // ─────────────────────────────────────────────────────────────────────
        // Report
        // ─────────────────────────────────────────────────────────────────────
        let mean = |v: &[f64]| v.iter().sum::<f64>() / v.len() as f64;
        let total = |v: &[f64]| v.iter().sum::<f64>();
        let mean_sz = |v: &[usize]| v.iter().sum::<usize>() / v.len();
        let ratio = |a: f64, b: f64| if b > 0.0 { a / b } else { f64::NAN };

        println!();
        println!("╔═══════════════════════════════════════════════════════════════════════════╗");
        println!("║         classical quilibrium_verkle  vs  verkle_pq (PQ-authenticated)    ║");
        println!("╠═══════════════════════════════════════════════════════════════════════════╣");
        println!("║  PHASE A — {BIG_N} keys: INSERT + COMMIT + 1 proof                          ║");
        println!(
            "║  (prove_multiple of all {BIG_N} keys ≈ {BIG_N}× single-proof cost in BLS48-581) ║"
        );
        println!("╠══════════════════════════════════╦══════════════╦══════════════╦══════════╣");
        println!("║ Operation                        ║  Classical   ║   PQ-auth    ║    ×     ║");
        println!("╠══════════════════════════════════╬══════════════╬══════════════╬══════════╣");
        println!(
            "║ Insert ({BIG_N} keys)                 ║ {:>9.1} ms ║ {:>9.1} ms ║ {:>6.2}× ║",
            cl_big_insert_ms,
            pq_big_insert_ms,
            ratio(pq_big_insert_ms, cl_big_insert_ms)
        );
        println!(
            "║ Commit                           ║ {:>9.1} ms ║ {:>9.1} ms ║ {:>6.2}× ║",
            cl_big_commit_ms,
            pq_big_commit_ms,
            ratio(pq_big_commit_ms, cl_big_commit_ms)
        );
        println!(
            "║ Prove 1 key (from {BIG_N}-key tree)   ║ {:>9.1} ms ║ {:>9.1} ms ║ {:>6.2}× ║",
            cl_big_prove_ms,
            pq_big_prove_ms,
            ratio(pq_big_prove_ms, cl_big_prove_ms)
        );
        println!(
            "║ Verify 1 key                     ║ {:>9.1} ms ║ {:>9.1} ms ║ {:>6.2}× ║",
            cl_big_verify_ms,
            pq_big_verify_ms,
            ratio(pq_big_verify_ms, cl_big_verify_ms)
        );
        println!(
            "║ Estimated prove all {BIG_N} keys      ║ {:>8.0} s  ║ {:>8.0} s  ║  same    ║",
            cl_big_prove_ms * BIG_N as f64 / 1_000.0,
            pq_big_prove_ms * BIG_N as f64 / 1_000.0
        );
        println!("╠══════════════════════════════════╩══════════════╩══════════════╩══════════╣");
        println!(
            "║  PHASE B — {SMALL_N} keys: full prove/verify cycle (per-proof unit cost)       ║"
        );
        println!("╠══════════════════════════════════╦══════════════╦══════════════╦══════════╣");
        println!(
            "║ Insert ({SMALL_N} keys)                  ║ {:>9.1} ms ║ {:>9.1} ms ║ {:>6.2}× ║",
            cl_insert_ms,
            pq_insert_ms,
            ratio(pq_insert_ms, cl_insert_ms)
        );
        println!(
            "║ Commit                           ║ {:>9.1} ms ║ {:>9.1} ms ║ {:>6.2}× ║",
            cl_commit_ms,
            pq_commit_ms,
            ratio(pq_commit_ms, cl_commit_ms)
        );
        println!(
            "║ Prove/key (avg)                  ║ {:>9.1} ms ║ {:>9.1} ms ║ {:>6.2}× ║",
            mean(&cl_prove_ms),
            mean(&pq_prove_ms),
            ratio(mean(&pq_prove_ms), mean(&cl_prove_ms))
        );
        println!(
            "║ Prove total ({SMALL_N} keys)              ║ {:>9.1} ms ║ {:>9.1} ms ║ {:>6.2}× ║",
            total(&cl_prove_ms),
            total(&pq_prove_ms),
            ratio(total(&pq_prove_ms), total(&cl_prove_ms))
        );
        println!(
            "║ Verify/key (avg)                 ║ {:>9.1} ms ║ {:>9.1} ms ║ {:>6.2}× ║",
            mean(&cl_verify_ms),
            mean(&pq_verify_ms),
            ratio(mean(&pq_verify_ms), mean(&cl_verify_ms))
        );
        println!("╠══════════════════════════════════╬══════════════╬══════════════╬══════════╣");
        println!(
            "║ Commitment package               ║ {:>8} B  ║ {:>8} B  ║ {:>6.1}× ║",
            cl_commitment_bytes,
            pq_total_commitment,
            ratio(pq_total_commitment as f64, cl_commitment_bytes as f64)
        );
        println!(
            "║   KZG bytes                      ║ {:>8} B  ║ {:>8} B  ║          ║",
            cl_commitment_bytes, pq_commitment_bytes
        );
        println!(
            "║   + Dilithium3 signature         ║      —       ║ {:>8} B  ║          ║",
            pq_sig_bytes
        );
        println!(
            "║   + embedded public key          ║      —       ║ {:>8} B  ║          ║",
            pq_pk_bytes
        );
        println!(
            "║ Proof bytes/key (avg)            ║ {:>8} B  ║ {:>8} B  ║ {:>6.2}× ║",
            mean_sz(&cl_proof_sizes),
            mean_sz(&pq_inner_sizes) + mean_sz(&pq_binding_sizes),
            ratio(
                (mean_sz(&pq_inner_sizes) + mean_sz(&pq_binding_sizes)) as f64,
                mean_sz(&cl_proof_sizes) as f64
            )
        );
        println!(
            "║   KZG inner proof                ║ {:>8} B  ║ {:>8} B  ║          ║",
            mean_sz(&cl_proof_sizes),
            mean_sz(&pq_inner_sizes)
        );
        println!(
            "║   + SHAKE-256 binding tag        ║      —       ║ {:>8} B  ║          ║",
            mean_sz(&pq_binding_sizes)
        );

        // ── Parallel proving section (rayon feature) ──────────────────────
        #[cfg(feature = "rayon")]
        {
            use rayon::prelude::*;

            let small_keys_vec: Vec<Vec<u8>> = small_pairs.iter().map(|(k, _)| k.clone()).collect();
            let num_threads = rayon::current_num_threads();

            // Parallel batch prove (prove_batch uses rayon internally)
            let t = Instant::now();
            let _batch_proofs = pq.prove_batch(&small_keys_vec).expect("prove_batch");
            let pq_batch_ms = t.elapsed().as_secs_f64() * 1_000.0;

            // Classical side: parallel prove-only (no verify), same as prove_batch
            let cl_pairs: Vec<Vec<u8>> = small_keys_vec.clone();
            let t = Instant::now();
            let chunk_size = (cl_pairs.len() + num_threads - 1) / num_threads;
            let cl_chunks: Vec<(Vec<Vec<u8>>, VectorCommitmentTrie)> = cl_pairs
                .chunks(chunk_size)
                .map(|c| (c.to_vec(), cl.clone()))
                .collect();
            let _cl_batch: Vec<_> = cl_chunks
                .into_par_iter()
                .flat_map(|(chunk_keys, mut local_cl)| {
                    chunk_keys
                        .iter()
                        .map(|k| local_cl.prove(k).expect("cl prove"))
                        .collect::<Vec<_>>()
                })
                .collect();
            let cl_batch_ms = t.elapsed().as_secs_f64() * 1_000.0;

            let serial_pq_total = total(&pq_prove_ms);

            println!(
                "╠══════════════════════════════════╩══════════════╩══════════════╩══════════╣"
            );
            println!(
                "║  PHASE C — parallel prove_batch ({SMALL_N} keys, {num_threads} rayon threads)              ║"
            );
            println!(
                "╠══════════════════════════════════╦══════════════╦══════════════╦══════════╣"
            );
            println!(
                "║ Serial prove total               ║ {:>9.1} ms ║ {:>9.1} ms ║          ║",
                total(&cl_prove_ms),
                serial_pq_total
            );
            println!(
                "║ Parallel prove_batch total       ║ {:>9.1} ms ║ {:>9.1} ms ║          ║",
                cl_batch_ms, pq_batch_ms
            );
            println!(
                "║ Speed-up (serial / parallel)     ║ {:>9.2}×  ║ {:>9.2}×  ║          ║",
                ratio(total(&cl_prove_ms), cl_batch_ms),
                ratio(serial_pq_total, pq_batch_ms)
            );
        }

        println!("╚══════════════════════════════════╩══════════════╩══════════════╩══════════╝");
        println!();
        println!("Key takeaways:");
        println!("  • Commit cost is roughly independent of N (tree depth grows as log N).");
        println!("  • Proof cost is per-key: O(N) for N keys, same for classical and PQ.");
        println!("  • For bulk proving, use prove_batch — with --features rayon it parallelises");
        println!("    across all CPU cores (one tree clone per rayon thread).");
        println!(
            "  • PQ overhead ≈ 0 on prove/verify; +{pq_sig_bytes} B + {pq_pk_bytes} B on the commitment."
        );
        println!("  • For a full parallel benchmark in release mode:");
        println!(
            "      cargo test --release --features rayon bench_classical_vs_pq -- --ignored --nocapture"
        );
    }
}
