
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
//! 1. **Signed commitments** — the tree owner signs every root commitment with
//!    Dilithium3 (ML-DSA-65), a NIST-standardised lattice-based signature
//!    scheme.  A verifier who holds the public key can reject unsigned or
//!    forged root commitments, even against a quantum adversary.
//!
//! 2. **Bound proofs** — each proof stores a 64-byte SHAKE-256 tag over
//!    `(commitment || keys)`.  Verification recomputes the tag; a mismatch
//!    means the proof was generated for a different commitment or key set,
//!    preventing proof-replay attacks.
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
//! assert!(commitment.verify_pq_signature().unwrap());
//!
//! // Single-key proof
//! let proof = tree.prove(b"key1").unwrap().expect("key exists");
//! let values = proof.verify_and_extract(&commitment).unwrap();
//! assert_eq!(values[0], b"value1");
//!
//! // Multi-key proof
//! let mp = tree.prove_multiple(&[b"key1".to_vec(), b"key2".to_vec()]).unwrap();
//! let all = mp.verify_and_extract(&commitment).unwrap();
//! assert_eq!(all[0], b"value1");
//! assert_eq!(all[1], b"value2");
//! ```


pub mod error;
pub mod pq_hash;
pub mod pq_sign;
pub mod pq_verkle;

pub use error::PqVerkleError;
pub use pq_sign::PQKeypair;
pub use pq_verkle::{PQCommitment, PQProof, PQVerkleTree};

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

        // The PQ signature on the commitment must be valid.
        assert!(
            commitment.verify_pq_signature().unwrap(),
            "PQ signature should be valid"
        );

        let proof = tree.prove(b"key1").unwrap().expect("key1 should exist");
        assert!(proof.verify(&commitment).unwrap());

        let values = proof.verify_and_extract(&commitment).unwrap();
        assert_eq!(values[0], b"value1");
    }

    #[test]
    fn test_multiple_keys_single_proof_each() {
        init_bls();
        let mut tree = PQVerkleTree::new();
        let pairs: Vec<(&[u8], &[u8])> = vec![
            (b"alpha", b"100"),
            (b"beta", b"200"),
            (b"gamma", b"300"),
        ];
        for (k, v) in &pairs {
            tree.insert(k.to_vec(), v.to_vec()).unwrap();
        }
        let commitment = tree.commit().unwrap();

        for (k, v) in &pairs {
            let proof = tree.prove(k).unwrap().expect("key should exist");
            assert!(proof.verify(&commitment).unwrap(), "verify failed for {k:?}");
            let values = proof.verify_and_extract(&commitment).unwrap();
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
        let mut commitment = tree.commit().unwrap();

        // Flip one bit of the raw commitment.
        commitment.commitment[0] ^= 0xFF;

        assert!(
            !commitment.verify_pq_signature().unwrap(),
            "tampered commitment should fail PQ signature check"
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
            !commitment.verify_pq_signature().unwrap(),
            "tampered signature should be rejected"
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

        let keys = vec![vec![1u8], vec![2u8], vec![3u8]];
        let proof = tree.prove_multiple(&keys).unwrap();

        assert!(proof.verify(&commitment).unwrap(), "multiproof verify failed");
        let values = proof.verify_and_extract(&commitment).unwrap();
        assert_eq!(values, vec![vec![10u8], vec![20u8], vec![30u8]]);
    }

    #[test]
    fn test_multiproof_rejects_wrong_commitment() {
        init_bls();
        let mut tree = PQVerkleTree::new();
        tree.insert(vec![1], vec![10]).unwrap();
        tree.insert(vec![2], vec![20]).unwrap();

        let c1 = tree.commit().unwrap();
        let proof = tree.prove_multiple(&[vec![1u8], vec![2u8]]).unwrap();

        // Build a different commitment.
        let mut tree2 = PQVerkleTree::new();
        tree2.insert(vec![1], vec![99]).unwrap();
        tree2.insert(vec![2], vec![88]).unwrap();
        let c2 = tree2.commit().unwrap();

        // The proof was bound to c1; it must fail against c2.
        assert!(!proof.verify(&c2).unwrap());
        // And it must still pass for c1.
        assert!(proof.verify(&c1).unwrap());
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
        let expected_pk = keypair.public_key_bytes().to_vec();

        let mut tree = PQVerkleTree::with_keypair(keypair);
        tree.insert(b"x".to_vec(), b"y".to_vec()).unwrap();
        let commitment = tree.commit().unwrap();

        assert_eq!(commitment.pq_pubkey, expected_pk);
        assert!(commitment.verify_pq_signature().unwrap());
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
        assert!(commitment.verify_pq_signature().unwrap());

        for i in 0..N {
            let proof = tree.prove(&[i]).unwrap().expect("key must exist");
            assert!(
                proof.verify(&commitment).unwrap(),
                "proof failed for key {i}"
            );
            let values = proof.verify_and_extract(&commitment).unwrap();
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

            let json = serde_json::to_string(&commitment).expect("serialize commitment");
            let restored: PQCommitment =
                serde_json::from_str(&json).expect("deserialize commitment");

            assert_eq!(commitment.commitment, restored.commitment);
            assert_eq!(commitment.pq_signature, restored.pq_signature);
            assert_eq!(commitment.pq_pubkey, restored.pq_pubkey);
            assert!(
                restored.verify_pq_signature().unwrap(),
                "restored commitment signature must still verify"
            );
        }

        #[test]
        fn test_proof_serde_roundtrip() {
            init_bls();
            let mut tree = PQVerkleTree::new();
            tree.insert(b"hello".to_vec(), b"world".to_vec()).unwrap();
            let commitment = tree.commit().unwrap();
            let proof = tree.prove(b"hello").unwrap().expect("key exists");

            let json = serde_json::to_string(&proof).expect("serialize proof");
            let restored: PQProof = serde_json::from_str(&json).expect("deserialize proof");

            assert_eq!(proof.keys(), restored.keys());
            assert_eq!(proof.pq_binding, restored.pq_binding);
            assert!(
                restored.verify(&commitment).unwrap(),
                "restored proof must verify against the original commitment"
            );
            let values = restored.verify_and_extract(&commitment).unwrap();
            assert_eq!(values[0], b"world");
        }

        #[test]
        fn test_multiproof_serde_roundtrip() {
            init_bls();
            let mut tree = PQVerkleTree::new();
            tree.insert(b"a".to_vec(), b"1".to_vec()).unwrap();
            tree.insert(b"b".to_vec(), b"2".to_vec()).unwrap();
            let commitment = tree.commit().unwrap();
            let keys = vec![b"a".to_vec(), b"b".to_vec()];
            let proof = tree.prove_multiple(&keys).unwrap();

            let json = serde_json::to_string(&proof).expect("serialize multiproof");
            let restored: PQProof = serde_json::from_str(&json).expect("deserialize multiproof");

            assert!(restored.verify(&commitment).unwrap());
            let values = restored.verify_and_extract(&commitment).unwrap();
            assert_eq!(values[0], b"1");
            assert_eq!(values[1], b"2");
        }
    }    // ── classical vs quantum-resistant comparison ─────────────────────────────

    /// Head-to-head comparison of classical `quilibrium_verkle` vs `PQVerkleTree`
    /// across performance, commitment size, and proof size.
    ///
    /// Run with:
    ///   cargo test bench_classical_vs_pq -- --ignored --nocapture
    #[test]
    #[ignore = "benchmarking: run with --ignored --nocapture"]
    fn bench_classical_vs_pq() {
        init_bls();

        // ── dataset ────────────────────────────────────────────────────────────
        // Fixed key/value pairs so both trees see identical inputs.
        const N: usize = 10;
        let pairs: Vec<(Vec<u8>, Vec<u8>)> = (0..N as u8)
            .map(|i| {
                let key = format!("benchmark-key-{i:04}").into_bytes();
                let val = format!("benchmark-val-{i:04}").into_bytes();
                (key, val)
            })
            .collect();

        // ─────────────────────────────────────────────────────────────────────
        // CLASSICAL (quilibrium_verkle)
        // ─────────────────────────────────────────────────────────────────────

        // Insert
        let t = Instant::now();
        let mut classical = VectorCommitmentTrie::new();
        for (k, v) in &pairs {
            classical.insert(k.clone(), v.clone()).expect("classical insert");
        }
        let classical_insert_ms = t.elapsed().as_secs_f64() * 1_000.0;

        // Commit
        let t = Instant::now();
        let classical_commitment = classical.commit().expect("classical commit");
        let classical_commit_ms = t.elapsed().as_secs_f64() * 1_000.0;
        let classical_commitment_bytes = classical_commitment.len();

        // Prove (generate one proof per key, collect timings + sizes)
        let mut classical_prove_ms = Vec::with_capacity(N);
        let mut classical_verify_ms = Vec::with_capacity(N);
        let mut classical_proof_sizes: Vec<usize> = Vec::with_capacity(N);

        for (k, _) in &pairs {
            let t = Instant::now();
            let proof = classical.prove(k).expect("classical prove");
            classical_prove_ms.push(t.elapsed().as_secs_f64() * 1_000.0);

            let bytes = proof.to_bytes().expect("classical proof to_bytes");
            classical_proof_sizes.push(bytes.len());

            let t = Instant::now();
            let valid = proof.verify(&classical_commitment).expect("classical verify");
            classical_verify_ms.push(t.elapsed().as_secs_f64() * 1_000.0);
            assert!(valid, "classical proof must verify");
        }

        // ─────────────────────────────────────────────────────────────────────
        // QUANTUM-RESISTANT (PQVerkleTree)
        // ─────────────────────────────────────────────────────────────────────

        // Insert
        let t = Instant::now();
        let mut pq = PQVerkleTree::new();
        for (k, v) in &pairs {
            pq.insert(k.clone(), v.clone()).expect("pq insert");
        }
        let pq_insert_ms = t.elapsed().as_secs_f64() * 1_000.0;

        // Commit
        let t = Instant::now();
        let pq_commitment = pq.commit().expect("pq commit");
        let pq_commit_ms = t.elapsed().as_secs_f64() * 1_000.0;
        let pq_commitment_bytes = pq_commitment.commitment.len();
        let pq_signature_bytes = pq_commitment.pq_signature.len();
        let pq_pubkey_bytes     = pq_commitment.pq_pubkey.len();
        let pq_total_commitment_bytes =
            pq_commitment_bytes + pq_signature_bytes + pq_pubkey_bytes;

        // Prove
        let mut pq_prove_ms: Vec<f64>   = Vec::with_capacity(N);
        let mut pq_verify_ms: Vec<f64>  = Vec::with_capacity(N);
        let mut pq_inner_sizes: Vec<usize>   = Vec::with_capacity(N);
        let mut pq_binding_sizes: Vec<usize> = Vec::with_capacity(N);

        for (k, _) in &pairs {
            let t = Instant::now();
            let proof = pq.prove(k).expect("pq prove").expect("key exists");
            pq_prove_ms.push(t.elapsed().as_secs_f64() * 1_000.0);

            pq_inner_sizes.push(proof.inner_to_bytes().unwrap().len());
            pq_binding_sizes.push(proof.pq_binding.len());

            let t = Instant::now();
            let valid = proof.verify(&pq_commitment).expect("pq verify");
            pq_verify_ms.push(t.elapsed().as_secs_f64() * 1_000.0);
            assert!(valid, "pq proof must verify");
        }

        // ─────────────────────────────────────────────────────────────────────
        // Report
        // ─────────────────────────────────────────────────────────────────────
        let mean = |v: &[f64]| v.iter().sum::<f64>() / v.len() as f64;
        let total = |v: &[f64]| v.iter().sum::<f64>();
        let mean_sz = |v: &[usize]| v.iter().sum::<usize>() / v.len();

        println!();
        println!("╔══════════════════════════════════════════════════════════════════════╗");
        println!("║         classical quilibrium_verkle  vs  verkle_pq (PQ-safe)        ║");
        println!("║  Dataset: {N} key-value pairs, one proof per key                     ║");
        println!("╠═══════════════════════════════╦══════════════╦══════════════╦═══════╣");
        println!("║ Phase                         ║  Classical   ║   PQ-safe    ║  ×    ║");
        println!("╠═══════════════════════════════╬══════════════╬══════════════╬═══════╣");

        let ratio = |pq: f64, cl: f64| if cl > 0.0 { pq / cl } else { f64::NAN };

        // Timings
        println!("║ Insert ({N} keys)               ║ {:>9.3} ms ║ {:>9.3} ms ║ {:>5.2}×║",
            classical_insert_ms, pq_insert_ms,
            ratio(pq_insert_ms, classical_insert_ms));
        println!("║ Commit                        ║ {:>9.3} ms ║ {:>9.3} ms ║ {:>5.2}×║",
            classical_commit_ms, pq_commit_ms,
            ratio(pq_commit_ms, classical_commit_ms));
        println!("║ Prove/key (avg)               ║ {:>9.3} ms ║ {:>9.3} ms ║ {:>5.2}×║",
            mean(&classical_prove_ms), mean(&pq_prove_ms),
            ratio(mean(&pq_prove_ms), mean(&classical_prove_ms)));
        println!("║ Prove total ({N} keys)          ║ {:>9.3} ms ║ {:>9.3} ms ║ {:>5.2}×║",
            total(&classical_prove_ms), total(&pq_prove_ms),
            ratio(total(&pq_prove_ms), total(&classical_prove_ms)));
        println!("║ Verify/key (avg)              ║ {:>9.3} ms ║ {:>9.3} ms ║ {:>5.2}×║",
            mean(&classical_verify_ms), mean(&pq_verify_ms),
            ratio(mean(&pq_verify_ms), mean(&classical_verify_ms)));
        println!("╠═══════════════════════════════╬══════════════╬══════════════╬═══════╣");

        // Sizes
        println!("║ Commitment (raw KZG bytes)    ║ {:>9} B  ║ {:>9} B  ║ {:>5.2}×║",
            classical_commitment_bytes, pq_commitment_bytes,
            ratio(pq_commitment_bytes as f64, classical_commitment_bytes as f64));
        println!("║ PQ signature (Dilithium3)     ║ {:>12} ║ {:>9} B  ║   N/A ║",
            "—", pq_signature_bytes);
        println!("║ PQ public key (embedded)      ║ {:>12} ║ {:>9} B  ║   N/A ║",
            "—", pq_pubkey_bytes);
        println!("║ Total commitment package      ║ {:>9} B  ║ {:>9} B  ║ {:>5.2}×║",
            classical_commitment_bytes, pq_total_commitment_bytes,
            ratio(pq_total_commitment_bytes as f64, classical_commitment_bytes as f64));
        println!("╠═══════════════════════════════╬══════════════╬══════════════╬═══════╣");
        println!("║ Proof bytes/key (avg)         ║ {:>9} B  ║ {:>9} B  ║ {:>5.2}×║",
            mean_sz(&classical_proof_sizes),
            mean_sz(&pq_inner_sizes),
            ratio(mean_sz(&pq_inner_sizes) as f64, mean_sz(&classical_proof_sizes) as f64));
        println!("║ PQ binding tag/key (avg)      ║ {:>12} ║ {:>9} B  ║   N/A ║",
            "—", mean_sz(&pq_binding_sizes));
        println!("║ Total proof package/key (avg) ║ {:>9} B  ║ {:>9} B  ║ {:>5.2}×║",
            mean_sz(&classical_proof_sizes),
            mean_sz(&pq_inner_sizes) + mean_sz(&pq_binding_sizes),
            ratio(
                (mean_sz(&pq_inner_sizes) + mean_sz(&pq_binding_sizes)) as f64,
                mean_sz(&classical_proof_sizes) as f64,
            ));
        println!("╚═══════════════════════════════╩══════════════╩══════════════╩═══════╝");
        println!();
        println!("Notes:");
        println!("  • Timings are wall-clock (debug build, single core, macOS).");
        println!("  • Inner proof bytes are identical for PQ-safe tree (same KZG core).");
        println!("  • PQ overhead = Dilithium3 sig ({pq_signature_bytes} B) + pubkey ({pq_pubkey_bytes} B)");
        println!("    in the commitment, plus SHAKE-256 binding tag ({} B) per proof.",
            mean_sz(&pq_binding_sizes));
        println!("  • Neither tree provides quantum security on the KZG layer itself; the");
        println!("    PQ layers bind and authenticate commitments against quantum forgery.");
    }}
