use verkle_pq::{DilithiumPubKey, PQKeypair, PQVerkleTree};

fn main() {
    // Initialise the BLS48-581 library (required once per process).
    verkle_pq::init();

    println!("=== verkle-pq: PQ-authenticated Verkle tree demo ===\n");

    // ── 1. Basic single-key proof ─────────────────────────────────────────────
    println!("--- Single-key proof ---");
    let mut tree = PQVerkleTree::new();
    let trusted_pk = tree.dilithium_pubkey(); // capture before inserting
    println!(
        "Dilithium3 public key ({} bytes): {}",
        trusted_pk.as_ref().len(),
        hex::encode(&trusted_pk.as_ref()[..8]) // show first 8 bytes
    );

    tree.insert(b"name".to_vec(), b"alice".to_vec()).unwrap();
    tree.insert(b"role".to_vec(), b"admin".to_vec()).unwrap();
    tree.insert(b"score".to_vec(), b"9001".to_vec()).unwrap();

    let commitment = tree.commit().unwrap();
    println!(
        "Root commitment ({} bytes): {}",
        commitment.commitment.len(),
        hex::encode(&commitment.commitment)
    );
    // Use authenticated verification (supply the trusted public key).
    println!(
        "PQ-authenticated commitment valid: {}",
        commitment.verify_against_pubkey(&trusted_pk).unwrap()
    );

    let proof = tree.prove(b"name").unwrap().expect("key must exist");
    let values = proof
        .verify_and_extract_with_pubkey(&commitment, &trusted_pk)
        .unwrap();
    println!(
        "Proven value for 'name': {:?}",
        String::from_utf8_lossy(&values[0])
    );
    assert_eq!(values[0], b"alice");

    // Missing key returns None (no proof possible).
    let no_proof = tree.prove(b"missing_key").unwrap();
    println!("Proof for missing key: {:?}", no_proof.is_none());
    assert!(no_proof.is_none());

    // ── 2. Multi-key proof ────────────────────────────────────────────────────
    println!("\n--- Multi-key proof (keys sorted canonically) ---");
    // Keys can be supplied in any order; prove_multiple sorts them internally.
    let keys = vec![b"score".to_vec(), b"name".to_vec(), b"role".to_vec()];
    let multiproof = tree.prove_multiple(&keys).unwrap();
    // Values are returned in canonical (sorted) key order.
    let all_values = multiproof
        .verify_and_extract_with_pubkey(&commitment, &trusted_pk)
        .unwrap();
    let mut sorted_keys = keys.clone();
    sorted_keys.sort();
    for (k, v) in sorted_keys.iter().zip(all_values.iter()) {
        println!(
            "  {}: {}",
            String::from_utf8_lossy(k),
            String::from_utf8_lossy(v)
        );
    }
    assert!(
        multiproof
            .verify_with_pubkey(&commitment, &trusted_pk)
            .unwrap()
    );

    // ── 3. Tamper-detection ───────────────────────────────────────────────────
    println!("\n--- Tamper detection ---");
    let mut tampered = commitment.clone();
    tampered.commitment[0] ^= 0xFF;
    // Both the self-consistency check and the trusted-key check must fail.
    println!(
        "Tampered commitment (self-consistency): {}",
        tampered.verify_embedded_key().unwrap()
    );
    println!(
        "Tampered commitment (trusted key):      {}",
        tampered.verify_against_pubkey(&trusted_pk).unwrap()
    );
    assert!(!tampered.verify_embedded_key().unwrap());
    assert!(!tampered.verify_against_pubkey(&trusted_pk).unwrap());

    // ── 4. Reusing an existing keypair ────────────────────────────────────────
    println!("\n--- Reusing a known keypair ---");
    let keypair = PQKeypair::generate();
    let expected_pk = DilithiumPubKey(keypair.public_key_bytes().to_vec());

    let mut tree2 = PQVerkleTree::with_keypair(keypair);
    tree2
        .insert(b"token".to_vec(), b"0xDEADBEEF".to_vec())
        .unwrap();
    let c2 = tree2.commit().unwrap();
    let tree2_pk = tree2.dilithium_pubkey();

    assert_eq!(c2.pq_pubkey, expected_pk.as_ref());
    println!(
        "Commitment authenticated with expected keypair: {}",
        c2.verify_against_pubkey(&tree2_pk).unwrap()
    );

    // ── 5. Public-key mismatch detection ─────────────────────────────────────
    println!("\n--- Public-key mismatch detection ---");
    // Trying to verify c2 (tree2's commitment) against tree's key must fail.
    let mismatch_result = c2.verify_against_pubkey(&trusted_pk);
    println!(
        "Wrong key rejected: {}",
        matches!(
            mismatch_result,
            Err(verkle_pq::PqVerkleError::PubkeyMismatch)
        )
    );
    assert!(matches!(
        mismatch_result,
        Err(verkle_pq::PqVerkleError::PubkeyMismatch)
    ));

    println!("\nAll demo assertions passed!");
}
