use verkle_pq::{PQKeypair, PQVerkleTree};

fn main() {
    // Initialise the BLS48-581 library (required once per process).
    verkle_pq::init();

    println!("=== verkle-pq: quantum-resistant Verkle tree demo ===\n");

    // ── 1. Basic single-key proof ─────────────────────────────────────────────
    println!("--- Single-key proof ---");
    let mut tree = PQVerkleTree::new();
    println!(
        "Dilithium3 public key ({} bytes): {}",
        tree.public_key_bytes().len(),
        hex::encode(&tree.public_key_bytes()[..8]) // show first 8 bytes
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
    println!(
        "PQ signature valid: {}",
        commitment.verify_pq_signature().unwrap()
    );

    let proof = tree.prove(b"name").unwrap().expect("key must exist");
    let values = proof.verify_and_extract(&commitment).unwrap();
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
    println!("\n--- Multi-key proof ---");
    let keys = vec![b"name".to_vec(), b"role".to_vec(), b"score".to_vec()];
    let multiproof = tree.prove_multiple(&keys).unwrap();
    let all_values = multiproof.verify_and_extract(&commitment).unwrap();
    for (k, v) in keys.iter().zip(all_values.iter()) {
        println!(
            "  {}: {}",
            String::from_utf8_lossy(k),
            String::from_utf8_lossy(v)
        );
    }
    assert!(multiproof.verify(&commitment).unwrap());

    // ── 3. Tamper-detection ───────────────────────────────────────────────────
    println!("\n--- Tamper detection ---");
    let mut tampered = commitment.clone();
    tampered.commitment[0] ^= 0xFF;
    println!(
        "Tampered commitment PQ sig valid: {}",
        tampered.verify_pq_signature().unwrap()
    );
    assert!(!tampered.verify_pq_signature().unwrap());

    // ── 4. Reusing an existing keypair ────────────────────────────────────────
    println!("\n--- Reusing a known keypair ---");
    let keypair = PQKeypair::generate();
    let pk_bytes = keypair.public_key_bytes().to_vec();

    let mut tree2 = PQVerkleTree::with_keypair(keypair);
    tree2
        .insert(b"token".to_vec(), b"0xDEADBEEF".to_vec())
        .unwrap();
    let c2 = tree2.commit().unwrap();
    assert_eq!(c2.pq_pubkey, pk_bytes);
    println!(
        "Commitment signed with expected keypair: {}",
        c2.verify_pq_signature().unwrap()
    );

    println!("\nAll demo assertions passed!");
}
