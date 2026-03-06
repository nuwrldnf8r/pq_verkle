#[cfg(test)]
mod tests {
    use crate::VectorCommitmentTrie;

    #[test]
    fn test_two_key_insertion() {
        bls48581::init();

        let mut trie = VectorCommitmentTrie::new();

        // Insert just two keys that will diverge
        trie.insert(
            vec![0x00, 0x00],
            b"testingtestingtestingtestingtestingtestingtestingtestingtestingtesting0000".to_vec()
        ).unwrap();

        trie.insert(
            vec![0x00, 0x01],
            b"testingtestingtestingtestingtestingtestingtestingtestingtestingtesting0001".to_vec()
        ).unwrap();

        let commit = trie.commit().unwrap();
        eprintln!("Two-key commitment: {}", hex::encode(&commit));
        eprintln!("Commitment length: {}", commit.len());
    }

    #[test]
    fn test_go_compatibility_vector() {
        // Ensure BLS is initialized
        bls48581::init();

        let mut trie = VectorCommitmentTrie::new();

        // Insert 64 entries with pattern [0x00, i]
        for i in 0u8..64 {
            let key = vec![0x00, i];
            // Go: "testing..." + "00" + hex.EncodeToString([]byte{i})
            // hex.EncodeToString produces lowercase hex
            let value = format!(
                "testingtestingtestingtestingtestingtestingtestingtestingtestingtesting00{:02x}",
                i
            );
            trie.insert(key, value.into_bytes()).unwrap();
        }

        // Insert 63 entries with pattern [i, 0x00] (i starts at 1)
        for i in 1u8..64 {
            let key = vec![i, 0x00];
            // Go: "testing..." + hex.EncodeToString([]byte{i}) + "00"
            let value = format!(
                "testingtestingtestingtestingtestingtestingtestingtestingtestingtesting{:02x}00",
                i
            );
            trie.insert(key, value.into_bytes()).unwrap();
        }

        // Compute commitment
        let commitment = trie.commit().unwrap();

        // Expected commitment from Go implementation
        let expected_commit = hex::decode(
            "030205b91c2a7f02c9859770c1240eb2ee03b5a301db37c924e84ef7be0e33b872d4d03be6406506fc0ead795446a2133fafe8b0bc4be7fc12cc4f035783f3d5c22e045a55e47636cbe8"
        ).unwrap();

        println!("Commitment (Rust): {}", hex::encode(&commitment));
        println!("Expected   (Go):   {}", hex::encode(&expected_commit));

        assert_eq!(
            commitment, expected_commit,
            "Commitment mismatch!\nGot:      {}\nExpected: {}",
            hex::encode(&commitment),
            hex::encode(&expected_commit)
        );

        // Test lookup to ensure the value is correct
        let test_key = vec![0x00, 0x05];
        let test_value = trie.get(&test_key);
        assert!(test_value.is_some(), "Key [0x00, 0x05] should exist");

        let expected_value = b"testingtestingtestingtestingtestingtestingtestingtestingtestingtesting0005".to_vec();
        assert_eq!(
            test_value.unwrap(),
            expected_value,
            "Value mismatch for key [0x00, 0x05]"
        );
    }

    #[test]
    fn test_single_key_proof() {
        bls48581::init();

        let mut trie = VectorCommitmentTrie::new();

        // Insert test keys
        trie.insert(vec![0x00, 0x00], b"value00".to_vec()).unwrap();
        trie.insert(vec![0x00, 0x01], b"value01".to_vec()).unwrap();
        trie.insert(vec![0x00, 0x02], b"value02".to_vec()).unwrap();

        // Generate proof for key [0x00, 0x01]
        let proof = trie.prove(&[0x00, 0x01]);
        assert!(proof.is_some(), "Proof should be generated for existing key");

        let proof = proof.unwrap();
        println!("Single key proof generated:");
        println!("  Multiproof length: {} bytes", proof.multiproof.len());
        println!("  Sub-proofs: {}", proof.sub_proofs.len());

        assert_eq!(proof.sub_proofs.len(), 1, "Should have one sub-proof");

        let sub_proof = &proof.sub_proofs[0];
        println!("  Commits: {}", sub_proof.commits.len());
        println!("  Ys: {}", sub_proof.ys.len());
        println!("  Paths: {}", sub_proof.paths.len());

        // Should have commits from root to leaf
        assert!(!sub_proof.commits.is_empty(), "Should have at least one commit");
        assert_eq!(sub_proof.commits.len(), sub_proof.ys.len(), "Commits and ys should match");
        // Paths are only for branch nodes, not for the leaf
        assert_eq!(sub_proof.paths.len(), sub_proof.commits.len() - 1, "Paths should be one less than commits (no path for leaf)");

        // Test proof serialization
        let serialized = proof.to_bytes().unwrap();
        println!("  Serialized proof size: {} bytes", serialized.len());

        // Test deserialization
        let deserialized = crate::proof::TraversalProof::from_bytes(&serialized).unwrap();
        assert_eq!(deserialized.multiproof.len(), proof.multiproof.len());
        assert_eq!(deserialized.sub_proofs.len(), proof.sub_proofs.len());
    }

    #[test]
    fn test_proof_for_nonexistent_key() {
        bls48581::init();

        let mut trie = VectorCommitmentTrie::new();
        trie.insert(vec![0x00, 0x00], b"value00".to_vec()).unwrap();

        // Try to generate proof for non-existent key
        let proof = trie.prove(&[0xFF, 0xFF]);
        assert!(proof.is_none(), "Proof should not be generated for non-existent key");
    }

    #[test]
    fn test_proof_with_go_compatibility_vector() {
        bls48581::init();

        let mut trie = VectorCommitmentTrie::new();

        // Insert just a few keys from the Go test vector
        for i in 0u8..5 {
            let key = vec![0x00, i];
            let value = format!(
                "testingtestingtestingtestingtestingtestingtestingtestingtestingtesting00{:02x}",
                i
            );
            trie.insert(key, value.into_bytes()).unwrap();
        }

        // Generate proof for key [0x00, 0x02]
        let proof = trie.prove(&[0x00, 0x02]);
        assert!(proof.is_some(), "Proof should be generated");

        let proof = proof.unwrap();
        println!("Go-compatible proof:");
        println!("  Multiproof length: {} bytes", proof.multiproof.len());
        println!("  Sub-proofs: {}", proof.sub_proofs.len());

        let sub_proof = &proof.sub_proofs[0];
        println!("  Commits: {}", sub_proof.commits.len());
        for (i, commit) in sub_proof.commits.iter().enumerate() {
            println!("    Commit[{}]: {} (len={})", i, hex::encode(commit), commit.len());
        }

        println!("  Ys: {}", sub_proof.ys.len());
        for (i, y) in sub_proof.ys.iter().enumerate() {
            println!("    Y[{}]: {} (len={})", i, hex::encode(y), y.len());
        }

        println!("  Paths: {}", sub_proof.paths.len());
        for (i, path) in sub_proof.paths.iter().enumerate() {
            println!("    Path[{}]: {:?}", i, path);
        }
    }

    #[test]
    fn test_multiple_key_proof() {
        bls48581::init();

        let mut trie = VectorCommitmentTrie::new();

        // Insert test keys
        trie.insert(vec![0x00, 0x00], b"value00".to_vec()).unwrap();
        trie.insert(vec![0x00, 0x01], b"value01".to_vec()).unwrap();
        trie.insert(vec![0x00, 0x02], b"value02".to_vec()).unwrap();
        trie.insert(vec![0x01, 0x00], b"value10".to_vec()).unwrap();

        // Generate proof for multiple keys
        let keys = vec![
            vec![0x00, 0x01],
            vec![0x00, 0x02],
            vec![0x01, 0x00],
        ];

        let proof = trie.prove_multiple(&keys);
        assert!(proof.is_some(), "Multi-key proof should be generated");

        let proof = proof.unwrap();
        println!("Multi-key proof generated:");
        println!("  Multiproof length: {} bytes", proof.multiproof.len());
        println!("  Sub-proofs: {}", proof.sub_proofs.len());

        assert_eq!(proof.sub_proofs.len(), 3, "Should have three sub-proofs");

        for (i, sub_proof) in proof.sub_proofs.iter().enumerate() {
            println!("  Sub-proof[{}]:", i);
            println!("    Commits: {}", sub_proof.commits.len());
            println!("    Ys: {}", sub_proof.ys.len());
            println!("    Paths: {}", sub_proof.paths.len());
        }

        // Test proof serialization
        let serialized = proof.to_bytes().unwrap();
        println!("  Serialized proof size: {} bytes", serialized.len());

        // Test deserialization
        let deserialized = crate::proof::TraversalProof::from_bytes(&serialized).unwrap();
        assert_eq!(deserialized.multiproof.len(), proof.multiproof.len());
        assert_eq!(deserialized.sub_proofs.len(), proof.sub_proofs.len());
    }

    #[test]
    fn test_proof_verification() {
        bls48581::init();

        let mut trie = VectorCommitmentTrie::new();

        // Insert test keys
        trie.insert(vec![0x00, 0x00], b"value00".to_vec()).unwrap();
        trie.insert(vec![0x00, 0x01], b"value01".to_vec()).unwrap();
        trie.insert(vec![0x00, 0x02], b"value02".to_vec()).unwrap();

        // Get root commitment
        let root_commitment = trie.commit().unwrap();
        println!("Root commitment: {}", hex::encode(&root_commitment));

        // Generate proof for key [0x00, 0x01]
        let proof = trie.prove(&[0x00, 0x01]).unwrap();

        // Verify the proof
        let verified = proof.verify(&root_commitment).unwrap();
        assert!(verified, "Proof should verify successfully");

        // Extract values
        let values = proof.verify_and_extract(&root_commitment).unwrap();
        assert_eq!(values.len(), 1, "Should extract one value");
        assert_eq!(values[0], b"value01".to_vec(), "Extracted value should match");

        println!("Proof verification successful!");
    }

    #[test]
    fn test_proof_verification_multi_key() {
        bls48581::init();

        let mut trie = VectorCommitmentTrie::new();

        // Insert test keys
        trie.insert(vec![0x00, 0x00], b"value00".to_vec()).unwrap();
        trie.insert(vec![0x00, 0x01], b"value01".to_vec()).unwrap();
        trie.insert(vec![0x00, 0x02], b"value02".to_vec()).unwrap();
        trie.insert(vec![0x01, 0x00], b"value10".to_vec()).unwrap();

        // Get root commitment
        let root_commitment = trie.commit().unwrap();
        println!("Root commitment: {}", hex::encode(&root_commitment));

        // Generate proof for multiple keys
        let keys = vec![
            vec![0x00, 0x01],
            vec![0x00, 0x02],
            vec![0x01, 0x00],
        ];

        let proof = trie.prove_multiple(&keys).unwrap();

        // Verify the proof
        let verified = proof.verify(&root_commitment).unwrap();
        assert!(verified, "Multi-key proof should verify successfully");

        // Extract values
        let values = proof.verify_and_extract(&root_commitment).unwrap();
        assert_eq!(values.len(), 3, "Should extract three values");
        assert_eq!(values[0], b"value01".to_vec(), "First value should match");
        assert_eq!(values[1], b"value02".to_vec(), "Second value should match");
        assert_eq!(values[2], b"value10".to_vec(), "Third value should match");

        println!("Multi-key proof verification successful!");
    }

    #[test]
    fn test_proof_verification_wrong_root() {
        bls48581::init();

        let mut trie = VectorCommitmentTrie::new();

        // Insert test keys
        trie.insert(vec![0x00, 0x00], b"value00".to_vec()).unwrap();
        trie.insert(vec![0x00, 0x01], b"value01".to_vec()).unwrap();

        // Generate proof
        let proof = trie.prove(&[0x00, 0x01]).unwrap();

        // Try to verify with wrong root
        let wrong_root = vec![0u8; 74];
        let verified = proof.verify(&wrong_root).unwrap();
        assert!(!verified, "Proof should not verify with wrong root");

        println!("Wrong root correctly rejected!");
    }

    #[test]
    fn test_go_compatibility_proof_format() {
        // This test matches the Go test: TestGetTestVector
        bls48581::init();

        let mut trie = VectorCommitmentTrie::new();

        // Insert 64 entries with pattern [0x00, i]
        for i in 0u8..64 {
            let key = vec![0x00, i];
            let value = format!(
                "testingtestingtestingtestingtestingtestingtestingtestingtestingtesting00{:02x}",
                i
            );
            trie.insert(key, value.into_bytes()).unwrap();
        }

        // Insert 63 entries with pattern [i, 0x00] (i starts at 1)
        for i in 1u8..64 {
            let key = vec![i, 0x00];
            let value = format!(
                "testingtestingtestingtestingtestingtestingtestingtestingtestingtesting{:02x}00",
                i
            );
            trie.insert(key, value.into_bytes()).unwrap();
        }

        // Compute commitment (should match Go)
        let commitment = trie.commit().unwrap();
        let expected_commit = hex::decode(
            "030205b91c2a7f02c9859770c1240eb2ee03b5a301db37c924e84ef7be0e33b872d4d03be6406506fc0ead795446a2133fafe8b0bc4be7fc12cc4f035783f3d5c22e045a55e47636cbe8"
        ).unwrap();
        assert_eq!(commitment, expected_commit, "Commitment should match Go");

        // Generate proof for key [0x00, 0x05]
        let proof = trie.prove(&[0x00, 0x05]).unwrap();

        // Serialize proof
        let proof_bytes = proof.to_bytes().unwrap();

        // Expected proof from Go
        let expected_proof_hex = "0000009c0000004a020d3f87a7086b3ab4744f7af91afe54f5b9b76793cb81eb925e975ad5996792597291e76c0a6f2c8836fd0642ea9bf0b9a8339260570c50a73ca21eca6fdc346e05293cc4348e28b5800000004a020d9f9529e6d44b3253c83e3144e37540646c2e4ba1832bf530b55c3d2ac4288b80d2362bea385817f4ca84e723075f6d123e4fd269842168256feeb3b5e921ce7526b561724b2379f500000001000000040000004a030205b91c2a7f02c9859770c1240eb2ee03b5a301db37c924e84ef7be0e33b872d4d03be6406506fc0ead795446a2133fafe8b0bc4be7fc12cc4f035783f3d5c22e045a55e47636cbe80000004a02107678a0d8b2aaa9cda967f31f3b1c2009fd54116bafc2959d28822d72c6d07dd5280864628f480c41c7380d4234eece045adcebe540c904102925669ed4eb6a82d55ec18c56210aa70000004a0308cc421708e44c2a042acaa20cad40cc18f21378781719eb28da896a73fa2b08f690f52459042175549e01829a871d4a35e43f7f2e3933ffdc990c07600a16bfdb82285903ce65e1aa00000040f8c66913be3715d13236de1f45727df42dcc9975367362fd7bfc815f2b345b4c0f12c27b6945c0e582de20e90ea756dc9f33fbc9a80df79ab28d1807f54a26dd0000000400000040a70a1ab3a842d905573d400108bfa1cd44a652ceecc13d247cb9062c5e0c8eb0a330e4a109d75289c8c4989b660f47b48ce5153067a7c3eaaf731fd5ae311b5100000040b024f455dcf7a245d381efda78b522cf6381160de1eb175a1be37439dc405134c7c301d0590deecdd35b5af95711293ac31f05de11b7f739e0440fd0af3cc93a00000040f8c66913be3715d13236de1f45727df42dcc9975367362fd7bfc815f2b345b4c0f12c27b6945c0e582de20e90ea756dc9f33fbc9a80df79ab28d1807f54a26dd0000004a74657374696e6774657374696e6774657374696e6774657374696e6774657374696e6774657374696e6774657374696e6774657374696e6774657374696e6774657374696e673030303500000003000000010000000000000000000000010000000000000000000000010000000000000014";

        println!("Rust proof (hex): {}", hex::encode(&proof_bytes));
        println!("Go   proof (hex): {}", expected_proof_hex);
        println!("Rust proof length: {} bytes", proof_bytes.len());
        println!("Go   proof length: {} bytes", expected_proof_hex.len() / 2);

        // Decode expected proof for comparison
        let expected_proof = hex::decode(expected_proof_hex).unwrap();

        // Compare lengths first
        if proof_bytes.len() != expected_proof.len() {
            println!("LENGTH MISMATCH!");
            println!("Rust: {} bytes", proof_bytes.len());
            println!("Go:   {} bytes", expected_proof.len());

            // Find first difference
            let min_len = proof_bytes.len().min(expected_proof.len());
            for i in 0..min_len {
                if proof_bytes[i] != expected_proof[i] {
                    println!("First difference at byte {}: Rust={:02x} Go={:02x}", i, proof_bytes[i], expected_proof[i]);
                    println!("Context (bytes {}-{}):", i.saturating_sub(8), i + 8);
                    println!("  Rust: {}", hex::encode(&proof_bytes[i.saturating_sub(8)..=(i+8).min(proof_bytes.len()-1)]));
                    println!("  Go:   {}", hex::encode(&expected_proof[i.saturating_sub(8)..=(i+8).min(expected_proof.len()-1)]));
                    break;
                }
            }
        }

        // Compare byte-by-byte
        assert_eq!(
            hex::encode(&proof_bytes),
            expected_proof_hex,
            "Proof serialization should match Go implementation exactly"
        );
    }
}
