#[cfg(test)]
mod tests {
    use crate::{VectorCommitmentTrie, RdfMultiprover, RdfSchemaParser};

    const NAME_RECORD_RDF: &str = r#"
@prefix qcl: <https://types.quilibrium.com/qcl/> .
@prefix rdfs: <http://www.w3.org/2000/01/rdf-schema#> .
@prefix name: <https://types.quilibrium.com/schema-repository/name/> .

name:NameRecord a rdfs:Class ;
    rdfs:comment "Quilibrium name service record" .

name:Name a rdfs:Property ;
    rdfs:range name:NameRecord ;
    rdfs:domain qcl:String ;
        qcl:size 32 ;
    qcl:order 1 .

name:AuthorityKey a rdfs:Property ;
    rdfs:range name:NameRecord ;
    rdfs:domain qcl:ByteArray ;
        qcl:size 57 ;
    qcl:order 2 .

name:Parent a rdfs:Property ;
    rdfs:range name:NameRecord ;
    rdfs:domain qcl:ByteArray ;
        qcl:size 32 ;
    qcl:order 3 .

name:CreatedAt a rdfs:Property ;
    rdfs:range name:NameRecord ;
    rdfs:domain qcl:Uint ;
    qcl:size 64 ;
    qcl:order 4 .

name:UpdatedAt a rdfs:Property ;
    rdfs:range name:NameRecord ;
    rdfs:domain qcl:Uint ;
    qcl:size 64 ;
    qcl:order 5 .

name:RecordType a rdfs:Property ;
    rdfs:range name:NameRecord ;
    rdfs:domain qcl:Uint ;
    qcl:size 8 ;
    qcl:order 6 .

name:Data a rdfs:Property ;
    rdfs:range name:NameRecord ;
    rdfs:domain qcl:String ;
        qcl:size 64 ;
    qcl:order 7 .
"#;

    fn create_test_tree() -> VectorCommitmentTrie {
        bls48581::init();

        let mut tree = VectorCommitmentTrie::new();

        // Insert test data at indices matching Go test
        // Go inserts at keys: [i << 2] for i in 0..63
        for i in 0u8..63 {
            let key = vec![i << 2];
            let data = vec![i + 1; 57]; // Repeat byte (i+1) for 57 bytes
            tree.insert(key, data).unwrap();
        }

        tree
    }

    #[test]
    fn test_prove() {
        let mut tree = create_test_tree();
        let multiprover = RdfMultiprover::new();

        let fields = vec!["Name".to_string(), "AuthorityKey".to_string()];
        let proof = multiprover.prove(NAME_RECORD_RDF, &fields, &mut tree).unwrap();

        let proof_bytes = proof.to_bytes().unwrap();
        println!("Rust proof: {}", hex::encode(&proof_bytes));

        // Expected from Go test
        let expected_hex = "0000004a0201543e1ce44d00d7842d4b7dd0fca624023e9b6ac3505ca37adae6341393b597c24dd5d6a36a2247282922a46765c6a400d58a6de374f6ddc7d2c20d3c952f58f877a4ef3aa69a94e90000004a020f883a94b6986fe3e6f382c15dd22cca6e1574547641f83d51168af2a4efd4a6bf6439dfb50f6a8113a820596fe286df8b1c46b3eb597c9540e1535790ff029913fd7200211ffaa502";

        println!("Go   proof: {}", expected_hex);

        // Compare lengths
        let expected_bytes = hex::decode(expected_hex).unwrap();
        assert_eq!(proof_bytes.len(), expected_bytes.len(), "Proof length mismatch");

        // Compare byte-by-byte
        if proof_bytes != expected_bytes {
            println!("MISMATCH!");
            for (i, (rust_byte, go_byte)) in proof_bytes.iter().zip(expected_bytes.iter()).enumerate() {
                if rust_byte != go_byte {
                    println!("First difference at byte {}: Rust={:02x} Go={:02x}", i, rust_byte, go_byte);
                    break;
                }
            }
        }

        assert_eq!(hex::encode(&proof_bytes), expected_hex, "Proof bytes should match Go implementation");
    }

    #[test]
    fn test_prove_with_type() {
        let mut tree = create_test_tree();

        // NOTE: The Go test does NOT insert the type marker before ProveWithType!
        // It just passes the typeIndex parameter. The type marker is only inserted
        // later in the VerifyWithType test.

        let multiprover = RdfMultiprover::new();
        let fields = vec!["Name".to_string(), "AuthorityKey".to_string()];

        // Test with type index (tree still has only 63 entries)
        let type_index = 63u64;
        let proof = multiprover.prove_with_type(NAME_RECORD_RDF, &fields, &mut tree, Some(type_index)).unwrap();
        let proof_bytes = proof.to_bytes().unwrap();

        println!("Rust proof with type: {}", hex::encode(&proof_bytes));

        let expected_with_type_hex = "0000004a0200e514c00ef5e9f54191a3fea588fdb17ea0bcd7645c6f066e655499d22b1fc00bd96b9d9be6de3c1d5a0972d1968e7e559089417627fb71b49e3f480f2f61c182c03f58b89d12a3660000004a0307b865f9dee0b0e8e11572ba8ed696b94711091b27838e74076d6f7f848e1a80dd5e85198b98558e13dfeef964eef0e76526a70e260086aa61cc62e5f5e7f836539649da632945acc2";

        println!("Go   proof with type: {}", expected_with_type_hex);

        // Compare
        let expected_with_type_bytes = hex::decode(expected_with_type_hex).unwrap();
        assert_eq!(proof_bytes.len(), expected_with_type_bytes.len(), "Proof with type length mismatch");
        assert_eq!(hex::encode(&proof_bytes), expected_with_type_hex, "Proof with type should match Go");

        // Test without type index (should match test_prove output since tree is unchanged)
        let proof_no_type = multiprover.prove_with_type(NAME_RECORD_RDF, &fields, &mut tree, None).unwrap();
        let proof_no_type_bytes = proof_no_type.to_bytes().unwrap();

        println!("Rust proof with type but type is nil: {}", hex::encode(&proof_no_type_bytes));

        let expected_no_type_hex = "0000004a0201543e1ce44d00d7842d4b7dd0fca624023e9b6ac3505ca37adae6341393b597c24dd5d6a36a2247282922a46765c6a400d58a6de374f6ddc7d2c20d3c952f58f877a4ef3aa69a94e90000004a020f883a94b6986fe3e6f382c15dd22cca6e1574547641f83d51168af2a4efd4a6bf6439dfb50f6a8113a820596fe286df8b1c46b3eb597c9540e1535790ff029913fd7200211ffaa502";

        println!("Go   proof with type but type is nil: {}", expected_no_type_hex);

        // This should match since tree is unchanged
        assert_eq!(hex::encode(&proof_no_type_bytes), expected_no_type_hex, "Proof without type should match Go");
    }

    #[test]
    fn test_get() {
        let tree = create_test_tree();
        let multiprover = RdfMultiprover::new();

        // Test getting Name field (order 1, so key is 1<<2 = 4, data at index 1)
        let value = multiprover.get(NAME_RECORD_RDF, "name:NameRecord", "Name", &tree).unwrap();
        assert_eq!(value, Some(vec![2; 57])); // Index 1 has value 2

        // Test getting AuthorityKey field (order 2, so key is 2<<2 = 8, data at index 2)
        let value = multiprover.get(NAME_RECORD_RDF, "name:NameRecord", "AuthorityKey", &tree).unwrap();
        assert_eq!(value, Some(vec![3; 57])); // Index 2 has value 3
    }

    #[test]
    fn test_get_field_order() {
        let parser = RdfSchemaParser::parse(NAME_RECORD_RDF).unwrap();

        let (order, max_order) = parser.get_field_order("Name").unwrap();
        assert_eq!(order, 1);
        assert_eq!(max_order, 7);

        let (order, max_order) = parser.get_field_order("AuthorityKey").unwrap();
        assert_eq!(order, 2);
        assert_eq!(max_order, 7);

        let (order, max_order) = parser.get_field_order("Parent").unwrap();
        assert_eq!(order, 3);
        assert_eq!(max_order, 7);
    }

    #[test]
    fn test_get_field_key() {
        let parser = RdfSchemaParser::parse(NAME_RECORD_RDF).unwrap();

        let key = parser.get_field_key("Name").unwrap();
        assert_eq!(key, vec![1 << 2]);

        let key = parser.get_field_key("AuthorityKey").unwrap();
        assert_eq!(key, vec![2 << 2]);
    }

    #[test]
    fn test_verify() {
        let mut tree = create_test_tree();
        let multiprover = RdfMultiprover::new();

        // Create proof
        let fields = vec!["Name".to_string(), "AuthorityKey".to_string(), "Parent".to_string()];
        let proof = multiprover.prove_with_type(NAME_RECORD_RDF, &fields, &mut tree, None).unwrap();

        // Get actual data from tree
        let data: Vec<Vec<u8>> = fields.iter().map(|field| {
            multiprover.get(NAME_RECORD_RDF, "name:NameRecord", field, &tree).unwrap().unwrap()
        }).collect();

        // Get commitment
        let commit = tree.commit().unwrap();
        let proof_bytes = proof.to_bytes().unwrap();

        // Verify should pass with correct data
        let valid = multiprover.verify(NAME_RECORD_RDF, &fields, None, &commit, &proof_bytes, &data).unwrap();
        assert!(valid, "Verification should pass with correct data");

        // Verify should fail with wrong data
        let wrong_data: Vec<Vec<u8>> = vec![vec![0xff; 57]; fields.len()];
        let valid = multiprover.verify(NAME_RECORD_RDF, &fields, None, &commit, &proof_bytes, &wrong_data).unwrap();
        assert!(!valid, "Verification should fail with wrong data");

        // Verify should error with non-existent field
        let invalid_fields = vec!["Name".to_string(), "NonExistent".to_string()];
        let result = multiprover.verify(NAME_RECORD_RDF, &invalid_fields, None, &commit, &proof_bytes, &data[..2]);
        assert!(result.is_err(), "Should error with non-existent field");
        assert!(result.unwrap_err().to_string().contains("not found"));
    }

    #[test]
    fn test_verify_with_type() {
        let mut tree = create_test_tree();

        // Add type marker
        let type_data = vec![0xff; 32];
        let type_index = 63u64;
        tree.insert(type_data.clone(), type_data.clone()).unwrap();

        let multiprover = RdfMultiprover::new();
        let fields = vec!["Name".to_string(), "AuthorityKey".to_string()];

        // Get commitment after all data inserted
        let commit = tree.commit().unwrap();

        // Create proof with type
        let proof = multiprover.prove_with_type(NAME_RECORD_RDF, &fields, &mut tree, Some(type_index)).unwrap();

        // Get actual data
        let data: Vec<Vec<u8>> = fields.iter().map(|field| {
            multiprover.get(NAME_RECORD_RDF, "name:NameRecord", field, &tree).unwrap().unwrap()
        }).collect();

        let proof_bytes = proof.to_bytes().unwrap();

        // Verify with type should pass
        let valid = multiprover.verify_with_type(
            NAME_RECORD_RDF,
            &fields,
            None,
            &commit,
            &proof_bytes,
            &data,
            Some(type_index),
            Some(&type_data)
        ).unwrap();
        assert!(valid, "Verification with type should pass");

        // Verify without type when proof was created with type should fail
        let valid = multiprover.verify_with_type(
            NAME_RECORD_RDF,
            &fields,
            None,
            &commit,
            &proof_bytes,
            &data,
            None,
            None
        ).unwrap();
        assert!(!valid, "Verification should fail when type is missing");

        // Create proof without type
        let proof_no_type = multiprover.prove_with_type(NAME_RECORD_RDF, &fields, &mut tree, None).unwrap();
        let proof_no_type_bytes = proof_no_type.to_bytes().unwrap();

        // Verify without type should pass
        let valid = multiprover.verify_with_type(
            NAME_RECORD_RDF,
            &fields,
            None,
            &commit,
            &proof_no_type_bytes,
            &data,
            None,
            None
        ).unwrap();
        assert!(valid, "Verification without type should pass");

        // Verify with wrong type data should fail
        let wrong_type_data = b"wrong type data";
        let valid = multiprover.verify_with_type(
            NAME_RECORD_RDF,
            &fields,
            None,
            &commit,
            &proof_bytes,
            &data,
            Some(type_index),
            Some(wrong_type_data)
        ).unwrap();
        assert!(!valid, "Verification with wrong type data should fail");
    }

    #[test]
    fn test_error_cases() {
        let tree = create_test_tree();
        let multiprover = RdfMultiprover::new();

        // Test non-existent field
        let result = multiprover.get(NAME_RECORD_RDF, "name:NameRecord", "NonExistent", &tree);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not found"));

        // Test invalid document
        let result = multiprover.get("invalid rdf", "name:NameRecord", "Name", &tree);
        assert!(result.is_err());
    }
}
