use crate::{VerkleError, Result};
use super::VectorCommitmentTrie;
use std::collections::HashMap;
use oxrdf::Triple;
use oxttl::TurtleParser;
use std::io::Cursor;
use std::io::{Write, Read};

/// RDF field definition parsed from Turtle RDF schema
#[derive(Debug, Clone)]
pub struct RdfField {
    pub name: String,
    pub order: usize,
    pub size: usize,
    pub domain: String,
}

/// RDF Multiproof - matches Go's KZG Multiproof format
#[derive(Debug, Clone)]
pub struct RdfMultiproof {
    /// D - the multicommitment (aggregate commitment)
    pub d: Vec<u8>,
    /// Proof - the KZG proof bytes
    pub proof: Vec<u8>,
}

impl RdfMultiproof {
    /// Serialize to bytes (matches Go format)
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut buf = Vec::new();

        // Write D length and data
        buf.write_all(&(self.d.len() as u32).to_be_bytes())?;
        buf.write_all(&self.d)?;

        // Write Proof length and data
        buf.write_all(&(self.proof.len() as u32).to_be_bytes())?;
        buf.write_all(&self.proof)?;

        Ok(buf)
    }

    /// Deserialize from bytes (matches Go format)
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        let mut cursor = Cursor::new(data);

        // Read D length
        let mut d_len_bytes = [0u8; 4];
        cursor.read_exact(&mut d_len_bytes)
            .map_err(|e| VerkleError::CryptoError(format!("Failed to read D length: {}", e)))?;
        let d_len = u32::from_be_bytes(d_len_bytes) as usize;

        // Read D
        let mut d = vec![0u8; d_len];
        cursor.read_exact(&mut d)
            .map_err(|e| VerkleError::CryptoError(format!("Failed to read D: {}", e)))?;

        // Read Proof length
        let mut proof_len_bytes = [0u8; 4];
        cursor.read_exact(&mut proof_len_bytes)
            .map_err(|e| VerkleError::CryptoError(format!("Failed to read Proof length: {}", e)))?;
        let proof_len = u32::from_be_bytes(proof_len_bytes) as usize;

        // Read Proof
        let mut proof = vec![0u8; proof_len];
        cursor.read_exact(&mut proof)
            .map_err(|e| VerkleError::CryptoError(format!("Failed to read Proof: {}", e)))?;

        Ok(Self { d, proof })
    }
}

/// Simple Turtle RDF parser for name record schema
pub struct RdfSchemaParser {
    fields: HashMap<String, RdfField>,
    max_order: usize,
}

impl RdfSchemaParser {
    /// Parse RDF schema from Turtle format
    pub fn parse(rdf_doc: &str) -> Result<Self> {
        let mut fields = HashMap::new();
        let mut max_order = 0;

        // Parse Turtle RDF
        let cursor = Cursor::new(rdf_doc.as_bytes());
        let parser = TurtleParser::new().for_reader(cursor);

        // Temporary storage for each property
        let mut property_data: HashMap<String, (Option<usize>, Option<usize>, Option<String>)> = HashMap::new();

        for triple_result in parser {
            let triple: Triple = triple_result
                .map_err(|e| VerkleError::InvalidData(format!("RDF parse error: {}", e)))?;

            let subject_str = triple.subject.to_string();
            let predicate_str = triple.predicate.to_string();
            let object_str = triple.object.to_string();

            // Skip class definitions (e.g., "name:SomeClass a rdfs:Class")
            // The predicate "a" is shorthand for rdf:type
            if (predicate_str == "<http://www.w3.org/1999/02/22-rdf-syntax-ns#type>" || predicate_str == "a")
                && object_str == "<http://www.w3.org/2000/01/rdf-schema#Class>" {
                continue;
            }

            // Extract property name from any schema-repository URL
            // Examples:
            // "<https://types.quilibrium.com/schema-repository/name/Name>" -> "Name"
            // "<https://types.quilibrium.com/schema-repository/token/test/coin/CoinInfo>" -> "CoinInfo"
            if let Some(after_repo) = subject_str.strip_prefix("<https://types.quilibrium.com/schema-repository/") {
                // Find the last '/' to get the property name after any prefix path
                if let Some(last_slash_idx) = after_repo.rfind('/') {
                    let prop_name = &after_repo[last_slash_idx + 1..];
                    let prop_name = prop_name.strip_suffix(">").unwrap_or(prop_name);

                    let entry = property_data.entry(prop_name.to_string()).or_insert((None, None, None));

                    // Parse qcl:order
                    if predicate_str == "<https://types.quilibrium.com/qcl/order>" {
                        if let oxrdf::Term::Literal(lit) = &triple.object {
                            if let Ok(order) = lit.value().parse::<usize>() {
                                entry.0 = Some(order);
                                max_order = max_order.max(order);
                            }
                        }
                    }

                    // Parse qcl:size
                    if predicate_str == "<https://types.quilibrium.com/qcl/size>" {
                        if let oxrdf::Term::Literal(lit) = &triple.object {
                            if let Ok(size) = lit.value().parse::<usize>() {
                                entry.1 = Some(size);
                            }
                        }
                    }

                    // Parse rdfs:domain
                    if predicate_str == "<http://www.w3.org/2000/01/rdf-schema#domain>" {
                        entry.2 = Some(object_str.clone());
                    }
                }
            }
        }

        // Convert parsed data to RdfField structs
        for (name, (order_opt, size_opt, domain_opt)) in property_data {
            if let (Some(order), Some(size), Some(domain)) = (order_opt, size_opt, domain_opt) {
                fields.insert(name.clone(), RdfField {
                    name,
                    order,
                    size,
                    domain,
                });
            }
        }

        Ok(Self {
            fields,
            max_order,
        })
    }

    /// Get field definition by name
    pub fn get_field(&self, field_name: &str) -> Result<&RdfField> {
        self.fields.get(field_name)
            .ok_or_else(|| VerkleError::InvalidData(format!("Field {} not found", field_name)))
    }

    /// Get field order (1-indexed)
    pub fn get_field_order(&self, field_name: &str) -> Result<(usize, usize)> {
        let field = self.get_field(field_name)?;
        Ok((field.order, self.max_order))
    }

    /// Get field key (order << 2)
    pub fn get_field_key(&self, field_name: &str) -> Result<Vec<u8>> {
        let field = self.get_field(field_name)?;
        Ok(vec![(field.order << 2) as u8])
    }

    /// Get all fields
    pub fn get_fields(&self) -> &HashMap<String, RdfField> {
        &self.fields
    }
}

/// RDF Multiprover for generating and verifying proofs for name record fields
pub struct RdfMultiprover;

impl RdfMultiprover {
    /// Create a new RDF multiprover
    pub fn new() -> Self {
        Self
    }

    /// Get a field value from the tree
    pub fn get(
        &self,
        rdf_doc: &str,
        _record_type: &str,
        field_name: &str,
        tree: &VectorCommitmentTrie,
    ) -> Result<Option<Vec<u8>>> {
        let parser = RdfSchemaParser::parse(rdf_doc)?;
        let key = parser.get_field_key(field_name)?;
        Ok(tree.get(&key))
    }

    /// Generate a proof for specified fields
    pub fn prove(
        &self,
        rdf_doc: &str,
        field_names: &[String],
        tree: &mut VectorCommitmentTrie,
    ) -> Result<RdfMultiproof> {
        self.prove_with_type(rdf_doc, field_names, tree, None)
    }

    /// Generate a proof for specified fields with optional type marker
    pub fn prove_with_type(
        &self,
        rdf_doc: &str,
        field_names: &[String],
        tree: &mut VectorCommitmentTrie,
        type_index: Option<u64>,
    ) -> Result<RdfMultiproof> {
        let parser = RdfSchemaParser::parse(rdf_doc)?;

        // Get tree commitment and polynomial
        let commit = tree.commit()
            .ok_or_else(|| VerkleError::CryptoError("Tree has no root".to_string()))?;
        let poly = tree.get_polynomial()
            .ok_or_else(|| VerkleError::CryptoError("Tree has no root branch".to_string()))?;

        // Build indices from field names
        let mut indices = Vec::new();
        let mut commits = Vec::new();
        let mut polys = Vec::new();

        for field_name in field_names {
            let field = parser.get_field(field_name)?;
            // Indices are order values (not shifted)
            indices.push(field.order as u64);
            commits.push(commit.clone());
            polys.push(poly.clone());
        }

        // Add type index if provided
        if let Some(type_idx) = type_index {
            indices.push(type_idx);
            commits.push(commit.clone());
            polys.push(poly.clone());
        }

        // Determine poly size (64 for standard name records with max order 7)
        let poly_size = 64u64;

        // Generate multiproof using bls48581
        let multiproof = bls48581::prove_multiple(&commits, &polys, &indices, poly_size);

        Ok(RdfMultiproof { d: multiproof.d, proof: multiproof.proof })
    }

    /// Verify a proof for specified fields
    pub fn verify(
        &self,
        rdf_doc: &str,
        field_names: &[String],
        _keys: Option<&[Vec<u8>]>,
        root_commitment: &[u8],
        proof_bytes: &[u8],
        expected_data: &[Vec<u8>],
    ) -> Result<bool> {
        self.verify_with_type(
            rdf_doc,
            field_names,
            _keys,
            root_commitment,
            proof_bytes,
            expected_data,
            None,
            None,
        )
    }

    /// Verify a proof with optional type marker
    pub fn verify_with_type(
        &self,
        rdf_doc: &str,
        field_names: &[String],
        keys: Option<&[Vec<u8>]>,
        root_commitment: &[u8],
        proof_bytes: &[u8],
        expected_data: &[Vec<u8>],
        type_index: Option<u64>,
        type_data: Option<&[u8]>,
    ) -> Result<bool> {
        use sha2::{Sha512, Digest};

        // Validate inputs
        if field_names.len() != expected_data.len() {
            return Err(VerkleError::InvalidData("fields and data length mismatch".to_string()));
        }
        if let Some(ks) = keys {
            if ks.len() != field_names.len() {
                return Err(VerkleError::InvalidData("keys and fields length mismatch".to_string()));
            }
        }

        let parser = RdfSchemaParser::parse(rdf_doc)?;

        // Build indices and evaluations
        let mut indices = Vec::new();
        let mut commits = Vec::new();
        let mut evaluations = Vec::new();

        // Determine poly size (64 for standard name records with max order 7)
        let poly_size = 64u64;

        for (i, field_name) in field_names.iter().enumerate() {
            let field = parser.get_field(field_name)?;

            // Calculate evaluation: SHA512(0x00 || key || data)
            let mut hasher = Sha512::new();
            hasher.update(&[0u8]);

            if let Some(ks) = keys {
                if let Some(key) = ks.get(i) {
                    hasher.update(key);
                } else {
                    // Use flexible order encoding
                    let key = parser.get_field_key(field_name)?;
                    hasher.update(&key);
                }
            } else {
                // Use flexible order encoding
                let key = parser.get_field_key(field_name)?;
                hasher.update(&key);
            }

            hasher.update(&expected_data[i]);
            let evaluation = hasher.finalize().to_vec();

            indices.push(field.order as u64);
            commits.push(root_commitment.to_vec());
            evaluations.push(evaluation);
        }

        // Add type verification if provided
        if let (Some(type_idx), Some(type_bytes)) = (type_index, type_data) {
            let mut hasher = Sha512::new();
            hasher.update(&[0u8]);
            hasher.update(&vec![0xff; 32]);
            hasher.update(type_bytes);
            let evaluation = hasher.finalize().to_vec();

            indices.push(type_idx);
            commits.push(root_commitment.to_vec());
            evaluations.push(evaluation);
        }

        // Deserialize multiproof
        let multiproof = RdfMultiproof::from_bytes(proof_bytes)?;

        // Verify multiproof
        let valid = bls48581::verify_multiple(
            &commits,
            &evaluations,
            &indices,
            poly_size,
            &multiproof.d,
            &multiproof.proof,
        );

        Ok(valid)
    }
}

impl Default for RdfMultiprover {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn test_rdf_parser() {
        let parser = RdfSchemaParser::parse(NAME_RECORD_RDF).unwrap();

        // Debug: print all parsed fields
        println!("Parsed fields: {:?}", parser.get_fields().keys().collect::<Vec<_>>());

        // Test field parsing
        let name_field = parser.get_field("Name").unwrap();
        assert_eq!(name_field.order, 1);
        assert_eq!(name_field.size, 32);

        let authority_field = parser.get_field("AuthorityKey").unwrap();
        assert_eq!(authority_field.order, 2);
        assert_eq!(authority_field.size, 57);

        // Test field order
        let (order, max_order) = parser.get_field_order("Name").unwrap();
        assert_eq!(order, 1);
        assert_eq!(max_order, 7);

        // Test field key
        let key = parser.get_field_key("Name").unwrap();
        assert_eq!(key, vec![1 << 2]); // order 1 << 2 = 4

        let key = parser.get_field_key("AuthorityKey").unwrap();
        assert_eq!(key, vec![2 << 2]); // order 2 << 2 = 8
    }

    #[test]
    fn test_multiprover_get_field_order() {
        let parser = RdfSchemaParser::parse(NAME_RECORD_RDF).unwrap();

        let (order, max_order) = parser.get_field_order("Name").unwrap();
        assert_eq!(order, 1);
        assert_eq!(max_order, 7);

        let (order, max_order) = parser.get_field_order("Parent").unwrap();
        assert_eq!(order, 3);
        assert_eq!(max_order, 7);
    }

    #[test]
    fn test_multiprover_get_field_key() {
        let parser = RdfSchemaParser::parse(NAME_RECORD_RDF).unwrap();

        let key = parser.get_field_key("Name").unwrap();
        assert_eq!(key, vec![1 << 2]);

        let key = parser.get_field_key("AuthorityKey").unwrap();
        assert_eq!(key, vec![2 << 2]);
    }

    #[test]
    fn test_different_schema_prefix() {
        // Test that parser works with different schema prefixes (e.g., coin: instead of name:)
        const COIN_SCHEMA: &str = r#"
@prefix qcl: <https://types.quilibrium.com/qcl/> .
@prefix rdfs: <http://www.w3.org/2000/01/rdf-schema#> .
@prefix coin: <https://types.quilibrium.com/schema-repository/token/test/coin/> .

coin:CoinRecord a rdfs:Class ;
    rdfs:comment "Test coin record" .

coin:Denomination a rdfs:Property ;
    rdfs:range coin:CoinRecord ;
    rdfs:domain qcl:Uint ;
    qcl:size 8 ;
    qcl:order 1 .

coin:Amount a rdfs:Property ;
    rdfs:range coin:CoinRecord ;
    rdfs:domain qcl:Uint ;
    qcl:size 64 ;
    qcl:order 2 .
"#;

        let parser = RdfSchemaParser::parse(COIN_SCHEMA).unwrap();

        // Should find fields from coin: prefix
        let field1 = parser.get_field("Denomination").unwrap();
        assert_eq!(field1.order, 1);
        assert_eq!(field1.size, 8);

        let field2 = parser.get_field("Amount").unwrap();
        assert_eq!(field2.order, 2);
        assert_eq!(field2.size, 64);

        // Verify field keys are correct
        let key1 = parser.get_field_key("Denomination").unwrap();
        assert_eq!(key1, vec![1 << 2]);

        let key2 = parser.get_field_key("Amount").unwrap();
        assert_eq!(key2, vec![2 << 2]);
    }
}
