use super::trie::VectorCommitmentTrie;
use crate::Result;
use serde::{Deserialize, Serialize};

/// Field mapping for structured data in a verkle trie
///
/// This provides a generic way to map field names to their paths and values
/// in a verkle trie, useful for structured data like records with named fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldMapping {
    /// Field name (e.g., "owner", "name", "parent")
    pub field_name: String,
    /// Field path in the trie (derived from field name)
    pub field_path: Vec<u8>,
    /// Field value as bytes
    pub value: Vec<u8>,
}

/// Generic schema for mapping structured records to verkle trie
///
/// This provides a way to organize structured data in a verkle trie,
/// where each field maps to a specific path derived from the field name.
pub struct RecordSchema {
    trie: VectorCommitmentTrie,
}

impl RecordSchema {
    /// Create a new schema
    pub fn new() -> Self {
        Self {
            trie: VectorCommitmentTrie::new(),
        }
    }

    /// Insert a field into the trie
    pub fn insert_field(&mut self, field_name: &str, value: &[u8]) -> Result<()> {
        let field_path = Self::derive_field_path(field_name);
        self.trie.insert(field_path, value.to_vec())
    }

    /// Derive a field path from field name
    /// Uses SHA512 to ensure uniform distribution of fields across the trie
    pub fn derive_field_path(field_name: &str) -> Vec<u8> {
        use sha2::{Sha512, Digest};
        let mut hasher = Sha512::new();
        hasher.update(b"field:");
        hasher.update(field_name.as_bytes());
        hasher.finalize().to_vec()
    }

    /// Get the trie commitment
    pub fn commitment(&mut self) -> Option<Vec<u8>> {
        self.trie.commit()
    }

    /// Get the underlying trie
    pub fn trie(&self) -> &VectorCommitmentTrie {
        &self.trie
    }

    /// Get mutable reference to the underlying trie
    pub fn trie_mut(&mut self) -> &mut VectorCommitmentTrie {
        &mut self.trie
    }
}

impl Default for RecordSchema {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_field_path_derivation() {
        let path1 = RecordSchema::derive_field_path("owner");
        let path2 = RecordSchema::derive_field_path("name");
        let path3 = RecordSchema::derive_field_path("owner");

        // Different fields should produce different paths
        assert_ne!(path1, path2);

        // Same field should produce same path
        assert_eq!(path1, path3);

        // All paths should be 64 bytes (SHA512 output)
        assert_eq!(path1.len(), 64);
        assert_eq!(path2.len(), 64);
    }

    #[test]
    fn test_schema_basic_operations() {
        bls48581::init();

        let mut schema = RecordSchema::new();

        // Insert fields
        schema.insert_field("owner", b"alice").unwrap();
        schema.insert_field("name", b"test").unwrap();
        schema.insert_field("value", b"12345").unwrap();

        // Should be able to get commitment
        let commitment = schema.commitment();
        assert!(commitment.is_some());
        // With multiple fields, we'll have a branch node -> KZG commitment (74 bytes)
        assert_eq!(commitment.unwrap().len(), 74);
    }

    #[test]
    fn test_deterministic_commitment() {
        bls48581::init();

        let mut schema1 = RecordSchema::new();
        schema1.insert_field("field1", b"value1").unwrap();
        schema1.insert_field("field2", b"value2").unwrap();

        let mut schema2 = RecordSchema::new();
        schema2.insert_field("field1", b"value1").unwrap();
        schema2.insert_field("field2", b"value2").unwrap();

        let commitment1 = schema1.commitment().unwrap();
        let commitment2 = schema2.commitment().unwrap();

        // Same fields should produce same commitment
        assert_eq!(commitment1, commitment2);
    }
}
