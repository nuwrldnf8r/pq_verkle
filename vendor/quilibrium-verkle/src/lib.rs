//! # Quilibrium Verkle Trie
//!
//! A Verkle trie implementation with KZG polynomial commitments for the Quilibrium network.
//!
//! This crate provides:
//! - Vector commitment trie data structure with 64-ary branching
//! - KZG polynomial commitments using BLS48-581 curve
//! - Cryptographic inclusion proofs (single and multi-key)
//! - RDF schema-based field mapping for structured data
//!
//! ## Features
//!
//! ### Verkle Trie
//! A 64-ary tree structure where each branch node's children are committed using
//! KZG polynomial commitments. This enables:
//! - Constant-size commitments (74 bytes) regardless of tree size
//! - Efficient inclusion proofs with logarithmic proof size
//! - Cryptographic binding of all data in the tree
//!
//! ### KZG Proofs
//! Generate and verify cryptographic proofs that specific keys exist in the tree
//! with their associated values, without revealing the entire tree structure.
//!
//! ### RDF Schema Support
//! Map structured records (like name records) to the verkle trie using RDF schemas
//! defined in Turtle format. This provides:
//! - Deterministic field ordering
//! - Type-safe field access
//! - Schema evolution support
//!
//! ## Example: Basic Verkle Trie
//!
//! ```rust
//! use quilibrium_verkle::VectorCommitmentTrie;
//!
//! // Initialize BLS library
//! bls48581::init();
//!
//! // Create a new trie
//! let mut trie = VectorCommitmentTrie::new();
//!
//! // Insert key-value pairs
//! trie.insert(vec![1, 2, 3], vec![4, 5, 6]).unwrap();
//! trie.insert(vec![1, 2, 4], vec![7, 8, 9]).unwrap();
//!
//! // Get the root commitment
//! let commitment = trie.commit().unwrap();
//! println!("Root commitment: {}", hex::encode(&commitment));
//!
//! // Retrieve a value
//! let value = trie.get(&[1, 2, 3]);
//! assert_eq!(value, Some(vec![4, 5, 6]));
//! ```
//!
//! ## Example: Generating and Verifying Proofs
//!
//! ```rust
//! use quilibrium_verkle::VectorCommitmentTrie;
//!
//! bls48581::init();
//!
//! let mut trie = VectorCommitmentTrie::new();
//! trie.insert(vec![1], vec![10]).unwrap();
//! trie.insert(vec![2], vec![20]).unwrap();
//!
//! // Generate proof for key [1]
//! let proof = trie.prove(&[1]).unwrap();
//! let commitment = trie.commit().unwrap();
//!
//! // Verify the proof
//! let is_valid = proof.verify(&commitment).unwrap();
//! assert!(is_valid);
//!
//! // Extract the proven value
//! let values = proof.verify_and_extract(&commitment).unwrap();
//! assert_eq!(values[0], vec![10]);
//! ```
//!
//! ## Example: RDF-Based Field Proofs
//!
//! ```rust
//! use quilibrium_verkle::{VectorCommitmentTrie, RdfMultiprover};
//!
//! bls48581::init();
//!
//! // RDF schema defining a name record
//! let schema = r#"
//! @prefix qcl: <https://types.quilibrium.com/qcl/> .
//! @prefix rdfs: <http://www.w3.org/2000/01/rdf-schema#> .
//! @prefix name: <https://types.quilibrium.com/schema-repository/name/> .
//!
//! name:NameRecord a rdfs:Class .
//! name:Name a rdfs:Property ;
//!     rdfs:domain qcl:String ;
//!     qcl:size 32 ;
//!     qcl:order 1 .
//! "#;
//!
//! // Create tree and multiprover
//! let mut tree = VectorCommitmentTrie::new();
//! let multiprover = RdfMultiprover::new();
//!
//! // Insert data at the correct index
//! tree.insert(vec![1 << 2], b"Alice".to_vec()).unwrap();
//!
//! // Generate proof for the "Name" field
//! let proof = multiprover.prove(schema, &["Name".to_string()], &mut tree).unwrap();
//! println!("Proof size: {} bytes", proof.to_bytes().unwrap().len());
//! ```

pub mod node;
pub mod trie;
pub mod schema;
pub mod proof;
pub mod rdf;

#[cfg(test)]
mod test_vector;

#[cfg(test)]
mod rdf_test;

pub use node::{VectorCommitmentNode, VectorCommitmentLeafNode, VectorCommitmentBranchNode};
pub use trie::VectorCommitmentTrie;
pub use schema::{RecordSchema, FieldMapping};
pub use proof::{TraversalProof, TraversalSubProof};
pub use rdf::{RdfSchemaParser, RdfMultiprover, RdfField, RdfMultiproof};

// Re-export error types for convenience
pub use error::{VerkleError, Result};

// Re-export bls48581 init function for convenience
pub use bls48581::init;

/// Error types for the verkle trie
pub mod error {
    use thiserror::Error;

    /// Result type alias for verkle operations
    pub type Result<T> = std::result::Result<T, VerkleError>;

    /// Errors that can occur in verkle trie operations
    #[derive(Error, Debug)]
    pub enum VerkleError {
        #[error("Invalid data: {0}")]
        InvalidData(String),

        #[error("Cryptographic error: {0}")]
        CryptoError(String),

        #[error("Serialization error: {0}")]
        SerializationError(String),

        #[error("I/O error: {0}")]
        IoError(#[from] std::io::Error),
    }
}
