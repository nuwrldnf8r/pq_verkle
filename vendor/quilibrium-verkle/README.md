# quilibrium-verkle

Verkle trie implementation with KZG polynomial commitments for the Quilibrium network.

[![Crates.io](https://img.shields.io/crates/v/quilibrium-verkle.svg)](https://crates.io/crates/quilibrium-verkle)
[![Documentation](https://docs.rs/quilibrium-verkle/badge.svg)](https://docs.rs/quilibrium-verkle)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Overview

This crate provides a Verkle trie data structure with KZG (Kate-Zaverucha-Goldberg) polynomial commitments. Verkle tries enable efficient, constant-size cryptographic proofs of inclusion for key-value data.

### Features

- **Vector Commitment Trie**: 64-ary tree structure with KZG commitments at each branch
- **Constant-Size Proofs**: 74-byte commitments regardless of tree size
- **Inclusion Proofs**: Logarithmic-size proofs that a key-value pair exists in the tree
- **Multiproofs**: Efficient batch proofs for multiple keys simultaneously
- **RDF Schema Support**: Map structured data (like name records) using RDF Turtle schemas
- **Go Compatibility**: Byte-for-byte compatible with Quilibrium's monorepo go implementation

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
quilibrium-verkle = "2.1.0"
bls48581 = "2.1.0"  # Required for cryptographic operations
```

## Quick Start

```rust
use quilibrium_verkle::VectorCommitmentTrie;

// Initialize the BLS library (required once)
bls48581::init();

// Create a new verkle trie
let mut trie = VectorCommitmentTrie::new();

// Insert key-value pairs
trie.insert(vec![1, 2, 3], vec![4, 5, 6]).unwrap();
trie.insert(vec![1, 2, 4], vec![7, 8, 9]).unwrap();

// Get the root commitment (74 bytes)
let commitment = trie.commit().unwrap();

// Retrieve a value
let value = trie.get(&[1, 2, 3]);
assert_eq!(value, Some(vec![4, 5, 6]));
```

## Generating Proofs

```rust
use quilibrium_verkle::VectorCommitmentTrie;

bls48581::init();

let mut trie = VectorCommitmentTrie::new();
trie.insert(vec![1], vec![10]).unwrap();
trie.insert(vec![2], vec![20]).unwrap();

// Generate a proof that key [1] exists with value [10]
let proof = trie.prove(&[1]).unwrap();
let commitment = trie.commit().unwrap();

// Verify the proof
assert!(proof.verify(&commitment).unwrap());

// Extract the proven value
let values = proof.verify_and_extract(&commitment).unwrap();
assert_eq!(values[0], vec![10]);
```

## Multiproofs

Prove multiple keys efficiently in a single proof:

```rust
use quilibrium_verkle::VectorCommitmentTrie;

bls48581::init();

let mut trie = VectorCommitmentTrie::new();
trie.insert(vec![1], vec![10]).unwrap();
trie.insert(vec![2], vec![20]).unwrap();
trie.insert(vec![3], vec![30]).unwrap();

// Generate a proof for multiple keys at once
let keys = vec![vec![1], vec![2], vec![3]];
let proof = trie.prove_multiple(&keys).unwrap();

// Verify and extract all values
let commitment = trie.commit().unwrap();
let values = proof.verify_and_extract(&commitment).unwrap();
assert_eq!(values, vec![vec![10], vec![20], vec![30]]);
```

## RDF Schema-Based Proofs

The RDF multiprover allows you to define structured schemas using Turtle RDF format:

```rust
use quilibrium_verkle::{VectorCommitmentTrie, RdfMultiprover};

bls48581::init();

// Define an RDF schema for a name record
let schema = r#"
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

name:Owner a rdfs:Property ;
    rdfs:range name:NameRecord ;
    rdfs:domain qcl:ByteArray ;
    qcl:size 57 ;
    qcl:order 2 .
"#;

// Create tree and insert data
let mut tree = VectorCommitmentTrie::new();
tree.insert(vec![1 << 2], b"alice".to_vec()).unwrap();
tree.insert(vec![2 << 2], vec![0u8; 57]).unwrap();

// Generate a proof for specific fields
let multiprover = RdfMultiprover::new();
let fields = vec!["Name".to_string(), "Owner".to_string()];
let proof = multiprover.prove(schema, &fields, &mut tree).unwrap();

// Get commitment and proof bytes
let commitment = tree.commit().unwrap();
let proof_bytes = proof.to_bytes().unwrap();

// Verify the proof
let data = vec![b"alice".to_vec(), vec![0u8; 57]];
let valid = multiprover.verify(schema, &fields, None, &commitment, &proof_bytes, &data).unwrap();
assert!(valid);
```

## How It Works

### Verkle Trie Structure

A Verkle trie is a 64-ary tree where:
- Each node has up to 64 children
- Leaf nodes store key-value pairs with SHA-512 commitments
- Branch nodes commit to their children using KZG polynomial commitments
- Paths through the tree are determined by 6-bit nibbles from the key

### KZG Commitments

Each branch node's 64 children are represented as a degree-63 polynomial, which is committed using KZG commitments on the BLS48-581 elliptic curve. This enables:
- Constant-size commitments (74 bytes) for any number of children
- Efficient opening proofs at specific indices
- Batch verification of multiple openings

### Cryptographic Security

The trie provides binding commitments: once data is committed, it cannot be changed without detectably altering the root commitment. Proofs are:
- **Complete**: Prove that a key exists with a specific value
- **Sound**: Cannot create false proofs for incorrect data
- **Succinct**: Logarithmic proof size relative to tree size

## Use Cases

- **Name Service Records**: Prove specific fields of a name record without revealing the entire record
- **State Commitments**: Commit to application state with efficient partial proofs
- **Blockchain Light Clients**: Verify specific state values without downloading full state
- **Verifiable Databases**: Provide cryptographic proofs for database queries

## Performance

- **Commitment Size**: 74 bytes (constant, regardless of tree size)
- **Proof Size**: ~437 bytes for single key, ~1.3KB for 3 keys
- **Generation Time**: ~10-15ms per single-key proof
- **Verification Time**: ~8-12ms per single-key proof

## Compatibility

This implementation is byte-for-byte compatible with the Go implementation in Quilibrium's [ceremonyclient](https://github.com/quilibriumnetwork/ceremonyclient).

## Documentation

For complete API documentation, run:

```bash
cargo doc --open
```

Or visit [docs.rs/quilibrium-verkle](https://docs.rs/quilibrium-verkle).

## Testing

Run the test suite:

```bash
cargo test
```

The test suite includes:
- Unit tests for all components
- Integration tests with known test vectors
- Go compatibility tests

## License

Licensed under the MIT License. See [LICENSE](LICENSE) for details.

## Contributing

Contributions are welcome! Please ensure:
- All tests pass (`cargo test`)
- Code is formatted (`cargo fmt`)
- No clippy warnings (`cargo clippy`)

## References

- [Verkle Trees](https://vitalik.ca/general/22.1.06/18/verkle.html)
- [KZG Commitments](https://dankradfeist.de/ethereum/2020/06/16/kate-polynomial-commitments.html)
- [BLS48-581 Curve](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-pairing-friendly-curves)
- [Quilibrium Network](https://quilibrium.com)
