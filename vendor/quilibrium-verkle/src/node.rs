use sha2::{Sha512, Digest};
use num_bigint::BigUint;
use bls48581;
use std::sync::Once;

static INIT_BLS: Once = Once::new();

fn ensure_bls_init() {
    INIT_BLS.call_once(|| {
        bls48581::init();
    });
}

/// Number of children per branch node (64-ary tree)
pub const BRANCH_NODES: usize = 64;
/// Bits per branch level (log2(64) = 6)
pub const BRANCH_BITS: usize = 6;
/// Mask for extracting branch index
pub const BRANCH_MASK: usize = BRANCH_NODES - 1;

/// Node types for serialization
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeType {
    Nil = 0,
    Leaf = 1,
    Branch = 2,
}

/// Vector commitment node - enum variant approach for safety
#[derive(Clone)]
pub enum VectorCommitmentNode {
    Leaf(VectorCommitmentLeafNode),
    Branch(Box<VectorCommitmentBranchNode>),
}

impl VectorCommitmentNode {
    /// Compute the commitment for this node
    pub fn commit(&mut self, recalculate: bool) -> Vec<u8> {
        match self {
            VectorCommitmentNode::Leaf(leaf) => leaf.commit(recalculate),
            VectorCommitmentNode::Branch(branch) => branch.commit(recalculate),
        }
    }

    /// Get the size of this node
    pub fn get_size(&self) -> BigUint {
        match self {
            VectorCommitmentNode::Leaf(leaf) => leaf.size.clone(),
            VectorCommitmentNode::Branch(branch) => branch.size.clone(),
        }
    }

    /// Check if this is a leaf node
    pub fn is_leaf(&self) -> bool {
        matches!(self, VectorCommitmentNode::Leaf(_))
    }

    /// Check if this is a branch node
    pub fn is_branch(&self) -> bool {
        matches!(self, VectorCommitmentNode::Branch(_))
    }

    /// Get as leaf reference
    pub fn as_leaf(&self) -> Option<&VectorCommitmentLeafNode> {
        match self {
            VectorCommitmentNode::Leaf(leaf) => Some(leaf),
            _ => None,
        }
    }

    /// Get as mutable leaf reference
    pub fn as_leaf_mut(&mut self) -> Option<&mut VectorCommitmentLeafNode> {
        match self {
            VectorCommitmentNode::Leaf(leaf) => Some(leaf),
            _ => None,
        }
    }

    /// Get as branch reference
    pub fn as_branch(&self) -> Option<&VectorCommitmentBranchNode> {
        match self {
            VectorCommitmentNode::Branch(branch) => Some(branch),
            _ => None,
        }
    }

    /// Get as mutable branch reference
    pub fn as_branch_mut(&mut self) -> Option<&mut VectorCommitmentBranchNode> {
        match self {
            VectorCommitmentNode::Branch(branch) => Some(branch),
            _ => None,
        }
    }
}

/// Leaf node containing a key-value pair
#[derive(Debug, Clone)]
pub struct VectorCommitmentLeafNode {
    /// Key for this leaf
    pub key: Vec<u8>,
    /// Value stored at this leaf
    pub value: Vec<u8>,
    /// Optional hash target (if provided, used instead of value for commitment)
    pub hash_target: Option<Vec<u8>>,
    /// Cached commitment
    pub commitment: Option<Vec<u8>>,
    /// Size (always 1 for a leaf)
    pub size: BigUint,
}

impl VectorCommitmentLeafNode {
    /// Create a new leaf node
    pub fn new(key: Vec<u8>, value: Vec<u8>) -> Self {
        Self {
            key,
            value,
            hash_target: None,
            commitment: None,
            size: BigUint::from(1u32),
        }
    }

    /// Create a new leaf node with a hash target
    pub fn new_with_hash(key: Vec<u8>, value: Vec<u8>, hash_target: Vec<u8>) -> Self {
        Self {
            key,
            value,
            hash_target: Some(hash_target),
            commitment: None,
            size: BigUint::from(1u32),
        }
    }

    pub fn commit(&mut self, recalculate: bool) -> Vec<u8> {
        if self.commitment.is_none() || recalculate {
            // Use SHA512 for leaf commitments (matches Go implementation)
            let mut hasher = Sha512::new();
            // Type byte for leaf
            hasher.update([0u8]);
            // Key
            hasher.update(&self.key);
            // Value or hash target
            if let Some(ref hash_target) = self.hash_target {
                hasher.update(hash_target);
            } else {
                hasher.update(&self.value);
            }
            self.commitment = Some(hasher.finalize().to_vec());
        }
        self.commitment.as_ref().unwrap().clone()
    }
}

/// Branch node with 64 children
#[derive(Clone)]
pub struct VectorCommitmentBranchNode {
    /// Prefix bits for this branch (path from root)
    pub prefix: Vec<usize>,
    /// Children nodes (64-way branching)
    pub children: [Option<VectorCommitmentNode>; BRANCH_NODES],
    /// Cached commitment
    pub commitment: Option<Vec<u8>>,
    /// Total size of all children
    pub size: BigUint,
    /// Number of leaf nodes under this branch
    pub leaf_count: usize,
    /// Length of longest branch path
    pub longest_branch: usize,
}

impl VectorCommitmentBranchNode {
    /// Create a new branch node
    pub fn new(prefix: Vec<usize>) -> Self {
        // Create array of None options
        const INIT: Option<VectorCommitmentNode> = None;
        let children = [INIT; BRANCH_NODES];

        Self {
            prefix,
            children,
            commitment: None,
            size: BigUint::from(0u32),
            leaf_count: 0,
            longest_branch: 0,
        }
    }

    /// Get the polynomial data for this branch (64 × 64 bytes)
    /// This is the same data used for commitment, but returned for proof generation
    pub fn get_polynomial(&mut self) -> Vec<u8> {
        let mut data = Vec::with_capacity(BRANCH_NODES * 64);

        for child_opt in &mut self.children {
            if let Some(child) = child_opt {
                let child_commit = child.commit(false);

                // For branch children, hash with prefix
                let commit = if let Some(branch) = child.as_branch() {
                    let mut hasher = sha2::Sha512::new();
                    hasher.update([1u8]); // Type byte for branch

                    // Include prefix
                    for &p in &branch.prefix {
                        hasher.update((p as u32).to_be_bytes());
                    }

                    hasher.update(&child_commit);
                    hasher.finalize().to_vec()
                } else {
                    // Leaf - use commitment as-is (SHA512, 64 bytes)
                    child_commit
                };

                data.extend_from_slice(&commit);
            } else {
                // Empty slot - push zeros (64 bytes)
                data.extend_from_slice(&vec![0u8; 64]);
            }
        }

        data
    }

    /// Generate a KZG proof for a specific child index
    /// Returns the proof bytes that can be used to verify the child commitment
    pub fn prove(&mut self, index: usize) -> Option<Vec<u8>> {
        if index >= BRANCH_NODES {
            return None;
        }

        // Get polynomial data
        let data = self.get_polynomial();

        // Initialize BLS48581 if not already done
        ensure_bls_init();

        // Generate KZG proof for the specific index
        let proof = bls48581::prove_raw(&data, index as u64, 64);
        Some(proof)
    }

    /// Set a child at the given index
    pub fn set_child(&mut self, index: usize, child: VectorCommitmentNode) {
        if index < BRANCH_NODES {
            self.children[index] = Some(child);
            self.commitment = None; // Invalidate cache
        }
    }

    /// Get a child at the given index
    pub fn get_child(&self, index: usize) -> Option<&VectorCommitmentNode> {
        if index < BRANCH_NODES {
            self.children[index].as_ref()
        } else {
            None
        }
    }

    /// Get a mutable child at the given index
    pub fn get_child_mut(&mut self, index: usize) -> Option<&mut VectorCommitmentNode> {
        if index < BRANCH_NODES {
            self.children[index].as_mut()
        } else {
            None
        }
    }

    pub fn commit(&mut self, recalculate: bool) -> Vec<u8> {
        if self.commitment.is_none() || recalculate {
            // Collect all child commitments (SHA512 hashes, 64 bytes each)
            let mut vector: Vec<Vec<u8>> = Vec::with_capacity(BRANCH_NODES);

            for child_opt in &mut self.children {
                if let Some(child) = child_opt {
                    let child_commit = child.commit(recalculate);

                    // For branch children, hash with prefix
                    let commit = if let Some(branch) = child.as_branch() {
                        let mut hasher = Sha512::new();
                        hasher.update([1u8]); // Type byte for branch

                        // Include prefix
                        for &p in &branch.prefix {
                            hasher.update((p as u32).to_be_bytes());
                        }

                        hasher.update(&child_commit);
                        hasher.finalize().to_vec()
                    } else {
                        // Leaf - use commitment as-is (SHA512, 64 bytes)
                        child_commit
                    };

                    vector.push(commit);
                } else {
                    // Empty slot - push zeros (64 bytes to match SHA512)
                    vector.push(vec![0u8; 64]);
                }
            }

            // Flatten into polynomial: 64 children × 64 bytes = 4096 bytes
            let mut data = Vec::with_capacity(BRANCH_NODES * 64);
            for commit in &vector {
                data.extend_from_slice(commit);
            }

            // Initialize BLS48581 if not already done
            ensure_bls_init();

            // Compute KZG commitment with poly_size = 64
            // The polynomial has 64 coefficients (one per child)
            let commitment = bls48581::commit_raw(&data, 64);

            self.commitment = Some(commitment);

            // Update size
            self.size = BigUint::from(0u32);
            for child_opt in &self.children {
                if let Some(child) = child_opt {
                    self.size += child.get_size();
                }
            }
        }

        self.commitment.as_ref().unwrap().clone()
    }
}
