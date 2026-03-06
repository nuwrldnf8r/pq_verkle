use super::node::{
    VectorCommitmentNode, VectorCommitmentLeafNode, VectorCommitmentBranchNode,
};
use crate::{VerkleError, Result};
use std::sync::Once;

static INIT_BLS: Once = Once::new();

fn ensure_bls_init() {
    INIT_BLS.call_once(|| {
        bls48581::init();
    });
}

/// Vector Commitment Trie
#[derive(Clone)]
pub struct VectorCommitmentTrie {
    root: Option<VectorCommitmentNode>,
}

impl VectorCommitmentTrie {
    /// Create a new empty trie
    pub fn new() -> Self {
        Self { root: None }
    }

    /// Insert a key-value pair into the trie
    pub fn insert(&mut self, key: Vec<u8>, value: Vec<u8>) -> Result<()> {
        let new_leaf = VectorCommitmentNode::Leaf(VectorCommitmentLeafNode::new(key.clone(), value));

        if self.root.is_none() {
            // First insertion - create root
            self.root = Some(new_leaf);
            return Ok(());
        }

        // Get key path (convert key bytes to 6-bit indices)
        let path = Self::key_to_path(&key);

        // Insert recursively
        let root = self.root.take().unwrap();
        self.root = Some(self.insert_recursive(root, new_leaf, &path, 0)?);

        Ok(())
    }

    /// Recursive insertion helper
    fn insert_recursive(
        &mut self,
        node: VectorCommitmentNode,
        new_leaf: VectorCommitmentNode,
        path: &[usize],
        depth: usize,
    ) -> Result<VectorCommitmentNode> {
        match node {
            VectorCommitmentNode::Leaf(leaf) => {
                // Current node is a leaf - need to split
                let old_key = leaf.key.clone();
                let old_value = leaf.value.clone();
                let old_hash_target = leaf.hash_target.clone();

                let old_path = Self::key_to_path(&old_key);

                // Check if this is actually the same key (update scenario)
                if old_path == path {
                    // Same key - return new leaf to replace old one
                    return Ok(new_leaf);
                }

                // Find where paths diverge (starting from depth, not 0)
                let mut diverge_depth = depth;
                while diverge_depth < path.len() && diverge_depth < old_path.len()
                    && path[diverge_depth] == old_path[diverge_depth] {
                    diverge_depth += 1;
                }

                // Get shared nibbles from depth to diverge_depth
                let shared_nibbles = if diverge_depth > depth {
                    path[depth..diverge_depth].to_vec()
                } else {
                    vec![]
                };

                // Create single branch with shared prefix
                let mut branch = VectorCommitmentBranchNode::new(shared_nibbles);

                // Recreate old leaf
                let old_leaf_node = if let Some(hash_target) = old_hash_target {
                    VectorCommitmentNode::Leaf(VectorCommitmentLeafNode::new_with_hash(old_key, old_value, hash_target))
                } else {
                    VectorCommitmentNode::Leaf(VectorCommitmentLeafNode::new(old_key, old_value))
                };

                // Place both leaves at their diverging indices
                if diverge_depth < old_path.len() && diverge_depth < path.len() {
                    let old_index = old_path[diverge_depth];
                    let new_index = path[diverge_depth];
                    branch.set_child(old_index, old_leaf_node);
                    branch.set_child(new_index, new_leaf);
                } else if diverge_depth < old_path.len() {
                    // New path is prefix of old path
                    let old_index = old_path[diverge_depth];
                    branch.set_child(old_index, old_leaf_node);
                    // new_leaf stays at this level (no further index)
                } else if diverge_depth < path.len() {
                    // Old path is prefix of new path
                    let new_index = path[diverge_depth];
                    branch.set_child(new_index, new_leaf);
                    // old_leaf stays at this level
                }

                Ok(VectorCommitmentNode::Branch(Box::new(branch)))
            }
            VectorCommitmentNode::Branch(mut branch) => {
                // Current node is a branch - check if path matches prefix
                for (i, &prefix_nibble) in branch.prefix.iter().enumerate() {
                    if depth + i >= path.len() {
                        return Err(VerkleError::CryptoError("Path too short for branch prefix".to_string()));
                    }
                    if path[depth + i] != prefix_nibble {
                        // Path diverges from prefix - need to split the branch
                        // This creates a new branch with shorter prefix
                        let diverge_point = i;
                        let new_prefix = branch.prefix[..diverge_point].to_vec();
                        let old_branch_index = branch.prefix[diverge_point]; // Get before modifying
                        let new_leaf_index = path[depth + diverge_point];

                        let mut new_branch = VectorCommitmentBranchNode::new(new_prefix);

                        // Old branch keeps the rest of its prefix
                        branch.prefix = branch.prefix[diverge_point + 1..].to_vec();
                        new_branch.set_child(old_branch_index, VectorCommitmentNode::Branch(branch));

                        // New leaf goes at its index
                        new_branch.set_child(new_leaf_index, new_leaf);

                        return Ok(VectorCommitmentNode::Branch(Box::new(new_branch)));
                    }
                }

                // Path matches prefix - skip past it
                let new_depth = depth + branch.prefix.len();

                if new_depth >= path.len() {
                    return Err(VerkleError::CryptoError("Path exhausted after prefix".to_string()));
                }

                let index = path[new_depth];

                if let Some(child) = branch.get_child_mut(index) {
                    // Child exists - recurse
                    let child_clone = child.clone();
                    let new_child = self.insert_recursive(child_clone, new_leaf, path, new_depth + 1)?;
                    branch.set_child(index, new_child);
                } else {
                    // No child at this index - insert leaf directly
                    branch.set_child(index, new_leaf);
                }

                Ok(VectorCommitmentNode::Branch(branch))
            }
        }
    }

    /// Look up a value by key
    pub fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        let path = Self::key_to_path(key);
        self.get_recursive(self.root.as_ref()?, &path, 0)
    }

    /// Recursive lookup helper
    fn get_recursive(
        &self,
        node: &VectorCommitmentNode,
        path: &[usize],
        depth: usize,
    ) -> Option<Vec<u8>> {
        match node {
            VectorCommitmentNode::Leaf(leaf) => {
                // Check if keys match by comparing the original key
                let leaf_path = Self::key_to_path(&leaf.key);
                if leaf_path == path {
                    return Some(leaf.value.clone());
                }
                None
            }
            VectorCommitmentNode::Branch(branch) => {
                // Check if the path matches the branch's prefix
                for (i, &prefix_nibble) in branch.prefix.iter().enumerate() {
                    if depth + i >= path.len() || path[depth + i] != prefix_nibble {
                        return None;
                    }
                }

                // Skip past the prefix
                let new_depth = depth + branch.prefix.len();

                if new_depth >= path.len() {
                    return None;
                }

                let index = path[new_depth];
                let child = branch.get_child(index)?;
                self.get_recursive(child, path, new_depth + 1)
            }
        }
    }

    /// Compute the root commitment
    pub fn commit(&mut self) -> Option<Vec<u8>> {
        self.root.as_mut().map(|node| node.commit(false))
    }

    /// Get the polynomial from the root branch node
    pub fn get_polynomial(&mut self) -> Option<Vec<u8>> {
        self.root.as_mut().and_then(|node| {
            if let VectorCommitmentNode::Branch(branch) = node {
                Some(branch.get_polynomial())
            } else {
                None
            }
        })
    }

    /// Generate a proof for a single key
    /// Returns None if the key is not found in the trie
    pub fn prove(&mut self, key: &[u8]) -> Option<crate::proof::TraversalProof> {
        if key.is_empty() {
            return None;
        }

        let path = Self::key_to_path(key);

        // Recursive proof function
        fn prove_recursive(
            node: &mut VectorCommitmentNode,
            key: &[u8],
            path: &[usize],
            depth: usize,
        ) -> Option<(Vec<Vec<u8>>, Vec<Vec<u8>>, Vec<Vec<u8>>, Vec<Vec<usize>>)> {
            match node {
                VectorCommitmentNode::Leaf(leaf) => {
                    // Check if this is the target leaf
                    if leaf.key == key {
                        let commitment = leaf.commit(false);
                        let value = if let Some(ref hash_target) = leaf.hash_target {
                            hash_target.clone()
                        } else {
                            leaf.value.clone()
                        };

                        // Leaf proof: no polynomials, just commitment and value
                        // No path for leaf - paths are only for branches
                        return Some((
                            vec![],           // polynomials
                            vec![commitment], // commits
                            vec![value],      // ys (values)
                            vec![],           // paths (no path for leaf)
                        ));
                    }
                    None
                }
                VectorCommitmentNode::Branch(branch) => {
                    // Check prefix match
                    for (i, &prefix_nibble) in branch.prefix.iter().enumerate() {
                        if depth + i >= path.len() || path[depth + i] != prefix_nibble {
                            return None;
                        }
                    }

                    // Get final nibble after prefix
                    let new_depth = depth + branch.prefix.len();
                    if new_depth >= path.len() {
                        return None;
                    }

                    let final_nibble = path[new_depth];

                    // Get branch commitment and polynomial
                    let branch_commitment = branch.commit(false);
                    let polynomial = branch.get_polynomial();

                    // Extract the y-value (64-byte chunk) for this nibble
                    let y_start = final_nibble * 64;
                    let y_end = y_start + 64;
                    let y_value = polynomial[y_start..y_end].to_vec();

                    // Recursively prove child
                    let child = branch.get_child_mut(final_nibble)?;
                    let (child_polys, child_commits, child_ys, child_paths) =
                        prove_recursive(child, key, path, new_depth + 1)?;

                    // Build current path (prefix + final nibble)
                    let mut current_path = branch.prefix.clone();
                    current_path.push(final_nibble);

                    // Combine results
                    let mut polynomials = vec![polynomial];
                    polynomials.extend(child_polys);

                    let mut commits = vec![branch_commitment];
                    commits.extend(child_commits);

                    let mut ys = vec![y_value];
                    ys.extend(child_ys);

                    let mut paths = vec![current_path];
                    paths.extend(child_paths);

                    Some((polynomials, commits, ys, paths))
                }
            }
        }

        let root = self.root.as_mut()?;
        let (polynomials, commits, ys, paths) = prove_recursive(root, key, &path, 0)?;

        if commits.is_empty() {
            return None;
        }

        // Convert paths to u64
        let path_indices: Vec<Vec<u64>> = paths
            .iter()
            .map(|p| p.iter().map(|&i| i as u64).collect())
            .collect();

        // Extract last nibble from each path as indices for multiproof
        let indices: Vec<u64> = paths
            .iter()
            .filter(|p| !p.is_empty())
            .map(|p| p[p.len() - 1] as u64)
            .collect();

        // Initialize BLS
        ensure_bls_init();

        // Generate multiproof (exclude last commit which is the leaf)
        let multiproof_bytes = if commits.len() > 1 {
            let commits_vec = commits[..commits.len() - 1].to_vec();
            let multiproof = bls48581::prove_multiple(&commits_vec, &polynomials, &indices, 64);
            // Serialize multiproof: length(d) + d + length(proof) + proof
            let mut bytes = Vec::new();
            bytes.extend_from_slice(&(multiproof.d.len() as u32).to_be_bytes());
            bytes.extend_from_slice(&multiproof.d);
            bytes.extend_from_slice(&(multiproof.proof.len() as u32).to_be_bytes());
            bytes.extend_from_slice(&multiproof.proof);
            bytes
        } else {
            Vec::new()
        };

        Some(crate::proof::TraversalProof {
            multiproof: multiproof_bytes,
            sub_proofs: vec![crate::proof::TraversalSubProof {
                commits,
                ys,
                paths: path_indices,
            }],
        })
    }

    /// Generate proofs for multiple keys
    /// Returns a single proof containing all sub-proofs
    pub fn prove_multiple(&mut self, keys: &[Vec<u8>]) -> Option<crate::proof::TraversalProof> {
        if keys.is_empty() {
            return None;
        }

        let mut all_polynomials = Vec::new();
        let mut all_commits = Vec::new();
        let mut all_indices = Vec::new();
        let mut sub_proofs = Vec::new();

        for key in keys {
            if key.is_empty() {
                continue;
            }

            let path = Self::key_to_path(key);

            // Recursive proof function (same as single-key prove)
            fn prove_recursive(
                node: &mut VectorCommitmentNode,
                key: &[u8],
                path: &[usize],
                depth: usize,
            ) -> Option<(Vec<Vec<u8>>, Vec<Vec<u8>>, Vec<Vec<u8>>, Vec<Vec<usize>>)> {
                match node {
                    VectorCommitmentNode::Leaf(leaf) => {
                        if leaf.key == key {
                            let commitment = leaf.commit(false);
                            let value = if let Some(ref hash_target) = leaf.hash_target {
                                hash_target.clone()
                            } else {
                                leaf.value.clone()
                            };

                            return Some((
                                vec![],
                                vec![commitment],
                                vec![value],
                                vec![vec![]],
                            ));
                        }
                        None
                    }
                    VectorCommitmentNode::Branch(branch) => {
                        for (i, &prefix_nibble) in branch.prefix.iter().enumerate() {
                            if depth + i >= path.len() || path[depth + i] != prefix_nibble {
                                return None;
                            }
                        }

                        let new_depth = depth + branch.prefix.len();
                        if new_depth >= path.len() {
                            return None;
                        }

                        let final_nibble = path[new_depth];

                        let branch_commitment = branch.commit(false);
                        let polynomial = branch.get_polynomial();

                        let y_start = final_nibble * 64;
                        let y_end = y_start + 64;
                        let y_value = polynomial[y_start..y_end].to_vec();

                        let child = branch.get_child_mut(final_nibble)?;
                        let (child_polys, child_commits, child_ys, child_paths) =
                            prove_recursive(child, key, path, new_depth + 1)?;

                        let mut current_path = branch.prefix.clone();
                        current_path.push(final_nibble);

                        let mut polynomials = vec![polynomial];
                        polynomials.extend(child_polys);

                        let mut commits = vec![branch_commitment];
                        commits.extend(child_commits);

                        let mut ys = vec![y_value];
                        ys.extend(child_ys);

                        let mut paths = vec![current_path];
                        paths.extend(child_paths);

                        Some((polynomials, commits, ys, paths))
                    }
                }
            }

            let root = self.root.as_mut()?;
            let (polynomials, commits, ys, paths) = match prove_recursive(root, key, &path, 0) {
                Some(result) => result,
                None => continue, // Skip keys that don't exist
            };

            if commits.is_empty() {
                continue;
            }

            // Convert paths to u64
            let path_indices: Vec<Vec<u64>> = paths
                .iter()
                .map(|p| p.iter().map(|&i| i as u64).collect())
                .collect();

            // Extract indices for multiproof
            let indices: Vec<u64> = paths
                .iter()
                .filter(|p| !p.is_empty())
                .map(|p| p[p.len() - 1] as u64)
                .collect();

            // Collect for combined multiproof
            all_polynomials.extend(polynomials);

            // Only add branch commits (exclude leaf commits from multiproof)
            if commits.len() > 1 {
                all_commits.extend(commits[..commits.len() - 1].iter().cloned());
            }

            all_indices.extend(indices);

            // Add sub-proof
            sub_proofs.push(crate::proof::TraversalSubProof {
                commits,
                ys,
                paths: path_indices,
            });
        }

        if sub_proofs.is_empty() {
            return None;
        }

        // Initialize BLS
        ensure_bls_init();

        // Generate combined multiproof
        let multiproof_bytes = if !all_commits.is_empty() && !all_polynomials.is_empty() {
            let multiproof = bls48581::prove_multiple(&all_commits, &all_polynomials, &all_indices, 64);
            let mut bytes = Vec::new();
            bytes.extend_from_slice(&(multiproof.d.len() as u32).to_be_bytes());
            bytes.extend_from_slice(&multiproof.d);
            bytes.extend_from_slice(&(multiproof.proof.len() as u32).to_be_bytes());
            bytes.extend_from_slice(&multiproof.proof);
            bytes
        } else {
            Vec::new()
        };

        Some(crate::proof::TraversalProof {
            multiproof: multiproof_bytes,
            sub_proofs,
        })
    }

    /// Convert a key to a path of 6-bit indices
    fn key_to_path(key: &[u8]) -> Vec<usize> {
        let mut path = Vec::new();
        let mut bit_buffer = 0u32;
        let mut bits_in_buffer = 0;

        for &byte in key {
            // Add byte to buffer
            bit_buffer = (bit_buffer << 8) | (byte as u32);
            bits_in_buffer += 8;

            // Extract 6-bit indices while we have enough bits
            while bits_in_buffer >= 6 {
                bits_in_buffer -= 6;
                let index = ((bit_buffer >> bits_in_buffer) & 0x3F) as usize;
                path.push(index);
            }
        }

        // Handle remaining bits if any
        if bits_in_buffer > 0 {
            let index = ((bit_buffer << (6 - bits_in_buffer)) & 0x3F) as usize;
            path.push(index);
        }

        path
    }
}

impl Default for VectorCommitmentTrie {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trie_insert_and_get() {
        let mut trie = VectorCommitmentTrie::new();

        // Test single insert
        trie.insert(b"key1".to_vec(), b"value1".to_vec()).unwrap();
        assert_eq!(trie.get(b"key1"), Some(b"value1".to_vec()));

        // Test second insert with different key
        trie.insert(b"key2".to_vec(), b"value2".to_vec()).unwrap();
        assert_eq!(trie.get(b"key1"), Some(b"value1".to_vec()));
        assert_eq!(trie.get(b"key2"), Some(b"value2".to_vec()));

        // Test third insert
        trie.insert(b"key3".to_vec(), b"value3".to_vec()).unwrap();
        assert_eq!(trie.get(b"key1"), Some(b"value1".to_vec()));
        assert_eq!(trie.get(b"key2"), Some(b"value2".to_vec()));
        assert_eq!(trie.get(b"key3"), Some(b"value3".to_vec()));

        // Test missing key
        assert_eq!(trie.get(b"key4"), None);
    }

    #[test]
    fn test_trie_commitment() {
        let mut trie = VectorCommitmentTrie::new();

        trie.insert(b"test".to_vec(), b"data".to_vec()).unwrap();

        let commitment = trie.commit();
        assert!(commitment.is_some());
        // Single leaf: SHA512 = 64 bytes
        assert_eq!(commitment.unwrap().len(), 64);
    }

    #[test]
    fn test_trie_branch_commitment() {
        let mut trie = VectorCommitmentTrie::new();

        // Insert multiple keys to create a branch
        trie.insert(b"key1".to_vec(), b"value1".to_vec()).unwrap();
        trie.insert(b"key2".to_vec(), b"value2".to_vec()).unwrap();

        let commitment = trie.commit();
        assert!(commitment.is_some());
        // Branch node: KZG commitment = 74 bytes
        assert_eq!(commitment.unwrap().len(), 74);
    }
}
