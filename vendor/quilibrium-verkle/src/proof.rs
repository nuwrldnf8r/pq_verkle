use crate::{VerkleError, Result};
use std::io::{Write, Read};

/// Sub-proof for a single key in the traversal
#[derive(Debug, Clone)]
pub struct TraversalSubProof {
    /// Commitments along the path
    pub commits: Vec<Vec<u8>>,
    /// Evaluation points (y-values)
    pub ys: Vec<Vec<u8>>,
    /// Indices along the path
    pub paths: Vec<Vec<u64>>,
}

impl TraversalSubProof {
    pub fn new() -> Self {
        Self {
            commits: Vec::new(),
            ys: Vec::new(),
            paths: Vec::new(),
        }
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut buf = Vec::new();

        // Write number of commits
        buf.write_all(&(self.commits.len() as u32).to_be_bytes())
            .map_err(|e| VerkleError::SerializationError(e.to_string()))?;

        // Write each commit
        for commit in &self.commits {
            buf.write_all(&(commit.len() as u32).to_be_bytes())
                .map_err(|e| VerkleError::SerializationError(e.to_string()))?;
            buf.write_all(commit)
                .map_err(|e| VerkleError::SerializationError(e.to_string()))?;
        }

        // Write number of ys
        buf.write_all(&(self.ys.len() as u32).to_be_bytes())
            .map_err(|e| VerkleError::SerializationError(e.to_string()))?;

        // Write each y
        for y in &self.ys {
            buf.write_all(&(y.len() as u32).to_be_bytes())
                .map_err(|e| VerkleError::SerializationError(e.to_string()))?;
            buf.write_all(y)
                .map_err(|e| VerkleError::SerializationError(e.to_string()))?;
        }

        // Write number of path arrays
        buf.write_all(&(self.paths.len() as u32).to_be_bytes())
            .map_err(|e| VerkleError::SerializationError(e.to_string()))?;

        // Write each path array
        for path in &self.paths {
            buf.write_all(&(path.len() as u32).to_be_bytes())
                .map_err(|e| VerkleError::SerializationError(e.to_string()))?;
            for &idx in path {
                buf.write_all(&idx.to_be_bytes())
                    .map_err(|e| VerkleError::SerializationError(e.to_string()))?;
            }
        }

        Ok(buf)
    }

    /// Deserialize from bytes
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        let mut cursor = std::io::Cursor::new(data);
        let mut proof = Self::new();

        // Read commits
        let mut len_buf = [0u8; 4];
        cursor.read_exact(&mut len_buf)
            .map_err(|e| VerkleError::SerializationError(e.to_string()))?;
        let num_commits = u32::from_be_bytes(len_buf) as usize;

        for _ in 0..num_commits {
            cursor.read_exact(&mut len_buf)
                .map_err(|e| VerkleError::SerializationError(e.to_string()))?;
            let commit_len = u32::from_be_bytes(len_buf) as usize;

            let mut commit = vec![0u8; commit_len];
            cursor.read_exact(&mut commit)
                .map_err(|e| VerkleError::SerializationError(e.to_string()))?;
            proof.commits.push(commit);
        }

        // Read ys
        cursor.read_exact(&mut len_buf)
            .map_err(|e| VerkleError::SerializationError(e.to_string()))?;
        let num_ys = u32::from_be_bytes(len_buf) as usize;

        for _ in 0..num_ys {
            cursor.read_exact(&mut len_buf)
                .map_err(|e| VerkleError::SerializationError(e.to_string()))?;
            let y_len = u32::from_be_bytes(len_buf) as usize;

            let mut y = vec![0u8; y_len];
            cursor.read_exact(&mut y)
                .map_err(|e| VerkleError::SerializationError(e.to_string()))?;
            proof.ys.push(y);
        }

        // Read paths
        cursor.read_exact(&mut len_buf)
            .map_err(|e| VerkleError::SerializationError(e.to_string()))?;
        let num_paths = u32::from_be_bytes(len_buf) as usize;

        for _ in 0..num_paths {
            cursor.read_exact(&mut len_buf)
                .map_err(|e| VerkleError::SerializationError(e.to_string()))?;
            let path_len = u32::from_be_bytes(len_buf) as usize;

            let mut path = Vec::with_capacity(path_len);
            let mut idx_buf = [0u8; 8];
            for _ in 0..path_len {
                cursor.read_exact(&mut idx_buf)
                    .map_err(|e| VerkleError::SerializationError(e.to_string()))?;
                path.push(u64::from_be_bytes(idx_buf));
            }
            proof.paths.push(path);
        }

        Ok(proof)
    }
}

/// Complete traversal proof including KZG multiproof
#[derive(Debug, Clone)]
pub struct TraversalProof {
    /// KZG multiproof data
    pub multiproof: Vec<u8>,
    /// Sub-proofs for each key
    pub sub_proofs: Vec<TraversalSubProof>,
}

impl TraversalProof {
    pub fn new() -> Self {
        Self {
            multiproof: Vec::new(),
            sub_proofs: Vec::new(),
        }
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut buf = Vec::new();

        // Write multiproof length and data
        buf.write_all(&(self.multiproof.len() as u32).to_be_bytes())
            .map_err(|e| VerkleError::SerializationError(e.to_string()))?;
        buf.write_all(&self.multiproof)
            .map_err(|e| VerkleError::SerializationError(e.to_string()))?;

        // Write number of sub-proofs
        buf.write_all(&(self.sub_proofs.len() as u32).to_be_bytes())
            .map_err(|e| VerkleError::SerializationError(e.to_string()))?;

        // Write each sub-proof inline (no sub-proof length prefix!)
        for sub_proof in &self.sub_proofs {
            // Write commits count
            buf.write_all(&(sub_proof.commits.len() as u32).to_be_bytes())
                .map_err(|e| VerkleError::SerializationError(e.to_string()))?;

            // Write each commit
            for commit in &sub_proof.commits {
                buf.write_all(&(commit.len() as u32).to_be_bytes())
                    .map_err(|e| VerkleError::SerializationError(e.to_string()))?;
                buf.write_all(commit)
                    .map_err(|e| VerkleError::SerializationError(e.to_string()))?;
            }

            // Write ys count
            buf.write_all(&(sub_proof.ys.len() as u32).to_be_bytes())
                .map_err(|e| VerkleError::SerializationError(e.to_string()))?;

            // Write each y
            for y in &sub_proof.ys {
                buf.write_all(&(y.len() as u32).to_be_bytes())
                    .map_err(|e| VerkleError::SerializationError(e.to_string()))?;
                buf.write_all(y)
                    .map_err(|e| VerkleError::SerializationError(e.to_string()))?;
            }

            // Write paths count
            buf.write_all(&(sub_proof.paths.len() as u32).to_be_bytes())
                .map_err(|e| VerkleError::SerializationError(e.to_string()))?;

            // Write each path
            for path in &sub_proof.paths {
                buf.write_all(&(path.len() as u32).to_be_bytes())
                    .map_err(|e| VerkleError::SerializationError(e.to_string()))?;
                for &idx in path {
                    buf.write_all(&idx.to_be_bytes())
                        .map_err(|e| VerkleError::SerializationError(e.to_string()))?;
                }
            }
        }

        Ok(buf)
    }

    /// Deserialize from bytes
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        let mut cursor = std::io::Cursor::new(data);
        let mut proof = Self::new();

        // Read multiproof
        let mut len_buf = [0u8; 4];
        cursor.read_exact(&mut len_buf)
            .map_err(|e| VerkleError::SerializationError(e.to_string()))?;
        let multiproof_len = u32::from_be_bytes(len_buf) as usize;

        proof.multiproof = vec![0u8; multiproof_len];
        cursor.read_exact(&mut proof.multiproof)
            .map_err(|e| VerkleError::SerializationError(e.to_string()))?;

        // Read sub-proofs
        cursor.read_exact(&mut len_buf)
            .map_err(|e| VerkleError::SerializationError(e.to_string()))?;
        let num_sub_proofs = u32::from_be_bytes(len_buf) as usize;

        for _ in 0..num_sub_proofs {
            let mut sub_proof = TraversalSubProof::new();

            // Read commits
            cursor.read_exact(&mut len_buf)
                .map_err(|e| VerkleError::SerializationError(e.to_string()))?;
            let num_commits = u32::from_be_bytes(len_buf) as usize;

            for _ in 0..num_commits {
                cursor.read_exact(&mut len_buf)
                    .map_err(|e| VerkleError::SerializationError(e.to_string()))?;
                let commit_len = u32::from_be_bytes(len_buf) as usize;

                let mut commit = vec![0u8; commit_len];
                cursor.read_exact(&mut commit)
                    .map_err(|e| VerkleError::SerializationError(e.to_string()))?;
                sub_proof.commits.push(commit);
            }

            // Read ys
            cursor.read_exact(&mut len_buf)
                .map_err(|e| VerkleError::SerializationError(e.to_string()))?;
            let num_ys = u32::from_be_bytes(len_buf) as usize;

            for _ in 0..num_ys {
                cursor.read_exact(&mut len_buf)
                    .map_err(|e| VerkleError::SerializationError(e.to_string()))?;
                let y_len = u32::from_be_bytes(len_buf) as usize;

                let mut y = vec![0u8; y_len];
                cursor.read_exact(&mut y)
                    .map_err(|e| VerkleError::SerializationError(e.to_string()))?;
                sub_proof.ys.push(y);
            }

            // Read paths
            cursor.read_exact(&mut len_buf)
                .map_err(|e| VerkleError::SerializationError(e.to_string()))?;
            let num_paths = u32::from_be_bytes(len_buf) as usize;

            for _ in 0..num_paths {
                cursor.read_exact(&mut len_buf)
                    .map_err(|e| VerkleError::SerializationError(e.to_string()))?;
                let path_len = u32::from_be_bytes(len_buf) as usize;

                let mut path = Vec::with_capacity(path_len);
                let mut idx_buf = [0u8; 8];
                for _ in 0..path_len {
                    cursor.read_exact(&mut idx_buf)
                        .map_err(|e| VerkleError::SerializationError(e.to_string()))?;
                    path.push(u64::from_be_bytes(idx_buf));
                }
                sub_proof.paths.push(path);
            }

            proof.sub_proofs.push(sub_proof);
        }

        Ok(proof)
    }
}

impl Default for TraversalSubProof {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for TraversalProof {
    fn default() -> Self {
        Self::new()
    }
}

impl TraversalProof {
    /// Verify this proof against a root commitment
    /// Returns true if the proof is valid for the given root commitment
    pub fn verify(&self, root_commitment: &[u8]) -> Result<bool> {
        if self.sub_proofs.is_empty() {
            return Err(VerkleError::CryptoError("No sub-proofs to verify".to_string()));
        }

        // Initialize BLS
        use std::sync::Once;
        static INIT_BLS: Once = Once::new();
        INIT_BLS.call_once(|| {
            bls48581::init();
        });

        // If we have a multiproof, verify it
        if !self.multiproof.is_empty() {
            // Deserialize multiproof
            if self.multiproof.len() < 8 {
                return Err(VerkleError::CryptoError("Invalid multiproof format".to_string()));
            }

            let mut cursor = std::io::Cursor::new(&self.multiproof);

            let mut len_buf = [0u8; 4];
            cursor.read_exact(&mut len_buf)
                .map_err(|e| VerkleError::CryptoError(format!("Failed to read d length: {}", e)))?;
            let d_len = u32::from_be_bytes(len_buf) as usize;

            let mut d = vec![0u8; d_len];
            cursor.read_exact(&mut d)
                .map_err(|e| VerkleError::CryptoError(format!("Failed to read d: {}", e)))?;

            cursor.read_exact(&mut len_buf)
                .map_err(|e| VerkleError::CryptoError(format!("Failed to read proof length: {}", e)))?;
            let proof_len = u32::from_be_bytes(len_buf) as usize;

            let mut proof_bytes = vec![0u8; proof_len];
            cursor.read_exact(&mut proof_bytes)
                .map_err(|e| VerkleError::CryptoError(format!("Failed to read proof: {}", e)))?;

            // Collect all commits and indices from sub-proofs
            let mut all_commits = Vec::new();
            let mut all_ys = Vec::new();
            let mut all_indices = Vec::new();

            for sub_proof in &self.sub_proofs {
                // Skip leaf commits (only verify branch commits with multiproof)
                if sub_proof.commits.len() > 1 {
                    all_commits.extend(sub_proof.commits[..sub_proof.commits.len() - 1].iter().cloned());
                    all_ys.extend(sub_proof.ys[..sub_proof.ys.len() - 1].iter().cloned());
                }

                // Extract indices from paths
                for path in &sub_proof.paths {
                    if !path.is_empty() {
                        all_indices.push(path[path.len() - 1]);
                    }
                }
            }

            // Verify multiproof
            let verified = bls48581::verify_multiple(&all_commits, &all_ys, &all_indices, 64, &d, &proof_bytes);

            if !verified {
                return Ok(false);
            }
        }

        // Verify that the first commit in the first sub-proof matches the root
        if let Some(first_sub_proof) = self.sub_proofs.first() {
            if let Some(first_commit) = first_sub_proof.commits.first() {
                if first_commit != root_commitment {
                    return Ok(false);
                }
            } else {
                return Err(VerkleError::CryptoError("Sub-proof has no commits".to_string()));
            }
        }

        Ok(true)
    }

    /// Verify this proof and extract the values for the proven keys
    /// Returns a vector of (key_index, value) pairs if verification succeeds
    pub fn verify_and_extract(&self, root_commitment: &[u8]) -> Result<Vec<Vec<u8>>> {
        if !self.verify(root_commitment)? {
            return Err(VerkleError::CryptoError("Proof verification failed".to_string()));
        }

        // Extract the last y-value from each sub-proof (which is the leaf value)
        let mut values = Vec::new();
        for sub_proof in &self.sub_proofs {
            if let Some(last_y) = sub_proof.ys.last() {
                values.push(last_y.clone());
            }
        }

        Ok(values)
    }
}
