use quilibrium_verkle::{TraversalProof, VectorCommitmentTrie};

use crate::{
    error::PqVerkleError,
    pq_hash::{commitment_sign_message, proof_binding},
    pq_sign::PQKeypair,
};

// ─────────────────────────────────────────────────────────────────────────────
// PQCommitment
// ─────────────────────────────────────────────────────────────────────────────

/// A Verkle root commitment authenticated by a post-quantum signature.
///
/// The 74-byte KZG commitment produced by the underlying
/// [`quilibrium_verkle`] trie is signed with a Dilithium3 (ML-DSA-65) key.
/// Any party holding the embedded `pq_pubkey` can verify the signature without
/// interacting with the tree owner, even on a future quantum computer.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PQCommitment {
    /// Raw 74-byte KZG Verkle root commitment.
    pub commitment: Vec<u8>,

    /// Dilithium3 detached signature (3293 bytes) over
    /// `SHAKE-256(DOMAIN_ROOT || commitment)`.
    pub pq_signature: Vec<u8>,

    /// Dilithium3 public key (1952 bytes) used to produce the signature.
    /// Embed this in your certificate / protocol handshake so verifiers do
    /// not need an out-of-band PKI lookup.
    pub pq_pubkey: Vec<u8>,
}

impl PQCommitment {
    /// Verify the post-quantum signature embedded in this commitment.
    ///
    /// Returns `true` if the signature is valid for the embedded public key
    /// and would therefore have been produced by the owner of the private key.
    pub fn verify_pq_signature(&self) -> Result<bool, PqVerkleError> {
        let msg = commitment_sign_message(&self.commitment);
        PQKeypair::verify_with_pubkey(&msg, &self.pq_signature, &self.pq_pubkey)
    }

    /// Returns the raw KZG commitment bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.commitment
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PQProof
// ─────────────────────────────────────────────────────────────────────────────

/// A Verkle inclusion proof bound to a specific commitment via SHAKE-256.
///
/// In addition to the inner [`TraversalProof`] from `quilibrium_verkle`, every
/// `PQProof` carries a *binding tag* — a 64-byte SHAKE-256 digest of
/// `(DOMAIN_PROOF || commitment || keys)` — that is recomputed during
/// verification.  If the binding tag does not match, verification is rejected,
/// preventing a proof from being replayed against a different commitment.
#[derive(Debug)]
pub struct PQProof {
    /// The key(s) this proof covers, in order.
    pub(crate) keys: Vec<Vec<u8>>,

    /// SHAKE-256 binding tag over `(commitment || keys)`.
    /// Computed at proof-generation time and stored here.
    pub(crate) pq_binding: Vec<u8>,

    /// The underlying Verkle traversal proof.
    pub(crate) inner: TraversalProof,
}

impl PQProof {
    /// Verify this proof against a [`PQCommitment`].
    ///
    /// Three checks are performed in order:
    ///
    /// 1. **PQ signature** — the Dilithium3 signature on the commitment must
    ///    be valid for the embedded public key.
    /// 2. **Binding tag** — the stored binding tag must equal the one
    ///    recomputed from `commitment` and `self.keys()`.
    /// 3. **Verkle proof** — the inner KZG traversal proof must verify against
    ///    the raw commitment bytes.
    ///
    /// Returns `Ok(true)` only when all three pass.
    pub fn verify(&self, commitment: &PQCommitment) -> Result<bool, PqVerkleError> {
        // 1. Check the PQ signature on the commitment.
        if !commitment.verify_pq_signature()? {
            return Ok(false);
        }

        // 2. Check the proof binding tag.
        let expected = proof_binding(&commitment.commitment, &self.keys);
        if self.pq_binding != expected {
            return Ok(false);
        }

        // 3. Verify the inner Verkle proof.
        self.inner
            .verify(&commitment.commitment)
            .map_err(|e| PqVerkleError::VerkleError(format!("{e:?}")))
    }

    /// Verify this proof and extract the proven values.
    ///
    /// Performs the same three checks as [`verify()`], then returns the values
    /// associated with each key in `self.keys()` order.
    pub fn verify_and_extract(
        &self,
        commitment: &PQCommitment,
    ) -> Result<Vec<Vec<u8>>, PqVerkleError> {
        // 1. PQ signature.
        if !commitment.verify_pq_signature()? {
            return Err(PqVerkleError::PqVerificationFailed);
        }

        // 2. Binding tag.
        let expected = proof_binding(&commitment.commitment, &self.keys);
        if self.pq_binding != expected {
            return Err(PqVerkleError::BindingMismatch);
        }

        // 3. Extract values from the inner proof.
        self.inner
            .verify_and_extract(&commitment.commitment)
            .map_err(|e| PqVerkleError::VerkleError(format!("{e:?}")))
    }

    /// The key(s) covered by this proof.
    pub fn keys(&self) -> &[Vec<u8>] {
        &self.keys
    }

    /// Serialize the inner `TraversalProof` to bytes for transmission or
    /// storage.  Pair with [`TraversalProof::from_bytes`] to reconstruct.
    pub fn inner_to_bytes(&self) -> Result<Vec<u8>, PqVerkleError> {
        self.inner
            .to_bytes()
            .map_err(|e| PqVerkleError::VerkleError(format!("{e:?}")))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PQVerkleTree
// ─────────────────────────────────────────────────────────────────────────────

/// A quantum-resistant Verkle tree with Dilithium3 authenticated commitments.
///
/// # Security model
///
/// Classical Verkle trees commit data using KZG polynomial commitments on
/// elliptic curves (here BLS48-581).  Shor's algorithm running on a
/// sufficiently large quantum computer could attack the elliptic-curve discrete
/// logarithm and potentially forge commitments.
///
/// `PQVerkleTree` adds two post-quantum layers on top:
///
/// 1. **Signed commitments** – every root commitment returned by [`commit()`]
///    carries a Dilithium3 detached signature.  A verifier who holds the tree
///    owner's public key can reject unsigned or forged commitments even if the
///    elliptic-curve layer is broken.
///
/// 2. **Bound proofs** – every proof returned by [`prove()`] /
///    [`prove_multiple()`] contains a SHAKE-256 tag that binds it to the exact
///    commitment it was produced for.  Replaying a valid proof under a
///    different (attacker-crafted) commitment fails immediately in step 2 of
///    verification.
///
/// # Example
///
/// ```no_run
/// # bls48581::init();
/// use verkle_pq::PQVerkleTree;
///
/// let mut tree = PQVerkleTree::new();
/// tree.insert(b"name".to_vec(), b"alice".to_vec()).unwrap();
///
/// let commitment = tree.commit().unwrap();
/// assert!(commitment.verify_pq_signature().unwrap());
///
/// let proof = tree.prove(b"name").unwrap().expect("key exists");
/// let values = proof.verify_and_extract(&commitment).unwrap();
/// assert_eq!(values[0], b"alice");
/// ```
pub struct PQVerkleTree {
    inner: VectorCommitmentTrie,
    keypair: PQKeypair,
    /// Raw commitment bytes from the most recent successful [`commit()`] call.
    /// Cleared to `None` whenever [`insert()`] is called.
    last_commitment: Option<Vec<u8>>,
}

impl PQVerkleTree {
    /// Create a new, empty tree with a freshly generated Dilithium3 key pair.
    pub fn new() -> Self {
        Self {
            inner: VectorCommitmentTrie::new(),
            keypair: PQKeypair::generate(),
            last_commitment: None,
        }
    }

    /// Create a new, empty tree that uses an *existing* Dilithium3 key pair.
    ///
    /// Use this when you need the tree's root commitments to be verifiable
    /// against a public key that was distributed out-of-band (e.g. recorded
    /// on-chain or in a certificate).
    pub fn with_keypair(keypair: PQKeypair) -> Self {
        Self {
            inner: VectorCommitmentTrie::new(),
            keypair,
            last_commitment: None,
        }
    }

    /// Returns the Dilithium3 public key bytes (1952 bytes).
    ///
    /// Share this with verifiers so they can authenticate commitments and
    /// proofs produced by this tree without holding the secret key.
    pub fn public_key_bytes(&self) -> &[u8] {
        self.keypair.public_key_bytes()
    }

    /// Insert a key-value pair into the trie.
    ///
    /// **Important:** this invalidates the cached commitment.  Call
    /// [`commit()`] again before generating proofs.
    pub fn insert(&mut self, key: Vec<u8>, value: Vec<u8>) -> Result<(), PqVerkleError> {
        self.last_commitment = None;
        self.inner
            .insert(key, value)
            .map_err(|e| PqVerkleError::VerkleError(format!("{e:?}")))
    }

    /// Retrieve a value by key without proving its presence.
    ///
    /// Returns `None` if the key is not in the trie.
    pub fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.inner.get(key)
    }

    /// Compute the root commitment and sign it with the Dilithium3 secret key.
    ///
    /// Returns a [`PQCommitment`] that contains:
    /// - the raw 74-byte KZG commitment,
    /// - the Dilithium3 detached signature,
    /// - the Dilithium3 public key (so verifiers are self-contained).
    ///
    /// Also caches the raw commitment bytes so that subsequent calls to
    /// [`prove()`] / [`prove_multiple()`] can compute the binding tag.
    pub fn commit(&mut self) -> Result<PQCommitment, PqVerkleError> {
        let commitment = self
            .inner
            .commit()
            .ok_or_else(|| PqVerkleError::VerkleError("commit() returned None".to_string()))?;

        let msg = commitment_sign_message(&commitment);
        let pq_signature = self.keypair.sign(&msg)?;
        let pq_pubkey = self.keypair.public_key_bytes().to_vec();

        self.last_commitment = Some(commitment.clone());

        Ok(PQCommitment {
            commitment,
            pq_signature,
            pq_pubkey,
        })
    }

    /// Generate a single-key inclusion proof bound to the current commitment.
    ///
    /// Returns `Ok(None)` when `key` does not exist in the trie (no proof is
    /// possible for absent keys).
    ///
    /// Returns `Err(PqVerkleError::NoCommitment)` if [`commit()`] has not been
    /// called yet, or if a subsequent [`insert()`] has invalidated it.
    pub fn prove(&mut self, key: &[u8]) -> Result<Option<PQProof>, PqVerkleError> {
        let commitment = self
            .last_commitment
            .as_ref()
            .ok_or(PqVerkleError::NoCommitment)?;

        let inner = match self.inner.prove(key) {
            Some(p) => p,
            None => return Ok(None),
        };

        let keys = vec![key.to_vec()];
        let pq_binding = proof_binding(commitment, &keys);

        Ok(Some(PQProof {
            keys,
            pq_binding,
            inner,
        }))
    }

    /// Generate a multi-key inclusion proof bound to the current commitment.
    ///
    /// All keys **must** exist in the trie; keys that are absent cause the
    /// underlying library to return an error.
    ///
    /// This is more efficient than generating one proof per key: the KZG
    /// multiproof combines all openings into a single constant-size artifact.
    pub fn prove_multiple(&mut self, keys: &[Vec<u8>]) -> Result<PQProof, PqVerkleError> {
        let commitment = self
            .last_commitment
            .as_ref()
            .ok_or(PqVerkleError::NoCommitment)?;

        let inner = self.inner.prove_multiple(keys).ok_or_else(|| {
            PqVerkleError::VerkleError("prove_multiple() returned None".to_string())
        })?;

        let pq_binding = proof_binding(commitment, keys);

        Ok(PQProof {
            keys: keys.to_vec(),
            pq_binding,
            inner,
        })
    }
}

impl Default for PQVerkleTree {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Serde support for PQProof
// ─────────────────────────────────────────────────────────────────────────────
//
// `TraversalProof` does not implement serde, so we serialise PQProof via a
// flattened helper struct that converts `TraversalProof` to/from its byte
// representation using `to_bytes()` / `from_bytes()`.

#[cfg(feature = "serde")]
#[derive(serde::Serialize, serde::Deserialize)]
struct PQProofBytes {
    keys: Vec<Vec<u8>>,
    pq_binding: Vec<u8>,
    /// Inner `TraversalProof` serialised with `TraversalProof::to_bytes()`.
    inner_bytes: Vec<u8>,
}

#[cfg(feature = "serde")]
impl serde::Serialize for PQProof {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let inner_bytes = self.inner.to_bytes().map_err(serde::ser::Error::custom)?;
        PQProofBytes {
            keys: self.keys.clone(),
            pq_binding: self.pq_binding.clone(),
            inner_bytes,
        }
        .serialize(serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for PQProof {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let b = PQProofBytes::deserialize(deserializer)?;
        let inner = TraversalProof::from_bytes(&b.inner_bytes).map_err(serde::de::Error::custom)?;
        Ok(PQProof {
            keys: b.keys,
            pq_binding: b.pq_binding,
            inner,
        })
    }
}
