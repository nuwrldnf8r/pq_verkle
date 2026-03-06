use quilibrium_verkle::{TraversalProof, VectorCommitmentTrie};

use crate::{
    error::PqVerkleError,
    pq_hash::{canonical_keys, commitment_sign_message, proof_binding},
    pq_sign::PQKeypair,
};

// ─────────────────────────────────────────────────────────────────────────────
// Newtypes
// ─────────────────────────────────────────────────────────────────────────────

/// The 74-byte KZG Verkle root commitment.
///
/// Using a newtype prevents accidentally passing raw commitment bytes where a
/// signature or public key is expected.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct CommitmentBytes(pub Vec<u8>);

impl AsRef<[u8]> for CommitmentBytes {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// A Dilithium3 (ML-DSA-65) public key (1952 bytes).
///
/// Share this with verifiers so they can call
/// [`PQCommitment::verify_against_pubkey`] to authenticate commitments
/// without holding the secret key.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct DilithiumPubKey(pub Vec<u8>);

impl AsRef<[u8]> for DilithiumPubKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// A Dilithium3 (ML-DSA-65) detached signature (3293 bytes).
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct DilithiumSignature(pub Vec<u8>);

impl AsRef<[u8]> for DilithiumSignature {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PQCommitment
// ─────────────────────────────────────────────────────────────────────────────

/// A Verkle root commitment authenticated by a post-quantum signature.
///
/// The 74-byte KZG commitment produced by the underlying
/// [`quilibrium_verkle`] trie is signed with a Dilithium3 (ML-DSA-65) key.
///
/// ## Public-key trust
///
/// The commitment embeds the signer's public key for convenience, but
/// **embedding alone does not prove authority**.  An attacker can attach
/// their own key and produce a self-consistent commitment.  Always verify
/// against a *trusted* public key obtained out-of-band:
///
/// ```no_run
/// # let commitment: verkle_pq::PQCommitment = unimplemented!();
/// # let trusted_pk: verkle_pq::DilithiumPubKey = unimplemented!();
/// // Correct: checks against the key you already trust.
/// let ok = commitment.verify_against_pubkey(&trusted_pk).unwrap();
///
/// // Self-consistency only: adequate for tamper detection, not authentication.
/// let ok = commitment.verify_embedded_key().unwrap();
/// ```
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PQCommitment {
    /// Raw 74-byte KZG Verkle root commitment.
    pub commitment: Vec<u8>,

    /// Dilithium3 detached signature (3293 bytes) over
    /// `SHAKE-256(DOMAIN_ROOT || commitment)`.
    pub pq_signature: Vec<u8>,

    /// Dilithium3 public key (1952 bytes) used to produce the signature.
    pub pq_pubkey: Vec<u8>,
}

impl PQCommitment {
    /// Check self-consistency: verify the embedded signature against the
    /// embedded public key.
    ///
    /// **This does not prove authority.** Use [`verify_against_pubkey`] with a
    /// key you obtained out-of-band to authenticate the commitment's origin.
    pub fn verify_embedded_key(&self) -> Result<bool, PqVerkleError> {
        let msg = commitment_sign_message(&self.commitment);
        PQKeypair::verify_with_pubkey(&msg, &self.pq_signature, &self.pq_pubkey)
    }

    /// Verify the signature against a *trusted* expected public key.
    ///
    /// Returns `Ok(true)` only when:
    /// 1. The embedded public key matches `expected_pk`, and
    /// 2. The embedded signature is valid for that key.
    ///
    /// This is the correct entrypoint for authentication: use the public key
    /// you obtained from a trusted source (PKI, on-chain record, certificate).
    pub fn verify_against_pubkey(
        &self,
        expected_pk: &DilithiumPubKey,
    ) -> Result<bool, PqVerkleError> {
        if self.pq_pubkey != expected_pk.0 {
            return Err(PqVerkleError::PubkeyMismatch);
        }
        let msg = commitment_sign_message(&self.commitment);
        PQKeypair::verify_with_pubkey(&msg, &self.pq_signature, &self.pq_pubkey)
    }

    /// The SHAKE-256 digest that was signed to produce the Dilithium3
    /// signature.
    ///
    /// Expose this for HSM / external signing flows where you need to sign
    /// the commitment digest with your own hardware key rather than using the
    /// built-in signer.
    pub fn commitment_digest(&self) -> Vec<u8> {
        commitment_sign_message(&self.commitment)
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
    /// Verify this proof against a [`PQCommitment`], checking self-consistency
    /// only (embedded key).
    ///
    /// ⚠️  For authenticated verification, use [`verify_with_pubkey`] and
    /// supply the public key you trust out-of-band.
    ///
    /// Three checks are performed:
    /// 1. **Embedded-key signature** — the commitment's own embedded key.
    /// 2. **Binding tag** — SHAKE-256 tag over `(commitment || sorted keys)`.
    /// 3. **Verkle proof** — inner KZG traversal proof.
    pub fn verify(&self, commitment: &PQCommitment) -> Result<bool, PqVerkleError> {
        if !commitment.verify_embedded_key()? {
            return Ok(false);
        }
        let expected = proof_binding(&commitment.commitment, &self.keys);
        if self.pq_binding != expected {
            return Ok(false);
        }
        self.inner
            .verify(&commitment.commitment)
            .map_err(|e| PqVerkleError::VerkleError(format!("{e:?}")))
    }

    /// Verify this proof against a *trusted* expected public key.
    ///
    /// This is the correct verification entrypoint for production use.
    /// `expected_pk` must be the [`DilithiumPubKey`] you obtained from a
    /// trusted source (PKI, on-chain record, certificate).
    ///
    /// Three checks are performed:
    /// 1. **Trusted-key signature** — commitment's embedded key must equal
    ///    `expected_pk` and the signature must be valid for it.
    /// 2. **Binding tag** — SHAKE-256 tag over `(commitment || sorted keys)`.
    /// 3. **Verkle proof** — inner KZG traversal proof.
    pub fn verify_with_pubkey(
        &self,
        commitment: &PQCommitment,
        expected_pk: &DilithiumPubKey,
    ) -> Result<bool, PqVerkleError> {
        if !commitment.verify_against_pubkey(expected_pk)? {
            return Ok(false);
        }
        let expected = proof_binding(&commitment.commitment, &self.keys);
        if self.pq_binding != expected {
            return Ok(false);
        }
        self.inner
            .verify(&commitment.commitment)
            .map_err(|e| PqVerkleError::VerkleError(format!("{e:?}")))
    }

    /// Verify this proof (embedded-key) and extract the proven values.
    ///
    /// ⚠️  For authenticated verification, use [`verify_and_extract_with_pubkey`].
    pub fn verify_and_extract(
        &self,
        commitment: &PQCommitment,
    ) -> Result<Vec<Vec<u8>>, PqVerkleError> {
        if !commitment.verify_embedded_key()? {
            return Err(PqVerkleError::PqVerificationFailed);
        }
        let expected = proof_binding(&commitment.commitment, &self.keys);
        if self.pq_binding != expected {
            return Err(PqVerkleError::BindingMismatch);
        }
        self.inner
            .verify_and_extract(&commitment.commitment)
            .map_err(|e| PqVerkleError::VerkleError(format!("{e:?}")))
    }

    /// Verify this proof against a trusted pubkey and extract the proven values.
    pub fn verify_and_extract_with_pubkey(
        &self,
        commitment: &PQCommitment,
        expected_pk: &DilithiumPubKey,
    ) -> Result<Vec<Vec<u8>>, PqVerkleError> {
        commitment.verify_against_pubkey(expected_pk)?;
        let expected = proof_binding(&commitment.commitment, &self.keys);
        if self.pq_binding != expected {
            return Err(PqVerkleError::BindingMismatch);
        }
        self.inner
            .verify_and_extract(&commitment.commitment)
            .map_err(|e| PqVerkleError::VerkleError(format!("{e:?}")))
    }

    /// The key(s) covered by this proof, in canonical (sorted) order.
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
/// use verkle_pq::{DilithiumPubKey, PQVerkleTree};
///
/// let mut tree = PQVerkleTree::new();
/// tree.insert(b"name".to_vec(), b"alice".to_vec()).unwrap();
///
/// let commitment = tree.commit().unwrap();
/// let trusted_pk: DilithiumPubKey = tree.dilithium_pubkey();
///
/// // Authenticated verification against the trusted key.
/// assert!(commitment.verify_against_pubkey(&trusted_pk).unwrap());
///
/// let proof = tree.prove(b"name").unwrap().expect("key exists");
/// let values = proof.verify_and_extract_with_pubkey(&commitment, &trusted_pk).unwrap();
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

    /// Returns the Dilithium3 public key as a [`DilithiumPubKey`] newtype.
    ///
    /// Pass this to [`PQCommitment::verify_against_pubkey`] and
    /// [`PQProof::verify_with_pubkey`] for authenticated verification.
    pub fn dilithium_pubkey(&self) -> DilithiumPubKey {
        DilithiumPubKey(self.keypair.public_key_bytes().to_vec())
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
    /// Keys are sorted into canonical lexicographic order before the proof
    /// is generated.  The caller does **not** need to pre-sort; the sorted
    /// order is recorded inside the [`PQProof`] and must be used when
    /// verifying.  Use [`canonical_keys`] on the verifier side if you need
    /// to reconstruct the same ordering.
    ///
    /// All keys **must** exist in the trie; absent keys cause the underlying
    /// library to return an error.
    pub fn prove_multiple(&mut self, keys: &[Vec<u8>]) -> Result<PQProof, PqVerkleError> {
        let commitment = self
            .last_commitment
            .as_ref()
            .ok_or(PqVerkleError::NoCommitment)?;

        // Canonical sort: ensures binding tag is order-independent.
        let mut sorted_keys = keys.to_vec();
        canonical_keys(&mut sorted_keys);

        let inner = self.inner.prove_multiple(&sorted_keys).ok_or_else(|| {
            PqVerkleError::VerkleError("prove_multiple() returned None".to_string())
        })?;

        let pq_binding = proof_binding(commitment, &sorted_keys);

        Ok(PQProof {
            keys: sorted_keys,
            pq_binding,
            inner,
        })
    }

    /// Prove a batch of independent single-key proofs.
    ///
    /// Without the `rayon` feature this is equivalent to calling [`prove`]
    /// for each key in sequence.  With `--features rayon`, proofs are
    /// generated concurrently (one clone of the inner tree per rayon worker
    /// thread).  Requires [`commit`] to have been called first.
    ///
    /// Returns one [`PQProof`] per input key in the same order as `keys`.
    /// Returns `Err` if any key is absent from the trie.
    pub fn prove_batch(&mut self, keys: &[Vec<u8>]) -> Result<Vec<PQProof>, PqVerkleError> {
        let commitment = self
            .last_commitment
            .as_ref()
            .ok_or(PqVerkleError::NoCommitment)?
            .clone();

        // Inner sequential helper — used directly without rayon, and as the
        // per-chunk body with rayon.
        fn prove_sequential(
            inner: &mut VectorCommitmentTrie,
            commitment: &[u8],
            keys: &[Vec<u8>],
        ) -> Result<Vec<PQProof>, PqVerkleError> {
            keys.iter()
                .map(|key| {
                    let inner_proof = inner.prove(key).ok_or_else(|| {
                        PqVerkleError::VerkleError(format!(
                            "key not found in prove_batch: {}",
                            hex::encode(key)
                        ))
                    })?;
                    let ks = vec![key.clone()];
                    let pb = proof_binding(commitment, &ks);
                    Ok(PQProof {
                        keys: ks,
                        pq_binding: pb,
                        inner: inner_proof,
                    })
                })
                .collect()
        }

        #[cfg(feature = "rayon")]
        {
            use rayon::prelude::*;

            // Divide keys into one chunk per rayon thread.  Each chunk gets
            // its own clone of the inner tree so threads never share state.
            let num_threads = rayon::current_num_threads().max(1);
            let chunk_size = keys.len().div_ceil(num_threads).max(1);

            // Pre-clone on the main thread (sequential) then ship to rayon.
            let chunks: Vec<(Vec<Vec<u8>>, VectorCommitmentTrie)> = keys
                .chunks(chunk_size)
                .map(|c| (c.to_vec(), self.inner.clone()))
                .collect();

            chunks
                .into_par_iter()
                .map(|(chunk_keys, mut local_inner)| {
                    prove_sequential(&mut local_inner, &commitment, &chunk_keys)
                })
                .collect::<Result<Vec<Vec<PQProof>>, _>>()
                .map(|nested| nested.into_iter().flatten().collect())
        }

        #[cfg(not(feature = "rayon"))]
        prove_sequential(&mut self.inner, &commitment, keys)
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
