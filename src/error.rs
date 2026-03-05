use thiserror::Error;

/// Errors returned by the `verkle_pq` library.
#[derive(Error, Debug)]
pub enum PqVerkleError {
    /// An error propagated from the underlying `quilibrium_verkle` trie.
    #[error("Verkle trie error: {0}")]
    VerkleError(String),

    /// An error during post-quantum signing or key handling.
    #[error("Post-quantum signature error: {0}")]
    SignatureError(String),

    /// The post-quantum signature on a commitment did not verify.
    #[error("Post-quantum signature verification failed")]
    PqVerificationFailed,

    /// The proof's SHAKE-256 binding tag did not match the supplied commitment.
    /// This means the proof was generated for a different commitment.
    #[error("Proof binding mismatch: proof was not generated for this commitment")]
    BindingMismatch,

    /// `prove()` or `prove_multiple()` was called before `commit()`, or a
    /// subsequent `insert()` has invalidated the cached commitment.
    #[error("No commitment available: call commit() before prove()")]
    NoCommitment,

    /// Supplied public key bytes are the wrong length or otherwise invalid.
    #[error("Invalid Dilithium3 public key bytes")]
    InvalidPublicKey,

    /// Supplied signature bytes are the wrong length or otherwise invalid.
    #[error("Invalid Dilithium3 signature bytes")]
    InvalidSignature,

    /// The commitment's embedded public key does not match the expected key.
    /// This means the commitment was not produced by the trusted key holder.
    #[error("Public key mismatch: commitment was not signed by the expected key")]
    PubkeyMismatch,
}
