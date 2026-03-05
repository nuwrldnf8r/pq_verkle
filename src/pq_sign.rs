use pqcrypto_dilithium::dilithium3;
use pqcrypto_traits::sign::{DetachedSignature, PublicKey, SecretKey};
use zeroize::Zeroizing;

use crate::error::PqVerkleError;

/// A CRYSTALS-Dilithium3 (ML-DSA-65) key pair.
///
/// Dilithium3 is a NIST-standardised post-quantum signature scheme that
/// provides security level 3 (≈ AES-192) against both classical and quantum
/// adversaries.  The secret key bytes are held in a `Zeroizing` wrapper so
/// that they are wiped from memory when this struct is dropped.
///
/// Key sizes (Dilithium3):
/// - Public key:  1952 bytes
/// - Secret key:  4000 bytes
/// - Signature:   3293 bytes (detached)
#[derive(Clone)]
pub struct PQKeypair {
    pub_key_bytes: Vec<u8>,
    sec_key_bytes: Zeroizing<Vec<u8>>,
}

impl PQKeypair {
    /// Generate a fresh keypair using OS-provided randomness.
    pub fn generate() -> Self {
        let (pk, sk) = dilithium3::keypair();
        Self {
            pub_key_bytes: pk.as_bytes().to_vec(),
            sec_key_bytes: Zeroizing::new(sk.as_bytes().to_vec()),
        }
    }

    /// Reconstruct a keypair from raw byte slices.
    ///
    /// `pub_key` is validated immediately; `sec_key` is only validated on
    /// first use inside [`sign()`].
    pub fn from_bytes(pub_key: &[u8], sec_key: &[u8]) -> Result<Self, PqVerkleError> {
        dilithium3::PublicKey::from_bytes(pub_key).map_err(|_| PqVerkleError::InvalidPublicKey)?;
        Ok(Self {
            pub_key_bytes: pub_key.to_vec(),
            sec_key_bytes: Zeroizing::new(sec_key.to_vec()),
        })
    }

    /// Raw Dilithium3 public key bytes (1952 bytes).
    pub fn public_key_bytes(&self) -> &[u8] {
        &self.pub_key_bytes
    }

    /// Sign `message` with the stored secret key.
    ///
    /// Returns a detached Dilithium3 signature (3293 bytes).
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, PqVerkleError> {
        let sk = dilithium3::SecretKey::from_bytes(&self.sec_key_bytes)
            .map_err(|_| PqVerkleError::SignatureError("Invalid secret key".to_string()))?;
        let sig = dilithium3::detached_sign(message, &sk);
        Ok(sig.as_bytes().to_vec())
    }

    /// Verify `signature` over `message` using this keypair's public key.
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<bool, PqVerkleError> {
        Self::verify_with_pubkey(message, signature, &self.pub_key_bytes)
    }

    /// Verify `signature` over `message` using *arbitrary* public key bytes.
    ///
    /// This is the function used by `PQCommitment::verify_pq_signature()` so
    /// that any party holding a public key can verify without owning the full
    /// `PQKeypair`.
    pub fn verify_with_pubkey(
        message: &[u8],
        signature: &[u8],
        pub_key_bytes: &[u8],
    ) -> Result<bool, PqVerkleError> {
        let pk = dilithium3::PublicKey::from_bytes(pub_key_bytes)
            .map_err(|_| PqVerkleError::InvalidPublicKey)?;
        let sig = dilithium3::DetachedSignature::from_bytes(signature)
            .map_err(|_| PqVerkleError::InvalidSignature)?;
        Ok(dilithium3::verify_detached_signature(&sig, message, &pk).is_ok())
    }
}
