use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};

// Domain-separation prefixes prevent hash outputs in one context from being
// reused in another, even if the raw input bytes happen to be identical.
const DOMAIN_ROOT: &[u8] = b"QUILIBRIUM_PQ_VERKLE_ROOT_V1\x00";
const DOMAIN_PROOF: &[u8] = b"QUILIBRIUM_PQ_VERKLE_PROOF_V1\x00";

/// Produce `output_len` bytes of SHAKE-256 output from `input`.
pub fn shake256(input: &[u8], output_len: usize) -> Vec<u8> {
    let mut hasher = Shake256::default();
    hasher.update(input);
    let mut reader = hasher.finalize_xof();
    let mut output = vec![0u8; output_len];
    reader.read(&mut output);
    output
}

/// Build the message that is signed to authenticate a root commitment.
///
/// Layout: `DOMAIN_ROOT || len(commitment):u64le || commitment`
///
/// The result is a 64-byte SHAKE-256 digest that is passed to Dilithium3.
pub fn commitment_sign_message(commitment: &[u8]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(DOMAIN_ROOT.len() + 8 + commitment.len());
    msg.extend_from_slice(DOMAIN_ROOT);
    msg.extend_from_slice(&(commitment.len() as u64).to_le_bytes());
    msg.extend_from_slice(commitment);
    shake256(&msg, 64)
}

/// Compute a proof-binding tag that ties a proof to a specific commitment and
/// set of keys.
///
/// Layout: `DOMAIN_PROOF || len(commitment):u64le || commitment
///          || num_keys:u64le || (len(key):u64le || key)*`
///
/// The result is a 64-byte SHAKE-256 digest stored inside every `PQProof`.
/// Verification recomputes this tag and compares it; a mismatch means the
/// proof was produced for a different commitment or different key set.
pub fn proof_binding(commitment: &[u8], keys: &[Vec<u8>]) -> Vec<u8> {
    let mut msg = Vec::new();
    msg.extend_from_slice(DOMAIN_PROOF);
    msg.extend_from_slice(&(commitment.len() as u64).to_le_bytes());
    msg.extend_from_slice(commitment);
    msg.extend_from_slice(&(keys.len() as u64).to_le_bytes());
    for key in keys {
        msg.extend_from_slice(&(key.len() as u64).to_le_bytes());
        msg.extend_from_slice(key);
    }
    shake256(&msg, 64)
}
