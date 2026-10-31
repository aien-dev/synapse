//! Keyed seal over revision records (issue #101).
//!
//! The WAL frame chain (CRC32C plus an unkeyed SHA-256 chain) and the checkpoint state root
//! detect corruption, not forgery: anyone who can rewrite the whole log can recompute both.
//! Kinds 7 and 8 carry a `chain` field that no signature in the record covers, so such a
//! rewrite could swap an admission's chain for links the forger minted and then sign kind 9
//! moves under them. A store opened with a [`RevisionSealKey`] (the server's machine key)
//! closes that: every revision record it writes (kinds 7, 8, 9, and 11) carries a
//! [`RevisionSeal`], an Ed25519 signature by that key over a running head that chains the
//! record's `WalSeq`, its full record digest (every field, chain included), and the head of
//! the previous sealed record. Replay applies a revision record only when its seal verifies
//! against the head so far, so a changed, inserted, reordered, or removed revision record
//! breaks the chain from that point on. Strict recovery refuses such a store
//! (`RevisionRecordUnsealed`).
//!
//! Layout (ADR 0003 principle P5): the seal is an optional trailer after the record body,
//! `1 u8 | server_key [32] | signature [64]`; a record without it ends at its body.
//!
//! * head 0 = 32 zero bytes;
//! * head n = `SHA-256(DOMAIN_REVISION_SEAL_HEAD_V1 || head n-1 || seq u64le || record digest)`;
//! * signature n = Ed25519 over `DOMAIN_REVISION_SEAL_SIGN_V1 || head n`, checked with
//!   `verify_strict` under the configured key, which must not be a small-order key.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
use synapse_core::WalSeq;

/// Domain tag of the running seal head.
pub const DOMAIN_REVISION_SEAL_HEAD_V1: &[u8] = b"SYNAPSE_REVISION_SEAL_HEAD_V1\0";
/// Domain tag of the server's signature over one seal head.
pub const DOMAIN_REVISION_SEAL_SIGN_V1: &[u8] = b"SYNAPSE_REVISION_SEAL_SIGN_V1\0";
/// Tag byte that opens the seal trailer of a revision record.
pub const REVISION_SEAL_TAG: u8 = 1;

/// The server's seal on one revision record: the key that signed and its signature over the
/// running head at that record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RevisionSeal {
    pub server_key: [u8; 32],
    pub signature: [u8; 64],
}

/// The server machine key a store seals revision records with (and verifies them against on
/// replay). The key never comes from the log: the operator hands it to
/// [`crate::SynapseStore::open_sealed`].
#[derive(Clone)]
pub struct RevisionSealKey(SigningKey);

impl RevisionSealKey {
    pub fn new(key: SigningKey) -> Self {
        Self(key)
    }

    /// The public half: what a seal must name and verify under.
    pub fn public_key(&self) -> [u8; 32] {
        self.0.verifying_key().to_bytes()
    }

    pub(crate) fn seal(&self, head: &[u8; 32]) -> RevisionSeal {
        RevisionSeal {
            server_key: self.public_key(),
            signature: self.0.sign(&signable(head)).to_bytes(),
        }
    }
}

impl std::fmt::Debug for RevisionSealKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("RevisionSealKey")
            .field(&hex::encode(self.public_key()))
            .finish()
    }
}

fn signable(head: &[u8; 32]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(DOMAIN_REVISION_SEAL_SIGN_V1.len() + 32);
    buf.extend_from_slice(DOMAIN_REVISION_SEAL_SIGN_V1);
    buf.extend_from_slice(head);
    buf
}

/// The head after the record at `seq` with digest `record_digest`, following `prev`.
pub(crate) fn next_head(prev: &[u8; 32], seq: WalSeq, record_digest: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(DOMAIN_REVISION_SEAL_HEAD_V1);
    h.update(prev);
    h.update(seq.0.to_le_bytes());
    h.update(record_digest);
    h.finalize().into()
}

impl RevisionSeal {
    /// True when the seal names `expected_key` (not a small-order key) and its signature over
    /// `head` verifies strictly.
    pub(crate) fn verifies(&self, expected_key: &[u8; 32], head: &[u8; 32]) -> bool {
        if &self.server_key != expected_key {
            return false;
        }
        let Ok(key) = VerifyingKey::from_bytes(expected_key) else {
            return false;
        };
        !key.is_weak()
            && key
                .verify_strict(&signable(head), &Signature::from_bytes(&self.signature))
                .is_ok()
    }
}
