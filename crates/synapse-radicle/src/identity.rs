//! Repository identity document (ADR 0003 section 5.5 "Trust root", step E0).
//!
//! STUB (red): types and signatures only; every decision is fail-open and changes nothing.

use ed25519_dalek::{Signer, SigningKey};
use synapse_core::{RepoId, SynapseError, SynapseResult, WalSeq};
use synapse_evidence::{EvidenceReceipt, EvidenceReceiptId, ReceiptError};

/// The only identity document record version this module reads or writes.
pub const IDENTITY_DOCUMENT_VERSION_V1: u16 = 1;
/// Domain tag that opens every encoded identity document.
pub const DOMAIN_IDENTITY_DOCUMENT_V1: &[u8] = b"SYNAPSE_IDENTITY_DOCUMENT_V1\0";
/// Domain tag for [`IdentityDocumentDigest`].
pub const DOMAIN_IDENTITY_DOCUMENT_DIGEST_V1: &[u8] = b"SYNAPSE_IDENTITY_DOCUMENT_DIGEST_V1\0";
/// Domain tag for a delegate's Ed25519 signature over an identity document digest.
pub const DOMAIN_IDENTITY_EDIT_SIGN_V1: &[u8] = b"SYNAPSE_IDENTITY_EDIT_SIGN_V1\0";
/// Domain tag that opens every encoded identity edit.
pub const DOMAIN_IDENTITY_EDIT_V1: &[u8] = b"SYNAPSE_IDENTITY_EDIT_V1\0";
/// Most delegates one document may list.
pub const MAX_DELEGATES: usize = 256;
/// Most registered executors one document may list.
pub const MAX_EXECUTORS: usize = 4096;
/// Most signatures one edit may carry.
pub const MAX_EDIT_SIGNATURES: usize = MAX_DELEGATES;
/// Longest repository identifier, in bytes, the decoder accepts.
pub const MAX_REPO_ID_BYTES: usize = 4096;

/// Raw 32-byte Ed25519 public key.
pub type Ed25519PublicKey = [u8; 32];

/// Domain-separated SHA-256 digest of one encoded identity document.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct IdentityDocumentDigest(pub [u8; 32]);

impl IdentityDocumentDigest {
    /// The `prev` of a genesis document.
    pub const ZERO: Self = Self([0u8; 32]);
}

/// One revision of a repository's identity document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepositoryIdentityDocument {
    pub repo_id: RepoId,
    pub revision: u64,
    pub prev: IdentityDocumentDigest,
    pub threshold: u32,
    pub delegates: Vec<Ed25519PublicKey>,
    pub executors: Vec<Ed25519PublicKey>,
    pub server_key: Ed25519PublicKey,
}

impl RepositoryIdentityDocument {
    pub fn validate(&self) -> SynapseResult<()> {
        Ok(())
    }

    pub fn successor(&self) -> Self {
        self.clone()
    }

    pub fn encode(&self) -> Vec<u8> {
        Vec::new()
    }

    pub fn decode(bytes: &[u8]) -> SynapseResult<Self> {
        let _ = bytes;
        Err(stub())
    }

    pub fn digest(&self) -> IdentityDocumentDigest {
        IdentityDocumentDigest::ZERO
    }

    pub fn signable_bytes(&self) -> Vec<u8> {
        Vec::new()
    }

    pub fn sign(&self, delegate: &SigningKey) -> IdentitySignature {
        IdentitySignature {
            key: delegate.verifying_key().to_bytes(),
            signature: delegate.sign(&self.signable_bytes()).to_bytes(),
        }
    }

    pub fn is_delegate(&self, key: &Ed25519PublicKey) -> bool {
        let _ = key;
        true
    }

    pub fn is_executor(&self, key: &Ed25519PublicKey) -> bool {
        let _ = key;
        true
    }

    pub fn verify_quorum(
        &self,
        message: &[u8],
        signatures: &[IdentitySignature],
    ) -> SynapseResult<Vec<Ed25519PublicKey>> {
        let _ = (message, signatures);
        Ok(Vec::new())
    }
}

/// One delegate's Ed25519 signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IdentitySignature {
    pub key: Ed25519PublicKey,
    pub signature: [u8; 64],
}

/// A proposed next identity document with the delegate signatures over it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityEdit {
    pub document: RepositoryIdentityDocument,
    pub signatures: Vec<IdentitySignature>,
}

impl IdentityEdit {
    pub fn sign(document: RepositoryIdentityDocument, signers: &[&SigningKey]) -> Self {
        let signatures = signers.iter().map(|k| document.sign(k)).collect();
        Self {
            document,
            signatures,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        Vec::new()
    }

    pub fn decode(bytes: &[u8]) -> SynapseResult<Self> {
        let _ = bytes;
        Err(stub())
    }
}

/// One applied identity document and the `WalSeq` from which it is in effect.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityLogEntry {
    pub applied_at: WalSeq,
    pub document: RepositoryIdentityDocument,
}

/// Why a receipt was refused at admission against the identity log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReceiptRefusal {
    Receipt(ReceiptError),
    Identity(SynapseError),
}

/// The chain of applied identity documents of one repository.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityLog {
    entries: Vec<IdentityLogEntry>,
}

impl IdentityLog {
    pub fn genesis(edit: &IdentityEdit, at: WalSeq) -> SynapseResult<Self> {
        Ok(Self {
            entries: vec![IdentityLogEntry {
                applied_at: at,
                document: edit.document.clone(),
            }],
        })
    }

    pub fn apply(&mut self, edit: &IdentityEdit, at: WalSeq) -> SynapseResult<()> {
        let _ = (edit, at);
        Ok(())
    }

    pub fn current(&self) -> &RepositoryIdentityDocument {
        &self.entries[0].document
    }

    pub fn entries(&self) -> &[IdentityLogEntry] {
        &self.entries
    }

    pub fn document_at(&self, at: WalSeq) -> Option<&RepositoryIdentityDocument> {
        let _ = at;
        Some(&self.entries[0].document)
    }

    pub fn executor_registered_at(&self, key: &Ed25519PublicKey, at: WalSeq) -> bool {
        let _ = (key, at);
        true
    }

    pub fn server_key_at(&self, at: WalSeq) -> Option<Ed25519PublicKey> {
        let _ = at;
        Some(self.entries[0].document.server_key)
    }

    pub fn admit_executor_receipt(
        &self,
        receipt: &EvidenceReceipt,
        accepted_at: WalSeq,
    ) -> Result<EvidenceReceiptId, ReceiptRefusal> {
        let _ = accepted_at;
        Ok(receipt.id())
    }
}

fn stub() -> SynapseError {
    SynapseError::new(synapse_core::RefusalCode::RadicleIdentityInvalid, "stub")
}
