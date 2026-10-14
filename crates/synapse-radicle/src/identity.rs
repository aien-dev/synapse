//! Repository identity document (ADR 0003 section 5.5 "Trust root", step E0).
//!
//! The document names who may change a repository's trust settings and which machines it
//! trusts:
//!
//! * `delegates` and `threshold`: the keys whose signatures change the document, and how many
//!   distinct delegates must sign. This mirrors Radicle `refs/rad/id` delegates and threshold
//!   (ADR 0001 section 2.2 item 3 is unchanged; delegates can be machines);
//! * `executors`: the registered executor machine keys whose evidence receipts may count
//!   (section 5.5 "Who may execute"; consumed by E1);
//! * `server_key`: the server's own machine key, which signs derivation attestations
//!   (section 5.1 `DerivationAttestation`; consumed by B5).
//!
//! Every revision after genesis is an [`IdentityEdit`]: the full next document plus delegate
//! signatures. An edit applies only if at least the *current* document's threshold of its
//! *current* delegates signed it, as in Radicle. The next document carries the revision
//! number and the digest of the document it replaces, so a signed edit cannot be replayed
//! onto a later revision, applied out of order, or moved to another repository.
//!
//! [`IdentityLog`] records the `WalSeq` from which each revision is in effect, so a question
//! such as "was this executor registered when that receipt was accepted" is answered from the
//! document in effect at that `WalSeq`. A later edit never revokes a receipt already
//! accepted; it refuses only receipts accepted from its own `WalSeq` on.
//!
//! Format (ADR 0003 principle P5): fixed-width, little-endian, length-prefixed binary, no
//! Rust-specific serialization. See `docs/E0_IDENTITY_DOCUMENT.md` for the byte layout.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use synapse_core::{
    decode_did_key_ed25519, RefusalCode, RepoId, SynapseError, SynapseResult, WalSeq,
};
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
/// Largest encoded document the edit decoder accepts (every list and string at its cap).
pub const MAX_DOCUMENT_BYTES: usize = DOMAIN_IDENTITY_DOCUMENT_V1.len()
    + 2
    + 4
    + MAX_REPO_ID_BYTES
    + 8
    + 32
    + 4
    + 4
    + MAX_DELEGATES * 32
    + 4
    + MAX_EXECUTORS * 32
    + 32;

/// Raw 32-byte Ed25519 public key.
pub type Ed25519PublicKey = [u8; 32];

/// Domain-separated SHA-256 digest of one encoded identity document. Never a `BlobDigest`,
/// `ChangesetId`, or receipt identity.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct IdentityDocumentDigest(pub [u8; 32]);

impl IdentityDocumentDigest {
    /// The `prev` of a genesis document.
    pub const ZERO: Self = Self([0u8; 32]);

    pub fn to_hex(self) -> String {
        hex::encode(self.0)
    }
}

/// One revision of a repository's identity document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepositoryIdentityDocument {
    pub repo_id: RepoId,
    /// 0 for genesis; each edit adds exactly 1.
    pub revision: u64,
    /// Digest of the document this one replaces; [`IdentityDocumentDigest::ZERO`] for genesis.
    pub prev: IdentityDocumentDigest,
    /// Distinct delegate signatures an edit of this document needs (1 to delegate count).
    pub threshold: u32,
    /// Strictly ascending, unique, at most [`MAX_DELEGATES`], at least one.
    pub delegates: Vec<Ed25519PublicKey>,
    /// Registered executor machine keys. Strictly ascending, unique, at most [`MAX_EXECUTORS`].
    pub executors: Vec<Ed25519PublicKey>,
    /// The server's machine key (signs derivation attestations).
    pub server_key: Ed25519PublicKey,
}

fn invalid(message: impl Into<String>) -> SynapseError {
    SynapseError::new(RefusalCode::RadicleIdentityInvalid, message)
}

/// A key is usable only if it decodes to a curve point that is not of small order.
fn check_key(key: &Ed25519PublicKey, what: &str) -> SynapseResult<VerifyingKey> {
    let vk = VerifyingKey::from_bytes(key)
        .map_err(|_| invalid(format!("{what} is not an Ed25519 public key")))?;
    if vk.is_weak() {
        return Err(invalid(format!("{what} is a small-order Ed25519 key")));
    }
    Ok(vk)
}

fn check_key_list(keys: &[Ed25519PublicKey], cap: usize, what: &str) -> SynapseResult<()> {
    if keys.len() > cap {
        return Err(invalid(format!(
            "{} {what} keys exceed the cap of {cap}",
            keys.len()
        )));
    }
    if keys.windows(2).any(|w| w[0] >= w[1]) {
        return Err(invalid(format!(
            "{what} keys must be strictly ascending and unique"
        )));
    }
    for k in keys {
        check_key(k, what)?;
    }
    Ok(())
}

impl RepositoryIdentityDocument {
    /// Check every structural rule of record version 1.
    pub fn validate(&self) -> SynapseResult<()> {
        if self.repo_id.as_str().len() > MAX_REPO_ID_BYTES {
            return Err(invalid("repository identifier exceeds its cap"));
        }
        if (self.revision == 0) != (self.prev == IdentityDocumentDigest::ZERO) {
            return Err(invalid(
                "revision 0, and only revision 0, has the zero prev digest",
            ));
        }
        if self.delegates.is_empty() {
            return Err(invalid("identity document must have at least one delegate"));
        }
        check_key_list(&self.delegates, MAX_DELEGATES, "delegate")?;
        if self.threshold == 0 || self.threshold as usize > self.delegates.len() {
            return Err(invalid(format!(
                "invalid threshold {} for {} delegates",
                self.threshold,
                self.delegates.len()
            )));
        }
        check_key_list(&self.executors, MAX_EXECUTORS, "executor")?;
        check_key(&self.server_key, "server key")?;
        Ok(())
    }

    /// The next revision's starting point: this document with `revision + 1` and `prev` set to
    /// this document's digest. The caller then changes what the edit changes.
    pub fn successor(&self) -> Self {
        let mut next = self.clone();
        next.revision = self.revision.saturating_add(1);
        next.prev = self.digest();
        next
    }

    /// Canonical record bytes (see `docs/E0_IDENTITY_DOCUMENT.md`).
    pub fn encode(&self) -> Vec<u8> {
        let repo = self.repo_id.as_str().as_bytes();
        let mut buf = Vec::with_capacity(
            DOMAIN_IDENTITY_DOCUMENT_V1.len()
                + 90
                + repo.len()
                + 32 * (self.delegates.len() + self.executors.len()),
        );
        buf.extend_from_slice(DOMAIN_IDENTITY_DOCUMENT_V1);
        buf.extend_from_slice(&IDENTITY_DOCUMENT_VERSION_V1.to_le_bytes());
        buf.extend_from_slice(&(repo.len() as u32).to_le_bytes());
        buf.extend_from_slice(repo);
        buf.extend_from_slice(&self.revision.to_le_bytes());
        buf.extend_from_slice(&self.prev.0);
        buf.extend_from_slice(&self.threshold.to_le_bytes());
        for list in [&self.delegates, &self.executors] {
            buf.extend_from_slice(&(list.len() as u32).to_le_bytes());
            for k in list {
                buf.extend_from_slice(k);
            }
        }
        buf.extend_from_slice(&self.server_key);
        buf
    }

    /// Decode and validate one record. Refuses a wrong tag or version, a truncated record,
    /// trailing bytes, a count above its cap (before allocating for it), and any document
    /// [`validate`](Self::validate) refuses. Every refusal is `RadicleIdentityInvalid`.
    pub fn decode(bytes: &[u8]) -> SynapseResult<Self> {
        let mut r = Reader::new(bytes);
        let doc = Self::read(&mut r)?;
        r.finish()?;
        Ok(doc)
    }

    fn read(r: &mut Reader<'_>) -> SynapseResult<Self> {
        r.tag(DOMAIN_IDENTITY_DOCUMENT_V1, "identity document")?;
        let version = r.u16()?;
        if version != IDENTITY_DOCUMENT_VERSION_V1 {
            return Err(invalid(format!(
                "identity document version {version} is not supported"
            )));
        }
        let repo_len = r.count(MAX_REPO_ID_BYTES, 1, "repo_id")?;
        let repo =
            std::str::from_utf8(r.take(repo_len)?).map_err(|_| invalid("repo_id is not UTF-8"))?;
        let repo_id = RepoId::new(repo).map_err(|e| invalid(e.message))?;
        let revision = r.u64()?;
        let prev = IdentityDocumentDigest(r.array()?);
        let threshold = r.u32()?;
        let delegates = r.keys(MAX_DELEGATES, "delegates")?;
        let executors = r.keys(MAX_EXECUTORS, "executors")?;
        let server_key = r.array()?;
        let doc = Self {
            repo_id,
            revision,
            prev,
            threshold,
            delegates,
            executors,
            server_key,
        };
        doc.validate()?;
        Ok(doc)
    }

    /// SHA-256 over the digest tag, the record length (u64 LE), and the record.
    pub fn digest(&self) -> IdentityDocumentDigest {
        let bytes = self.encode();
        let mut h = Sha256::new();
        h.update(DOMAIN_IDENTITY_DOCUMENT_DIGEST_V1);
        h.update((bytes.len() as u64).to_le_bytes());
        h.update(&bytes);
        IdentityDocumentDigest(h.finalize().into())
    }

    /// Bytes a delegate signs to approve this document: the sign tag, then the digest.
    pub fn signable_bytes(&self) -> Vec<u8> {
        let mut buf = DOMAIN_IDENTITY_EDIT_SIGN_V1.to_vec();
        buf.extend_from_slice(&self.digest().0);
        buf
    }

    /// One delegate's signature approving this document.
    pub fn sign(&self, delegate: &SigningKey) -> IdentitySignature {
        IdentitySignature {
            key: delegate.verifying_key().to_bytes(),
            signature: delegate.sign(&self.signable_bytes()).to_bytes(),
        }
    }

    pub fn is_delegate(&self, key: &Ed25519PublicKey) -> bool {
        self.delegates.contains(key)
    }

    pub fn is_executor(&self, key: &Ed25519PublicKey) -> bool {
        self.executors.contains(key)
    }

    /// Check that at least `threshold` distinct delegates of *this* document signed `message`
    /// (strict Ed25519). Fails closed: a signer that is not a delegate is refused with
    /// `RadicleIdentityInvalid`, a signature that does not verify with
    /// `RadicleSignatureInvalid`, and too few distinct delegates with
    /// `RadicleQuorumInsufficient`. A delegate signing twice counts once. Returns the distinct
    /// signing delegates, ascending. `message` must carry its own domain tag.
    pub fn verify_quorum(
        &self,
        message: &[u8],
        signatures: &[IdentitySignature],
    ) -> SynapseResult<Vec<Ed25519PublicKey>> {
        if signatures.len() > MAX_EDIT_SIGNATURES {
            return Err(invalid(format!(
                "{} signatures exceed the cap of {MAX_EDIT_SIGNATURES}",
                signatures.len()
            )));
        }
        let mut signed = BTreeSet::new();
        for s in signatures {
            if !self.is_delegate(&s.key) {
                return Err(invalid(format!(
                    "signer {} is not a delegate of identity revision {}",
                    hex::encode(s.key),
                    self.revision
                )));
            }
            let vk = check_key(&s.key, "delegate")?;
            vk.verify_strict(message, &Signature::from_bytes(&s.signature))
                .map_err(|_| {
                    SynapseError::new(
                        RefusalCode::RadicleSignatureInvalid,
                        format!(
                            "Ed25519 signature of delegate {} does not verify",
                            hex::encode(s.key)
                        ),
                    )
                })?;
            signed.insert(s.key);
        }
        if signed.len() < self.threshold as usize {
            return Err(SynapseError::new(
                RefusalCode::RadicleQuorumInsufficient,
                format!(
                    "{} of {} required distinct delegate signatures for identity revision {}",
                    signed.len(),
                    self.threshold,
                    self.revision
                ),
            ));
        }
        Ok(signed.into_iter().collect())
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
    /// Sign `document` with each of `signers` (in the given order).
    pub fn sign(document: RepositoryIdentityDocument, signers: &[&SigningKey]) -> Self {
        let signatures = signers.iter().map(|k| document.sign(k)).collect();
        Self {
            document,
            signatures,
        }
    }

    /// Canonical record bytes: tag, version, length-prefixed document, signature count, then
    /// each 32-byte key and 64-byte signature.
    pub fn encode(&self) -> Vec<u8> {
        let doc = self.document.encode();
        let mut buf = Vec::with_capacity(
            DOMAIN_IDENTITY_EDIT_V1.len() + 10 + doc.len() + 96 * self.signatures.len(),
        );
        buf.extend_from_slice(DOMAIN_IDENTITY_EDIT_V1);
        buf.extend_from_slice(&IDENTITY_DOCUMENT_VERSION_V1.to_le_bytes());
        buf.extend_from_slice(&(doc.len() as u32).to_le_bytes());
        buf.extend_from_slice(&doc);
        buf.extend_from_slice(&(self.signatures.len() as u32).to_le_bytes());
        for s in &self.signatures {
            buf.extend_from_slice(&s.key);
            buf.extend_from_slice(&s.signature);
        }
        buf
    }

    /// Decode one edit record. Structural refusals are `RadicleIdentityInvalid`. Signatures
    /// are not verified here; [`IdentityLog::apply`] verifies them against the current
    /// document.
    pub fn decode(bytes: &[u8]) -> SynapseResult<Self> {
        let mut r = Reader::new(bytes);
        r.tag(DOMAIN_IDENTITY_EDIT_V1, "identity edit")?;
        let version = r.u16()?;
        if version != IDENTITY_DOCUMENT_VERSION_V1 {
            return Err(invalid(format!(
                "identity edit version {version} is not supported"
            )));
        }
        let doc_len = r.count(MAX_DOCUMENT_BYTES, 1, "document")?;
        let document = RepositoryIdentityDocument::decode(r.take(doc_len)?)?;
        let n = r.count(MAX_EDIT_SIGNATURES, 96, "signatures")?;
        let mut signatures = Vec::with_capacity(n);
        for _ in 0..n {
            signatures.push(IdentitySignature {
                key: r.array()?,
                signature: r.array()?,
            });
        }
        r.finish()?;
        Ok(Self {
            document,
            signatures,
        })
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
    /// The receipt failed its own verification (`EvidenceReceipt::verify`): structure,
    /// executor key, or signature.
    Receipt(ReceiptError),
    /// No identity document was in effect at the `WalSeq`, or the executor key was not
    /// registered in it (`RadicleIdentityInvalid`).
    Identity(SynapseError),
}

/// The chain of applied identity documents of one repository, in `WalSeq` order. Entry 0 is
/// genesis; entry `i` has revision `i` and chains to entry `i - 1` by digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityLog {
    entries: Vec<IdentityLogEntry>,
}

impl IdentityLog {
    /// Start a log from a genesis document (revision 0, zero `prev`) signed by at least its own
    /// threshold of its own delegates, in effect from `at`.
    pub fn genesis(edit: &IdentityEdit, at: WalSeq) -> SynapseResult<Self> {
        let doc = &edit.document;
        doc.validate()?;
        if doc.revision != 0 {
            return Err(invalid(format!(
                "genesis identity document has revision {}",
                doc.revision
            )));
        }
        doc.verify_quorum(&doc.signable_bytes(), &edit.signatures)?;
        Ok(Self {
            entries: vec![IdentityLogEntry {
                applied_at: at,
                document: doc.clone(),
            }],
        })
    }

    /// Apply `edit` from `at` on. Refused unless `at` is after the current document's
    /// `WalSeq`, the next document is valid, names the same repository, has the next revision
    /// number and the current document's digest as `prev`, and at least the *current*
    /// threshold of *current* delegates signed it. A refused edit changes nothing.
    pub fn apply(&mut self, edit: &IdentityEdit, at: WalSeq) -> SynapseResult<()> {
        let last = self.last();
        let cur = &last.document;
        if at <= last.applied_at {
            return Err(invalid(format!(
                "identity edit at {at} does not follow the current revision's {}",
                last.applied_at
            )));
        }
        let next = &edit.document;
        next.validate()?;
        if next.repo_id != cur.repo_id {
            return Err(invalid(format!(
                "identity edit for {} applied to {}",
                next.repo_id, cur.repo_id
            )));
        }
        if Some(next.revision) != cur.revision.checked_add(1) {
            return Err(invalid(format!(
                "identity edit revision {} does not follow current revision {}",
                next.revision, cur.revision
            )));
        }
        let cur_digest = cur.digest();
        if next.prev != cur_digest {
            return Err(invalid(format!(
                "identity edit chains to {}, current document is {}",
                next.prev.to_hex(),
                cur_digest.to_hex()
            )));
        }
        cur.verify_quorum(&next.signable_bytes(), &edit.signatures)?;
        self.entries.push(IdentityLogEntry {
            applied_at: at,
            document: next.clone(),
        });
        Ok(())
    }

    fn last(&self) -> &IdentityLogEntry {
        // Every constructor creates the genesis entry and nothing removes entries.
        &self.entries[self.entries.len() - 1]
    }

    /// The document in effect now (the last applied).
    pub fn current(&self) -> &RepositoryIdentityDocument {
        &self.last().document
    }

    pub fn entries(&self) -> &[IdentityLogEntry] {
        &self.entries
    }

    /// The document in effect at `at`: the last one applied at or before `at`. `None` before
    /// genesis.
    pub fn document_at(&self, at: WalSeq) -> Option<&RepositoryIdentityDocument> {
        let n = self.entries.partition_point(|e| e.applied_at <= at);
        n.checked_sub(1).map(|i| &self.entries[i].document)
    }

    /// Whether `key` was a registered executor in the document in effect at `at`.
    pub fn executor_registered_at(&self, key: &Ed25519PublicKey, at: WalSeq) -> bool {
        self.document_at(at).is_some_and(|d| d.is_executor(key))
    }

    /// The server machine key in the document in effect at `at`.
    pub fn server_key_at(&self, at: WalSeq) -> Option<Ed25519PublicKey> {
        self.document_at(at).map(|d| d.server_key)
    }

    /// Admit `receipt` as accepted at `accepted_at` only if it verifies and its executor key is
    /// registered in the document in effect at `accepted_at`. Checking an earlier receipt at
    /// its own acceptance `WalSeq` (replay) gives the same answer after any later edit. This
    /// checks executor registration only; what a receipt counts toward (input root, policy,
    /// independence) is E1.
    pub fn admit_executor_receipt(
        &self,
        receipt: &EvidenceReceipt,
        accepted_at: WalSeq,
    ) -> Result<EvidenceReceiptId, ReceiptRefusal> {
        let id = receipt.verify().map_err(ReceiptRefusal::Receipt)?;
        let key =
            decode_did_key_ed25519(&receipt.executor_did).map_err(ReceiptRefusal::Identity)?;
        let doc = self.document_at(accepted_at).ok_or_else(|| {
            ReceiptRefusal::Identity(invalid(format!(
                "no identity document in effect at {accepted_at}"
            )))
        })?;
        if !doc.is_executor(&key) {
            return Err(ReceiptRefusal::Identity(invalid(format!(
                "executor {} is not registered in identity revision {} in effect at {accepted_at}",
                receipt.executor_did, doc.revision
            ))));
        }
        Ok(id)
    }
}

/// Bounded little-endian reader. Every read is checked against the remaining bytes.
struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    fn take(&mut self, n: usize) -> SynapseResult<&'a [u8]> {
        let end = self
            .pos
            .checked_add(n)
            .filter(|&e| e <= self.bytes.len())
            .ok_or_else(|| invalid("identity record is truncated"))?;
        let s = &self.bytes[self.pos..end];
        self.pos = end;
        Ok(s)
    }

    fn array<const N: usize>(&mut self) -> SynapseResult<[u8; N]> {
        let mut a = [0u8; N];
        a.copy_from_slice(self.take(N)?);
        Ok(a)
    }

    fn u16(&mut self) -> SynapseResult<u16> {
        Ok(u16::from_le_bytes(self.array()?))
    }

    fn u32(&mut self) -> SynapseResult<u32> {
        Ok(u32::from_le_bytes(self.array()?))
    }

    fn u64(&mut self) -> SynapseResult<u64> {
        Ok(u64::from_le_bytes(self.array()?))
    }

    fn tag(&mut self, tag: &[u8], what: &str) -> SynapseResult<()> {
        if self.take(tag.len())? != tag {
            return Err(invalid(format!("{what} record has the wrong domain tag")));
        }
        Ok(())
    }

    /// A u32 count, refused above `cap` or above what the remaining bytes can hold at
    /// `item_bytes` each, before the caller allocates for it.
    fn count(&mut self, cap: usize, item_bytes: usize, what: &str) -> SynapseResult<usize> {
        let n = self.u32()? as usize;
        if n > cap {
            return Err(invalid(format!(
                "{what} count {n} exceeds the cap of {cap}"
            )));
        }
        if n.saturating_mul(item_bytes) > self.bytes.len() - self.pos {
            return Err(invalid(format!("{what} count {n} exceeds the record")));
        }
        Ok(n)
    }

    fn keys(&mut self, cap: usize, what: &str) -> SynapseResult<Vec<Ed25519PublicKey>> {
        let n = self.count(cap, 32, what)?;
        let mut v = Vec::with_capacity(n);
        for _ in 0..n {
            v.push(self.array()?);
        }
        Ok(v)
    }

    fn finish(&self) -> SynapseResult<()> {
        if self.pos != self.bytes.len() {
            return Err(invalid("identity record has trailing bytes"));
        }
        Ok(())
    }
}
