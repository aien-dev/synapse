//! Changeset envelope v2, change identity, authorship attestations, admission witnesses, and
//! obsolescence markers (ADR 0003 sections 5.1, 5.3 and 5.8, section 9 step B1).
//!
//! * A **revision** is one immutable version of a change. Its [`RevisionContent`] is what its
//!   v2 `ChangesetId` covers: the `ChangeId`, the native base `TreeDigest`, parent revisions,
//!   path mutations, and the intent summary. Who submitted it and when are excluded, so a
//!   rewrite (new content, same `ChangeId`) gets a new `ChangesetId` while identical content
//!   from two agents is one revision.
//! * An [`AuthorshipAttestation`] is an agent's signed statement that it produced a revision
//!   at a time, bound to the repository and the submission's `IdempotencyKey`. A
//!   [`ChangesetEnvelopeV2`] is content plus one attestation.
//! * An [`AdmissionWitness`] is what the server records, once and never changed, when it admits
//!   an envelope: repository, revision, signer, idempotency key, admission `WalSeq`, server
//!   time, and the [`ChainPath`] the request was authorized under. The witness of the first
//!   admission under a `ChangeId` fixes that change's **creating chain**.
//! * An [`ObsolescenceMarker`] says that one revision was replaced by zero (pruned), one
//!   (rewritten), or several (split) successors.
//!
//! Envelope v1 (`ChangesetEnvelope`) is unchanged: its encoding, signature, and `ChangesetId`
//! stay exactly as they were, and v1 identities never collide with v2 ones (distinct domain
//! tags).
//!
//! Every signed and persisted form here is the fixed-width, little-endian, length-prefixed
//! binary encoding of `docs/B1_CHANGE_IDENTITY.md` (ADR 0003 principle P5, the A1 codec style):
//! one encoding per value, every length checked against the bytes that remain before anything
//! is allocated, and any other byte sequence refused with `EnvelopeMalformed` (or
//! `EnvelopeVersionUnsupported` for an unknown content version). There is no serde form.

use crate::{
    encode_did_key_ed25519, validate_intent_summary, validate_mutations,
    validate_parent_changesets, ChangeId, ChangesetId, FileMode, IdempotencyKey, MutationOp,
    PathMutation, RefusalCode, RepoId, SynapseError, SynapseResult, TreeDigest, WalSeq,
    MAX_INTENT_SUMMARY_BYTES,
};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};

/// Content format version of envelope v2 (the first field of [`RevisionContent::encode`]).
pub const ENVELOPE_V2_VERSION: u16 = 2;
/// Domain tag of a v2 `ChangesetId` (v1 uses `SYNAPSE_CHANGESET_V1\0`).
pub const DOMAIN_CHANGESET_ID_V2: &[u8] = b"SYNAPSE_CHANGESET_V2\0";
/// Domain tag of the Ed25519 signature of an [`AuthorshipAttestation`].
pub const DOMAIN_AUTHORSHIP_SIGN_V2: &[u8] = b"SYNAPSE_AUTHORSHIP_SIGN_V2\0";
/// Domain tag of the Ed25519 signature of an [`ObsolescenceMarker`].
pub const DOMAIN_OBSOLESCENCE_SIGN_V1: &[u8] = b"SYNAPSE_OBSOLESCENCE_SIGN_V1\0";
/// Domain tag of [`AdmissionWitness::digest`].
pub const DOMAIN_ADMISSION_WITNESS_V1: &[u8] = b"SYNAPSE_ADMISSION_WITNESS_V1\0";
/// Most links in a [`ChainPath`] (the F1 `MAX_CHAIN_DEPTH`).
pub const MAX_CHAIN_PATH_DEPTH: usize = 16;
/// Most successors of one obsolescence marker.
pub const MAX_OBSOLESCENCE_SUCCESSORS: usize = 256;

const MAX_PATH_BYTES: usize = 2048;
const MAX_REPO_ID_BYTES: usize = 128;
/// Encoded size of the smallest mutation (`u32` empty path and a delete tag).
const MIN_MUTATION_BYTES: usize = 4 + 1;
/// Witness signer tag of an agent admission (B5 adds the server-derived signer as tag 2).
const SIGNER_TAG_AGENT: u8 = 1;
const OP_TAG_UPSERT: u8 = 1;
const OP_TAG_DELETE: u8 = 2;

fn malformed(msg: impl Into<String>) -> SynapseError {
    SynapseError::new(RefusalCode::EnvelopeMalformed, msg)
}

fn put_str(buf: &mut Vec<u8>, s: &str) {
    buf.extend_from_slice(&(s.len() as u32).to_le_bytes());
    buf.extend_from_slice(s.as_bytes());
}

fn verify_ed25519(key: &[u8; 32], msg: &[u8], sig: &[u8; 64], what: &str) -> SynapseResult<()> {
    let vk = VerifyingKey::from_bytes(key).map_err(|_| {
        SynapseError::new(
            RefusalCode::DidKeyInvalid,
            format!("{what}: invalid Ed25519 public key"),
        )
    })?;
    vk.verify_strict(msg, &Signature::from_bytes(sig))
        .map_err(|_| {
            SynapseError::new(
                RefusalCode::AuthSignatureInvalid,
                format!("{what}: Ed25519 signature verification failed"),
            )
        })
}

// ---------------------------------------------------------------------------------------
// Revision content and the v2 ChangesetId
// ---------------------------------------------------------------------------------------

/// What a v2 `ChangesetId` covers: the content of one revision, never who submitted it or
/// when. `IntentRecord` (step B3) and conflict terms (step D2) extend it under a later content
/// version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevisionContent {
    /// The unit of intended work this revision belongs to.
    pub change_id: ChangeId,
    /// Native base: the `TreeDigest` the mutations apply to (envelope v1's `base_git_oid`).
    pub base_tree: TreeDigest,
    /// Revisions this one depends on, strictly ascending.
    pub parents: Vec<ChangesetId>,
    /// Path mutations, strictly ascending by path, at least one.
    pub mutations: Vec<PathMutation>,
    /// Free-text intent, 1..=4096 bytes (replaced by `IntentRecord` in step B3).
    pub intent_summary: String,
}

impl RevisionContent {
    /// Parents strictly ascending, mutations non-empty on valid sorted unique paths, intent
    /// summary 1..=4096 bytes (the same rules and refusal codes as envelope v1).
    pub fn validate(&self) -> SynapseResult<()> {
        validate_intent_summary(&self.intent_summary)?;
        validate_parent_changesets(&self.parents)?;
        validate_mutations(&self.mutations)
    }

    /// `version u16 (2) | change_id [16] | base_tree [32] | u32 count | parent [32]* |
    /// u32 count | (path str | op)* | intent_summary str`, where `op` is `1 | mode u8 |
    /// blob_digest [32] | size u64` (upsert) or `2` (delete) and `str` is `u32 len | UTF-8`.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(128 + 96 * self.mutations.len());
        buf.extend_from_slice(&ENVELOPE_V2_VERSION.to_le_bytes());
        buf.extend_from_slice(&self.change_id.0);
        buf.extend_from_slice(&self.base_tree.0);
        buf.extend_from_slice(&(self.parents.len() as u32).to_le_bytes());
        for p in &self.parents {
            buf.extend_from_slice(&p.0);
        }
        buf.extend_from_slice(&(self.mutations.len() as u32).to_le_bytes());
        for m in &self.mutations {
            put_str(&mut buf, &m.path);
            match &m.op {
                MutationOp::Upsert {
                    mode,
                    blob_digest,
                    size_bytes,
                } => {
                    buf.push(OP_TAG_UPSERT);
                    buf.push(mode.tag_byte());
                    buf.extend_from_slice(&blob_digest.0);
                    buf.extend_from_slice(&size_bytes.to_le_bytes());
                }
                MutationOp::Delete => buf.push(OP_TAG_DELETE),
            }
        }
        put_str(&mut buf, &self.intent_summary);
        buf
    }

    /// Decode exactly one canonical content encoding (structure only; see [`Self::validate`]).
    pub fn decode(bytes: &[u8]) -> SynapseResult<Self> {
        let mut r = Reader::new(bytes);
        let content = Self::decode_from(&mut r)?;
        r.finish()?;
        Ok(content)
    }

    fn decode_from(r: &mut Reader) -> SynapseResult<Self> {
        let version = r.u16()?;
        if version != ENVELOPE_V2_VERSION {
            return Err(SynapseError::new(
                RefusalCode::EnvelopeVersionUnsupported,
                format!("unsupported revision content version {version}"),
            ));
        }
        let change_id = ChangeId(r.array()?);
        let base_tree = TreeDigest(r.array()?);
        let n = r.count(usize::MAX, 32)?;
        let mut parents = Vec::with_capacity(n);
        for _ in 0..n {
            parents.push(ChangesetId(r.array()?));
        }
        let n = r.count(usize::MAX, MIN_MUTATION_BYTES)?;
        let mut mutations = Vec::with_capacity(n);
        for _ in 0..n {
            let path = r.string(MAX_PATH_BYTES)?;
            let op = match r.u8()? {
                OP_TAG_UPSERT => {
                    let tag = r.u8()?;
                    let mode = FileMode::from_tag_byte(tag)
                        .ok_or_else(|| malformed(format!("unknown file mode tag {tag}")))?;
                    MutationOp::Upsert {
                        mode,
                        blob_digest: crate::BlobDigest(r.array()?),
                        size_bytes: r.u64()?,
                    }
                }
                OP_TAG_DELETE => MutationOp::Delete,
                tag => return Err(malformed(format!("unknown mutation tag {tag}"))),
            };
            mutations.push(PathMutation { path, op });
        }
        let intent_summary = r.string(MAX_INTENT_SUMMARY_BYTES)?;
        Ok(Self {
            change_id,
            base_tree,
            parents,
            mutations,
            intent_summary,
        })
    }

    /// `SHA-256(DOMAIN_CHANGESET_ID_V2 || u64 len || encode())`: content only.
    pub fn changeset_id(&self) -> ChangesetId {
        let bytes = self.encode();
        let mut h = Sha256::new();
        h.update(DOMAIN_CHANGESET_ID_V2);
        h.update((bytes.len() as u64).to_le_bytes());
        h.update(&bytes);
        ChangesetId(h.finalize().into())
    }
}

// ---------------------------------------------------------------------------------------
// Authorship attestation and envelope v2
// ---------------------------------------------------------------------------------------

/// An agent's signed statement that it produced revision `changeset_id` of repository
/// `repo_id` at `attested_at_ms` (the agent's clock, never used for ordering or retention),
/// submitted under `idempotency_key`. An attestation added later never revokes a receipt
/// already accepted (ADR 0003 section 5.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorshipAttestation {
    pub repo_id: RepoId,
    pub changeset_id: ChangesetId,
    pub author_key: [u8; 32],
    pub idempotency_key: IdempotencyKey,
    pub attested_at_ms: u64,
    pub signature: [u8; 64],
}

impl AuthorshipAttestation {
    /// Sign an attestation with `author`.
    pub fn sign(
        author: &SigningKey,
        repo_id: RepoId,
        changeset_id: ChangesetId,
        idempotency_key: IdempotencyKey,
        attested_at_ms: u64,
    ) -> Self {
        let mut att = Self {
            repo_id,
            changeset_id,
            author_key: author.verifying_key().to_bytes(),
            idempotency_key,
            attested_at_ms,
            signature: [0u8; 64],
        };
        att.signature = author.sign(&att.signable_bytes()).to_bytes();
        att
    }

    /// The author's `did:key`.
    pub fn author_did(&self) -> String {
        encode_did_key_ed25519(&self.author_key)
    }

    fn encode_body(&self, buf: &mut Vec<u8>) {
        put_str(buf, self.repo_id.as_str());
        buf.extend_from_slice(&self.changeset_id.0);
        buf.extend_from_slice(&self.author_key);
        buf.extend_from_slice(&self.idempotency_key.0);
        buf.extend_from_slice(&self.attested_at_ms.to_le_bytes());
    }

    /// `DOMAIN_AUTHORSHIP_SIGN_V2 || repo_id str || changeset_id || author_key ||
    /// idempotency_key || attested_at_ms u64`.
    pub fn signable_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(192);
        buf.extend_from_slice(DOMAIN_AUTHORSHIP_SIGN_V2);
        self.encode_body(&mut buf);
        buf
    }

    /// Strict Ed25519 verification of the author's signature.
    pub fn verify(&self) -> SynapseResult<()> {
        verify_ed25519(
            &self.author_key,
            &self.signable_bytes(),
            &self.signature,
            "authorship attestation",
        )
    }

    /// Body (as signed, without the domain tag) then the 64-byte signature.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(192);
        self.encode_into(&mut buf);
        buf
    }

    fn encode_into(&self, buf: &mut Vec<u8>) {
        self.encode_body(buf);
        buf.extend_from_slice(&self.signature);
    }

    /// Decode exactly one canonical attestation (structure only; see [`Self::verify`]).
    pub fn decode(bytes: &[u8]) -> SynapseResult<Self> {
        let mut r = Reader::new(bytes);
        let att = Self::decode_from(&mut r)?;
        r.finish()?;
        Ok(att)
    }

    fn decode_from(r: &mut Reader) -> SynapseResult<Self> {
        Ok(Self {
            repo_id: r.repo()?,
            changeset_id: ChangesetId(r.array()?),
            author_key: r.array()?,
            idempotency_key: IdempotencyKey(r.array()?),
            attested_at_ms: r.u64()?,
            signature: r.array()?,
        })
    }
}

/// Signed changeset envelope v2: one revision's content plus one authorship attestation over
/// its content-only `ChangesetId`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChangesetEnvelopeV2 {
    pub content: RevisionContent,
    pub attestation: AuthorshipAttestation,
}

impl ChangesetEnvelopeV2 {
    /// Build and sign an envelope: the attestation names `content.changeset_id()`.
    pub fn sign_new(
        author: &SigningKey,
        repo_id: RepoId,
        content: RevisionContent,
        idempotency_key: IdempotencyKey,
        attested_at_ms: u64,
    ) -> Self {
        let id = content.changeset_id();
        let attestation =
            AuthorshipAttestation::sign(author, repo_id, id, idempotency_key, attested_at_ms);
        Self {
            content,
            attestation,
        }
    }

    /// The content-only v2 `ChangesetId`.
    pub fn changeset_id(&self) -> ChangesetId {
        self.content.changeset_id()
    }

    /// Validate the content, check that the attestation names this content, and verify its
    /// signature. Returns the v2 `ChangesetId`.
    pub fn validate(&self) -> SynapseResult<ChangesetId> {
        self.content.validate()?;
        let id = self.content.changeset_id();
        if self.attestation.changeset_id != id {
            return Err(SynapseError::new(
                RefusalCode::AuthSignatureInvalid,
                format!(
                    "attestation names revision {} but the content is revision {id}",
                    self.attestation.changeset_id
                ),
            ));
        }
        self.attestation.verify()?;
        Ok(id)
    }

    /// `u32 content_len | content | attestation`.
    pub fn encode(&self) -> Vec<u8> {
        let content = self.content.encode();
        let mut buf = Vec::with_capacity(content.len() + 196);
        buf.extend_from_slice(&(content.len() as u32).to_le_bytes());
        buf.extend_from_slice(&content);
        self.attestation.encode_into(&mut buf);
        buf
    }

    /// Decode exactly one canonical envelope (structure only; see [`Self::validate`]).
    pub fn decode(bytes: &[u8]) -> SynapseResult<Self> {
        let mut r = Reader::new(bytes);
        let len = r.u32()? as usize;
        let mut inner = Reader::new(r.take(len)?);
        let content = RevisionContent::decode_from(&mut inner)?;
        inner.finish()?;
        let attestation = AuthorshipAttestation::decode_from(&mut r)?;
        r.finish()?;
        Ok(Self {
            content,
            attestation,
        })
    }
}

// ---------------------------------------------------------------------------------------
// Chains, witnesses, markers
// ---------------------------------------------------------------------------------------

/// A delegation chain as the digests of its capability links, root first (each digest is a
/// `synapse_auth::LinkDigest`). Chains are compared by their link digests: chain `A`
/// **dominates** chain `B` when `A` is `B` or one of its ancestors (a prefix of it), and `B`
/// then **descends from** `A`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ChainPath(Vec<[u8; 32]>);

impl ChainPath {
    /// A chain of 1..=`MAX_CHAIN_PATH_DEPTH` link digests, root first.
    pub fn new(links: Vec<[u8; 32]>) -> SynapseResult<Self> {
        if links.is_empty() || links.len() > MAX_CHAIN_PATH_DEPTH {
            return Err(SynapseError::new(
                RefusalCode::AuthChainBroken,
                format!(
                    "chain path length {} outside 1..={MAX_CHAIN_PATH_DEPTH}",
                    links.len()
                ),
            ));
        }
        Ok(Self(links))
    }

    /// Link digests, root first.
    pub fn links(&self) -> &[[u8; 32]] {
        &self.0
    }

    /// True when `self` is `other` or an ancestor of it (a prefix of its links).
    pub fn dominates(&self, other: &ChainPath) -> bool {
        other.0.starts_with(&self.0)
    }

    /// True when `self` is `ancestor` or descends from it.
    pub fn descends_from(&self, ancestor: &ChainPath) -> bool {
        ancestor.dominates(self)
    }

    /// `count u8 | digest [32]*`.
    pub fn encode_into(&self, buf: &mut Vec<u8>) {
        buf.push(self.0.len() as u8);
        for d in &self.0 {
            buf.extend_from_slice(d);
        }
    }

    /// Decode exactly one canonical chain path.
    pub fn decode(bytes: &[u8]) -> SynapseResult<Self> {
        let mut r = Reader::new(bytes);
        let c = Self::decode_from(&mut r)?;
        r.finish()?;
        Ok(c)
    }

    fn decode_from(r: &mut Reader) -> SynapseResult<Self> {
        let n = r.u8()? as usize;
        if n == 0 || n > MAX_CHAIN_PATH_DEPTH {
            return Err(malformed(format!(
                "chain path length {n} outside 1..={MAX_CHAIN_PATH_DEPTH}"
            )));
        }
        let mut links = Vec::with_capacity(n);
        for _ in 0..n {
            links.push(r.array()?);
        }
        Ok(Self(links))
    }
}

/// Who signed an admitted revision. Step B5 adds the server-derived signer (the server's
/// machine-key signature and its `DerivationAttestation` digest) under tag 2.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WitnessSigner {
    /// An agent's key and its signature over the envelope (its authorship attestation).
    Agent {
        author_key: [u8; 32],
        signature: [u8; 64],
    },
}

/// The immutable record of one admission of a revision (ADR 0003 section 5.1). Idempotency
/// is keyed on (`repo_id`, signer DID, `idempotency_key`); replay order is `admission_seq`;
/// retention follows the server's clock (`admitted_at_ms`), never a client clock. `chain` is
/// the delegation chain the admission was authorized under; the first admission's chain is
/// the change's creating chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmissionWitness {
    pub repo_id: RepoId,
    pub changeset_id: ChangesetId,
    pub signer: WitnessSigner,
    pub idempotency_key: IdempotencyKey,
    pub admission_seq: WalSeq,
    pub admitted_at_ms: u64,
    pub chain: ChainPath,
}

impl AdmissionWitness {
    /// The witness of admitting `attestation` at `admission_seq` under `chain`.
    pub fn of_attestation(
        attestation: &AuthorshipAttestation,
        chain: ChainPath,
        admission_seq: WalSeq,
        admitted_at_ms: u64,
    ) -> Self {
        Self {
            repo_id: attestation.repo_id.clone(),
            changeset_id: attestation.changeset_id,
            signer: WitnessSigner::Agent {
                author_key: attestation.author_key,
                signature: attestation.signature,
            },
            idempotency_key: attestation.idempotency_key,
            admission_seq,
            admitted_at_ms,
            chain,
        }
    }

    /// The signer's `did:key`.
    pub fn signer_did(&self) -> String {
        match &self.signer {
            WitnessSigner::Agent { author_key, .. } => encode_did_key_ed25519(author_key),
        }
    }

    /// `repo_id str | changeset_id [32] | signer | idempotency_key [32] | admission_seq u64 |
    /// admitted_at_ms u64 | chain`, with `signer` = `1 | author_key [32] | signature [64]`.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(256);
        put_str(&mut buf, self.repo_id.as_str());
        buf.extend_from_slice(&self.changeset_id.0);
        match &self.signer {
            WitnessSigner::Agent {
                author_key,
                signature,
            } => {
                buf.push(SIGNER_TAG_AGENT);
                buf.extend_from_slice(author_key);
                buf.extend_from_slice(signature);
            }
        }
        buf.extend_from_slice(&self.idempotency_key.0);
        buf.extend_from_slice(&self.admission_seq.0.to_le_bytes());
        buf.extend_from_slice(&self.admitted_at_ms.to_le_bytes());
        self.chain.encode_into(&mut buf);
        buf
    }

    /// Decode exactly one canonical witness.
    pub fn decode(bytes: &[u8]) -> SynapseResult<Self> {
        let mut r = Reader::new(bytes);
        let repo_id = r.repo()?;
        let changeset_id = ChangesetId(r.array()?);
        let signer = match r.u8()? {
            SIGNER_TAG_AGENT => WitnessSigner::Agent {
                author_key: r.array()?,
                signature: r.array()?,
            },
            tag => return Err(malformed(format!("unknown witness signer tag {tag}"))),
        };
        let w = Self {
            repo_id,
            changeset_id,
            signer,
            idempotency_key: IdempotencyKey(r.array()?),
            admission_seq: WalSeq(r.u64()?),
            admitted_at_ms: r.u64()?,
            chain: ChainPath::decode_from(&mut r)?,
        };
        r.finish()?;
        Ok(w)
    }

    /// `SHA-256(DOMAIN_ADMISSION_WITNESS_V1 || encode())`: the admission witness digest that
    /// promotion signatures cover (ADR 0003 section 5.5).
    pub fn digest(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(DOMAIN_ADMISSION_WITNESS_V1);
        h.update(self.encode());
        h.finalize().into()
    }
}

/// How many successors replace the obsolete revision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObsolescenceKind {
    /// Zero successors: the attempt is discarded.
    Pruned,
    /// One successor.
    Rewritten,
    /// Several successors.
    Split,
}

/// A signed record that revision `predecessor` of change `change_id` was replaced by
/// `successors` (strictly ascending, never containing `predecessor`): zero for a prune, one
/// for a rewrite, several for a split (ADR 0003 sections 5.1 and 5.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObsolescenceMarker {
    pub repo_id: RepoId,
    pub change_id: ChangeId,
    pub predecessor: ChangesetId,
    pub successors: Vec<ChangesetId>,
    pub signer_key: [u8; 32],
    pub signed_at_ms: u64,
    pub signature: [u8; 64],
}

impl ObsolescenceMarker {
    /// Build and sign a marker; `successors` are sorted and deduplicated.
    pub fn sign_new(
        signer: &SigningKey,
        repo_id: RepoId,
        change_id: ChangeId,
        predecessor: ChangesetId,
        mut successors: Vec<ChangesetId>,
        signed_at_ms: u64,
    ) -> Self {
        successors.sort();
        successors.dedup();
        let mut m = Self {
            repo_id,
            change_id,
            predecessor,
            successors,
            signer_key: signer.verifying_key().to_bytes(),
            signed_at_ms,
            signature: [0u8; 64],
        };
        m.signature = signer.sign(&m.signable_bytes()).to_bytes();
        m
    }

    /// Pruned, rewritten, or split, by successor count.
    pub fn kind(&self) -> ObsolescenceKind {
        match self.successors.len() {
            0 => ObsolescenceKind::Pruned,
            1 => ObsolescenceKind::Rewritten,
            _ => ObsolescenceKind::Split,
        }
    }

    /// The signer's `did:key`.
    pub fn signer_did(&self) -> String {
        encode_did_key_ed25519(&self.signer_key)
    }

    fn encode_body(&self, buf: &mut Vec<u8>) {
        put_str(buf, self.repo_id.as_str());
        buf.extend_from_slice(&self.change_id.0);
        buf.extend_from_slice(&self.predecessor.0);
        buf.extend_from_slice(&(self.successors.len() as u32).to_le_bytes());
        for s in &self.successors {
            buf.extend_from_slice(&s.0);
        }
        buf.extend_from_slice(&self.signer_key);
        buf.extend_from_slice(&self.signed_at_ms.to_le_bytes());
    }

    /// `DOMAIN_OBSOLESCENCE_SIGN_V1 || repo_id str || change_id [16] || predecessor [32] ||
    /// u32 count || successor [32]* || signer_key [32] || signed_at_ms u64`.
    pub fn signable_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(160 + 32 * self.successors.len());
        buf.extend_from_slice(DOMAIN_OBSOLESCENCE_SIGN_V1);
        self.encode_body(&mut buf);
        buf
    }

    /// Successors strictly ascending, at most `MAX_OBSOLESCENCE_SUCCESSORS`, never the
    /// predecessor; signature verifies strictly.
    pub fn validate(&self) -> SynapseResult<()> {
        if self.successors.len() > MAX_OBSOLESCENCE_SUCCESSORS {
            return Err(SynapseError::new(
                RefusalCode::ObsolescenceMarkerInvalid,
                format!("more than {MAX_OBSOLESCENCE_SUCCESSORS} successors"),
            ));
        }
        if self.successors.windows(2).any(|w| w[0] >= w[1]) {
            return Err(SynapseError::new(
                RefusalCode::ObsolescenceMarkerInvalid,
                "successors must be strictly ascending",
            ));
        }
        if self.successors.contains(&self.predecessor) {
            return Err(SynapseError::new(
                RefusalCode::ObsolescenceMarkerInvalid,
                "a revision cannot be its own successor",
            ));
        }
        verify_ed25519(
            &self.signer_key,
            &self.signable_bytes(),
            &self.signature,
            "obsolescence marker",
        )
    }

    /// Body (as signed, without the domain tag) then the 64-byte signature.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(160 + 32 * self.successors.len());
        self.encode_body(&mut buf);
        buf.extend_from_slice(&self.signature);
        buf
    }

    /// Decode exactly one canonical marker (structure only; see [`Self::validate`]).
    pub fn decode(bytes: &[u8]) -> SynapseResult<Self> {
        let mut r = Reader::new(bytes);
        let repo_id = r.repo()?;
        let change_id = ChangeId(r.array()?);
        let predecessor = ChangesetId(r.array()?);
        let n = r.count(MAX_OBSOLESCENCE_SUCCESSORS, 32)?;
        let mut successors = Vec::with_capacity(n);
        for _ in 0..n {
            successors.push(ChangesetId(r.array()?));
        }
        let m = Self {
            repo_id,
            change_id,
            predecessor,
            successors,
            signer_key: r.array()?,
            signed_at_ms: r.u64()?,
            signature: r.array()?,
        };
        r.finish()?;
        Ok(m)
    }

    /// `SHA-256(DOMAIN_OBSOLESCENCE_SIGN_V1 || encode())`: identity of one signed marker.
    pub fn digest(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(DOMAIN_OBSOLESCENCE_SIGN_V1);
        h.update(self.encode());
        h.finalize().into()
    }
}

// ---------------------------------------------------------------------------------------
// Bounded reader
// ---------------------------------------------------------------------------------------

/// Bounds-checked little-endian reader; every failure is `EnvelopeMalformed`.
struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    fn take(&mut self, n: usize) -> SynapseResult<&'a [u8]> {
        if n > self.remaining() {
            return Err(malformed(format!(
                "truncated: need {n} bytes at offset {}, {} remain",
                self.pos,
                self.remaining()
            )));
        }
        let out = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(out)
    }

    fn array<const N: usize>(&mut self) -> SynapseResult<[u8; N]> {
        Ok(self.take(N)?.try_into().expect("N bytes"))
    }

    fn u8(&mut self) -> SynapseResult<u8> {
        Ok(self.take(1)?[0])
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

    /// A `u32` count, refused above `cap` or above what `min_item_bytes` per item could fit
    /// in the bytes that remain (so nothing is reserved beyond the input).
    fn count(&mut self, cap: usize, min_item_bytes: usize) -> SynapseResult<usize> {
        let n = self.u32()? as usize;
        if n > cap || n.saturating_mul(min_item_bytes) > self.remaining() {
            return Err(malformed(format!(
                "count {n} above cap {cap} or the {} bytes that remain",
                self.remaining()
            )));
        }
        Ok(n)
    }

    fn string(&mut self, cap: usize) -> SynapseResult<String> {
        let len = self.u32()? as usize;
        if len > cap {
            return Err(malformed(format!("string length {len} above cap {cap}")));
        }
        let bytes = self.take(len)?;
        String::from_utf8(bytes.to_vec()).map_err(|_| malformed("string is not UTF-8"))
    }

    fn repo(&mut self) -> SynapseResult<RepoId> {
        let s = self.string(MAX_REPO_ID_BYTES)?;
        RepoId::new(s).map_err(|e| malformed(format!("repository id: {}", e.message)))
    }

    fn finish(&self) -> SynapseResult<()> {
        if self.pos != self.buf.len() {
            return Err(malformed(format!("{} trailing bytes", self.remaining())));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::BlobDigest;

    fn repo() -> RepoId {
        RepoId::new("aien-spark/synapse").unwrap()
    }

    fn content(change: u8, body: &[u8]) -> RevisionContent {
        RevisionContent {
            change_id: ChangeId([change; 16]),
            base_tree: TreeDigest([0x5A; 32]),
            parents: vec![],
            mutations: vec![PathMutation {
                path: "src/lib.rs".into(),
                op: MutationOp::Upsert {
                    mode: FileMode::Regular644,
                    blob_digest: BlobDigest::compute(body),
                    size_bytes: body.len() as u64,
                },
            }],
            intent_summary: "add lib".into(),
        }
    }

    #[test]
    fn b1_v2_changeset_id_covers_content_only_not_author_or_time() {
        let a = SigningKey::from_bytes(&[1; 32]);
        let b = SigningKey::from_bytes(&[2; 32]);
        let c = content(7, b"x");
        let ea = ChangesetEnvelopeV2::sign_new(&a, repo(), c.clone(), IdempotencyKey([1; 32]), 10);
        let eb = ChangesetEnvelopeV2::sign_new(&b, repo(), c.clone(), IdempotencyKey([2; 32]), 99);
        assert_eq!(ea.validate().unwrap(), eb.validate().unwrap());
        assert_ne!(ea.attestation, eb.attestation);
        let mut rewritten = c.clone();
        rewritten.intent_summary = "add lib, rewritten".into();
        assert_ne!(rewritten.changeset_id(), c.changeset_id());
        assert_eq!(rewritten.change_id, c.change_id);
    }

    #[test]
    fn b1_envelope_v2_round_trips_and_refuses_malformed_bytes() {
        let a = SigningKey::from_bytes(&[1; 32]);
        let mut c = content(7, b"x");
        c.parents = vec![ChangesetId([1; 32]), ChangesetId([2; 32])];
        c.mutations.push(PathMutation {
            path: "src/old.rs".into(),
            op: MutationOp::Delete,
        });
        let env = ChangesetEnvelopeV2::sign_new(&a, repo(), c, IdempotencyKey([1; 32]), 10);
        let bytes = env.encode();
        assert_eq!(ChangesetEnvelopeV2::decode(&bytes).unwrap(), env);
        assert_eq!(ChangesetEnvelopeV2::decode(&bytes).unwrap().encode(), bytes);
        for cut in 0..bytes.len() {
            assert!(
                ChangesetEnvelopeV2::decode(&bytes[..cut]).is_err(),
                "cut {cut}"
            );
        }
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert_eq!(
            ChangesetEnvelopeV2::decode(&trailing).unwrap_err().code,
            RefusalCode::EnvelopeMalformed
        );
        let mut huge = bytes.clone();
        huge[0..4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(
            ChangesetEnvelopeV2::decode(&huge).unwrap_err().code,
            RefusalCode::EnvelopeMalformed
        );
        let mut version = bytes.clone();
        version[4] = 3;
        assert_eq!(
            ChangesetEnvelopeV2::decode(&version).unwrap_err().code,
            RefusalCode::EnvelopeVersionUnsupported
        );
    }

    #[test]
    fn b1_envelope_v2_signature_binds_repo_key_and_time() {
        let a = SigningKey::from_bytes(&[1; 32]);
        let env = ChangesetEnvelopeV2::sign_new(
            &a,
            repo(),
            content(7, b"x"),
            IdempotencyKey([1; 32]),
            10,
        );
        let mut t = env.clone();
        t.attestation.attested_at_ms = 11;
        assert_eq!(
            t.validate().unwrap_err().code,
            RefusalCode::AuthSignatureInvalid
        );
        let mut t = env.clone();
        t.attestation.repo_id = RepoId::new("aien-spark/other").unwrap();
        assert_eq!(
            t.validate().unwrap_err().code,
            RefusalCode::AuthSignatureInvalid
        );
        let mut t = env.clone();
        t.content.intent_summary = "changed".into();
        assert_eq!(
            t.validate().unwrap_err().code,
            RefusalCode::AuthSignatureInvalid
        );
    }

    #[test]
    fn b1_chain_path_dominance_is_prefix_order() {
        let r = ChainPath::new(vec![[1; 32]]).unwrap();
        let o = ChainPath::new(vec![[1; 32], [2; 32]]).unwrap();
        let w = ChainPath::new(vec![[1; 32], [2; 32], [3; 32]]).unwrap();
        let x = ChainPath::new(vec![[1; 32], [9; 32]]).unwrap();
        assert!(r.dominates(&o) && o.dominates(&w) && r.dominates(&w) && o.dominates(&o));
        assert!(!w.dominates(&o) && !x.dominates(&w) && !o.dominates(&x));
        assert!(w.descends_from(&o) && !x.descends_from(&o));
        assert!(ChainPath::new(vec![]).is_err());
        assert!(ChainPath::new(vec![[0; 32]; MAX_CHAIN_PATH_DEPTH + 1]).is_err());
    }

    #[test]
    fn b1_witness_and_marker_round_trip() {
        let a = SigningKey::from_bytes(&[1; 32]);
        let env = ChangesetEnvelopeV2::sign_new(
            &a,
            repo(),
            content(7, b"x"),
            IdempotencyKey([1; 32]),
            10,
        );
        let chain = ChainPath::new(vec![[1; 32], [2; 32]]).unwrap();
        let w = AdmissionWitness::of_attestation(&env.attestation, chain, WalSeq(4), 77);
        assert_eq!(AdmissionWitness::decode(&w.encode()).unwrap(), w);
        assert_eq!(w.signer_did(), env.attestation.author_did());
        let m = ObsolescenceMarker::sign_new(
            &a,
            repo(),
            ChangeId([7; 16]),
            ChangesetId([3; 32]),
            vec![
                ChangesetId([5; 32]),
                ChangesetId([4; 32]),
                ChangesetId([5; 32]),
            ],
            12,
        );
        assert_eq!(
            m.successors,
            vec![ChangesetId([4; 32]), ChangesetId([5; 32])]
        );
        assert_eq!(m.kind(), ObsolescenceKind::Split);
        m.validate().unwrap();
        assert_eq!(ObsolescenceMarker::decode(&m.encode()).unwrap(), m);
        let mut own = m.clone();
        own.successors = vec![m.predecessor];
        assert_eq!(
            own.validate().unwrap_err().code,
            RefusalCode::ObsolescenceMarkerInvalid
        );
    }
}
