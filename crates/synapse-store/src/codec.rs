//! Binary canonical codec v2 for WAL records and checkpoints (ADR 0003 section 9, step A1).
//!
//! Scope: only the bytes inside WAL frames and the checkpoint file change. The changeset
//! envelope, its signature bytes and every identity (`ChangesetId`, `BlobDigest`, frame
//! digests) are unchanged; envelope v2 is a separate step (B1).
//!
//! Record layout: `CODEC_V2 (u8) | kind (u8, same as WalRecord::kind_byte) | body`.
//! Primitives are fixed width and little endian: `u8`, `u16`, `u32`, `u64`; `usize` is
//! written as `u64`; `bool` is one byte 0 or 1; `Option` is a tag byte 0 or 1 then the
//! value; strings and byte strings are `u32 length | bytes` (strings must be UTF-8);
//! sequences are `u32 count | items`; fixed arrays (`[u8; 32]`, `GitOid`) are raw bytes.
//! There is exactly one encoding per logical record: any other tag value, trailing byte,
//! invalid UTF-8, or out-of-order checkpoint key is refused, so decode then encode gives
//! the input bytes back.
//!
//! Untrusted input: every length and count is checked against the bytes that remain and
//! against the caller's cap before anything is allocated, so a frame that declares a
//! huge length is refused without allocating it.

use super::*;
use crate::git_bridge::{
    GitBlobMapping, GitBridgeEntry, GitBridgeTarget, GitImportedCommit, GitImportedRefs,
    GitImportedTag, GitTreeMapping,
};
use crate::seal::REVISION_SEAL_TAG;
use synapse_auth::CapabilityLink;
use synapse_core::{FileMode, GitOid, PathMutation, TreeDigest};

/// Codec version byte that starts every binary record and checkpoint content.
pub const CODEC_V2: u8 = 2;

/// WAL frame header byte 7 (flags): set when the payload holds a binary v2 record.
/// Zero means the v1 JSON record. Any other value is refused (`WalFlagsNonZero`).
pub const WAL_FLAG_CODEC_V2: u8 = 0x01;

/// Binary checkpoint file name inside the store root.
pub const CHECKPOINT_V2_FILE: &str = "checkpoint.v2";
/// Binary checkpoint magic.
pub const CHECKPOINT_V2_MAGIC: [u8; 4] = *b"SCK2";
/// Binary checkpoint format version.
pub const CHECKPOINT_V2_VERSION: u16 = 2;
/// Fixed header length of `checkpoint.v2` (everything before the content).
pub const CHECKPOINT_V2_HEADER_LEN: usize = 216;
/// Domain tag of the checkpoint content digest.
pub const DOMAIN_CHECKPOINT_CONTENT_V2: &[u8] = b"SYNAPSE_CHECKPOINT_CONTENT_V2\0";
/// Domain tag of the checkpoint root chain.
pub const DOMAIN_CHECKPOINT_ROOT_V2: &[u8] = b"SYNAPSE_CHECKPOINT_ROOT_V2\0";
/// Domain tag of `SynapseStore::state_root_digest` (unchanged from v1).
pub const DOMAIN_STATE_ROOT_V1: &[u8] = b"SYNAPSE_STATE_ROOT_V1\0";

/// Which encoding a WAL record payload uses (declared by the frame header flags).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordCodec {
    /// v1: `serde_json` text (flags 0).
    JsonV1,
    /// v2: this module's binary canonical encoding (flags [`WAL_FLAG_CODEC_V2`]).
    BinaryV2,
}

impl RecordCodec {
    /// Frame header flags byte for this codec.
    pub fn frame_flags(self) -> u8 {
        match self {
            Self::JsonV1 => 0,
            Self::BinaryV2 => WAL_FLAG_CODEC_V2,
        }
    }

    /// Codec declared by a frame header flags byte (`None` for any unknown value).
    pub fn from_frame_flags(flags: u8) -> Option<Self> {
        match flags {
            0 => Some(Self::JsonV1),
            WAL_FLAG_CODEC_V2 => Some(Self::BinaryV2),
            _ => None,
        }
    }
}

/// Typed refusal from the binary decoder. `at` is the byte offset where it was found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CodecRefusal {
    /// The input ends before a field: `need` more bytes were required.
    Truncated { at: usize, need: usize },
    /// A declared length or count needs more than the cap allows.
    LengthOverCap { at: usize, declared: u64, cap: u64 },
    /// Bytes remain after the last field.
    TrailingBytes { at: usize, count: usize },
    /// A tag byte (record kind, enum variant, bool, option) has no meaning.
    UnknownTag {
        at: usize,
        field: &'static str,
        tag: u8,
    },
    /// A string is not UTF-8.
    InvalidUtf8 { at: usize },
    /// The codec version byte is not [`CODEC_V2`].
    VersionUnsupported { found: u8 },
    /// Keys out of strict order (checkpoint maps), so a second encoding would exist.
    NotCanonical { at: usize, field: &'static str },
    /// A repository id fails `RepoId::new`.
    InvalidRepoId { at: usize },
    /// An embedded `synapse-core` encoding (envelope v2, chain path, marker) is refused
    /// by its own decoder with `code`.
    EmbeddedMalformed {
        at: usize,
        field: &'static str,
        code: RefusalCode,
    },
}

impl CodecRefusal {
    /// Short stable name of the refusal kind.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Truncated { .. } => "Truncated",
            Self::LengthOverCap { .. } => "LengthOverCap",
            Self::TrailingBytes { .. } => "TrailingBytes",
            Self::UnknownTag { .. } => "UnknownTag",
            Self::InvalidUtf8 { .. } => "InvalidUtf8",
            Self::VersionUnsupported { .. } => "VersionUnsupported",
            Self::NotCanonical { .. } => "NotCanonical",
            Self::InvalidRepoId { .. } => "InvalidRepoId",
            Self::EmbeddedMalformed { .. } => "EmbeddedMalformed",
        }
    }

    /// The refusal as a `SynapseError` with `code`.
    pub fn into_error(self, code: RefusalCode, context: &str) -> SynapseError {
        SynapseError::new(code, format!("{context}: {} ({self:?})", self.kind()))
    }
}

// ---------------------------------------------------------------------------------------
// Writer
// ---------------------------------------------------------------------------------------

struct Writer(Vec<u8>);

impl Writer {
    fn u8(&mut self, v: u8) {
        self.0.push(v);
    }
    fn u16(&mut self, v: u16) {
        self.0.extend_from_slice(&v.to_le_bytes());
    }
    fn u32(&mut self, v: u32) {
        self.0.extend_from_slice(&v.to_le_bytes());
    }
    fn u64(&mut self, v: u64) {
        self.0.extend_from_slice(&v.to_le_bytes());
    }
    fn raw(&mut self, b: &[u8]) {
        self.0.extend_from_slice(b);
    }
    fn bool(&mut self, v: bool) {
        self.u8(u8::from(v));
    }
    fn len(&mut self, n: usize, what: &str) -> SynapseResult<()> {
        let n = u32::try_from(n).map_err(|_| {
            SynapseError::new(
                RefusalCode::QuotaPayloadTooLarge,
                format!("{what} exceeds the 32-bit length field"),
            )
        })?;
        self.u32(n);
        Ok(())
    }
    fn bytes(&mut self, b: &[u8], what: &str) -> SynapseResult<()> {
        self.len(b.len(), what)?;
        self.raw(b);
        Ok(())
    }
    fn str(&mut self, s: &str, what: &str) -> SynapseResult<()> {
        self.bytes(s.as_bytes(), what)
    }
    fn repo(&mut self, r: &RepoId) -> SynapseResult<()> {
        // `RepoId` deserializes from JSON without validation; refuse here what the
        // decoder would refuse, so every written record stays readable.
        RepoId::new(r.as_str())?;
        self.str(r.as_str(), "repository id")
    }
}

fn put_attachment(w: &mut Writer, a: &EvidenceAttachment) -> SynapseResult<()> {
    w.str(&a.gate_name, "gate name")?;
    w.bool(a.passed);
    w.raw(&a.artifact_digest);
    w.str(&a.summary, "evidence summary")
}

fn put_attachments(w: &mut Writer, v: &[EvidenceAttachment]) -> SynapseResult<()> {
    w.len(v.len(), "evidence count")?;
    v.iter().try_for_each(|a| put_attachment(w, a))
}

fn put_envelope(w: &mut Writer, e: &ChangesetEnvelope) -> SynapseResult<()> {
    w.u16(e.version);
    w.repo(&e.repo_id)?;
    w.raw(&e.base_git_oid.0);
    w.len(e.parent_changesets.len(), "parent count")?;
    for p in &e.parent_changesets {
        w.raw(&p.0);
    }
    w.str(&e.author_did, "author did")?;
    w.raw(&e.idempotency_key.0);
    w.u64(e.created_at_ms);
    w.str(&e.intent_summary, "intent summary")?;
    w.len(e.mutations.len(), "mutation count")?;
    for m in &e.mutations {
        w.str(&m.path, "path")?;
        match &m.op {
            MutationOp::Upsert {
                mode,
                blob_digest,
                size_bytes,
            } => {
                w.u8(1);
                w.u8(mode.tag_byte());
                w.raw(&blob_digest.0);
                w.u64(*size_bytes);
            }
            MutationOp::Delete => w.u8(2),
        }
    }
    put_attachments(w, &e.evidence_receipts)?;
    w.bytes(&e.signature, "signature")
}

fn put_review(w: &mut Writer, r: &ReviewRecord) -> SynapseResult<()> {
    w.str(&r.reviewer_did, "reviewer did")?;
    w.bool(r.approved);
    w.str(&r.comment, "review comment")?;
    w.u64(r.recorded_at_ms);
    Ok(())
}

fn put_projection(w: &mut Writer, p: &GitHubPullRequestProjection) -> SynapseResult<()> {
    w.repo(&p.repo_id)?;
    w.u64(p.pr_number);
    w.raw(&p.changeset_id.0);
    w.raw(&p.head_git_oid.0);
    w.raw(&p.base_git_oid.0);
    w.str(&p.pr_branch_ref, "branch ref")?;
    w.str(&p.title, "title")?;
    w.str(&p.body_markdown, "body")?;
    w.raw(&p.evidence_summary_digest);
    w.bool(p.github_merged);
    Ok(())
}

fn put_canonical(w: &mut Writer, c: &RadicleCanonicalHead) -> SynapseResult<()> {
    w.repo(&c.repo_id)?;
    w.str(&c.default_branch, "default branch")?;
    w.raw(&c.canonical_git_oid.0);
    match &c.promoted_changeset_id {
        Some(id) => {
            w.u8(1);
            w.raw(&id.0);
        }
        None => w.u8(0),
    }
    w.raw(&c.rad_id_commit_oid.0);
    w.u64(c.threshold as u64);
    w.len(c.verified_delegates.len(), "delegate count")?;
    for d in &c.verified_delegates {
        w.str(d, "delegate")?;
    }
    w.u64(c.verified_at_ms);
    Ok(())
}

fn put_stored(w: &mut Writer, s: &StoredChangeset) -> SynapseResult<()> {
    w.raw(&s.changeset_id.0);
    w.u64(s.committed_seq.0);
    put_envelope(w, &s.envelope)?;
    put_attachments(w, &s.evaluations)?;
    w.len(s.reviews.len(), "review count")?;
    for r in &s.reviews {
        put_review(w, r)?;
    }
    w.u64(s.lease_expires_at_ms);
    Ok(())
}

/// Encode `record` with the binary canonical codec v2.
pub fn encode_record(record: &WalRecord) -> SynapseResult<Vec<u8>> {
    let mut w = Writer(Vec::with_capacity(256));
    w.u8(CODEC_V2);
    w.u8(record.kind_byte());
    match record {
        WalRecord::ChangesetIngest {
            envelope,
            changeset_id,
            new_blobs,
        } => {
            put_envelope(&mut w, envelope)?;
            w.raw(&changeset_id.0);
            w.len(new_blobs.len(), "new blob count")?;
            for b in new_blobs {
                w.raw(&b.0);
            }
        }
        WalRecord::EvaluationAttached {
            changeset_id,
            attachment,
        } => {
            w.raw(&changeset_id.0);
            put_attachment(&mut w, attachment)?;
        }
        WalRecord::ReviewRecorded {
            changeset_id,
            review,
        } => {
            w.raw(&changeset_id.0);
            put_review(&mut w, review)?;
        }
        WalRecord::GitProjected { projection } => put_projection(&mut w, projection)?,
        WalRecord::CanonicalPromoted { canonical } => put_canonical(&mut w, canonical)?,
        WalRecord::LeaseUpdated {
            changeset_id,
            lease_expires_at_ms,
        } => {
            w.raw(&changeset_id.0);
            w.u64(*lease_expires_at_ms);
        }
        WalRecord::RevisionAdmitted {
            envelope,
            chain,
            admitted_at_ms,
            new_blobs,
            seal,
        } => {
            w.bytes(&envelope.encode(), "envelope v2")?;
            put_chain(&mut w, chain)?;
            w.u64(*admitted_at_ms);
            w.len(new_blobs.len(), "new blob count")?;
            for b in new_blobs {
                w.raw(&b.0);
            }
            put_seal(&mut w, seal);
        }
        WalRecord::ObsolescenceRecorded {
            marker,
            chain,
            recorded_at_ms,
            seal,
        } => {
            w.bytes(&marker.encode(), "obsolescence marker")?;
            put_chain(&mut w, chain)?;
            w.u64(*recorded_at_ms);
            put_seal(&mut w, seal);
        }
        WalRecord::RevisionStateMoved {
            state_move: m,
            moved_at_ms,
            seal,
        } => {
            w.repo(&m.repo_id)?;
            w.raw(&m.changeset_id.0);
            w.u8(m.to.tag_byte());
            put_chain(&mut w, &m.chain)?;
            w.u64(*moved_at_ms);
            w.u64(m.signed_at_ms);
            w.bytes(&m.leaf_link.encode(), "leaf link")?;
            w.raw(&m.mover_key);
            w.raw(&m.signature);
            put_seal(&mut w, seal);
        }
        WalRecord::DerivedRevisionAdmitted {
            derived,
            chain,
            admitted_at_ms,
            seal,
        } => {
            w.bytes(&derived.encode(), "derived revision")?;
            put_chain(&mut w, chain)?;
            w.u64(*admitted_at_ms);
            put_seal(&mut w, seal);
        }
        WalRecord::GitBridgeImported {
            repo_id,
            entry,
            seal,
        } => {
            w.repo(repo_id)?;
            put_git_bridge_entry(&mut w, entry)?;
            put_seal(&mut w, seal);
        }
    }
    Ok(w.0)
}

/// The body of a kind 10 record without its seal trailer, `repo_id | entry`: what the
/// record digest (state root and seal chain) covers.
pub(crate) fn git_bridge_body(repo_id: &RepoId, entry: &GitBridgeEntry) -> SynapseResult<Vec<u8>> {
    let mut w = Writer(Vec::with_capacity(256));
    w.repo(repo_id)?;
    put_git_bridge_entry(&mut w, entry)?;
    Ok(w.0)
}

fn put_git_target(w: &mut Writer, t: &GitBridgeTarget) {
    match t {
        GitBridgeTarget::Commit(c) => {
            w.u8(1);
            w.raw(&c.0);
        }
        GitBridgeTarget::Tree(d) => {
            w.u8(2);
            w.raw(&d.0);
        }
        GitBridgeTarget::Blob(b) => {
            w.u8(3);
            w.raw(&b.0);
        }
        GitBridgeTarget::Tag(o) => {
            w.u8(4);
            w.raw(&o.0);
        }
    }
}

/// `entry tag (u8) | body`: 1 objects `u32 n | (git oid [20] | blob [32] | size u64)* | u32 m
/// | (git oid [20] | u32 len | tree node)*`; 2 commit `git oid | tree [32] | u32 n | parent
/// [32]* | u32 len | headers`; 3 tag `git oid | target | u32 len | rest`; 4 refs `u32 n |
/// (name | target)* | option head`. A target is `tag (u8) | [32]` (1 commit, 2 tree, 3 blob)
/// or `4 | git oid [20]` (tag).
fn put_git_bridge_entry(w: &mut Writer, e: &GitBridgeEntry) -> SynapseResult<()> {
    w.u8(e.tag());
    match e {
        GitBridgeEntry::Objects { blobs, trees } => {
            w.len(blobs.len(), "Git blob count")?;
            for b in blobs {
                w.raw(&b.git_oid.0);
                w.raw(&b.blob.0);
                w.u64(b.size_bytes);
            }
            w.len(trees.len(), "Git tree count")?;
            for t in trees {
                w.raw(&t.git_oid.0);
                w.bytes(&t.node, "Git tree node")?;
            }
        }
        GitBridgeEntry::Commit(c) => {
            w.raw(&c.git_oid.0);
            w.raw(&c.tree.0);
            w.len(c.parents.len(), "Git parent count")?;
            for p in &c.parents {
                w.raw(&p.0);
            }
            w.bytes(&c.headers, "Git commit headers")?;
        }
        GitBridgeEntry::Tag(t) => {
            w.raw(&t.git_oid.0);
            put_git_target(w, &t.target);
            w.bytes(&t.rest, "Git tag body")?;
        }
        GitBridgeEntry::Refs(r) => {
            w.len(r.refs.len(), "Git reference count")?;
            for (name, target) in &r.refs {
                w.str(name, "Git reference name")?;
                put_git_target(w, target);
            }
            match &r.head {
                Some(h) => {
                    w.bool(true);
                    w.str(h, "Git HEAD")?;
                }
                None => w.bool(false),
            }
        }
    }
    Ok(())
}

/// The optional seal trailer of a revision record (issue #101): nothing when unsealed,
/// else `1 u8 | server_key [32] | signature [64]`. Bytes after a body that do not open
/// with the seal tag are refused as `TrailingBytes`.
fn put_seal(w: &mut Writer, seal: &Option<RevisionSeal>) {
    if let Some(seal) = seal {
        w.u8(REVISION_SEAL_TAG);
        w.raw(&seal.server_key);
        w.raw(&seal.signature);
    }
}

fn get_seal(r: &mut Reader) -> Decoded<Option<RevisionSeal>> {
    if r.remaining() == 0 {
        return Ok(None);
    }
    // Anything after the body that is not a seal is trailing bytes, as before seals.
    if r.buf[r.pos] != REVISION_SEAL_TAG {
        return Err(CodecRefusal::TrailingBytes {
            at: r.pos,
            count: r.remaining(),
        });
    }
    r.u8()?;
    Ok(Some(RevisionSeal {
        server_key: r.array()?,
        signature: r.array()?,
    }))
}

fn put_chain(w: &mut Writer, chain: &ChainPath) -> SynapseResult<()> {
    let mut buf = Vec::with_capacity(1 + 32 * chain.links().len());
    chain.encode_into(&mut buf);
    w.bytes(&buf, "chain path")
}

// ---------------------------------------------------------------------------------------
// Reader (untrusted input)
// ---------------------------------------------------------------------------------------

type Decoded<T> = Result<T, CodecRefusal>;

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
    cap: u64,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8], cap: u64) -> Self {
        Self { buf, pos: 0, cap }
    }

    fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    fn take(&mut self, n: usize) -> Decoded<&'a [u8]> {
        if n > self.remaining() {
            return Err(CodecRefusal::Truncated {
                at: self.pos,
                need: n - self.remaining(),
            });
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    fn array<const N: usize>(&mut self) -> Decoded<[u8; N]> {
        let mut a = [0u8; N];
        a.copy_from_slice(self.take(N)?);
        Ok(a)
    }

    fn u8(&mut self) -> Decoded<u8> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Decoded<u16> {
        Ok(u16::from_le_bytes(self.array()?))
    }
    fn u32(&mut self) -> Decoded<u32> {
        Ok(u32::from_le_bytes(self.array()?))
    }
    fn u64(&mut self) -> Decoded<u64> {
        Ok(u64::from_le_bytes(self.array()?))
    }

    fn tag(&mut self, field: &'static str, max: u8) -> Decoded<u8> {
        let at = self.pos;
        let t = self.u8()?;
        if t > max {
            return Err(CodecRefusal::UnknownTag { at, field, tag: t });
        }
        Ok(t)
    }

    fn bool(&mut self) -> Decoded<bool> {
        Ok(self.tag("bool", 1)? == 1)
    }

    /// A `u32` length of a byte run: checked against the cap, then the input.
    fn byte_len(&mut self) -> Decoded<usize> {
        let at = self.pos;
        let n = self.u32()?;
        if u64::from(n) > self.cap {
            return Err(CodecRefusal::LengthOverCap {
                at,
                declared: u64::from(n),
                cap: self.cap,
            });
        }
        let n = n as usize;
        if n > self.remaining() {
            return Err(CodecRefusal::Truncated {
                at: self.pos,
                need: n - self.remaining(),
            });
        }
        Ok(n)
    }

    fn bytes(&mut self) -> Decoded<Vec<u8>> {
        let n = self.byte_len()?;
        Ok(self.take(n)?.to_vec())
    }

    fn str_slice(&mut self) -> Decoded<&'a str> {
        let n = self.byte_len()?;
        let at = self.pos;
        std::str::from_utf8(self.take(n)?).map_err(|_| CodecRefusal::InvalidUtf8 { at })
    }

    fn string(&mut self) -> Decoded<String> {
        Ok(self.str_slice()?.to_owned())
    }

    fn repo(&mut self) -> Decoded<RepoId> {
        let at = self.pos;
        let s = self.str_slice()?;
        RepoId::new(s).map_err(|_| CodecRefusal::InvalidRepoId { at })
    }

    /// A `u32` element count. Each element takes at least `min_encoded` input bytes, so
    /// the count is checked against the input before anything is reserved, and the
    /// reservation (`count x size_of::<T>()`) against the cap.
    fn vec<T>(&mut self, min_encoded: usize) -> Decoded<(usize, Vec<T>)> {
        let at = self.pos;
        let n = u64::from(self.u32()?);
        let need = n.saturating_mul(min_encoded as u64);
        let bytes = n.saturating_mul(std::mem::size_of::<T>() as u64);
        if need > self.cap || bytes > self.cap {
            return Err(CodecRefusal::LengthOverCap {
                at,
                declared: n,
                cap: self.cap,
            });
        }
        if need > self.remaining() as u64 {
            return Err(CodecRefusal::Truncated {
                at: self.pos,
                need: (need - self.remaining() as u64) as usize,
            });
        }
        Ok((n as usize, Vec::with_capacity(n as usize)))
    }

    /// A length-prefixed value in a `synapse-core` canonical encoding, decoded by `decode`.
    fn embedded<T>(
        &mut self,
        field: &'static str,
        decode: impl FnOnce(&[u8]) -> SynapseResult<T>,
    ) -> Decoded<T> {
        let at = self.pos;
        let n = self.byte_len()?;
        decode(self.take(n)?).map_err(|e| CodecRefusal::EmbeddedMalformed {
            at,
            field,
            code: e.code,
        })
    }

    fn finish(&self) -> Decoded<()> {
        match self.remaining() {
            0 => Ok(()),
            count => Err(CodecRefusal::TrailingBytes {
                at: self.pos,
                count,
            }),
        }
    }
}

const MIN_STR: usize = 4;
const MIN_ATTACHMENT: usize = MIN_STR + 1 + 32 + MIN_STR;
const MIN_MUTATION: usize = MIN_STR + 1;
const MIN_REVIEW: usize = MIN_STR + 1 + MIN_STR + 8;

fn get_attachment(r: &mut Reader) -> Decoded<EvidenceAttachment> {
    Ok(EvidenceAttachment {
        gate_name: r.string()?,
        passed: r.bool()?,
        artifact_digest: r.array()?,
        summary: r.string()?,
    })
}

fn get_attachments(r: &mut Reader) -> Decoded<Vec<EvidenceAttachment>> {
    let (n, mut v) = r.vec(MIN_ATTACHMENT)?;
    for _ in 0..n {
        v.push(get_attachment(r)?);
    }
    Ok(v)
}

fn get_envelope(r: &mut Reader) -> Decoded<ChangesetEnvelope> {
    let version = r.u16()?;
    let repo_id = r.repo()?;
    let base_git_oid = GitOid(r.array()?);
    let (n, mut parent_changesets) = r.vec(32)?;
    for _ in 0..n {
        parent_changesets.push(ChangesetId(r.array()?));
    }
    let author_did = r.string()?;
    let idempotency_key = IdempotencyKey(r.array()?);
    let created_at_ms = r.u64()?;
    let intent_summary = r.string()?;
    let (n, mut mutations) = r.vec(MIN_MUTATION)?;
    for _ in 0..n {
        let path = r.string()?;
        let op = match r.tag("mutation op", 2)? {
            1 => {
                let at = r.pos;
                let mode = match r.u8()? {
                    1 => FileMode::Regular644,
                    2 => FileMode::Executable755,
                    3 => FileMode::Symlink120000,
                    tag => {
                        return Err(CodecRefusal::UnknownTag {
                            at,
                            field: "file mode",
                            tag,
                        })
                    }
                };
                MutationOp::Upsert {
                    mode,
                    blob_digest: BlobDigest(r.array()?),
                    size_bytes: r.u64()?,
                }
            }
            2 => MutationOp::Delete,
            tag => {
                return Err(CodecRefusal::UnknownTag {
                    at: r.pos - 1,
                    field: "mutation op",
                    tag,
                })
            }
        };
        mutations.push(PathMutation { path, op });
    }
    let evidence_receipts = get_attachments(r)?;
    let signature = r.bytes()?;
    Ok(ChangesetEnvelope {
        version,
        repo_id,
        base_git_oid,
        parent_changesets,
        author_did,
        idempotency_key,
        created_at_ms,
        intent_summary,
        mutations,
        evidence_receipts,
        signature,
    })
}

fn get_review(r: &mut Reader) -> Decoded<ReviewRecord> {
    Ok(ReviewRecord {
        reviewer_did: r.string()?,
        approved: r.bool()?,
        comment: r.string()?,
        recorded_at_ms: r.u64()?,
    })
}

fn get_projection(r: &mut Reader) -> Decoded<GitHubPullRequestProjection> {
    Ok(GitHubPullRequestProjection {
        repo_id: r.repo()?,
        pr_number: r.u64()?,
        changeset_id: ChangesetId(r.array()?),
        head_git_oid: GitOid(r.array()?),
        base_git_oid: GitOid(r.array()?),
        pr_branch_ref: r.string()?,
        title: r.string()?,
        body_markdown: r.string()?,
        evidence_summary_digest: r.array()?,
        github_merged: r.bool()?,
    })
}

fn get_canonical(r: &mut Reader) -> Decoded<RadicleCanonicalHead> {
    let repo_id = r.repo()?;
    let default_branch = r.string()?;
    let canonical_git_oid = GitOid(r.array()?);
    let promoted_changeset_id = match r.tag("option", 1)? {
        1 => Some(ChangesetId(r.array()?)),
        _ => None,
    };
    let rad_id_commit_oid = GitOid(r.array()?);
    let at = r.pos;
    let threshold = usize::try_from(r.u64()?).map_err(|_| CodecRefusal::LengthOverCap {
        at,
        declared: u64::MAX,
        cap: usize::MAX as u64,
    })?;
    let (n, mut verified_delegates) = r.vec(MIN_STR)?;
    for _ in 0..n {
        verified_delegates.push(r.string()?);
    }
    Ok(RadicleCanonicalHead {
        repo_id,
        default_branch,
        canonical_git_oid,
        promoted_changeset_id,
        rad_id_commit_oid,
        threshold,
        verified_delegates,
        verified_at_ms: r.u64()?,
    })
}

fn get_stored(r: &mut Reader) -> Decoded<StoredChangeset> {
    let changeset_id = ChangesetId(r.array()?);
    let committed_seq = WalSeq(r.u64()?);
    let envelope = get_envelope(r)?;
    let evaluations = get_attachments(r)?;
    let (n, mut reviews) = r.vec(MIN_REVIEW)?;
    for _ in 0..n {
        reviews.push(get_review(r)?);
    }
    Ok(StoredChangeset {
        changeset_id,
        committed_seq,
        envelope,
        evaluations,
        reviews,
        lease_expires_at_ms: r.u64()?,
    })
}

fn get_version(r: &mut Reader) -> Decoded<()> {
    match r.u8()? {
        CODEC_V2 => Ok(()),
        found => Err(CodecRefusal::VersionUnsupported { found }),
    }
}

/// Decode a binary v2 record. `cap` bounds every declared length and every reservation.
const MIN_GIT_TARGET: usize = 1 + 20;

fn get_git_target(r: &mut Reader) -> Decoded<GitBridgeTarget> {
    let at = r.pos;
    Ok(match r.u8()? {
        1 => GitBridgeTarget::Commit(ChangesetId(r.array()?)),
        2 => GitBridgeTarget::Tree(TreeDigest(r.array()?)),
        3 => GitBridgeTarget::Blob(BlobDigest(r.array()?)),
        4 => GitBridgeTarget::Tag(GitOid(r.array()?)),
        tag => {
            return Err(CodecRefusal::UnknownTag {
                at,
                field: "Git bridge target",
                tag,
            })
        }
    })
}

fn get_git_bridge_entry(r: &mut Reader) -> Decoded<GitBridgeEntry> {
    let at = r.pos;
    Ok(match r.u8()? {
        1 => {
            let (n, mut blobs) = r.vec(20 + 32 + 8)?;
            for _ in 0..n {
                blobs.push(GitBlobMapping {
                    git_oid: GitOid(r.array()?),
                    blob: BlobDigest(r.array()?),
                    size_bytes: r.u64()?,
                });
            }
            let (m, mut trees) = r.vec(20 + 4 + 4)?;
            for _ in 0..m {
                let git_oid = GitOid(r.array()?);
                let node = r.embedded("Git tree node", |b| {
                    synapse_core::decode_tree_node(b).map(|_| b.to_vec())
                })?;
                trees.push(GitTreeMapping { git_oid, node });
            }
            GitBridgeEntry::Objects { blobs, trees }
        }
        2 => {
            let git_oid = GitOid(r.array()?);
            let tree = TreeDigest(r.array()?);
            let (n, mut parents) = r.vec(32)?;
            for _ in 0..n {
                parents.push(ChangesetId(r.array()?));
            }
            let headers = r.bytes()?;
            GitBridgeEntry::Commit(GitImportedCommit {
                git_oid,
                tree,
                parents,
                headers,
            })
        }
        3 => GitBridgeEntry::Tag(GitImportedTag {
            git_oid: GitOid(r.array()?),
            target: get_git_target(r)?,
            rest: r.bytes()?,
        }),
        4 => {
            let (n, mut refs) = r.vec::<(String, GitBridgeTarget)>(MIN_STR + MIN_GIT_TARGET)?;
            for _ in 0..n {
                let name_at = r.pos;
                let name = r.string()?;
                if refs.last().is_some_and(|(p, _)| *p >= name) {
                    return Err(CodecRefusal::NotCanonical {
                        at: name_at,
                        field: "Git reference names",
                    });
                }
                refs.push((name, get_git_target(r)?));
            }
            let head = if r.bool()? { Some(r.string()?) } else { None };
            GitBridgeEntry::Refs(GitImportedRefs { refs, head })
        }
        tag => {
            return Err(CodecRefusal::UnknownTag {
                at,
                field: "Git bridge entry",
                tag,
            })
        }
    })
}

pub fn decode_record(bytes: &[u8], cap: u64) -> Result<WalRecord, CodecRefusal> {
    let mut r = Reader::new(bytes, cap);
    get_version(&mut r)?;
    let at = r.pos;
    let record = match r.u8()? {
        1 => {
            let envelope = get_envelope(&mut r)?;
            let changeset_id = ChangesetId(r.array()?);
            let (n, mut new_blobs) = r.vec(32)?;
            for _ in 0..n {
                new_blobs.push(BlobDigest(r.array()?));
            }
            WalRecord::ChangesetIngest {
                envelope,
                changeset_id,
                new_blobs,
            }
        }
        2 => WalRecord::EvaluationAttached {
            changeset_id: ChangesetId(r.array()?),
            attachment: get_attachment(&mut r)?,
        },
        3 => WalRecord::ReviewRecorded {
            changeset_id: ChangesetId(r.array()?),
            review: get_review(&mut r)?,
        },
        4 => WalRecord::GitProjected {
            projection: get_projection(&mut r)?,
        },
        5 => WalRecord::CanonicalPromoted {
            canonical: get_canonical(&mut r)?,
        },
        6 => WalRecord::LeaseUpdated {
            changeset_id: ChangesetId(r.array()?),
            lease_expires_at_ms: r.u64()?,
        },
        7 => {
            let envelope = r.embedded("envelope v2", ChangesetEnvelopeV2::decode)?;
            let chain = r.embedded("chain path", ChainPath::decode)?;
            let admitted_at_ms = r.u64()?;
            let (n, mut new_blobs) = r.vec(32)?;
            for _ in 0..n {
                new_blobs.push(BlobDigest(r.array()?));
            }
            WalRecord::RevisionAdmitted {
                envelope,
                chain,
                admitted_at_ms,
                new_blobs,
                seal: get_seal(&mut r)?,
            }
        }
        8 => WalRecord::ObsolescenceRecorded {
            marker: r.embedded("obsolescence marker", ObsolescenceMarker::decode)?,
            chain: r.embedded("chain path", ChainPath::decode)?,
            recorded_at_ms: r.u64()?,
            seal: get_seal(&mut r)?,
        },
        9 => {
            let repo_id = r.repo()?;
            let changeset_id = ChangesetId(r.array()?);
            let at = r.pos;
            let tag = r.u8()?;
            let to = RevisionState::from_tag_byte(tag).ok_or(CodecRefusal::UnknownTag {
                at,
                field: "revision state",
                tag,
            })?;
            let chain = r.embedded("chain path", ChainPath::decode)?;
            let moved_at_ms = r.u64()?;
            WalRecord::RevisionStateMoved {
                state_move: SignedStateMove {
                    repo_id,
                    changeset_id,
                    to,
                    chain,
                    signed_at_ms: r.u64()?,
                    leaf_link: r.embedded("leaf link", CapabilityLink::decode)?,
                    mover_key: r.array()?,
                    signature: r.array()?,
                },
                moved_at_ms,
                seal: get_seal(&mut r)?,
            }
        }
        11 => WalRecord::DerivedRevisionAdmitted {
            derived: r.embedded("derived revision", DerivedRevision::decode)?,
            chain: r.embedded("chain path", ChainPath::decode)?,
            admitted_at_ms: r.u64()?,
            seal: get_seal(&mut r)?,
        },
        10 => {
            let repo_id = r.repo()?;
            let entry = get_git_bridge_entry(&mut r)?;
            WalRecord::GitBridgeImported {
                repo_id,
                entry,
                seal: get_seal(&mut r)?,
            }
        }
        tag => {
            return Err(CodecRefusal::UnknownTag {
                at,
                field: "record kind",
                tag,
            })
        }
    };
    r.finish()?;
    Ok(record)
}

/// Encode one changeset envelope alone: `CODEC_V2 | envelope body`, the same field layout a
/// `ChangesetIngest` record uses. The wire (`synapse-wire`, step G1) carries proposals in it.
pub fn encode_envelope(envelope: &ChangesetEnvelope) -> SynapseResult<Vec<u8>> {
    let mut w = Writer(Vec::with_capacity(256));
    w.u8(CODEC_V2);
    put_envelope(&mut w, envelope)?;
    Ok(w.0)
}

/// Decode exactly one envelope written by [`encode_envelope`]. `cap` bounds every declared
/// length and reservation; trailing bytes and every non-canonical form are refused.
pub fn decode_envelope(bytes: &[u8], cap: u64) -> Result<ChangesetEnvelope, CodecRefusal> {
    let mut r = Reader::new(bytes, cap);
    get_version(&mut r)?;
    let envelope = get_envelope(&mut r)?;
    r.finish()?;
    Ok(envelope)
}

/// Encode `record` with `codec`.
pub fn encode_record_with(record: &WalRecord, codec: RecordCodec) -> SynapseResult<Vec<u8>> {
    match codec {
        RecordCodec::JsonV1 => serde_json::to_vec(record).map_err(|e| {
            SynapseError::new(RefusalCode::IoFailure, format!("serialize WAL record: {e}"))
        }),
        RecordCodec::BinaryV2 => encode_record(record),
    }
}

/// Decode a record payload written with `codec`. A malformed binary record is refused
/// with `WalRecordMalformed`; malformed JSON keeps its v1 code (`WalCrcMismatch`).
pub fn decode_record_with(bytes: &[u8], codec: RecordCodec, cap: u64) -> SynapseResult<WalRecord> {
    match codec {
        RecordCodec::JsonV1 => serde_json::from_slice(bytes).map_err(|e| {
            SynapseError::new(
                RefusalCode::WalCrcMismatch,
                format!("corrupt WAL record JSON: {e}"),
            )
        }),
        RecordCodec::BinaryV2 => decode_record(bytes, cap)
            .map_err(|r| r.into_error(RefusalCode::WalRecordMalformed, "binary WAL record")),
    }
}

// ---------------------------------------------------------------------------------------
// Checkpoints
// ---------------------------------------------------------------------------------------

/// Logical checkpoint state with typed keys (the content of `checkpoint.v1` and
/// `checkpoint.v2`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CheckpointState {
    pub checkpoint_seq: WalSeq,
    pub anchor_frame_sha256: [u8; 32],
    pub changesets: BTreeMap<ChangesetId, StoredChangeset>,
    pub idempotency_index: BTreeMap<(RepoId, IdempotencyKey), (WalSeq, ChangesetId)>,
    pub blob_first_visible_seq: BTreeMap<BlobDigest, WalSeq>,
    pub github_projections: BTreeMap<u64, GitHubPullRequestProjection>,
    pub canonical_heads: BTreeMap<RepoId, RadicleCanonicalHead>,
    /// Revision records (kinds 7 to 11; 10 is the H1 Git bridge) in sequence order (ADR 0003 B1, B4, B5, H1). Written only when
    /// non-empty, so checkpoints of stores without revisions keep their exact bytes.
    pub revision_log: Vec<(WalSeq, WalRecord)>,
}

/// `state_root_digest` of a store that holds nothing (sequence 0, no changesets): the
/// v1 root recorded by a store that never wrote a v1 record.
pub fn empty_state_root() -> [u8; 32] {
    state_root_of(&BTreeMap::new(), &[], WalSeq::ZERO)
}

/// `SynapseStore::state_root_digest` over `changesets` at `snapshot_seq`.
pub fn state_root_of(
    changesets: &BTreeMap<ChangesetId, StoredChangeset>,
    revision_log: &[(WalSeq, WalRecord)],
    snapshot_seq: WalSeq,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN_STATE_ROOT_V1);
    hasher.update(snapshot_seq.0.to_le_bytes());
    for (id, cs) in changesets {
        if cs.committed_seq <= snapshot_seq {
            hasher.update(id.0);
            hasher.update(cs.committed_seq.0.to_le_bytes());
            hasher.update((cs.evaluations.len() as u32).to_le_bytes());
            hasher.update((cs.reviews.len() as u32).to_le_bytes());
        }
    }
    crate::revision::RevisionLedger::hash_into(revision_log, snapshot_seq, &mut hasher);
    hasher.finalize().into()
}

fn corrupt(what: impl std::fmt::Display) -> SynapseError {
    SynapseError::new(
        RefusalCode::CheckpointCorrupt,
        format!("checkpoint: {what}"),
    )
}

fn parse_hex32(s: &str) -> SynapseResult<[u8; 32]> {
    hex::decode(s)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| corrupt(format!("invalid 32-byte hex key {s:?}")))
}

impl CheckpointState {
    /// Typed state from a v1 JSON manifest. Every key must equal the key its value
    /// implies (the store derives them that way), so nothing in the manifest is lost.
    pub fn from_v1_manifest(m: CheckpointManifest) -> SynapseResult<Self> {
        if m.version != CHECKPOINT_VERSION {
            return Err(SynapseError::new(
                RefusalCode::WalVersionUnsupported,
                format!("unsupported checkpoint version {}", m.version),
            ));
        }
        let mut s = Self {
            checkpoint_seq: m.checkpoint_seq,
            anchor_frame_sha256: m.anchor_frame_sha256,
            ..Default::default()
        };
        for (k, v) in m.changesets {
            let id = ChangesetId(parse_hex32(&k)?);
            if v.changeset_id != id || k != id.to_hex() {
                return Err(corrupt(format!(
                    "changeset key {k} does not match its value"
                )));
            }
            s.changesets.insert(id, v);
        }
        for (k, v) in m.idempotency_index {
            let (repo_s, idem_hex) = k
                .split_once("::")
                .ok_or_else(|| corrupt("invalid idempotency key"))?;
            let repo = RepoId::new(repo_s)?;
            let key = IdempotencyKey(parse_hex32(idem_hex)?);
            if format!("{}::{}", repo.as_str(), key.to_hex()) != k {
                return Err(corrupt(format!("idempotency key {k} is not canonical")));
            }
            s.idempotency_index.insert((repo, key), v);
        }
        for (k, v) in m.blob_first_visible_seq {
            let d = BlobDigest(parse_hex32(&k)?);
            if d.to_hex() != k {
                return Err(corrupt(format!("blob key {k} is not canonical")));
            }
            s.blob_first_visible_seq.insert(d, v);
        }
        for (k, v) in m.github_projections {
            if v.pr_number != k {
                return Err(corrupt(format!(
                    "projection key {k} does not match its value"
                )));
            }
            s.github_projections.insert(k, v);
        }
        for (k, v) in m.canonical_heads {
            let repo = RepoId::new(k.clone())?;
            if v.repo_id != repo {
                return Err(corrupt(format!(
                    "canonical head key {k} does not match its value"
                )));
            }
            s.canonical_heads.insert(repo, v);
        }
        Ok(s)
    }

    /// The v1 JSON manifest of this state.
    pub fn to_v1_manifest(&self) -> CheckpointManifest {
        CheckpointManifest {
            version: CHECKPOINT_VERSION,
            checkpoint_seq: self.checkpoint_seq,
            anchor_frame_sha256: self.anchor_frame_sha256,
            changesets: self
                .changesets
                .iter()
                .map(|(k, v)| (k.to_hex(), v.clone()))
                .collect(),
            idempotency_index: self
                .idempotency_index
                .iter()
                .map(|((repo, key), v)| (format!("{}::{}", repo.as_str(), key.to_hex()), *v))
                .collect(),
            blob_first_visible_seq: self
                .blob_first_visible_seq
                .iter()
                .map(|(k, v)| (k.to_hex(), *v))
                .collect(),
            github_projections: self.github_projections.clone(),
            canonical_heads: self
                .canonical_heads
                .iter()
                .map(|(k, v)| (k.as_str().to_string(), v.clone()))
                .collect(),
        }
    }

    /// State root of this state at its checkpoint sequence.
    pub fn state_root(&self) -> [u8; 32] {
        state_root_of(&self.changesets, &self.revision_log, self.checkpoint_seq)
    }

    /// Keys that the encoding derives from values must match them.
    fn check_keys(&self) -> SynapseResult<()> {
        let ok = self.changesets.iter().all(|(k, v)| *k == v.changeset_id)
            && self
                .github_projections
                .iter()
                .all(|(k, v)| *k == v.pr_number)
            && self.canonical_heads.iter().all(|(k, v)| *k == v.repo_id);
        if ok {
            Ok(())
        } else {
            Err(corrupt("a map key does not match its value"))
        }
    }

    pub(crate) fn encode_content(&self) -> SynapseResult<Vec<u8>> {
        self.check_keys()?;
        let mut w = Writer(Vec::with_capacity(4096));
        w.u8(CODEC_V2);
        w.len(self.changesets.len(), "changeset count")?;
        for s in self.changesets.values() {
            put_stored(&mut w, s)?;
        }
        w.len(self.idempotency_index.len(), "idempotency count")?;
        for ((repo, key), (seq, id)) in &self.idempotency_index {
            w.repo(repo)?;
            w.raw(&key.0);
            w.u64(seq.0);
            w.raw(&id.0);
        }
        w.len(self.blob_first_visible_seq.len(), "blob count")?;
        for (d, seq) in &self.blob_first_visible_seq {
            w.raw(&d.0);
            w.u64(seq.0);
        }
        w.len(self.github_projections.len(), "projection count")?;
        for p in self.github_projections.values() {
            put_projection(&mut w, p)?;
        }
        w.len(self.canonical_heads.len(), "canonical head count")?;
        for c in self.canonical_heads.values() {
            put_canonical(&mut w, c)?;
        }
        // Revision section (ADR 0003 B1): present only when there are revision records.
        if !self.revision_log.is_empty() {
            w.len(self.revision_log.len(), "revision record count")?;
            for (seq, record) in &self.revision_log {
                w.u64(seq.0);
                w.bytes(&encode_record(record)?, "revision record")?;
            }
        }
        Ok(w.0)
    }

    pub(crate) fn decode_content(
        bytes: &[u8],
        checkpoint_seq: WalSeq,
        anchor_frame_sha256: [u8; 32],
    ) -> Decoded<Self> {
        let mut r = Reader::new(bytes, bytes.len() as u64);
        get_version(&mut r)?;
        let mut s = Self {
            checkpoint_seq,
            anchor_frame_sha256,
            ..Default::default()
        };
        // Maps are written in strictly increasing key order; anything else would be a
        // second encoding of the same state.
        fn ordered<K: Ord>(prev: &Option<K>, k: &K, at: usize, field: &'static str) -> Decoded<()> {
            match prev {
                Some(p) if p >= k => Err(CodecRefusal::NotCanonical { at, field }),
                _ => Ok(()),
            }
        }
        let (n, _) = r.vec::<u8>(32 + 8)?;
        let mut prev = None;
        for _ in 0..n {
            let at = r.pos;
            let v = get_stored(&mut r)?;
            ordered(&prev, &v.changeset_id, at, "changesets")?;
            prev = Some(v.changeset_id);
            s.changesets.insert(v.changeset_id, v);
        }
        let (n, _) = r.vec::<u8>(MIN_STR + 32 + 8 + 32)?;
        let mut prev = None;
        for _ in 0..n {
            let at = r.pos;
            let k = (r.repo()?, IdempotencyKey(r.array()?));
            let v = (WalSeq(r.u64()?), ChangesetId(r.array()?));
            ordered(&prev, &k, at, "idempotency index")?;
            prev = Some(k.clone());
            s.idempotency_index.insert(k, v);
        }
        let (n, _) = r.vec::<u8>(32 + 8)?;
        let mut prev = None;
        for _ in 0..n {
            let at = r.pos;
            let d = BlobDigest(r.array()?);
            ordered(&prev, &d, at, "blob visibility")?;
            prev = Some(d);
            s.blob_first_visible_seq.insert(d, WalSeq(r.u64()?));
        }
        let (n, _) = r.vec::<u8>(MIN_STR + 8)?;
        let mut prev = None;
        for _ in 0..n {
            let at = r.pos;
            let p = get_projection(&mut r)?;
            ordered(&prev, &p.pr_number, at, "projections")?;
            prev = Some(p.pr_number);
            s.github_projections.insert(p.pr_number, p);
        }
        let (n, _) = r.vec::<u8>(MIN_STR)?;
        let mut prev: Option<RepoId> = None;
        for _ in 0..n {
            let at = r.pos;
            let c = get_canonical(&mut r)?;
            ordered(&prev, &c.repo_id, at, "canonical heads")?;
            prev = Some(c.repo_id.clone());
            s.canonical_heads.insert(c.repo_id.clone(), c);
        }
        if r.remaining() > 0 {
            let at = r.pos;
            let (n, _) = r.vec::<u8>(8 + MIN_STR)?;
            if n == 0 {
                // An empty section is written as no section at all.
                return Err(CodecRefusal::NotCanonical {
                    at,
                    field: "revision records",
                });
            }
            let mut prev = None;
            for _ in 0..n {
                let at = r.pos;
                let seq = WalSeq(r.u64()?);
                if prev.is_some_and(|p| p >= seq) || seq > checkpoint_seq {
                    return Err(CodecRefusal::NotCanonical {
                        at,
                        field: "revision records",
                    });
                }
                prev = Some(seq);
                let tag_at = r.pos + 4 + 1;
                let bytes = r.bytes()?;
                let record = decode_record(&bytes, r.cap)?;
                if !matches!(record.kind_byte(), 7..=11) {
                    return Err(CodecRefusal::UnknownTag {
                        at: tag_at,
                        field: "revision record kind",
                        tag: record.kind_byte(),
                    });
                }
                s.revision_log.push((seq, record));
            }
        }
        r.finish()?;
        Ok(s)
    }
}

/// Chain fields of a binary checkpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CheckpointChain {
    pub checkpoint_seq: WalSeq,
    pub anchor_frame_sha256: [u8; 32],
    /// The last v1 `state_root_digest` of this store (constant along the chain).
    pub v1_state_root: [u8; 32],
    /// Root of the previous checkpoint; the v1 state root for the first v2 checkpoint.
    pub prev_checkpoint_root: [u8; 32],
    /// `state_root_digest` of the state this checkpoint holds.
    pub state_root: [u8; 32],
    /// SHA-256 of the content (domain separated).
    pub content_sha256: [u8; 32],
    /// This checkpoint's root, see [`checkpoint_root`].
    pub checkpoint_root: [u8; 32],
}

/// `SHA-256(DOMAIN_CHECKPOINT_ROOT_V2 || v1_state_root || prev_checkpoint_root ||
/// checkpoint_seq (u64 LE) || anchor_frame_sha256 || state_root || content_sha256)`.
pub fn checkpoint_root(
    v1_state_root: &[u8; 32],
    prev_checkpoint_root: &[u8; 32],
    checkpoint_seq: WalSeq,
    anchor_frame_sha256: &[u8; 32],
    state_root: &[u8; 32],
    content_sha256: &[u8; 32],
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(DOMAIN_CHECKPOINT_ROOT_V2);
    h.update(v1_state_root);
    h.update(prev_checkpoint_root);
    h.update(checkpoint_seq.0.to_le_bytes());
    h.update(anchor_frame_sha256);
    h.update(state_root);
    h.update(content_sha256);
    h.finalize().into()
}

fn content_digest(content: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(DOMAIN_CHECKPOINT_CONTENT_V2);
    h.update(content);
    h.finalize().into()
}

/// Encode `state` as `checkpoint.v2` bytes chained to `prev_checkpoint_root`.
///
/// Layout: `SCK2 | version u16 = 2 | codec u8 = 2 | reserved u8 = 0 | checkpoint_seq u64
/// | anchor_frame_sha256 | v1_state_root | prev_checkpoint_root | state_root |
/// content_sha256 | checkpoint_root | content_len u64 | content`.
pub fn encode_checkpoint_v2(
    state: &CheckpointState,
    v1_state_root: [u8; 32],
    prev_checkpoint_root: [u8; 32],
) -> SynapseResult<(Vec<u8>, CheckpointChain)> {
    let content = state.encode_content()?;
    let state_root = state.state_root();
    let content_sha256 = content_digest(&content);
    let chain = CheckpointChain {
        checkpoint_seq: state.checkpoint_seq,
        anchor_frame_sha256: state.anchor_frame_sha256,
        v1_state_root,
        prev_checkpoint_root,
        state_root,
        content_sha256,
        checkpoint_root: checkpoint_root(
            &v1_state_root,
            &prev_checkpoint_root,
            state.checkpoint_seq,
            &state.anchor_frame_sha256,
            &state_root,
            &content_sha256,
        ),
    };
    let mut w = Writer(Vec::with_capacity(CHECKPOINT_V2_HEADER_LEN + content.len()));
    w.raw(&CHECKPOINT_V2_MAGIC);
    w.u16(CHECKPOINT_V2_VERSION);
    w.u8(CODEC_V2);
    w.u8(0);
    w.u64(chain.checkpoint_seq.0);
    w.raw(&chain.anchor_frame_sha256);
    w.raw(&chain.v1_state_root);
    w.raw(&chain.prev_checkpoint_root);
    w.raw(&chain.state_root);
    w.raw(&chain.content_sha256);
    w.raw(&chain.checkpoint_root);
    w.u64(content.len() as u64);
    debug_assert_eq!(w.0.len(), CHECKPOINT_V2_HEADER_LEN);
    w.raw(&content);
    Ok((w.0, chain))
}

/// Decode and verify `checkpoint.v2` bytes: header, content length, content digest,
/// checkpoint root, canonical content, and the state root recomputed from the decoded
/// state. Every failure is `CheckpointCorrupt`.
pub fn decode_checkpoint_v2(bytes: &[u8]) -> SynapseResult<(CheckpointState, CheckpointChain)> {
    let mut r = Reader::new(bytes, bytes.len() as u64);
    let header =
        |e: CodecRefusal| e.into_error(RefusalCode::CheckpointCorrupt, "checkpoint.v2 header");
    if r.array::<4>().map_err(header)? != CHECKPOINT_V2_MAGIC {
        return Err(corrupt("bad checkpoint.v2 magic"));
    }
    let version = r.u16().map_err(header)?;
    // A later checkpoint format gets its own file name, so a `checkpoint.v2` with another
    // version is damaged.
    if version != CHECKPOINT_V2_VERSION {
        return Err(corrupt(format!("checkpoint.v2 states version {version}")));
    }
    let codec = r.u8().map_err(header)?;
    let reserved = r.u8().map_err(header)?;
    if codec != CODEC_V2 || reserved != 0 {
        return Err(corrupt(format!(
            "checkpoint.v2 codec {codec} reserved {reserved}"
        )));
    }
    let checkpoint_seq = WalSeq(r.u64().map_err(header)?);
    let anchor_frame_sha256 = r.array().map_err(header)?;
    let v1_state_root = r.array().map_err(header)?;
    let prev_checkpoint_root = r.array().map_err(header)?;
    let state_root = r.array().map_err(header)?;
    let content_sha256 = r.array().map_err(header)?;
    let stored_root = r.array().map_err(header)?;
    let content_len = r.u64().map_err(header)?;
    if content_len != r.remaining() as u64 {
        return Err(corrupt(format!(
            "checkpoint.v2 declares {content_len} content bytes, holds {}",
            r.remaining()
        )));
    }
    let content = &bytes[r.pos..];
    if content_digest(content) != content_sha256 {
        return Err(corrupt("checkpoint.v2 content digest mismatch"));
    }
    let root = checkpoint_root(
        &v1_state_root,
        &prev_checkpoint_root,
        checkpoint_seq,
        &anchor_frame_sha256,
        &state_root,
        &content_sha256,
    );
    if root != stored_root {
        return Err(corrupt("checkpoint.v2 root mismatch"));
    }
    let state = CheckpointState::decode_content(content, checkpoint_seq, anchor_frame_sha256)
        .map_err(|e| e.into_error(RefusalCode::CheckpointCorrupt, "checkpoint.v2 content"))?;
    if state.state_root() != state_root {
        return Err(corrupt(
            "checkpoint.v2 state root does not match its content",
        ));
    }
    Ok((
        state,
        CheckpointChain {
            checkpoint_seq,
            anchor_frame_sha256,
            v1_state_root,
            prev_checkpoint_root,
            state_root,
            content_sha256,
            checkpoint_root: root,
        },
    ))
}

/// Bytes written to `checkpoint.v1` once `checkpoint.v2` exists: valid v1 JSON with
/// `version: 2` and nothing else, so a binary that only knows v1 refuses the store
/// (`WalVersionUnsupported`) instead of opening it as empty.
pub fn v1_tombstone_bytes() -> Vec<u8> {
    let tombstone = CheckpointManifest {
        version: CHECKPOINT_V2_VERSION,
        ..Default::default()
    };
    serde_json::to_vec(&tombstone).expect("a default manifest serializes")
}
