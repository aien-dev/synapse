//! Core domain identities, canonical changeset envelope v1, `did:key` Ed25519 codec,
//! and deterministic refusal taxonomy for Synapse (ADR 0001).

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use std::fmt;

/// Current canonical changeset envelope schema version.
pub const SYNAPSE_ENVELOPE_VERSION: u16 = 1;

/// Domain tag for `BlobDigest` SHA-256 computation.
pub const DOMAIN_BLOB_V1: &[u8] = b"SYNAPSE_BLOB_V1\0";

/// Domain tag for `ChangesetEnvelope` Ed25519 signing.
pub const DOMAIN_CHANGESET_SIGN_V1: &[u8] = b"SYNAPSE_CHANGESET_SIGN_V1\0";

/// Domain tag for `ChangesetId` SHA-256 computation.
pub const DOMAIN_CHANGESET_ID_V1: &[u8] = b"SYNAPSE_CHANGESET_V1\0";

/// Deterministic refusal codes across all Synapse boundaries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RefusalCode {
    // Storage and integrity refusals
    BlobDigestMismatch,
    BlobImmutableConflict,
    BlobNotFound,
    WalMagicInvalid,
    WalVersionUnsupported,
    WalFlagsNonZero,
    WalCrcMismatch,
    WalChainMismatch,
    WalSequenceGap,
    WalTornFrame,
    /// A WAL record payload passed its checksums but does not decode (binary codec v2).
    WalRecordMalformed,
    CheckpointCorrupt,
    IoFailure,

    // Capacity and backpressure refusals
    BackpressureOverCapacity,
    QuotaPayloadTooLarge,
    QuotaTooManyPaths,
    QuotaRateLimitExceeded,
    PaginationLimitExceeded,

    // Schema, path, and consistency refusals
    EnvelopeVersionUnsupported,
    RepoIdInvalid,
    PathInvalid,
    PathDuplicate,
    MutationsUnsorted,
    BaseTreeNotFound,
    ParentChangesetNotFound,
    ChangesetNotFound,
    VisibilitySeqAhead,
    IdempotencyKeyConflict,
    CursorInvalid,

    // Authentication and capability refusals
    DidKeyInvalid,
    AuthSignatureInvalid,
    AuthGrantSignatureInvalid,
    AuthGrantExpired,
    AuthCapabilityDenied,
    AuthCrossRepoDenied,
    AuthReplayDetected,
    AuthSelfReviewRefused,
    AuditChainCorrupt,

    // Git and Radicle canonicality refusals
    GitObjectCorrupt,
    GitRefNonFastForward,
    RadicleIdentityInvalid,
    RadicleSignatureInvalid,
    RadicleQuorumInsufficient,
    StaleBaseHead,
    SplitBrainDivergence,
}

/// Structured error pairing a deterministic `RefusalCode` with diagnostic context.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SynapseError {
    pub code: RefusalCode,
    pub message: String,
}

impl SynapseError {
    pub fn new(code: RefusalCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

impl fmt::Display for SynapseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}: {}", self.code, self.message)
    }
}

impl std::error::Error for SynapseError {}

/// Result alias for Synapse operations.
pub type SynapseResult<T> = Result<T, SynapseError>;

/// Validated repository identifier (e.g. `"aien-spark/aien-sovereign-core"`).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct RepoId(String);

impl RepoId {
    pub fn new(raw: impl Into<String>) -> SynapseResult<Self> {
        let s = raw.into();
        if s.is_empty() || s.len() > 128 {
            return Err(SynapseError::new(
                RefusalCode::RepoIdInvalid,
                "repository id must be 1..=128 ASCII characters",
            ));
        }
        if !s
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'/'))
            || s.starts_with('/')
            || s.ends_with('/')
            || s.contains("//")
            || s.contains("..")
        {
            return Err(SynapseError::new(
                RefusalCode::RepoIdInvalid,
                format!("invalid repository id: {s}"),
            ));
        }
        Ok(Self(s))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for RepoId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Monotonic 64-bit sequence number in the single-writer WAL.
/// Defines local ingest and replay order; never confers canonical branch authority.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Serialize, Deserialize,
)]
pub struct WalSeq(pub u64);

impl WalSeq {
    pub const ZERO: Self = Self(0);

    pub fn next(self) -> Self {
        Self(self.0.saturating_add(1))
    }
}

impl fmt::Display for WalSeq {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "wal:{}", self.0)
    }
}

/// 32-byte domain-separated SHA-256 digest of a canonical `ChangesetEnvelope`.
/// Distinct from `GitOid`, `BlobDigest`, `WorldId`, and `SemanticId`.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ChangesetId(pub [u8; 32]);

impl ChangesetId {
    pub fn to_hex(self) -> String {
        hex::encode(self.0)
    }

    pub fn from_hex(s: &str) -> SynapseResult<Self> {
        let bytes = hex::decode(s).map_err(|_| {
            SynapseError::new(
                RefusalCode::ChangesetNotFound,
                "invalid hex for ChangesetId",
            )
        })?;
        let arr: [u8; 32] = bytes.try_into().map_err(|_| {
            SynapseError::new(
                RefusalCode::ChangesetNotFound,
                "ChangesetId must be 32 bytes (64 hex chars)",
            )
        })?;
        Ok(Self(arr))
    }
}

impl fmt::Debug for ChangesetId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ChangesetId({})", self.to_hex())
    }
}

impl fmt::Display for ChangesetId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

/// 32-byte domain-separated SHA-256 digest of immutable blob content stored in Synapse.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct BlobDigest(pub [u8; 32]);

impl BlobDigest {
    pub fn compute(data: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(DOMAIN_BLOB_V1);
        hasher.update((data.len() as u64).to_le_bytes());
        hasher.update(data);
        Self(hasher.finalize().into())
    }

    pub fn to_hex(self) -> String {
        hex::encode(self.0)
    }

    pub fn from_hex(s: &str) -> SynapseResult<Self> {
        let bytes = hex::decode(s).map_err(|_| {
            SynapseError::new(
                RefusalCode::BlobDigestMismatch,
                "invalid hex for BlobDigest",
            )
        })?;
        let arr: [u8; 32] = bytes.try_into().map_err(|_| {
            SynapseError::new(
                RefusalCode::BlobDigestMismatch,
                "BlobDigest must be 32 bytes (64 hex chars)",
            )
        })?;
        Ok(Self(arr))
    }
}

impl fmt::Debug for BlobDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BlobDigest({})", self.to_hex())
    }
}

impl fmt::Display for BlobDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

/// 20-byte standard Git SHA-1 object identifier (`blob`, `tree`, or `commit`).
/// Distinct from `ChangesetId` and `BlobDigest`.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct GitOid(pub [u8; 20]);

impl GitOid {
    pub const ZERO: Self = Self([0u8; 20]);

    pub fn compute_git_object(kind: &str, payload: &[u8]) -> Self {
        let mut hasher = Sha1::new();
        let header = format!("{kind} {}\0", payload.len());
        hasher.update(header.as_bytes());
        hasher.update(payload);
        Self(hasher.finalize().into())
    }

    pub fn compute_blob(payload: &[u8]) -> Self {
        Self::compute_git_object("blob", payload)
    }

    pub fn to_hex(self) -> String {
        hex::encode(self.0)
    }

    pub fn from_hex(s: &str) -> SynapseResult<Self> {
        let bytes = hex::decode(s).map_err(|_| {
            SynapseError::new(RefusalCode::GitObjectCorrupt, "invalid hex for GitOid")
        })?;
        let arr: [u8; 20] = bytes.try_into().map_err(|_| {
            SynapseError::new(
                RefusalCode::GitObjectCorrupt,
                "GitOid must be 20 bytes (40 hex chars)",
            )
        })?;
        Ok(Self(arr))
    }
}

impl fmt::Debug for GitOid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "GitOid({})", self.to_hex())
    }
}

impl fmt::Display for GitOid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

/// 32-byte client-supplied idempotency key for deduplicating changeset submissions.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct IdempotencyKey(pub [u8; 32]);

impl IdempotencyKey {
    pub fn from_label(label: &str) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(b"SYNAPSE_IDEMPOTENCY_V1\0");
        hasher.update(label.as_bytes());
        Self(hasher.finalize().into())
    }

    pub fn to_hex(self) -> String {
        hex::encode(self.0)
    }
}

impl fmt::Debug for IdempotencyKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "IdempotencyKey({})", self.to_hex())
    }
}

/// Human-facing GitHub Pull Request projection record.
/// Merging a GitHub PR never by itself confers a `RadicleCanonicalHead`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GitHubPullRequestProjection {
    pub repo_id: RepoId,
    pub pr_number: u64,
    pub changeset_id: ChangesetId,
    pub head_git_oid: GitOid,
    pub base_git_oid: GitOid,
    pub pr_branch_ref: String,
    pub title: String,
    pub body_markdown: String,
    pub evidence_summary_digest: [u8; 32],
    pub github_merged: bool,
}

/// Cryptographically verified Radicle canonical head receipt.
/// Produced only after verifying `refs/rad/id` and at least `threshold` delegate
/// Ed25519 signatures over `refs/namespaces/<nid>/refs/rad/sigrefs`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RadicleCanonicalHead {
    pub repo_id: RepoId,
    pub default_branch: String,
    pub canonical_git_oid: GitOid,
    pub promoted_changeset_id: Option<ChangesetId>,
    pub rad_id_commit_oid: GitOid,
    pub threshold: usize,
    pub verified_delegates: Vec<String>,
    pub verified_at_ms: u64,
}

/// Supported file modes in a repository tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum FileMode {
    Regular644,
    Executable755,
    Symlink120000,
}

impl FileMode {
    pub fn git_octal_str(self) -> &'static str {
        match self {
            Self::Regular644 => "100644",
            Self::Executable755 => "100755",
            Self::Symlink120000 => "120000",
        }
    }

    pub fn tag_byte(self) -> u8 {
        match self {
            Self::Regular644 => 1,
            Self::Executable755 => 2,
            Self::Symlink120000 => 3,
        }
    }
}

/// Atomic mutation operation on a single normalized repository path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MutationOp {
    Upsert {
        mode: FileMode,
        blob_digest: BlobDigest,
        size_bytes: u64,
    },
    Delete,
}

/// A path-level mutation within a `ChangesetEnvelope`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PathMutation {
    pub path: String,
    pub op: MutationOp,
}

/// Bounded machine evidence receipt attached to a changeset (full logs stay in Synapse).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceAttachment {
    pub gate_name: String,
    pub passed: bool,
    pub artifact_digest: [u8; 32],
    pub summary: String,
}

/// Signed, immutable changeset proposal envelope (`SYNAPSE_ENVELOPE_VERSION = 1`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChangesetEnvelope {
    pub version: u16,
    pub repo_id: RepoId,
    pub base_git_oid: GitOid,
    pub parent_changesets: Vec<ChangesetId>,
    pub author_did: String,
    pub idempotency_key: IdempotencyKey,
    pub created_at_ms: u64,
    pub intent_summary: String,
    pub mutations: Vec<PathMutation>,
    pub evidence_receipts: Vec<EvidenceAttachment>,
    pub signature: Vec<u8>,
}

impl ChangesetEnvelope {
    /// Validate envelope version, path normalization, sort order, and Ed25519 signature.
    pub fn validate(&self) -> SynapseResult<ChangesetId> {
        if self.version != SYNAPSE_ENVELOPE_VERSION {
            return Err(SynapseError::new(
                RefusalCode::EnvelopeVersionUnsupported,
                format!("unsupported envelope version {}", self.version),
            ));
        }
        if self.intent_summary.is_empty() || self.intent_summary.len() > 4096 {
            return Err(SynapseError::new(
                RefusalCode::QuotaPayloadTooLarge,
                "intent_summary must be 1..=4096 bytes",
            ));
        }

        // Verify parent_changesets are sorted and deduplicated
        for pair in self.parent_changesets.windows(2) {
            if pair[0] >= pair[1] {
                return Err(SynapseError::new(
                    RefusalCode::MutationsUnsorted,
                    "parent_changesets must be strictly sorted and unique",
                ));
            }
        }

        // Verify mutations are non-empty, valid repo-relative paths, strictly sorted, and unique
        if self.mutations.is_empty() {
            return Err(SynapseError::new(
                RefusalCode::PathInvalid,
                "changeset must contain at least one path mutation",
            ));
        }
        let mut prev_path: Option<&str> = None;
        for m in &self.mutations {
            validate_repo_relative_path(&m.path)?;
            if let Some(prev) = prev_path {
                if prev == m.path {
                    return Err(SynapseError::new(
                        RefusalCode::PathDuplicate,
                        format!("duplicate path in changeset: {}", m.path),
                    ));
                }
                if prev > m.path.as_str() {
                    return Err(SynapseError::new(
                        RefusalCode::MutationsUnsorted,
                        format!("unsorted path in changeset: {} after {}", m.path, prev),
                    ));
                }
            }
            prev_path = Some(&m.path);
        }

        // Verify author_did and Ed25519 signature
        let pubkey_bytes = decode_did_key_ed25519(&self.author_did)?;
        let verifying_key = VerifyingKey::from_bytes(&pubkey_bytes).map_err(|_| {
            SynapseError::new(RefusalCode::DidKeyInvalid, "invalid Ed25519 public key")
        })?;
        let sig_arr: [u8; 64] = self.signature.as_slice().try_into().map_err(|_| {
            SynapseError::new(
                RefusalCode::AuthSignatureInvalid,
                "signature must be 64 bytes",
            )
        })?;
        let sig = Signature::from_bytes(&sig_arr);
        let signable = self.canonical_signable_bytes();
        verifying_key.verify(&signable, &sig).map_err(|_| {
            SynapseError::new(
                RefusalCode::AuthSignatureInvalid,
                "Ed25519 signature verification failed for changeset envelope",
            )
        })?;

        Ok(self.compute_id())
    }

    /// Sign the envelope using an Ed25519 `SigningKey`, setting `author_did` and `signature`.
    pub fn sign(&mut self, signing_key: &SigningKey) {
        self.author_did = encode_did_key_ed25519(&signing_key.verifying_key().to_bytes());
        let signable = self.canonical_signable_bytes();
        let sig = signing_key.sign(&signable);
        self.signature = sig.to_bytes().to_vec();
    }

    /// Deterministically encode all unsigned fields with domain separation for Ed25519 signing.
    pub fn canonical_signable_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(512);
        buf.extend_from_slice(DOMAIN_CHANGESET_SIGN_V1);
        buf.extend_from_slice(&self.version.to_le_bytes());
        put_str(&mut buf, self.repo_id.as_str());
        buf.extend_from_slice(&self.base_git_oid.0);
        buf.extend_from_slice(&(self.parent_changesets.len() as u32).to_le_bytes());
        for parent in &self.parent_changesets {
            buf.extend_from_slice(&parent.0);
        }
        put_str(&mut buf, &self.author_did);
        buf.extend_from_slice(&self.idempotency_key.0);
        buf.extend_from_slice(&self.created_at_ms.to_le_bytes());
        put_str(&mut buf, &self.intent_summary);
        buf.extend_from_slice(&(self.mutations.len() as u32).to_le_bytes());
        for m in &self.mutations {
            put_str(&mut buf, &m.path);
            match &m.op {
                MutationOp::Upsert {
                    mode,
                    blob_digest,
                    size_bytes,
                } => {
                    buf.push(1);
                    buf.push(mode.tag_byte());
                    buf.extend_from_slice(&blob_digest.0);
                    buf.extend_from_slice(&size_bytes.to_le_bytes());
                }
                MutationOp::Delete => {
                    buf.push(2);
                }
            }
        }
        buf.extend_from_slice(&(self.evidence_receipts.len() as u32).to_le_bytes());
        for ev in &self.evidence_receipts {
            put_str(&mut buf, &ev.gate_name);
            buf.push(u8::from(ev.passed));
            buf.extend_from_slice(&ev.artifact_digest);
            put_str(&mut buf, &ev.summary);
        }
        buf
    }

    /// Compute the domain-separated `ChangesetId` over the canonical signable bytes and signature.
    pub fn compute_id(&self) -> ChangesetId {
        let mut hasher = Sha256::new();
        hasher.update(DOMAIN_CHANGESET_ID_V1);
        let signable = self.canonical_signable_bytes();
        hasher.update((signable.len() as u64).to_le_bytes());
        hasher.update(&signable);
        hasher.update((self.signature.len() as u64).to_le_bytes());
        hasher.update(&self.signature);
        ChangesetId(hasher.finalize().into())
    }
}

fn put_str(buf: &mut Vec<u8>, s: &str) {
    buf.extend_from_slice(&(s.len() as u32).to_le_bytes());
    buf.extend_from_slice(s.as_bytes());
}

/// Validate that a path is a clean, normalized repository-relative POSIX path.
/// Refuses leading/trailing `/`, empty segments, `.` or `..`, backslashes, NULs, and `.git`.
pub fn validate_repo_relative_path(path: &str) -> SynapseResult<()> {
    if path.is_empty() || path.len() > 2048 {
        return Err(SynapseError::new(
            RefusalCode::PathInvalid,
            "path must be 1..=2048 bytes",
        ));
    }
    if path.starts_with('/') || path.ends_with('/') || path.contains('\\') || path.contains('\0') {
        return Err(SynapseError::new(
            RefusalCode::PathInvalid,
            format!("path contains forbidden slash or control characters: {path}"),
        ));
    }
    for segment in path.split('/') {
        if segment.is_empty() || segment == "." || segment == ".." || segment == ".git" {
            return Err(SynapseError::new(
                RefusalCode::PathInvalid,
                format!("path contains forbidden segment '{segment}': {path}"),
            ));
        }
    }
    Ok(())
}

const BASE58_ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// Encode raw bytes into Base58btc (Bitcoin alphabet used by Multibase `z` in Radicle).
pub fn base58btc_encode(input: &[u8]) -> String {
    let mut zeros = 0;
    while zeros < input.len() && input[zeros] == 0 {
        zeros += 1;
    }
    let mut digits = Vec::with_capacity(input.len() * 138 / 100 + 1);
    for &byte in &input[zeros..] {
        let mut carry = u32::from(byte);
        for d in &mut digits {
            carry += u32::from(*d) << 8;
            *d = (carry % 58) as u8;
            carry /= 58;
        }
        while carry > 0 {
            digits.push((carry % 58) as u8);
            carry /= 58;
        }
    }
    let mut out = String::with_capacity(zeros + digits.len());
    for _ in 0..zeros {
        out.push('1');
    }
    for &d in digits.iter().rev() {
        out.push(char::from(BASE58_ALPHABET[d as usize]));
    }
    out
}

/// Decode Base58btc string into raw bytes.
pub fn base58btc_decode(input: &str) -> SynapseResult<Vec<u8>> {
    let bytes = input.as_bytes();
    let mut zeros = 0;
    while zeros < bytes.len() && bytes[zeros] == b'1' {
        zeros += 1;
    }
    let mut b256 = Vec::with_capacity(bytes.len() * 733 / 1000 + 1);
    for &ch in &bytes[zeros..] {
        let val = BASE58_ALPHABET
            .iter()
            .position(|&c| c == ch)
            .ok_or_else(|| {
                SynapseError::new(RefusalCode::DidKeyInvalid, "invalid base58btc char")
            })? as u32;
        let mut carry = val;
        for b in &mut b256 {
            carry += u32::from(*b) * 58;
            *b = (carry & 0xff) as u8;
            carry >>= 8;
        }
        while carry > 0 {
            b256.push((carry & 0xff) as u8);
            carry >>= 8;
        }
    }
    let mut out = vec![0u8; zeros];
    out.extend(b256.into_iter().rev());
    Ok(out)
}

/// Encode a 32-byte Ed25519 public key as a Radicle-compatible `did:key:z6Mk...` string.
pub fn encode_did_key_ed25519(pubkey: &[u8; 32]) -> String {
    let mut prefixed = [0u8; 34];
    prefixed[0] = 0xed;
    prefixed[1] = 0x01;
    prefixed[2..].copy_from_slice(pubkey);
    format!("did:key:z{}", base58btc_encode(&prefixed))
}

/// Decode a `did:key:z6Mk...` (or `z6Mk...` Radicle NID) into a 32-byte Ed25519 public key.
pub fn decode_did_key_ed25519(did: &str) -> SynapseResult<[u8; 32]> {
    let multibase = did.strip_prefix("did:key:").unwrap_or(did);
    let b58 = multibase.strip_prefix('z').ok_or_else(|| {
        SynapseError::new(
            RefusalCode::DidKeyInvalid,
            "did:key must use multibase 'z' (base58btc)",
        )
    })?;
    let decoded = base58btc_decode(b58)?;
    if decoded.len() != 34 || decoded[0] != 0xed || decoded[1] != 0x01 {
        return Err(SynapseError::new(
            RefusalCode::DidKeyInvalid,
            "did:key must have Ed25519 multicodec prefix 0xed01 and 32-byte key",
        ));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&decoded[2..34]);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn test_radicle_did_key_roundtrip_and_real_spark_did() {
        // Real Radicle DID from `rad self` on spark-b87b:
        let real_did = "did:key:z6MkfZDue1TbaNFi3ZzcD9uiTeduPLC52ucdFVuLKZwexxhK";
        let pubkey = decode_did_key_ed25519(real_did).expect("decode real Radicle DID");
        let reencoded = encode_did_key_ed25519(&pubkey);
        assert_eq!(reencoded, real_did);

        // Also accept bare Radicle NID without `did:key:` prefix
        let nid = "z6MkfZDue1TbaNFi3ZzcD9uiTeduPLC52ucdFVuLKZwexxhK";
        assert_eq!(decode_did_key_ed25519(nid).unwrap(), pubkey);
    }

    #[test]
    fn test_distinct_identities_and_domain_separation() {
        let payload = b"fn main() {}\n";
        let blob_digest = BlobDigest::compute(payload);
        let git_oid = GitOid::compute_blob(payload);
        assert_ne!(&blob_digest.0[..20], &git_oid.0[..]);

        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let mut env = ChangesetEnvelope {
            version: SYNAPSE_ENVELOPE_VERSION,
            repo_id: RepoId::new("aien-spark/synapse").unwrap(),
            base_git_oid: git_oid,
            parent_changesets: vec![],
            author_did: String::new(),
            idempotency_key: IdempotencyKey::from_label("req-001"),
            created_at_ms: 1_789_800_000_000,
            intent_summary: "Add main entrypoint".to_string(),
            mutations: vec![PathMutation {
                path: "src/main.rs".to_string(),
                op: MutationOp::Upsert {
                    mode: FileMode::Regular644,
                    blob_digest,
                    size_bytes: payload.len() as u64,
                },
            }],
            evidence_receipts: vec![EvidenceAttachment {
                gate_name: "cargo-test".to_string(),
                passed: true,
                artifact_digest: [0x11; 32],
                summary: "12 passed, 0 failed".to_string(),
            }],
            signature: vec![],
        };
        env.sign(&signing_key);

        let cs_id = env.validate().expect("valid signed envelope");
        assert_ne!(cs_id.0, blob_digest.0);

        // Tampering with intent_summary must fail signature verification
        let mut tampered = env.clone();
        tampered.intent_summary = "Tampered summary".to_string();
        let err = tampered.validate().unwrap_err();
        assert_eq!(err.code, RefusalCode::AuthSignatureInvalid);
    }

    #[test]
    fn test_path_validation_refuses_traversal_and_git_dir() {
        assert!(validate_repo_relative_path("crates/synapse-core/src/lib.rs").is_ok());
        for bad in [
            "",
            "/etc/passwd",
            "src/../secrets",
            "./src/lib.rs",
            ".git/config",
            "sub/.git/hooks/pre-commit",
            "trailing/",
            "back\\slash.rs",
        ] {
            let err = validate_repo_relative_path(bad).unwrap_err();
            assert_eq!(err.code, RefusalCode::PathInvalid, "path {bad} must fail");
        }
    }

    #[test]
    fn test_unslop_zero_em_or_en_dashes_across_workspace() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap();
        let mut checked = 0usize;
        check_dir_unslop(root, &mut checked);
        assert!(checked >= 5, "expected to check workspace files");
    }

    fn check_dir_unslop(dir: &Path, checked: &mut usize) {
        let entries = std::fs::read_dir(dir).expect("read_dir");
        for entry in entries {
            let entry = entry.expect("entry");
            let path = entry.path();
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if name_str == ".git" || name_str == "target" {
                continue;
            }
            if path.is_dir() {
                check_dir_unslop(&path, checked);
            } else if matches!(
                path.extension().and_then(|e| e.to_str()),
                Some("rs" | "md" | "toml" | "json" | "sh")
            ) && name_str != "Cargo.lock"
            {
                let content = std::fs::read_to_string(&path).expect("read text file");
                assert!(
                    !content.contains('\u{2014}'),
                    "em dash found in {}",
                    path.display()
                );
                assert!(
                    !content.contains('\u{2013}'),
                    "en dash found in {}",
                    path.display()
                );
                *checked += 1;
            }
        }
    }
}
