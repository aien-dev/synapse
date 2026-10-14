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
        }
    }

    /// The refusal as a `SynapseError` with `code`.
    pub fn into_error(self, code: RefusalCode, context: &str) -> SynapseError {
        SynapseError::new(code, format!("{context}: {} ({self:?})", self.kind()))
    }
}

/// Encode `record` with the binary canonical codec v2.
pub fn encode_record(_record: &WalRecord) -> SynapseResult<Vec<u8>> {
    Ok(Vec::new())
}

/// Decode a binary v2 record. `cap` bounds every length and allocation.
pub fn decode_record(_bytes: &[u8], _cap: u64) -> Result<WalRecord, CodecRefusal> {
    Err(CodecRefusal::VersionUnsupported { found: 0 })
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

/// Decode a record payload written with `codec`.
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
}

/// `state_root_digest` of a store that holds nothing (sequence 0, no changesets): the
/// v1 root recorded by a store that never wrote a v1 record.
pub fn empty_state_root() -> [u8; 32] {
    [0u8; 32]
}

/// `SynapseStore::state_root_digest` over `changesets` at `snapshot_seq`.
pub fn state_root_of(
    _changesets: &BTreeMap<ChangesetId, StoredChangeset>,
    _snapshot_seq: WalSeq,
) -> [u8; 32] {
    [0u8; 32]
}

impl CheckpointState {
    /// Typed state from a v1 JSON manifest (keys must match their values).
    pub fn from_v1_manifest(_m: CheckpointManifest) -> SynapseResult<Self> {
        Err(SynapseError::new(
            RefusalCode::CheckpointCorrupt,
            "not implemented",
        ))
    }

    /// The v1 JSON manifest of this state.
    pub fn to_v1_manifest(&self) -> CheckpointManifest {
        CheckpointManifest::default()
    }

    /// State root of this state at its checkpoint sequence.
    pub fn state_root(&self) -> [u8; 32] {
        state_root_of(&self.changesets, self.checkpoint_seq)
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
    _v1_state_root: &[u8; 32],
    _prev_checkpoint_root: &[u8; 32],
    _checkpoint_seq: WalSeq,
    _anchor_frame_sha256: &[u8; 32],
    _state_root: &[u8; 32],
    _content_sha256: &[u8; 32],
) -> [u8; 32] {
    [0u8; 32]
}

/// Encode `state` as `checkpoint.v2` bytes chained to `prev_checkpoint_root`.
pub fn encode_checkpoint_v2(
    _state: &CheckpointState,
    _v1_state_root: [u8; 32],
    _prev_checkpoint_root: [u8; 32],
) -> SynapseResult<(Vec<u8>, CheckpointChain)> {
    Err(SynapseError::new(
        RefusalCode::CheckpointCorrupt,
        "not implemented",
    ))
}

/// Decode and verify `checkpoint.v2` bytes (content digest, root, and state root).
pub fn decode_checkpoint_v2(_bytes: &[u8]) -> SynapseResult<(CheckpointState, CheckpointChain)> {
    Err(SynapseError::new(
        RefusalCode::CheckpointCorrupt,
        "not implemented",
    ))
}

/// Bytes written to `checkpoint.v1` once `checkpoint.v2` exists: valid v1 JSON with
/// `version: 2`, so a binary that only knows v1 refuses the store
/// (`WalVersionUnsupported`) instead of opening it as empty.
pub fn v1_tombstone_bytes() -> Vec<u8> {
    Vec::new()
}
