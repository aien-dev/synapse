//! Durable single-writer changeset storage engine (`synapse-store`, Gate 1).
//!
//! Provides:
//! - Append-only WAL (`SWAL` v1, 88-byte header) with Castagnoli CRC-32C, SHA-256 hash chain,
//!   monotonic `WalSeq` validation, and explicit `FsyncPolicy`.
//! - Content-addressed immutable blobs with atomic visibility tied strictly to committed
//!   `WalSeq` watermarks (preventing phantom visibility after crashes): one file each
//!   (`blobs/<2-hex>/<64-hex>`) in v1 stores, inside the append-only segment files in
//!   group-commit stores (ADR 0003 A2, [`segment`]).
//! - Idempotent ingest (`IdempotencyKey`), snapshot reads (`snapshot_seq`), read-your-writes
//!   enforcement (`min_visible_seq`), deterministic replay, and admission backpressure.
//! - Atomic checkpointing, WAL compaction, and root-based garbage collection (`GarbageRoot`).
//! - Deterministic fault injection for torn headers, torn payloads, CRC corruption, broken
//!   chains, sequence gaps, pre-WAL crash recovery, and child-process `SIGABRT` crash recovery.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
pub use synapse_auth::{SignedStateMove, StateMoveFault};
use synapse_core::{
    BlobDigest, ChainPath, ChangesetEnvelope, ChangesetEnvelopeV2, ChangesetId, DerivedRevision,
    EvidenceAttachment, GitHubPullRequestProjection, IdempotencyKey, MutationOp,
    ObsolescenceMarker, RadicleCanonicalHead, RefusalCode, RepoId, RevisionState, SynapseError,
    SynapseResult, WalSeq,
};

#[cfg(test)]
mod a1_tests;
pub mod codec;
#[cfg(test)]
mod group_tests;
mod revision;
pub mod seal;
pub mod segment;
#[cfg(test)]
mod segment_tests;
mod shared;
pub mod wal2;

pub use codec::{CheckpointChain, CheckpointState, CodecRefusal, RecordCodec};
pub use revision::{
    verify_revision_log, AdmissionAuthority, ChangeStatus, RecordedMarker, RevisionOutcome,
    SealReplayReport, StateMoveReplayReport, StoredRevision, DOMAIN_STATE_ROOT_REVISIONS_V1,
};
pub use seal::{RevisionSeal, RevisionSealKey};
pub use shared::{GroupCommitStats, SharedStore};

/// Magic bytes for a Synapse WAL frame (`b"SWAL"`).
pub const WAL_MAGIC: [u8; 4] = *b"SWAL";

/// Supported WAL frame format version.
pub const WAL_VERSION: u16 = 1;

/// Fixed byte length of a WAL frame header.
pub const WAL_HEADER_LEN: usize = 88;

/// Domain tag for WAL frame SHA-256 chain computation.
pub const DOMAIN_WAL_FRAME_V1: &[u8] = b"SYNAPSE_WAL_FRAME_V1\0";

/// Supported checkpoint manifest format version.
pub const CHECKPOINT_VERSION: u16 = 1;

/// Castagnoli CRC-32C (`0x82F63B78` reflected polynomial).
///
/// Uses the Arm `crc` instructions when the CPU has them (detected at run time) and the
/// portable bitwise loop otherwise. Both produce identical values (tested).
pub fn crc32c(bytes: &[u8]) -> u32 {
    #[cfg(target_arch = "aarch64")]
    {
        if std::arch::is_aarch64_feature_detected!("crc") {
            // SAFETY: the `crc` target feature was detected at run time.
            return unsafe { crc32c_aarch64(bytes) };
        }
    }
    crc32c_portable(bytes)
}

#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "crc")]
unsafe fn crc32c_aarch64(bytes: &[u8]) -> u32 {
    use std::arch::aarch64::{__crc32cb, __crc32cd};
    let mut crc: u32 = !0;
    let (chunks, rest) = bytes.as_chunks::<8>();
    for c in chunks {
        crc = __crc32cd(crc, u64::from_le_bytes(*c));
    }
    for &b in rest {
        crc = __crc32cb(crc, b);
    }
    !crc
}

/// Portable bitwise CRC-32C (reference implementation).
pub fn crc32c_portable(bytes: &[u8]) -> u32 {
    let mut crc: u32 = !0;
    for &b in bytes {
        crc ^= u32::from(b);
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0x82F6_3B78 & mask);
        }
    }
    !crc
}

/// Explicit fsync durability policy for the single-writer engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FsyncPolicy {
    /// Synchronize blob files, shard directories, and `wal.log` via `sync_all()` before
    /// advancing `committed_seq` or acknowledging any commit.
    EveryCommit,
    /// Flush to OS kernel buffers on each commit and call `sync_all()` every `max_records`
    /// commits (or on explicit `sync()`). Survives user-space process crashes once written
    /// to the kernel page cache, but does not claim physical power-loss durability until synced.
    BatchWindow { max_records: u32 },
    /// Group commit with the same guarantee as `EveryCommit` (`FsyncBeforeAck`): records
    /// go to WAL v2 (`wal.v2.log`, blobs stored inline), and every batch of up to
    /// `max_batch_records` records is made durable with one write and one `fdatasync`
    /// into pre-written log space before any record in it is acknowledged. Concurrent
    /// submitters batch through [`SharedStore`]; the leader waits at most
    /// `max_batch_delay_us` microseconds for a batch to fill (0 = natural batching only:
    /// whatever queued while the previous batch was syncing). Opening a store with this
    /// policy switches it to WAL v2 permanently (a marker frame in `wal.log` makes older
    /// binaries refuse the store instead of missing commits).
    GroupCommit {
        max_batch_records: u32,
        max_batch_delay_us: u32,
    },
}

impl FsyncPolicy {
    /// Group commit with natural batching and at most 256 records per batch.
    pub const GROUP_COMMIT_DEFAULT: Self = Self::GroupCommit {
        max_batch_records: 256,
        max_batch_delay_us: 0,
    };

    fn is_group_commit(&self) -> bool {
        matches!(self, Self::GroupCommit { .. })
    }
}

/// Tested vs hardware durability classification attached to commit receipts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DurabilityGuarantee {
    /// `fsync` (`sync_all`) completed on blob files, directory metadata, and `wal.log`
    /// prior to commit acknowledgment. Verified against user-space process crash and torn writes;
    /// physical power-loss durability additionally depends on storage hardware FUA/PLP.
    FsyncBeforeAck,
    /// Written to OS kernel page cache without immediate `fsync`; durable against user-space
    /// process termination (`SIGKILL`/`SIGABRT`) but not host kernel panic or power loss until flushed.
    ProcessCrashPageCacheOnly,
}

/// Policy governing how `SynapseStore::open` handles a torn frame at the EOF tail of `wal.log`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RecoveryPolicy {
    /// Refuse to open if any frame (including the EOF tail frame) is torn or corrupt.
    StrictFailClosed,
    /// If all committed frames up to `N` have valid CRC32C and SHA-256 chain links, and only
    /// frame `N + 1` at the very end of `wal.log` is truncated/torn (from an unacknowledged write
    /// interrupted by a crash), truncate `wal.log` back to the end of frame `N` and recover cleanly.
    /// Any corruption before the final frame still fails closed.
    TruncateTornTail,
}

/// Capacity, payload size, and backpressure limits for `SynapseStore`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoreLimits {
    pub max_blob_bytes: u64,
    pub max_paths_per_changeset: usize,
    pub max_total_changeset_bytes: u64,
    pub max_inflight_admissions: usize,
    pub default_retention_window_ms: u64,
    /// WAL v2 only: bytes of zero-filled, synced log space kept ahead of the write
    /// position. Extending it costs one `sync_all` (journal commit) per extension, so a
    /// larger value moves that cost out of more commits.
    #[serde(default = "default_wal_prealloc_bytes")]
    pub wal_prealloc_bytes: u64,
    /// Largest WAL record payload the store writes or reads (the frame length cap). A
    /// frame declaring a longer payload is refused before anything is allocated for it,
    /// and the writer refuses a record above it, so every written frame stays readable.
    /// Must exceed `max_total_changeset_bytes` plus envelope metadata (WAL v2 frames carry
    /// their blobs inline).
    #[serde(default = "default_max_wal_record_bytes")]
    pub max_wal_record_bytes: u64,
    /// Segment store (ADR 0003 A2): a new segment file is started when the active one
    /// holds data and the next batch would end past this many bytes. A larger batch
    /// still goes into one segment on its own.
    #[serde(default = "default_segment_bytes")]
    pub segment_bytes: u64,
}

fn default_segment_bytes() -> u64 {
    256 * 1024 * 1024
}

fn default_wal_prealloc_bytes() -> u64 {
    64 * 1024 * 1024
}

fn default_max_wal_record_bytes() -> u64 {
    128 * 1024 * 1024
}

impl Default for StoreLimits {
    fn default() -> Self {
        Self {
            max_blob_bytes: 16 * 1024 * 1024, // 16 MiB per blob
            max_paths_per_changeset: 2_048,
            max_total_changeset_bytes: 64 * 1024 * 1024, // 64 MiB per changeset
            max_inflight_admissions: 64,
            default_retention_window_ms: 3_600_000, // 1 hour default speculative retention
            wal_prealloc_bytes: default_wal_prealloc_bytes(),
            max_wal_record_bytes: default_max_wal_record_bytes(),
            segment_bytes: default_segment_bytes(),
        }
    }
}

/// Deterministic fault injection hooks for Gate 1 crash and torn-write qualification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FaultInjection {
    /// No fault injected.
    None,
    /// Abort WAL append after writing blobs to disk, simulating a crash before WAL frame write.
    CrashAfterBlobWriteBeforeWalAppend,
    /// Write only the first `bytes_written` bytes (`< 88`) of the WAL header, simulating a torn header.
    TornWalHeaderWrite { bytes_written: usize },
    /// Write the full 88-byte WAL header but only `bytes_written` bytes of the payload.
    TornWalPayloadWrite { bytes_written: usize },
    /// Flip a bit in `payload_crc32c` when writing the next WAL frame.
    CorruptNextWalCrc,
    /// Corrupt `prev_frame_sha256` when writing the next WAL frame.
    CorruptNextWalChain,
    /// Write the next WAL frame with `seq + 1` (creating a sequence gap).
    InjectNextWalSequenceGap,
    /// Write the next WAL frame with duplicate `seq` (reusing the current `committed_seq`).
    InjectDuplicateWalSequence,
    /// WAL v2: write only the first `bytes_written` bytes of the next batch, then fail the
    /// write. The batch extent is rolled back (zeroed and synced); nothing is acknowledged.
    FailNextBatchWrite { bytes_written: usize },
    /// WAL v2: write the next batch completely, then report an `fdatasync` failure. The
    /// batch is rolled back; nothing is acknowledged.
    FailNextBatchSync,
    /// WAL v2: as `FailNextBatchSync`, and the rollback fails too. The store refuses all
    /// further writes until it is reopened (poisoned).
    FailNextBatchSyncAndRollback,
    /// WAL v2: write the first `bytes_written` bytes of the next batch, then terminate the
    /// process with exit code [`FAULT_CRASH_EXIT_CODE`] (crash in the middle of a batch).
    CrashMidBatchWrite { bytes_written: usize },
    /// WAL v2: write the whole next batch without syncing, then terminate the process with
    /// exit code [`FAULT_CRASH_EXIT_CODE`].
    CrashBeforeBatchSync,
    /// Segment store: write and `fdatasync` the next batch, then terminate the process
    /// with exit code [`FAULT_CRASH_EXIT_CODE`] before the blob index is updated or
    /// anything is acknowledged (crash between payload and index).
    CrashAfterBatchSyncBeforeIndex,
    /// Segment store: if the next batch rotates to a new segment, create and pre-write
    /// the new file, then terminate the process with exit code
    /// [`FAULT_CRASH_EXIT_CODE`] before the directory flush.
    CrashAfterSegmentCreateBeforeDirSync,
    /// Segment store: if the next batch rotates to a new segment, report a failure of
    /// the directory flush. Nothing is written into the log; nothing is acknowledged.
    FailNextSegmentDirSync,
    /// Segment store: in the next `checkpoint_and_compact`, write the segment index
    /// file, then terminate the process with exit code [`FAULT_CRASH_EXIT_CODE`] before
    /// the checkpoint replaces the previous one.
    CrashAfterSegmentIndexBeforeCheckpoint,
}

/// Exit code used by the process-terminating fault injections.
pub const FAULT_CRASH_EXIT_CODE: i32 = 42;

/// Review verdict attached to a committed changeset.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReviewRecord {
    pub reviewer_did: String,
    pub approved: bool,
    pub comment: String,
    pub recorded_at_ms: u64,
}

/// Record variants persisted inside WAL frames.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum WalRecord {
    ChangesetIngest {
        envelope: ChangesetEnvelope,
        changeset_id: ChangesetId,
        new_blobs: Vec<BlobDigest>,
    },
    EvaluationAttached {
        changeset_id: ChangesetId,
        attachment: EvidenceAttachment,
    },
    ReviewRecorded {
        changeset_id: ChangesetId,
        review: ReviewRecord,
    },
    GitProjected {
        projection: GitHubPullRequestProjection,
    },
    CanonicalPromoted {
        canonical: RadicleCanonicalHead,
    },
    LeaseUpdated {
        changeset_id: ChangesetId,
        lease_expires_at_ms: u64,
    },
    /// Admission of an envelope v2 revision under `chain` at server time `admitted_at_ms`
    /// (ADR 0003 B1). Binary codec only: it has no v1 JSON form.
    #[serde(skip)]
    RevisionAdmitted {
        envelope: ChangesetEnvelopeV2,
        chain: ChainPath,
        admitted_at_ms: u64,
        new_blobs: Vec<BlobDigest>,
        /// The server's keyed seal (issue #101); `None` in a store opened without a seal key.
        seal: Option<RevisionSeal>,
    },
    /// An obsolescence marker recorded under `chain` at server time `recorded_at_ms`
    /// (ADR 0003 B1). Binary codec only.
    #[serde(skip)]
    ObsolescenceRecorded {
        marker: ObsolescenceMarker,
        chain: ChainPath,
        recorded_at_ms: u64,
        seal: Option<RevisionSeal>,
    },
    /// A move of a revision to another state, signed by its mover (the audience of the
    /// chain's leaf link) and recorded at server time `moved_at_ms` (ADR 0003 B4, issue
    /// #89). Binary codec only.
    #[serde(skip)]
    RevisionStateMoved {
        state_move: SignedStateMove,
        moved_at_ms: u64,
        seal: Option<RevisionSeal>,
    },
    /// Admission of a server-derived revision under `chain` at server time `admitted_at_ms`
    /// (ADR 0003 B5). It references only blobs already visible, so it carries none. Binary
    /// codec only.
    #[serde(skip)]
    DerivedRevisionAdmitted {
        derived: DerivedRevision,
        chain: ChainPath,
        admitted_at_ms: u64,
        seal: Option<RevisionSeal>,
    },
}

impl WalRecord {
    pub fn kind_byte(&self) -> u8 {
        match self {
            Self::ChangesetIngest { .. } => 1,
            Self::EvaluationAttached { .. } => 2,
            Self::ReviewRecorded { .. } => 3,
            Self::GitProjected { .. } => 4,
            Self::CanonicalPromoted { .. } => 5,
            Self::LeaseUpdated { .. } => 6,
            Self::RevisionAdmitted { .. } => 7,
            Self::ObsolescenceRecorded { .. } => 8,
            Self::RevisionStateMoved { .. } => 9,
            Self::DerivedRevisionAdmitted { .. } => 11,
        }
    }

    /// True for the revision records a seal covers (kinds 7, 8, 9, and 11).
    pub fn is_revision_record(&self) -> bool {
        matches!(
            self,
            Self::RevisionAdmitted { .. }
                | Self::ObsolescenceRecorded { .. }
                | Self::RevisionStateMoved { .. }
                | Self::DerivedRevisionAdmitted { .. }
        )
    }

    /// The keyed seal of a revision record (issue #101), if it carries one.
    pub fn seal(&self) -> Option<&RevisionSeal> {
        match self {
            Self::RevisionAdmitted { seal, .. }
            | Self::ObsolescenceRecorded { seal, .. }
            | Self::RevisionStateMoved { seal, .. }
            | Self::DerivedRevisionAdmitted { seal, .. } => seal.as_ref(),
            _ => None,
        }
    }

    fn set_seal(&mut self, value: RevisionSeal) {
        if let Self::RevisionAdmitted { seal, .. }
        | Self::ObsolescenceRecorded { seal, .. }
        | Self::RevisionStateMoved { seal, .. }
        | Self::DerivedRevisionAdmitted { seal, .. } = self
        {
            *seal = Some(value);
        }
    }

    /// Blob digests this record references and replay requires present: the upserts of an
    /// ingest or revision record, and a revision intent's context blob (step B3).
    pub fn upsert_blobs(&self) -> Vec<BlobDigest> {
        match self {
            Self::ChangesetIngest { envelope, .. } => envelope
                .mutations
                .iter()
                .filter_map(|m| match &m.op {
                    MutationOp::Upsert { blob_digest, .. } => Some(*blob_digest),
                    MutationOp::Delete => None,
                })
                .collect(),
            Self::RevisionAdmitted { envelope, .. } => {
                envelope.content.referenced_blobs().collect()
            }
            Self::DerivedRevisionAdmitted { derived, .. } => {
                derived.content.referenced_blobs().collect()
            }
            _ => Vec::new(),
        }
    }
}

/// Stored metadata for a committed changeset in `SynapseStore`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredChangeset {
    pub changeset_id: ChangesetId,
    pub committed_seq: WalSeq,
    pub envelope: ChangesetEnvelope,
    pub evaluations: Vec<EvidenceAttachment>,
    pub reviews: Vec<ReviewRecord>,
    pub lease_expires_at_ms: u64,
}

/// Outcome of submitting a changeset to `SynapseStore`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum IngestOutcome {
    /// Newly committed at `wal_seq`.
    Committed {
        wal_seq: WalSeq,
        changeset_id: ChangesetId,
        frame_sha256: [u8; 32],
        durability: DurabilityGuarantee,
    },
    /// Already committed under the same `(repo_id, idempotency_key)` with identical `ChangesetId`.
    IdempotentDuplicate {
        wal_seq: WalSeq,
        changeset_id: ChangesetId,
    },
}

/// Persisted checkpoint manifest (`checkpoint.v1`) enabling WAL compaction and GC.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckpointManifest {
    pub version: u16,
    pub checkpoint_seq: WalSeq,
    pub anchor_frame_sha256: [u8; 32],
    pub changesets: BTreeMap<String, StoredChangeset>,
    pub idempotency_index: BTreeMap<String, (WalSeq, ChangesetId)>,
    pub blob_first_visible_seq: BTreeMap<String, WalSeq>,
    pub github_projections: BTreeMap<u64, GitHubPullRequestProjection>,
    pub canonical_heads: BTreeMap<String, RadicleCanonicalHead>,
}

impl Default for CheckpointManifest {
    fn default() -> Self {
        Self {
            version: CHECKPOINT_VERSION,
            checkpoint_seq: WalSeq::ZERO,
            anchor_frame_sha256: [0u8; 32],
            changesets: BTreeMap::new(),
            idempotency_index: BTreeMap::new(),
            blob_first_visible_seq: BTreeMap::new(),
            github_projections: BTreeMap::new(),
            canonical_heads: BTreeMap::new(),
        }
    }
}

/// Summary returned after running `checkpoint_and_compact`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompactionReport {
    pub checkpoint_seq: WalSeq,
    pub anchor_frame_sha256: [u8; 32],
    pub retained_changesets: usize,
    pub evicted_changesets: usize,
    pub retained_blobs: usize,
    pub swept_blob_files: usize,
}

/// Single-writer durable changeset and content-addressed blob engine.
pub struct SynapseStore {
    root_dir: PathBuf,
    blobs_dir: PathBuf,
    wal_path: PathBuf,
    checkpoint_path: PathBuf,
    fsync_policy: FsyncPolicy,
    limits: StoreLimits,
    committed_seq: WalSeq,
    last_frame_sha256: [u8; 32],
    unflushed_frames: u32,
    inflight_admissions: usize,
    fault_injection: FaultInjection,
    changesets: BTreeMap<ChangesetId, StoredChangeset>,
    idempotency_index: BTreeMap<(RepoId, IdempotencyKey), (WalSeq, ChangesetId)>,
    blob_first_visible_seq: BTreeMap<BlobDigest, WalSeq>,
    github_projections: BTreeMap<u64, GitHubPullRequestProjection>,
    canonical_heads: BTreeMap<RepoId, RadicleCanonicalHead>,
    torn_frames_truncated_on_open: usize,
    /// True once `wal.log` ends with the WAL v2 marker: all new frames go to `wal.v2.log`.
    v2_mode: bool,
    /// Layout of the log after `wal.log`, from the marker recovery found.
    log_layout: LogLayout,
    /// Segment writer (taken out by the group-commit leader while it writes a batch).
    wal_v2: Option<segment::SegmentLog>,
    /// Read handles on the segment files, by segment id, for inline blob reads.
    segment_readers: BTreeMap<u64, File>,
    /// End of the valid log found by recovery: (segment, byte offset).
    wal_v2_recovered_end: (u64, u64),
    /// The blob index: digest to its location inside a segment.
    blob_locations: BTreeMap<BlobDigest, segment::BlobLoc>,
    /// Set when a failed batch could not be rolled back: every write is refused until reopen.
    poisoned: Option<String>,
    /// Codec new WAL records are written with (ADR 0003 A1).
    codec: RecordCodec,
    /// Chain of the binary checkpoint (`checkpoint.v2`) this store holds.
    checkpoint_chain: Option<CheckpointChain>,
    /// The store holds v1 history: a v1 checkpoint or replayed v1 JSON frames.
    v1_history: bool,
    /// A binary checkpoint or a binary frame was replayed: v1 JSON frames are refused.
    binary_seen: bool,
    /// `checkpoint.v1` is not yet the tombstone although `checkpoint.v2` exists.
    /// Envelope v2 revisions, changes, witnesses, and markers (ADR 0003 B1).
    revisions: revision::RevisionLedger,
    /// The server key revision records are sealed with and checked against (issue #101).
    revision_seal: Option<RevisionSealKey>,
    tombstone_pending: bool,
}

/// What follows the v1 frames of `wal.log`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LogLayout {
    /// No marker: a v1 store (or a new one).
    V1,
    /// WAL v2 marker (version 2): `wal.v2.log` alone, checkpoints emptied it and moved
    /// retained blobs to blob files (the layout before ADR 0003 A2).
    SingleFileV2,
    /// Segment marker (version 3): segments `wal.v2.log`, `wal.v2.000002.log`, ... with
    /// a segment index bound to the checkpoint (ADR 0003 A2).
    Segments,
}

/// One upsert check from ingest step 7, evaluated in mutation order.
#[derive(Debug, Clone)]
enum UpsertCheck {
    /// The provided blob has a different size than the mutation declares.
    SizeMismatch(SynapseError),
    /// The blob was not provided, so it must already be committed.
    MustBeVisible { digest: BlobDigest, path: String },
}

/// Stateless half of an ingest, computed without any store lock (signature check,
/// blob digests, limits, and for WAL v2 the encoded payload with its SHA-256 and CRC-32C).
/// Errors from these checks are deferred so that the stateful half reports refusals in
/// exactly the same order as [`SynapseStore::ingest_changeset`] always has.
#[derive(Debug, Clone)]
pub struct PreparedIngest {
    envelope: ChangesetEnvelope,
    changeset_id: ChangesetId,
    path_count_error: Option<SynapseError>,
    blob_error: Option<SynapseError>,
    upsert_checks: Vec<UpsertCheck>,
    new_blobs: Vec<BlobDigest>,
    /// Provided blobs, unique and in digest order (v1 writes all of them as files).
    provided: Vec<(BlobDigest, Vec<u8>)>,
    encoded: Option<wal2::EncodedRecord>,
}

impl PreparedIngest {
    /// Changeset id computed from the validated envelope.
    pub fn changeset_id(&self) -> ChangesetId {
        self.changeset_id
    }

    /// The validated envelope.
    pub fn envelope(&self) -> &ChangesetEnvelope {
        &self.envelope
    }

    fn record(&self) -> WalRecord {
        WalRecord::ChangesetIngest {
            envelope: self.envelope.clone(),
            changeset_id: self.changeset_id,
            new_blobs: self.new_blobs.clone(),
        }
    }
}

/// Pending (not yet durable) effects of earlier records in the same batch.
#[derive(Debug, Default)]
struct BatchOverlay {
    idempotency: BTreeMap<(RepoId, IdempotencyKey), (WalSeq, ChangesetId)>,
    changesets: BTreeMap<ChangesetId, RepoId>,
    blobs: BTreeSet<BlobDigest>,
}

/// Result of the stateful half of an ingest.
#[derive(Debug)]
enum Planned {
    /// Already committed (or pending in this batch when `depends_on_batch`).
    Duplicate {
        wal_seq: WalSeq,
        changeset_id: ChangesetId,
        depends_on_batch: bool,
    },
    /// Refused (because of a pending record in this batch when `depends_on_batch`).
    Refused {
        error: SynapseError,
        depends_on_batch: bool,
    },
    /// Accepted: becomes the next frame.
    Accept,
}

/// A WAL v2 batch in flight: the writer and fault taken out of the store, plus the
/// chain position the batch starts from.
pub(crate) struct V2Ticket {
    writer: segment::SegmentLog,
    fault: FaultInjection,
    base_seq: WalSeq,
    prev_sha: [u8; 32],
}

impl SynapseStore {
    /// Open or initialize a `SynapseStore` at `root_dir`, verifying checkpoint + WAL chain.
    /// Revision records are neither sealed nor checked for a seal: whoever can rewrite the
    /// whole log can rewrite them too (issue #101). Use [`Self::open_sealed`] to close that.
    pub fn open(
        root_dir: impl AsRef<Path>,
        fsync_policy: FsyncPolicy,
        recovery_policy: RecoveryPolicy,
        limits: StoreLimits,
    ) -> SynapseResult<Self> {
        Self::open_with(root_dir, fsync_policy, recovery_policy, limits, None)
    }

    /// [`Self::open`] with the server's machine key as the revision seal key (issue #101).
    /// Every revision record written (kinds 7, 8, 9, and 11) is sealed by `seal`, chained to
    /// the previous one; on replay a revision record whose seal does not verify against that
    /// chain changes nothing. `StrictFailClosed` refuses such a store with
    /// `RevisionRecordUnsealed` (including one with revision records written before it was
    /// sealed); `TruncateTornTail` opens it, reports them in [`Self::seal_replay_report`],
    /// and `checkpoint_and_compact` then leaves them out.
    pub fn open_sealed(
        root_dir: impl AsRef<Path>,
        fsync_policy: FsyncPolicy,
        recovery_policy: RecoveryPolicy,
        limits: StoreLimits,
        seal: RevisionSealKey,
    ) -> SynapseResult<Self> {
        Self::open_with(root_dir, fsync_policy, recovery_policy, limits, Some(seal))
    }

    fn open_with(
        root_dir: impl AsRef<Path>,
        fsync_policy: FsyncPolicy,
        recovery_policy: RecoveryPolicy,
        limits: StoreLimits,
        revision_seal: Option<RevisionSealKey>,
    ) -> SynapseResult<Self> {
        let root_dir = root_dir.as_ref().to_path_buf();
        let blobs_dir = root_dir.join("blobs");
        let wal_path = root_dir.join("wal.log");
        let checkpoint_path = root_dir.join("checkpoint.v1");

        fs::create_dir_all(&blobs_dir).map_err(io_err)?;

        let mut store = Self {
            root_dir,
            blobs_dir,
            wal_path,
            checkpoint_path,
            fsync_policy,
            limits,
            committed_seq: WalSeq::ZERO,
            last_frame_sha256: [0u8; 32],
            unflushed_frames: 0,
            inflight_admissions: 0,
            fault_injection: FaultInjection::None,
            changesets: BTreeMap::new(),
            idempotency_index: BTreeMap::new(),
            blob_first_visible_seq: BTreeMap::new(),
            github_projections: BTreeMap::new(),
            canonical_heads: BTreeMap::new(),
            torn_frames_truncated_on_open: 0,
            v2_mode: false,
            log_layout: LogLayout::V1,
            wal_v2: None,
            segment_readers: BTreeMap::new(),
            wal_v2_recovered_end: (1, 0),
            blob_locations: BTreeMap::new(),
            poisoned: None,
            codec: RecordCodec::BinaryV2,
            checkpoint_chain: None,
            v1_history: false,
            binary_seen: false,
            tombstone_pending: false,
            revisions: revision::RevisionLedger::new(
                revision_seal.as_ref().map(RevisionSealKey::public_key),
            ),
            revision_seal,
        };

        store.recover(recovery_policy)?;
        if store.tombstone_pending {
            store.write_v1_tombstone()?;
        }
        if fsync_policy.is_group_commit() {
            if store.log_layout != LogLayout::Segments {
                store.upgrade_to_segments()?;
            }
            let (active, end) = store.wal_v2_recovered_end;
            let writer = segment::SegmentLog::open(
                &store.root_dir,
                active,
                end,
                store.limits.segment_bytes,
                store.limits.wal_prealloc_bytes,
            )?;
            store.wal_v2 = Some(writer);
            store.open_segment_readers()?;
        } else if store.v2_mode {
            return Err(SynapseError::new(
                RefusalCode::WalVersionUnsupported,
                "store uses WAL v2 (wal.log ends with the v2 marker); open it with FsyncPolicy::GroupCommit",
            ));
        }
        Ok(store)
    }

    /// Codec this store writes new WAL records with (ADR 0003 A1).
    pub fn record_codec(&self) -> RecordCodec {
        self.codec
    }

    /// Chain fields of the binary checkpoint this store holds, if it has one.
    pub fn checkpoint_chain(&self) -> Option<CheckpointChain> {
        self.checkpoint_chain
    }

    /// True when this store writes WAL v2 (group commit).
    pub fn is_wal_v2(&self) -> bool {
        self.v2_mode
    }

    /// The fsync policy this store was opened with.
    pub fn fsync_policy(&self) -> FsyncPolicy {
        self.fsync_policy
    }

    /// Admission limits.
    pub fn limits(&self) -> &StoreLimits {
        &self.limits
    }

    /// `Some(reason)` when a failed batch could not be rolled back; writes are refused.
    pub fn poisoned(&self) -> Option<&str> {
        self.poisoned.as_deref()
    }

    /// Return the current committed WAL sequence watermark.
    pub fn committed_seq(&self) -> WalSeq {
        self.committed_seq
    }

    /// Return the SHA-256 digest of the most recently committed WAL frame.
    pub fn last_frame_sha256(&self) -> [u8; 32] {
        self.last_frame_sha256
    }

    /// Return the number of torn tail frames truncated during `open()`.
    pub fn torn_frames_truncated_on_open(&self) -> usize {
        self.torn_frames_truncated_on_open
    }

    /// Configure fault injection for the next write operation (used in Gate 1 fault tests).
    pub fn set_fault_injection(&mut self, fault: FaultInjection) {
        self.fault_injection = fault;
    }

    /// Simulate in-flight queue saturation for testing admission backpressure.
    pub fn set_simulated_inflight(&mut self, inflight: usize) {
        self.inflight_admissions = inflight;
    }

    /// Explicitly `fsync` (`sync_all`) the WAL file and reset the batch counter.
    pub fn sync_wal(&mut self) -> SynapseResult<()> {
        if let Some(w) = &self.wal_v2 {
            // Every v2 batch is already synced before acknowledgment; this is a no-op
            // apart from the system call.
            w.sync()?;
        } else if self.wal_path.exists() {
            let f = OpenOptions::new()
                .read(true)
                .write(true)
                .open(&self.wal_path)
                .map_err(io_err)?;
            f.sync_all().map_err(io_err)?;
        }
        self.unflushed_frames = 0;
        Ok(())
    }

    /// Ingest a signed `ChangesetEnvelope` along with its referenced `(BlobDigest, Vec<u8>)` blobs.
    pub fn ingest_changeset(
        &mut self,
        envelope: ChangesetEnvelope,
        blobs: &[(BlobDigest, Vec<u8>)],
    ) -> SynapseResult<IngestOutcome> {
        // 1. Check admission backpressure
        if self.inflight_admissions >= self.limits.max_inflight_admissions {
            return Err(SynapseError::new(
                RefusalCode::BackpressureOverCapacity,
                format!(
                    "admission queue at capacity ({}/{})",
                    self.inflight_admissions, self.limits.max_inflight_admissions
                ),
            ));
        }

        // 2. Validate canonical envelope and Ed25519 signature (the stateless halves of
        //    steps 4, 6 and 7 are computed here too; their errors are reported in order).
        let prepared = Self::prepare_ingest(
            &self.limits,
            envelope,
            blobs,
            self.v2_mode.then_some(self.codec),
        )?;
        self.ingest_prepared(prepared)
    }

    /// Stateless half of [`Self::ingest_changeset`]: validates the envelope and signature,
    /// checks limits and blob digests, and (when `wal_v2_codec` is set) encodes the WAL v2
    /// payload with that record codec, its SHA-256 and CRC-32C. A store re-encodes it at
    /// commit if its codec changed in between (migration checkpoint). Needs no store lock, so concurrent submitters run it
    /// in parallel. Only a validation failure (step 2) is returned here; refusals from
    /// steps 4, 6 and 7 are deferred to the stateful half so their order is unchanged.
    pub fn prepare_ingest(
        limits: &StoreLimits,
        envelope: ChangesetEnvelope,
        blobs: &[(BlobDigest, Vec<u8>)],
        wal_v2_codec: Option<RecordCodec>,
    ) -> SynapseResult<PreparedIngest> {
        let changeset_id = envelope.validate()?;

        // 4. Path count limit (deferred).
        let path_count_error =
            (envelope.mutations.len() > limits.max_paths_per_changeset).then(|| {
                SynapseError::new(
                    RefusalCode::QuotaTooManyPaths,
                    format!(
                        "changeset touches {} paths, exceeding limit {}",
                        envelope.mutations.len(),
                        limits.max_paths_per_changeset
                    ),
                )
            });

        // 6. Index provided blobs and verify digests and size limits (deferred).
        let mut provided_map: BTreeMap<BlobDigest, &[u8]> = BTreeMap::new();
        let mut total_bytes = 0u64;
        let mut blob_error = None;
        for (declared_digest, bytes) in blobs {
            let len = bytes.len() as u64;
            if len > limits.max_blob_bytes {
                blob_error = Some(SynapseError::new(
                    RefusalCode::QuotaPayloadTooLarge,
                    format!(
                        "blob size {len} exceeds max_blob_bytes {}",
                        limits.max_blob_bytes
                    ),
                ));
                break;
            }
            total_bytes = total_bytes.saturating_add(len);
            if total_bytes > limits.max_total_changeset_bytes {
                blob_error = Some(SynapseError::new(
                    RefusalCode::QuotaPayloadTooLarge,
                    format!(
                        "total blob payload {total_bytes} exceeds max_total_changeset_bytes {}",
                        limits.max_total_changeset_bytes
                    ),
                ));
                break;
            }
            let actual_digest = BlobDigest::compute(bytes);
            if actual_digest != *declared_digest {
                blob_error = Some(SynapseError::new(
                    RefusalCode::BlobDigestMismatch,
                    format!(
                        "declared blob digest {} does not match computed {}",
                        declared_digest, actual_digest
                    ),
                ));
                break;
            }
            provided_map.insert(*declared_digest, bytes.as_slice());
        }

        // 7. Upsert checks in mutation order (size mismatches and blobs that must already
        //    be committed; the latter needs store state and is checked later).
        let mut upsert_checks = Vec::new();
        let mut new_blobs = Vec::new();
        if blob_error.is_none() {
            for m in &envelope.mutations {
                if let MutationOp::Upsert {
                    blob_digest,
                    size_bytes,
                    ..
                } = &m.op
                {
                    if let Some(raw) = provided_map.get(blob_digest) {
                        if raw.len() as u64 != *size_bytes {
                            upsert_checks.push(UpsertCheck::SizeMismatch(SynapseError::new(
                                RefusalCode::BlobDigestMismatch,
                                format!(
                                    "mutation path {} declared size {} but blob is {} bytes",
                                    m.path,
                                    size_bytes,
                                    raw.len()
                                ),
                            )));
                        } else {
                            new_blobs.push(*blob_digest);
                        }
                    } else {
                        upsert_checks.push(UpsertCheck::MustBeVisible {
                            digest: *blob_digest,
                            path: m.path.clone(),
                        });
                    }
                }
            }
        }

        let clean = path_count_error.is_none()
            && blob_error.is_none()
            && !upsert_checks
                .iter()
                .any(|c| matches!(c, UpsertCheck::SizeMismatch(_)));
        let mut prepared = PreparedIngest {
            envelope,
            changeset_id,
            path_count_error,
            blob_error,
            upsert_checks,
            new_blobs,
            provided: Vec::new(),
            encoded: None,
        };
        if let Some(codec) = wal_v2_codec {
            if clean {
                let mut inline: Vec<(BlobDigest, &[u8])> = Vec::new();
                for d in &prepared.new_blobs {
                    if !inline.iter().any(|(x, _)| x == d) {
                        inline.push((*d, provided_map[d]));
                    }
                }
                prepared.encoded = Some(wal2::encode_record(&prepared.record(), &inline, codec)?);
            }
        } else {
            prepared.provided = provided_map
                .into_iter()
                .map(|(d, b)| (d, b.to_vec()))
                .collect();
        }
        Ok(prepared)
    }

    /// Stateful half of [`Self::ingest_changeset`], committing one prepared changeset
    /// on its own (one record, one sync).
    pub fn ingest_prepared(
        &mut self,
        mut prepared: PreparedIngest,
    ) -> SynapseResult<IngestOutcome> {
        self.check_writable()?;
        match self.plan_ingest(&prepared, &BatchOverlay::default()) {
            Planned::Duplicate {
                wal_seq,
                changeset_id,
                ..
            } => {
                return Ok(IngestOutcome::IdempotentDuplicate {
                    wal_seq,
                    changeset_id,
                })
            }
            Planned::Refused { error, .. } => return Err(error),
            Planned::Accept => {}
        }
        let changeset_id = prepared.changeset_id;
        let record = prepared.record();

        if self.v2_mode {
            self.conform_v2(&mut prepared)?;
            let encoded = prepared.encoded.expect("conform_v2 checked it");
            let mut ticket = self.v2_begin()?;
            let result = Self::v2_write(&mut ticket, &[&encoded]);
            let placed = self.v2_finish(ticket, result)?;
            self.apply_v2_ingest(&placed[0], record, &encoded.inline);
            return Ok(IngestOutcome::Committed {
                wal_seq: placed[0].seq,
                changeset_id,
                frame_sha256: placed[0].frame_sha256,
                durability: DurabilityGuarantee::FsyncBeforeAck,
            });
        }

        // The frame payload is encoded (and checked against the frame cap) before any
        // blob is written.
        let payload = self.encode_v1_payload(&record)?;

        // 8. Write all provided blobs to the content-addressed store BEFORE appending the WAL frame
        for (digest, raw) in &prepared.provided {
            self.write_blob_file(*digest, raw)?;
        }

        if self.fault_injection == FaultInjection::CrashAfterBlobWriteBeforeWalAppend {
            self.fault_injection = FaultInjection::None;
            return Err(SynapseError::new(
                RefusalCode::IoFailure,
                "injected fault: crash after blob write before WAL append",
            ));
        }

        // 9. Append the WAL frame
        let (wal_seq, frame_sha256, durability) =
            self.append_v1_payload(record.kind_byte(), &payload)?;

        // 10. Advance in-memory visibility atomically with `wal_seq`
        self.apply_record(wal_seq, record);

        Ok(IngestOutcome::Committed {
            wal_seq,
            changeset_id,
            frame_sha256,
            durability,
        })
    }

    /// Stateful checks of an ingest (steps 3, 4, 5, 6, 7 in the original order) against
    /// committed state plus the not-yet-durable records earlier in the same batch.
    fn plan_ingest(&self, p: &PreparedIngest, overlay: &BatchOverlay) -> Planned {
        // 3. Idempotency
        let idem_key = (p.envelope.repo_id.clone(), p.envelope.idempotency_key);
        let (existing, mut dep) = match self.idempotency_index.get(&idem_key) {
            Some(v) => (Some(*v), false),
            None => (overlay.idempotency.get(&idem_key).copied(), true),
        };
        if let Some((existing_seq, existing_cs_id)) = existing {
            if existing_cs_id == p.changeset_id {
                return Planned::Duplicate {
                    wal_seq: existing_seq,
                    changeset_id: existing_cs_id,
                    depends_on_batch: dep,
                };
            }
            return Planned::Refused {
                error: SynapseError::new(
                    RefusalCode::IdempotencyKeyConflict,
                    format!(
                        "idempotency key {} already bound to changeset {}, cannot rebind to {}",
                        p.envelope.idempotency_key.to_hex(),
                        existing_cs_id,
                        p.changeset_id
                    ),
                ),
                depends_on_batch: dep,
            };
        }
        dep = false;
        let refuse = |error: SynapseError, dep: bool| Planned::Refused {
            error,
            depends_on_batch: dep,
        };

        // 4. Path count
        if let Some(e) = &p.path_count_error {
            return refuse(e.clone(), dep);
        }

        // 5. Parents must be committed (or earlier in this batch)
        for parent_id in &p.envelope.parent_changesets {
            let parent_repo = if let Some(parent) = self.changesets.get(parent_id) {
                &parent.envelope.repo_id
            } else if let Some(repo) = overlay.changesets.get(parent_id) {
                dep = true;
                repo
            } else {
                return refuse(
                    SynapseError::new(
                        RefusalCode::ParentChangesetNotFound,
                        format!("parent changeset {parent_id} not found"),
                    ),
                    dep,
                );
            };
            if parent_repo != &p.envelope.repo_id {
                return refuse(
                    SynapseError::new(
                        RefusalCode::AuthCrossRepoDenied,
                        "parent changeset belongs to a different repository",
                    ),
                    dep,
                );
            }
        }

        // 6. Blob sizes and digests
        if let Some(e) = &p.blob_error {
            return refuse(e.clone(), dep);
        }

        // 7. Upserts: provided with the right size, or already committed
        for c in &p.upsert_checks {
            match c {
                UpsertCheck::SizeMismatch(e) => return refuse(e.clone(), dep),
                UpsertCheck::MustBeVisible { digest, path } => {
                    if self.blob_first_visible_seq.contains_key(digest) {
                        continue;
                    }
                    if overlay.blobs.contains(digest) {
                        dep = true;
                        continue;
                    }
                    return refuse(
                        SynapseError::new(
                            RefusalCode::BlobNotFound,
                            format!("mutation path {path} references missing blob {digest}"),
                        ),
                        dep,
                    );
                }
            }
        }
        Planned::Accept
    }

    fn check_writable(&self) -> SynapseResult<()> {
        match &self.poisoned {
            Some(reason) => Err(SynapseError::new(
                RefusalCode::IoFailure,
                format!("store refuses writes until it is reopened: {reason}"),
            )),
            None => Ok(()),
        }
    }

    /// Take the WAL v2 writer and the pending fault for one batch.
    pub(crate) fn v2_begin(&mut self) -> SynapseResult<V2Ticket> {
        self.check_writable()?;
        let writer = self.wal_v2.take().ok_or_else(|| {
            SynapseError::new(RefusalCode::IoFailure, "WAL v2 writer is not available")
        })?;
        Ok(V2Ticket {
            writer,
            fault: std::mem::replace(&mut self.fault_injection, FaultInjection::None),
            base_seq: self.committed_seq,
            prev_sha: self.last_frame_sha256,
        })
    }

    /// Build one batch from `records` and make it durable (one write, one `fdatasync`).
    /// Needs no store lock: the ticket owns the writer and the chain position.
    pub(crate) fn v2_write(
        ticket: &mut V2Ticket,
        records: &[&wal2::EncodedRecord],
    ) -> Result<Vec<wal2::PlacedFrame>, wal2::BatchFailure> {
        use segment::RotationFault as Rot;
        use wal2::{BatchIoFault as Io, FrameFault as Fr};
        let first_len = records.first().map_or(0, |r| r.payload.len());
        let rotation_fault = match ticket.fault {
            FaultInjection::CrashAfterSegmentCreateBeforeDirSync => Rot::CrashBeforeDirSync {
                code: FAULT_CRASH_EXIT_CODE,
            },
            FaultInjection::FailNextSegmentDirSync => Rot::FailDirSync,
            _ => Rot::None,
        };
        let (frame_fault, io_fault) = match ticket.fault {
            FaultInjection::None => (Fr::None, Io::None),
            FaultInjection::CrashAfterBlobWriteBeforeWalAppend => {
                return Err(wal2::BatchFailure::RolledBack(SynapseError::new(
                    RefusalCode::IoFailure,
                    "injected fault: crash before WAL v2 batch write",
                )))
            }
            FaultInjection::TornWalHeaderWrite { bytes_written } => (
                Fr::None,
                Io::TornThenStop {
                    bytes_written: wal2::WAL_V2_BATCH_HEADER_LEN
                        + bytes_written.min(WAL_HEADER_LEN - 1),
                },
            ),
            FaultInjection::TornWalPayloadWrite { bytes_written } => (
                Fr::None,
                Io::TornThenStop {
                    bytes_written: wal2::WAL_V2_BATCH_HEADER_LEN
                        + WAL_HEADER_LEN
                        + bytes_written.min(first_len.saturating_sub(1)),
                },
            ),
            FaultInjection::CorruptNextWalCrc => (Fr::CorruptCrc, Io::None),
            FaultInjection::CorruptNextWalChain => (Fr::CorruptChain, Io::None),
            FaultInjection::InjectNextWalSequenceGap => (Fr::SequenceGap, Io::None),
            FaultInjection::InjectDuplicateWalSequence => (Fr::DuplicateSequence, Io::None),
            FaultInjection::FailNextBatchWrite { bytes_written } => {
                (Fr::None, Io::FailWrite { bytes_written })
            }
            FaultInjection::FailNextBatchSync => (Fr::None, Io::FailSync),
            FaultInjection::FailNextBatchSyncAndRollback => (Fr::None, Io::FailSyncAndRollback),
            FaultInjection::CrashMidBatchWrite { bytes_written } => (
                Fr::None,
                Io::CrashAfterBytes {
                    bytes_written,
                    code: FAULT_CRASH_EXIT_CODE,
                },
            ),
            FaultInjection::CrashBeforeBatchSync => (
                Fr::None,
                Io::CrashBeforeSync {
                    code: FAULT_CRASH_EXIT_CODE,
                },
            ),
            FaultInjection::CrashAfterBatchSyncBeforeIndex => (
                Fr::None,
                Io::CrashAfterSync {
                    code: FAULT_CRASH_EXIT_CODE,
                },
            ),
            FaultInjection::CrashAfterSegmentCreateBeforeDirSync
            | FaultInjection::FailNextSegmentDirSync
            | FaultInjection::CrashAfterSegmentIndexBeforeCheckpoint => (Fr::None, Io::None),
        };
        let capacity = wal2::WAL_V2_BATCH_HEADER_LEN
            + records
                .iter()
                .map(|r| WAL_HEADER_LEN + r.payload.len())
                .sum::<usize>();
        // The finished batch is padded to the next 4 KiB after its 8-byte trailer.
        let batch_len = wal2::align_up((capacity + wal2::WAL_V2_BATCH_TRAILER.len()) as u64);
        let (segment, base) = ticket.writer.reserve(batch_len, rotation_fault)?;
        let mut builder = wal2::BatchBuilder::new(segment, base, capacity);
        let mut seq = ticket.base_seq;
        let mut prev = ticket.prev_sha;
        let mut placed = Vec::with_capacity(records.len());
        for (i, r) in records.iter().enumerate() {
            seq = seq.next();
            let fault = if i == 0 { frame_fault } else { Fr::None };
            let p = builder.push(seq, prev, r, fault);
            prev = p.frame_sha256;
            placed.push(p);
        }
        let buf = builder.finish();
        ticket.writer.write_batch(&buf, io_fault)?;
        Ok(placed)
    }

    /// Return the writer to the store and advance the chain after a durable batch.
    /// On failure nothing advances; an unrecoverable failure poisons the store.
    pub(crate) fn v2_finish(
        &mut self,
        ticket: V2Ticket,
        result: Result<Vec<wal2::PlacedFrame>, wal2::BatchFailure>,
    ) -> SynapseResult<Vec<wal2::PlacedFrame>> {
        let active = ticket.writer.active();
        self.wal_v2 = Some(ticket.writer);
        if !self.segment_readers.contains_key(&active) {
            // A new segment (its directory entry is already flushed). Without a read
            // handle its blobs could not be served, so a failure here poisons the store.
            match File::open(self.root_dir.join(segment::segment_file_name(active))) {
                Ok(f) => {
                    self.segment_readers.insert(active, f);
                }
                Err(e) => {
                    let msg = format!("open segment {active} for reads: {e}");
                    self.poisoned = Some(msg.clone());
                    return Err(SynapseError::new(RefusalCode::IoFailure, msg));
                }
            }
        }
        match result {
            Ok(placed) => {
                if let Some(last) = placed.last() {
                    self.committed_seq = last.seq;
                    self.last_frame_sha256 = last.frame_sha256;
                }
                Ok(placed)
            }
            Err(wal2::BatchFailure::RolledBack(e)) => Err(e),
            Err(wal2::BatchFailure::Poisoned(e)) => {
                self.poisoned = Some(e.message.clone());
                Err(e)
            }
        }
    }

    /// Make a durable WAL v2 ingest frame visible: inline blob locations, then state.
    pub(crate) fn apply_v2_ingest(
        &mut self,
        placed: &wal2::PlacedFrame,
        record: WalRecord,
        inline: &[(BlobDigest, u32, u32)],
    ) {
        for &(digest, off, len) in inline {
            self.blob_locations
                .entry(digest)
                .or_insert(segment::BlobLoc {
                    segment: placed.segment,
                    offset: placed.payload_offset + u64::from(off),
                    len,
                });
        }
        self.apply_record(placed.seq, record);
    }

    fn read_inline_blob(
        &self,
        digest: BlobDigest,
        loc: segment::BlobLoc,
    ) -> SynapseResult<Vec<u8>> {
        let f = self.segment_readers.get(&loc.segment).ok_or_else(|| {
            SynapseError::new(
                RefusalCode::BlobNotFound,
                format!("segment {} is not open for reads", loc.segment),
            )
        })?;
        let bytes = segment::read_at(f, loc.offset, loc.len).map_err(|e| {
            SynapseError::new(
                RefusalCode::BlobNotFound,
                format!("read blob {digest} from segment {}: {e}", loc.segment),
            )
        })?;
        let computed = BlobDigest::compute(&bytes);
        if computed != digest {
            return Err(SynapseError::new(
                RefusalCode::BlobDigestMismatch,
                format!("on-disk inline blob corruption for {digest}: computed {computed}"),
            ));
        }
        Ok(bytes)
    }

    /// Switch the store to the segment layout for good (ADR 0003 A2). Runs on open with
    /// `GroupCommit` for a v1 store, a new store, or a single-file WAL v2 store.
    ///
    /// First the segment index for the checkpoint on disk is written (replay from the
    /// start of segment 1, no entries: such checkpoints keep their blobs as files), then
    /// `wal.log` gets the segment marker, atomically: the current log (without a WAL v2
    /// marker at its end) plus the marker is written to `wal.log.tmp`, synced, and
    /// renamed over `wal.log`, then the directory is synced. A crash before the rename
    /// leaves the old store untouched (the stray files are overwritten next time); after
    /// it, the complete marker is in place. An in-place append could leave a torn
    /// 88-byte tail that strict recovery refuses.
    fn upgrade_to_segments(&mut self) -> SynapseResult<()> {
        for id in segment::list_segments(&self.root_dir)? {
            if id >= 2 && self.segment_has_data(id)? {
                return Err(SynapseError::new(
                    RefusalCode::WalVersionUnsupported,
                    format!("segment {id} holds data but wal.log has no segment marker"),
                ));
            }
        }
        let index = segment::SegmentIndex {
            binding: segment::checkpoint_binding(&self.root_dir)?,
            replay_segment: 1,
            replay_offset: 0,
            entries: BTreeMap::new(),
        };
        let keep = index.write(&self.root_dir)?;
        let (keep_len, seq, prev) = match self.log_layout {
            LogLayout::SingleFileV2 => {
                // Replace the WAL v2 marker (the last 88 bytes) with the segment marker
                // at the same chain position.
                let old = fs::read(&self.wal_path).map_err(io_err)?;
                let at = old.len() - WAL_HEADER_LEN;
                let seq = WalSeq(u64::from_le_bytes(old[at + 8..at + 16].try_into().unwrap()));
                let prev: [u8; 32] = old[at + 16..at + 48].try_into().unwrap();
                (at as u64, seq, prev)
            }
            _ => {
                let len = match fs::metadata(&self.wal_path) {
                    Ok(m) => m.len(),
                    Err(_) => 0,
                };
                (len, self.committed_seq, self.last_frame_sha256)
            }
        };
        let header = marker_header(segment::WAL_SEGMENT_MARKER_VERSION, seq, prev);
        let tmp = self.root_dir.join("wal.log.tmp");
        {
            let mut f = File::create(&tmp).map_err(io_err)?;
            if keep_len > 0 {
                let src = File::open(&self.wal_path).map_err(io_err)?;
                std::io::copy(&mut src.take(keep_len), &mut f).map_err(io_err)?;
            }
            f.write_all(&header).map_err(io_err)?;
            f.sync_all().map_err(io_err)?;
        }
        fs::rename(&tmp, &self.wal_path).map_err(io_err)?;
        sync_dir(&self.root_dir)?;
        segment::remove_other_indexes(&self.root_dir, &keep)?;
        self.v2_mode = true;
        self.log_layout = LogLayout::Segments;
        Ok(())
    }

    /// True when segment `id` exists and holds a non-zero byte.
    fn segment_has_data(&self, id: u64) -> SynapseResult<bool> {
        let path = self.root_dir.join(segment::segment_file_name(id));
        match fs::read(&path) {
            Ok(b) => Ok(b.iter().any(|x| *x != 0)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(io_err(e)),
        }
    }

    /// Open a read handle on every segment file up to the active one.
    fn open_segment_readers(&mut self) -> SynapseResult<()> {
        let last = self.wal_v2.as_ref().map_or(0, |w| w.active());
        for id in 1..=last {
            if self.segment_readers.contains_key(&id) {
                continue;
            }
            let path = self.root_dir.join(segment::segment_file_name(id));
            match File::open(&path) {
                Ok(f) => {
                    self.segment_readers.insert(id, f);
                }
                // Segments before the replay start may hold no retained blob; a missing
                // one only fails the reads that need it (BlobNotFound).
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(io_err(e)),
            }
        }
        Ok(())
    }

    /// Atomically replace `wal.log` with a file holding only the segment marker.
    fn replace_wal_log_with_segment_marker(&self) -> SynapseResult<()> {
        let header = marker_header(
            segment::WAL_SEGMENT_MARKER_VERSION,
            self.committed_seq,
            self.last_frame_sha256,
        );
        let tmp = self.root_dir.join("wal.log.tmp");
        {
            let mut f = File::create(&tmp).map_err(io_err)?;
            f.write_all(&header).map_err(io_err)?;
            f.sync_all().map_err(io_err)?;
        }
        fs::rename(&tmp, &self.wal_path).map_err(io_err)?;
        sync_dir(&self.root_dir)
    }

    /// Attach a machine evaluation receipt to an existing changeset.
    pub fn attach_evaluation(
        &mut self,
        changeset_id: ChangesetId,
        attachment: EvidenceAttachment,
    ) -> SynapseResult<WalSeq> {
        if !self.changesets.contains_key(&changeset_id) {
            return Err(SynapseError::new(
                RefusalCode::ChangesetNotFound,
                format!("changeset {changeset_id} not found"),
            ));
        }
        let record = WalRecord::EvaluationAttached {
            changeset_id,
            attachment,
        };
        let (seq, _, _) = self.append_wal_record(&record)?;
        self.apply_record(seq, record);
        Ok(seq)
    }

    /// Record a review verdict on an existing changeset.
    pub fn record_review(
        &mut self,
        changeset_id: ChangesetId,
        review: ReviewRecord,
    ) -> SynapseResult<WalSeq> {
        let cs = self.changesets.get(&changeset_id).ok_or_else(|| {
            SynapseError::new(
                RefusalCode::ChangesetNotFound,
                format!("changeset {changeset_id} not found"),
            )
        })?;
        if cs.envelope.author_did == review.reviewer_did {
            return Err(SynapseError::new(
                RefusalCode::AuthSelfReviewRefused,
                "author cannot review their own changeset",
            ));
        }
        let record = WalRecord::ReviewRecorded {
            changeset_id,
            review,
        };
        let (seq, _, _) = self.append_wal_record(&record)?;
        self.apply_record(seq, record);
        Ok(seq)
    }

    /// Record a human-facing GitHub Pull Request projection.
    pub fn record_github_projection(
        &mut self,
        projection: GitHubPullRequestProjection,
    ) -> SynapseResult<WalSeq> {
        if !self.changesets.contains_key(&projection.changeset_id) {
            return Err(SynapseError::new(
                RefusalCode::ChangesetNotFound,
                format!("changeset {} not found", projection.changeset_id),
            ));
        }
        let record = WalRecord::GitProjected { projection };
        let (seq, _, _) = self.append_wal_record(&record)?;
        self.apply_record(seq, record);
        Ok(seq)
    }

    /// Record a verified `RadicleCanonicalHead` receipt.
    pub fn record_canonical_promotion(
        &mut self,
        canonical: RadicleCanonicalHead,
    ) -> SynapseResult<WalSeq> {
        if let Some(cs_id) = canonical.promoted_changeset_id {
            if !self.changesets.contains_key(&cs_id) {
                return Err(SynapseError::new(
                    RefusalCode::ChangesetNotFound,
                    format!("promoted changeset {cs_id} not found"),
                ));
            }
        }
        let record = WalRecord::CanonicalPromoted { canonical };
        let (seq, _, _) = self.append_wal_record(&record)?;
        self.apply_record(seq, record);
        Ok(seq)
    }

    /// Update the active evaluation/integration lease timestamp on a changeset.
    pub fn update_lease(
        &mut self,
        changeset_id: ChangesetId,
        lease_expires_at_ms: u64,
    ) -> SynapseResult<WalSeq> {
        if !self.changesets.contains_key(&changeset_id) {
            return Err(SynapseError::new(
                RefusalCode::ChangesetNotFound,
                format!("changeset {changeset_id} not found"),
            ));
        }
        let record = WalRecord::LeaseUpdated {
            changeset_id,
            lease_expires_at_ms,
        };
        let (seq, _, _) = self.append_wal_record(&record)?;
        self.apply_record(seq, record);
        Ok(seq)
    }

    /// Read a committed changeset respecting `min_visible_seq` (read-your-writes) and `snapshot_seq`.
    pub fn get_changeset(
        &self,
        changeset_id: ChangesetId,
        min_visible_seq: Option<WalSeq>,
        snapshot_seq: Option<WalSeq>,
    ) -> SynapseResult<StoredChangeset> {
        let effective_snapshot = self.resolve_snapshot_seq(min_visible_seq, snapshot_seq)?;
        let stored = self.changesets.get(&changeset_id).ok_or_else(|| {
            SynapseError::new(
                RefusalCode::ChangesetNotFound,
                format!("changeset {changeset_id} not found"),
            )
        })?;
        if stored.committed_seq > effective_snapshot {
            return Err(SynapseError::new(
                RefusalCode::ChangesetNotFound,
                format!(
                    "changeset {changeset_id} committed at {} is not visible at snapshot {}",
                    stored.committed_seq, effective_snapshot
                ),
            ));
        }
        Ok(stored.clone())
    }

    /// Read an immutable blob ONLY if it is associated with a WAL commit at `<= snapshot_seq`,
    /// recomputing its `BlobDigest` on read to detect disk corruption.
    pub fn get_blob_visible(
        &self,
        digest: BlobDigest,
        min_visible_seq: Option<WalSeq>,
        snapshot_seq: Option<WalSeq>,
    ) -> SynapseResult<Vec<u8>> {
        let effective_snapshot = self.resolve_snapshot_seq(min_visible_seq, snapshot_seq)?;
        let visible_at = self
            .blob_first_visible_seq
            .get(&digest)
            .copied()
            .ok_or_else(|| {
                SynapseError::new(
                    RefusalCode::BlobNotFound,
                    format!("blob {digest} is not committed in the WAL"),
                )
            })?;
        if visible_at > effective_snapshot {
            return Err(SynapseError::new(
                RefusalCode::BlobNotFound,
                format!(
                    "blob {digest} committed at {visible_at} not visible at {effective_snapshot}"
                ),
            ));
        }
        if let Some(&loc) = self.blob_locations.get(&digest) {
            return self.read_inline_blob(digest, loc);
        }
        let path = self.blob_path(digest);
        let bytes = fs::read(&path).map_err(|_| {
            SynapseError::new(
                RefusalCode::BlobNotFound,
                format!("blob file missing on disk for {digest}"),
            )
        })?;
        let computed = BlobDigest::compute(&bytes);
        if computed != digest {
            return Err(SynapseError::new(
                RefusalCode::BlobDigestMismatch,
                format!("on-disk blob corruption for {digest}: computed {computed}"),
            ));
        }
        Ok(bytes)
    }

    /// List all committed changesets visible at `snapshot_seq`, ordered by `committed_seq`.
    pub fn list_changesets(
        &self,
        repo_id: Option<&RepoId>,
        min_visible_seq: Option<WalSeq>,
        snapshot_seq: Option<WalSeq>,
    ) -> SynapseResult<Vec<StoredChangeset>> {
        let effective_snapshot = self.resolve_snapshot_seq(min_visible_seq, snapshot_seq)?;
        let mut list: Vec<StoredChangeset> = self
            .changesets
            .values()
            .filter(|cs| {
                cs.committed_seq <= effective_snapshot
                    && repo_id.is_none_or(|r| &cs.envelope.repo_id == r)
            })
            .cloned()
            .collect();
        list.sort_by_key(|cs| cs.committed_seq);
        Ok(list)
    }

    /// Return the current verified `RadicleCanonicalHead` for `repo_id`, if any.
    pub fn canonical_head(&self, repo_id: &RepoId) -> Option<&RadicleCanonicalHead> {
        self.canonical_heads.get(repo_id)
    }

    /// Return all recorded `GitHubPullRequestProjection` entries.
    pub fn github_projections(&self) -> &BTreeMap<u64, GitHubPullRequestProjection> {
        &self.github_projections
    }

    /// Compute a deterministic SHA-256 digest of all visible state up to `snapshot_seq`.
    pub fn state_root_digest(&self, snapshot_seq: Option<WalSeq>) -> SynapseResult<[u8; 32]> {
        let snap = self.resolve_snapshot_seq(None, snapshot_seq)?;
        Ok(codec::state_root_of(
            &self.changesets,
            self.revisions.log(),
            snap,
        ))
    }

    /// Write an atomic checkpoint, compact `wal.log`, and sweep unreferenced speculative blobs
    /// outside active `GarbageRoot`s.
    pub fn checkpoint_and_compact(&mut self, now_ms: u64) -> SynapseResult<CompactionReport> {
        self.check_writable()?;
        // The last v1 state root, taken before eviction changes the state (used only by a
        // v1 store's migration checkpoint).
        let v1_state_root_at_entry = self.state_root_digest(None)?;
        // 1. Identify garbage roots:
        //    - Canonical head changeset lineages
        //    - Open (non-merged) or merged GitHub PR projection changeset lineages
        //    - Changesets with active lease `lease_expires_at_ms > now_ms`
        //    - Changesets within `default_retention_window_ms`
        let mut retained_cs: BTreeSet<ChangesetId> = BTreeSet::new();
        let mut worklist: Vec<ChangesetId> = Vec::new();

        for canon in self.canonical_heads.values() {
            if let Some(cs_id) = canon.promoted_changeset_id {
                worklist.push(cs_id);
            }
        }
        for proj in self.github_projections.values() {
            worklist.push(proj.changeset_id);
        }
        for (cs_id, stored) in &self.changesets {
            let within_window = now_ms.saturating_sub(stored.envelope.created_at_ms)
                <= self.limits.default_retention_window_ms;
            let active_lease = stored.lease_expires_at_ms > now_ms;
            if within_window || active_lease {
                worklist.push(*cs_id);
            }
        }

        // Revisions are never evicted (no sweep before K1), so their v1 parents stay too.
        for rev in self.revisions.revisions() {
            worklist.extend(rev.content.parents.iter().copied());
        }

        // Compute transitive ancestor closure over `parent_changesets`
        while let Some(cs_id) = worklist.pop() {
            if retained_cs.insert(cs_id) {
                if let Some(stored) = self.changesets.get(&cs_id) {
                    for parent in &stored.envelope.parent_changesets {
                        worklist.push(*parent);
                    }
                }
            }
        }

        let total_before = self.changesets.len();
        self.changesets.retain(|id, _| retained_cs.contains(id));
        let evicted_changesets = total_before.saturating_sub(self.changesets.len());

        self.idempotency_index
            .retain(|_, (_, cs_id)| retained_cs.contains(cs_id));

        // 2. Compute retained blob closure from retained changesets
        let mut retained_blobs: BTreeSet<BlobDigest> = BTreeSet::new();
        for rev in self.revisions.revisions() {
            retained_blobs.extend(rev.content.referenced_blobs());
        }
        for stored in self.changesets.values() {
            for m in &stored.envelope.mutations {
                if let MutationOp::Upsert { blob_digest, .. } = &m.op {
                    retained_blobs.insert(*blob_digest);
                }
            }
        }
        self.blob_first_visible_seq
            .retain(|digest, _| retained_blobs.contains(digest));

        // 2b. Segment store (ADR 0003 A2): retained blobs stay where they are, inside
        //     the segments; the segment index written below records their locations.
        //     No blob file is written and no segment byte is removed (no garbage
        //     collection of segment data before step K1).

        // 3. Persist the atomic binary checkpoint `checkpoint.v2`. Every logged frame is
        //    made durable first, so frames the checkpoint covers are never torn if the
        //    process dies before `wal.log` is replaced (recovery verifies and skips them;
        //    in the segment layout the segment index vouches for the covered prefix).
        //    The first binary checkpoint records the last v1 state root (or the empty
        //    root for a store that never wrote v1) and chains its own root to it; every
        //    later one chains to the previous checkpoint root.
        //    Unverified kind 9 records (kept as no-ops only under `TruncateTornTail`) are left
        //    out (review of PR #100): they change no state, and carrying them would make
        //    strict recovery refuse the store forever. The ledger is rebuilt without them
        //    only once the checkpoint is durable; the replay report counts them. In a sealed
        //    store (issue #101) the same holds for revision records whose seal does not
        //    verify; sealed records always stay, so the seal chain stays whole.
        self.sync_wal()?;
        let revision::CompactedRevisionLog {
            log: revision_log,
            dropped_moves,
            dropped_unsealed,
        } = self.revisions.compacted_log();
        let (v1_state_root, prev_checkpoint_root) = match self.checkpoint_chain {
            Some(c) => (c.v1_state_root, c.checkpoint_root),
            None if self.v1_history => (v1_state_root_at_entry, v1_state_root_at_entry),
            None => (codec::empty_state_root(), codec::empty_state_root()),
        };
        let state = CheckpointState {
            checkpoint_seq: self.committed_seq,
            anchor_frame_sha256: self.last_frame_sha256,
            changesets: std::mem::take(&mut self.changesets),
            idempotency_index: std::mem::take(&mut self.idempotency_index),
            blob_first_visible_seq: std::mem::take(&mut self.blob_first_visible_seq),
            github_projections: std::mem::take(&mut self.github_projections),
            canonical_heads: std::mem::take(&mut self.canonical_heads),
            revision_log,
        };
        let encoded = codec::encode_checkpoint_v2(&state, v1_state_root, prev_checkpoint_root);
        self.changesets = state.changesets;
        self.idempotency_index = state.idempotency_index;
        self.blob_first_visible_seq = state.blob_first_visible_seq;
        self.github_projections = state.github_projections;
        self.canonical_heads = state.canonical_heads;
        let revision_log = state.revision_log;
        let (bytes, chain) = encoded?;
        // Read back what will be written: it must decode to the same chain and root (the
        // live state, less any unverified kind 9 records left out above).
        let snap = self.resolve_snapshot_seq(None, None)?;
        let expected_root = codec::state_root_of(&self.changesets, &revision_log, snap);
        let (_, check) = codec::decode_checkpoint_v2(&bytes)?;
        if check != chain || chain.state_root != expected_root {
            return Err(SynapseError::new(
                RefusalCode::CheckpointCorrupt,
                "checkpoint.v2 does not decode back to the state it was written from",
            ));
        }
        // Segment store: the index bound to this checkpoint's exact bytes goes first. A
        // crash before the checkpoint rename leaves the previous checkpoint and its own
        // index (removed only below, after this checkpoint is durable).
        let segment_index = if self.v2_mode {
            let log = self.wal_v2.as_ref().ok_or_else(|| {
                SynapseError::new(RefusalCode::IoFailure, "WAL v2 writer is not available")
            })?;
            let index = segment::SegmentIndex {
                binding: segment::binding_of(Some((codec::CHECKPOINT_V2_FILE, &bytes))),
                replay_segment: log.active(),
                replay_offset: log.write_offset(),
                entries: self
                    .blob_locations
                    .iter()
                    .filter(|(d, _)| retained_blobs.contains(d))
                    .map(|(d, l)| (*d, *l))
                    .collect(),
            };
            let name = index.write(&self.root_dir)?;
            if self.fault_injection == FaultInjection::CrashAfterSegmentIndexBeforeCheckpoint {
                std::process::exit(FAULT_CRASH_EXIT_CODE);
            }
            Some((name, index))
        } else {
            None
        };
        write_file_atomic(
            &self.root_dir,
            &self.root_dir.join("checkpoint.v2.tmp"),
            &self.root_dir.join(codec::CHECKPOINT_V2_FILE),
            &bytes,
        )?;
        self.checkpoint_chain = Some(chain);
        if dropped_moves + dropped_unsealed > 0 {
            self.revisions
                .rebuild_after_compaction(revision::CompactedRevisionLog {
                    log: revision_log,
                    dropped_moves,
                    dropped_unsealed,
                });
        }
        self.codec = RecordCodec::BinaryV2;
        self.binary_seen = true;
        // checkpoint.v1 becomes the tombstone only after checkpoint.v2 is durable.
        self.write_v1_tombstone()?;

        // 4. Compact `wal.log` (truncate to empty since all state up to `checkpoint_seq` is in `checkpoint.v2`)
        if let Some((name, index)) = segment_index {
            // Segment store: `wal.log` keeps only the segment marker (so older binaries
            // still refuse the store); the segments are kept whole, replay starts at the
            // index's position, and older index files are removed.
            self.replace_wal_log_with_segment_marker()?;
            segment::remove_other_indexes(&self.root_dir, &name)?;
            self.blob_locations = index.entries;
        } else {
            let f = OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(&self.wal_path)
                .map_err(io_err)?;
            f.sync_all().map_err(io_err)?;
        }
        sync_dir(&self.root_dir)?;
        self.unflushed_frames = 0;

        // 5. Sweep unreferenced blobs on disk (including orphan blobs from pre-WAL crashes)
        let swept_blob_files = self.sweep_unreferenced_blobs(&retained_blobs)?;

        Ok(CompactionReport {
            checkpoint_seq: self.committed_seq,
            anchor_frame_sha256: self.last_frame_sha256,
            retained_changesets: self.changesets.len(),
            evicted_changesets,
            retained_blobs: retained_blobs.len(),
            swept_blob_files,
        })
    }

    fn resolve_snapshot_seq(
        &self,
        min_visible_seq: Option<WalSeq>,
        snapshot_seq: Option<WalSeq>,
    ) -> SynapseResult<WalSeq> {
        if let Some(min_seq) = min_visible_seq {
            if min_seq > self.committed_seq {
                return Err(SynapseError::new(
                    RefusalCode::VisibilitySeqAhead,
                    format!(
                        "requested min_visible_seq {} exceeds committed_seq {}",
                        min_seq, self.committed_seq
                    ),
                ));
            }
        }
        if let Some(snap) = snapshot_seq {
            if snap > self.committed_seq {
                return Err(SynapseError::new(
                    RefusalCode::VisibilitySeqAhead,
                    format!(
                        "requested snapshot_seq {} exceeds committed_seq {}",
                        snap, self.committed_seq
                    ),
                ));
            }
            if let Some(min_seq) = min_visible_seq {
                if snap < min_seq {
                    return Err(SynapseError::new(
                        RefusalCode::VisibilitySeqAhead,
                        format!("snapshot_seq {snap} is older than min_visible_seq {min_seq}"),
                    ));
                }
            }
            Ok(snap)
        } else {
            Ok(self.committed_seq)
        }
    }

    fn blob_path(&self, digest: BlobDigest) -> PathBuf {
        let hex = digest.to_hex();
        self.blobs_dir.join(&hex[0..2]).join(&hex)
    }

    fn write_blob_file(&self, digest: BlobDigest, bytes: &[u8]) -> SynapseResult<()> {
        let final_path = self.blob_path(digest);
        if final_path.exists() {
            let existing = fs::read(&final_path).map_err(io_err)?;
            let existing_digest = BlobDigest::compute(&existing);
            if existing_digest != digest || existing.as_slice() != bytes {
                return Err(SynapseError::new(
                    RefusalCode::BlobImmutableConflict,
                    format!("on-disk blob {digest} conflicts with immutable content"),
                ));
            }
            if self.syncs_blob_files() {
                // The file may be left over from a crash before its WAL frame (never
                // synced); make it durable before a frame that references it is.
                File::open(&final_path)
                    .and_then(|f| f.sync_all())
                    .map_err(io_err)?;
                sync_dir(final_path.parent().expect("blob shard parent"))?;
            }
            return Ok(());
        }
        let shard_dir = final_path.parent().expect("blob shard parent");
        if !shard_dir.exists() {
            fs::create_dir_all(shard_dir).map_err(io_err)?;
            if self.syncs_blob_files() {
                sync_dir(&self.blobs_dir)?;
            }
        }
        let tmp_path = shard_dir.join(format!("{}.tmp.{}", digest.to_hex(), std::process::id()));
        {
            let mut f = File::create(&tmp_path).map_err(io_err)?;
            f.write_all(bytes).map_err(io_err)?;
            if self.syncs_blob_files() {
                f.sync_all().map_err(io_err)?;
            }
        }
        fs::rename(&tmp_path, &final_path).map_err(io_err)?;
        if self.syncs_blob_files() {
            sync_dir(shard_dir)?;
        }
        Ok(())
    }

    /// Blob files are synced under `EveryCommit` and when `GroupCommit` compaction moves
    /// inline blobs out of the log.
    fn syncs_blob_files(&self) -> bool {
        matches!(
            self.fsync_policy,
            FsyncPolicy::EveryCommit | FsyncPolicy::GroupCommit { .. }
        )
    }

    fn sweep_unreferenced_blobs(
        &self,
        retained_blobs: &BTreeSet<BlobDigest>,
    ) -> SynapseResult<usize> {
        let mut swept = 0usize;
        if !self.blobs_dir.exists() {
            return Ok(0);
        }
        for shard_entry in fs::read_dir(&self.blobs_dir).map_err(io_err)? {
            let shard_entry = shard_entry.map_err(io_err)?;
            let shard_path = shard_entry.path();
            if !shard_path.is_dir() {
                continue;
            }
            for file_entry in fs::read_dir(&shard_path).map_err(io_err)? {
                let file_entry = file_entry.map_err(io_err)?;
                let file_path = file_entry.path();
                let name = file_entry.file_name();
                let name_str = name.to_string_lossy();
                let should_remove = if name_str.contains(".tmp.") {
                    true
                } else if let Ok(digest) = BlobDigest::from_hex(&name_str) {
                    !retained_blobs.contains(&digest)
                } else {
                    false
                };
                if should_remove {
                    fs::remove_file(&file_path).map_err(io_err)?;
                    swept += 1;
                }
            }
        }
        Ok(swept)
    }

    /// Refuse a WAL payload above `StoreLimits::max_wal_record_bytes` (replay would refuse it).
    fn check_frame_cap(&self, payload_len: usize) -> SynapseResult<()> {
        if payload_len as u64 > self.limits.max_wal_record_bytes {
            return Err(SynapseError::new(
                RefusalCode::QuotaPayloadTooLarge,
                format!(
                    "WAL record of {payload_len} bytes exceeds max_wal_record_bytes {}",
                    self.limits.max_wal_record_bytes
                ),
            ));
        }
        Ok(())
    }

    /// `record` as a `wal.log` payload in this store's codec, checked against the cap.
    fn encode_v1_payload(&self, record: &WalRecord) -> SynapseResult<Vec<u8>> {
        let payload = codec::encode_record_with(record, self.codec)?;
        self.check_frame_cap(payload.len())?;
        Ok(payload)
    }

    /// Bring a prepared WAL v2 payload to this store's codec (it changes once, at the
    /// migration checkpoint, possibly between prepare and commit) and check the cap.
    pub(crate) fn conform_v2(&self, p: &mut PreparedIngest) -> SynapseResult<()> {
        let enc = p.encoded.as_ref().ok_or_else(|| {
            SynapseError::new(
                RefusalCode::IoFailure,
                "changeset was prepared for WAL v1 but the store writes WAL v2",
            )
        })?;
        if enc.codec() != self.codec {
            let recoded = enc.recode(&p.record(), self.codec)?;
            p.encoded = Some(recoded);
        }
        self.check_frame_cap(p.encoded.as_ref().map_or(0, |e| e.payload.len()))
    }

    fn append_wal_record(
        &mut self,
        record: &WalRecord,
    ) -> SynapseResult<(WalSeq, [u8; 32], DurabilityGuarantee)> {
        if self.v2_mode {
            let encoded = wal2::encode_record(record, &[], self.codec)?;
            self.check_frame_cap(encoded.payload.len())?;
            let mut ticket = self.v2_begin()?;
            let result = Self::v2_write(&mut ticket, &[&encoded]);
            let placed = self.v2_finish(ticket, result)?;
            return Ok((
                placed[0].seq,
                placed[0].frame_sha256,
                DurabilityGuarantee::FsyncBeforeAck,
            ));
        }
        let payload = self.encode_v1_payload(record)?;
        self.append_v1_payload(record.kind_byte(), &payload)
    }

    fn append_v1_payload(
        &mut self,
        kind: u8,
        payload: &[u8],
    ) -> SynapseResult<(WalSeq, [u8; 32], DurabilityGuarantee)> {
        let fault = std::mem::replace(&mut self.fault_injection, FaultInjection::None);

        let next_seq = match fault {
            FaultInjection::InjectNextWalSequenceGap => self.committed_seq.next().next(),
            FaultInjection::InjectDuplicateWalSequence => self.committed_seq,
            _ => self.committed_seq.next(),
        };

        let mut prev_sha = self.last_frame_sha256;
        if fault == FaultInjection::CorruptNextWalChain {
            prev_sha[0] ^= 0xff;
        }

        let mut crc = crc32c(payload);
        if fault == FaultInjection::CorruptNextWalCrc {
            crc ^= 0xdead_beef;
        }

        let mut header_prefix = [0u8; 56];
        header_prefix[0..4].copy_from_slice(&WAL_MAGIC);
        header_prefix[4..6].copy_from_slice(&WAL_VERSION.to_le_bytes());
        header_prefix[6] = kind;
        header_prefix[7] = self.codec.frame_flags();
        header_prefix[8..16].copy_from_slice(&next_seq.0.to_le_bytes());
        header_prefix[16..48].copy_from_slice(&prev_sha);
        header_prefix[48..52].copy_from_slice(&(payload.len() as u32).to_le_bytes());
        header_prefix[52..56].copy_from_slice(&crc.to_le_bytes());

        let frame_sha256 = compute_wal_frame_sha256(&header_prefix, payload);
        let mut header = [0u8; WAL_HEADER_LEN];
        header[0..56].copy_from_slice(&header_prefix);
        header[56..88].copy_from_slice(&frame_sha256);

        let mut f = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.wal_path)
            .map_err(io_err)?;

        match fault {
            FaultInjection::TornWalHeaderWrite { bytes_written } => {
                let n = bytes_written.min(WAL_HEADER_LEN - 1);
                f.write_all(&header[..n]).map_err(io_err)?;
                f.sync_all().map_err(io_err)?;
                return Err(SynapseError::new(
                    RefusalCode::WalTornFrame,
                    "injected fault: torn WAL header write",
                ));
            }
            FaultInjection::TornWalPayloadWrite { bytes_written } => {
                let n = bytes_written.min(payload.len().saturating_sub(1));
                f.write_all(&header).map_err(io_err)?;
                f.write_all(&payload[..n]).map_err(io_err)?;
                f.sync_all().map_err(io_err)?;
                return Err(SynapseError::new(
                    RefusalCode::WalTornFrame,
                    "injected fault: torn WAL payload write",
                ));
            }
            _ => {
                f.write_all(&header).map_err(io_err)?;
                f.write_all(payload).map_err(io_err)?;
            }
        }

        let durability = match self.fsync_policy {
            // GroupCommit stores always write WAL v2 (handled above); syncing here keeps
            // the guarantee if that invariant were ever broken.
            FsyncPolicy::EveryCommit | FsyncPolicy::GroupCommit { .. } => {
                f.sync_all().map_err(io_err)?;
                self.unflushed_frames = 0;
                DurabilityGuarantee::FsyncBeforeAck
            }
            FsyncPolicy::BatchWindow { max_records } => {
                self.unflushed_frames = self.unflushed_frames.saturating_add(1);
                if self.unflushed_frames >= max_records.max(1) {
                    f.sync_all().map_err(io_err)?;
                    self.unflushed_frames = 0;
                    DurabilityGuarantee::FsyncBeforeAck
                } else {
                    f.flush().map_err(io_err)?;
                    DurabilityGuarantee::ProcessCrashPageCacheOnly
                }
            }
        };

        self.committed_seq = next_seq;
        self.last_frame_sha256 = frame_sha256;
        Ok((next_seq, frame_sha256, durability))
    }

    fn apply_record(&mut self, seq: WalSeq, record: WalRecord) {
        match record {
            WalRecord::ChangesetIngest {
                envelope,
                changeset_id,
                new_blobs,
            } => {
                for digest in new_blobs {
                    self.blob_first_visible_seq.entry(digest).or_insert(seq);
                }
                for m in &envelope.mutations {
                    if let MutationOp::Upsert { blob_digest, .. } = &m.op {
                        self.blob_first_visible_seq
                            .entry(*blob_digest)
                            .or_insert(seq);
                    }
                }
                self.idempotency_index.insert(
                    (envelope.repo_id.clone(), envelope.idempotency_key),
                    (seq, changeset_id),
                );
                self.changesets.insert(
                    changeset_id,
                    StoredChangeset {
                        changeset_id,
                        committed_seq: seq,
                        envelope,
                        evaluations: Vec::new(),
                        reviews: Vec::new(),
                        lease_expires_at_ms: 0,
                    },
                );
            }
            WalRecord::EvaluationAttached {
                changeset_id,
                attachment,
            } => {
                if let Some(cs) = self.changesets.get_mut(&changeset_id) {
                    cs.evaluations.push(attachment);
                }
            }
            WalRecord::ReviewRecorded {
                changeset_id,
                review,
            } => {
                if let Some(cs) = self.changesets.get_mut(&changeset_id) {
                    cs.reviews.push(review);
                }
            }
            WalRecord::GitProjected { projection } => {
                self.github_projections
                    .insert(projection.pr_number, projection);
            }
            WalRecord::CanonicalPromoted { canonical } => {
                self.canonical_heads
                    .insert(canonical.repo_id.clone(), canonical);
            }
            WalRecord::LeaseUpdated {
                changeset_id,
                lease_expires_at_ms,
            } => {
                if let Some(cs) = self.changesets.get_mut(&changeset_id) {
                    cs.lease_expires_at_ms = lease_expires_at_ms;
                }
            }
            record @ WalRecord::RevisionAdmitted { .. }
                if !self.revisions.accepts(seq, &record) =>
            {
                self.revisions.apply(seq, record);
            }
            record @ WalRecord::RevisionAdmitted { .. } => {
                if let WalRecord::RevisionAdmitted { new_blobs, .. } = &record {
                    for digest in new_blobs {
                        self.blob_first_visible_seq.entry(*digest).or_insert(seq);
                    }
                }
                for digest in record.upsert_blobs() {
                    self.blob_first_visible_seq.entry(digest).or_insert(seq);
                }
                self.revisions.apply(seq, record);
            }
            record @ (WalRecord::ObsolescenceRecorded { .. }
            | WalRecord::RevisionStateMoved { .. }) => self.revisions.apply(seq, record),
            record @ WalRecord::DerivedRevisionAdmitted { .. }
                if !self.revisions.accepts(seq, &record) =>
            {
                self.revisions.apply(seq, record);
            }
            record @ WalRecord::DerivedRevisionAdmitted { .. } => {
                for digest in record.upsert_blobs() {
                    self.blob_first_visible_seq.entry(digest).or_insert(seq);
                }
                self.revisions.apply(seq, record);
            }
        }
    }

    fn recover(&mut self, recovery_policy: RecoveryPolicy) -> SynapseResult<()> {
        // 1. Load the checkpoint: checkpoint.v2 (binary, chained) when present, else
        //    checkpoint.v1 (JSON). Once checkpoint.v2 exists, checkpoint.v1 is the
        //    tombstone that makes binaries knowing only v1 refuse the store.
        let v2_path = self.root_dir.join(codec::CHECKPOINT_V2_FILE);
        if v2_path.exists() {
            let raw = fs::read(&v2_path).map_err(io_err)?;
            let (state, chain) = codec::decode_checkpoint_v2(&raw)?;
            if self.checkpoint_path.exists() {
                let v1 = fs::read(&self.checkpoint_path).map_err(io_err)?;
                if v1 != codec::v1_tombstone_bytes() {
                    // A crash between writing checkpoint.v2 and the tombstone leaves the
                    // older v1 checkpoint; it must not be ahead of checkpoint.v2.
                    let m: CheckpointManifest = serde_json::from_slice(&v1).map_err(|e| {
                        SynapseError::new(
                            RefusalCode::CheckpointCorrupt,
                            format!("corrupt checkpoint.v1 next to checkpoint.v2: {e}"),
                        )
                    })?;
                    if m.version != CHECKPOINT_VERSION || m.checkpoint_seq > chain.checkpoint_seq {
                        return Err(SynapseError::new(
                            RefusalCode::CheckpointCorrupt,
                            "checkpoint.v1 is neither the tombstone nor older than checkpoint.v2",
                        ));
                    }
                    self.tombstone_pending = true;
                }
            } else {
                self.tombstone_pending = true;
            }
            self.load_checkpoint_state(state);
            self.checkpoint_chain = Some(chain);
            self.binary_seen = true;
        } else if self.checkpoint_path.exists() {
            let raw = fs::read(&self.checkpoint_path).map_err(io_err)?;
            if raw == codec::v1_tombstone_bytes() {
                return Err(SynapseError::new(
                    RefusalCode::CheckpointCorrupt,
                    "checkpoint.v1 is the v2 tombstone but checkpoint.v2 is missing",
                ));
            }
            let manifest: CheckpointManifest = serde_json::from_slice(&raw).map_err(|e| {
                SynapseError::new(
                    RefusalCode::CheckpointCorrupt,
                    format!("corrupt checkpoint.v1: {e}"),
                )
            })?;
            self.load_checkpoint_state(CheckpointState::from_v1_manifest(manifest)?);
            self.v1_history = true;
        }

        // 2. Replay wal.log (v1 frames, possibly ending in the WAL v2 marker), then wal.v2.log.
        //    Frames the checkpoint already covers (a crash after the checkpoint rename and
        //    before the logs were emptied) are verified and skipped. In the segment layout
        //    (ADR 0003 A2) replay of the segments starts at the segment index position.
        let mut overlap = CheckpointOverlap::default();
        if self.wal_path.exists() {
            self.recover_v1(recovery_policy, &mut overlap)?;
        }
        self.recover_v2(recovery_policy, &mut overlap)?;
        overlap.close(self.committed_seq, self.last_frame_sha256)?;

        // 3. A state move that does not verify was written without the mover's key: the
        //    unkeyed seal cannot tell a forgery from a store's write, so strict recovery
        //    refuses the store instead of hiding it as a no-op (issue #89). It checks the
        //    records themselves, so a forgery inside a resealed checkpoint is refused too.
        if recovery_policy == RecoveryPolicy::StrictFailClosed {
            // Issue #101: in a sealed store, a revision record whose seal does not verify
            // against the chain so far was written, changed, moved, or followed by a removal
            // without the server key.
            let seals = self.revisions.seal_report();
            if let Some(seq) = seals.first_unsealed {
                return Err(SynapseError::new(
                    RefusalCode::RevisionRecordUnsealed,
                    format!(
                        "{} revision record(s) are not sealed by the store's seal key (first at {seq}); strict recovery refuses the store (open it with TruncateTornTail and run checkpoint_and_compact to drop them)",
                        seals.unsealed
                    ),
                ));
            }
            let report = self.revisions.state_move_report();
            if let Some((seq, fault)) = report.first_unverified {
                return Err(SynapseError::new(
                    RefusalCode::RevisionStateMoveUnverified,
                    format!(
                        "{} WAL kind 9 state move(s) do not verify (first at {seq}: {fault:?}); strict recovery refuses the store (open it with TruncateTornTail and run checkpoint_and_compact to drop them)",
                        report.unverified()
                    ),
                ));
            }
        }

        // 4. A store with v1 history keeps writing v1 JSON until its first binary
        //    checkpoint (the migration checkpoint); every other store writes binary v2.
        self.codec = if self.checkpoint_chain.is_some() || !self.v1_history {
            RecordCodec::BinaryV2
        } else {
            RecordCodec::JsonV1
        };
        Ok(())
    }

    fn load_checkpoint_state(&mut self, s: CheckpointState) {
        self.committed_seq = s.checkpoint_seq;
        self.last_frame_sha256 = s.anchor_frame_sha256;
        self.changesets = s.changesets;
        self.idempotency_index = s.idempotency_index;
        self.blob_first_visible_seq = s.blob_first_visible_seq;
        self.github_projections = s.github_projections;
        self.canonical_heads = s.canonical_heads;
        self.revisions = revision::RevisionLedger::from_log(
            s.revision_log,
            self.revision_seal.as_ref().map(RevisionSealKey::public_key),
        );
    }

    /// Admit a replayed (not checkpoint-covered) frame written with `codec`: the codec
    /// moves from v1 JSON to binary v2 only at the migration checkpoint, never back.
    fn admit_replayed_codec(&mut self, codec: RecordCodec, seq: WalSeq) -> SynapseResult<()> {
        match codec {
            RecordCodec::JsonV1 if self.binary_seen => Err(SynapseError::new(
                RefusalCode::WalVersionUnsupported,
                format!("v1 JSON WAL record at {seq} after binary v2 records"),
            )),
            RecordCodec::JsonV1 => {
                self.v1_history = true;
                Ok(())
            }
            RecordCodec::BinaryV2 if self.v1_history && self.checkpoint_chain.is_none() => {
                Err(SynapseError::new(
                    RefusalCode::WalVersionUnsupported,
                    format!(
                        "binary v2 WAL record at {seq} in a v1 store before its migration checkpoint"
                    ),
                ))
            }
            RecordCodec::BinaryV2 => {
                self.binary_seen = true;
                Ok(())
            }
        }
    }

    /// Replace `checkpoint.v1` with the tombstone (atomic: temp file, sync, rename, sync).
    fn write_v1_tombstone(&mut self) -> SynapseResult<()> {
        write_file_atomic(
            &self.root_dir,
            &self.root_dir.join("checkpoint.v1.tmp"),
            &self.checkpoint_path,
            &codec::v1_tombstone_bytes(),
        )?;
        self.tombstone_pending = false;
        Ok(())
    }

    fn recover_v1(
        &mut self,
        recovery_policy: RecoveryPolicy,
        overlap: &mut CheckpointOverlap,
    ) -> SynapseResult<()> {
        let mut f = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&self.wal_path)
            .map_err(io_err)?;
        let file_len = f.metadata().map_err(io_err)?.len();
        let mut offset = 0u64;

        while offset < file_len {
            let remaining = file_len - offset;
            if remaining < WAL_HEADER_LEN as u64 {
                return self.handle_torn_tail(&mut f, offset, recovery_policy, "torn WAL header");
            }

            let mut header = [0u8; WAL_HEADER_LEN];
            f.seek(SeekFrom::Start(offset)).map_err(io_err)?;
            f.read_exact(&mut header).map_err(io_err)?;

            if header[0..4] != WAL_MAGIC {
                return Err(SynapseError::new(
                    RefusalCode::WalMagicInvalid,
                    format!("invalid WAL magic at byte offset {offset}"),
                ));
            }
            let version = u16::from_le_bytes(header[4..6].try_into().unwrap());
            let marker_version =
                version == wal2::WAL_V2_VERSION || version == segment::WAL_SEGMENT_MARKER_VERSION;
            if marker_version && header[6] == WAL_V2_MARKER_KIND {
                // Log marker: the log continues in wal.v2.log (version 2) or in the
                // segments (version 3). It must be the last frame, continue the chain
                // without advancing it, and hash correctly.
                if offset + WAL_HEADER_LEN as u64 != file_len {
                    return Err(SynapseError::new(
                        RefusalCode::WalMagicInvalid,
                        format!("unexpected bytes after the WAL v2 marker at offset {offset}"),
                    ));
                }
                let seq = WalSeq(u64::from_le_bytes(header[8..16].try_into().unwrap()));
                let marker_prev: [u8; 32] = header[16..48].try_into().unwrap();
                // Inside the checkpoint overlap the marker continues the skipped frames; a
                // marker with nothing skipped before it and below the checkpoint is checked
                // through the v2 batches that must chain from it up to the anchor.
                let covered = overlap.covers(seq, self.committed_seq);
                let (expected_seq, expected_prev) = match overlap.cursor {
                    Some(cursor) if covered => cursor,
                    None if covered && seq < self.committed_seq => (seq, marker_prev),
                    _ => (self.committed_seq, self.last_frame_sha256),
                };
                if seq != expected_seq {
                    return Err(SynapseError::new(
                        RefusalCode::WalSequenceGap,
                        format!("WAL v2 marker at {seq} does not follow {expected_seq}"),
                    ));
                }
                if header != marker_header(version, expected_seq, expected_prev) {
                    return Err(SynapseError::new(
                        RefusalCode::WalChainMismatch,
                        format!("WAL v2 marker at offset {offset} does not match the chain"),
                    ));
                }
                if covered && (overlap.cursor.is_some() || seq < self.committed_seq) {
                    overlap.cursor = Some((seq, marker_prev));
                }
                self.v2_mode = true;
                self.log_layout = if version == wal2::WAL_V2_VERSION {
                    LogLayout::SingleFileV2
                } else {
                    LogLayout::Segments
                };
                break;
            }
            if version != WAL_VERSION {
                return Err(SynapseError::new(
                    RefusalCode::WalVersionUnsupported,
                    format!("unsupported WAL version {version} at offset {offset}"),
                ));
            }
            let flags = header[7];
            let frame_codec = RecordCodec::from_frame_flags(flags).ok_or_else(|| {
                SynapseError::new(
                    RefusalCode::WalFlagsNonZero,
                    format!("unknown WAL flags {flags} at offset {offset}"),
                )
            })?;

            let seq = WalSeq(u64::from_le_bytes(header[8..16].try_into().unwrap()));
            let prev_sha: [u8; 32] = header[16..48].try_into().unwrap();
            let payload_len = u32::from_le_bytes(header[48..52].try_into().unwrap()) as u64;
            let expected_crc = u32::from_le_bytes(header[52..56].try_into().unwrap());
            let expected_frame_sha: [u8; 32] = header[56..88].try_into().unwrap();

            // The declared length is checked against the cap before it is trusted (so a
            // damaged length is never taken for a torn tail) and before any allocation.
            if payload_len > self.limits.max_wal_record_bytes {
                return Err(SynapseError::new(
                    RefusalCode::QuotaPayloadTooLarge,
                    format!(
                        "WAL frame at offset {offset} declares {payload_len} payload bytes, above max_wal_record_bytes {}",
                        self.limits.max_wal_record_bytes
                    ),
                ));
            }

            if remaining < (WAL_HEADER_LEN as u64 + payload_len) {
                return self.handle_torn_tail(
                    &mut f,
                    offset,
                    recovery_policy,
                    "torn WAL payload at EOF",
                );
            }

            let mut payload = vec![0u8; payload_len as usize];
            f.read_exact(&mut payload).map_err(io_err)?;

            // Frames covered by checkpoint.v1: verify their integrity and their chain,
            // then skip them (the checkpoint already holds their effects).
            if overlap.covers(seq, self.committed_seq) {
                let actual_crc = crc32c(&payload);
                if actual_crc != expected_crc {
                    return Err(SynapseError::new(
                        RefusalCode::WalCrcMismatch,
                        format!("WAL payload CRC32C mismatch at {seq} (covered by checkpoint)"),
                    ));
                }
                if compute_wal_frame_sha256(&header[0..56], &payload) != expected_frame_sha {
                    return Err(SynapseError::new(
                        RefusalCode::WalChainMismatch,
                        format!("WAL frame_sha256 mismatch at {seq} (covered by checkpoint)"),
                    ));
                }
                overlap.skip(seq, prev_sha, expected_frame_sha)?;
                offset += WAL_HEADER_LEN as u64 + payload_len;
                continue;
            }
            overlap.close(self.committed_seq, self.last_frame_sha256)?;

            // Sequence continuity check
            let expected_seq = self.committed_seq.next();
            if seq != expected_seq {
                return Err(SynapseError::new(
                    RefusalCode::WalSequenceGap,
                    format!(
                        "WAL sequence mismatch at offset {offset}: expected {expected_seq}, found {seq}"
                    ),
                ));
            }

            // Hash-chain continuity check
            if prev_sha != self.last_frame_sha256 {
                return Err(SynapseError::new(
                    RefusalCode::WalChainMismatch,
                    format!("WAL prev_frame_sha256 mismatch at {seq}"),
                ));
            }

            // CRC32C check
            let actual_crc = crc32c(&payload);
            if actual_crc != expected_crc {
                return Err(SynapseError::new(
                    RefusalCode::WalCrcMismatch,
                    format!(
                        "WAL payload CRC32C mismatch at {seq}: expected {expected_crc:#x}, computed {actual_crc:#x}"
                    ),
                ));
            }

            // Frame SHA-256 check
            let actual_frame_sha = compute_wal_frame_sha256(&header[0..56], &payload);
            if actual_frame_sha != expected_frame_sha {
                return Err(SynapseError::new(
                    RefusalCode::WalChainMismatch,
                    format!("WAL frame_sha256 mismatch at {seq}"),
                ));
            }

            self.admit_replayed_codec(frame_codec, seq)?;
            let record =
                codec::decode_record_with(&payload, frame_codec, self.limits.max_wal_record_bytes)
                    .map_err(|e| {
                        SynapseError::new(e.code, format!("WAL record at {seq}: {}", e.message))
                    })?;
            if frame_codec == RecordCodec::BinaryV2 && record.kind_byte() != header[6] {
                return Err(SynapseError::new(
                    RefusalCode::WalRecordMalformed,
                    format!("record kind byte does not match payload at {seq}"),
                ));
            }

            // Verify that all blobs referenced by a committed ingest or revision exist and match digest
            for blob_digest in &record.upsert_blobs() {
                {
                    {
                        let bpath = self.blob_path(*blob_digest);
                        let raw = fs::read(&bpath).map_err(|_| {
                            SynapseError::new(
                                RefusalCode::BlobNotFound,
                                format!("committed blob {blob_digest} missing during WAL replay"),
                            )
                        })?;
                        if BlobDigest::compute(&raw) != *blob_digest {
                            return Err(SynapseError::new(
                                RefusalCode::BlobDigestMismatch,
                                format!("committed blob {blob_digest} corrupt during WAL replay"),
                            ));
                        }
                    }
                }
            }

            self.committed_seq = seq;
            self.last_frame_sha256 = expected_frame_sha;
            self.apply_record(seq, record);

            offset += WAL_HEADER_LEN as u64 + payload_len;
        }

        Ok(())
    }

    /// Replay the log after `wal.log`: segment 1 (`wal.v2.log`) and, in the segment
    /// layout, the segments after it, whole batches only (all frames valid or none
    /// applied). In the segment layout replay starts at the position the segment index
    /// of the checkpoint names, and the index supplies the locations of the blobs the
    /// checkpoint retains.
    fn recover_v2(
        &mut self,
        recovery_policy: RecoveryPolicy,
        overlap: &mut CheckpointOverlap,
    ) -> SynapseResult<()> {
        let ids = segment::list_segments(&self.root_dir)?;
        if !self.v2_mode {
            for &id in &ids {
                if self.segment_has_data(id)? {
                    return Err(SynapseError::new(
                        RefusalCode::WalVersionUnsupported,
                        format!(
                            "{} holds data but wal.log does not end with the WAL v2 marker",
                            segment::segment_file_name(id)
                        ),
                    ));
                }
            }
            return Ok(());
        }
        let (start_seg, start_off) = if self.log_layout == LogLayout::Segments {
            let binding = segment::checkpoint_binding(&self.root_dir)?;
            let index = segment::SegmentIndex::load(&self.root_dir, &binding)?;
            self.blob_locations = index.entries.clone();
            if (index.replay_segment, index.replay_offset) != (1, 0) {
                // The index vouches for every segment byte before its replay position:
                // those frames are covered by the checkpoint it is bound to.
                if overlap.cursor.is_some() {
                    overlap.cursor = Some((self.committed_seq, self.last_frame_sha256));
                }
                overlap.close(self.committed_seq, self.last_frame_sha256)?;
            }
            (index.replay_segment, index.replay_offset)
        } else {
            // Single-file WAL v2: segment 1 only.
            if let Some(&id) = ids.iter().find(|&&id| id >= 2) {
                if self.segment_has_data(id)? {
                    return Err(SynapseError::new(
                        RefusalCode::WalVersionUnsupported,
                        format!(
                            "segment {id} holds data but wal.log has the single-file WAL v2 marker"
                        ),
                    ));
                }
            }
            (1, 0)
        };
        let last = ids.last().copied().unwrap_or(0).max(start_seg);
        let max = if self.log_layout == LogLayout::Segments {
            // Segments are never removed (no garbage collection before K1), so every id
            // up to the last must be present; only a store that crashed before creating
            // its first segment has none.
            let never_created = ids.is_empty() && (start_seg, start_off) == (1, 0);
            if let Some(missing) = (1..=last).find(|id| !never_created && !ids.contains(id)) {
                return Err(SynapseError::new(
                    RefusalCode::WalSequenceGap,
                    format!(
                        "segment file {} is missing",
                        segment::segment_file_name(missing)
                    ),
                ));
            }
            last
        } else {
            1
        };
        self.wal_v2_recovered_end = (start_seg, start_off);
        for id in start_seg..=max {
            let path = self.root_dir.join(segment::segment_file_name(id));
            if !path.exists() {
                break;
            }
            let base = if id == start_seg { start_off } else { 0 };
            let buf = {
                let mut f = File::open(&path).map_err(io_err)?;
                f.seek(SeekFrom::Start(base)).map_err(io_err)?;
                let mut b = Vec::new();
                f.read_to_end(&mut b).map_err(io_err)?;
                b
            };
            let (end, holds_data, truncated) =
                self.replay_segment(id, &path, base, &buf, max, recovery_policy, overlap)?;
            if holds_data || id == start_seg {
                self.wal_v2_recovered_end = (id, end);
            }
            if truncated {
                break;
            }
        }
        Ok(())
    }

    /// True when every segment after `id` up to `max` is missing or all zero.
    fn later_segments_zero(&self, id: u64, max: u64) -> SynapseResult<bool> {
        for later in id + 1..=max {
            if self.segment_has_data(later)? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Replay the batches of segment `id` held in `buf` (the file from byte `base` on).
    /// Returns the absolute end of the valid log in this segment, whether it holds a
    /// batch (or a torn tail), and whether a torn tail was truncated.
    #[allow(clippy::too_many_arguments)]
    fn replay_segment(
        &mut self,
        id: u64,
        path: &Path,
        base: u64,
        buf: &[u8],
        max: u64,
        recovery_policy: RecoveryPolicy,
        overlap: &mut CheckpointOverlap,
    ) -> SynapseResult<(u64, bool, bool)> {
        let hlen = wal2::WAL_V2_BATCH_HEADER_LEN;
        let mut off = 0usize;
        let mut holds_data = false;
        while off < buf.len() {
            let header_end = (off + hlen).min(buf.len());
            let header_zero = buf[off..header_end].iter().all(|b| *b == 0);
            if header_zero && buf[off..].iter().all(|b| *b == 0) {
                break; // clean end of this segment
            }
            holds_data = true;
            // A batch the checkpoint covers: verify it whole (fail closed on any error, it
            // was acknowledged before the checkpoint) and skip it.
            if let Some((_, _, first)) = buf.get(off..off + hlen).and_then(wal2::parse_batch_header)
            {
                if overlap.covers(first, self.committed_seq) {
                    let (expected_seq, expected_prev) = match overlap.cursor {
                        Some((s, h)) => (s.next(), h),
                        // Nothing skipped yet: take the chain link the batch states; the
                        // skipped chain must still end at the checkpoint anchor.
                        None => (first, wal2::first_frame_prev(buf, off)),
                    };
                    let (frames, next) = wal2::validate_batch(
                        buf,
                        off,
                        expected_seq,
                        expected_prev,
                        self.limits.max_wal_record_bytes,
                    )?;
                    for fr in &frames {
                        if fr.seq > self.committed_seq {
                            return Err(SynapseError::new(
                                RefusalCode::WalSequenceGap,
                                format!(
                                    "WAL v2 batch at {off} straddles checkpoint {} (frame {})",
                                    self.committed_seq, fr.seq
                                ),
                            ));
                        }
                        overlap.cursor = Some((fr.seq, fr.frame_sha256));
                    }
                    off = next;
                    continue;
                }
            }
            overlap.close(self.committed_seq, self.last_frame_sha256)?;
            let result = if header_zero {
                Err(SynapseError::new(
                    RefusalCode::WalTornFrame,
                    format!("non-zero bytes after an empty WAL v2 batch header at {off}"),
                ))
            } else {
                wal2::validate_batch(
                    buf,
                    off,
                    self.committed_seq.next(),
                    self.last_frame_sha256,
                    self.limits.max_wal_record_bytes,
                )
            };
            match result {
                Ok((frames, next)) => {
                    for fr in frames {
                        self.admit_replayed_codec(fr.codec, fr.seq)?;
                        {
                            for blob_digest in &fr.record.upsert_blobs() {
                                {
                                    let inline = fr.inline.iter().any(|(d, _, _)| d == blob_digest);
                                    if inline || self.blob_locations.contains_key(blob_digest) {
                                        continue;
                                    }
                                    let raw = fs::read(self.blob_path(*blob_digest)).map_err(|_| {
                                        SynapseError::new(
                                            RefusalCode::BlobNotFound,
                                            format!("committed blob {blob_digest} missing during WAL v2 replay"),
                                        )
                                    })?;
                                    if BlobDigest::compute(&raw) != *blob_digest {
                                        return Err(SynapseError::new(
                                            RefusalCode::BlobDigestMismatch,
                                            format!("committed blob {blob_digest} corrupt during WAL v2 replay"),
                                        ));
                                    }
                                }
                            }
                        }
                        for &(d, rel, len) in &fr.inline {
                            self.blob_locations.entry(d).or_insert(segment::BlobLoc {
                                segment: id,
                                offset: base + rel,
                                len,
                            });
                        }
                        self.committed_seq = fr.seq;
                        self.last_frame_sha256 = fr.frame_sha256;
                        self.apply_record(fr.seq, fr.record);
                    }
                    off = next;
                }
                Err(e) => {
                    // A length above the cap is never taken for a torn tail.
                    if e.code == RefusalCode::QuotaPayloadTooLarge {
                        return Err(e);
                    }
                    // A torn tail is only the last write: nothing valid after it in this
                    // segment, its lost end reads back as zeros, and every later segment
                    // is empty (a batch never goes to a new segment before the previous
                    // one is durable).
                    let torn = !wal2::valid_batch_after(buf, off + 1)
                        && wal2::torn_evidence(buf, off)
                        && self.later_segments_zero(id, max)?;
                    if !torn {
                        return Err(e);
                    }
                    match recovery_policy {
                        RecoveryPolicy::StrictFailClosed => {
                            return Err(SynapseError::new(
                                RefusalCode::WalTornFrame,
                                format!(
                                    "torn WAL v2 batch in segment {id} at byte offset {}: {}",
                                    base + off as u64,
                                    e.message
                                ),
                            ))
                        }
                        RecoveryPolicy::TruncateTornTail => {
                            use std::os::unix::fs::FileExt;
                            let last_nonzero = buf.iter().rposition(|b| *b != 0).unwrap_or(off);
                            let end = wal2::align_up(last_nonzero as u64 + 1) as usize;
                            let f = OpenOptions::new().write(true).open(path).map_err(io_err)?;
                            f.write_all_at(&vec![0u8; end - off], base + off as u64)
                                .map_err(io_err)?;
                            f.sync_data().map_err(io_err)?;
                            self.torn_frames_truncated_on_open += 1;
                            return Ok((base + off as u64, true, true));
                        }
                    }
                }
            }
        }
        Ok((base + off as u64, holds_data, false))
    }

    fn handle_torn_tail(
        &mut self,
        f: &mut File,
        valid_offset: u64,
        recovery_policy: RecoveryPolicy,
        reason: &str,
    ) -> SynapseResult<()> {
        match recovery_policy {
            RecoveryPolicy::StrictFailClosed => Err(SynapseError::new(
                RefusalCode::WalTornFrame,
                format!("{reason} at byte offset {valid_offset}"),
            )),
            RecoveryPolicy::TruncateTornTail => {
                f.set_len(valid_offset).map_err(io_err)?;
                f.sync_all().map_err(io_err)?;
                self.torn_frames_truncated_on_open += 1;
                Ok(())
            }
        }
    }
}

/// Log frames that `checkpoint.v1` already covers, met at the start of replay.
///
/// A crash after the checkpoint is renamed into place but before `wal.log` (and, in the
/// single-file WAL v2 layout before ADR 0003 A2, `wal.v2.log`) is emptied leaves frames with `seq <= checkpoint_seq` in front of the
/// log. Recovery verifies them (CRC, frame digest, and one unbroken hash chain among
/// them) and skips them; the skipped chain must end exactly at the checkpoint's sequence
/// and anchor digest. Skipping is allowed only before the first frame is applied.
#[derive(Debug, Default)]
struct CheckpointOverlap {
    /// Last skipped frame: `(seq, frame_sha256)`.
    cursor: Option<(WalSeq, [u8; 32])>,
    /// Set once replay moved past the covered frames.
    closed: bool,
}

impl CheckpointOverlap {
    fn covers(&self, seq: WalSeq, committed: WalSeq) -> bool {
        !self.closed && seq <= committed
    }

    /// Record a skipped v1 frame; it must extend the skipped chain.
    fn skip(&mut self, seq: WalSeq, prev: [u8; 32], frame_sha256: [u8; 32]) -> SynapseResult<()> {
        if let Some((s, h)) = self.cursor {
            if seq != s.next() {
                return Err(SynapseError::new(
                    RefusalCode::WalSequenceGap,
                    format!("covered WAL frames jump from {s} to {seq}"),
                ));
            }
            if prev != h {
                return Err(SynapseError::new(
                    RefusalCode::WalChainMismatch,
                    format!("covered WAL frame {seq} does not chain to {s}"),
                ));
            }
        }
        self.cursor = Some((seq, frame_sha256));
        Ok(())
    }

    /// Leave the overlap: the skipped chain, if any, must end at the checkpoint anchor.
    fn close(&mut self, checkpoint_seq: WalSeq, anchor: [u8; 32]) -> SynapseResult<()> {
        if self.closed {
            return Ok(());
        }
        self.closed = true;
        match self.cursor {
            Some((s, _)) if s != checkpoint_seq => Err(SynapseError::new(
                RefusalCode::WalSequenceGap,
                format!(
                    "frames covered by checkpoint.v1 end at {s}, checkpoint is {checkpoint_seq}"
                ),
            )),
            Some((_, h)) if h != anchor => Err(SynapseError::new(
                RefusalCode::WalChainMismatch,
                format!(
                    "frames covered by checkpoint.v1 do not end at its anchor ({checkpoint_seq})"
                ),
            )),
            _ => Ok(()),
        }
    }
}

/// Frame kind of the WAL v2 marker written at the end of `wal.log`.
const WAL_V2_MARKER_KIND: u8 = 0xFF;

/// The 88-byte log marker: v1 header layout with `version` (2: WAL v2 in `wal.v2.log`
/// alone; 3: the segment layout of ADR 0003 A2), kind `0xFF`, an empty payload, `seq`
/// and `prev_frame_sha256` equal to the last committed frame, and the v2 frame digest.
/// Binaries that do not know the version refuse it (`WalVersionUnsupported`) instead of
/// missing the commits that follow it.
fn marker_header(version: u16, seq: WalSeq, prev: [u8; 32]) -> [u8; WAL_HEADER_LEN] {
    let mut h = wal2::frame_header(
        seq,
        prev,
        WAL_V2_MARKER_KIND,
        0,
        0,
        crc32c(&[]),
        &wal2::payload_digest(&[]),
    )
    .0;
    h[4..6].copy_from_slice(&version.to_le_bytes());
    let sha = wal2::frame_digest(&h[0..56], &wal2::payload_digest(&[]));
    h[56..88].copy_from_slice(&sha);
    h
}

fn compute_wal_frame_sha256(header_prefix_56: &[u8], payload: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN_WAL_FRAME_V1);
    hasher.update(header_prefix_56);
    hasher.update(payload);
    hasher.finalize().into()
}

/// One `wal.log` frame (88-byte header plus payload) decoded and verified on its own:
/// header fields, length cap, CRC-32C, frame digest, record codec and kind. Sequence and
/// chain continuity are the caller's (recovery checks them against the previous frame).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedFrame {
    pub seq: WalSeq,
    pub prev_frame_sha256: [u8; 32],
    pub frame_sha256: [u8; 32],
    pub codec: RecordCodec,
    pub record: WalRecord,
    /// Bytes the frame occupies (header plus payload).
    pub frame_len: usize,
}

/// Build a `wal.log` frame around `payload` (any bytes) with header `kind` and `flags`.
/// Returns the frame and its `frame_sha256`. Used by the writer and by test corpora.
pub fn wal_frame_from_payload(
    seq: WalSeq,
    prev_frame_sha256: [u8; 32],
    kind: u8,
    flags: u8,
    payload: &[u8],
) -> (Vec<u8>, [u8; 32]) {
    let mut header_prefix = [0u8; 56];
    header_prefix[0..4].copy_from_slice(&WAL_MAGIC);
    header_prefix[4..6].copy_from_slice(&WAL_VERSION.to_le_bytes());
    header_prefix[6] = kind;
    header_prefix[7] = flags;
    header_prefix[8..16].copy_from_slice(&seq.0.to_le_bytes());
    header_prefix[16..48].copy_from_slice(&prev_frame_sha256);
    header_prefix[48..52].copy_from_slice(&(payload.len() as u32).to_le_bytes());
    header_prefix[52..56].copy_from_slice(&crc32c(payload).to_le_bytes());
    let sha = compute_wal_frame_sha256(&header_prefix, payload);
    let mut frame = Vec::with_capacity(WAL_HEADER_LEN + payload.len());
    frame.extend_from_slice(&header_prefix);
    frame.extend_from_slice(&sha);
    frame.extend_from_slice(payload);
    (frame, sha)
}

/// Encode `record` with `codec` as one `wal.log` frame. Refuses a payload above `cap`.
pub fn encode_wal_frame(
    seq: WalSeq,
    prev_frame_sha256: [u8; 32],
    record: &WalRecord,
    codec: RecordCodec,
    cap: u64,
) -> SynapseResult<(Vec<u8>, [u8; 32])> {
    let payload = codec::encode_record_with(record, codec)?;
    if payload.len() as u64 > cap {
        return Err(SynapseError::new(
            RefusalCode::QuotaPayloadTooLarge,
            format!(
                "WAL record of {} bytes exceeds the cap {cap}",
                payload.len()
            ),
        ));
    }
    Ok(wal_frame_from_payload(
        seq,
        prev_frame_sha256,
        record.kind_byte(),
        codec.frame_flags(),
        &payload,
    ))
}

/// Decode and verify the `wal.log` frame at the start of `buf`; `cap` is the largest
/// payload length accepted (`StoreLimits::max_wal_record_bytes`).
pub fn decode_wal_frame(buf: &[u8], cap: u64) -> SynapseResult<DecodedFrame> {
    let header = buf.get(..WAL_HEADER_LEN).ok_or_else(|| {
        SynapseError::new(
            RefusalCode::WalTornFrame,
            format!("{} bytes cannot hold a WAL frame header", buf.len()),
        )
    })?;
    if header[0..4] != WAL_MAGIC {
        return Err(SynapseError::new(
            RefusalCode::WalMagicInvalid,
            "invalid WAL magic",
        ));
    }
    let version = u16::from_le_bytes([header[4], header[5]]);
    if version != WAL_VERSION {
        return Err(SynapseError::new(
            RefusalCode::WalVersionUnsupported,
            format!("unsupported WAL version {version}"),
        ));
    }
    let codec = RecordCodec::from_frame_flags(header[7]).ok_or_else(|| {
        SynapseError::new(
            RefusalCode::WalFlagsNonZero,
            format!("unknown WAL flags {}", header[7]),
        )
    })?;
    let seq = WalSeq(u64::from_le_bytes(
        header[8..16].try_into().expect("8 bytes"),
    ));
    let prev_frame_sha256: [u8; 32] = header[16..48].try_into().expect("32 bytes");
    let payload_len = u32::from_le_bytes(header[48..52].try_into().expect("4 bytes"));
    let crc = u32::from_le_bytes(header[52..56].try_into().expect("4 bytes"));
    let frame_sha256: [u8; 32] = header[56..88].try_into().expect("32 bytes");
    if u64::from(payload_len) > cap {
        return Err(SynapseError::new(
            RefusalCode::QuotaPayloadTooLarge,
            format!("WAL frame {seq} declares {payload_len} payload bytes, above the cap {cap}"),
        ));
    }
    let frame_len = WAL_HEADER_LEN + payload_len as usize;
    let payload = buf.get(WAL_HEADER_LEN..frame_len).ok_or_else(|| {
        SynapseError::new(
            RefusalCode::WalTornFrame,
            format!(
                "WAL frame {seq} declares {payload_len} payload bytes, {} present",
                buf.len() - WAL_HEADER_LEN
            ),
        )
    })?;
    if crc32c(payload) != crc {
        return Err(SynapseError::new(
            RefusalCode::WalCrcMismatch,
            format!("WAL payload CRC32C mismatch at {seq}"),
        ));
    }
    if compute_wal_frame_sha256(&header[0..56], payload) != frame_sha256 {
        return Err(SynapseError::new(
            RefusalCode::WalChainMismatch,
            format!("WAL frame_sha256 mismatch at {seq}"),
        ));
    }
    let record = codec::decode_record_with(payload, codec, cap)?;
    if record.kind_byte() != header[6] {
        return Err(SynapseError::new(
            RefusalCode::WalRecordMalformed,
            format!("record kind byte does not match payload at {seq}"),
        ));
    }
    Ok(DecodedFrame {
        seq,
        prev_frame_sha256,
        frame_sha256,
        codec,
        record,
        frame_len,
    })
}

fn sync_dir(dir: &Path) -> SynapseResult<()> {
    let f = File::open(dir).map_err(io_err)?;
    f.sync_all().map_err(io_err)
}

/// Write `bytes` to `path` atomically: `tmp` is written and synced, renamed over `path`,
/// and `dir` is synced.
fn write_file_atomic(dir: &Path, tmp: &Path, path: &Path, bytes: &[u8]) -> SynapseResult<()> {
    {
        let mut f = File::create(tmp).map_err(io_err)?;
        f.write_all(bytes).map_err(io_err)?;
        f.sync_all().map_err(io_err)?;
    }
    fs::rename(tmp, path).map_err(io_err)?;
    sync_dir(dir)
}

fn io_err(e: std::io::Error) -> SynapseError {
    SynapseError::new(RefusalCode::IoFailure, e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use std::process::Command;
    use synapse_core::{FileMode, GitOid, PathMutation, SYNAPSE_ENVELOPE_VERSION};

    pub(crate) fn temp_store_dir(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "synapse-store-test-{}-{}-{}",
            label,
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    pub(crate) fn make_signed_changeset(
        signing_key: &SigningKey,
        idem_label: &str,
        path: &str,
        content: &[u8],
        parents: Vec<ChangesetId>,
        created_at_ms: u64,
    ) -> (ChangesetEnvelope, Vec<(BlobDigest, Vec<u8>)>) {
        let digest = BlobDigest::compute(content);
        let mut env = ChangesetEnvelope {
            version: SYNAPSE_ENVELOPE_VERSION,
            repo_id: RepoId::new("aien-spark/synapse").unwrap(),
            base_git_oid: GitOid::compute_blob(b"base"),
            parent_changesets: parents,
            author_did: String::new(),
            idempotency_key: IdempotencyKey::from_label(idem_label),
            created_at_ms,
            intent_summary: format!("Update {path}"),
            mutations: vec![PathMutation {
                path: path.to_string(),
                op: MutationOp::Upsert {
                    mode: FileMode::Regular644,
                    blob_digest: digest,
                    size_bytes: content.len() as u64,
                },
            }],
            evidence_receipts: vec![],
            signature: vec![],
        };
        env.sign(signing_key);
        (env, vec![(digest, content.to_vec())])
    }

    #[test]
    fn test_crc32c_standard_rfc3720_vector() {
        assert_eq!(crc32c(b"123456789"), 0xe306_9283);
    }

    #[test]
    fn test_idempotent_ingest_snapshot_reads_and_deterministic_replay() {
        let dir = temp_store_dir("idempotent-replay");
        let key = SigningKey::from_bytes(&[11u8; 32]);

        let (root_before, cs1_id, cs2_id);
        {
            let mut store = SynapseStore::open(
                &dir,
                FsyncPolicy::EveryCommit,
                RecoveryPolicy::StrictFailClosed,
                StoreLimits::default(),
            )
            .unwrap();

            let (env1, blobs1) =
                make_signed_changeset(&key, "idem-1", "src/a.rs", b"pub fn a() {}\n", vec![], 1000);
            let out1 = store.ingest_changeset(env1.clone(), &blobs1).unwrap();
            let seq1 = match out1 {
                IngestOutcome::Committed {
                    wal_seq,
                    changeset_id,
                    durability,
                    ..
                } => {
                    assert_eq!(wal_seq, WalSeq(1));
                    assert_eq!(durability, DurabilityGuarantee::FsyncBeforeAck);
                    cs1_id = changeset_id;
                    wal_seq
                }
                _ => panic!("expected Committed"),
            };

            // Re-submitting identical envelope + idempotency key returns IdempotentDuplicate without advancing WAL
            let dup = store.ingest_changeset(env1, &blobs1).unwrap();
            assert_eq!(
                dup,
                IngestOutcome::IdempotentDuplicate {
                    wal_seq: seq1,
                    changeset_id: cs1_id
                }
            );
            assert_eq!(store.committed_seq(), WalSeq(1));

            // Re-submitting the SAME idempotency key with DIFFERENT content fails closed
            let (env_conflict, blobs_conflict) = make_signed_changeset(
                &key,
                "idem-1",
                "src/a.rs",
                b"pub fn a_modified() {}\n",
                vec![],
                1001,
            );
            let err = store
                .ingest_changeset(env_conflict, &blobs_conflict)
                .unwrap_err();
            assert_eq!(err.code, RefusalCode::IdempotencyKeyConflict);

            // Submit second changeset stacked on cs1_id
            let (env2, blobs2) = make_signed_changeset(
                &key,
                "idem-2",
                "src/b.rs",
                b"pub fn b() {}\n",
                vec![cs1_id],
                2000,
            );
            let out2 = store.ingest_changeset(env2, &blobs2).unwrap();
            match out2 {
                IngestOutcome::Committed {
                    wal_seq,
                    changeset_id,
                    ..
                } => {
                    assert_eq!(wal_seq, WalSeq(2));
                    cs2_id = changeset_id;
                }
                _ => panic!("expected Committed"),
            }

            // Snapshot isolation check: at snapshot WalSeq(1), cs1 is visible, cs2 and blob2 are NOT visible
            assert!(store
                .get_changeset(cs1_id, Some(WalSeq(1)), Some(WalSeq(1)))
                .is_ok());
            assert_eq!(
                store
                    .get_changeset(cs2_id, None, Some(WalSeq(1)))
                    .unwrap_err()
                    .code,
                RefusalCode::ChangesetNotFound
            );
            assert_eq!(
                store
                    .get_blob_visible(blobs2[0].0, None, Some(WalSeq(1)))
                    .unwrap_err()
                    .code,
                RefusalCode::BlobNotFound
            );
            // At WalSeq(2), blob2 is visible
            assert_eq!(
                store
                    .get_blob_visible(blobs2[0].0, Some(WalSeq(2)), Some(WalSeq(2)))
                    .unwrap(),
                b"pub fn b() {}\n"
            );

            // Requesting min_visible_seq ahead of committed_seq refuses with VisibilitySeqAhead
            assert_eq!(
                store
                    .get_changeset(cs1_id, Some(WalSeq(99)), None)
                    .unwrap_err()
                    .code,
                RefusalCode::VisibilitySeqAhead
            );

            root_before = store.state_root_digest(None).unwrap();
        }

        // Reopen and deterministically replay WAL from disk
        let reopened = SynapseStore::open(
            &dir,
            FsyncPolicy::EveryCommit,
            RecoveryPolicy::StrictFailClosed,
            StoreLimits::default(),
        )
        .unwrap();
        assert_eq!(reopened.committed_seq(), WalSeq(2));
        assert_eq!(reopened.state_root_digest(None).unwrap(), root_before);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_fault_injection_crash_before_wal_and_torn_frames_no_phantom_visibility() {
        let dir = temp_store_dir("fault-injection");
        let key = SigningKey::from_bytes(&[22u8; 32]);

        let mut store = SynapseStore::open(
            &dir,
            FsyncPolicy::EveryCommit,
            RecoveryPolicy::StrictFailClosed,
            StoreLimits::default(),
        )
        .unwrap();

        // Commit seq 1 normally
        let (env1, blobs1) = make_signed_changeset(
            &key,
            "k1",
            "src/one.rs",
            b"const ONE: u32 = 1;\n",
            vec![],
            100,
        );
        store.ingest_changeset(env1, &blobs1).unwrap();
        assert_eq!(store.committed_seq(), WalSeq(1));

        // Fault 1: Crash after writing blob to disk, BEFORE appending WAL frame
        store.set_fault_injection(FaultInjection::CrashAfterBlobWriteBeforeWalAppend);
        let (env_phantom, blobs_phantom) = make_signed_changeset(
            &key,
            "k-phantom",
            "src/phantom.rs",
            b"phantom content\n",
            vec![],
            200,
        );
        let phantom_blob_digest = blobs_phantom[0].0;
        let phantom_cs_id = env_phantom.compute_id();
        assert_eq!(
            store
                .ingest_changeset(env_phantom, &blobs_phantom)
                .unwrap_err()
                .code,
            RefusalCode::IoFailure
        );

        // Even though the blob file is on disk, it MUST NOT be visible through the store!
        assert_eq!(
            store
                .get_blob_visible(phantom_blob_digest, None, None)
                .unwrap_err()
                .code,
            RefusalCode::BlobNotFound
        );
        assert_eq!(
            store
                .get_changeset(phantom_cs_id, None, None)
                .unwrap_err()
                .code,
            RefusalCode::ChangesetNotFound
        );

        // Fault 2: Torn WAL payload write on seq 2
        store.set_fault_injection(FaultInjection::TornWalPayloadWrite { bytes_written: 12 });
        let (env_torn, blobs_torn) = make_signed_changeset(
            &key,
            "k-torn",
            "src/torn.rs",
            b"torn payload bytes\n",
            vec![],
            300,
        );
        let torn_blob_digest = blobs_torn[0].0;
        let torn_cs_id = env_torn.compute_id();
        assert_eq!(
            store
                .ingest_changeset(env_torn, &blobs_torn)
                .unwrap_err()
                .code,
            RefusalCode::WalTornFrame
        );
        drop(store);

        // StrictFailClosed must refuse the torn tail frame
        let strict_err = SynapseStore::open(
            &dir,
            FsyncPolicy::EveryCommit,
            RecoveryPolicy::StrictFailClosed,
            StoreLimits::default(),
        )
        .err()
        .expect("StrictFailClosed must refuse torn tail");
        assert_eq!(strict_err.code, RefusalCode::WalTornFrame);

        // TruncateTornTail must truncate the unacknowledged torn frame, preserve seq 1, and expose zero phantom data
        let mut recovered = SynapseStore::open(
            &dir,
            FsyncPolicy::EveryCommit,
            RecoveryPolicy::TruncateTornTail,
            StoreLimits::default(),
        )
        .unwrap();
        assert_eq!(recovered.torn_frames_truncated_on_open(), 1);
        assert_eq!(recovered.committed_seq(), WalSeq(1));
        assert_eq!(
            recovered
                .get_changeset(torn_cs_id, None, None)
                .unwrap_err()
                .code,
            RefusalCode::ChangesetNotFound
        );
        assert_eq!(
            recovered
                .get_blob_visible(torn_blob_digest, None, None)
                .unwrap_err()
                .code,
            RefusalCode::BlobNotFound
        );

        // Subsequent commit seq 2 after recovery must chain cleanly from seq 1!
        let (env2, blobs2) = make_signed_changeset(
            &key,
            "k2",
            "src/two.rs",
            b"const TWO: u32 = 2;\n",
            vec![],
            400,
        );
        let out2 = recovered.ingest_changeset(env2, &blobs2).unwrap();
        assert!(matches!(
            out2,
            IngestOutcome::Committed {
                wal_seq: WalSeq(2),
                ..
            }
        ));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_wal_crc_chain_and_sequence_corruption_refusals() {
        for (label, fault, expected_code) in [
            (
                "crc",
                FaultInjection::CorruptNextWalCrc,
                RefusalCode::WalCrcMismatch,
            ),
            (
                "chain",
                FaultInjection::CorruptNextWalChain,
                RefusalCode::WalChainMismatch,
            ),
            (
                "seq-gap",
                FaultInjection::InjectNextWalSequenceGap,
                RefusalCode::WalSequenceGap,
            ),
            (
                "seq-dup",
                FaultInjection::InjectDuplicateWalSequence,
                RefusalCode::WalSequenceGap,
            ),
        ] {
            let dir = temp_store_dir(label);
            let key = SigningKey::from_bytes(&[33u8; 32]);
            let mut store = SynapseStore::open(
                &dir,
                FsyncPolicy::EveryCommit,
                RecoveryPolicy::StrictFailClosed,
                StoreLimits::default(),
            )
            .unwrap();
            let (env1, blobs1) = make_signed_changeset(&key, "k1", "src/a.rs", b"a\n", vec![], 100);
            store.ingest_changeset(env1, &blobs1).unwrap();

            store.set_fault_injection(fault);
            let (env2, blobs2) = make_signed_changeset(&key, "k2", "src/b.rs", b"b\n", vec![], 200);
            store.ingest_changeset(env2, &blobs2).unwrap();
            drop(store);

            let err = SynapseStore::open(
                &dir,
                FsyncPolicy::EveryCommit,
                RecoveryPolicy::TruncateTornTail,
                StoreLimits::default(),
            )
            .err()
            .expect("corrupted WAL must fail closed");
            assert_eq!(err.code, expected_code, "case {label} failed");
            let _ = fs::remove_dir_all(&dir);
        }
    }

    #[test]
    fn test_compaction_checkpoint_and_garbage_collection() {
        let dir = temp_store_dir("compaction-gc");
        let key = SigningKey::from_bytes(&[44u8; 32]);
        let limits = StoreLimits {
            default_retention_window_ms: 500,
            ..Default::default()
        };

        let mut store = SynapseStore::open(
            &dir,
            FsyncPolicy::EveryCommit,
            RecoveryPolicy::StrictFailClosed,
            limits.clone(),
        )
        .unwrap();

        // 1. Old speculative changeset at t=100 (unpinned, will expire at now_ms=2000)
        let (env_ephemeral, blobs_ephemeral) = make_signed_changeset(
            &key,
            "ephemeral",
            "src/speculative.rs",
            b"ephemeral work\n",
            vec![],
            100,
        );
        let ephemeral_blob = blobs_ephemeral[0].0;
        let ephemeral_id = match store
            .ingest_changeset(env_ephemeral, &blobs_ephemeral)
            .unwrap()
        {
            IngestOutcome::Committed { changeset_id, .. } => changeset_id,
            _ => unreachable!(),
        };

        // 2. Old changeset at t=150 that IS promoted to RadicleCanonicalHead (GarbageRoot!)
        let (env_canon, blobs_canon) = make_signed_changeset(
            &key,
            "canon",
            "src/lib.rs",
            b"pub fn canonical() {}\n",
            vec![],
            150,
        );
        let canon_blob = blobs_canon[0].0;
        let canon_id = match store.ingest_changeset(env_canon, &blobs_canon).unwrap() {
            IngestOutcome::Committed { changeset_id, .. } => changeset_id,
            _ => unreachable!(),
        };
        store
            .record_canonical_promotion(RadicleCanonicalHead {
                repo_id: RepoId::new("aien-spark/synapse").unwrap(),
                default_branch: "main".to_string(),
                canonical_git_oid: GitOid::compute_blob(b"commit"),
                promoted_changeset_id: Some(canon_id),
                rad_id_commit_oid: GitOid::compute_blob(b"rad-id"),
                threshold: 1,
                verified_delegates: vec![
                    "did:key:z6MkfZDue1TbaNFi3ZzcD9uiTeduPLC52ucdFVuLKZwexxhK".to_string(),
                ],
                verified_at_ms: 200,
            })
            .unwrap();

        // Compact at now_ms = 2000: ephemeral (t=100) is evicted and its blob swept; canon (t=150) is retained!
        let report = store.checkpoint_and_compact(2000).unwrap();
        assert_eq!(report.evicted_changesets, 1);
        assert_eq!(report.retained_changesets, 1);
        assert_eq!(report.swept_blob_files, 1);
        assert!(store.get_changeset(canon_id, None, None).is_ok());
        assert!(store.get_blob_visible(canon_blob, None, None).is_ok());
        assert_eq!(
            store
                .get_changeset(ephemeral_id, None, None)
                .unwrap_err()
                .code,
            RefusalCode::ChangesetNotFound
        );
        assert_eq!(
            store
                .get_blob_visible(ephemeral_blob, None, None)
                .unwrap_err()
                .code,
            RefusalCode::BlobNotFound
        );

        // Append another changeset after compaction and verify reopen replays checkpoint + new WAL frame
        let (env_post, blobs_post) = make_signed_changeset(
            &key,
            "post-ckpt",
            "src/post.rs",
            b"pub fn post() {}\n",
            vec![canon_id],
            2100,
        );
        let post_id = match store.ingest_changeset(env_post, &blobs_post).unwrap() {
            IngestOutcome::Committed { changeset_id, .. } => changeset_id,
            _ => unreachable!(),
        };
        let expected_seq = store.committed_seq();
        let expected_root = store.state_root_digest(None).unwrap();
        drop(store);

        let reopened = SynapseStore::open(
            &dir,
            FsyncPolicy::EveryCommit,
            RecoveryPolicy::StrictFailClosed,
            limits,
        )
        .unwrap();
        assert_eq!(reopened.committed_seq(), expected_seq);
        assert_eq!(reopened.state_root_digest(None).unwrap(), expected_root);
        assert!(reopened.get_changeset(canon_id, None, None).is_ok());
        assert!(reopened.get_changeset(post_id, None, None).is_ok());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_subprocess_crash_recovery_no_lost_ack_and_no_phantom_visibility() {
        // Child subprocess entry point when invoked with SYNAPSE_CRASH_CHILD_DIR
        if let Ok(child_dir) = std::env::var("SYNAPSE_CRASH_CHILD_DIR") {
            let key = SigningKey::from_bytes(&[55u8; 32]);
            let mut store = SynapseStore::open(
                &child_dir,
                FsyncPolicy::EveryCommit,
                RecoveryPolicy::StrictFailClosed,
                StoreLimits::default(),
            )
            .unwrap();
            for i in 1..=5u64 {
                let (env, blobs) = make_signed_changeset(
                    &key,
                    &format!("child-ack-{i}"),
                    &format!("src/f{i}.rs"),
                    format!("pub const V{i}: u64 = {i};\n").as_bytes(),
                    vec![],
                    i * 100,
                );
                store.ingest_changeset(env, &blobs).unwrap();
            }
            // Start writing 6th changeset with a torn WAL header, then immediately terminate process
            store.set_fault_injection(FaultInjection::TornWalHeaderWrite { bytes_written: 24 });
            let (env6, blobs6) = make_signed_changeset(
                &key,
                "child-unacked-6",
                "src/f6.rs",
                b"unacked 6\n",
                vec![],
                600,
            );
            let _ = store.ingest_changeset(env6, &blobs6);
            std::process::exit(42);
        }

        let dir = temp_store_dir("subprocess-crash");
        let exe = std::env::current_exe().expect("test binary path");
        let status = Command::new(exe)
            .arg("--exact")
            .arg("tests::test_subprocess_crash_recovery_no_lost_ack_and_no_phantom_visibility")
            .arg("--nocapture")
            .env("SYNAPSE_CRASH_CHILD_DIR", &dir)
            .status()
            .expect("spawn child process");
        assert_eq!(status.code(), Some(42));

        // Parent process recovers the store after child process crash
        let recovered = SynapseStore::open(
            &dir,
            FsyncPolicy::EveryCommit,
            RecoveryPolicy::TruncateTornTail,
            StoreLimits::default(),
        )
        .unwrap();
        assert_eq!(recovered.committed_seq(), WalSeq(5));
        assert_eq!(recovered.torn_frames_truncated_on_open(), 1);
        let all = recovered
            .list_changesets(None, Some(WalSeq(5)), None)
            .unwrap();
        assert_eq!(all.len(), 5);
        let _ = fs::remove_dir_all(&dir);
    }
}
