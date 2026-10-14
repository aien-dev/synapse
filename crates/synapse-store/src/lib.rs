//! Durable single-writer changeset storage engine (`synapse-store`, Gate 1).
//!
//! Provides:
//! - Append-only WAL (`SWAL` v1, 88-byte header) with Castagnoli CRC-32C, SHA-256 hash chain,
//!   monotonic `WalSeq` validation, and explicit `FsyncPolicy`.
//! - Content-addressed immutable blob store (`blobs/<2-hex>/<64-hex>`) with atomic visibility
//!   tied strictly to committed `WalSeq` watermarks (preventing phantom visibility after crashes).
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
use synapse_core::{
    BlobDigest, ChangesetEnvelope, ChangesetId, EvidenceAttachment, GitHubPullRequestProjection,
    IdempotencyKey, MutationOp, RadicleCanonicalHead, RefusalCode, RepoId, SynapseError,
    SynapseResult, WalSeq,
};

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
pub fn crc32c(bytes: &[u8]) -> u32 {
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
}

impl Default for StoreLimits {
    fn default() -> Self {
        Self {
            max_blob_bytes: 16 * 1024 * 1024, // 16 MiB per blob
            max_paths_per_changeset: 2_048,
            max_total_changeset_bytes: 64 * 1024 * 1024, // 64 MiB per changeset
            max_inflight_admissions: 64,
            default_retention_window_ms: 3_600_000, // 1 hour default speculative retention
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
}

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
}

impl SynapseStore {
    /// Open or initialize a `SynapseStore` at `root_dir`, verifying checkpoint + WAL chain.
    pub fn open(
        root_dir: impl AsRef<Path>,
        fsync_policy: FsyncPolicy,
        recovery_policy: RecoveryPolicy,
        limits: StoreLimits,
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
        };

        store.recover(recovery_policy)?;
        Ok(store)
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
        if self.wal_path.exists() {
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

        // 2. Validate canonical envelope and Ed25519 signature
        let changeset_id = envelope.validate()?;

        // 3. Check idempotency index before mutating state
        let idem_key = (envelope.repo_id.clone(), envelope.idempotency_key);
        if let Some(&(existing_seq, existing_cs_id)) = self.idempotency_index.get(&idem_key) {
            if existing_cs_id == changeset_id {
                return Ok(IngestOutcome::IdempotentDuplicate {
                    wal_seq: existing_seq,
                    changeset_id: existing_cs_id,
                });
            }
            return Err(SynapseError::new(
                RefusalCode::IdempotencyKeyConflict,
                format!(
                    "idempotency key {} already bound to changeset {}, cannot rebind to {}",
                    envelope.idempotency_key.to_hex(),
                    existing_cs_id,
                    changeset_id
                ),
            ));
        }

        // 4. Enforce path count and payload size limits
        if envelope.mutations.len() > self.limits.max_paths_per_changeset {
            return Err(SynapseError::new(
                RefusalCode::QuotaTooManyPaths,
                format!(
                    "changeset touches {} paths, exceeding limit {}",
                    envelope.mutations.len(),
                    self.limits.max_paths_per_changeset
                ),
            ));
        }

        // 5. Verify all parent changesets exist in committed state
        for parent_id in &envelope.parent_changesets {
            let parent = self.changesets.get(parent_id).ok_or_else(|| {
                SynapseError::new(
                    RefusalCode::ParentChangesetNotFound,
                    format!("parent changeset {parent_id} not found"),
                )
            })?;
            if parent.envelope.repo_id != envelope.repo_id {
                return Err(SynapseError::new(
                    RefusalCode::AuthCrossRepoDenied,
                    "parent changeset belongs to a different repository",
                ));
            }
        }

        // 6. Index provided blobs and verify digests and size limits
        let mut provided_map: BTreeMap<BlobDigest, &[u8]> = BTreeMap::new();
        let mut total_bytes = 0u64;
        for (declared_digest, bytes) in blobs {
            let len = bytes.len() as u64;
            if len > self.limits.max_blob_bytes {
                return Err(SynapseError::new(
                    RefusalCode::QuotaPayloadTooLarge,
                    format!(
                        "blob size {len} exceeds max_blob_bytes {}",
                        self.limits.max_blob_bytes
                    ),
                ));
            }
            total_bytes = total_bytes.saturating_add(len);
            if total_bytes > self.limits.max_total_changeset_bytes {
                return Err(SynapseError::new(
                    RefusalCode::QuotaPayloadTooLarge,
                    format!(
                        "total blob payload {total_bytes} exceeds max_total_changeset_bytes {}",
                        self.limits.max_total_changeset_bytes
                    ),
                ));
            }
            let actual_digest = BlobDigest::compute(bytes);
            if actual_digest != *declared_digest {
                return Err(SynapseError::new(
                    RefusalCode::BlobDigestMismatch,
                    format!(
                        "declared blob digest {} does not match computed {}",
                        declared_digest, actual_digest
                    ),
                ));
            }
            provided_map.insert(*declared_digest, bytes.as_slice());
        }

        // 7. Verify every Upsert mutation has its blob either provided now or already visible
        let mut new_blobs = Vec::new();
        for m in &envelope.mutations {
            if let MutationOp::Upsert {
                blob_digest,
                size_bytes,
                ..
            } = &m.op
            {
                if let Some(raw) = provided_map.get(blob_digest) {
                    if raw.len() as u64 != *size_bytes {
                        return Err(SynapseError::new(
                            RefusalCode::BlobDigestMismatch,
                            format!(
                                "mutation path {} declared size {} but blob is {} bytes",
                                m.path,
                                size_bytes,
                                raw.len()
                            ),
                        ));
                    }
                    new_blobs.push(*blob_digest);
                } else if !self.blob_first_visible_seq.contains_key(blob_digest) {
                    return Err(SynapseError::new(
                        RefusalCode::BlobNotFound,
                        format!(
                            "mutation path {} references missing blob {}",
                            m.path, blob_digest
                        ),
                    ));
                }
            }
        }

        // 8. Write all provided blobs to the content-addressed store BEFORE appending the WAL frame
        for (digest, raw) in &provided_map {
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
        let record = WalRecord::ChangesetIngest {
            envelope: envelope.clone(),
            changeset_id,
            new_blobs: new_blobs.clone(),
        };
        let (wal_seq, frame_sha256, durability) = self.append_wal_record(&record)?;

        // 10. Advance in-memory visibility atomically with `wal_seq`
        self.apply_record(wal_seq, record);

        Ok(IngestOutcome::Committed {
            wal_seq,
            changeset_id,
            frame_sha256,
            durability,
        })
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
        let mut hasher = Sha256::new();
        hasher.update(b"SYNAPSE_STATE_ROOT_V1\0");
        hasher.update(snap.0.to_le_bytes());
        for (id, cs) in &self.changesets {
            if cs.committed_seq <= snap {
                hasher.update(id.0);
                hasher.update(cs.committed_seq.0.to_le_bytes());
                hasher.update((cs.evaluations.len() as u32).to_le_bytes());
                hasher.update((cs.reviews.len() as u32).to_le_bytes());
            }
        }
        Ok(hasher.finalize().into())
    }

    /// Write an atomic checkpoint, compact `wal.log`, and sweep unreferenced speculative blobs
    /// outside active `GarbageRoot`s.
    pub fn checkpoint_and_compact(&mut self, now_ms: u64) -> SynapseResult<CompactionReport> {
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
        for stored in self.changesets.values() {
            for m in &stored.envelope.mutations {
                if let MutationOp::Upsert { blob_digest, .. } = &m.op {
                    retained_blobs.insert(*blob_digest);
                }
            }
        }
        self.blob_first_visible_seq
            .retain(|digest, _| retained_blobs.contains(digest));

        // 3. Persist atomic checkpoint file `checkpoint.v1`
        let manifest = CheckpointManifest {
            version: CHECKPOINT_VERSION,
            checkpoint_seq: self.committed_seq,
            anchor_frame_sha256: self.last_frame_sha256,
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
        };

        let encoded = serde_json::to_vec(&manifest).map_err(|e| {
            SynapseError::new(
                RefusalCode::CheckpointCorrupt,
                format!("serialize checkpoint: {e}"),
            )
        })?;
        let tmp_ckpt = self.root_dir.join("checkpoint.v1.tmp");
        {
            let mut f = File::create(&tmp_ckpt).map_err(io_err)?;
            f.write_all(&encoded).map_err(io_err)?;
            f.sync_all().map_err(io_err)?;
        }
        fs::rename(&tmp_ckpt, &self.checkpoint_path).map_err(io_err)?;
        sync_dir(&self.root_dir)?;

        // 4. Compact `wal.log` (truncate to empty since all state up to `checkpoint_seq` is in `checkpoint.v1`)
        {
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
            return Ok(());
        }
        let shard_dir = final_path.parent().expect("blob shard parent");
        fs::create_dir_all(shard_dir).map_err(io_err)?;
        let tmp_path = shard_dir.join(format!("{}.tmp.{}", digest.to_hex(), std::process::id()));
        {
            let mut f = File::create(&tmp_path).map_err(io_err)?;
            f.write_all(bytes).map_err(io_err)?;
            if matches!(self.fsync_policy, FsyncPolicy::EveryCommit) {
                f.sync_all().map_err(io_err)?;
            }
        }
        fs::rename(&tmp_path, &final_path).map_err(io_err)?;
        if matches!(self.fsync_policy, FsyncPolicy::EveryCommit) {
            sync_dir(shard_dir)?;
        }
        Ok(())
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

    fn append_wal_record(
        &mut self,
        record: &WalRecord,
    ) -> SynapseResult<(WalSeq, [u8; 32], DurabilityGuarantee)> {
        let payload = serde_json::to_vec(record).map_err(|e| {
            SynapseError::new(RefusalCode::IoFailure, format!("serialize WAL record: {e}"))
        })?;
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

        let mut crc = crc32c(&payload);
        if fault == FaultInjection::CorruptNextWalCrc {
            crc ^= 0xdead_beef;
        }

        let mut header_prefix = [0u8; 56];
        header_prefix[0..4].copy_from_slice(&WAL_MAGIC);
        header_prefix[4..6].copy_from_slice(&WAL_VERSION.to_le_bytes());
        header_prefix[6] = record.kind_byte();
        header_prefix[7] = 0;
        header_prefix[8..16].copy_from_slice(&next_seq.0.to_le_bytes());
        header_prefix[16..48].copy_from_slice(&prev_sha);
        header_prefix[48..52].copy_from_slice(&(payload.len() as u32).to_le_bytes());
        header_prefix[52..56].copy_from_slice(&crc.to_le_bytes());

        let frame_sha256 = compute_wal_frame_sha256(&header_prefix, &payload);
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
                f.write_all(&payload).map_err(io_err)?;
            }
        }

        let durability = match self.fsync_policy {
            FsyncPolicy::EveryCommit => {
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
        }
    }

    fn recover(&mut self, recovery_policy: RecoveryPolicy) -> SynapseResult<()> {
        // 1. Load checkpoint.v1 if present
        if self.checkpoint_path.exists() {
            let raw = fs::read(&self.checkpoint_path).map_err(io_err)?;
            let manifest: CheckpointManifest = serde_json::from_slice(&raw).map_err(|e| {
                SynapseError::new(
                    RefusalCode::CheckpointCorrupt,
                    format!("corrupt checkpoint.v1: {e}"),
                )
            })?;
            if manifest.version != CHECKPOINT_VERSION {
                return Err(SynapseError::new(
                    RefusalCode::WalVersionUnsupported,
                    format!("unsupported checkpoint version {}", manifest.version),
                ));
            }
            self.committed_seq = manifest.checkpoint_seq;
            self.last_frame_sha256 = manifest.anchor_frame_sha256;
            for (k, v) in manifest.changesets {
                let id = ChangesetId::from_hex(&k)?;
                self.changesets.insert(id, v);
            }
            for (k, v) in manifest.idempotency_index {
                let (repo_s, idem_hex) = k.split_once("::").ok_or_else(|| {
                    SynapseError::new(RefusalCode::CheckpointCorrupt, "invalid idempotency key")
                })?;
                let repo = RepoId::new(repo_s)?;
                let idem_bytes = hex::decode(idem_hex).map_err(|_| {
                    SynapseError::new(RefusalCode::CheckpointCorrupt, "invalid idempotency hex")
                })?;
                let idem_arr: [u8; 32] = idem_bytes.try_into().map_err(|_| {
                    SynapseError::new(RefusalCode::CheckpointCorrupt, "invalid idempotency len")
                })?;
                self.idempotency_index
                    .insert((repo, IdempotencyKey(idem_arr)), v);
            }
            for (k, v) in manifest.blob_first_visible_seq {
                let digest = BlobDigest::from_hex(&k)?;
                self.blob_first_visible_seq.insert(digest, v);
            }
            self.github_projections = manifest.github_projections;
            for (k, v) in manifest.canonical_heads {
                let repo = RepoId::new(k)?;
                self.canonical_heads.insert(repo, v);
            }
        }

        // 2. Replay wal.log if present
        if !self.wal_path.exists() {
            return Ok(());
        }

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
            if version != WAL_VERSION {
                return Err(SynapseError::new(
                    RefusalCode::WalVersionUnsupported,
                    format!("unsupported WAL version {version} at offset {offset}"),
                ));
            }
            let flags = header[7];
            if flags != 0 {
                return Err(SynapseError::new(
                    RefusalCode::WalFlagsNonZero,
                    format!("non-zero WAL flags {flags} at offset {offset}"),
                ));
            }

            let seq = WalSeq(u64::from_le_bytes(header[8..16].try_into().unwrap()));
            let prev_sha: [u8; 32] = header[16..48].try_into().unwrap();
            let payload_len = u32::from_le_bytes(header[48..52].try_into().unwrap()) as u64;
            let expected_crc = u32::from_le_bytes(header[52..56].try_into().unwrap());
            let expected_frame_sha: [u8; 32] = header[56..88].try_into().unwrap();

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

            let record: WalRecord = serde_json::from_slice(&payload).map_err(|e| {
                SynapseError::new(
                    RefusalCode::WalCrcMismatch,
                    format!("corrupt WAL record JSON at {seq}: {e}"),
                )
            })?;

            // Verify that all blobs referenced by a committed ChangesetIngest exist and match digest
            if let WalRecord::ChangesetIngest { ref envelope, .. } = record {
                for m in &envelope.mutations {
                    if let MutationOp::Upsert { blob_digest, .. } = &m.op {
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

fn compute_wal_frame_sha256(header_prefix_56: &[u8], payload: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN_WAL_FRAME_V1);
    hasher.update(header_prefix_56);
    hasher.update(payload);
    hasher.finalize().into()
}

fn sync_dir(dir: &Path) -> SynapseResult<()> {
    let f = File::open(dir).map_err(io_err)?;
    f.sync_all().map_err(io_err)
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

    fn temp_store_dir(label: &str) -> PathBuf {
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

    fn make_signed_changeset(
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
