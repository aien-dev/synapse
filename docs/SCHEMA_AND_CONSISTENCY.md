# Synapse Changeset Schema, WAL Format, Consistency, and Garbage Collection

Tracking Issue: [aien-spark/aien-sovereign-core#515](https://github.com/aien-spark/aien-sovereign-core/issues/515)

## 1. Canonical Changeset Envelope (`SYNAPSE_ENVELOPE_VERSION = 1`)

A `ChangesetEnvelope` represents one atomic, immutable agent proposal:

* `version: u16` (must be `1`)
* `repo_id: RepoId` (canonical ASCII repository identifier, e.g., `"aien-spark/aien-sovereign-core"`)
* `base_git_oid: GitOid` (20-byte Git commit OID on which the proposal is based)
* `parent_changesets: Vec<ChangesetId>` (sorted 32-byte parent changeset digests for stacked proposals)
* `author_did: String` (`did:key:z6Mk...` encoding the author's Ed25519 public key)
* `idempotency_key: IdempotencyKey` (32-byte client deduplication token)
* `created_at_ms: u64`
* `intent_summary: String` (bounded UTF-8 description of the change)
* `mutations: Vec<PathMutation>` (strictly sorted by normalized repository-relative path, with no duplicate paths, no leading `/`, no `.` or `..` segments, and no `.git` path components):
  * `path: String`
  * `op: MutationOp`:
    * `Upsert { mode: FileMode, blob_digest: BlobDigest, size_bytes: u64 }` (`FileMode`: `Regular644`, `Executable755`, `Symlink120000`)
    * `Delete`
* `evidence_receipts: Vec<EvidenceAttachment>` (bounded machine test/verification digests attached at submission)
* `signature: [u8; 64]` (Ed25519 signature by `author_did` over the canonical unsigned envelope bytes prefixed with `"SYNAPSE_CHANGESET_SIGN_V1\0"`)

### 1.1 Domain-Separated Digests

* `BlobDigest`: `SHA-256("SYNAPSE_BLOB_V1\0" || u64_le(blob.len()) || blob_bytes)`
* `ChangesetId`: `SHA-256("SYNAPSE_CHANGESET_V1\0" || canonical_unsigned_envelope_bytes || signature_bytes)`

## 2. Single-Writer WAL Format (`SYNAPSE_WAL_VERSION = 1`)

Each record in `wal.log` is framed with a fixed 84-byte little-endian header followed by `payload_len` bytes:

| Offset | Size | Field | Description |
| :--- | :--- | :--- | :--- |
| `0..4` | `4` | `magic` | Exact ASCII bytes `b"SWAL"` |
| `4..6` | `2` | `version` | `1u16` (little-endian) |
| `6` | `1` | `record_kind` | `1 = ChangesetIngest`, `2 = EvaluationAttached`, `3 = ReviewRecorded`, `4 = GitProjected`, `5 = CanonicalPromoted`, `6 = CheckpointMarker` |
| `7` | `1` | `flags` | Record codec: `0` = v1 JSON, `1` = binary canonical codec v2 (ADR 0003 A1); any other value is refused (`WalFlagsNonZero`) |
| `8..16` | `8` | `seq` | Monotonic `WalSeq` (`u64` little-endian, starting at `1`) |
| `16..48` | `32` | `prev_frame_sha256` | `[0u8; 32]` for `seq == 1` (or checkpoint anchor digest), else `frame_sha256` of `seq - 1` |
| `48..52` | `4` | `payload_len` | Byte length of payload (`u32` little-endian) |
| `52..56` | `4` | `payload_crc32c` | CRC32C checksum over `payload` bytes |
| `56..88` | `32` | `frame_sha256` | `SHA-256("SYNAPSE_WAL_FRAME_V1\0" || header[0..56] || payload)` |
| `88..88+N` | `N` | `payload` | Canonical serialized record payload |

*(Total header size is 88 bytes.)*

### 2.1 Durability and `FsyncPolicy`

* `FsyncPolicy::EveryCommit` (default):
  1. Write each new blob to `blobs/<aa>/<digest>.tmp` (`O_CREAT | O_EXCL | O_WRONLY`), `fsync` temp file, atomic `rename` to `blobs/<aa>/<digest>`, `fsync` shard directory.
  2. Append the 88-byte WAL header + payload to `wal.log`, `fsync` `wal.log`.
  3. Advance the in-memory `committed_seq` atomic watermark so readers can observe `seq`.
* `FsyncPolicy::BatchWindow { max_records }` / `NoSyncForTesting`:
  Explicitly labeled as process-crash durable only (survives `SIGKILL` of the user-space process once kernel write buffers complete, but does not claim physical power-loss durability until `flush_sync()` completes).

## 3. Consistency Model, Replay Ordering, and Idempotency

1. **Single-Writer Total Order**:
   All state-mutating operations within a repository are serialized through the single writer and assigned a contiguous `WalSeq` (`1, 2, 3, ...`).
2. **Read-Your-Writes and Snapshot Isolation**:
   Every mutation response returns `committed_seq: WalSeq`. Any read/query call (`get`, `tree`, `diff`, `history`, `conflicts`, `status`) accepts an optional `min_visible_seq: Option<WalSeq>` and `snapshot_seq: Option<WalSeq>`:
   * If `min_visible_seq > current_committed_seq`, the query refuses with `RefusalCode::VisibilitySeqAhead` (never serving stale state silently).
   * If `snapshot_seq` is specified, the query evaluates deterministically against the exact state as of `snapshot_seq`.
3. **Deterministic Replay**:
   Replaying a checkpoint at `checkpoint_seq` followed by WAL frames `checkpoint_seq + 1 ..= committed_seq` produces the exact same `state_root_digest` across restarts. Any gap, duplicate sequence, or hash-chain mismatch refuses recovery with `WalSequenceGap` or `WalChainMismatch`.
4. **Idempotent Ingest**:
   Each `ChangesetEnvelope` includes a 32-byte `IdempotencyKey`.
   * If `(repo_id, idempotency_key)` is already committed with the **same** `ChangesetId`, `submit` succeeds idempotently with `IngestStatus::IdempotentDuplicate { wal_seq, changeset_id }` without appending a second WAL frame.
   * If `(repo_id, idempotency_key)` is already committed with a **different** `ChangesetId`, `submit` fails closed with `RefusalCode::IdempotencyKeyConflict`.

## 4. Retention, Garbage Collection, and Garbage-Root Ownership

Speculative agent changesets are high-volume and ephemeral unless promoted or pinned.

### 4.1 Garbage Roots (`GarbageRoot`)

A `ChangesetId` (and all its ancestor `parent_changesets` and referenced `BlobDigest` objects) is protected from garbage collection if and only if at least one of the following holds:
1. **Canonical Root**: The changeset is part of a verified `RadicleCanonicalHead` lineage.
2. **Human Review Root**: The changeset is referenced by an open `GitHubPullRequestProjection`.
3. **Active Lease Root**: The changeset holds an unexpired evaluation or integration queue lease (`lease_expires_at_ms > now_ms`).
4. **Retention Window Root**: `now_ms.saturating_sub(changeset.created_at_ms) <= retention_window_ms`.

### 4.2 Compaction and Sweep Procedure

During `checkpoint_and_compact(now_ms)`:
1. Compute the transitive closure of reachable `ChangesetId`s and `BlobDigest`s from all active `GarbageRoot`s.
2. Write `checkpoint.v1.tmp` containing the committed `checkpoint_seq`, `last_frame_sha256`, the retained changeset manifests, idempotency table, projections, and canonical heads; `fsync` and atomically rename to `checkpoint.v1`.
3. Compact `wal.log` so that new frames chain cleanly from `(checkpoint_seq, last_frame_sha256)`.
4. Unlink any blob file in `blobs/<aa>/<digest>` that is not in the retained `BlobDigest` closure and has no in-flight writer reservation.

## 5. Deterministic Failure and Refusal Codes (`RefusalCode`)

Every error path returns a typed `RefusalCode`:
* Storage & Integrity: `BlobDigestMismatch`, `BlobImmutableConflict`, `WalMagicInvalid`, `WalVersionUnsupported`, `WalCrcMismatch`, `WalChainMismatch`, `WalSequenceGap`, `WalTornFrame`, `WalRecordMalformed` (a binary v2 record that fails canonical decoding), `CheckpointCorrupt`, `IoFailure`
* Capacity & Backpressure: `BackpressureOverCapacity`, `QuotaPayloadTooLarge`, `QuotaTooManyPaths`, `QuotaRateLimitExceeded`, `PaginationLimitExceeded`
* Schema & Path Validation: `EnvelopeVersionUnsupported`, `PathInvalid`, `PathDuplicate`, `MutationsUnsorted`, `BaseTreeNotFound`, `ParentChangesetNotFound`, `ChangesetNotFound`, `VisibilitySeqAhead`, `IdempotencyKeyConflict`
* Auth & Security: `AuthSignatureInvalid`, `AuthGrantSignatureInvalid`, `AuthGrantExpired`, `AuthCapabilityDenied`, `AuthCrossRepoDenied`, `AuthReplayDetected`, `AuthSelfReviewRefused`
* Git & Radicle Canonicality: `GitObjectCorrupt`, `GitRefNonFastForward`, `RadicleIdentityInvalid`, `RadicleSignatureInvalid`, `RadicleQuorumInsufficient`, `StaleBaseHead`, `SplitBrainDivergence`

## 6. Schema and Storage Upgrades

Every persisted structure (`ChangesetEnvelope`, WAL frame header, `CheckpointManifest`, `AuditEntry`) starts with an explicit `u16` format version (`1`). Readers refuse any version `!= 1` prior to deserializing variable-length fields (`WalVersionUnsupported`, `EnvelopeVersionUnsupported`). Future schema versions (`v2`) will be introduced via explicit migration checkpoints that verify the `v1` state digest before writing a `v2` checkpoint.

Record codec v2 (ADR 0003 section 9 step A1, `docs/A1_BINARY_CODEC.md`): WAL record payloads and the checkpoint move from JSON to one canonical binary encoding; the envelope, its signature and every identity are unchanged. A store with v1 history keeps writing JSON until its first `checkpoint.v2`; that migration checkpoint records the last v1 `state_root_digest` and chains its own root to it, and every later checkpoint chains to the previous root. `checkpoint.v1` is then replaced by a `version: 2` tombstone so binaries that only know v1 refuse the store. Fresh stores write binary from the first record. Replay refuses a JSON record after a binary one and a binary record before the migration (`WalVersionUnsupported`). A frame whose declared payload exceeds `StoreLimits::max_wal_record_bytes` is refused before anything is allocated for it (`QuotaPayloadTooLarge`).
