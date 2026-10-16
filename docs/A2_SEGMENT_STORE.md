# A2: Segment Store Replacing File per Blob

ADR 0003 section 9 step A2 (issue #23), design in section 5.9. Group-commit stores (WAL v2) now keep
every blob inside append-only segment files for good. Before A2, WAL v2 already wrote blobs inline in
`wal.v2.log`, but every `checkpoint_and_compact` turned the retained inline blobs back into one file
each (`blobs/<2-hex>/<64-hex>`, temporary file, rename, directory flush) and emptied the log. A2 removes
that: no blob file is written for a segment store, and acknowledged segment bytes are never rewritten
or removed.

## 1. Design

- **Segments.** Segment 1 is `wal.v2.log` (so a pre-A2 single-file WAL v2 store is simply segment 1);
  segment n >= 2 is `wal.v2.{n:06}.log`. Every segment uses the WAL v2 batch format unchanged
  (`crates/synapse-store/src/wal2.rs`): 4 KiB-aligned batches of frames with the blobs inline,
  written into pre-written zero space. A batch is one `pwrite` plus one `fdatasync`.
- **Rotation.** When the active segment holds data and the next batch would end past
  `StoreLimits::segment_bytes` (default 256 MiB), the writer creates the next file, zero-fills it,
  `sync_all`s it, and flushes the store directory, and only then writes the batch into it. A batch
  larger than a segment goes into an empty segment on its own. Reopening a store also syncs the active
  segment and flushes the directory before the first write (a file left by a crash before its
  directory flush is made durable first).
- **Index.** In memory: `digest -> (segment, offset, length)` for every blob, filled as batches become
  durable. On disk, next to each checkpoint: a segment index file `wal.v2.index.<16 hex>` (format `SSX1`,
  documented in `crates/synapse-store/src/segment.rs`) holding the replay position (segment, offset)
  and the locations of the blobs the checkpoint retains. It is bound to the checkpoint by
  `SHA-256("SYNAPSE_SEGMENT_CHECKPOINT_BINDING_V1\0" || checkpoint file name || checkpoint bytes)` and
  sealed by a SHA-256 trailer; a missing, damaged, or mismatched index refuses to open
  (`CheckpointCorrupt`). Recovery seeds the in-memory index from it and rebuilds the rest by replaying
  the segments from the replay position.
- **Checkpoint.** Order: every frame durable; segment index written atomically (temporary file,
  rename, directory flush); `checkpoint.v2` renamed into place; `wal.log` replaced by the marker; older
  index files removed. Only index metadata is ever removed: segment data is not swept (no garbage
  collection before step K1, ADR section 9). Blob reads verify the digest of the bytes read, so a
  damaged segment byte under a retained blob is refused on read (`BlobDigestMismatch`).
- **Layout marker.** `wal.log` ends with an 88-byte marker frame (kind `0xFF`); version 3 means the
  segment layout, version 2 the single-file WAL v2 layout. A pre-A2 binary refuses version 3
  (`WalVersionUnsupported`), so it can never misread a segment store as single-file.
- **Upgrade.** Opening a v1 store or a single-file WAL v2 store with group commit writes the index
  (replay from segment 1, offset 0) and then atomically rewrites `wal.log` with the version 3 marker.
  Old WAL logs still replay; v1 blob files stay where they are and stay readable.

## 2. Durability Contract

A change is acknowledged only after the `fdatasync` of its batch in its segment returned success, and,
when the batch is the first in a new segment file, after that file was synced and the store directory
flushed. Whether a flush survives power loss (the drive's volatile write cache) is UNVERIFIED; the
guarantee is "survives process crash and kernel crash" (ADR section 5.9).

Recovery rules for segments:

- Every segment id from 1 to the last must be present (a missing middle segment is `WalSequenceGap`).
- A torn tail (the last batch written, nothing valid after it, its lost end reading back as zeros) is
  accepted only in the last segment that holds data; every later segment must be all zero or empty.
  Strict recovery refuses it (`WalTornFrame`); truncating recovery zeroes it. The same damage in an
  earlier segment fails closed under both policies.
- A last segment file that is all zero, empty, or missing (crash after its creation, before or after its
  directory flush) is not data; the next rotation truncates and pre-writes it again.

## 3. Acceptance and Tests

Tests are in `crates/synapse-store/src/segment_tests.rs`, named after the acceptance items. Stores use
64 KiB segments so a few 6 KB changesets cross several segment files. Process crashes rerun the test
binary as a child that terminates itself at the injected fault (exit code 42) and logs every
acknowledgement the moment `ingest_changeset` returns it; the parent then checks that every logged
acknowledgement survives.

| Acceptance item | Test | What it shows |
| :--- | :--- | :--- |
| Torn segment | `a2_torn_segment_crash_mid_batch_keeps_every_ack` | Crash after 3,000 bytes of a batch in segment 2: strict refuses `WalTornFrame`, truncating recovery keeps all 12 acknowledged changes and nothing else, then new commits and a strict reopen work |
| Torn segment (fail closed) | `a2_torn_segment_with_data_after_it_fails_closed_under_both_policies` | The same torn-looking damage in segment 2 with data in segment 3 refuses to open under both policies; in the last segment it is a torn tail (control) |
| Crash between payload and index | `a2_crash_between_payload_and_index_keeps_every_ack` | Crash after a batch's `fdatasync`, before the in-memory index update and the acknowledgement: all 10 acknowledged changes survive, the durable unacknowledged change is present with a readable blob, and its retry returns `IdempotentDuplicate` |
| Crash between payload and index (checkpoint) | `a2_crash_after_segment_index_before_checkpoint_keeps_every_ack` | Crash after the new segment index is written, before the checkpoint rename: the old checkpoint and its own index still describe the store; all acknowledged changes survive; the next checkpoint removes the orphan index |
| Flush failure | `a2_flush_failure_directory_flush_of_new_segment_acks_nothing`, `a2_flush_failure_batch_sync_in_new_segment_acks_nothing` | A failed directory flush of a new segment, or a failed `fdatasync` of the first batch in it: nothing acknowledged, state root unchanged, store not poisoned; reopen shows nothing of the attempt; the retry commits once |
| Crash after a new segment file before its directory flush | `a2_crash_after_new_segment_file_before_directory_flush_keeps_every_ack` | Crash after segment 2 is created and pre-written, before the directory flush; reopened with the file kept, emptied, and deleted (lost directory entry): all 8 acknowledged changes survive strictly, and the next commit flushes the directory before writing |
| Durability order | `a2_directory_flush_precedes_every_batch_in_a_new_segment` | A test-only trace of the writer: in every new segment, create, then file sync, then directory flush, then the first batch; a reopened store syncs its active segment and the directory before writing |
| File per blob replaced | `a2_checkpoint_keeps_blobs_in_segments_across_reopen` | After checkpoints no file exists under `blobs/`, segment bytes are unchanged, blobs read back across four segments after reopen |
| Old stores readable | `a2_pre_a2_stores_replay_and_switch_to_segments` | The A1 fixtures written by the pre-A2 binary (v1 file-per-blob store, single-file WAL v2 store) replay to their recorded state root, switch to the segment layout, and keep working across new segments |
| Index decoder | `a2_segment_index_round_trips_and_refuses_damage` | Round trip; a flipped bit, truncation, an entry past the replay position, or unsorted entries are refused |

Three existing tests changed with the layout, keeping their intent: two A1 migration tests read the
frames after the checkpoint's replay position instead of the whole `wal.v2.log` (a checkpoint no
longer empties it), and `test_v2_checkpoint_crash_window_reopens_and_skips_covered_frames` now covers
the A2 checkpoint window (checkpoint renamed, `wal.log` not yet replaced), checks a damaged covered
blob is refused on read, and checks a missing segment index refuses to open.

### 3.1 Red before green

Evidence in `evidence/a2-segment-store/red-green/`:

- `red-main-compile.txt`: the suite against main `e863c87` cannot build (no segment store, none of the
  four new fault injections).
- `red-main-behaviour.txt`: a probe with the core assertion of
  `a2_checkpoint_keeps_blobs_in_segments_across_reopen`, written against main's API: main's checkpoint
  writes 20 blob files for 20 changesets and empties `wal.v2.log`. Fails on main, passes here.
- `mutation-M1.txt` to `mutation-M7.txt`: each acceptance test fails when the defect it guards is put
  back into this branch, and passes again without it (`green.txt`):

| Mutation | Defect put back | Tests that fail |
| :--- | :--- | :--- |
| M1 | Rotation skips the directory flush of the new segment | the three new-segment tests and the durability-order test |
| M2 | Reopen does not flush the directory before writing | durability order |
| M3 | A torn batch is accepted with data in a later segment | torn segment (fail closed) |
| M4 | The segment index is written without blob locations | both crash-between-payload-and-index tests, checkpoint, old stores |
| M5 | Replay does not rebuild blob locations from the segments | 8 of 10 |
| M6 | A failed directory flush is ignored (the batch is acknowledged) | flush failure (directory) |
| M7 | Strict recovery truncates a torn tail like `TruncateTornTail` | both torn segment tests |

The crash tests kill a process; they cannot see a missing flush on their own (the page cache survives a
process crash). The durability-order trace is what makes M1 and M2 fail.

## 4. Seconds and Joules per Accepted Change

This section is a performance report. It is not acceptance: acceptance is the crash suite in section 3.

**Method.** `synapse-bench segments` (`crates/synapse-bench/src/segments.rs`) opens a group-commit
store (`GROUP_COMMIT_DEFAULT`, 16 MiB segments) and runs N agent threads that ingest 4,000 changesets
of one 11,949-byte blob each, with `checkpoint_and_compact` after every 1,000 accepted changes. One
cell is one (agents, repetition); its time runs from the first ingest to the end of its last
checkpoint, so checkpoint cost is inside the figure. Seconds per accepted change = cell time / 4,000.
Each acknowledgement's latency is recorded (p50, p99, max). Energy is the `aien_spbm` SoC package
counter read before and after each cell; idle power is measured once per run over a 30 s window before
the first cell. Agents 1, 4, 8, 32; 3 repetitions; medians reported with the range of the three.

**Bounds (ADR section 6).** The flush bound is the cheapest `overwrite_*_fdatasync` p50 measured the same
morning by `synapse-bench floor`: 1.006 ms (64 KiB overwrite; 4 KiB and 1 MiB were 1.099 ms). The
interval bound per accepted change is the largest of: flush bound / agents (one flush can carry every
waiting agent), 11,949 B at the 15.754 GB/s measured write floor, 11,949 B at 273 GB/s memory
bandwidth, and the SHA-256 (39.46 GB/s) plus Ed25519 (397,560 verifies/s) cost of one change. The
latency bound is flush bound + bytes at 273 GB/s. The energy bound is idle package power times the
interval bound (the least energy the machine spends being on for that long). Fraction of bound =
bound / measured, so 1.0 is at the bound.

**Results** (run 2026-10-16T08:13:12Z to 08:21:08Z, branch commit `0da8183`; raw samples in
`evidence/a2-segment-store/measurement/raw-a2.json`, summary in `report-a2.json`):

| Agents | Interval per change (ms) median [range] | Interval bound (ms) | Fraction | Latency p50 / p99 / max (ms) | Latency fraction (p50) | Package energy per change (mJ) median [range] | Energy bound (mJ) | Energy fraction | Changes per flush |
| ---: | :--- | ---: | ---: | :--- | ---: | :--- | ---: | ---: | ---: |
| 1 | 1.3003 [1.2865, 1.3015] | 1.0060 | 0.774 | 1.197 / 2.200 / 12.208 | 0.841 | 27.767 [26.896, 34.392] | 20.34 | 0.733 | 1.00 |
| 4 | 0.6000 [0.5950, 0.6075] | 0.2515 | 0.419 | 2.150 / 4.287 / 41.618 | | 17.043 [14.128, 26.639] | 5.086 | 0.298 | 2.17 |
| 8 | 0.3347 [0.3345, 0.3398] | 0.1258 | 0.376 | 2.303 / 9.642 / 43.637 | | 7.970 [6.915, 14.857] | 2.543 | 0.319 | 4.01 |
| 32 | 0.1284 [0.1241, 0.1862] | 0.0314 | 0.245 | 2.573 / 39.732 / 45.933 | | 3.405 [2.866, 13.833] | 0.636 | 0.187 | 15.62 |

Idle package power over the 30 s window was 20.222 W; average package power during the cells was
21.6 to 28.4 W. Each cell wrote 4 segment files and 0 blob files; the four checkpoints of a cell took
0.14 to 0.21 s in total. Latency fraction is given only for 1 agent: with more agents an
acknowledgement waits for the batch ahead of it by design (group commit), so p50 above the single-flush
bound is queueing, not a missed flush.

**Comparison with main (pre-A2).** The same harness built on main `e863c87`
(`measurement/main-comparison.patch` adds only the benchmark module; `raw-main.json`,
`report-main.json`), same host, same morning:

| Agents | Main interval per change (ms) | Main fraction | A2 interval per change (ms) | Main package energy per change (mJ) | A2 package energy per change (mJ) |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | 7.8461 | 0.128 | 1.3003 | 253.973 | 27.767 |
| 4 | 7.0774 | 0.036 | 0.6000 | 255.014 | 17.043 |
| 8 | 6.7881 | 0.019 | 0.3347 | 222.001 | 7.970 |
| 32 | 6.6204 | 0.005 | 0.1284 | 216.313 | 3.405 |

On main each 1,000-change checkpoint writes 1,000 blob files (file, rename, directory flush each):
about 26 s of checkpoint per 4,000-change cell, with acknowledgements stalled up to 7.6 s behind it.
Between checkpoints both layouts write the same batches; the difference is the checkpoint.

**What these figures do not show.**

- The host was shared with other agent sessions (load average 2.2 at start, 5.8 at end). Energy
  above idle is small against this noise and some cells read below idle; the figures above are
  totals, not energy above idle, for that reason. Main's idle window read 33.0 W against A2's 20.2 W.
- The package meter is uncalibrated and covers the SoC only; NVMe energy is UNMEASURED.
- One host, one filesystem (ext4 on NVMe), one blob size, one segment size; no power-loss run.
- The remaining gap at 1 agent (0.774 of the flush bound) is per-batch work outside the flush (4 KiB
  padding, encoding, signature verification, index update); it was not broken down further here.

**Reproduce.**

```sh
cargo build --release -p synapse-bench
target/release/synapse-bench floor --dir <scratch-dir> --out floor.json --iterations 300
target/release/synapse-bench segments --dir <scratch-dir> --out raw.json
target/release/synapse-bench segments-report --raw raw.json --floor floor.json > report.json
```

`measurement/manifest.json` records the binaries' SHA-256, the host, and the run window;
`measurement/SHA256SUMS` seals the files.

## 5. Deviations from ADR Section 5.9

- **Padding per batch.** Batches stay 4 KiB-aligned (the WAL v2 format), so each batch, not each
  object, ends in a partly filled block. The alignment is what lets recovery tell a torn tail from
  corruption (`torn_evidence`).
- **Index rebuilt from checkpoint plus segments.** The ADR says the index "is rebuilt from
  checkpoints". Here the checkpoint carries a bound segment index for the blobs it retains, and the
  locations of later blobs come from replaying the segments after the replay position. Covered segment
  bytes before the replay position are not re-verified at open (the bound index vouches for them);
  their blobs are verified on every read.
- **WAL records and content chunks share segments, content is not chunked.** Content-defined chunking
  is step G2 (after X6); a blob is stored whole inside its frame.
- **No reclamation.** Segments only grow until K1 (garbage collection) lands; superseded blob bytes
  stay on disk. The pre-written zero tail of each finished segment (at most one pre-write chunk) is
  also not reclaimed.

## 6. Limits

- Power loss was not tested; flush durability on power loss is UNVERIFIED (drive write cache).
- 512-byte sector write atomicity on this drive is UNVERIFIED; the torn-tail rule assumes it (as W1).
- Energy is SoC package only, from the uncalibrated `aien_spbm` counters; NVMe energy is UNMEASURED.
- A v1 store opened with group commit keeps its existing blob files (they stay readable and are swept
  only by the existing unreferenced-blob sweep).
- A pre-A2 binary refuses a segment store (marker version 3); there is no downgrade path.
