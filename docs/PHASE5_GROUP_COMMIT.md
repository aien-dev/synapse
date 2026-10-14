# Phase 5: Durable Group Commit

Status: implemented on branch `feat/phase5-group-commit`; measured on the Spark (GB10) host on
2026-10-14 from commit `6826610` (the code with the review fixes). Evidence: `evidence/phase5-group-commit/` (manifest, report, floor, raw traces,
red/green test logs, `SHA256SUMS`).

## 1. Design in Two Lines

Many submitters hand prepared changes (signature, digests and encoding done in parallel on their own
threads) to one leader, which writes the whole batch with one positioned write into WAL v2 space that
was written and synced in advance, then calls `fdatasync` once and only then acknowledges every member.

A failed write or sync rolls the batch back (zeroes it) and acknowledges nobody; if the rollback
itself fails the store is poisoned until reopened, and recovery accepts a batch all-or-nothing.

## 2. Durability Rule

No acknowledgement before the blobs, directories and WAL bytes that make the change readable are
synced. Concretely (`crates/synapse-store/src/shared.rs`, `wal2.rs`):

- Blobs travel inline in the WAL v2 batch, so the batch `fdatasync` covers them.
- WAL v2 space is extended by writing zeros and calling `sync_all` (file size and directory entry
  synced) before any batch lands in it; the file is created with a directory `fsync`.
- Waiters are released only after `v2_finish` has advanced the durable watermark. The test-only
  `ack_log` records release order so tests can check it.

On-disk format: `wal.v2.log`, 4 KiB aligned batches with a 64-byte `SWB2` header, CRC-32C per frame,
and an 8-byte trailer `SWB2END!` (no zero byte) closing every batch. A version marker frame added to
the legacy `wal.log` makes older fsync policies refuse the store (`WalVersionUnsupported`) instead of
silently ignoring v2 data. The upgrade writes the old log plus the marker to `wal.log.tmp`, syncs it,
renames it over `wal.log` and syncs the directory, so a crash leaves either the v1 store or the
complete marker.

Torn tail rule: an invalid batch is a torn tail only when no valid batch follows it, the sector
holding the end of its declared extent reads back all zero, and every byte after it is zero (or its
header's whole sector is zero). The space was zero before the write and the trailer has no zero
byte, so a complete batch never ends in zeros, however few bytes of it sit in the last sector.
Strict open refuses a torn tail; `TruncateTornTail` drops that whole batch. A batch that still ends
in its trailer but fails validation is corruption, and both policies refuse it, even when its blobs
contain whole zero sectors.

Checkpoint crash window: `checkpoint_and_compact` syncs the WAL, renames `checkpoint.v1` into place,
then empties the logs. A crash between the rename and the emptying leaves frames the checkpoint
already covers. Recovery verifies them (CRC, frame digest, one unbroken hash chain that must end at
the checkpoint's sequence and anchor digest) and skips them, for `wal.log` (v1 frames and the v2
marker) and `wal.v2.log` alike. Skipping is allowed only before the first frame is applied.

Unknown outcome: a refusal is not proof of non-commit. When a batch's rollback fails (the store is
then poisoned) or the leader dies after its write, callers get `IoFailure` although the batch may be
durable. Clients must reopen and retry with the same idempotency key; the retry returns
`IdempotentDuplicate` if the first attempt landed and commits exactly once otherwise
(`SharedStore::submit` documents this, and the error message says so).

API edit: `SynapseService::submit` was split into `admit_submit` (authorization and checks) and
`index_submitted` (index update) with unchanged behaviour, so the bench can run admission, then
`SharedStore::submit` outside the service lock. No root `Cargo.toml` changes.

## 3. Tests and Red-Before-Green Evidence

`crates/synapse-store/src/group_tests.rs` (15 tests; the store crate runs 21, all pass):

| Test | What it proves |
| :--- | :--- |
| `test_crc32c_hardware_matches_portable` | Arm `crc32c` instructions equal the portable table |
| `test_group_commit_roundtrip_reopen_and_legacy_policy_refusal` | Data survives reopen; legacy policy refuses a v2 store |
| `test_v1_store_upgrades_to_v2_with_continuous_chain` | v1 history stays readable, sequence continues |
| `test_concurrent_submitters_acks_unique_contiguous_and_durable_before_ack` | 16 threads x 8 changes behind a Barrier; acks unique, contiguous 1..=128, never ahead of the durable watermark |
| `test_duplicate_idempotency_keys_inside_one_batch` | Same key twice in one batch commits once |
| `test_injected_sync_failure_acks_nothing_and_retry_commits_once` | Failed `fdatasync`: no ack, nothing visible after reopen, retry commits once |
| `test_injected_write_failure_acks_nothing_and_retry_commits_once` | Partial write (1500 bytes): same as above |
| `test_rollback_failure_poisons_store_until_reopen` | Sync and rollback both fail: store refuses work until reopen; after reopen the refused record is there and the retry is `IdempotentDuplicate` |
| `test_shutdown_drains_queued_submissions_and_refuses_new_ones` | Queued work finishes, new work refused |
| `test_subprocess_crash_mid_batch_no_lost_ack_no_phantom` | Child process exits mid-batch write; every ack survives, no unacked change appears |
| `test_v2_checkpoint_crash_window_reopens_and_skips_covered_frames` | Crash after the checkpoint rename, before `wal.log` is replaced and before `wal.v2.log` is reset: reopens with the same state, new commits follow; a damaged covered frame or a covered chain short of the anchor is refused |
| `test_v1_checkpoint_crash_window_reopens_and_skips_covered_frames` | Same window for a v1 store (before `wal.log` is truncated) |
| `test_torn_last_sector_with_short_tail_is_truncatable` | Last batch ends 9 to 63 bytes into its last sector and that sector is lost: strict refuses (`WalTornFrame`), `TruncateTornTail` drops only that batch |
| `test_corrupt_last_batch_with_zero_sector_in_blob_is_not_dropped` | One flipped bit in an acknowledged last batch whose blob holds whole zero sectors: both policies refuse, nothing truncated |
| `test_v2_upgrade_marker_is_atomic_and_survives_a_stray_temp_file` | A crash mid-upgrade leaves the v1 store intact; the upgrade then completes |

Red runs (code deliberately broken, logs in `evidence/phase5-group-commit/red-green/`; each mutation
was reverted from a saved copy):

1. Crash: recovery made to keep the valid frames of a torn batch. Crash test fails: "strict recovery
   accepted the torn batch: committed_seq wal:5 with 4 acknowledged".
2. Failed flush: rollback zeroing removed. Sync test fails "failed batch visible after reopen"; write
   test fails on reopen with a CRC mismatch (`WalTornFrame`).
3. Ack ordering: waiters released before the batch write. Four tests fail, including "acknowledged
   wal:8 while the durable watermark was wal:1" and "no waiter of a failed batch is acknowledged".

Green: all three restored; full store suite 16/16, three consecutive runs.

Review fixes (independent review of PR #18), red on the unfixed code, then green (`red-green/review-red.txt`, `review-green.txt`):

4. Checkpoint crash window: both crash-window tests fail before the fix with `WalSequenceGap` ("expected wal:6, found wal:1" for v2, "expected wal:4, found wal:1" for v1): the store could never be opened again.
5. Torn tail rule: before the fix the short-tail test fails because the lost sector is not recognised as torn (strict open returns `WalCrcMismatch` instead of `WalTornFrame`, so `TruncateTornTail` refuses to open too), and the bit-rot test fails because the corrupt acknowledged batch is classified as torn (`WalTornFrame`), which `TruncateTornTail` would drop.
6. Atomic upgrade: before the fix the upgrade appended in place (the stray-temp-file test fails on its `wal.log.tmp` check).

Green: store crate 21/21, three consecutive runs.

## 4. Measurement Method

Command (release binary built from commit `6826610e7cd2`, clean tree; `manifest.json` records the
revision and the `git archive` source digest):

```
synapse-bench run --fixture-repo ~/workspace/aien-sovereign-core \
  --fixture-rev 1b6e340d48417dfbcfe2df56d48a0696a3a9b250 --write-only --arms S1,S3 \
  --tiers 1,4,8,32 --reps 3 --ops-floor 4000 --idle-window-s 30
synapse-bench floor   # hardware floor, floor.json
```

- S1 is Gate 4's arm: Synapse with `EveryCommit` (one WAL append plus fsync per change).
- S3 is the same service admission (auth, checks) followed by `SharedStore` group commit
  (`GROUP_COMMIT_DEFAULT`: up to 256 records, no added delay).
- Agent counts 1, 4, 8, 32 are an observed sweep, not targets. 4000 changes per cell, 3 repetitions,
  medians reported. Storage: `/dev/nvme0n1p2`, ext4.

Energy sensor: the `aien_spbm` hwmon device, which reads the GB10 SPBM firmware energy counters. It
covers the SoC package only (CPU clusters plus the rest of the package); the NVMe drive is
UNMEASURED. 1 mJ step, the counter updates about every 0.1 s, sampled at 10 Hz. There is no published
accuracy and it has never been compared with an external meter: treat all joules as uncalibrated.
A 30 s idle window (22.731 W) is the counterfactual baseline for "above idle" values.

## 5. Hardware Floor

From `floor.json` (300 iterations each, same filesystem):

| Floor item | Measured p50 |
| :--- | :--- |
| Overwrite already-synced space + `fdatasync`, 4 KiB / 64 KiB / 1 MiB | 1.106 / 0.903 / 0.805 ms |
| Append + fsync or fdatasync (4 KiB to 1 MiB) | 3.5 to 3.8 ms |
| `fallocate`d space + `fdatasync` | 3.715 ms |
| New blob file + fsync + rename + directory fsync | 6.401 ms |
| Sequential write, O_DIRECT / buffered | 0.138 / 0.263 s per GiB |
| Ed25519 verify / sign | 0.023 / 0.010 ms |
| Blob digest (12 KiB) / CRC-32C (request sized) | 0.021 / 0.001 ms |

Floor per change at N agents (assumptions: ext4 file, not raw block device; the cheapest sync
measured; all N changes share one sync; the essential CPU work runs on 20 cores in parallel):

- t_floor(N) = max(0.805 ms, 0.055 ms x ceil(N/20)) / N + 11 500 B x 0.138 s/GiB
- E_floor(N) = 22.731 W x t_floor(N) + 0.2766 mJ (above-idle energy of verify, sign, blob digest and CRC)

One idle baseline throughout: the sweep's 30 s idle window, 22.731 W. `floor.json` stores
per-operation above-idle energy against its own 5 s idle window (23.19 W), which gives 0.2504 mJ for
the same four operations; re-based to 22.731 W (per operation: package joules minus 22.731 W times
the operation's share of its window) they sum to 0.2766 mJ: verify 0.0919, sign 0.0165, blob digest
0.1655, CRC 0.0027 mJ. `floor.json` itself is unchanged; it was measured with the `floor`
subcommand from the earlier build `de17a0a` (the floor is hardware and file system behaviour, and
that subcommand did not change).

"Fraction of floor" = floor / measured. 1.0 would mean running at the floor.

## 6. Results (medians of 3)

| Arm | Agents | s per change | floor | fraction | J per change (pkg) | floor | fraction | above idle | mean W |
| :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| S1 | 1 | 14.217 ms | 0.806 ms | 0.057 | 305.2 mJ | 18.61 mJ | 0.061 | -18.0 mJ | 21.5 |
| S3 | 1 | 2.048 ms | 0.806 ms | 0.394 | 51.7 mJ | 18.61 mJ | 0.360 | 4.9 mJ | 24.9 |
| S1 | 4 | 14.030 ms | 0.203 ms | 0.014 | 316.3 mJ | 4.88 mJ | 0.015 | -3.0 mJ | 22.5 |
| S3 | 4 | 0.726 ms | 0.203 ms | 0.279 | 17.2 mJ | 4.88 mJ | 0.283 | 0.7 mJ | 23.8 |
| S1 | 8 | 13.623 ms | 0.102 ms | 0.007 | 376.9 mJ | 2.60 mJ | 0.007 | 67.3 mJ | 27.7 |
| S3 | 8 | 0.411 ms | 0.102 ms | 0.248 | 12.9 mJ | 2.60 mJ | 0.202 | 4.0 mJ | 33.1 |
| S1 | 32 | 14.038 ms | 0.027 ms | 0.002 | 305.2 mJ | 0.88 mJ | 0.003 | -13.9 mJ | 21.7 |
| S3 | 32 | 0.349 ms | 0.027 ms | 0.076 | 8.5 mJ | 0.88 mJ | 0.104 | 0.6 mJ | 24.6 |

- Gate 4 S1 for reference (`docs/GATE4_QUALIFICATION.md`): 13.79, 14.33, 13.58, 14.38 ms per change at
  1, 4, 8, 32 agents. This run's S1 agrees within about 0.5 ms.
- S3 mean batch size: 1.0, about 1.8, about 3.1, about 3.6 records at 1, 4, 8, 32 agents (max 1, 4,
  7, 16). No failed batches.
- S3 latency p50 / p99: 1.86 / 5.09, 2.71 / 5.61, 2.99 / 6.69, 9.95 / 28.3 ms. S1 p99 at 32 agents is
  1372 ms.
- Above-idle energy varies widely between repetitions (for example S1 at 1 agent: -42.6 to 11.0 mJ),
  and medians can be negative: S1 often drew less package power than the idle window (21.5 W
  against 22.7 W), so other work on the host moved the baseline. Do not read S1 above-idle values
  as S1's own cost. The package totals are steadier.
- An earlier run on `de17a0a` (before the review fixes) gave S3 2.010, 0.718, 0.398, 0.348 ms per
  change; it is replaced by this run and kept only in git history.

## 7. What Still Sits Between the Agent and the Floor

- Admission is serialized by the service lock (auth payload digest about 0.108 ms, signature
  verification, JSON). This limits how many changes reach a batch (about 3.6 at 32 agents) and holds
  per-change time near 0.35 ms.
- JSON encode and decode on the wire (the bench approximates the transport).
- The signature is verified twice (admission and `prepare_ingest`).
- The ext4 journal and page cache: the floor itself is an ext4 overwrite plus `fdatasync`, not a raw
  block write.
- A single agent waits a full write-and-sync round per change: about 2.0 ms against the 0.8 ms sync.

## 8. Limits

- Energy is SoC package only and uncalibrated; NVMe energy is UNMEASURED. Above-idle values use an
  idle window as a counterfactual and can be noisy or negative.
- Other work was running on the host (load average about 2 during the idle window).
- One run, one host, one filesystem. No confidence intervals beyond min and max of 3 repetitions.
- 512-byte sector write atomicity on this drive is UNVERIFIED; the torn-tail rule assumes it.
- A torn write that lost a middle sector of the last batch but persisted its final sector is not
  recognised as torn: recovery then refuses to open under both policies (fails closed; an operator
  must inspect). A corrupt last batch whose final sector became all zero would be taken as torn and
  dropped; that needs the whole final sector zeroed, not bit rot.
- A refused submit (`IoFailure`) can still be durable after a failed rollback or a leader failure;
  only a retry with the same idempotency key settles it.
- The crash test kills a process; it cannot detect a missing fsync. Power loss was not tested.
- In S3 the service's own store is opened but unused; `SharedStore` is not yet wired into
  `SynapseService`'s read path. The 64 MiB WAL pre-write happens during setup, outside the timed window.
- The measured binary is `6826610`. Later commits on the branch rebase onto main and change docs
  and evidence; the store code is unchanged since the measurement.
- A stray `wal.log.tmp` left by a crash during the v1 to v2 upgrade is not removed on open; it is
  overwritten when the upgrade runs again, and it is harmless but stays on disk otherwise.
- The floor model is a lower bound under the stated assumptions, not a proven physical limit.

## 9. Reproduction

`cargo build --release -p synapse-bench`, then the two commands in section 4 with `--out` and
`--work-dir` set. Verify the evidence with `cd evidence/phase5-group-commit && sha256sum -c SHA256SUMS`.
