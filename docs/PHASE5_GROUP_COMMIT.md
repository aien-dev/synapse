# Phase 5: Durable Group Commit

Status: implemented on branch `feat/phase5-group-commit`; measured once on the Spark (GB10) host on
2026-10-14. Evidence: `evidence/phase5-group-commit/` (manifest, report, floor, raw traces,
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

On-disk format: `wal.v2.log`, 4 KiB aligned batches with a 64-byte `SWB2` header and CRC-32C per frame.
A version marker frame appended to the legacy `wal.log` makes older fsync policies refuse the store
(`WalVersionUnsupported`) instead of silently ignoring v2 data. Torn tails are detected by CRC; strict
open refuses them, `TruncateTornTail` drops the whole unfinished batch.

API edit: `SynapseService::submit` was split into `admit_submit` (authorization and checks) and
`index_submitted` (index update) with unchanged behaviour, so the bench can run admission, then
`SharedStore::submit` outside the service lock. No root `Cargo.toml` changes.

## 3. Tests and Red-Before-Green Evidence

`crates/synapse-store/src/group_tests.rs`, 16 tests in the store crate pass:

| Test | What it proves |
| :--- | :--- |
| `test_crc32c_hardware_matches_portable` | Arm `crc32c` instructions equal the portable table |
| `test_group_commit_roundtrip_reopen_and_legacy_policy_refusal` | Data survives reopen; legacy policy refuses a v2 store |
| `test_v1_store_upgrades_to_v2_with_continuous_chain` | v1 history stays readable, sequence continues |
| `test_concurrent_submitters_acks_unique_contiguous_and_durable_before_ack` | 16 threads x 8 changes behind a Barrier; acks unique, contiguous 1..=128, never ahead of the durable watermark |
| `test_duplicate_idempotency_keys_inside_one_batch` | Same key twice in one batch commits once |
| `test_injected_sync_failure_acks_nothing_and_retry_commits_once` | Failed `fdatasync`: no ack, nothing visible after reopen, retry commits once |
| `test_injected_write_failure_acks_nothing_and_retry_commits_once` | Partial write (1500 bytes): same as above |
| `test_rollback_failure_poisons_store_until_reopen` | Sync and rollback both fail: store refuses work until reopen |
| `test_shutdown_drains_queued_submissions_and_refuses_new_ones` | Queued work finishes, new work refused |
| `test_subprocess_crash_mid_batch_no_lost_ack_no_phantom` | Child process exits mid-batch write; every ack survives, no unacked change appears |

Red runs (code deliberately broken, logs in `evidence/phase5-group-commit/red-green/`; each mutation
was reverted from a saved copy):

1. Crash: recovery made to keep the valid frames of a torn batch. Crash test fails: "strict recovery
   accepted the torn batch: committed_seq wal:5 with 4 acknowledged".
2. Failed flush: rollback zeroing removed. Sync test fails "failed batch visible after reopen"; write
   test fails on reopen with a CRC mismatch (`WalTornFrame`).
3. Ack ordering: waiters released before the batch write. Four tests fail, including "acknowledged
   wal:8 while the durable watermark was wal:1" and "no waiter of a failed batch is acknowledged".

Green: all three restored; full store suite 16/16, three consecutive runs.

## 4. Measurement Method

Command (binary built from commit `de17a0a`, source digest in `manifest.json`):

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
A 30 s idle window (22.755 W) is the counterfactual baseline for "above idle" values.

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
- E_floor(N) = 22.755 W x t_floor(N) + 0.2504 mJ (above-idle energy of verify, sign, blob digest, CRC)

"Fraction of floor" = floor / measured. 1.0 would mean running at the floor.

## 6. Results (medians of 3)

| Arm | Agents | s per change | floor | fraction | J per change (pkg) | floor | fraction | above idle | mean W |
| :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| S1 | 1 | 13.784 ms | 0.807 ms | 0.059 | 366.1 mJ | 18.60 mJ | 0.051 | 43.2 mJ | 25.8 |
| S3 | 1 | 2.010 ms | 0.807 ms | 0.401 | 50.1 mJ | 18.60 mJ | 0.371 | 3.4 mJ | 24.4 |
| S1 | 4 | 13.817 ms | 0.203 ms | 0.015 | 382.0 mJ | 4.86 mJ | 0.013 | 67.6 mJ | 27.6 |
| S3 | 4 | 0.718 ms | 0.203 ms | 0.282 | 20.3 mJ | 4.86 mJ | 0.239 | 4.0 mJ | 28.3 |
| S1 | 8 | 13.916 ms | 0.102 ms | 0.007 | 357.6 mJ | 2.57 mJ | 0.007 | 40.2 mJ | 25.6 |
| S3 | 8 | 0.398 ms | 0.102 ms | 0.257 | 14.1 mJ | 2.57 mJ | 0.183 | 5.1 mJ | 35.5 |
| S1 | 32 | 13.892 ms | 0.027 ms | 0.002 | 350.8 mJ | 0.86 mJ | 0.002 | 27.3 mJ | 24.7 |
| S3 | 32 | 0.348 ms | 0.027 ms | 0.077 | 11.3 mJ | 0.86 mJ | 0.076 | 3.4 mJ | 32.5 |

- Gate 4 S1 for reference (`docs/GATE4_QUALIFICATION.md`): 13.79, 14.33, 13.58, 14.38 ms per change at
  1, 4, 8, 32 agents. This run's S1 agrees.
- S3 mean batch size: 1.0, about 1.8, about 3.1, about 3.6 records at 1, 4, 8, 32 agents (max 1, 4,
  7, 10). No failed batches.
- S3 latency p50 / p99: 1.83 / 4.90, 2.63 / 5.92, 2.91 / 6.50, 9.91 / 27.2 ms. S1 p99 at 32 agents is
  1269 ms.
- Above-idle energy varies widely between repetitions (for example S1 at 4 agents: -0.1 to 124.8 mJ),
  because other work on the host moves the baseline. The package totals are steadier.

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
- The crash test kills a process; it cannot detect a missing fsync. Power loss was not tested.
- In S3 the service's own store is opened but unused; `SharedStore` is not yet wired into
  `SynapseService`'s read path. The 64 MiB WAL pre-write happens during setup, outside the timed window.
- The measured binary is `de17a0a`; later commits on the branch change only comments, docs and evidence.
- The floor model is a lower bound under the stated assumptions, not a proven physical limit.

## 9. Reproduction

`cargo build --release -p synapse-bench`, then the two commands in section 4 with `--out` and
`--work-dir` set. Verify the evidence with `cd evidence/phase5-group-commit && sha256sum -c SHA256SUMS`.
