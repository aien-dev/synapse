# Gate 4: Comparative Qualification Report

Tracking Issue: [aien-spark/aien-sovereign-core#515](https://github.com/aien-spark/aien-sovereign-core/issues/515)

Evidence: [`evidence/gate4-qualification/`](../evidence/gate4-qualification/) (`report.json`, `manifest.json`, `traces/*.jsonl`, `SHA256SUMS`), produced by `scripts/run_gate4_qualification.sh` with the `synapse-bench` crate. Every number below is copied from `report.json` or `manifest.json`. The harness code contains no verdict; the adoption section at the end is a proposal for Drake's decision.

## 1. What Was Measured, in Short

* **Today's hive practice (G1, a fresh `git worktree add` per proposal)** costs about 1 second and 146 MB of disk per proposal on this repository. Every other arm removes that cost.
* **Durable writes (fsync before acknowledging):** Synapse S1 commits about 70 proposals per second no matter how many agents submit, because one writer serializes every fsync. Git plumbing with `core.fsync=all` (G3F) starts lower (18.7 per second for one agent) but scales with agents (107 per second at 8 agents, 383 at 32). S1 has the lower latency up to 4 agents; G3F has the higher throughput and much lower tail latency from 8 agents up.
* **Writes acknowledged from the page cache:** Synapse S2 sustains 1,557 to 2,036 proposals per second; Git plumbing at git's default durability (G3) sustains 75 (one agent) to 1,016 (32 agents).
* **Reads:** the git command line answers single-file reads (through a persistent `git cat-file --batch`), full tree listings, and diffs with lower median latency than the Synapse API on the same data (for example `git ls-tree -r` 3.6 ms against Synapse `tree` 17.7 ms). Spawning a new `git cat-file` for each file read (1.51 ms) is slower than Synapse `read_file` (1.11 ms).
* **Correctness and conformance:** Synapse's conflict detection matched the generator's ground truth on all 253 pairs, flagged every pair Git could not merge (0 false negatives), and over-flagged 3 pairs that Git merged cleanly. All 29 conformance cases (WAL 11, Git 7, Radicle 11, including a live Radicle repository) passed in each of 3 runs.
* **CPU:** Synapse spends about 0.5 to 1.1 ms of CPU per proposal; Git plumbing spends about 14 to 16 ms (five git process launches per proposal).

## 2. Method

### 2.1 Fixture

| Field | Value |
| :--- | :--- |
| Repository | `aien-sovereign-core`, local checkout on `spark-b87b` |
| Pinned commit | `1b6e340d48417dfbcfe2df56d48a0696a3a9b250` (the Gate 0 baseline commit) |
| Tree OID | `39684d806998aa579244a55aab41b954be963525` |
| Files | 4,376 (145,731,971 bytes; largest file 65,855,376 bytes) |
| Editable text files used by the generator | 2,307 (256 bytes to 64 KiB, at least 8 lines) |
| Isolation | One `git clone --no-checkout --no-hardlinks` into a temporary work directory; every cell then clones that copy with `--local`. The original repository is only read (`clone`, `rev-parse`, `for-each-ref`). |

The manifest records `HEAD` and a SHA-256 over `git for-each-ref` of the original repository before and after the run. `HEAD` was unchanged. The refs digest changed: a separate agent session working on `aien-sovereign-core` deleted a local branch and ran a fetch at about 15:24 to 15:25 UTC, inside the run window (visible as new `packed-refs`, `config`, and `FETCH_HEAD` timestamps in the original repository). The harness never writes there, and the pinned commit and tree are content addressed, so the fixture itself is unaffected.

### 2.2 Arms

| Arm | What one proposal does | Durability at acknowledgement | Setup (excluded from per-proposal latency) |
| :--- | :--- | :--- | :--- |
| S1 | Signed `SynapseService::submit` with JSON encode and decode of the request; `FsyncPolicy::EveryCommit` | Blob files, shard directories, and WAL fsynced before ack (receipts: `FsyncBeforeAck` on every proposal) | Register the base tree in memory (once per process) |
| S2 | Same, `FsyncPolicy::BatchWindow { max_records: 64 }`; the final `sync_wal` is inside the timed window | Process-crash durable only between WAL syncs; blobs never fsynced (receipts: 394 or 410 `ProcessCrashPageCacheOnly` and 6 `FsyncBeforeAck` per cell) | Same as S1 |
| G1 | `git worktree add -b` (full checkout), edit, `git add`, `git commit` | Git default | None (the checkout is the per-proposal cost) |
| G2 | One persistent worktree per agent: `git checkout -B <branch> <base>`, edit, `add`, `commit` | Git default | `git worktree add --detach` per agent |
| G3 | No checkout: per-agent temporary index, `hash-object -w --stdin-paths`, `update-index --index-info`, `write-tree`, `commit-tree`, `update-ref` | Git default | `read-tree` of the base into a per-agent index |
| G3F | G3 with `-c core.fsync=all -c core.fsyncMethod=fsync` on every git command | Objects, index, and refs fsynced | Same as G3 |

Git default durability: `core.fsync`, `core.fsyncMethod`, and `core.fsyncObjectFiles` are unset in every config scope (manifest `git_config`). `git-config(1)` for git 2.43 states that the default "on most platforms is equivalent to `core.fsync=committed,-loose-object`", and that `committed` is equivalent to `objects`, which is `loose-object,pack`. The default therefore hardens packs only; the loose objects, index, and refs these arms write are not fsynced. An `strace -f -c` probe of one `git hash-object -w --stdin` counted 0 fsync-family calls with the default configuration and 1 with `core.fsync=all core.fsyncMethod=fsync`. The man page names `writeout-only` as the macOS default for `core.fsyncMethod` and does not state the Linux default (UNVERIFIED); G3F sets it explicitly.

S1 and G3F are the like-for-like durable pair. S2 and G3 both acknowledge from the page cache and lose recent work on power loss.

### 2.3 Workload and Load Model

* Each proposal makes 1 edit (50%), 2 edits (35%), or 3 edits (15%). Each edit modifies an existing text file by inserting a 3 to 12 line hunk (70%), adds a new file under `synapse-gate4-bench/` (20%), or deletes an existing file (10%). Proposals are generated from a recorded seed and are identical across arms for the same tier and repetition. Every arm keeps every proposal.
* Tiers: 1, 4, and 8 agents (representative) and 32 agents (stress). Each agent is a thread; all start on a shared barrier. Synapse latency includes the wait for the single-writer service lock (reported separately as queue wait).
* Operations per cell: at least 400 for S1, S2, G2, G3, and G3F (`max(8, ceil(400 / agents))` per agent). G1 is capped at `max(2, ceil(32 / agents))` per agent (32 or 64 per cell) because each operation is a full checkout.
* Each cell runs 3 times. Within each repetition, the order of all write cells, the query cell, and the conformance cell is shuffled with a recorded seed (`cell_order_seed` in the manifest). Results show the median across repetitions with the minimum and maximum in parentheses.
* p95 is reported only when a cell has at least 20 samples and p99 only when it has at least 100; otherwise "n/a".
* Write and read phases are measured separately; there is no mixed-load measurement.
* Each cell runs in its own child process. CPU is `getrusage` self plus waited children (user plus system) over the timed window. Peak RSS of the arm process and of its largest git child are reported separately and never summed.
* Storage is `du -s -b` (apparent) and `du -s -B1` (allocated) over the arm's directories before setup, after setup, and after the operations.

### 2.4 Host

| Field | Value |
| :--- | :--- |
| Host | `spark-b87b`, aarch64, Cortex-X925 and Cortex-A725 cores (`lscpu`), 20 logical CPUs, 127,598,752 KiB RAM |
| Kernel | 7.0.0-1019-nvidia |
| Work directory filesystem | ext4 on `/dev/nvme0n1p2`, 1,040,488,902,656 bytes free at start |
| Toolchain | git 2.43.0, rustc 1.98.1, cargo 1.98.1, release build |
| Run | 81 cells, 627.9 s inside the harness (10 min 46 s including the release build), 0 failed cells |

The host was not idle. A whole-filesystem `tar` plus `zstd` backup and another agent's test binary were running before the run started and were still running after it finished. Disk-bound arms (S1, G3F, G1, G2) are the most exposed; the size of the effect is not measured (UNVERIFIED).

## 3. Write Phase Results

### 3.1 Throughput and Latency

Latency is per proposal in milliseconds; "n per rep" is the number of successful timed proposals in each repetition.

| Agents | Arm | n per rep | Throughput ops/s | p50 ms | p95 ms | p99 ms | Queue wait p50 ms |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| 1 | S1 | 400/400/400 | 72.5 (70 to 73.2) | 11.8 (11.62 to 12.41) | 23.92 (23.89 to 25.18) | 27.89 (26.22 to 28.29) | 0 |
| 1 | S2 | 400/400/400 | 1666.5 (1396.6 to 1675.9) | 0.34 (0.33 to 0.34) | 1.68 (1.5 to 1.81) | 4.11 (3.95 to 4.11) | 0 |
| 1 | G1 | 32/32/32 | 1 (1 to 1) | 1061.46 (1058.28 to 1062.77) | 1096.3 (1089.92 to 1110.62) | n/a | n/a |
| 1 | G2 | 400/400/400 | 38.8 (38.5 to 39.3) | 23.71 (23.54 to 25.73) | 32.17 (31.86 to 33.02) | 34.78 (33.31 to 35.66) | n/a |
| 1 | G3 | 400/400/400 | 75.2 (72.3 to 77.4) | 13.1 (12.8 to 13.85) | 17.17 (16.31 to 17.56) | 18.67 (17.28 to 18.68) | n/a |
| 1 | G3F | 400/400/400 | 18.7 (18.6 to 18.9) | 51.63 (51.03 to 52.72) | 75.99 (74.09 to 76.31) | 85.87 (81.16 to 87.34) | n/a |
| 4 | S1 | 400/400/400 | 69.8 (67.8 to 70.7) | 54.41 (53.08 to 55.13) | 106.32 (105.49 to 128.68) | 150.77 (146.28 to 242.23) | 39.75 |
| 4 | S2 | 400/400/400 | 1805.4 (1560.9 to 2113.2) | 1.53 (1.39 to 1.58) | 4.86 (4.64 to 5.05) | 7.53 (6.81 to 14.74) | 0.82 |
| 4 | G1 | 32/32/32 | 4.1 (4.1 to 4.2) | 892.83 (872.37 to 923.11) | 1117.79 (1108.84 to 1136.01) | n/a | n/a |
| 4 | G2 | 400/400/400 | 140.3 (128.1 to 143.7) | 23.7 (23.66 to 23.88) | 32.15 (31.08 to 32.57) | 76.27 (51.93 to 103.68) | n/a |
| 4 | G3 | 400/400/400 | 269.5 (269.2 to 274) | 14.39 (14.31 to 14.63) | 18.07 (18.06 to 18.21) | 19.06 (18.92 to 19.08) | n/a |
| 4 | G3F | 400/400/400 | 54.2 (52.6 to 54.3) | 69.55 (69.54 to 72.26) | 103.28 (101.25 to 108.3) | 118.85 (115.94 to 121.79) | n/a |
| 8 | S1 | 400/400/400 | 73.6 (72.5 to 75.1) | 100.19 (96.48 to 101.84) | 213.91 (212.57 to 216.19) | 303.6 (268.73 to 311.13) | 87.16 |
| 8 | S2 | 400/400/400 | 2035.5 (1975.3 to 2180.7) | 3.21 (3.19 to 3.32) | 6.89 (6.68 to 7.29) | 10.32 (8.59 to 18.15) | 2.49 |
| 8 | G1 | 32/32/30 | 7 (6.9 to 8.7) | 987.42 (872.42 to 1100.44) | 1146.59 (1107.45 to 1363.79) | n/a | n/a |
| 8 | G2 | 400/400/400 | 204.5 (200.6 to 210.9) | 23.79 (23.32 to 24.11) | 30.89 (30.85 to 31.51) | 208.2 (201.02 to 268.19) | n/a |
| 8 | G3 | 400/400/400 | 555.4 (545.4 to 567.3) | 14.01 (13.6 to 14.05) | 17.73 (17.66 to 17.87) | 18.93 (18.85 to 19.14) | n/a |
| 8 | G3F | 400/400/400 | 107.2 (104.8 to 111.2) | 68.02 (67.97 to 69.9) | 100.99 (98.35 to 109.85) | 115.82 (108.29 to 119.41) | n/a |
| 32 | S1 | 416/416/416 | 69.5 (69 to 73.1) | 417.81 (410.57 to 429.6) | 904.74 (882.28 to 944.83) | 1221.51 (995.56 to 1235.7) | 400.9 |
| 32 | S2 | 416/416/416 | 1557.3 (1485.8 to 1980.8) | 15.36 (14.56 to 15.87) | 74.61 (20.74 to 93.68) | 89.22 (31.38 to 108.17) | 14.43 |
| 32 | G1 | 64/64/64 | 15.1 (14.9 to 15.4) | 1698.12 (1599.37 to 1906.36) | 2414.39 (2382.47 to 2695.68) | n/a | n/a |
| 32 | G2 | 416/416/416 | 326.3 (302.6 to 337.9) | 53.01 (50.98 to 61.03) | 429.77 (399.52 to 431.82) | 669.63 (638.2 to 695.03) | n/a |
| 32 | G3 | 416/416/416 | 1015.9 (971.2 to 1046.8) | 28.44 (28.19 to 30.2) | 44.75 (42.62 to 46.58) | 51.63 (48.7 to 58.71) | n/a |
| 32 | G3F | 416/416/416 | 383.2 (364.3 to 400.7) | 70.75 (67.71 to 74.88) | 106.58 (105.2 to 107.89) | 119.39 (115.38 to 119.64) | n/a |

Failed operations: 2 of 96 G1 operations at 8 agents (one repetition) failed with `fatal: failed to read .git/worktrees/a005-p00000/commondir: Success` while several agents ran `git worktree add` in the same repository at once. Every other operation in every cell succeeded. The cause looks like one `worktree add` reading another's half-written administrative files (UNVERIFIED interpretation of git's message).

What the table shows:

* S1 throughput stays near 70 ops/s from 1 to 32 agents; its latency grows with agents almost entirely as queue wait (400.9 ms of the 417.8 ms median at 32 agents).
* G3F and G3 throughput grows with agents because independent git processes write in parallel. G3F overtakes S1 between 4 and 8 agents.
* G2 and G1 tail latency grows sharply at 8 and 32 agents (G2 p99 669.6 ms at 32 agents).

### 3.2 Setup Cost (Per Unit, Excluded from Latency)

| Arm | Setup unit | Median ms per unit at 1 agent | Median ms per unit at 32 agents |
| :--- | :--- | :--- | :--- |
| S1, S2 | Register the 4,376-file base tree in memory (once per process) | 381.9 (S1), 384.5 (S2) | 380.2 (S1), 384.9 (S2) |
| G2 | `git worktree add --detach` per agent | 574.1 | 578.8 |
| G3 | `read-tree` into a per-agent index | 10.1 | 7.8 |
| G3F | Same with fsync | 55.7 | 11 |

The G2 figure agrees with the Gate 0 worktree checkout median of 588 ms.

### 3.3 CPU and Memory

| Agents | Arm | CPU ms per proposal | Peak RSS arm process MiB | Peak RSS largest git child MiB |
| :--- | :--- | :--- | :--- | :--- |
| 1 | S1 | 0.88 (0.8 to 0.96) | 167 | n/a |
| 1 | S2 | 0.51 (0.5 to 0.52) | 167 | n/a |
| 1 | G1 | 990.45 (988.48 to 992.32) | 40 | 178 |
| 1 | G2 | 35.92 (35.54 to 36.2) | 39 | 178 |
| 1 | G3 | 13.57 (13.2 to 14.15) | 40 | 40 |
| 1 | G3F | 15.3 (14.66 to 15.44) | 39 | 39 |
| 32 | S1 | 1.06 (1.04 to 1.09) | 175 | n/a |
| 32 | S2 | 0.82 (0.76 to 0.82) | 175 | n/a |
| 32 | G1 | 1019.98 (994.43 to 1064.14) | 40 | 178 |
| 32 | G2 | 51.72 (51.1 to 52.27) | 39 | 178 |
| 32 | G3 | 14.01 (13.89 to 14.06) | 40 | 40 |
| 32 | G3F | 16.49 (16.18 to 16.49) | 39 | 39 |

Tiers 4 and 8 sit between these rows (`write_summary` in `report.json`). The Synapse process holds the full base tree in memory (145.7 MB of file content), which is most of its 167 to 175 MiB. The "largest git child" column comes from `RUSAGE_CHILDREN` and is at least the arm process's own size for G3 and G3F (40 MiB both); this suggests Linux counts memory a child inherits before `exec` (UNVERIFIED), so treat that column as an upper bound.

### 3.4 Storage Per Proposal

| Agents | Arm | Apparent bytes per proposal | Allocated bytes per proposal | Setup apparent bytes | Mean Synapse request bytes |
| :--- | :--- | :--- | :--- | :--- | :--- |
| 1 | S1 | 11,949 | 17,818 | 0 | 37,993 |
| 1 | S2 | 11,948 | 17,807 | 0 | 37,993 |
| 1 | G1 | 146,372,694 | 158,899,456 | 0 | n/a |
| 1 | G2 | 10,996 | 47,677 | 146,361,153 | n/a |
| 1 | G3 | 11,969 | 48,927 | 628,780 | n/a |
| 32 | S1 | 11,194 | 16,975 | 0 | 35,587 |
| 32 | S2 | 11,194 | 16,965 | 0 | 35,590 |
| 32 | G1 | 146,371,809 | 158,902,976 | 0 | n/a |
| 32 | G2 | 10,819 | 49,063 | 4,683,556,896 | n/a |
| 32 | G3 | 59,898 | 98,846 | 20,120,960 | n/a |

G3F stores the same bytes as G3. Git's allocated size is larger than its apparent size because every loose object occupies at least one 4 KiB filesystem block. At 32 agents G3's per-proposal figure includes a 629 KB working copy of the index that each agent creates on its first proposal. Synapse keeps the base tree in memory, so its setup costs no disk. All Git arms share one object store per clone.

## 4. Query Results

400 samples per method per repetition over a population of 400 proposals (8 agents, 50 each), one client thread. Git figures include process start-up except for `cat-file --batch`. Synapse figures include request signing, signature and grant verification, and JSON encoding and decoding in both directions; "API only" excludes the JSON and signing work.

| Query | System | Method | n per rep | p50 ms | p95 ms | p99 ms | API only p50 ms | Failures |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| read_file | Synapse | `SynapseService::read_file` | 400/400/400 | 1.111 (1.026 to 1.119) | 1.739 | 2.108 | 0.996 | 0 |
| read_file | git | `git cat-file --batch` (one persistent process) | 400/400/400 | 0.179 (0.144 to 0.196) | 0.306 | 0.384 | n/a | 0 |
| read_file | git | `git cat-file blob <commit>:<path>` (spawn per read) | 400/400/400 | 1.51 (1.301 to 1.898) | 2.224 | 2.389 | n/a | 0 |
| tree | Synapse | `SynapseService::tree`, every page (256 entries per page) | 400/400/400 | 17.718 (17.706 to 17.751) | 18.798 | 19.101 | 11.394 | 0 |
| tree | git | `git ls-tree -r <commit>` | 400/400/400 | 3.646 (3.605 to 3.688) | 6.07 | 6.213 | n/a | 0 |
| diff | Synapse | `SynapseService::diff` base to changeset, every page | 400/400/400 | 2.462 (2.455 to 2.53) | 3.179 | 4.683 | 2.215 | 0 |
| diff | git | `git diff-tree -r --name-status <base> <commit>` | 400/400/400 | 1.48 (1.436 to 2.098) | 2.534 | 2.696 | n/a | 0 |
| conflicts | Synapse | `SynapseService::conflicts`, one candidate against every same-base peer (path level) | 400/400/400 | 0.219 (0.218 to 0.219) | 0.228 | 0.245 | 0.196 | 0 |
| merge-tree | git | `git merge-tree --write-tree` for one pair (content level) | 400/400/400 | 1.948 (1.74 to 2.412) | 3.54 | 3.901 | n/a | 0 |

`conflicts` and `merge-tree` do different work (one path-level query over the whole population against one content-level three-way merge of one pair) and are not a head-to-head comparison.

Parity checks (computed per sample): Synapse `tree` entry counts equalled `git ls-tree -r` and Synapse `diff` entry counts equalled `git diff-tree` in all 1,200 samples of each; Synapse `read_file` and both git read methods returned exactly the generated bytes in every sample (a mismatch would count as a failure; there were none). The first `tree` query on a changeset builds and caches its virtual tree (104 to 114 such cold samples per repetition). With 372 to 377 cached trees, the query process peaked at 782,316 to 789,720 KiB RSS; the cache has no size bound.

## 5. Conflict Correctness

A designed scenario of 23 proposals on the same base (253 pairs) with known ground truth. Each pair was checked with `SynapseService::conflicts` from both sides and with `git merge-tree --write-tree` on the equivalent Git commits.

| Pair class | Pairs | Synapse flagged | Git conflicts |
| :--- | :--- | :--- | :--- |
| Hotspot rewrite (both rewrite the same file) | 6 | 6 | 6 |
| File and directory collision | 1 | 1 | 1 |
| Modify and delete of the same file | 1 | 1 | 1 |
| Disjoint hunks in the same file | 3 | 3 | 0 |
| Identical change (same add or same delete) | 2 | 0 | 0 |
| Distinct paths | 240 | 0 | 0 |

| Check | Result |
| :--- | :--- |
| Synapse flagged set equals generator ground truth (path-level rule) | pass, 0 of 253 mismatches |
| Every Git textual conflict is flagged by Synapse | pass, 0 false negatives, 0 merge-tree errors |
| Every pair Synapse reports clean merges cleanly in Git | pass, 242 pairs |
| Git outcomes match the generator's expectation | pass |

The 3 over-flags are the disjoint-hunk pairs: Synapse works at path level, so two edits to different parts of one file are reported as a conflict even though Git merges them. Stale-base refusal is a canonical-promotion property in Synapse and is covered by the Radicle conformance case `stale_base_refused`.

## 6. Conformance Suites

Each case compares observed behaviour with a stated expectation and records pass, fail, or skipped; a harness error inside a case marks that case failed. The suites ran once per repetition (3 runs); every case had the same outcome in every run.

| Suite | Cases | Passed per run | Cases |
| :--- | :--- | :--- | :--- |
| WAL | 11 | 11, 11, 11 | clean reopen (positive control); crash after blob write before WAL append; torn header and torn payload refused under `StrictFailClosed` and recovered under `TruncateTornTail` (exactly 1 frame truncated, acknowledged data and state root intact, next append and strict reopen succeed); CRC, chain, sequence-gap, and duplicate-sequence corruption refused under both policies; committed blob bit flip refused |
| Git | 7 | 7, 7, 7 | deterministic re-materialization (identical commit and tree OIDs); `git fsck --full --strict` clean; `fsck` detects a corrupted object (negative control); fetch and checkout byte parity with the Synapse virtual tree including executable bits; materialized diff lists exactly the changeset's paths; fast-forward of a human branch allowed; non-fast-forward refused with the branch unchanged |
| Radicle | 11 | 11, 11, 11 | 2 of 3 delegates promote; 1 of 3 refused; a vote for another OID not counted; tampered sigrefs refused; non-delegate signer refused; forged delegate signature refused; stale base refused; GitHub merged without quorum classified and refused; diverged quorum refused; invalid threshold refused; live repository |

The live Radicle case read the `aien-sovereign-core` Radicle storage repository (read-only): 1 delegate, threshold 1, 1 sigrefs loaded, default branch head `8a42b145ce05843728e50f4e81e028604dc6244b`, classified `CanonicalQuorumSatisfied`.

## 7. Transfer Size (ESTIMATE)

For each of the 400 query-population proposals (3 repetitions, numbers from repetition 0):

| Measure | Median bytes | Mean bytes |
| :--- | :--- | :--- |
| Synapse signed JSON submit request | 16,653 | 33,851 |
| Raw new file content in the proposal | 3,967 | 9,100 |
| Git thin pack against a receiver that has the base (`pack-objects --thin --stdout --revs`) | 904 | 1,002 |

These are estimates, not network measurements. Synapse has no wire protocol yet; this harness uses JSON, where `serde_json` writes blob bytes as decimal number arrays, and every request carries a full new copy of each changed file. The Git pack sends compressed deltas.

## 8. WAL Recovery

Fresh stores populated with generated changesets (`BatchWindow { max_records: 1024 }`, then `sync_wal`), then reopened 3 times immediately (warm page cache).

| Changesets | WAL bytes | Store bytes (apparent) | Blob files | `SynapseStore::open` median ms (min to max) | `SynapseService::open` median ms | `checkpoint_and_compact` ms | Open after checkpoint median ms |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| 100 | 163,035 | 1,311,359 | 163 | 3.52 (3.491 to 3.727) | 3.516 | 14.525 | 0.428 |
| 1,000 | 1,567,560 | 10,834,831 | 1,445 | 31.161 (30.924 to 32.376) | 31.512 | 55.059 | 4.23 |
| 10,000 | 15,878,840 | 117,196,023 | 14,957 | 344.575 (344.547 to 352.21) | 353.43 | 422.474 | 45.976 |

Raw WAL replay grows linearly (about 34 microseconds per changeset) because it re-reads and re-digests every committed blob. After a checkpoint (17,645,842 bytes at 10,000 changesets, WAL truncated to 0 bytes) reopen takes about 13% as long (45.976 ms against 344.575 ms). Every reopen preserved the committed sequence and the state root digest; no reopen failed; the checkpoint evicted nothing.

Base tree import probe: the crate's own `import_base_tree_from_git_repo` took 6,440 ms on the pinned commit, against 581 ms for the harness loader (`git cat-file --batch`) plus 380 ms to register. Both produced identical virtual trees.

## 9. Operational Complexity Assessment

This section is a qualitative reading of the code and the measurements, not a measurement.

| Concern | Synapse (S1/S2) | Git plumbing (G3/G3F) | Persistent worktrees (G2) |
| :--- | :--- | :--- | :--- |
| New moving parts | WAL, blob store, checkpoint and compaction schedule, identity authority and grants, Git materialization, Radicle promotion | None beyond git; a temporary index per agent and per-proposal refs | Worktree lifecycle and cleanup |
| Durable write scaling | One writer; measured flat at about 70 ops/s | Parallel processes; measured 18.7 to 383 ops/s | Parallel; tails grow at 8 and 32 agents |
| Memory | Base tree held in memory per process (about 167 to 175 MiB here); virtual tree cache unbounded (about 771 MiB peak in the query cell) | About 40 MiB per agent process | About 40 MiB per agent process plus a full checkout on disk |
| Disk | About 11 to 12 KB per proposal | About 12 to 60 KB per proposal; loose objects accumulate until `gc` | 146 MB per agent at setup |
| Failure handling | Fails closed on WAL or blob corruption (operator must repair); torn tail recoverable by policy | Standard git tooling (`fsck`, `gc`) | Standard git tooling; concurrent `worktree add` raced in G1 |
| What agents gain | Signed, capability-scoped requests; path-level conflict index across all open proposals; provenance and Radicle canonicality checks | Proposals as ordinary Git commits | Ordinary commits plus a working directory |
| What it does not remove | Agents that build or test still need a checkout somewhere | Same | Nothing to remove |

## 10. Limitations

* In-process only: Synapse arms call the service inside the arm process. The JSON round trip approximates a wire format; no socket, daemon, or network is measured.
* Warm page cache: every cell starts from a fresh clone, but caches were never dropped (no root access for that).
* Single host and single ext4 NVMe filesystem on aarch64; other hardware may differ.
* The host was busy with other work during the run (section 2.4); the effect on disk-bound arms is not measured.
* Synthetic edits: generated hunks, adds, and deletes on the real tree; no compile, test, or agent reasoning time.
* G1 runs 32 or 64 operations per cell, so it has no p99.
* The conflict scenario is designed (23 proposals), not drawn from real agent traffic.
* Transfer sizes are estimates (section 7).
* Recovery used synthetic changesets up to 10,000 with a warm cache.
* The "largest git child" RSS is an upper bound (section 3.3).
* Stated as UNVERIFIED: the Linux default for `core.fsyncMethod`; the cause of the G1 `worktree add` failures; the reason the largest-child RSS equals the parent's size; the size of the background-load effect.
* The source identity in the manifest was recorded before the harness was committed (`dirty`); the digest covers the harness files themselves (section 12), and recomputing it over the committed files gives the same value (`6ded22a9d626f237f050c146ea3bb86240b1f74e3b39a0c205a1e62e636c85c8`).

## 11. Gate 4 Checklist to Evidence

| Gate 4 item | Evidence |
| :--- | :--- |
| Representative and stress concurrent agent workloads against conventional Git workflows | `report.json` `write_summary`, `write_cells`; `traces/write-*.jsonl` (every operation); tiers 1, 4, 8 and 32 |
| Ingest throughput | `report.json` `headline`, `write_summary[].throughput_ops_per_s` |
| p50/p95/p99 query latency | `report.json` `query_summary`, `query_cells`; `traces/query-r*.jsonl` |
| Conflict-resolution correctness | `report.json` `conflict`; `traces/conflict.jsonl` (all 253 pairs) |
| Bytes stored and transferred | `write_summary[].storage_*`, `write_cells[].storage`; `query_cells[].transfer` (ESTIMATE) |
| CPU and memory | `write_summary[].cpu_ms_per_op`, `peak_rss_*`; `write_cells[].cpu` |
| WAL recovery | `report.json` `recovery`; `traces/recovery.jsonl`; WAL conformance suite |
| Operational complexity | Section 9 of this document |
| Neutral conformance suites on Git materialization and Radicle canonical decisions | `report.json` `conformance_runs`, `conformance_summary` |
| Raw traces, manifests, host and hardware details, reproducible commands | `traces/`, `manifest.json` (host, toolchain, fixture, git config, fsync probe, seeds, cell order, timings), `SHA256SUMS`, `scripts/run_gate4_qualification.sh` |
| No unverified headline speedups | Every comparison in this document cites a measured value with its method; unmeasured claims are marked UNVERIFIED |
| Propose rollout only after correctness and security gates pass and benefits outweigh complexity | Section 13, for Drake's decision |

## 12. Reproduction

```bash
cd synapse
scripts/run_gate4_qualification.sh            # full run (about 11 minutes here)
SMOKE=1 OUT_DIR=/tmp/gate4-smoke scripts/run_gate4_qualification.sh   # quick harness check
```

The script builds `synapse-bench` in release mode, records the harness source (`git rev-parse HEAD`, a dirty flag, and a SHA-256 over every file in `crates/`, `Cargo.toml`, `Cargo.lock`, and `scripts/`), clones the fixture into a temporary directory that it removes afterwards, compresses traces only if they exceed 20 MiB (this run: about 7 MB, uncompressed), and writes `SHA256SUMS`. Environment overrides: `FIXTURE_REPO`, `FIXTURE_REV`, `OUT_DIR`, `WORK_PARENT`, `REPS`, `TIERS`, `ARMS`, `SEED`, `RADICLE_REPO`, `SMOKE`.

## 13. Adoption Proposal (for Drake's Decision)

### Decision (Drake, 2026-10-14)

Drake chose a Synapse-first direction, which none of Options A, B, or C below proposed. In his words:

> "I want Synapse to do everything Git does and I want a simple small interface with Git. I want us to use both the power of Git and the benefits of Synapse. Eventually Synapse will take over Git from our actual hardware."
>
> "I want Synapse to be the new Git for AI."

He refined the scope the same day:

> "Don't just copy features because we feel like we need them. I want you to take the good parts of everything and make the best system possible."
>
> "This is going to be for AI only. AI is going to be the only one writing code in the future and this is not going to be for humans. Nothing human-related needs to be in this."

What the decision means:

* Synapse becomes the source control system for AI agents. No human-facing features are in scope.
* Git stays as a small machine bridge for ecosystem interop (import, export, existing tooling and hosting), not as a human path.
* The decision supersedes the Option C recommendation below and the non-goal "Replacing Git" in [aien-spark/aien-sovereign-core#515](https://github.com/aien-spark/aien-sovereign-core/issues/515).
* The gaps this report measured are now the Phase 5 work list:
  1. **Durable single-writer ceiling:** S1 stays near 70 ops/s from 1 to 32 agents, while G3F reaches 383 ops/s and a 119 ms p99 at 32 agents against S1's 1.2 s (section 3.1).
  2. **Slower reads than `git cat-file --batch`:** Synapse `read_file` 1.11 ms against 0.18 ms, `tree` 17.7 ms against `git ls-tree -r` 3.6 ms, `diff` 2.5 ms against `git diff-tree` 1.5 ms (section 4).
  3. **Unbounded virtual tree cache:** the query process peaked at 782,316 to 789,720 KiB RSS with no size bound (section 4).
  4. **No compact wire format:** the signed JSON submit request has a median of 16,653 bytes against a 904-byte Git thin pack (section 7, ESTIMATE).
* The roadmap (Phases 5 to 9) and the gates that must pass before agents cut over are recorded in [ADR 0002](adr/0002-synapse-first-git-as-bridge.md).

The proposal text below is kept unchanged as history.

**Where the numbers point.** Most of the cost of today's practice comes from the checkout, not from Git. Removing the checkout with plain Git plumbing (G3) takes a proposal from about 1,061 ms and 146 MB to about 13 to 28 ms and 12 to 60 KB, with no new service. Against that baseline, Synapse's remaining advantages are narrower:

* page-cache writes (S2 against G3): higher throughput at every tier (1,557 to 2,036 against 75 to 1,016 ops/s) and lower median latency;
* durable writes (S1 against G3F): lower latency and higher throughput only up to about 4 agents; from 8 agents G3F is ahead, and S1's 32-agent p99 is 1.2 s against 119 ms;
* 13 to 27 times less CPU per proposal than G3 (S1 0.88 to 1.06 ms, S2 0.51 to 0.82 ms, G3 about 14 ms);
* a path-level conflict query across every open proposal in 0.22 ms, with no false negatives and 3 conservative over-flags in 253 pairs;
* signed, capability-scoped requests and Radicle canonicality checks, all passing their conformance cases.

Reads have lower latency through the git command line (file reads through a persistent `git cat-file --batch` 0.18 ms, tree 3.6 ms, diff 1.5 ms against Synapse 1.11, 17.7, and 2.5 ms); only spawning `git cat-file` per read (1.51 ms) is slower than Synapse `read_file`. In addition, the estimated Synapse request size is many times the Git thin pack.

**Option A: Replace fresh worktrees with Git plumbing now; keep Synapse in the lab.**
Agents write proposals with the G3 recipe (temporary index, `commit-tree`, per-proposal ref) and only check out when they must build or test.
*Upside:* the large measured win (time, disk, CPU) with tools everyone already knows; nothing new to operate; easy to undo.
*Downside:* no signed capability model, no cross-proposal conflict index, no Radicle promotion engine; loose objects need periodic `git gc`.
*If chosen:* a small hive tooling change; Synapse stays at Gate 4 with this evidence; no new service is deployed.

**Option B: Pilot Synapse for the agent inner loop beside Git.**
Agents submit through Synapse (S2 durability) and use its conflict query; Git and GitHub stay canonical through materialization.
*Upside:* the fastest measured ingest, the cheapest CPU, and the conflict index and audit trail Git lacks.
*Downside:* a new stateful service to operate; durable mode does not scale past one writer; memory grows with base trees and the unbounded tree cache; no wire protocol yet (the JSON approximation is large); S2 loses acknowledged work on power loss.
*If chosen:* before a pilot, fix or accept the single-writer durable ceiling, bound the virtual tree cache, and design a compact wire format; this is several weeks of engineering, and the pilot can be switched off because Git remains the source of truth.

**Option C: Do both in sequence.** Take Option A now for the immediate win, and revisit Option B only if the conflict index, capability model, or Radicle promotion prove necessary in practice.
*Upside:* immediate benefit with low risk; Synapse work continues only where Git cannot help.
*Downside:* two transitions if Synapse is adopted later.
*If chosen:* same immediate change as Option A, plus a later decision point.

**Recommendation:** Option C. The measurements show Git plumbing removes most of today's cost, while Synapse's distinct value is in coordination features (conflict index, capabilities, Radicle canonicality) rather than raw speed at durable settings.

**Decision for Drake:** adopt Git plumbing now and hold Synapse for a later pilot (Option C), go straight to a Synapse pilot (Option B), or adopt Git plumbing only (Option A)?
