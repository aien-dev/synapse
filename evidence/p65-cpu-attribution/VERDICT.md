# Issue #65 Stage A: CPU attribution and verdict (NO-GO for Stage B)

**Verdict: NO-GO.** CPU control flow (branch mispredicts) is not a measured or plausible dominant cost on the
accepted-submit, query or crumb-advisory paths. The hot path is unchanged: this PR touches no file under
`crates/`. Tags: **[MEASURED]** from sealed raw files here, **[INFERRED]** reasoning from measured data,
**[NOT_RUN]** could not be measured on this host.

Source: `aien-dev/synapse` main `3d78efe` + the protocol commit `1d77738` (protocol pre-registered and committed
at 01:40:01 UTC before the run). Host: GB10 Spark, 10 Cortex-X925 + 10 Cortex-A725, kernel 7.0.0-1019-nvidia,
ext4 on `/dev/nvme0n1p2`, `perf_event_paranoid = 4`, yama `ptrace_scope = 1`. Quiet flag clear (`quietlock check`
exit 0, not held); other lanes were live: load average 6.65 at start, 6.30 at end of the timed run.

## 1. What was run

| Step | Command | Files |
| :--- | :--- | :--- |
| Timed attribution, 10 legs x 3 affinities x 7 reps (control + instrumented window each) | `synapse-bench pmu-diag --evidence evidence/p65-cpu-attribution/stage-a --work-dir ../work-65/scratch --fixture-repo . --source-rev 1d77738...` | `stage-a/` (`pmu-verify` passes) |
| Physical floors on the store filesystem | `synapse-bench floor --dir ../work-65/scratch --out evidence/p65-cpu-attribution/floor/floor.json --iterations 300` | `floor/floor.json` |
| Stack sampling (where CPU and wait time go) | `scripts/p65-gdb-sample.sh <out> <max> 0.02 -- synapse-bench pmu-diag ...` on a symbols build of the same release profile | `samples/*/samples.txt.gz`, `protocol.json` |
| Folding | `scripts/p65-sample-report.sh <samples> <anchor>` | `samples/*/folded*.txt` |
| Sampler positive control | SHA-256-only and Ed25519-verify-only floor legs | `samples/control/` |

**PMU counts [NOT_RUN].** Every instrumented window (210 of 210) is `INSTRUMENT_UNAVAILABLE` /
`PERMISSION_DENIED`: `perf_event_paranoid = 4` refuses `perf_event_open` to unprivileged users, and also
blocks `perf record`. Lowering the sysctl is an operator decision and was not done. Instructions per
cycle and mispredicts per kilo-branch are therefore unmeasured. Joules: NOT_MEASURED by `pmu-diag`.

**Sampler.** Because perf is blocked, `p65-gdb-sample.sh` runs the bench under gdb (allowed for a child under
`ptrace_scope = 1`), interrupts it about every 20 ms of its own run time, prints every thread's backtrace and
continues. Each thread-sample is classed as `run` (user code) or `wait:<syscall>` (futex, fdatasync, pwrite)
and charged to the operation phase under the anchor frame and to the leaf-most crate. Positive control
(`samples/control/folded.txt`): a run of a SHA-256 leg then an Ed25519-verify leg folds to 215 `sha2` and
200 `curve25519-dalek` of 438 thread-samples, with 22 in bench loop code; nothing else.

## 2. Timed results [MEASURED] (`stage-a/report.json`, control | instrumented windows, min / p50 / max, n = 7 each)

The instrumented side differs from the control only by one refused system call, so it is a second sample of
the same work. Write CPU microseconds are per window (all threads, user + system).

| Leg | Affinity | Wall ns/op control | Wall ns/op instrumented | CPU us per window control |
| :--- | :--- | ---: | ---: | ---: |
| floor/sha256_content_12k | unpinned | 5586 / 5587 / 5594 | 5586 / 5587 / 5588 | 111735 / 111747 / 111784 |
| floor/sha256_content_12k | a725 | 5938 / 5952 / 5962 | 5938 / 5941 / 5962 | 118775 / 119038 / 119240 |
| floor/sha256_content_12k | x925 | 5587 / 5587 / 5590 | 5587 / 5587 / 5588 | 111741 / 111759 / 111806 |
| floor/ed25519_verify | unpinned | 23796 / 23799 / 23809 | 23792 / 23795 / 23804 | 47593 / 47599 / 47618 |
| floor/ed25519_verify | a725 | 49072 / 49098 / 49382 | 49082 / 49173 / 49279 | 98137 / 98194 / 98758 |
| floor/ed25519_verify | x925 | 23801 / 23803 / 23831 | 23801 / 23806 / 23815 | 47602 / 47606 / 47659 |
| floor/envelope_validate | unpinned | 27802 / 27806 / 27820 | 27797 / 27812 / 27824 | 55606 / 55612 / 55637 |
| floor/envelope_validate | a725 | 55421 / 55436 / 55539 | 55405 / 55416 / 56057 | 110839 / 110857 / 111073 |
| floor/envelope_validate | x925 | 27790 / 27797 / 27833 | 27789 / 27792 / 27836 | 55582 / 55595 / 55667 |
| floor/json_decode_submit_request | unpinned | 76613 / 76639 / 76742 | 76596 / 76654 / 76819 | 153226 / 153278 / 153484 |
| floor/json_decode_submit_request | a725 | 172110 / 172280 / 172464 | 172122 / 172387 / 172616 | 344219 / 344560 / 344916 |
| floor/json_decode_submit_request | x925 | 76559 / 76620 / 76707 | 76544 / 76690 / 76727 | 153119 / 153239 / 153415 |
| write/every_commit/agents=1 | unpinned | 31483771 / 33115993 / 35418082 | 27127989 / 32700608 / 38985429 | 14634 / 20435 / 28092 |
| write/every_commit/agents=1 | a725 | 25870058 / 32069619 / 34276117 | 26471647 / 32509366 / 34007433 | 18337 / 23811 / 27941 |
| write/every_commit/agents=1 | x925 | 29964562 / 36821096 / 43093736 | 29827638 / 33387985 / 39639619 | 13889 / 15709 / 18950 |
| write/group_commit/agents=1 | unpinned | 2110718 / 3430125 / 3688262 | 3121811 / 3312190 / 4314356 | 17611 / 20855 / 28459 |
| write/group_commit/agents=1 | a725 | 3259798 / 3497523 / 3683238 | 3148551 / 3540771 / 3680481 | 25563 / 27596 / 31016 |
| write/group_commit/agents=1 | x925 | 2727414 / 2902470 / 3122745 | 2681457 / 2841150 / 3065417 | 16643 / 17534 / 20810 |
| write/group_commit/agents=8 | unpinned | 595428 / 652716 / 664322 | 606371 / 661298 / 996906 | 158046 / 181499 / 200483 |
| write/group_commit/agents=8 | a725 | 646391 / 705731 / 749651 | 687878 / 735705 / 768821 | 207535 / 221304 / 246491 |
| write/group_commit/agents=8 | x925 | 612031 / 690644 / 872520 | 639120 / 672240 / 688665 | 130177 / 138547 / 158097 |
| write/group_commit/agents=32 | unpinned | 243435 / 303629 / 309108 | 244559 / 271205 / 304319 | 734829 / 774294 / 808109 |
| write/group_commit/agents=32 | a725 | 321043 / 361320 / 452117 | 311396 / 357795 / 383509 | 912810 / 934662 / 964515 |
| write/group_commit/agents=32 | x925 | 222997 / 266239 / 284743 | 224844 / 251069 / 261024 | 541327 / 571664 / 615516 |
| query/read_tree_diff | unpinned | 235590 / 235840 / 236060 | 235589 / 235931 / 236423 | 35334 / 35377 / 35409 |
| query/read_tree_diff | a725 | 470179 / 470766 / 470991 | 468877 / 470339 / 471198 | 70498 / 70604 / 70626 |
| query/read_tree_diff | x925 | 235942 / 236299 / 236409 | 235879 / 236226 / 237067 | 35385 / 35445 / 35462 |
| crumb/context_advisory | unpinned | 138324 / 138906 / 139842 | 138241 / 138679 / 139305 | 13833 / 13891 / 13985 |
| crumb/context_advisory | a725 | 264052 / 265257 / 266341 | 264082 / 265438 / 266981 | 26407 / 26530 / 26623 |
| crumb/context_advisory | x925 | 138131 / 139104 / 140516 | 138374 / 139032 / 140419 | 13814 / 13911 / 14053 |

Accepted submit, group commit, X925: **558.3 CPU us per op at 32 agents** (571,664 us / 1,024 ops,
calc:a3ff66467530abb48a87642f3d26dd1f696251db219709d84961f917d40ccb38) and **547.9 at 1 agent**
(17,534 / 32, calc:0e2e971abfe8c1a99999dd251be96a0af5e516007219786c27b7d300139afd56). At 1 agent the CPU is
busy **18.88 %** of the wall window (calc:f64adc897b478593aaf2975a97c45e3c78a2500e73a39a4015e37acff249bc82).

**Physical floor context** (`floor/floor.json`, same filesystem, load average 7.84 to 9.73 during the run):
`overwrite_4k_fdatasync` p50 2.097 ms (min 1.884, max 3.492), `append_4k_fdatasync` p50 5.399 ms. The 1-agent
group-commit p50 of 2.902 ms per accepted submit on X925 is **1.384x** the overwrite-fdatasync floor
(calc:772f8d05beea00f6163dc6b668fe4722d17215ae2d3a1e8e7e4f0ce2837bad45): one durable acknowledgment is
mostly one storage flush. CPU primitive floors (p50): SHA-256 12 KiB 0.005 ms, Ed25519 verify 0.023 ms,
Ed25519 sign 0.009 ms, JSON encode/decode of a submit request 0.033 / 0.083 ms, envelope validate 0.027 ms.

## 3. Where the time goes [MEASURED counts, INFERRED shares]

### Accepted submit, group commit, 8 agents x 1,500 ops, unpinned (`samples/write8/folded.txt`)

3,727 agent thread-samples (anchor `synapse_submit`):

| State | Samples | Share |
| :--- | ---: | ---: |
| Waiting on a futex inside `SharedStore::submit` (follower waiting for the group-commit leader's flush and ack) | 1,954 | 52.43 % (calc:c9834cac5bc39a6bdb7cff958e12cb0cc7d8f1da603a8fdac85a539c94e96844) |
| In `fdatasync` (group-commit leader) | 448 | 12.02 % (calc:be7208b265bdc035a23f138d7a04a4e701b045f147eac4cf8fdbff836cdf8381) |
| Waiting on the bench's service mutex | 389 | 10.44 % (calc:116605f2bdecf6ded2e12f39e3d15b419f54d0cab9ffb61d5c40784b2ed34e37) |
| Running user code | 917 | 24.6 % (calc:60c4816bd184b1f06f27d44d4aee8d41a69360307633c62b541ae5579e03633f) |
| Other syscalls (pwrite, misc) | 19 | |

Running samples by phase (917): bench client side (request build + signing 208, JSON wire round trip 347)
**60.52 %** (calc:119b58f187ea4adc21d2d133772c24e879eeed753db6b8ad9cc4b77e501542f9); server admission
(`admit_submit`: auth, grant and request signature checks, payload digest) 259 = **28.24 %**
(calc:95813e0dfd15b38039222a2529a0f0cabc9ad0d6cffd370ff685806253095c5f); store commit path
(`SharedStore::submit`: `prepare_ingest`, envelope validation, WAL framing) plus path indexing 99 + 3 =
**11.12 %** (calc:0034ae0234042d10fd9d6add3eaddac46f5bd6b68105b1863f2378e7414c44c5).

Running samples by leaf class (917): Ed25519 + SHA-256 (`curve25519-dalek`, `ed25519-dalek`, `signature`,
`subtle`, `sha2`, `digest`) 308 = **33.59 %** (calc:4a6f0e5cd325e8331b66186dd8dcb55dcf3ebd895c2b0ea7df2245c3eed3a288);
JSON (`serde_json`, `serde_core`, `itoa`) 294 = **32.06 %** (calc:5a9f77409ee22a3a3d235ca2692f2b37acff45c05f9f237c3efaa5ce98514481);
allocation and memory copies (libc malloc/free/mem*, Rust alloc) 282 = **30.75 %**
(calc:7e2ddf5bebb5d6ee0a4e401e4b671604caf20ba1d65d56af0cb392f0acdac359); Synapse's own code as leaf
(`synapse-auth`, `synapse-core`, `synapse-store`, `synapse-bench`) 33 = **3.599 %**
(calc:ded93597f8fd3c0ff00c367d7c47788b6e721efa79f91c86348e3ea41f06c027).

### Query: read_file, tree, diff (`samples/query/folded.txt`, 785 running of 793)

JSON 323 = **41.15 %** (calc:dba34dac189c77b6b5b6260b40c623769014134624d6135736e87a0627922ce3); Ed25519 +
SHA-256 (request authentication) 250 = **31.85 %** (calc:35a6e2be1fbf2d50eea114bd474bd72c014664591e01274a9d6e4ee5c80a6424);
virtual-tree, index and validation code as leaf (`synapse-api` tree/lib, `synapse-core`, `synapse-store`,
`synapse-auth`) 42 = **5.35 %** (calc:e9a7ca11be6fe4f6a1866568d5dd61891c0c9033878c7f186f02a93095672f27).

### Crumb context + changeset advisory (`samples/crumb/folded.txt`, 794 running)

Allocation (Rust alloc + libc malloc/free) 341 = **42.95 %** (calc:22bac92fa1d1655d4e7f842eeea12277b33c4ca668aaec03255ff55e4ab0906a);
Ed25519 + SHA-256 (request authentication) 325 = **40.93 %** (calc:10ab9ebe2d2db60f50f43465d08f37aaa98eb787edc8d1c2b5da3c41f1d3bbc6);
Crumb resolution, advisory, tree code as leaf 35 = **4.408 %** (calc:1d5e72c0412a2836c76434e745b1ec308e74b56230d80004dbf676b3e3925790).

## 4. Why this is a no-go [INFERRED]

1. On the write path three quarters of agent wall time is off CPU: waiting for the group-commit flush and
   acknowledgment, in `fdatasync`, or on the service lock. A CPU control-flow change cannot reduce that time.
2. Of the on-CPU time, the top classes are Ed25519 field arithmetic and SHA-256 compression (written to be
   constant time, i.e. without data-dependent branches), JSON encoding and decoding, and allocation/copies.
   These are data-path costs. The branch-heavy code the issue names (path indexing, virtual-tree queries,
   Crumb resolution, validation and refusal checks) is 3.6 to 5.4 % of running samples as leaf on every path.
   Even a perfect branch fix there could not make a repeatable end-to-end cut in seconds that the issue's
   acceptance rule requires.
3. Branch misses themselves are unmeasured (PMU blocked). Stage B requires a *verified* control-flow cost;
   none can be verified on this host as configured.

So, per the issue, the hot path is not altered and no Stage B change is made. Durability and authority are
unchanged by construction: `git diff --name-only origin/main` lists only `evidence/p65-cpu-attribution/**`
and two new scripts under `scripts/`; the full workspace suite stays green (`red-green/green.txt`).

## 5. Candidates for separate issues (not control flow; not changed here)

| Candidate | Evidence | Note |
| :--- | :--- | :--- |
| `check_request_inner` re-serializes the whole payload to JSON (blobs become JSON arrays of numbers via `itoa`) to recompute `payload_sha256` | `crates/synapse-auth/src/lib.rs` step 6; 90 of 260 `admit_submit` running samples have `serde_json` on stack (`samples/write8/folded-admit_submit.txt`) | Authority-sensitive: the digest binds the signed bytes; any change needs its own parity proof |
| Ed25519 public-key decompression on every verify (`VerifyingKey::from_bytes`), three verifies per submit (request, grant, envelope) | 117 running samples under auth verify sites, 49 under envelope validate | Caching decoded keys must keep refusal codes for bad keys |
| Crumb advisory rebuilds a `BTreeSet` of every path plus ancestors per call (`SnapshotOracle::new`, `advisory.rs` 143-145) and re-materializes the virtual tree per call | 73 + 40 allocation samples of 794 | Snapshot results must stay identical |
| Bench client simulation (request build, signing, JSON wire round trip) is 60.52 % of write-leg CPU | section 3 | Bench-side cost, not server cost; read write-leg CPU figures with this in mind |

## 6. Limits

- One host, one session, other lanes live (load average 6.3 to 9.7). Wall spreads are in section 2.
- PMU counts NOT_RUN (paranoid 4). The no-go rests on time attribution, not on measured mispredict rates.
- Sampling is stop-the-world through gdb: counts are thread-samples, not seconds; stopped time is not sampled;
  a flush that completes while gdb is printing is under-counted, so wait shares are lower bounds. The sampling
  runs are not timed evidence. Each run ends at its sample cap (the query and crumb runs reached 800 and were
  ended by gdb; the write and control runs ended on their own).
- The sampled binary is the release profile with symbols kept (`CARGO_PROFILE_RELEASE_STRIP=false`,
  `CARGO_PROFILE_RELEASE_DEBUG=line-tables-only`). Code generation is assumed identical to the stripped
  timed binary: UNVERIFIED (no instruction-level diff was made).
- Leaf classing charges `std`/`core` frames and crate-relative-path frames to the nearest named crate.
- Joules NOT_MEASURED.
