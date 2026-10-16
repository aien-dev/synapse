# Bench PMU Diagnostics (issue #64)

`synapse-bench pmu-diag` adds optional CPU performance-counter readings beside the existing
physical-bound benchmarks. It is **diagnostic only**: seconds per operation stay the measured unit,
hardware counts are supporting units, and nothing here is a qualification result or a performance
claim. Energy is not measured by this path (`raw.json` says `NOT_MEASURED`); the `run`, `floor` and
`bounds` subcommands and their SI and joule reporting are unchanged.

Diagnostics are opt-in. Nothing runs unless `pmu-diag` is invoked with a protocol file. The default
benchmark output, the existing subcommands and CI (`scripts/ci/portable.sh`) are untouched. In
disabled mode no `perf_event_open` call is made at all (test
`acceptance1_disabled_mode_makes_no_system_call`).

## 1. Acceptance and Where It Is Met

| Issue #64 acceptance | How it is met | Proof |
| :--- | :--- | :--- |
| Portable tests: schema validity | Protocol, raw and report schemas are versioned (`synapse-bench/pmu-diag-*/v1`) and refuse unknown fields; the protocol refuses a wrong schema, an order other than control-then-instrumented, duplicate legs, zero sizes | `acceptance1_schema_protocol_refuses_bad_plans` |
| Portable tests: counter unavailable | `perf_event_open` failing with `EACCES`/`EPERM` gives `INSTRUMENT_UNAVAILABLE` / `PERMISSION_DENIED` with the OS error text and **no counts**; `ENOENT`/`ENODEV`/`EOPNOTSUPP` give `UNSUPPORTED_EVENT`; `ENOSYS` gives `UNSUPPORTED_PLATFORM`; any other failure `COUNTER_UNAVAILABLE` | `acceptance1_permission_denied_is_instrument_unavailable_without_counts` |
| Portable tests: unsupported | No CPU PMU in sysfs (a device with `events/cpu_cycles` and a `cpus` list) gives `NO_PMU`; a PMU whose sysfs event encoding differs from the ARM number, or that lacks one of the four events, refuses with `UNSUPPORTED_EVENT` before any open | `acceptance1_unsupported_or_missing_pmu_refuses_before_any_open`, `acceptance1_discovery_verifies_encodings_and_core_classes` |
| Portable tests: multiplexed | A counter with `time_running < time_enabled` is labelled `MULTIPLEXED` (pinned to its class) or `PARTIAL_RESIDENCY` (unpinned: migration and multiplexing cannot be told apart); the raw count is kept **unscaled**. `time_running = 0` with count 0 is `NOT_SCHEDULED` | `acceptance1_multiplexed_and_partial_residency_are_labelled_not_scaled` |
| Portable tests: disabled-mode no-op | Disabled mode returns `DISABLED` without touching the backend | `acceptance1_disabled_mode_makes_no_system_call` |
| Portable tests: malformed or mismatched PMU output | Short reads, wrong member counts, `time_running > time_enabled`, a count without running time are refused, never repaired. `pmu-verify` refuses raw evidence whose readings name an unknown PMU or event, a wrong core class, a missing or duplicated event, or a state that does not match the times | `acceptance1_malformed_reads_are_refused_never_repaired`, `acceptance1_verify_refuses_mismatched_pmu_output` |
| Portable tests: correct manifest attribution | Every reading carries PMU name, perf type, core class (from MIDR), ARM event number and sysfs encoding; the manifest records invocation, host, compiler, kernel, `perf_event_paranoid`, PMU discovery, fixture repo and commit, source and sibling revisions | `acceptance1_counted_reads_are_raw_and_attributed_per_core_class`, `acceptance1_manifest_attribution_and_every_leg_kind_runs`, `acceptance1_event_attr_is_user_only_inherited_counting` |
| Spark run of 1/4/8/32-agent write legs and query legs with matched baselines; wall-time and PMU distributions and overhead, else `NOT_RUN` | Run on this Spark (section 2). **Wall time: measured.** **PMU counts: `NOT_RUN`**: the host has `perf_event_paranoid = 4`, so every instrumented window is `INSTRUMENT_UNAVAILABLE` / `PERMISSION_DENIED` (84 of 84). Lowering the sysctl or running privileged is an operator decision and was not done | `evidence/bench-pmu-diagnostics/host-sample-2026-10-16/` |
| Derived numbers recompute from raw evidence; digest/manifest checks pass | `report.json` is a pure function of `protocol.json` and `raw.json` (integers only); `pmu-verify` recomputes it byte for byte, re-validates every PMU reading and checks `SHA256SUMS` | `acceptance3_report_recomputes_from_raw_and_digests_verify`; `synapse-bench pmu-verify` on the host sample passes |
| One PR scoped to `crates/synapse-bench/**` and benchmark evidence | New modules `pmu.rs`, `pmu_diag.rs` (+ tests), two subcommands in `main.rs`, two lines in `lib.rs`; no change to synapse-store, synapse-api or synapse-crumb | the diff |

Also covered: a crumb leg on a fixture without `.crumb` files is recorded under `not_run`, never faked
(`acceptance1_crumb_leg_without_crumb_fixture_is_not_run`); on whatever host runs the tests, a real
open either counts or returns a typed unavailable state (`acceptance1_real_host_sample_is_counted_or_typed_unavailable`).

Red before green: each guard was reverted one at a time and its test failed
(`evidence/bench-pmu-diagnostics/red-green/red-mutations.txt`: disabled-mode-opens, counts-scaled,
multiplex-unlabelled, refusal-yields-counts, encoding-unchecked, class-unchecked, sums-unchecked). One
mutant (fall back to the first PMU for an unknown name) survived because the coverage check still refused
the edited evidence; it is recorded there. All 14 tests pass (`red-green/green.txt`).

**Deviation from the issue text.** The issue asks to consume the Omega #453 PMU contract. Omega #453 is
still open and has not landed. This PR therefore carries a small native backend in `synapse-bench`
(`perf_event_open` through the existing `libc` dependency, no new crates) and uses Omega #453's status
vocabulary (`COUNTER_UNAVAILABLE`, `PERMISSION_DENIED`, `MULTIPLEXED`, `UNSUPPORTED_EVENT`) so it can
switch to that contract when it lands.

## 2. Host Sample (diagnostic, not qualification)

Host: GB10 Spark, 20 CPUs (10 Cortex-X925, 10 Cortex-A725), kernel 7.0.0-1019-nvidia, ext4 on
`/dev/nvme0n1p2`, `perf_event_paranoid = 4`. Binary built from `601b598`. The protocol was committed
(`168fc4e`, 07:54:15 UTC) before the run started (07:56:56 UTC); `raw.json` carries its SHA-256. The
commit in between (`601b598`) only changed how affinity is parsed and left the protocol bytes unchanged.
Whole run: 51 s wall. Three repetitions per leg and affinity; each repetition is a control window
(counters never opened) followed by an instrumented window on identical input.

Discovery found both PMUs and verified every event encoding against the ARM numbers:
`armv8_pmuv3_0` (perf type 10, CPUs 0-4 and 10-14, MIDR part 0xD87 Cortex-A725) and `armv8_pmuv3_1`
(type 11, CPUs 5-9 and 15-19, part 0xD85 Cortex-X925). Every instrumented open was refused:
`perf_event_open(armv8_pmuv3_0 type 10 event 0x0011 cpu_cycles): Permission denied (os error 13)`.

Wall nanoseconds per operation, median of 3 (full min/p50/max and CPU-time distributions are in
`report.json`). Overhead is `(instrumented p50 - control p50) / control p50`. Because every open was
refused, the instrumented side differs from the control only by one failed system call, so these
overheads measure run-to-run noise, not counter cost.

| Leg | Affinity | Control ns/op | Instrumented ns/op | Overhead (ppm) |
| :--- | :--- | ---: | ---: | ---: |
| floor/sha256_content_12k | a725 | 5,947 | 5,941 | -998 |
| floor/sha256_content_12k | x925 | 5,591 | 5,591 | 142 |
| floor/ed25519_verify | a725 | 49,096 | 49,116 | 403 |
| floor/ed25519_verify | x925 | 23,838 | 23,831 | -316 |
| floor/envelope_validate | a725 | 55,642 | 55,652 | 183 |
| floor/envelope_validate | x925 | 27,706 | 27,705 | -51 |
| floor/json_decode_submit_request | a725 | 170,888 | 170,810 | -458 |
| floor/json_decode_submit_request | x925 | 84,576 | 84,599 | 273 |
| write/every_commit, 1 agent | a725 | 18,901,382 | 17,563,601 | -70,776 |
| write/every_commit, 1 agent | x925 | 17,340,747 | 16,910,196 | -24,828 |
| write/every_commit, 4 agents | a725 | 15,949,643 | 16,494,380 | 34,153 |
| write/every_commit, 4 agents | x925 | 17,351,934 | 16,127,962 | -70,538 |
| write/every_commit, 8 agents | a725 | 16,459,075 | 15,196,846 | -76,688 |
| write/every_commit, 8 agents | x925 | 16,209,404 | 15,523,021 | -42,344 |
| write/every_commit, 32 agents | a725 | 17,047,042 | 16,517,166 | -31,083 |
| write/every_commit, 32 agents | x925 | 15,915,449 | 15,999,518 | 5,282 |
| write/group_commit, 1 agent | a725 | 2,137,378 | 2,239,238 | 47,656 |
| write/group_commit, 1 agent | x925 | 1,813,332 | 1,657,427 | -85,977 |
| write/group_commit, 4 agents | a725 | 796,566 | 843,486 | 58,903 |
| write/group_commit, 4 agents | x925 | 659,727 | 660,281 | 839 |
| write/group_commit, 8 agents | a725 | 395,578 | 412,826 | 43,602 |
| write/group_commit, 8 agents | x925 | 323,440 | 324,335 | 2,768 |
| write/group_commit, 32 agents | a725 | 318,176 | 306,580 | -36,445 |
| write/group_commit, 32 agents | x925 | 186,150 | 177,818 | -44,759 |
| query/read_tree_diff | a725 | 617,578 | 615,837 | -2,818 |
| query/read_tree_diff | x925 | 333,933 | 334,493 | 1,674 |
| crumb/context_advisory | a725 | 252,178 | 250,992 | -4,706 |
| crumb/context_advisory | x925 | 131,462 | 131,023 | -3,343 |

Reading the table: the CPU-bound legs (floor, query, crumb) repeat within 0.1 to 0.5 percent. The write
legs move by up to about 9 percent between back-to-back windows, because each write window is only
4 operations per agent and is dominated by storage flush time. The X925 cores run the CPU-bound legs about
twice as fast as the A725 cores. None of this is a qualification figure: 3 repetitions, short windows,
one host.

PMU counts, IPC and mispredict ratios: **`NOT_RUN`** (`INSTRUMENT_UNAVAILABLE` / `PERMISSION_DENIED`,
84 of 84 instrumented windows). Joules: `NOT_MEASURED`.

## 3. Method

- **Events** (ARM PMUv3 common events): `CPU_CYCLES` 0x11, `INST_RETIRED` 0x08, `BR_PRED` 0x12,
  `BR_MIS_PRED` 0x10. Source: Linux `include/linux/perf/arm_pmuv3.h` in the installed kernel headers
  (`/usr/src/linux-headers-7.0.0-1019-nvidia`, `ARMV8_PMUV3_PERFCTR_INST_RETIRED 0x0008`,
  `..._BR_MIS_PRED 0x0010`, `..._CPU_CYCLES 0x0011`, `..._BR_PRED 0x0012`). Each event is also read from
  `/sys/bus/event_source/devices/<pmu>/events/<name>` and must equal `event=0x00NN`, or the PMU is refused.
- **Core classes.** Each PMU's `cpus` list is read from sysfs and its class taken from the MIDR part number
  (`/sys/devices/system/cpu/cpuN/regs/identification/midr_el1`): 0xD87 Cortex-A725, 0xD85 Cortex-X925.
  Readings are attributed to the PMU that produced them, never merged across classes.
- **Open.** `perf_event_open(2)` per PMU, one group of the four events (leader opened disabled),
  `pid = 0, cpu = -1`, `inherit = 1` so every thread the window creates is counted,
  `exclude_kernel = 1, exclude_hv = 1` (user-space work only, which is also what paranoid level 2 allows),
  `read_format = TOTAL_TIME_ENABLED | TOTAL_TIME_RUNNING`. Members are read one by one because the man page
  states `inherit` "does not work for some combinations of read_format values, such as
  PERF_FORMAT_GROUP". Group members are scheduled together, so ratios within one group compare the same
  intervals even when the group was multiplexed. Source: `man 2 perf_event_open` (ioctl
  `PERF_EVENT_IOC_ENABLE`/`DISABLE`/`RESET`, error codes, `perf_event_paranoid` levels) and
  `/usr/include/linux/perf_event.h` (`PERF_ATTR_SIZE_VER0` = 64 bytes, ioctl numbers, `PERF_FLAG_FD_CLOEXEC`).
- **Fail closed.** If any event of any PMU fails to open, the whole window is `INSTRUMENT_UNAVAILABLE`
  with the reason and OS error; no partial counts are kept. Counts are never scaled by
  `enabled / running`; the times are recorded so a reader can see multiplexing.
- **Affinity.** `unpinned`, `a725` or `x925`, set with `sched_setaffinity` on the measuring thread before
  the window (threads it creates inherit it) and restored afterwards.
- **Timing.** `CLOCK_MONOTONIC` wall nanoseconds around the measured work only; counters are opened before
  the clock starts and read after it stops. CPU time is `getrusage(RUSAGE_SELF)` user plus system
  microseconds over the window. Wall time minus CPU time shows off-CPU time (storage waits); with
  `exclude_kernel` the counters see only user-space work, so CPU work and storage wait stay separate.
- **Legs.** `floor` (SHA-256 of 12 KiB, Ed25519 verify, envelope validate, JSON decode of a submit
  request), `write` (every-commit or group-commit arm, N agents each submitting M operations, through the
  same `synapse_submit` path as `run`), `query` (populate then `read_tree_diff`), `crumb` (context and
  changeset advisory; `NOT_RUN` when the fixture has no `.crumb`). Setup is outside the clock; floor,
  query and crumb legs run one warm-up pass first.

## 4. Formulas (recompute by hand)

All values in `raw.json` are integers. Per side (control or instrumented) over windows without an error:

- `wall_ns_per_op = wall_ns / ops` (integer division) per window; `cpu_us = cpu_user_us + cpu_sys_us`.
- Distributions are `n`, `min`, `p50` (nearest rank, rank `ceil(0.5 n)`), `max`.
- `overhead_ppm_p50 = (instrumented p50 wall_ns - control p50 wall_ns) * 1,000,000 / control p50 wall_ns`
  (integer, truncated toward zero).
- Per core class and event, over readings that are not `NOT_SCHEDULED`: distributions of `raw_count`
  and `raw_count / ops`.
- `instructions_per_kilocycle = sum(INST_RETIRED) * 1000 / sum(CPU_CYCLES)`;
  `mispredicts_per_kilo_predicted_branches = sum(BR_MIS_PRED) * 1000 / sum(BR_PRED)`, summed per class
  over counted windows. Absent when the denominator is 0 or nothing was counted.

## 5. Limits

- No counts on this host without an operator change (`perf_event_paranoid` 4). The code path that reads
  real counts is covered by tests with a fake backend and by the real-host test, which on this host takes
  the typed-unavailable branch. Real counted output on GB10 is **UNVERIFIED**.
- The overhead of open, enable, disable and read on a permitted host is therefore not measured here.
- `pmu-verify` is a consistency check: anyone can edit `raw.json` and regenerate the report and checksums.
  Authenticity comes from git history and review.
- Diagnostic only. Nothing was tuned from this run; any optimisation decision needs its own
  pre-registered, held-out runs.

## 6. Reproduction

```
cargo build --release -p synapse-bench
synapse-bench pmu-diag --evidence <dir holding protocol.json> --work-dir <scratch dir> \
  --fixture-repo <git repo at the protocol's fixture_rev> --source-rev <commit> [--sibling name=rev]...
synapse-bench pmu-verify --evidence evidence/bench-pmu-diagnostics/host-sample-2026-10-16
cd evidence/bench-pmu-diagnostics/host-sample-2026-10-16 && sha256sum -c SHA256SUMS
```

The run refuses to overwrite an existing `raw.json` and writes `report.json` and `SHA256SUMS` when it
finishes. To get counts on a Spark, an operator must permit unprivileged user-space counting
(`perf_event_paranoid` at 2 or lower) or run with `CAP_PERFMON`; the tool never changes this itself.
