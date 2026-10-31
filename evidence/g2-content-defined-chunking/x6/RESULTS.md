# X6 Results: Content-Defined Chunking Threshold and Chunk Sizes

Decision per the rule committed before the runs (`RULE.md`, sha256
`dd4ed8f936fdbeadb05fc12278fb05448e63dc44b8e8fb8bb006e0729b3f3935`, commit ab9ccc0, unchanged).
Raw samples: `raw.json`. Decision: `report.json` (`synapse-bench x6-report --raw raw.json`, the rule
applied by `crates/synapse-bench/src/x6.rs::decide`, unit-tested on constructed runs).

**Result: PASS. Winner K1 (T = 16 KiB, min 1 KiB, avg 4 KiB, max 16 KiB), the only eligible candidate.
`ChunkParams::X6_DEFAULT` is K1.** The run is valid: log and content bytes agree in all three
repetitions of every configuration, and every blob read back byte for byte.

## Run

Binary built from commit 7145a26 (`synapse-bench x6 --corpus ../corpus --out raw.json --dir <scratch>
--reps 3 --idle-window-s 10`), started 2026-10-16T09:01:04Z, load average 5.7 4.97 4.5 at start.
Host: DGX Spark, 20 CPUs, kernel 7.0.0-1019-nvidia, store on `/dev/nvme0n1p2` ext4. Shared host (other
agent sessions ran). Corpus (host-observed): 1,037 accepted changes, 24,093 file revisions, 433,805,920
bytes, 19,618 distinct blobs. Limits raised to `max_paths_per_changeset` = 2,184 and
`max_total_changeset_bytes` = 67,108,864 so that no commit is refused. Ingest is one agent, strict
recovery, `GROUP_COMMIT_DEFAULT`; each change is a durable group-commit batch (1,037 batches).

## Numbers (host-observed; medians of 3 repetitions)

| Config | W ms/change | W/W0 | R us/read | R/R0 | S log bytes | S/S0 | Eligible |
| :--- | ---: | ---: | ---: | ---: | ---: | ---: | :--- |
| C0 | 1.947 | 1.000 | 12.31 | 1.000 | 415,395,840 | 1.000 | control |
| K1 | 2.133 | 1.095 | 13.16 | 1.068 | 329,252,864 | 0.793 | yes |
| K2 | 2.186 | 1.122 | 12.81 | 1.040 | 343,347,200 | 0.827 | no (W) |
| K3 | 2.189 | 1.124 | 12.71 | 1.032 | 375,672,832 | 0.904 | no (W) |
| K4 | 2.171 | 1.115 | 12.51 | 1.016 | 385,204,224 | 0.927 | no (W) |
| K5 | 2.144 | 1.100 | 12.37 | 1.004 | 390,643,712 | 0.940 | no (W just above 1.10) |
| K6 | 1.984 | 1.019 | 12.45 | 1.011 | 410,193,920 | 0.987 | no (S) |
| K7 | 2.067 | 1.061 | 12.33 | 1.001 | 410,808,320 | 0.989 | no (S) |

Eligibility: W <= 1.10 W0, R <= 1.25 R0, S <= 0.95 S0. K1 is eligible with W/W0 = 1.095, a margin of
0.5 percentage points on a shared host; K5 misses the same limit by a similar margin. The rule decides,
and it was fixed before the runs, so the margin does not change the outcome, but the ranking of K1
against the W limit is within host noise (UNVERIFIED that K1 would pass again on a quiet host). The
smallest log is K1 (20.7 % fewer log bytes than C0; 4,512 blobs chunked into 54,731 distinct chunks,
258,659,059 chunk bytes).

## Seconds per accepted change against the A2 flush bound

Flush bound 1.006 ms (A2 `floor.json`, `overwrite_64k_fdatasync` p50). Median seconds per accepted
change K1: 2.133 ms (C0: 1.947 ms), so K1 reaches 0.471 of the bound (C0 0.516). Per-change latency
(raw samples in `raw.json`, `ingest_latency_ns`): K1 p50 1.5 ms, p99 18.5 ms; C0 p50 1.4 ms, p99 17.3 ms.
Reads: 12.3 to 13.2 us per read; the fraction of the 273 GB/s memory bound is in `report.json`
(`read_bound_fraction`; the index lookup term is not modelled there). This experiment measures one
agent, so the 1.006 ms figure is the single-flush floor of one change, not a multi-agent bound.

## Joules

From the `aien_spbm` SoC package counter (uncalibrated, 1 mJ step, 10 Hz; NVMe and memory outside the
SoC are UNMEASURED). Idle package power over 10 s: 34.6 W. Package joules per accepted change: C0
0.0773, K1 0.0762; above idle: C0 0.0099, K1 0.0017, with K2 and K4 reading below idle (negative). The
above-idle figures are inside the measurement noise on this shared host, which is why RULE.md section 6
does not use joules in the decision. No window was refused.

## Not run / limits

- No quiet-host rerun; no external energy meter (INSTRUMENT_UNAVAILABLE for anything but the SoC package).
- Reads measured through `get_blob_visible` in memory-warm state (page cache), not cold from the device.
- One agent only; group-commit batch sizes were 1 (1,037 batches for 1,037 changes).
