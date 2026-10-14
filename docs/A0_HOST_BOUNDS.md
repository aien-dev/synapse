# A0: Host Bound Probes (Experiment X0)

ADR 0003 section 9 step A0 (issue #21). This step measures the host inputs that the section 6.2 bounds
need and that were "not yet measured": memory bandwidth, device read and write bandwidth, and all-core
SHA-256 and Ed25519 verification throughput, with an energy preflight. The flush time comes from W1
(Phase 5) and is not measured again. These figures are bound inputs, not targets.

## 1. Acceptance and Where It Is Met

| ADR 0003 A0 acceptance | How it is met | Proof |
| :--- | :--- | :--- |
| Sealed evidence with instrument, resolution, and raw samples | `evidence/a0-host-bounds/`: `protocol.json`, `raw.json` (every timing in ns, every work count, every meter reading in µJ, `/proc/loadavg` at each run's edges), `report.json`, `SHA256SUMS`. `raw.json` names the clock (`CLOCK_MONOTONIC`, 1 ns resolution from `clock_getres`) and the meter (1 mJ step, 0.1 s update, 10 Hz sampling) | `sha256sum -c SHA256SUMS` |
| Repetitions and spread statistic fixed before the runs | `protocol.json` fixes 7 repetitions, median, range (min and max), the bound statistic (highest rate any repetition reached), and every probe size. It was committed and pushed (`f24a5d6`, 18:18:18 UTC) before the run started (18:18:25 UTC). `raw.json` carries the protocol's SHA-256, and verification refuses a changed protocol, a dropped or extra repetition, or a run whose threads or work differ from the protocol | tests `verify_refuses_a_protocol_changed_after_the_run`, `verify_refuses_dropped_extra_or_resized_repetitions` |
| Someone holding only the sealed raw data recomputes every reported figure exactly | `raw.json` holds integers only; `report.json` is a pure function of the protocol and raw bytes (formulas in section 3). `synapse-bench bounds-verify` recomputes it and compares byte for byte. On the sealed data: `verified` | `red-green/tamper.txt`, tests `verify_*` |
| With the energy device hidden, the probe refuses with `INSTRUMENT_UNAVAILABLE` | Energy preflight runs first: no `aien_spbm` device, a counter that does not advance, an unreadable channel, or a set overflow flag refuses with `INSTRUMENT_UNAVAILABLE`; nothing is written and no probe runs | `red-green/hidden-meter.txt`, tests `hidden_energy_device_*`, `frozen_overflowed_or_missing_counters_refuse_preflight` |

Red before green: the 19 tests were committed first against a skeleton whose bodies were stubs
(`aadd9e6`); 18 failed for the stated reason (`red-green/red.txt`). The 19th, an advancing counter
passing preflight, is the control against a preflight that refuses everything, so it passes against a
stub that accepts everything. The implementation (`00c3f1f`) turns all 19 green (`red-green/green.txt`).
The only later change to the test file adds two load-average fields to a test fixture.

## 2. Results

Host: GB10, 20 CPUs (10 Cortex-X925, 10 Cortex-A725), 127,598,752 KiB memory, kernel
7.0.0-1019-nvidia, ext4 on `/dev/nvme0n1p2`. Binary built from `f24a5d6`. Seven repetitions, probes
interleaved in the order of the table inside each repetition.

| Probe | Threads | Bound input (max rate) | Median | Range | Package W (median) | Package J per unit (median) | Above idle (median) |
| :--- | ---: | ---: | ---: | :--- | ---: | ---: | ---: |
| Idle (2 s sleep) | 0 | | | | 28.59 (23.25 to 33.32) | | |
| Memory read | 20 | 103.80 GB/s | 102.82 GB/s | 100.27 to 103.80 | 61.58 | 0.601 nJ/B | 0.319 nJ/B |
| Memory copy (read plus written) | 20 | 122.02 GB/s | 120.90 GB/s | 116.37 to 122.02 | 59.35 | 0.494 nJ/B | 0.277 nJ/B |
| Device write, O_DIRECT, through `fdatasync` | 8 | 10.92 GB/s | 3.665 GB/s | 1.558 to 10.92 | 29.58 | 9.23 nJ/B | 0.690 nJ/B |
| Device read, O_DIRECT | 8 | 12.25 GB/s | 11.79 GB/s | 10.24 to 12.25 | 30.61 | 2.62 nJ/B | 0.299 nJ/B |
| SHA-256, `sha2` crate as built | 20 | 6.167 GB/s | 6.054 GB/s | 5.676 to 6.167 | 50.90 | 8.35 nJ/B | 3.84 nJ/B |
| SHA-256, Armv8 SHA-2 instructions | 20 | 22.25 GB/s | 20.48 GB/s | 20.13 to 22.25 | 59.46 | 2.90 nJ/B | 1.50 nJ/B |
| Ed25519 verify, `ed25519-dalek` | 20 | 395,192 /s | 392,552 /s | 298,004 to 395,192 | 55.55 | 140.9 µJ | 77.2 µJ |

GB means 10^9 bytes. Every exact value is in `report.json`; the table rounds them.

Flush, from W1 (`evidence/phase5-group-commit/floor.json`, SHA-256 `9c30eddf…5ccef`, pinned in the
protocol), p50: overwrite of already written space plus `fdatasync` 1.106 ms (4 KiB), 0.903 ms (64 KiB),
0.805 ms (1 MiB); `O_DIRECT | O_DSYNC` 4 KiB overwrite 1.606 ms; append 4 KiB plus `fdatasync` 3.703 ms.

Bound inputs for section 6.2 (the highest rate any repetition reached, so the host demonstrably did at
least that):

- Memory bandwidth: 103.80 GB/s read (hardware measurement, every core).
- Device bandwidth: 10.92 GB/s write through `fdatasync`, 12.25 GB/s read (hardware measurement).
- All-core SHA-256: 22.25 GB/s with the SHA-2 instructions (implementation reference, section 6.2).
- All-core Ed25519 verification: 395,192 per second with `ed25519-dalek` (implementation reference).

Section 6.2 replay row, now computable: Gate 4 replays 117,196,023 bytes with a warm page cache. Reading
them at 103.80 GB/s takes 1.129 ms (calc:373a2064); digesting them at 22.25 GB/s takes 5.267 ms
(calc:fea168bc). The bound is the larger, 5.267 ms. Gate 4's measured median replay, 344.575 ms, is
0.0153 of that bound (calc:9fb2ae77). Supporting figures per Gate 4 change of 11,949 bytes: 0.115 µs to
move once at memory bandwidth (calc:f02900c4), 0.537 µs to digest at the all-core SHA-256 reference
(calc:f77f12b6), and 2.53 µs of all-core Ed25519 time per verification (calc:65a531d5).

Finding: the workspace builds `sha2` 0.10.9 without its `asm` feature, and on aarch64 that crate then uses
its software backend (`sha2/src/sha256.rs`: the aarch64 backend needs `feature = "asm"`). Synapse's own
hashing therefore runs at the 6.054 GB/s all-core median, not the 20.48 GB/s of the SHA-2 instructions on
the same block size. Changing that is a dependency decision for X1 or J3, not part of A0.

## 3. Formulas (enough to recompute by hand)

For each run in `raw.json`: `elapsed_s = elapsed_ns / 1e9`; `rate = work_units * 1e9 / elapsed_ns`.
Energy from the run's meter samples: `pkg_j = (last pkg_uj - first pkg_uj) / 1e6` (same for `cpu_p`,
`cpu_e`); `window_s = (last t_ns - first t_ns) / 1e9`; `pkg_mean_w = pkg_j / window_s`;
`pkg_edge_sd_j = pkg_mean_w * 0.1 * sqrt(2/3)`; `pkg_j_per_unit = pkg_j / work_units`;
`above idle = (pkg_j - idle_w * window_s) / work_units`, where `idle_w` is the `pkg_mean_w` of the idle run
in the same repetition. A window is refused (no joules) when an overflow flag is set at an edge, two
samples are more than 300 ms apart, fewer than 90% of `floor(window_ns / 100 ms)` samples arrived, a
counter is unreadable or decreases, or it is within one window of the 32-bit wrap; none of the 56 sealed
windows was refused. Median: middle value of the seven; range: minimum and maximum; bound input: maximum.
All arithmetic is IEEE double in the order written in `compute_report` and `energy_figures`
(`crates/synapse-bench/src/bounds.rs`).

## 4. Method

- Memory: each thread pinned to one CPU owns a 64 MiB buffer (20 x 64 MiB, far above the caches) and sums
  it as u64 words 80 times (read) or copies it into a second 64 MiB buffer 80 times (copy). Buffers are
  filled before timing. Copy counts bytes read plus bytes written; write-allocate reads are not counted.
- Device: a 16 GiB file is written with zeros and fsynced once (untimed), then each repetition overwrites
  it with `O_DIRECT` in 4 MiB chunks from 8 threads (2 GiB region each), each thread ending with
  `fdatasync`; the time runs until the last thread's flush returns. The read probe then reads the file
  back with `O_DIRECT` and checks the pattern of every chunk.
- SHA-256: each thread hashes its own 16 KiB block 60,000 times. The instruction version is checked
  against the `sha2` crate digest before timing, and in tests over 204 lengths.
- Ed25519: each thread verifies 16 prepared signatures over 256-byte messages in turn, 20,000
  verifications per thread; any failure aborts the run.
- Threads are released together by a barrier; the time runs from release until the last thread is done.
- Sizes come from two unsealed calibration passes (3 repetitions each), chosen so every timed window
  lasts about 0.7 to 3.3 s against the meter's 0.1 s update period. Calibration output is not evidence.

## 5. Limits

- The host was shared: the 1-minute load average was 7.73 to 15.85 at run starts, and the idle window
  drew 23.25 to 33.32 W. Above-idle joules are therefore noisy and can be negative (device write minimum
  -1.19 nJ/B). Medians below the maximum, especially device write (median 3.665 GB/s against a maximum
  10.92 GB/s, one run took 11.0 s), reflect contention as well as the device. The bound statistic is the
  maximum for that reason.
- Energy is SoC package only, uncalibrated, with no published accuracy; NVMe energy is UNMEASURED, so
  "device energy per flushed byte" (X0) is not available: the device rows give package joules only.
- The edge uncertainty (`pkg_edge_sd_j`) reaches 5.5 J per window for the busiest probes; joules per unit
  inherit it.
- The device read follows the write of the same data; the drive's internal cache may serve part of it.
- SHA-256 and Ed25519 figures are implementation references (section 6.2): a faster implementation
  measured later replaces them. OpenSSL was not measured here.
- One host, one filesystem, one run of seven repetitions.

## 6. Reproduction

```
cargo build --release -p synapse-bench
synapse-bench bounds --evidence <dir holding protocol.json> --work-dir <dir on the store filesystem> \
  --repo-root . --source-rev <commit>
synapse-bench bounds-verify --evidence evidence/a0-host-bounds
cd evidence/a0-host-bounds && sha256sum -c SHA256SUMS
```

The run refuses to overwrite an existing `raw.json` or `report.json`.
