# Swarm board bench: results (record run)

Rule: [`RULE.md`](RULE.md), committed in 56df1a0 before this run. Raw data: `raw/`
(`runs.txt`, per-message latencies `*.lat_us`, `env.txt`, `fsync.txt`, `energy-idle.txt`).
Every number below is **host-observed** on this machine (`env.txt`: Linux 7.0.0-1019-nvidia
aarch64, ext4 on `/dev/nvme0n1p2`, release binary sha256 prefix 980b0289f990e79e, commit
56df1a0). One run per (flow, W), 128 messages each. Derived figures carry an aien-calc
receipt id (listed at the end).

## Verdict: PASS

At every W the board delivered 128 of 128 with no duplicate, `board check` was clean, and its
p50 was below the pre-board p50.

| W | flow | delivered | dups | p50 ms | p95 ms | max ms | wall s |
|---|------|-----------|------|--------|--------|--------|--------|
| 1 | board | 128 | 0 | 7.39 | 8.06 | 23.15 | 0.961 |
| 1 | pre-board | 128 | 0 | 20.90 | 31.49 | 34.23 | 1.334 |
| 4 | board | 128 | 0 | 8.32 | 12.08 | 22.95 | 0.374 |
| 4 | pre-board | 128 | 0 | 131.79 | 210.95 | 226.89 | 0.459 |
| 8 | board | 128 | 0 | 8.70 | 21.85 | 23.57 | 0.191 |
| 8 | pre-board | 128 | 0 | 247.83 | 320.57 | 326.79 | 0.405 |
| 32 | board | 128 | 0 | 13.51 | 28.84 | 39.15 | 0.085 |
| 32 | pre-board | 128 | 0 | 374.71 | 409.75 | 420.62 | 0.430 |

p50 against our own pre-board flow: 2.83x lower at W=1 [calc:e6e79b72], 27.7x lower at W=32
[calc:4b7eb583]. The pre-board flow does not fsync its mail and is not durable; the board
acknowledges only after two fsync rounds. The orchestrator repost the pre-board flow needs
(an LLM turn) is excluded, as the rule says.

## Against the disk's limit

`dd` 500 x 512 B with `oflag=dsync` took 1.96715 s: t_fsync = 3.9343 ms [calc:373b85d5]. One
acknowledged post needs two serial fsync rounds, so its latency floor is 2 x t_fsync =
7.87 ms. floor / p50:

| W | floor / p50 |
|---|-------------|
| 1 | 1.065 [calc:bb86387e] |
| 4 | 0.946 [calc:bb6893fd] |
| 8 | 0.905 [calc:769614a0] |
| 32 | 0.583 [calc:ac902fe5] |

At W=1 the board's median sits at the disk's measured limit; the value above 1.0 says the
`dd` figure is not a strict lower bound for the board's `fdatasync` (it was measured at a
different moment, and flush latency on this disk varied from about 3.5 to 8.6 ms per synced
write across today's measurements). With group commit the floor does not grow with W: at 32
concurrent writers the median is about 1.7 times the single-post floor (the inverse of
0.583), the rest being queueing for the lock and 32 concurrent process starts.

## Energy (reported, does not decide the verdict)

Whole-package meter (`hwmon aien_spbm energy1`, pkg), background included. Idle over 5 s
before the runs: 32.372 W [calc:6e78a176]. W=1 runs (about 1 s each): board 0.2863 J per
message [calc:3b273eb5], pre-board 0.3916 J per message [calc:5d8771ae]; both are dominated
by the idle draw. The shorter runs are below the meter's update period (the W=32 board run,
85 ms, read the same counter value at start and end), so their energy is **not resolved** and
is not reported; the raw counters are in `runs.txt`.

## Limits of this evidence

- One run per cell on a shared host; no repeat runs, so no spread across runs is claimed.
- The receiver latency includes process start of each send command on both sides.
- The pre-board receiver is a busy loop (its best case); a real agent polls less often.
- The disk was 99% full during the run.

## Receipts

- calc:373b85d54fef4ff616808c598d65f56baa028c4fc6cff8a2721f3008331b6e3a (t_fsync)
- calc:bb86387e350f23a028c72fb595069245d7383dd65cf57f4527a8a5182654557c (W=1 fraction)
- calc:bb6893fd5fac5ba81b764f53cac8d7be5cd62ed37ee3d0473f9108b03798d358 (W=4 fraction)
- calc:769614a075bd3b02d047be29c93dd1319a835e13d894d24a0fe1bc49cbdd57a3 (W=8 fraction)
- calc:ac902fe50d4f9c09f3488de294eae6059787377068d0e28e57bcd14794f49a4b (W=32 fraction)
- calc:e6e79b72fdd1cf6f92627206e0ca4ecc9334607a5e3380cc5405137639b104f0 (W=1 p50 ratio)
- calc:4b7eb583ba84ec17dfdc07fdfae6f0fc0e132ac4da2f68a01a8ea63d2ec83957 (W=32 p50 ratio)
- calc:6e78a176d07e05d159ee058f80b3b2d6e8abf1c7ecd51bec6a954d38a096c769 (idle W)
- calc:3b273eb59a1092662ad4596c4d4fedb76739009a85c108123daf57e9ad3f47e0 (board J/msg W=1)
- calc:5d8771aec1f58cc290e0e4a574404bd672d77d1ffd25cd4e04c882024911861d (pre-board J/msg W=1)
