# X5 result (run1, release build, rev 864aeca, 2026-10-16)

Decision under the rule fixed in `RULE.md` (committed in 864aeca before the run; the tool recorded that commit and the file hash in `run1/spec.json`): **NOT ADOPTED**. The Unix socket stays the default transport. The ring is kept as a tested, optional transport.

Both conditions of the rule must hold. Neither does.

| Condition | Ring (5 reps) | Unix socket (5 reps) | Met |
| :--- | :--- | :--- | :--- |
| Seconds per accepted change: median lower AND ring slowest < socket fastest | median 1.541 ms; reps 1.471, 1.479, 1.541, 1.558, 1.863 ms | median 1.606 ms; reps 1.466, 1.597, 1.606, 1.638, 1.682 ms | NO. Median is 4.1 percent lower, but the ring's slowest rep (1.863) is above the socket's fastest (1.466): the ranges overlap |
| Package joules per accepted change: same test, all windows valid | median 46.4 mJ; reps 42.4, 43.7, 46.4, 51.2, 85.5 mJ | median 46.1 mJ; reps 44.0, 45.1, 46.1, 47.1, 48.1 mJ | NO. Median is not lower, ranges overlap |

Against the bound (`docs/PHASE5_GROUP_COMMIT.md` section 5: t_floor 0.806 ms, E_floor 18.6 mJ), fraction of bound (floor over measured): ring 0.524 in time and 0.401 in energy; socket 0.502 and 0.403; `direct_auth` (no transport) 0.530 and 0.461. All three arms sit near the same level, so the transport is a small part of the cost per change; the durable commit dominates.

Supporting only, not part of the rule: echo round trips (20,000 per transport per rep, no store) have a median of p50 6.8 us for the ring against 9.1 us for the socket. The ring is faster at moving bytes; that gain is hidden behind the commit cost.

Validity: every change in every arm and repetition was accepted and none was a duplicate (the tool aborts otherwise). The joules windows were valid.

Limits (host-observed unless marked):
* Joules are the `aien_spbm` SoC package meter only: uncalibrated, no published accuracy, not compared with an external meter, NVMe unmeasured.
* The machine was shared: the 30 s idle window read 38.6 W mean with load average about 5.8 and 132 CPU-seconds of other activity, so the above-idle figures are noise and are not used. One ring rep (85.5 mJ, 1.863 ms) is a clear outlier on this shared host; it is kept, not dropped.
* Client and server are two threads in one process over two views of one region; a separate client process is covered by the safety test, not by this measurement.
* One run, as the rule says.

Raw samples: `run1/result.json` (every per-change latency in nanoseconds, every energy window, every echo round trip), `run1/run.log`, `run1/spec.json`.
