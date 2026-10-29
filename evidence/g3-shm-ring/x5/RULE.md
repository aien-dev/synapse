# X5 decision rule (fixed before the run)

Step G3 of ADR 0003 (issue #46). This file is committed before any X5 measurement is taken.
The bench tool (`wire-transport --rule`) refuses to run unless this file is tracked by git and
unchanged from the committed version, and it records the commit and the file's SHA-256 in
`spec.json`.

## Question

Does the shared-memory ring (`RingStream`) carry the G1 workload at lower cost per accepted
change than the Unix socket (`UnixStream`), the G1 default?

## Workload and arms

- The G1 workload, unchanged: the `wire-transport` change set (same fixture, same blob sizes,
  same store), 2,000 changes per arm per repetition, run with `--release`.
- Arms: `ring`, `wire` (Unix socket), `direct_auth` (no wire, reference only). Arm order rotates
  each repetition.
- 5 repetitions. 30 s idle window before the run for the idle power figure.
- Echo round trips (20,000 per transport per repetition) are recorded as supporting data only.
  They are not part of the verdict.

## Bound (same as G1)

`docs/PHASE5_GROUP_COMMIT.md` section 5: t_floor 0.806 ms and E_floor 18.6 mJ per durable
change. Results are reported as multiples of this bound; the bound is not part of the verdict.

## Validity

A run is valid only if every submitted change in every arm and repetition is accepted and none
is reported as a duplicate (the tool aborts otherwise). An invalid run gives no verdict: the ring
is NOT ADOPTED, and the run may be repeated once with both runs kept.

## Verdict

ADOPTED only if both hold:

1. Seconds per accepted change: the ring's median over the 5 repetitions is lower than the
   socket's, AND the ring's slowest repetition is faster than the socket's fastest repetition.
2. Package joules per accepted change, from the real instrument: the same test (median lower,
   ring maximum below socket minimum), with every repetition's energy window valid. If joules
   are not available from a real instrument, the joules figure is INSTRUMENT_UNAVAILABLE and
   the verdict is NOT ADOPTED.

Otherwise NOT ADOPTED: the Unix socket stays the default transport, and the ring is kept as a
tested, optional transport (its safety tests and this measurement stay in the tree).

The verdict is computed by `x5_verdict` in `crates/synapse-bench/src/bin/wire-transport.rs`
and written to `result.json`. One run; no re-runs to change a verdict.
