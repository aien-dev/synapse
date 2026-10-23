# L662: recover the existing Synapse105 implementation

**Intermediate qualification, not merge/closure approval.** Existing PR110 still names an earlier partial implementation. This branch preserves the full original work rather than starting another repair tool or PR. Dependency PR103 is now merged. Publisher handoff L663 must advance existing PR110 only after final source review and exact-head signed gates; paused lanes are not resumed here.

## Source lineage

- Current public base: `5b732e5d353bbcc3f6d0cd1eac60f2e543601521`.
- Earlier partial PR110: `b1cc199a63744efb6919ba0873b98e32cddb87a8`.
- Recovered full original branch: `synapse-105@ad38ef217254ab38246e0593ec2d9b899deebd3e`, including `765521b5178d36e2585373377006f851305bb81f`, `ff28b5639202ff16233c6a31ea28eb2122043bea` and `ad38ef217254ab38246e0593ec2d9b899deebd3e`.
- Those three code/doc commits were carried with author attribution onto current main, without overwriting newer API/auth/Git/store changes or importing old generated crumbs. Initial recovered carry: `5c6aad4701a44f3187487123f70753bd13ef0714`.
- New bounded repair fixes and regression tests: `e7ec679cfed7fd0fa27b727964ca337ce77ce45f`.

The original full implementation includes read-only diagnosis, explicit roll-forward/adopt intent, backup-before-write, signed chained on-device repair history, healthy-image no-op, foreign-signature refusal and exclusive locking. Existing tests exercise acknowledged content recovered byte-identically, signed history verified on reopen, loss ranges and interrupted adopt. This is library/CLI host-image qualification, not real partition testing, independent security audit or a new operator-key trust policy. A signature attributes a key; replacing the whole raw disk/log under a different key is not prevented by this mechanism alone.

## Actual new behavioral RED/GREEN

1. A tiny backup with a valid body checksum and a `u64::MAX` section length panicked in `read_backup` at unchecked index addition. The regression failed101 with `attempt to add with overflow`; the reader now uses checked length conversion and bounds arithmetic and returns a refusal without altering the file.
2. A pipe-synchronized helper forks while the parent owns a `DirectFile` and never accesses the device. Dropping the parent wrapper left the advisory lock held through the inherited open file description. Reopening failed101 deterministically, without sleep or timing retries. The wrapper now explicitly releases its advisory lock on final drop before closing. The same test passes while existing live-owner lock refusals stay intact. Child cleanup/reaping precedes the assertion. This reproduces the mechanism conjectured in the old handoff, not proof of the exact helper responsible for its historical flaky run. It does not claim raw-partition O_EXCL inheritance was separately qualified.

Raw failure and post-fix logs are retained separately. No assertions were weakened and no failure was retried until it happened to pass.

## Qualification at this checkpoint

- Initial recovered source:502 passed,0 failed,2 pre-existing fixture-dependent ignores.
- After fixes:504 passed,0 failed, same2 fixture-dependent ignores, across53 test groups. Whole workspace uses the ordinary concurrent test execution; no test-thread serialization was introduced to hide the lock race. Focused repair tests, actual CLI test, workspace fmt and all-target Clippy passed.
- Both normally ignored fixtures were then explicitly attempted, not silently accepted as a full pass:
  - `c1_tree_and_diff_parity_with_git_on_gate4_fixture`:PASS on immutable Gate4 source commit `1b6e340d48417dfbcfe2df56d48a0696a3a9b250`,400 changesets with per-entry tree/diff equality.
  - `h1_real_repository_full_history_round_trips_with_identical_object_ids`:**FAIL101**. Native Git import/export loses the `refs/remotes/origin/HEAD` name even though its target object exists. The failed full reference-map comparison is preserved in `fixture-gates/h1-real-repository.log`.
- **Whole acceptance remains NOT PASS.** L664 is a narrowly owned, disjoint native Git reference-resolution repair; the existing broader PR96 contains the same skip and does not supply a fix. Do not remove the fixture alias, filter the assertion, waive the failure or call this branch complete. Its qualified fix must be carried and affected gates rerun before final independent review.
- Signed Spark judging, hosted exact-head acceptance, PR110 update, final source review, merge and issue closure are not established here. Required CRUMB-VERIFY remains in force; metadata must be refreshed with the current base's pinned tool after final source/evidence freeze, not the old branch's obsolete tool.

## Reproduction boundary

All runs are on the Spark Linux host, max6 build jobs under `quiet-build`; per-head target and owned `TMPDIR` are recorded in each state/log. Only synthetic in-memory or regular-file device images were used. No real block device, production store, GPU/model, live inference process, private editorial content or credentials were used. Scripts, compiler versions, exact commands and exit statuses are preserved. Test-generated signing keys are synthetic fixtures, not operator credentials.

Core commands:

```sh
cargo test --locked -j 6 --workspace --no-fail-fast
cargo test --locked -j 6 -p synapse-store r1_repair -- --test-threads=1
cargo test --locked -j 6 -p synapse-bench --test store_repair_cli
cargo fmt --all --check
cargo clippy --locked -j 6 --workspace --all-targets -- -D warnings
```

The fixture gate environment, full commands, actual source input hashes and failed result are in `fixture-gates/state.json`; ordinary suite totals and ignore names are in `suite-counts.json`. Failed records and historical source are not rewritten by later qualifications. No deployment/publisher workflow was added or run.
