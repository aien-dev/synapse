# Crumb-Synapse Combined Qualification (ADR 0004 D5)

Tracking issue: [aien-spark/synapse#12](https://github.com/aien-spark/synapse/issues/12). ADR: [0004](adr/0004-crumb-synapse-integration.md), deliverable D5.

Evidence: [`evidence/crumb-synapse/`](../evidence/crumb-synapse/) (`results.txt`, `results.json`, `negative-control.txt`, `SHA256SUMS`), written by `scripts/qualify-crumb-synapse.sh`. The results record the Synapse commit, the pinned `crumb.c` commit and sha256, and one status per scenario.

## How it runs

`scripts/qualify-crumb-synapse.sh [aien-architecture checkout]` builds `tools/crumb/crumb.c` at `29780e5` with `cc` only (and refuses a source whose sha256 is not `ef0f6566...`), then:

1. runs `crates/synapse-bench/tests/crumb_synapse_qualification.rs` with `CRUMB_C_BIN` set; each scenario prints one `D5-RESULT <id> <status> <detail>` line, and a scenario with no line counts as FAIL;
2. re-runs every known-defect test (ignored in normal runs) and requires it to still fail, so a silent fix or a silent regression of the record is caught;
3. runs `scripts/crumb-parity.sh` (D1) and `scripts/crumb-coord-interop.sh` (D2).

It exits 0 only when every scenario is PASS or KNOWN-GAP, every known defect reproduces, and both sibling scripts pass. Statuses: **PASS** (property holds), **KNOWN-GAP** (behaviour is as designed today but is not the end state), **UNVERIFIED** (not run, reason given; `cargo test` alone reports S10 this way because it has no `crumb.c`).

## Scenarios

| ID | Scenario | What it proves | Limits |
|---|---|---|---|
| S01 | Two agents, same file | The second claim is refused with the holder named; the second agent's advisory shows the first agent's claim and open proposal. | Advisory only: Synapse does not refuse the second agent's submit (by design, ADR 0004 section 2.6). |
| S02 | Two agents, separate files | Both claims granted; the advisory has no claims, overlaps, pending `.crumb` changes or staleness. Invariants still appear as guidance. | |
| S03 | Stale Crumb snapshot | Advisory reports `Stale` and names the open `.crumb` rewrite. A receipt binding the base context on the changeset side is `Stale` `InChangeset`; one built from a stale base snapshot is `Stale` `AtBase`; each names the directory and the expected digest. | |
| S04 | Expired claims | A claim is live at its TTL, ignored one second later by the advisory and taken over in the plane; an unparseable timestamp counts as expired (crumb.c rule). | Fixed test clock; real-time expiry across tools is covered by interop I8. |
| S05 | Forged/tampered coordination records | Corrupt or over-deep JSON gives `Unavailable` (no panic, record not overwritten); holders that are empty or not strings are skipped; a forged holder is shown as information only; hostile keys (traversal, absolute, empty, prefix, 70 KB, non-UTF-8) match nothing. With all of that present, a submit still commits and its receipt is `Current`: coordination is never authority. | Records are unauthenticated: a writer of the store can forge any claim (shown as advice), and a lock forged in the caller's own name is hidden from that caller (ADR 0004 section 2.6). An escaped `\u0000` truncates a key as in crumb.c. A FIFO, symlinked or over-1-MiB record is refused (`Unavailable`) without blocking (#58, fixed). |
| S06 | Forged/tampered receipts | Bad signature, a key forging another runner's DID, a non-canonical (bare `z6Mk`) DID, six field tampers, wrong domain, truncation, trailing bytes, an over-cap record and an over-cap log are each refused with the expected typed error; every 7th single-byte flip is refused. | |
| S07 | Self-signed receipt | A receipt signed by the changeset author's own key verifies `Current`. **KNOWN-GAP**: version 1 has no executor registry; executor independence waits for ADR 0003 E0/E1. `Current` grants nothing (S12). | |
| S08 | Crash mid-claim | Torn `*.tmp<pid>` files are never read as records. A child process aborted (SIGABRT, `SYNAPSE_COORD_FAULT=before-rename`) between the tmp write and the rename leaves the record byte-identical; the plane stays usable. | One fault point (before rename); kill timing elsewhere is not swept. |
| S09 | Crash mid-submit | With group commit (WAL v2, PR #18), a child process killed mid batch write (`CrashMidBatchWrite`, exit 42): strict reopen refuses the torn tail, truncating reopen shows only acknowledged changesets, the advisory shows no phantom proposal, the agent's claim survives, and a resubmit plus receipt is `Current`. | Uses the store's own fault injection, not an external `SIGKILL` at a random point. Claims are not released by a failed submit; they expire by TTL. |
| S10 | Mixed agents | `crumb.c` in a Git worktree and `synapse-coord` share one store: each refuses the other's claim (crumb.c exit 2), and the Synapse advisory shows the crumb.c holder and branch. `open_expecting` refuses a root with no `STORE_ID` and one with another store's id. | crumb.c does not check `STORE_ID`: pointed at a wrong root it grants a second claim on the same file (recorded in the result line; ADR 0004 D2 "not yet done"). |
| S11 | Git round trip | A Git repository with D1, D2 and D3 `.crumb` files imports into Synapse with each dialect recognised; a changeset rewriting the D1 crumb materializes back to Git with all four `.crumb` blobs byte-identical, the untouched directory's tree OID unchanged, and a re-import giving identical context digests. | Regular files only (mode 100644). |
| S12 | Exit rule | After a clean run with a `Current` `Pass` receipt, GitHub PR projection is refused without `Capability::Publish` (for the author and the runner, holding every other capability), and Radicle canonical promotion is refused without the delegate quorum (no sigrefs, runner sigrefs, author sigrefs; a merged GitHub PR does not help). No canonical head is recorded. Each gate opens only for its own credential (a Publish grant, delegate sigrefs). Neither gate takes a receipt as input. | **AEGIS is not integrated** (it lives in aienos `crates/aienos-aegis`); only Synapse's own gates are tested. `SynapseStore::record_canonical_promotion` is an unauthenticated store call used after the engine verifies; it is not an agent-facing API. `synapse-git::advance_human_branch_fast_forward` writes `refs/heads/<branch>` in a local Git directory with no capability check; it is a library function for callers that already hold filesystem access, not a `SynapseService` path, and S12 does not cover it (tracked in a follow-up issue). |

Scenarios S01, S02, S04, S08, S10 and S11 qualify coordination, context and Git behaviour and do not produce a D4 evidence receipt; receipts appear in S03, S05, S06, S07, S09 and S12 where the scenario is about evidence.

## Negative control

With signature checking disabled in `EvidenceReceipt::verify`, the suite went red (S06: a receipt with a flipped signature byte verified `Current`; 13 passed, 1 failed). The change was reverted. Details in `evidence/crumb-synapse/negative-control.txt`.

## Defects found

* [#58](https://github.com/aien-spark/synapse/issues/58) (fixed): coordination record reads were unbounded. A FIFO named `*.json` hung `sniff` (and so the advisory) forever; `/dev/zero` or a huge file was read in full. synapse-coord now refuses non-regular, symlinked and over-1-MiB store files with a typed `RefusedRecord` (advisory: `Unavailable`) without blocking; the test `s05_fifo_record_refused_advisory_answers` runs in the suite. crumb.c @ 29780e5 still hangs the same way (aien-architecture follow-up).
