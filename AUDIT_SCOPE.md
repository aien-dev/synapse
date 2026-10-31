# Audit scope

Written for an outside, independent security audit. Revision described:
`5f9a638d6be5c271748dc740f69159422788ca81` on `main`, 2026-10-30. Everything below is taken from
the repository's own files at that revision; items marked NOT_RUN were not executed while writing
this document.

## What this repository is

Synapse is source control for AI agents. Agents submit signed changesets, inspect virtual trees and
diffs without a working-tree checkout, attach evidence and queue integration. Accepted changesets
materialize deterministically into standard Git objects; GitHub pull requests are only a human
projection; canonical promotion needs a verified Radicle delegate quorum. One Rust Cargo workspace
under `crates/`: `synapse-core`, `-store`, `-auth`, `-api`, `-git`, `-radicle`, `-bench`,
`-crumb`, `-coord`, `-evidence`, `-wire`. The library crates read no configuration files.

## What to review, in priority order

1. `crates/synapse-auth`: `did:key` Ed25519 extraction and signature verification, capability
   grants (`Read`, `Propose`, `Evaluate`, `Review`, `Publish`), expiry, replay nonces, quotas,
   self-review refusal, `PolicyEnforcer::authorize` and `authorize_chain`, the audit log.
2. `crates/synapse-radicle`: delegate threshold verification over `refs/rad/id` and
   `refs/namespaces/<nid>/refs/rad/sigrefs`; split-brain refusal.
3. `crates/synapse-wire`: frame decoding (`docs/G1_WIRE_FRAMES.md`), the stream transport (any
   ordered byte stream, including `UnixStream` and `TcpStream`), the shared-memory ring
   (`docs/G3_SHM_RING.md`), connection closing after 64 refusals.
4. `crates/synapse-store`: SWAL v1 parsing and recovery, blob store, compaction and GC, torn write
   handling; malformed corpus tests; the R1 raw block store repair after `CheckpointCorrupt`
   (`src/blockdev/repair.rs`, `docs/R1_RAW_BLOCK_STORE.md`), which writes to the device; the G2
   content-defined chunking and WAL v2 path (`src/chunk.rs`, `src/wal2.rs`, `src/segment.rs`,
   `docs/G2_CONTENT_DEFINED_CHUNKING.md`), which parses committed v2 checkpoints and logs.
5. `crates/synapse-api`: bounds, pagination, cross-repository lookups; the M1 admission secret
   scanner (`src/secret_scan.rs`: hand-written single pass, refuse by default, no allowlist).
   With `crates/synapse-core/src/merge.rs` and both `derivation.rs` files: merge tier T1, which
   combines changes to different parts of one file (`docs/D1_MERGE_TIER_T1.md`).
6. `crates/synapse-git`: loose object writer and reader, `ChangesetId <-> GitOid` map, ref
   namespaces, GitHub pull request projection.
7. `crates/synapse-coord` (Unix datagram socket notifications in `src/board/notify.rs`) and
   `crates/synapse-evidence`.
8. `tests/gates/run.sh`, `scripts/ci/portable.sh`, `.aien/always`, `.aien/unmapped-ok`,
   `.aien/verify.pub`.
9. `.github/workflows/aien-verification.yml`: pull request and push, `contents: read`, advisory;
   nothing on GitHub builds this repository's code (AGENTS.md).

AGENTS.md: a change to `.aien/`, `tests/gates/`, `.github/workflows/` or `.forgejo/` is
`BLOCKED_OPERATOR` and runs only when the operator starts it by hand.

## Trust boundaries

From `docs/THREAT_MODEL.md`:

- Agent clients are untrusted until authenticated by an Ed25519 signature and authorized by an
  unexpired, repository-scoped `AgentCapabilityGrant`.
- Disk files and incoming payloads are treated as possibly corrupted or adversarial; digests and
  WAL chain links are recomputed on ingest and recovery.
- GitHub pull requests are human projections, never proof of canonical promotion.
- Only a `RadicleCanonicalHead` backed by a verified identity document and a threshold of delegate
  signatures marks a lineage canonical.
- CI: the DGX Spark is the test judge, running `tests/gates/run.sh`; GitHub checks are advisory
  (AGENTS.md, `docs/PIPELINE.md`).

## Threat model summary

- Assets: canonical branch authority, changeset and blob integrity, capability grants, the audit
  log.
- Attackers considered (T1 to T6): forged agent identity; cross-repository token or object reuse;
  expired or replayed mutations; memory or disk exhaustion; split-brain canonical spoofing; crash
  or torn write corruption.
- Defended: each threat above with a deterministic `RefusalCode`; fail closed on unknown versions,
  malformed input and conflicting `IdempotencyKey`.
- Not defended: the audit log is in memory, not independently signed or persisted; at 4,096
  entries authorization refuses until an operator export or restart (backpressure, not drain).
- Explicitly out of scope: the security of Git, Radicle and GitHub.

## Build from source at a pin

Rust toolchain (the gates record Rust 1.98.1; there is no `rust-toolchain.toml`), `git`, and `cc`
for the crumb qualification scripts. `Cargo.lock` is committed.

```sh
git clone https://github.com/aien-dev/synapse.git
cd synapse
git checkout 5f9a638d6be5c271748dc740f69159422788ca81
cargo build --locked --workspace
```

## Run every test

```sh
bash scripts/ci/portable.sh workspace
cargo fmt --all --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace
tests/gates/run.sh zero-disk-secrets
tests/gates/run.sh workspace
tests/gates/run.sh crumb-verify
tests/gates/run.sh conformance
```

- `crumb-verify` and `conformance` need a sibling `../aien-architecture`; `crumb-verify` builds
  the crumb tool at `crumb.lock` `12ad0141b41ec67ef5aa51cb4e1815894c1083bb`, `conformance` checks out
  `29780e56c9e6b9111d884e0d4b146737228c19f6`.
- `.aien/always`: `CRUMB-VERIFY`, `SYNAPSE-ZERO-DISK-SECRETS`. Expected line from the secrets
  gate: `Zero plaintext .env files verified.`
- `scripts/run_gate4_qualification.sh` (comparative benchmark) needs a fixture repository and
  writes `evidence/gate4-qualification/`; `SMOKE=1` runs a small check.
- All commands above: NOT_RUN while writing this document.

## Known limitations and NOT_RUN

- No toolchain pin; the recorded Rust version is 1.98.1.
- The audit log is in memory only (above).
- Published performance numbers come from runs on the DGX Spark, not from other machines.
- Fuzzing: `crates/synapse-wire/src/fuzz.rs` exists; whether a fuzzing campaign has been run is
  unknown from the repository.

## Dependencies and provenance

- Crates.io dependencies locked in `Cargo.lock` (57 packages).
- Sibling aien-architecture at the two commits above for the crumb gates.
- Licence: Apache-2.0 (`LICENSE`).

## Evidence

- `evidence/<item>/`, 27 items, treated as immutable; a new run writes new evidence. 17 carry a
  top-level `SHA256SUMS` (for example `gate0-baseline`, `gate4-qualification`,
  `f1-capability-chains`, `j3-crypto-vectors`, `d1-merge-tier-t1`); 10 do not:
  `REPAIR-RECOVERY-L662`, `a1-binary-codec`, `a2-segment-store`, `bench-pmu-diagnostics`,
  `g1-wire-frames`, `g2-content-defined-chunking` (one only under `x6/`), `g3-shm-ring`,
  `j1-codec-corpus`, `r1-raw-block-store`, `swarm-board`.
- Signed Spark bundles: `aien-dev/aien-receipts` at `synapse/<sha>/bundle.json` (workflow path).
  Receipts are append-only and never edited.
