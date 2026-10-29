# Synapse (agent-native changeset and integration service)

> Synapse is source control for AI agents. Agents submit signed changesets, inspect virtual trees and diffs without a working-tree checkout, attach evidence and queue integration. Accepted changesets materialize deterministically into standard Git objects, GitHub pull requests are only a human projection, and canonical promotion needs a verified Radicle delegate quorum. The repository is one Rust Cargo workspace under `crates/`.

Shared rules: read https://www.aienos.com/agents/RULES.md first. This file adds what is specific to this repository; where the two differ, this file wins here.

## Scope

- Applies to the whole repository.
- Code: the Cargo workspace in `Cargo.toml` with the crates `synapse-core`, `synapse-store`, `synapse-auth`, `synapse-api`, `synapse-git`, `synapse-radicle`, `synapse-bench`, `synapse-crumb`, `synapse-coord`, `synapse-evidence` and `synapse-wire`. The root `.crumb` gives each crate's role.
- Design: `CONTEXT.md` (glossary), `docs/adr/` (decisions 0001 to 0004), and one specification per work item in `docs/` (for example `docs/SCHEMA_AND_CONSISTENCY.md`, `docs/THREAT_MODEL.md`, `docs/G1_WIRE_FRAMES.md`).
- Evidence: `evidence/<item>/` holds recorded qualification runs with `SHA256SUMS`. Treat recorded evidence as immutable; a new run writes new evidence, it does not edit old files.
- Verification: `tests/gates/*.gate` and `tests/gates/run.sh` (the Spark gates), `.aien/` (always-run gates, paths that need only those, and the bundle verification key), `.github/workflows/aien-verification.yml`.

## Installation

```bash
git clone https://github.com/aien-dev/synapse.git
cd synapse
cargo build --locked --workspace
```

You need a Rust toolchain (the gates record Rust 1.98.1), `git`, and a C compiler (`cc`) for the crumb qualification scripts. There is no `rust-toolchain.toml`; use a current stable toolchain.

## Configuration

- The library crates read no configuration files. Behaviour such as the WAL `fsync` policy, quotas and capability grants is set through the crate APIs; see `docs/SCHEMA_AND_CONSISTENCY.md` and `docs/THREAT_MODEL.md`.
- `crumb.lock` pins the aien-architecture commit whose `crumb` tool checks `.crumb`.
- `scripts/ci/portable.sh` writes its logs to `$CI_EVIDENCE_DIR` (default `target/ci-evidence`).
- `scripts/run_gate4_qualification.sh` takes `FIXTURE_REPO`, `FIXTURE_REV`, `OUT_DIR`, `WORK_PARENT`, `REPS`, `TIERS`, `ARMS`, `SEED`, `RADICLE_REPO` and `SMOKE=1`; its header documents each one.
- The interop and Gate 4 scripts honour `CARGO_TARGET_DIR`.

## Usage

```bash
# The SYNAPSE-WORKSPACE gate: fmt check, cargo metadata --locked, clippy -D warnings, all tests
bash scripts/ci/portable.sh workspace

# The same steps one at a time
cargo fmt --all --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace

# The SYNAPSE-ZERO-DISK-SECRETS gate: no plaintext .env* file in the tree
tests/gates/run.sh zero-disk-secrets
```

These gates need a sibling checkout of aien-architecture at `../aien-architecture`:

```bash
# CRUMB-VERIFY: builds the crumb tool at the commit in crumb.lock, then runs `crumb verify .`
tests/gates/run.sh crumb-verify

# SYNAPSE-CONFORMANCE: the combined Crumb-Synapse qualification at the pinned architecture commit
tests/gates/run.sh conformance
```

`scripts/run_gate4_qualification.sh` is the Gate 4 comparative benchmark (Synapse against Git worktree and Git plumbing workflows). It needs a real fixture repository (`FIXTURE_REPO`) and writes `evidence/gate4-qualification/`; `SMOKE=1` runs a tiny end-to-end check of the harness. Published performance numbers come from runs on the DGX Spark, not from a laptop.

## Conventions

- Keep the identity types distinct. `ChangesetId`, `BlobDigest`, `GitOid`, `WalSeq`, `RadicleCanonicalHead` and `GitHubPullRequestProjection` are different things; `CONTEXT.md` lists the terms to use and the ones to avoid.
- `WalSeq` order and GitHub pull request state never confer authority to advance a canonical branch. Only a verified Radicle delegate threshold does (ADR 0001).
- Git is a bridge for import, export and existing tooling, not the primary history format (ADR 0002). Materialized Git objects must stay deterministic and pass `git fsck`.
- Fail closed: an unknown version, a malformed input or a conflicting `IdempotencyKey` is refused with a `RefusalCode`, never accepted with a guess.
- Every crate passes `cargo fmt` and `cargo clippy -D warnings`. Tests live beside the code and under each crate's `tests/`.
- A new work item gets its specification in `docs/` and its evidence in `evidence/<item>/`, and the README or the spec links both.
- Keep `.crumb` exactly what the pinned compiler produces; CI runs `crumb verify .`.

## Safety and approvals

- The DGX Spark is the test judge (`docs/PIPELINE.md`). GitHub checks on pull requests are advisory; nothing on GitHub builds this repository's code.
- A change to `.aien/`, `tests/gates/`, `.github/workflows/` or `.forgejo/` is `BLOCKED_OPERATOR`: it runs only when the operator starts it by hand. Ask before touching those paths, and never relax a gate to make a change pass.
- Do not run benchmark or qualification scripts on the Spark unless the operator has given you a window; the Spark hosts other work.
- No plaintext secrets: `.env*` files are refused by `SYNAPSE-ZERO-DISK-SECRETS` and ignored by `.gitignore`. Never commit keys, tokens or agent signing material.
- Do not edit recorded evidence or rewrite published history. Work on a branch and merge through a pull request; `docs/PIPELINE.md` explains the `ready-to-merge` label.

## Further reading

- `README.md`: architecture overview and the crate table.
- `CONTEXT.md`: the domain glossary.
- `docs/adr/`: architecture decisions 0001 to 0004.
- `docs/PIPELINE.md`: how the Spark gates test and merge a pull request.
- `docs/GATE4_QUALIFICATION.md`: the comparative qualification report.
