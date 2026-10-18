# Synapse

Synapse is source control built for AI agents. Agents propose changes, inspect trees and diffs without checking files out, attach test evidence, and coordinate who is working where. Git stays as a bridge for import, export and existing tools.

An attachment of [Aienix](https://github.com/aien-dev/aienix), the core tree of AIEN. Synapse lives in its own repository and plugs into the core at a boundary.

**Status (2026-10-18): pre-alpha, under active development.** Synapse is a Rust library workspace with tests and qualification evidence. There is no deployed Synapse server yet; the API runs in-process. New steps from [ADR 0003](docs/adr/0003-ai-native-source-control-model.md) land most days (the most recent merges are listed under [pull requests](https://github.com/aien-dev/synapse/pulls?q=is%3Apr+is%3Amerged)). Pull requests are judged on the DGX Spark by AIEN's own pipeline ([docs/PIPELINE.md](docs/PIPELINE.md)).

**Direction (2026-10-14):** Synapse is becoming source control for AI agents first, with Git kept as a small machine bridge ([ADR 0002](docs/adr/0002-synapse-first-git-as-bridge.md), tracked in [synapse#8](https://github.com/aien-dev/synapse/issues/8)). The original tracker is [aien-sovereign-core#515](https://github.com/aien-dev/aien-sovereign-core/issues/515).

## Boundaries Synapse keeps

1. **Git compatibility.** Accepted changes materialize into standard Git `blob`, `tree` and `commit` objects that `git fsck`, `git clone` and `git fetch` accept.
2. **Human review on GitHub.** Pull request projections (`GitHubPullRequestProjection`) publish short summaries and evidence digests. They never upload bulky machine logs or silently force-move a human branch.
3. **Radicle canonical authority.** WAL ingest order (`WalSeq`) and GitHub pull request state never grant authority to advance a canonical branch. Canonical promotion (`RadicleCanonicalHead`) requires verifying `refs/rad/id` and `refs/namespaces/<nid>/refs/rad/sigrefs` against the repository's delegate quorum.

## Workspace crates

| Crate | What it does |
| :--- | :--- |
| [`synapse-core`](crates/synapse-core) | Identity types (`ChangesetId`, `BlobDigest`, `GitOid`, `RadicleCanonicalHead`, `IdempotencyKey`, `WalSeq` and others), the changeset envelope, `did:key` Ed25519 verification, and the `RefusalCode` list |
| [`synapse-store`](crates/synapse-store) | Single-writer append-only WAL with CRC32C and a SHA-256 hash chain, durable group commit, a segment store for blobs (ADR 0003 step A2), checkpoints, garbage collection, and crash fault injection |
| [`synapse-auth`](crates/synapse-auth) | Ed25519 capability grants (`Read`, `Propose`, `Evaluate`, `Review`, `Publish`), attenuated capability chains (step F1), signed state moves, expiry and replay guards, quotas, and a hash-chained audit log |
| [`synapse-api`](crates/synapse-api) | Bounded, paginated read and proposal API, checkout-free tree inspection over shared Merkle trees (step C1), exact path-index invalidation, and durable watch cursors |
| [`synapse-git`](crates/synapse-git) | The Git bridge: native Git objects, packfiles, full-history read and export (step H1, cut 1 of 2), the `ChangesetId <-> GitOid` map, and the GitHub pull request projection |
| [`synapse-radicle`](crates/synapse-radicle) | Radicle `refs/rad/id` and `refs/rad/sigrefs` delegate threshold verifier and split-brain refusal |
| [`synapse-wire`](crates/synapse-wire) | Binary wire frames with a fuzzed decoder, have-want chunk negotiation, and stream transports (step G1) |
| [`synapse-crumb`](crates/synapse-crumb) | Strict, bounded reader for `.crumb` files and the `CrumbContext` digest over Synapse snapshots (ADR 0004) |
| [`synapse-coord`](crates/synapse-coord) | Shared agent coordination (claims, presence, whispers) on the same store as the Crumb tool, so a claim made through either is seen by both ([README](crates/synapse-coord/README.md)) |
| [`synapse-evidence`](crates/synapse-evidence) | Signed evidence receipts bound to a `ChangesetId` and the crumb context the runner saw (ADR 0004) |
| [`synapse-bench`](crates/synapse-bench) | Qualification harness, WAL, Git and Radicle conformance suites, transport measurement, and opt-in CPU counter diagnostics |

## Build and test

```sh
cargo test --locked --workspace
bash scripts/ci/portable.sh workspace     # fmt, clippy -D warnings, tests (the SYNAPSE-WORKSPACE gate)
```

The Spark gates live in [`tests/gates/`](tests/gates). [docs/PIPELINE.md](docs/PIPELINE.md) explains how a pull request is tested and merged.

## Documentation and evidence

* [Domain glossary (`CONTEXT.md`)](CONTEXT.md)
* Decision records: [ADR 0001](docs/adr/0001-synapse-architecture-and-boundaries.md) (architecture and boundaries), [ADR 0002](docs/adr/0002-synapse-first-git-as-bridge.md) (Synapse first, Git as a bridge), [ADR 0003](docs/adr/0003-ai-native-source-control-model.md) (the source control model and its numbered steps), [ADR 0004](docs/adr/0004-crumb-synapse-integration.md) (Crumb and Synapse)
* [Threat model and capability matrix](docs/THREAT_MODEL.md)
* [Changeset schema, WAL format, consistency and garbage collection](docs/SCHEMA_AND_CONSISTENCY.md)
* One document per ADR 0003 step in [`docs/`](docs) (for example [A2 segment store](docs/A2_SEGMENT_STORE.md), [B4 revision states](docs/B4_REVISION_STATES.md), [H1 Git bridge](docs/H1_GIT_BRIDGE.md)), each with its receipts under [`evidence/`](evidence)
* [Gate 0 reality check and baseline](docs/GATE0_REALITY_CHECK_AND_BASELINE.md) with its [receipt](evidence/gate0-baseline/baseline_report.json)
* [Gate 4 qualification report](docs/GATE4_QUALIFICATION.md) with its [evidence](evidence/gate4-qualification/report.json), reproduced with `scripts/run_gate4_qualification.sh`

## License

GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later).
