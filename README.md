# Synapse

Synapse is AIEN's high-throughput, agent-native changeset and integration service with deterministic Git object materialization and Radicle canonicality verification ([aien-spark/aien-sovereign-core#515](https://github.com/aien-spark/aien-sovereign-core/issues/515)).

**Direction (2026-10-14):** Synapse is becoming the new Git for AI: source control for AI agents only, built from the best ideas of every system, with Git kept as a small machine bridge for import, export, and existing tooling ([ADR 0002](docs/adr/0002-synapse-first-git-as-bridge.md), tracked in [aien-spark/synapse#8](https://github.com/aien-spark/synapse/issues/8)).

## Architecture Overview

Synapse accelerates the high-frequency multi-agent inner loop (changeset creation, virtual tree/diff inspection without working-tree checkout, test evidence attachment, conflict detection, and integration queueing) while enforcing three non-negotiable boundaries:

1. **Git Compatibility**: Accepted changesets deterministically materialize into standard Git `blob`, `tree`, and `commit` objects compatible with `git fsck`, `git clone`, and `git fetch`.
2. **GitHub Human Projection**: Human review projections (`GitHubPullRequestProjection`) publish compact summaries and evidence digests without uploading bulky machine logs or silently force-moving human branches.
3. **Radicle Canonical Authority**: Fast WAL ingest order (`WalSeq`) and GitHub PR state never confer authority to advance canonical branches. Canonical promotion (`RadicleCanonicalHead`) requires cryptographic verification of `refs/rad/id` and `refs/namespaces/<nid>/refs/rad/sigrefs` against the repository's delegate quorum threshold.

## Workspace Crates

| Crate | Gate | Responsibility |
| :--- | :--- | :--- |
| [`synapse-core`](crates/synapse-core) | Gate 0 | Distinct identity types (`ChangesetId`, `BlobDigest`, `GitOid`, `RadicleCanonicalHead`, `GitHubPullRequestProjection`, `IdempotencyKey`, `WalSeq`), `ChangesetEnvelope` v1, `did:key` Ed25519 verification, and `RefusalCode` taxonomy |
| [`synapse-store`](crates/synapse-store) | Gate 1 | Single-writer append-only WAL (`SWAL` v1) with CRC32C and SHA-256 hash chain, configurable `fsync` policy, content-addressed blob store, checkpoint compaction, GC, and crash fault injection |
| [`synapse-auth`](crates/synapse-auth) | Gate 2 | Ed25519 capability grants (`Read`, `Propose`, `Evaluate`, `Review`, `Publish`), expiry/replay guards, rate/size quotas, and hash-chained security audit log |
| [`synapse-api`](crates/synapse-api) | Gate 2 | Bounded paginated API (`submit`, `get`, `diff`, `tree`, `history`, `provenance`, `conflicts`, `status`, `watch`), checkout-free virtual tree overlay, and exact path-index invalidation |
| [`synapse-git`](crates/synapse-git) | Gate 3 | Deterministic Git loose object writer/reader, bidirectional `ChangesetId <-> GitOid` map, ref namespace separation, and GitHub PR projection builder |
| [`synapse-radicle`](crates/synapse-radicle) | Gate 3 | Radicle `refs/rad/id` and `refs/rad/sigrefs` Ed25519 delegate threshold verifier and split-brain refusal engine |
| [`synapse-bench`](crates/synapse-bench) | Gate 4 | Comparative qualification harness (Synapse ingest and checkout-free queries versus Git worktree and Git plumbing workflows) plus WAL, Git materialization, and Radicle canonicality conformance suites |

## Documentation and Evidence

* [Domain Glossary (`CONTEXT.md`)](CONTEXT.md)
* [ADR 0001: Synapse Architecture, Owning Boundary, and Compatibility Invariants](docs/adr/0001-synapse-architecture-and-boundaries.md)
* [ADR 0002: Synapse-First Source Control for AI Agents, with Git as a Bridge](docs/adr/0002-synapse-first-git-as-bridge.md)
* [Gate 0 Reality Check Audit and Reproducible Baseline](docs/GATE0_REALITY_CHECK_AND_BASELINE.md)
* [Threat Model and Capability Permission Matrix](docs/THREAT_MODEL.md)
* [Changeset Schema, WAL Format, Consistency, and GC Specification](docs/SCHEMA_AND_CONSISTENCY.md)
* [Gate 0 Empirical Baseline Receipt (`evidence/gate0-baseline/`)](evidence/gate0-baseline/baseline_report.json)
* [Gate 4 Comparative Qualification Report](docs/GATE4_QUALIFICATION.md)
* [Gate 4 Qualification Evidence (`evidence/gate4-qualification/`)](evidence/gate4-qualification/report.json), reproduced with `scripts/run_gate4_qualification.sh`
* [Spark verification gates (`docs/PIPELINE.md`)](docs/PIPELINE.md): the interop and Gate 4 scripts honour `CARGO_TARGET_DIR`, so `SYNAPSE-CONFORMANCE` runs the same on the Spark as in a plain checkout

## License

Licensed under the Apache License, Version 2.0 (Apache-2.0).

## Human-Directed Agentic Engineering

Development follows Human-Directed Agentic Engineering (HDAE): humans define goals, architecture,
constraints, acceptance criteria, and stopping points; agents implement, execute checks, diagnose
failures, and revise within those boundaries. Human review retains responsibility for claims,
acceptance, and release decisions. This development method is distinct from Synapse's agent-native
runtime interfaces and does not change its canonical promotion rules.

For the documented method and a systems-software case study, see Gregory M. Kurtzer,
[*Ginux: Building an Independent Kernel That Runs Linux Userspace through Human-Directed Agentic
Engineering* (2026)](https://doi.org/10.5281/zenodo.23682548).
