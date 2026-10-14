# ADR 0001: Synapse Architecture, Owning Boundary, and Compatibility Invariants

* **Status**: Accepted; superseded in part by [ADR 0002](0002-synapse-first-git-as-bridge.md) (Synapse-first for AI agents, Git as a bridge; section 2.2 items 1 and 2 and the #515 non-goal "Replacing Git")
* **Date**: 2026-10-14
* **Tracking Issue**: [aien-spark/aien-sovereign-core#515](https://github.com/aien-spark/aien-sovereign-core/issues/515)

## 1. Context

AIEN executes concurrent multi-agent builder, reviewer, verifier, and benchmark lanes on the NVIDIA DGX Spark (Grace Blackwell GB10). Empirical inspection of `/home/drakestapleton/workspace` on `spark-b87b` shows 291 worktrees in `hive-worktrees` consuming 27.05 GB (25.19 GiB), 276 additional agent clone directories in the workspace root, and 460 registered Git worktrees across `aien-sovereign-core` (150) and `omega` (310). Each `git worktree add` on `aien-sovereign-core` writes 138.98 MiB to disk and takes 588.511 ms at p50, capping checkout throughput at 1.713 worktrees/sec.

High-frequency agent loops need to create changesets, attach machine test receipts, inspect trees and diffs without cloning or checking out a full working tree, detect path-level conflicts across concurrent lanes, and project accepted changes into Git and Radicle without compromising cryptographic canonicality.

## 2. Decision

### 2.1 Owning Repository and Daemon Boundary

Synapse is implemented in a dedicated sovereign repository (`aien-spark/synapse`) rather than inside `aien-sovereign-core`.

Rationale:
1. `aien-sovereign-core` already hosts 51 crates centered on the inference runtime, scheduler, KV store, and legacy adapters.
2. Existing primitives in `aien-sovereign-core`, `aien-protocols`, and `omega` solve distinct problems (`WorldStore` is an in-memory runtime draft map; `rad-id-sync` only discovers local SSH/Radicle public keys; `aien-provenance` verifies P-256 dataset/model license grants; `omega_vcstore` stores Verified Crumbs keyed by semantic ID).
3. Separating Synapse into non-overlapping workspace crates (`synapse-core`, `synapse-store`, `synapse-auth`, `synapse-api`, `synapse-git`, `synapse-radicle`, `synapse-bench`) allows independent development, verification, and PR review per subsystem.

### 2.2 Non-Negotiable Compatibility Boundaries

1. **Git Remains the Portable Repository History Format**:
   Every accepted Synapse changeset can be deterministically materialized into standard Git `blob`, `tree`, and `commit` objects (`objects/<xx>/<38-hex>`) that pass `git fsck --full` and work with standard `git clone`, `git fetch`, `git log`, and `git diff`.
2. **GitHub Remains the Human-Facing Forge Projection**:
   Synapse projects accepted changesets into GitHub branches (`refs/synapse/changesets/<id>`, `refs/synapse/queue/<lane>`) and bounded pull request metadata (`GitHubPullRequestProjection`). Bulky machine evidence (full logs, benchmark traces, WAL receipts) remains in Synapse and is referenced by digest.
3. **Radicle Remains the Cryptographic Trust and Canonicality Boundary**:
   Fast ingest ordering (`WalSeq`) and GitHub PR merge state are never treated as authority to advance a canonical branch. Canonical promotion produces a `RadicleCanonicalHead` receipt only after verifying the repository's `refs/rad/id` identity document (`xyz.radicle.project`), verifying Ed25519 signatures over `refs/namespaces/<nid>/refs/rad/sigrefs`, confirming that at least `threshold` authorized delegates signed the target `GitOid`, and confirming that the changeset's `base_git_oid` matches the current canonical head.

### 2.3 Distinct Identity Invariant

Synapse enforces separate Rust newtypes for every domain identity so that no identifier can be substituted for another:

| Type | Width / Format | Domain Tag / Authority | Meaning |
| :--- | :--- | :--- | :--- |
| `ChangesetId` | 32-byte SHA-256 | `"SYNAPSE_CHANGESET_V1\0"` | Immutable agent changeset envelope digest in Synapse |
| `BlobDigest` | 32-byte SHA-256 | `"SYNAPSE_BLOB_V1\0"` | Immutable file content digest in the Synapse blob store |
| `GitOid` | 20-byte SHA-1 | Standard Git `"<type> <len>\0"` | Materialized or base Git blob, tree, or commit object ID |
| `RadicleCanonicalHead` | Struct receipt | Verified `refs/rad/id` + `sigrefs` | Cryptographic proof of delegate quorum on canonical branch |
| `GitHubPullRequestProjection` | Struct record | Human forge projection | Mapping from `ChangesetId` and `GitOid` to a GitHub PR |
| `IdempotencyKey` | 32-byte token | Client deduplication scope | Idempotent submission key preventing duplicate ingest |
| `WalSeq` | `u64` monotonic | Single-writer WAL order | Local ingest and replay sequence number (non-authoritative) |

None of these types may be aliased to `WorldId` (`aien-runtime`), `SemanticId` (`omega_vcstore`), or `SourceGrant` (`aien-provenance`).

### 2.4 Crate Ownership Map

* `crates/synapse-core`: Distinct identity types, `ChangesetEnvelope` v1 canonical encoding, path validation, `RefusalCode` taxonomy, and domain invariants.
* `crates/synapse-store`: Single-writer append-only WAL (`SWAL` v1) with CRC32C and SHA-256 hash chaining, configurable `FsyncPolicy`, content-addressed blob store, atomic sequence visibility, checkpoint compaction, garbage collection, and crash/torn-write fault injection.
* `crates/synapse-auth`: Ed25519 agent identity (`did:key:z6Mk...`), capability-scoped grants (`Read`, `Propose`, `Evaluate`, `Review`, `Publish`), expiration and replay guards, rate/size quotas, and hash-chained security audit log.
* `crates/synapse-api`: Bounded paginated API (`submit`, `get`, `diff`, `tree`, `history`, `provenance`, `conflicts`, `status`, `watch`), checkout-free virtual tree overlay, exact path-index invalidation, and durable cursor recovery.
* `crates/synapse-git`: Deterministic Git loose object writer/reader (`blob`, `tree`, `commit`), bidirectional `ChangesetId <-> GitOid` index, ref namespace management (`refs/synapse/*` vs human `refs/heads/*`), and GitHub PR projection builder.
* `crates/synapse-radicle`: Radicle `refs/rad/id` and `refs/namespaces/<nid>/refs/rad/sigrefs` Ed25519 verifier, multi-delegate threshold checker, stale-base refusal, and split-brain state machine.
* `crates/synapse-bench`: Comparative multi-agent benchmark harness and correctness conformance suite against conventional Git worktree workflows.

## 3. Consequences

* Concurrent coding and verification agents can submit changesets, inspect virtual trees and diffs, and detect path conflicts in microseconds without creating 139 MiB Git worktrees on disk.
* Standard Git clients and human reviewers continue to interact with ordinary Git commits and GitHub pull requests without silent force-pushes to human branches.
* Promotion to canonical history fails closed whenever Radicle delegate threshold signatures are missing, mismatched, or based on a stale head.
