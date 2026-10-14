# Gate 0: Reality Check Audit and Reproducible Baseline

Tracking Issue: [aien-spark/aien-sovereign-core#515](https://github.com/aien-spark/aien-sovereign-core/issues/515)

## 1. Source Anchor Audit (`implemented` / `partial` / `proposed`)

Before writing any Synapse runtime code, every source anchor referenced in `aien-sovereign-core#515` was audited directly against the local checkouts on `spark-b87b`:

| Subsystem / Source Anchor | Repository & Path | Status | Verified Behavior and Gap Analysis |
| :--- | :--- | :--- | :--- |
| **Runtime World Store** (`WorldStore`, `WorldManifest`, `WorldDraft`, `EffectIntent::PublishGit`) | `aien-sovereign-core` `crates/aien-runtime/src/world.rs` | `partial` | Implements an in-memory `HashMap<u64, WorldManifest>` and `HashMap<[u8; 32], Vec<u8>>` with SHA-256 `object_root` folding and an `EffectIntent::PublishGit { remote, branch, commit_sha }` enum variant. Not a durable source-control changeset store; has no WAL, no disk persistence, no Git object formatting, and `gc()` only removes manifest entries with explicit comment `// Note: blob-level GC is a future hardening pass`. |
| **Radicle Local Key Sync** (`IdentityAnchor`, `KeyRecord`, `sync_identity_keys`) | `aien-sovereign-core` `crates/rad-id-sync/src/{lib,identity,keys}.rs` | `partial` | Discovers `~/.radicle/keys/radicle.pub` and `~/.ssh/id_ed25519.pub` on the local filesystem and writes `~/.radicle/identity_anchor.json`. Does not parse Radicle identity documents (`refs/rad/id` / `xyz.radicle.project`), does not verify `refs/namespaces/<nid>/refs/rad/sigrefs` Ed25519 signatures, and does not check delegate quorum thresholds. |
| **Provenance Grants** (`SourceGrant`, `GrantPermissions`) | `aien-protocols` `crates/aien-provenance/src/lib.rs` | `implemented` (distinct scope) | Implements P-256 ECDSA (`p256::ecdsa`) signed licensing grants with bitflags (`READ`, `EVALUATE`, `TRAIN`, `DISTILL`, `REDISTRIBUTE`, `COMMERCIAL`) for dataset and model provenance. Does not authenticate Ed25519 coding agents or authorize repository changeset operations. |
| **Verified Crumb Store** (`omega_vcstore`) | `omega` `src/omega_vcstore.h` (ADR 0029) | `implemented` (distinct scope) | Implements a fail-closed content-addressed C store (`OMEGA_VC_FORMAT_VERSION 1`) keyed by domain-separated SHA-256 `omega_semantic_id_t`, recomputing digests on `insert` and `get`, refusing immutable conflicts while accepting identical bytes idempotently, and separating the mutable name index from digest authority. Serves as the structural model for `synapse-store` refusal discipline while keeping `SemanticId` distinct from `ChangesetId`. |
| **Capability & Security Primitives** (`CapabilityDescriptor`, `SecretProvider`, `NetworkPurpose`) | `aien-sovereign-core` `crates/aien-capability`, `crates/aien-security` | `partial` | Defines runtime capability metadata and secret resolution contracts (`Tpm2SecretProvider`), plus the `unslop` zero-em-dash invariant test. Does not implement per-repository Ed25519 agent changeset capability tokens (`Read`, `Propose`, `Evaluate`, `Review`, `Publish`), rate/size quotas, or a hash-chained changeset security audit log. |
| **Multi-Agent Hive Worktrees** (`spark-hive`, `hive-worktrees`, `hive-ledger.md`) | `aien-sovereign-core` `crates/spark-hive` & `/home/drakestapleton/workspace/hive-worktrees` | `partial` | Coordinates multi-agent lanes using full Git worktree checkouts on disk. Currently leaves 291 worktrees (27.05 GB) in `hive-worktrees` and 460 registered worktrees across `aien-sovereign-core` and `omega`. |
| **Synapse Changeset Engine, API, Auth, Git Materializer, and Radicle Canonical Verifier** | `aien-spark/synapse` `crates/synapse-*` | `proposed` (implemented in Gates 1-4) | Dedicated changeset service providing single-writer WAL + blob store (`synapse-store`), Ed25519 capability auth (`synapse-auth`), checkout-free virtual tree and diff API (`synapse-api`), deterministic Git object materialization (`synapse-git`), Radicle delegate threshold verification (`synapse-radicle`), and comparative benchmark harness (`synapse-bench`). |

## 2. Reproducible Pre-Synapse Baseline from Actual AIEN Traces

The baseline measurement script [`scripts/measure_gate0_baseline.sh`](../scripts/measure_gate0_baseline.sh) was executed on `spark-b87b` (NVIDIA DGX Spark GB10, 20-core ARM Cortex-X925 + Cortex-A725, Linux `7.0.0-1019-nvidia`, `git version 2.43.0`). Raw output is sealed in [`evidence/gate0-baseline/baseline_report.json`](../evidence/gate0-baseline/baseline_report.json) and [`evidence/gate0-baseline/SHA256SUMS`](../evidence/gate0-baseline/SHA256SUMS).

### 2.1 Multi-Agent Workspace Footprint and Conflict Incidence

| Metric | Measured Value | Source |
| :--- | :--- | :--- |
| Retained worktrees in `/home/drakestapleton/workspace/hive-worktrees` | `291` directories | `scripts/measure_gate0_baseline.sh` |
| Disk usage of `/home/drakestapleton/workspace/hive-worktrees` | `27,050,585,731` bytes (`25.19 GiB`) | `du -sb /home/drakestapleton/workspace/hive-worktrees` |
| Additional agent clone directories in `/home/drakestapleton/workspace` | `276` directories | `omega-*`, `sc-*`, `interplane-*`, `physics-*`, `aienos-*` |
| Registered Git worktrees in `aien-sovereign-core` | `150` worktrees | `git -C aien-sovereign-core worktree list` |
| Registered Git worktrees in `omega` | `310` worktrees | `git -C omega worktree list` |
| Total tracked lanes / rows in `hive-ledger.md` | `559` (`41` merged, `499` retired, `6` active) | `/home/drakestapleton/workspace/hive-ledger.md` |
| Explicit conflict / rebase / stale-base mentions in `hive-ledger.md` | `18` occurrences | `/home/drakestapleton/workspace/hive-ledger.md` |

### 2.2 Conventional Git Operation Latencies on `aien-sovereign-core` (`1b6e340d48`)

| Operation | p50 Latency (ms) | p95 / Max Latency (ms) | Mean Latency (ms) | Disk / Throughput Notes |
| :--- | :--- | :--- | :--- | :--- |
| `git worktree add --detach` (full checkout) | `588.511` | `593.010` | `583.872` | Writes `145,732,071` bytes (`138.98 MiB`) per checkout; max sequential throughput `1.713` worktrees/sec |
| `git diff --stat <parent> <head>` | `21.584` | `22.279` | `19.852` | Full tree comparison on `aien-sovereign-core` |
| `git ls-tree -r <head>` | `6.515` | `6.975` | `5.561` | Recursive tree enumeration |
| `git log -n 50 --oneline <head>` | `2.884` | `4.118` | `3.258` | Commit history walk |
| `git merge-tree --write-tree <parent> <head>` | `3.151` | `3.333` | `3.019` | Pairwise merge-tree check |

### 2.3 Reproduction Command

```bash
./scripts/measure_gate0_baseline.sh evidence/gate0-baseline
sha256sum -c evidence/gate0-baseline/SHA256SUMS
```
