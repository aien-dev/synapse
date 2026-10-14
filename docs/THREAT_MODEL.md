# Synapse Threat Model and Capability Enforcement Contract

Tracking Issue: [aien-spark/aien-sovereign-core#515](https://github.com/aien-spark/aien-sovereign-core/issues/515)

## 1. Trust Boundaries

1. **Agent Client Boundary**:
   Autonomous builder, reviewer, verifier, and benchmark agents are untrusted callers until authenticated by an Ed25519 signature over the canonical request/changeset payload and authorized by an unexpired, repository-scoped `AgentCapabilityGrant`.
2. **Storage Engine Boundary (`synapse-store`)**:
   The single-writer WAL and content-addressed blob store treat disk files and incoming payloads as potentially corrupted or adversarial. Every blob digest and WAL frame CRC32C + SHA-256 chain link is recomputed and verified on ingest and recovery.
3. **Human Forge Projection Boundary (`synapse-git` / GitHub)**:
   GitHub pull requests and review comments are human-facing projections. A merged GitHub pull request or remote branch update is never trusted as proof of canonical promotion unless accompanied by verified Radicle delegate threshold signatures.
4. **Canonical Authority Boundary (`synapse-radicle`)**:
   Only a `RadicleCanonicalHead` receipt backed by a verified `refs/rad/id` identity document (`xyz.radicle.project`) and at least `threshold` valid Ed25519 signatures over `refs/namespaces/<nid>/refs/rad/sigrefs` for the target `GitOid` can mark a lineage as canonical.

## 2. Capability Permission Matrix

Each `AgentCapabilityGrant` is signed by a repository authority Ed25519 key and binds `(repo_id, agent_did, capabilities, max_bytes_per_op, max_ops_per_window, issued_at_ms, expires_at_ms, grant_nonce)`.

| Operation | Required Capability | Additional Invariants Checked | Refusal Code on Violation |
| :--- | :--- | :--- | :--- |
| `get`, `tree`, `diff`, `history`, `provenance`, `conflicts`, `status`, `watch` | `Read` | `grant.repo_id == request.repo_id`, `now_ms <= grant.expires_at_ms`, `page_size <= max_page_size` | `AuthCapabilityDenied`, `AuthCrossRepoDenied`, `AuthGrantExpired`, `PaginationLimitExceeded` |
| `submit` (propose changeset) | `Propose` | Valid agent Ed25519 signature over `ChangesetEnvelope`, payload within `max_bytes_per_op`, rate quota available, base tree known | `AuthSignatureInvalid`, `AuthCapabilityDenied`, `QuotaPayloadTooLarge`, `QuotaRateLimitExceeded` |
| `attach_evaluation` (test/benchmark receipt) | `Evaluate` | Target `ChangesetId` exists in `repo_id`, signed evaluation receipt digest valid, single-use request nonce not replayed | `AuthCapabilityDenied`, `AuthReplayDetected`, `ChangesetNotFound` |
| `record_review` (review verdict) | `Review` | Reviewer `agent_did != changeset.author_did` (no self-approval), valid signature, non-replayed nonce | `AuthCapabilityDenied`, `AuthSelfReviewRefused`, `AuthReplayDetected` |
| `project_git` / `promote_canonical` | `Publish` | For canonical promotion: verified `RadicleCanonicalHead` (`refs/rad/id` + `sigrefs` quorum >= `threshold`) and `base_git_oid == current_canonical_head` | `AuthCapabilityDenied`, `RadicleQuorumInsufficient`, `RadicleSignatureInvalid`, `StaleBaseHead`, `SplitBrainDivergence` |

## 3. Adversarial Threat Catalog and Mitigations

| Threat ID | Adversarial Scenario | Mitigation and Deterministic Refusal |
| :--- | :--- | :--- |
| **T1: Forged Agent Identity** | Attacker submits a changeset claiming `author_did = did:key:z6Mk...` with a forged or mismatched Ed25519 signature. | `synapse-auth` extracts the 32-byte Ed25519 public key directly from `did:key:z6Mk...` (multicodec `0xed01`) and verifies the 64-byte signature over the domain-separated canonical envelope before any store admission. Refuses with `AuthSignatureInvalid`. |
| **T2: Cross-Repository Token Reuse** | Agent holding a valid `Propose` grant for repository `repo-A` attempts to read or submit a changeset to `repo-B`. | Every grant and request is domain-bound to `RepoId`. Mismatched `repo_id` fails closed with `AuthCrossRepoDenied`. |
| **T3: Expired or Replayed Mutation** | Attacker replays a captured mutation token or uses an expired `AgentCapabilityGrant`. | Grants enforce `now_ms <= expires_at_ms` (`AuthGrantExpired`). Mutation requests carry a monotonic or unique `request_nonce` tracked per `(repo_id, agent_did)` window; duplicates fail closed with `AuthReplayDetected`. |
| **T4: Unbounded Memory / Disk Exhaustion** | Flood of large blobs, deep directory trees, or uncollected speculative changesets. | Enforces `max_blob_bytes`, `max_paths_per_changeset`, `max_pending_ops`, `max_pending_bytes`, and `max_page_size` prior to allocation (`QuotaPayloadTooLarge`, `BackpressureOverCapacity`), plus TTL/root-based garbage collection during compaction. |
| **T5: Split-Brain CanonicalSpoofing** | GitHub PR is merged or fast ingest `WalSeq` advances, and an agent attempts to mark the changeset canonical without Radicle delegate quorum. | `synapse-radicle` refuses canonical promotion unless `refs/rad/id` and `refs/namespaces/<nid>/refs/rad/sigrefs` verify at least `threshold` distinct delegate signatures on the target `GitOid` (`RadicleQuorumInsufficient`, `SplitBrainDivergence`). |
| **T6: Crash or Torn Write Corruption** | Process dies mid-blob write or mid-WAL frame append. | Blobs are written and synced before the WAL frame is appended. Recovery verifies `SWAL` header magic, sequence continuity, CRC32C, and `prev_frame_sha256` hash chain; uncommitted blobs remain unindexed and torn tail frames are refused/quarantined without phantom visibility. |

## 4. Tamper-Evident Security Audit Log

Every authentication, authorization, submission, evaluation, review, projection, and promotion decision (both `Admitted` and `Refused`) appends a signed/hash-chained `AuditEntry` containing:
* `audit_seq: u64`
* `timestamp_ms: u64`
* `repo_id: RepoId`
* `actor_did: String`
* `operation: String`
* `outcome: AuditOutcome` (`Admitted { wal_seq }` or `Refused { code }`)
* `prev_entry_sha256: [u8; 32]`
* `entry_sha256: [u8; 32]`

Any tampering with historical audit entries breaks the `prev_entry_sha256` chain and is detected by `AuditLog::verify_chain()`.
