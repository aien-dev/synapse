# Synapse

Synapse is AIEN's high-throughput agent changeset and integration service. It enables concurrent coding, review, verification, and benchmark agents to submit, inspect, validate, and queue source changes without materializing a full Git working-tree checkout for every operation, with Radicle as the cryptographic canonicality boundary. Synapse is source control for AI agents only (ADR 0002). Git is a small machine bridge at the edge: full-history import and export and interop with existing tooling and hosting, through deterministic Git object materialization. Git is not the primary history format.

## Language

### Identities

**ChangesetId**:
The 32-byte domain-separated SHA-256 digest (`"SYNAPSE_CHANGESET_V1\0"`) of a canonical `ChangesetEnvelope`. It identifies one immutable agent proposal and its provenance metadata inside Synapse.
_Avoid_: Git commit SHA, GitOid, WorldId, SemanticId, PR number

**BlobDigest**:
The 32-byte domain-separated SHA-256 digest (`"SYNAPSE_BLOB_V1\0"`) of an immutable file content blob stored in the Synapse content-addressed store.
_Avoid_: Git blob OID, ChangesetId, Verified Crumb digest

**GitOid**:
The 20-byte standard Git SHA-1 object identifier (`blob`, `tree`, or `commit` header plus payload). It identifies an object materialized into or imported from a Git repository through the Git bridge.
_Avoid_: ChangesetId, BlobDigest, RadicleCanonicalHead

**RadicleCanonicalHead**:
A cryptographically verified promotion receipt proving that a target `GitOid` on a repository's default branch is signed by at least `threshold` authorized delegates in `refs/namespaces/<nid>/refs/rad/sigrefs` under a verified `refs/rad/id` identity document.
_Avoid_: WalSeq, GitHubPullRequestProjection, unverified Git ref

**GitHubPullRequestProjection**:
A human-facing projection record linking a `ChangesetId` and its materialized `GitOid` to a GitHub pull request number and bounded review metadata. Merging a GitHub pull request never by itself establishes a `RadicleCanonicalHead`. Legacy edge adapter: kept until agent cutover (Phase 8), then removed (ADR 0002).
_Avoid_: canonical head, Radicle quorum, source of truth

**IdempotencyKey**:
A 32-byte client-supplied deduplication token bound to a changeset submission. Repeating a submission with the same `IdempotencyKey` and identical `ChangesetId` returns the existing committed `WalSeq`; repeating it with a different `ChangesetId` fails closed with `IdempotencyKeyConflict`.
_Avoid_: ChangesetId, WalSeq, random request ID

### Storage and Ordering

**WalSeq**:
A strictly monotonic 64-bit sequence number assigned by the single-writer append-only write-ahead log (WAL). It defines ingest and replay order within one Synapse repository store and serves as the read-your-writes visibility token. It never confers authority to promote a canonical branch.
_Avoid_: canonical commit order, Git commit timestamp, Radicle revision

**ChangesetEnvelope**:
The signed, immutable proposal record submitted by an agent. It binds the repository identifier, base `GitOid`, parent `ChangesetId` dependencies, sorted path mutations, intent summary, structured machine evidence receipts, `IdempotencyKey`, agent `DidKey`, and Ed25519 signature.
_Avoid_: working tree diff, mutable draft, WorldDraft

**VirtualTree**:
An in-memory or indexed directory tree view constructed by applying one or more committed `ChangesetEnvelope` path mutation sets atop a base Git tree without checking out files onto the filesystem.
_Avoid_: Git worktree checkout, working directory

**GarbageRoot**:
A retention anchor that prevents a changeset and its referenced blobs from being collected during checkpoint compaction. Garbage roots are verified `RadicleCanonicalHead` lineages, open `GitHubPullRequestProjection` heads, active evaluation leases, and changesets inside the retention window.
_Avoid_: unpinned speculative changeset, permanent history

### Authorization

**AgentCapabilityGrant**:
An Ed25519-signed authorization token issued by a repository authority that grants a specific agent `DidKey` a bounded set of capabilities (`Read`, `Propose`, `Evaluate`, `Review`, `Publish`) on a single repository until an explicit expiration timestamp, subject to rate and payload size quotas.
_Avoid_: SourceGrant, ambient filesystem permission, unauthenticated agent ID
