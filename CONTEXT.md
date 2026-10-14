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

### AI-Native Model (ADR 0003, proposed)

**ChangeId**:
A 16-byte random identifier that names one unit of intended work across all its rewrites, rebases, and retries. It is bound to its creating chain: only keys whose chain descends from it, or whose grant names it in change scope, may add revisions, and pruning needs the creating chain or one that dominates it. Each rewrite is a new `ChangesetId` with the same `ChangeId`.
_Avoid_: ChangesetId, branch name, task title

**TreeDigest**:
The domain-separated digest of a whole repository state, encoded as a native Merkle tree of directories. Evidence receipts bind to it. Git tree OIDs are computed from it only at the Git bridge.
_Avoid_: Git tree OID, ChangesetId, working directory

**ChunkDigest**:
The digest of one content-defined chunk of a large blob. A storage and transfer unit only; a blob's identity stays its `BlobDigest` over the whole content.
_Avoid_: BlobDigest, Git delta

**AdmissionWitness**:
The immutable record of a revision's first admission: `repo_id`, the submitting agent's DID and signature (or, for a server-derived revision, the server's machine-key signature and its `DerivationAttestation` digest), the `IdempotencyKey`, the admission `WalSeq`, and the server's admission time. Idempotency is keyed on repository, DID, and key; replay order is the `WalSeq`; retention follows per-owner rules and the server's clock, never a client clock.
_Avoid_: ChangesetId (content only), AuthorshipAttestation, created_at_ms

**AuthorshipAttestation**:
A signed statement that an agent produced a given revision at a given time. Under envelope v2 the `ChangesetId` covers content only, so identical content submitted by two agents under the same `ChangeId` is one revision with two attestations.
_Avoid_: commit author, signature inside the content digest

**IntentRecord**:
The machine-structured purpose of a revision: a closed `kind`, a typed task reference, a list of claims, a footprint, superseded revisions, and an optional digest of a machine-readable rationale. It replaces the prose `intent_summary`.
_Avoid_: commit message, PR description

**Claim**:
A machine-checkable assertion in an `IntentRecord` (for example "action A passes on the resulting tree" or "behaviour unchanged") that must be discharged by a passing `EvidenceReceipt` before promotion.
_Avoid_: description, checklist item

**Footprint**:
The declared set of paths (later, symbols) a change intends to touch. Every actual mutation must lie inside it. Used for predictive conflict queries and subscriptions, and charged against the declarer's footprint quota by breadth.
_Avoid_: diff, touched files after the fact

**ObsolescenceMarker**:
A signed record that one revision was replaced by zero (pruned), one (rewritten), or several (split) successors. Pruning needs the change's creating chain or one that dominates it. Dependent `Private` and `Draft` revisions without receipts are rebased onto successors lazily, when they are next used.
_Avoid_: reflog entry, deleted changeset

**RevisionState**:
Where a revision stands: `Private` (visible only to its owner's delegation chain) or `Draft` (visible within `Read` scope), then `Proposed`, `Verified` (every claim and required action discharged on its exact tree), and `Canonical` (promoted by quorum, immutable). States never move backwards.
_Avoid_: branch, phase, PR status

**ConflictTerm**:
A tree entry that records an unresolved merge as data: a sorted multiset of add terms and a sorted multiset of remove terms, with one more add than remove. Each term is a full entry state (absent, or a file, directory, or symlink with its mode and content digest). Identical add and remove terms cancel. Trees containing any conflict term cannot be materialized for a build or promoted.
_Avoid_: conflict markers in file text, failed merge

**MergeTier**:
The level at which two revisions were merged: T0 path, T1 region, T2 syntax tree, or T3 first-class conflict. Recorded in the merged revision.
_Avoid_: merge strategy name

**Operation**:
One admitted mutation of repository state (revision created, marker recorded, reference moved, receipt attached, capability granted or revoked), carried by one WAL frame and recording the actor, the capability chain, and the view digest before and after. Undo is a new operation that restores an earlier view.
_Avoid_: WalSeq (the ordering number), audit entry (refusals), commit

**View**:
The complete set of references (canonical head, workspace pointers, visible heads per change) after an operation, identified by a Merkle digest.
_Avoid_: branch list, checkout

**Workspace**:
A server-side pointer to a base plus an overlay of changed paths, owned by a capability. Forking copies the pointer, not the content; every write is a draft revision.
_Avoid_: Git worktree, clone, working directory

**ActionDigest**:
The digest of one exact evaluation: input root, toolchain digest, command digest, environment digest, and platform. The input root is a Merkle root over sorted (`repo_id`, `TreeDigest`) pairs, so one action can cover trees from several repositories.
_Avoid_: test name, CI job ID

**EvidenceReceipt**:
A signed record of one action's result that applies only to the exact input root in its `ActionDigest`. Its deterministic part (exit status plus declared output digests) is its identity, the result digest; its observation part (logs, seconds, joules when measured) is stored but never part of that identity. It also records the hermetic flag and the executor machine key. Only receipts from registered executors (machine keys listed in the identity document, running a sandbox the requesting agent does not control) count toward promotion.
_Avoid_: EvidenceAttachment (v1, unbound), PASS label, CI badge

**ActionCache**:
The map from `ActionDigest` to stored results that returns a result for an identical hermetic action from a registered executor instead of running it again. Receipts are compared by result digest only (exit status plus declared outputs), so differing logs agree; differing result digests make the entry `Flaky`. A receipt is served only while its inputs and outputs are retained.
_Avoid_: test result reuse across different trees

**PromotionQueue**:
The service that advances the canonical head by compare-and-swap only to a tree that passed every required action and discharged every claim on that exact tree and carries the delegate threshold of signatures over the `ChangesetId`, `TreeDigest`, admission witness digest, and receipt-set root; candidates are batched and failed batches bisected.
_Avoid_: GitHub merge button, WalSeq order

**MachineDelegate**:
A delegate in the repository identity document that is a machine or agent key, for example one that signs only after independently re-executing the required actions and getting matching output digests.
_Avoid_: human maintainer, reviewer

**CapabilityChain**:
A sequence of grants from the repository authority to an agent in which each link may only narrow operations (`Read`, `Propose`, `Evaluate`, `Review`, `Publish`, `Undo`), paths, references, change scope, quotas (request rate, storage, and footprint), and expiry. Each link signs its parent's digest, the `repo_id`, the audience, and its caveats; child quotas never sum above the parent's. The server accepts a chain only if every link is unexpired and unrevoked at the request's `WalSeq`.
_Avoid_: shared token, bearer secret

**ChangeGroup**:
A record naming one revision per repository for changes that must land together across repositories (for example a pinned dependency and its consumer). The group is tested as one action over a composite input root and promotes by one compare-and-swap on the group manifest, so every member lands or none does.
_Avoid_: distributed transaction, submodule bump

**PhysicalBound**:
The least time or energy the hardware allows for a given piece of work, derived from device flush time and bandwidth, memory bandwidth, and all-core throughput, with every source stated; never from one implementation's single-core rate. Where the hardware gives no closed-form limit, the best measured all-core implementation is used and labelled as a reference, replaced whenever beaten, so the fraction achieved stays at most 1. Performance results are reported in seconds, joules, and watts with the fraction of this bound achieved.
_Avoid_: target, speedup, operations per second headline

**Segment**:
An append-only storage file holding WAL records and content chunks together, so one batch is one sequential write plus one flush.
_Avoid_: blob file, loose object, packfile

**Turing (T)**:
One bit of net held-out description-length saving against a declared baseline, after charging the model's own size. ADR 0003 section 7 proposes it, at Level 0 (definition only: never computed on Synapse data, not independently replicated, energy instrument uncalibrated), for scoring how well Synapse's change representation predicts code history. It is not a performance measure.
_Avoid_: tesla (also symbol T), throughput, compression ratio

**DerivationAttestation**:
A record signed by the server's registered machine key for a revision the server produced (a lazy rebase, a promotion-queue merge, or a derived-file output). It names the input revisions or trees, the deterministic rule applied, and the output digests, so any replica can recompute and check it.
_Avoid_: agent signature on server output, unsigned merge

**Flaky**:
The typed action-cache result for an `ActionDigest` whose registered receipts disagree in their deterministic part (exit status or declared outputs). It lists each distinct result and executor, is served as `Flaky`, and never discharges a claim or counts toward promotion.
_Avoid_: pass, fail, non-deterministic error

**GroupManifest**:
One record mapping each linked repository's `repo_id` to its canonical `TreeDigest`. A `ChangeGroup` promotes by one compare-and-swap on it, so linked repositories move together or not at all.
_Avoid_: compensating revert, distributed lock

**OwnerRetention**:
The v2 garbage-collection rule: an owner's revisions, operations, and views are kept while its grant or a lease it holds is live and for a server-clock window after, within a storage quota partitioned down its delegation chain. One owner's write volume never shortens another owner's retention.
_Avoid_: retention counted in WalSeq, client created_at_ms

**CryptographicErasure**:
The only exception to never-lose-work: under the delegate threshold, the data key of a leaked secret is destroyed so every stored copy becomes unreadable; index, cache, and trace references are removed, the digest stays, and the erasure record is permanent.
_Avoid_: history rewrite, force push, delete
