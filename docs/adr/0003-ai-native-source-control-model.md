# ADR 0003: The AI-Native Source Control Model

* **Status**: Proposed (for the owner's acceptance)
* **Date**: 2026-10-14
* **Builds on**: [ADR 0002](0002-synapse-first-git-as-bridge.md) (Synapse-first, Git as a bridge, section 2.6 performance rule) and [ADR 0001](0001-synapse-architecture-and-boundaries.md)
* **Tracking Issue**: [aien-spark/synapse#8](https://github.com/aien-spark/synapse/issues/8) (Phase 7: AI-native model)
* **Evidence used**: [Gate 0 baseline](../GATE0_REALITY_CHECK_AND_BASELINE.md), [Gate 4 qualification](../GATE4_QUALIFICATION.md), the hive ledger (`~/workspace/hive-ledger.md`, 2026-10-14T15:31:22Z), host probes recorded in section 6.2, and the sources in section 12.
* **Numbers**: values with a `calc:` id are derived and carry an aien-calc receipt; values without one are copied measurements from the cited Gate 0 and Gate 4 reports, the ledger, or the host probes in section 6.2 (CALC-EXEMPT: copied measurements, not derived).

## 1. Context

ADR 0002 made Synapse the primary source control system for AI agents, with Git as a small machine bridge, and fixed the performance rule (section 2.6). It left the native model to this ADR. The owner's direction, verbatim (Drake, 2026-10-14):

> "I want Synapse to be the new Git for AI."
> "Don't just copy features because we feel like we need them. I want you to take the good parts of everything and make the best system possible."
> "This is going to be for AI only. AI is going to be the only one writing code in the future and this is not going to be for humans. Nothing human-related needs to be in this."
> "Eventually Synapse will take over Git from our actual hardware."
> "Be inventive... Build your own."
> "When you're doing things to improve speed, I don't want '5 times faster' or '32 agents'. The ultimate goal is to be as close to physically possible in speed and throughput. If there's something between speed and the hard metal, it needs to get rewritten or reworked to make it faster. We need to push this to the limit."
> "I want our things to be measured in physical scientific units that can be measured and verified in a scientifically verifiable open way. I do not want people to be hiding behind these fake units, like tokens or even bytes."
> "Omega needs to be the final layer that is just talking to the metal, the machine itself."
> "Fuck the targets. Chase the boundaries of physical limitation."

This ADR derives what AI agents need from evidence (section 3), judges the best ideas from other systems against those needs (section 4), and defines the native model (section 5), the performance method (section 6), a Turing-unit proposal (section 7), the crate map (section 8), and the implementation sequence (section 9).

## 2. Principles

* **P1. AI only.** Every reader and writer is an agent or a machine. Nothing exists for a human to read: no prose messages, no review pages, no display formats, no human branch names.
* **P2. Need first.** Every element in section 5 names the need it serves (N1 to N14, section 3). An idea from another system is adopted only for a named need. Copying a feature without a need is not allowed.
* **P3. The physical bound is the only goal (first-class).** Performance is stated in SI units only: seconds per accepted change (with the latency distribution), joules per accepted change, and watts. Each result is reported next to a physical bound for the same work, with the bound's derivation and the source of every input, and as the fraction of that bound achieved (bound divided by measured, at most 1). There are no targets, no multipliers, no operations-per-second headlines, no token counts, and no byte counts as performance measures; amounts of data are supporting facts only. Every layer between an agent and the metal (process spawns, text and JSON formats, per-file filesystem objects, kernel copies, locks, allocations, the filesystem itself) must justify its measured cost in seconds and joules or be removed. Measurements are open and reproducible: the instrument, its resolution, the sampling method, the host load, the commands, and the raw samples are published with checksums. This extends ADR 0002 section 2.6; section 6 makes it operational.
* **P4. Evidence over assertion.** A claim about a change (it builds, it passes, it is equivalent) counts only as a signed receipt bound to the exact content it was measured on. Fail closed everywhere (unchanged from ADR 0001).
* **P5. Language-neutral formats; Omega is the destination.** Rust is scaffolding and Omega is the destination (aien-architecture ADR 0024, as recorded in the mind map note `no-rust-atlas-lineage-conflict`). Every persisted and wire format is a fixed-width, little-endian, length-prefixed binary specification with no Rust-specific serialization, so that an Omega implementation on AIENOS can read the same bytes. The Rust crates are the current implementation and the specification-by-test for that port.
* **P6. Never lose work.** Nothing an agent produced is destroyed by another agent's action. Rewrites, undo, and discard are recorded, and only garbage collection under explicit retention rules frees space.

## 3. What AI Agents Actually Need

Each need is derived from measured or recorded behaviour, not from another system's feature list.

| Id | Need | Evidence |
| :--- | :--- | :--- |
| N1 | Cheap speculative attempts; most are thrown away; attempts at the same task must stay linked | Hive ledger snapshot 2026-10-14T15:31:22Z, rows counted with `awk` over the table: 563 lanes, 41 merged (7.282 %, calc:077749de), 501 retired (88.99 %, calc:d50a715e); Gate 0's earlier snapshot recorded 559, 41, and 499; 73 lane names match a rough retry-suffix pattern (for example `STALEGEN-RD-V1` to `-V5`) |
| N2 | Read without a checkout | 293 worktrees using 28 GiB (`du -sh`) on 2026-10-14, against 291 and 25.19 GiB at Gate 0; `git worktree add` p50 588.511 ms and 138.98 MiB each; Gate 4 G1 (fresh worktree per proposal) p50 1,061.46 ms and about 146 MB per proposal |
| N3 | A filesystem view only when building or testing | Gate 4 section 9: agents that build or test still need a checkout; ADR 0002 cutover gate 5 |
| N4 | Proof by evidence bound to exact content | Handoff 2026-10-14: test receipts reused across commits produced a stale PASS risk (aien-sovereign-core#516, fixed by dropping cross-commit reuse; the same risk remains in direct `aien-test` runs on main) |
| N5 | Frequent conflicts and rebases, resolved without stopping work | Gate 0: 18 conflict, rebase, or stale-base mentions in the ledger; 5 lanes exist only to rebase (for example `I11-REBASE`, `E1-REBASE`); Gate 4 section 5: path-level detection over-flags 3 of 253 pairs that Git merges cleanly |
| N6 | Undo of mistakes, by the agent or by a supervisor, without losing anything | Ledger: 501 lanes closed with "worker gone, row closed by hand" (the work's fate is not recorded in source control); LD replay finding: speculative work on a stale belief is discarded and rerun |
| N7 | Least privilege for untrusted agents, delegable to sub-agents | Threat model T1 to T6; the hive runs orchestrators that hand work to workers, which hand work to sub-workers |
| N8 | Machine-structured intent; no human reading | Owner direction (P1); ADR 0002 section 2.1 |
| N9 | Speed at the physical limit, in SI units | Owner direction (P3); Gate 4 section 3.1: durable Synapse writes (S1) ran at 72.5 accepted changes per second at 1 agent, an interval of 13.8 ms between acknowledgements (calc:80d09f2c), with p50 latency 11.8 ms, flat from 1 to 32 agents; CPU per change 0.88 ms at 1 agent (section 3.3) |
| N10 | Promotion trusted by machines, with machines as delegates | ADR 0001 section 2.2 item 3; ADR 0002 section 2.5 |
| N11 | Awareness of what other agents are touching now | Ledger retry and rebase lanes; Gate 4: the path-level conflict query across all open proposals costs 0.219 ms p50 and is the only coordination signal today |
| N12 | Determinism: the same work gives the same result regardless of agent count or arrival order | LD replay finding (2026-10-01): "history differs by worker count" |
| N13 | Changes that span repositories and must land together | Omega builds against the `physics` repository at the commit pinned in `physics.lock` (omega README); agents work in both `aien-sovereign-core` and `omega` (Gate 0: 150 and 310 registered worktrees) |
| N14 | Private speculative work | Untrusted agents (threat model section 1) and discarded attempts (N1) should not be readable by every other agent by default |

## 4. Survey: What to Take, Adapt, or Reject

Verdicts: **Adopt** (take the idea as is), **Adapt** (take the idea, change the mechanism), **Reject** (no AI need, or a cost that breaks P3). Sources are listed in section 12; claims not confirmed from a primary source are marked UNVERIFIED.

| System and idea | Verdict | Need | One-line reason |
| :--- | :--- | :--- | :--- |
| Git: content-addressed Merkle DAG | Adopt | N4, N12 | Integrity, deduplication, and equality checks in one digest comparison [S1] |
| Git: SHA-1 object IDs as native identity | Reject | N4 | SHAttered showed a practical SHA-1 collision and Git itself is moving to SHA-256 [S2]; SHA-1 stays only in the bridge map |
| Git: loose objects (one file per object) | Reject | N9 | Per-file filesystem objects: Gate 4 shows 17,818 allocated against 11,949 apparent bytes per Synapse proposal with file-per-blob, and Git loose objects take at least one 4 KiB block each |
| Git: packfiles with delta chains [S1] | Adapt | N9 | Keep append-only packed storage; replace read-time delta chains with whole chunks (reads should cost one lookup, not a chain walk); deltas only on the bridge wire |
| Git: index, staging area, working-tree checkout | Reject | N2, N8 | Exists for a human editing files in a directory; agents write changes directly |
| Git: commit message, author name, wall-clock time in identity | Reject | N8, N1 | Human text; timestamps in identity stop identical work from deduplicating |
| Git: mutable named branches | Adapt | N10, N7 | Keep named pointers, updated only by atomic compare-and-swap under capability scope |
| Pijul and Darcs: commutation of independent patches [S3, S4] | Adopt | N5, N12 | Independent changes apply in any order with the same result, so outcomes do not depend on arrival order |
| Pijul: line-graph storage with conflicts as graph state [S3] | Adapt | N4, N2 | Keep conflicts as data; store snapshots (tree digests) instead, because evidence must name the exact tree that was tested and reads must not reconstruct a graph |
| Darcs: patch theory as the storage model | Reject | N9 | Pijul documents Darcs' exponential merge problem as the reason it was rebuilt [S4] |
| Jujutsu: stable change ID separate from commit ID [S5] | Adopt | N1, N6 | One task's attempts and rewrites stay one change while each revision keeps a content digest |
| Jujutsu: operation log with undo and restore [S6] | Adopt | N6 | Every repository state change is an operation; undo is a new operation; nothing is lost |
| Jujutsu: conflicts stored in commits as terms that cancel [S7] | Adopt | N5 | Rebase never fails; repeated rebases simplify; resolution can come later from any agent |
| Jujutsu: working copy is always a commit [S5] | Adapt | N6, N1 | An agent's workspace is always a draft revision on the server, so a worker that dies leaves its work as data |
| Mercurial evolve and Sapling: obsolescence markers (predecessor to successors, prune, split, fold) [S8, S9] | Adapt | N1, N5, N6 | Records which revision replaced which, so dependants rebase automatically and retries of one task stay linked. The evolve page was read only through a search summary, so the marker rules are specified here (section 5.1) and proved by PR B1's tests rather than inherited |
| Mercurial phases (public, draft, secret) | Adapt | N10, N14 | Becomes the revision state machine in section 5.3, including a `Private` state from the secret phase |
| Fossil: history as a relational database, queried directly [S10] | Adapt | N2, N11 | Keep "history is queryable data"; reject SQLite as the engine because it is a layer between the agent and the metal (P3) |
| Fossil: autosync of every commit [S10] | Adopt | N11, P6 | Work lives on the server from the first write (as `Private` or `Draft`, section 5.3), so nothing is lost and in-scope agents can see `Draft` work |
| Fossil: no rebase, by design [S10] | Reject | N5 | Agents need automatic rebase of untested drafts; the operation log already keeps what happened. Tested (`Verified`) revisions are never rebased; the promotion queue merges and retests them (section 5.3) |
| Fossil: integrated tickets, wiki, forum [S10] | Reject | N8 | Human collaboration features; agents reference tasks by typed IDs (section 5.2) |
| Radicle: signed refs, identity document, delegate threshold [S11] | Adopt | N10 | Machine-verifiable quorum for canonical promotion; delegates can be machines |
| Radicle: collaborative objects as Git commit graphs [S11] | Reject | N9 | Synapse stores its own records natively; Git encoding only at the bridge |
| Google Piper and CitC: server-side workspaces that overlay only changed files [S12] | Adopt | N1, N2, N3 | A fork is a pointer plus an overlay, so speculative attempts cost almost nothing. Adopted on our own measurements (Gate 0, Gate 4 G1); the Google source is secondary (primary paper not fetched) and no Google figure is relied on |
| Google: trunk-based development, few branches [S12] | Adopt | N5 | One canonical line; everything else is short-lived stacked changes |
| Scion: per-agent container with its own worktree or clone and credentials [S13] | Adapt | N7 | Keep per-agent scoped credentials; reject its workspace model, which uses worktrees or clones, the cost Gate 0 measured. (The brief named it "Anthropic Scion"; the repository is GoogleCloudPlatform/scion and states it is not an officially supported Google product.) |
| Bazel Remote Execution: Action = digest of command plus input root; action cache; FindMissingBlobs [S14] | Adopt | N4, N3, N9 | Evidence keyed by exact input digests; repeated tests on identical inputs reuse results; only missing content is sent |
| Nix: content-addressed outputs, so unchanged outputs stop rebuild propagation [S15] | Adopt | N4, N9 | Evidence that depends on an output stays valid when a change leaves that output's digest unchanged (floating content addressing is experimental in Nix) |
| Unison: definitions identified by syntax-tree hash, names as metadata, cached test results [S16] | Adapt | N4, N5 | Apply to Omega code through Omega's own `SEMANTIC_ID`; reject as a general approach because agents also write Rust, C, and other languages Synapse does not control |
| Structured merge: Spork architecture, GumTree matching, tree-sitter parsing, as in Mergiraf [S17, S18] | Adopt, gated by PR D3 | N5 | Merges edits that touch the same file but different syntax nodes; leaves cautious conflicts otherwise. The GumTree paper was not fetched, so adoption stands only if D3's sealed corpus passes |
| difftastic: structural diff for display [S19] | Reject | N8 | Display tool; agents need edit scripts as data (GumTree actions: insert, delete, update, move) |
| CRDTs for obsolescence markers and authorship attestations (grow-only sets) | Adapt | N12 | Replicas can merge these sets without consensus. Grants, revocations, receipts, and references are not merged this way: they need a total order and replicate through the signed operation log; canonical promotion still needs quorum. Shapiro et al. not fetched (UNVERIFIED wording); Pijul documents itself as a CRDT [S3] |
| CRDTs for file text (character-level co-editing) | Reject | N9, N8 | Per-character identifiers cost storage and time; agents submit whole changes, not keystrokes |
| Content-defined chunking (FastCDC) [S20] | Adapt | N9 | For large blobs only, so an edit stores and sends only the changed chunks; small source files stay whole; parameters decided by experiment X6 |
| Capabilities: macaroon caveats [S21] and UCAN attenuated delegation with DID principals [S22] | Adopt | N7 | An orchestrator can mint a narrower grant for a worker without the repository authority; public-key chains (UCAN style), because any replica must verify without a shared secret |
| in-toto attestation layers (envelope, statement, subject digests, predicate) [S23] | Adapt | N4 | Receipt shape for evidence; native binary encoding inside, in-toto JSON only when exported at the edge |
| The "not rocket science" merge rule as built by bors: test the exact merged result, then fast-forward; batch; bisect on failure [S24] | Adopt | N4, N10 | Canonical only ever points at a tree that itself passed; the original Hoare post was not fetched (UNVERIFIED wording) |
| Trigram index for regular-expression code search [S25] | Adopt | N2, N11 | Agents search code constantly; an index turns a search into a candidate set before any bytes are read |

## 5. The Synapse Native Model

### 5.1 Objects and identity (N1, N4, N12)

Every object is immutable and content-addressed with a domain-separated SHA-256 digest (the existing scheme in `docs/SCHEMA_AND_CONSISTENCY.md`), each with its own type so no identity can be substituted for another (ADR 0001 section 2.3). The hash function is reviewed by experiment X1 (section 6.4).

| Identity | What it names | Notes |
| :--- | :--- | :--- |
| `BlobDigest` (kept) | File content bytes | Digest of the whole content, independent of chunking, so chunk parameters can change without changing identity |
| `ChunkDigest` (new) | One content-defined chunk of a large blob | Storage and transfer unit only (section 5.9) |
| `TreeDigest` (new) | A whole repository state as a Merkle tree of directories | Native encoding, not Git's; Git tree IDs are computed only at the bridge. Evidence binds to this |
| `ChangeId` (new) | One unit of intended work across all its rewrites and retries | 16 random bytes, allocated by the submitter or by an orchestrator that hands one `ChangeId` to several speculative attempts at the same task; refused on collision; not content-derived because content changes on rewrite. Several live revisions of one `ChangeId` are divergent attempts; selecting one prunes the others with obsolescence markers |
| `ChangesetId` (kept, redefined in envelope v2) | One immutable revision of a change | Digest of the revision's content only: `ChangeId`, parent revisions or base `TreeDigest`, mutations, conflict terms, and the intent record. It excludes who submitted it and when. v1 envelopes keep their v1 identities |
| `AdmissionWitness` (new) | The first admission of a revision | Recorded once by the server and never changed: `repo_id`, the submitting agent's DID and its signature over the envelope, the `IdempotencyKey`, the admission `WalSeq`, and the server's admission time. Idempotency is keyed on (`repo_id`, agent DID, `IdempotencyKey`); retention and replay use the admission `WalSeq`, never a client clock |
| `AuthorshipAttestation` (new) | A signed statement that an agent produced a revision, at a time | Identical content submitted under the same `ChangeId` (for example by two attempts of one task) is one revision with two attestations, so duplicate speculative attempts collapse (N1). Identical trees under different `ChangeId`s share evidence through `TreeDigest` (section 5.5). An attestation added later never revokes a receipt already accepted |
| `OperationId` (new) | One entry in the operation log (section 5.4) | Equal to the WAL frame digest that carries it |
| `ActionDigest` (new) | One exact evaluation: input `TreeDigest`, toolchain digest, command digest, environment digest, platform | Evidence key (section 5.5) |
| `GitOid` (kept, bridge only) | Git objects imported or exported | Never a native base; the envelope v1 field `base_git_oid` becomes a native base in v2 |

### 5.2 Intent as data, not prose (N8, N4)

The free-text `intent_summary` is replaced by an `IntentRecord`:

* `kind`: a closed enumeration (`Fix`, `Feature`, `Refactor`, `Revert`, `Merge`, `ResolveConflict`, `Format`, `DependencyUpdate`, `Generated`).
* `task`: a typed reference to the work item (tracker issue, ledger lane), never free text.
* `claims`: machine-checkable assertions the change makes, each naming a predicate type: for example "action A passes on the resulting tree", "public interface of module M is unchanged", "behaviour unchanged" for `Refactor` (discharged by an equivalence or test receipt), "reverts revision R exactly".
* `footprint`: the declared paths (later, symbols) the change intends to touch. It must lie inside the submitter's `Propose` scope, and every actual mutation must lie inside it (refused otherwise). Predictions and subscriptions use footprints; conflict detection and capability checks use the actual mutations.
* `supersedes`: revisions this one replaces (also expressed as obsolescence markers).
* `context`: an optional digest of a machine-readable rationale blob (the agent's plan or trace) for other agents. It is never part of any decision rule.

Claims are obligations: promotion requires every claim to be discharged by a passing receipt (section 5.5). A change that claims nothing beyond "passes the repository's required actions" is valid. Verification and benchmark lanes do not create revisions; they produce `EvidenceReceipt`s against existing trees, so they need no intent kind.

### 5.3 Revision states and the change algebra (N5, N12)

**States.** `Private` (visible only to its owner's delegation chain: the key that submitted it and the keys its grant descends from; N14) or `Draft` (visible within `Read` scope), then `Proposed`, then `Verified` (all claims and required actions discharged on its exact tree), then `Canonical` (promoted by quorum, immutable). The grant sets the default between `Private` and `Draft`. Revisions never change state backwards; replacing one creates a new revision and an obsolescence marker.

**Commutation.** The commutation promise is limited to T0: revisions on the same base whose actual mutations touch disjoint paths (and no file and directory prefix collision) give the same `TreeDigest` in every order, checked by a permutation test. T1 and T2 merges are not claimed to commute (three-way merging is not associative in general, and region merges can depend on order at a shared boundary). Instead, whenever more than two revisions are combined, the server merges them in canonical order (ascending `ChangesetId`) and records that order and the tier, so the result is a function of the set of revisions, never of arrival order or agent count (N12).

**Merge tiers.** The merge engine tries, in order, and records the tier used in the merged revision:

1. **T0 path:** different paths (what Synapse does today, 0.219 ms p50 per query in Gate 4).
2. **T1 region:** three-way merge of non-overlapping byte or line regions within one file. This removes the 3 over-flags of Gate 4 section 5.
3. **T2 structure:** syntax-tree merge (tree-sitter parse, GumTree matching, Spork-style merge, as Mergiraf does [S17, S18]) for languages with a grammar. A T2 result is accepted only if all of these hold, otherwise the merge falls to T3: the matched nodes edited by the two sides do not overlap; the result parses with the same grammar; and diffing the result against each side reproduces exactly the other side's edit script.
4. **T3 conflict:** a first-class conflict (below).

**Derived files.** A path can be declared derived (for example a lockfile) with the action that produces it. Derived files are never merged: after the other paths merge, the server runs the declared action on the merged tree and records its output, or records a conflict if the action fails. How often lockfile merges occur in AIEN repositories is UNVERIFIED.

A merged tree never inherits evidence from its parts; it must earn its own receipts (section 5.5). Policy can demand more evidence for higher tiers.

**First-class conflicts.** A tree entry can hold a `ConflictTerm`, the Jujutsu idea of a conflict as a sum of states [S7]: a set of add terms and a set of remove terms, with one more add than remove, each stored as a sorted multiset so the encoding is canonical. Each term is a full entry state: absent, or present as a file, directory, or symlink with its `FileMode` and content digest. Typed terms represent the cases Gate 4 section 5 measured: modify against delete (one term absent), file against directory (different kinds), and mode changes. Cancellation deletes an add term and a remove term only when they are identical entry states; the reduced form removes the multiset intersection of adds and removes from both sides, which is the same whatever order the cancellations happen in. One remaining add term and no remove terms is a resolved entry. Applying further changes adds terms; equal terms cancel, so rebasing twice reduces to a plain three-way conflict and reverting returns a clean tree. A tree with any conflict term can be read, rebased, and resolved, but cannot be materialized for a build and cannot be promoted. Resolution is a new revision of the same `ChangeId` with `kind = ResolveConflict`, by any agent with the capability.

**Automatic evolution.** When a base moves (canonical advances, or a parent revision is replaced), the server rebases every dependent `Private` and `Draft` revision that has no receipts, records obsolescence markers, stores any conflicts as terms, and notifies subscribers, as one operation per base move. Revisions that already carry receipts (`Proposed`, `Verified`) are not rebased, so their tested trees and evidence stay intact: the promotion queue merges them onto the current head and tests the merged tree (section 5.5). Rebasing stops being a job agents do (the 5 rebase lanes in N5).

### 5.4 Operation log, views, and undo (N6, P6)

* Every admitted mutation (revision created, marker recorded, reference moved, receipt attached, capability granted or revoked) is one operation in the existing hash-chained WAL. An operation records the actor, the capability chain used, and the view digest before and after.
* The **view** is the full set of references (canonical, workspace pointers, per-change visible heads). Its digest is a Merkle root, so two views compare in one step.
* **Undo** is a new operation that restores a chosen earlier view, either whole or filtered to one actor's operations (an orchestrator can undo one worker without touching others). Undo is itself undoable. Where a later operation by another actor conflicts with the undo, the result is recorded as conflict data, never silently dropped.
* **Who can undo what.** Undo needs a new `Undo` capability, and undoing another actor's operations needs a delegation chain that dominates that actor's (an ancestor of its grant). Undo changes references only; it never deletes objects, so content shared with other attestations or children stays (garbage collection alone frees space).
* **Facts that undo cannot reverse:** canonical promotions (canonical moves only by the promotion queue's compare-and-swap; a revert is a new change), revocations, accepted receipts, and identity-document changes.
* **Undo survives compaction:** checkpoints keep every operation and view root inside the undo window, and the undo window is a `GarbageRoot`. Undo to a view outside the window is refused with a typed refusal.
* Refused requests stay in the separate hash-chained security audit log (`synapse-auth`), bounded in size, so a flood of refusals cannot force durable writes on the hot path.

### 5.5 Evidence-carrying changes and promotion (N4, N10)

* An `EvidenceReceipt` states: the `ActionDigest` (exact input tree, toolchain, command, environment, platform), the result (exit status plus digests of outputs and logs stored in the content store), resources used in SI units (seconds, and joules when the instrument is present), whether the action declared all its inputs (hermetic), and the executor's machine key and signature. The shape follows in-toto (subject digests plus a typed predicate) [S23] and the Bazel Action and ActionResult split [S14].
* **Validity rule.** A receipt applies only to the exact `TreeDigest` in its action. A rebase that yields the identical tree keeps its evidence for free; a different tree never inherits any. This removes the stale-PASS failure (N4) by construction.
* **Who may execute.** Executors are untrusted unless registered: only receipts from registered executor machines (machine keys listed in the repository identity document, added under the delegate threshold) running a sandbox that the requesting agent does not control count toward promotion or enter the action cache. The registered executor, not the agent, decides the hermetic flag by checking that the action read only its declared inputs. A receipt from any other executor is an observation for the agent's own use only.
* **Action cache.** Any agent asking for an action already executed on identical inputs gets the stored result. Only hermetic receipts from registered executors are reusable across machines and time. Two receipts for one `ActionDigest` with different output digests fail closed: the action is marked non-deterministic, neither receipt is served or counted, and the disagreeing executors are recorded until a delegate re-executes it. A receipt is served only while its inputs and outputs are retained; garbage collection evicts it with them.
* **Independence.** A receipt does not count toward promotion if its executor shares a machine key or a delegation root with the revision's admission witness or with any attester known when the receipt was accepted (this generalizes today's `AuthSelfReviewRefused`, which compares one `author_did`). Two DIDs under one delegation root are one party.
* **Promotion queue.** Canonical advances only by compare-and-swap from the current head to a tree that (a) passed every required action and discharged every claim, on that exact tree, and (b) carries the delegate threshold of signatures. Delegates can be machines. The number of independent registered executors that must agree on each required action is repository policy, by default equal to the delegate threshold; each re-execution costs energy, so the policy and its joules per accepted change are reported together. Candidates are batched; a failed batch is bisected (bors [S24]).
* **What delegates sign.** The `ChangesetId`, the `TreeDigest`, the digest of the admission witness, and the root of the set of receipt digests the promotion relies on, so no unexamined receipt can ride along.
* **Trust root.** The quorum rule of ADR 0001 section 2.2 item 3 is unchanged. Delegates and threshold live in a Synapse identity document that mirrors the Radicle `refs/rad/id` delegates and threshold; changing it (including registering executors) needs the current threshold, as in Radicle [S11]. While the Git edge exists, the Radicle check over the bridged `GitOid` is also required, and any disagreement is refused as split-brain (existing `SplitBrainDivergence`).

### 5.6 Workspaces and speculative forks (N1, N2, N3)

* A **workspace** is a server-side pointer: a base (`TreeDigest` or revision) plus an overlay of changed paths, owned by a capability. Forking copies the pointer; it does not copy content. Every write by the agent is a draft revision (auto-snapshot), so no state lives only inside an agent.
* Reads (file, tree, diff, search) come straight from the content store. Trees are persistent Merkle structures: forks share every unchanged subtree, so memory grows with what changed, not with the number of workspaces. The cache is keyed by subtree digest and bounded (this replaces the unbounded per-changeset virtual tree cache of Gate 4 section 4).
* **Materialization for building and testing** is decided by experiment X7 among: (a) actions that read inputs by digest, with no filesystem view at all (Bazel style); (b) a lazy filesystem view that fetches on first read (CitC style [S12]); (c) a copy from the content store into memory-backed storage. The bound is the bytes the build actually reads divided by memory bandwidth.

### 5.7 Queries and subscriptions (N2, N11)

* Queries: revision, change (all revisions and markers), tree at any revision or snapshot sequence, diff as an edit script (path level now; GumTree actions [S18] at T2), content search through a trigram index over canonical trees and overlays [S25], evidence (which receipts exist for a tree; which trees passed an action), operation ranges, and conflicts.
* **Predictive conflicts:** intersect a footprint with the footprints of all open drafts, before the agent writes anything.
* **Subscriptions:** an agent subscribes to its footprint and receives every operation that touches it (at-least-once, resumable from a durable cursor, as the existing `watch` does), so it learns of overlapping work while it is still working.
* **Scope filter:** every query, search, conflict prediction, and subscription result is filtered to the caller's `Read` scope (paths and references), so a path-scoped agent learns nothing about drafts outside its scope. `Private` revisions take part only in their owner chain's predictions and are checked against others at proposal. A subscription event carries only the operation kind, the `ChangesetId`, and the written paths inside the subscriber's scope; never another agent's capability chain or full view.
* Read-your-writes and snapshot reads by `WalSeq` stay as specified in `docs/SCHEMA_AND_CONSISTENCY.md` section 3.

### 5.8 Agent identity and capabilities (N7)

* Identity stays Ed25519 `did:key`.
* Grants become **delegation chains**: the repository authority issues a root grant; a holder can issue a narrower grant to another key. Each link may only narrow: operations (`Read`, `Propose`, `Evaluate`, `Review`, `Publish`, `Undo`), path prefixes, reference scope (own drafts only; canonical only through the promotion queue), quotas, and expiry [S21, S22]. Each link signs the parent link's digest, the `repo_id`, the audience DID, and its caveats. Rate and size quotas are partitioned: the children of one grant together never exceed it. The server accepts a chain only if every link is unexpired and unrevoked at the request's `WalSeq`. Revocation is an operation in the log and cannot be undone.
* Every admitted mutation keeps its agent's Ed25519 signature (threat model T1 and T3). Verification runs on all cores before the single writer (section 5.9), so it is off the serial path; batch verification is experiment X2.

### 5.9 Storage and scale (N9)

* **Group commit** (W1, Phase 5 item 1, in flight on `feat/phase5-group-commit`): one device flush acknowledges every change in the batch, durable before acknowledgement. W1 measures the storage bound on this host; this ADR uses its results and does not repeat them.
* **Log-structured segments instead of a file per blob:** WAL records and content chunks are appended to the same segment files, so a batch is one sequential write plus one flush, with no per-object files, per-object directory flushes, or partly filled filesystem blocks. An in-memory index maps digest to (segment, offset) and is rebuilt from checkpoints.
* **Durability contract:** a change is acknowledged only after `fdatasync` of its segment returns success, and after a directory flush whenever a new segment file was created. Whether the device's flush survives power loss (the drive's volatile write cache) is a device property that experiment X0 and W1 must establish; until then it is UNVERIFIED and the guarantee is stated as "survives process crash and kernel crash".
* **Binary canonical encoding** replaces `serde_json` for WAL payloads and checkpoints (`crates/synapse-store/src/lib.rs` lines 829, 984, 1148, 1292 today), so replay stops parsing text.
* **Parallel stages, one serial point:** signature verification, hashing, and merge computation run on all cores before the writer; the single writer per repository only appends and updates the index, which keeps one total order per repository.
* **Content-defined chunking** for blobs above a threshold (experiment X6); the wire sends only chunks the receiver lacks (FindMissingBlobs style [S14]).
* **Garbage collection** from roots: canonical lineage, drafts with live leases, the operation-log undo window, and the inputs of receipts inside retention. Obsolete revisions stay restorable until the undo window ends (ADR 0002 cutover gate 3, history-safe GC).
* **Scale-out:** the repository is the unit of total order. More throughput comes from moving the bound (group commit, segments, parallel stages), and more repositories from more writers.
* **Change groups across repositories (N13):** a `ChangeGroup` record names one revision per repository. Each repository's promotion queue holds its member until every member is `Verified` and has its quorum; the members then promote in a fixed repository order, and a group whose later member fails its compare-and-swap is completed by a recorded follow-up revert in the earlier repositories (no distributed lock). The exact protocol is decided in PR L1.

### 5.10 The minimal Git bridge (machine interop only)

* **Import:** full history into native objects, with a persistent `GitOid` to (`ChangesetId`, `TreeDigest`) map; merge parents, tags, modes, and signatures preserved (signatures as opaque data).
* **Export:** deterministic materialization (existing, `git fsck` clean) written as packfiles, not loose objects; thin packs on the wire.
* **Remote helper:** `git-remote-synapse` (ADR 0002 Phase 6).
* Imported commits keep their original Git commit and tag headers as opaque bridge data, so exporting imported history reproduces the same Git object IDs.
* Native revisions exported to Git need a message and author fields because Git requires them. They are generated deterministically from the `IntentRecord` and the agent's DID; they are a format requirement, not text for humans.
* The bridge never confers promotion authority (unchanged).

### 5.11 What is dropped as human-only

* **Removed from the native model:** prose commit messages; author names and e-mail; wall-clock time inside identity; the staging area; working-tree checkout as the default; blame and log display; interactive rebase; human branch naming; review comments and markdown; PR titles and bodies.
* **Legacy edge adapters, removed after agent cutover (Phase 8), as ADR 0002 section 2.4 already states:** `GitHubPullRequestProjection` and `project_github_pull_request` with its markdown body; `advance_human_branch_fast_forward` and `RefusalCode::GitRefNonFastForward` (the human-branch guard); the `GarbageRoot` kind "open GitHub pull request projection"; the `WalRecord::GitProjected` record kind (kept readable for replay of old logs).

### 5.12 End state: Omega on AIENOS, talking to the metal

The end-state stack is: agent, then Synapse binary frames over shared memory, then the Synapse core written in Omega, then the AIENOS kernel, then NVMe and the CPU's hash and signature instructions, with no foreign runtime and no filesystem in between. The Rust crates and their conformance suites (WAL, Git, Radicle, plus the suites added in section 9) are the specification-by-test that the Omega port must pass byte for byte.

What Omega needs, as dependencies:

| Dependency | What exists | Status |
| :--- | :--- | :--- |
| Direct NVMe queue access with flush and known atomic write unit | AIENOS has `crates/aienos-kernel/src/nvme/{driver,atomicity}.rs`, a kernel store engine (`crates/aienos-kernel/src/store/`), and NVMe flush tests | Hardware qualification of these: UNVERIFIED (not checked for this ADR) |
| SHA-256 using the ARMv8 SHA-2 instructions | The host CPU reports the `sha2` feature; AIENOS has `crates/aienos-kernel/src/crypto/sha256.rs` | Whether that code uses the instructions: UNVERIFIED |
| Ed25519 verification (single and batch) | AIENOS has `native/sig/ed25519.c` and vendors `ed25519-dalek` | Omega binding: UNVERIFIED |
| Shared-memory rings between agent processes and Synapse | None found | Missing |
| Energy instrument | `aien_spbm` hwmon driver on the Linux host (section 6.2) | Availability under AIENOS: UNVERIFIED |
| Omega able to express all of the above | Omega is research-grade and pre-alpha, not self-hosting, with no general compiler yet (omega README, 2026-10-14) | Omega's current capability for this port: UNVERIFIED |

Omega code gets one more native benefit: Omega already identifies programs by `SEMANTIC_ID` (SHA-256 of the canonical encoding). Synapse can store Omega definitions by that identity, so equivalent Omega programs collapse to one object and evidence attaches to meaning rather than to text (the Unison idea [S16], applied to our own language). Candidate X8.

## 6. Performance: Chasing the Physical Bound

### 6.1 The metrics

* **Seconds per accepted change:** the latency distribution (p50, p99, maximum) from request sent to durable acknowledgement, and the steady-state interval between acknowledgements under load.
* **Joules per accepted change:** energy counter difference over the run divided by accepted changes, reported with and without the idle baseline subtracted.
* **Watts:** mean and peak over the run.
* Each is reported with its bound and the fraction of the bound achieved. Agent counts are measurement points only.

### 6.2 The bounds and their inputs

| Bound | Derivation | Input and source |
| :--- | :--- | :--- |
| Durable latency for one change | one device flush of one sequential append, plus one signature verification and the hashing of the new bytes on one core | Flush time: W1's measurement on this host (Phase 5 item 1). Ed25519 verify: 42.07 microseconds per signature per core (23,768 per second, calc:20f50860). SHA-256: 2.458 GB/s per core for 16 KiB blocks, so 4.86 microseconds for an 11,949-byte change (calc:8bc3db27) |
| Steady state per accepted change | the largest of: flush time divided by batch size; CPU work per change divided by cores; bytes per change divided by device write bandwidth | W1 (flush, bandwidth); probes above (CPU) |
| Read of n bytes | n divided by memory bandwidth, plus one index lookup | Memory bandwidth: experiment X0 (not yet measured) |
| WAL replay | bytes re-digested divided by hashing rate (a lower bound: it leaves out opening and reading the blob files) | Gate 4 section 8 states that replay re-reads and re-digests every committed blob, so the bytes are its "Store bytes (apparent)" column at 10,000 changesets (WAL plus 14,957 blob files): 117,196,023 bytes at 2.458 GB/s gives 47.69 ms (calc:1382b220) against the 344.575 ms median `SynapseStore::open`, so replay reaches 0.138 of the bound (calc:85a501db) |
| Thermodynamic reference | Landauer: at least kT ln 2 joules per bit erased [S26] | 2.871e-21 J per bit at 300 K (calc:b9494dee). Landauer charges erasure, not writing: the per-change figure assumes every stored bit overwrites one earlier bit (a log that reuses reclaimed space), giving 2.744e-16 J for the 11,949 bytes stored per change (calc:7bc56f71). A reference for what physics allows, far below any device; practical joule bounds come from measured device energy per flushed byte (experiment X0) |

Host probes for the table (single runs, raw output not sealed, so these figures are provisional until PR A0 repeats them with sealed evidence): OpenSSL 3.0.13, `taskset -c 9 openssl speed -seconds 2 -evp sha256` and `taskset -c 9 openssl speed -seconds 2 ed25519`, on core 9 (Cortex-X925, 3.9 GHz maximum), host load average 2.74 at the time. OpenSSL reported `OPENSSL_armcap=0xfd`, and the CPU lists the `sha2` feature, so these rates use the hardware SHA-2 instructions.

**Energy instrument.** The host exposes the `aien_spbm` hwmon device (hwmon3 on 2026-10-14) with energy channels `pkg`, `cpu_e`, `cpu_p`, `gpc_unverified` (always 0), and `gpm`, in microjoules per the kernel hwmon interface [S27]. Per the Omega energy protocol as summarised in the Turing unit brief: 10 Hz sampling, 1 mJ step, a 32-bit counter that wraps near 4.29 MJ, and no external calibration, so absolute accuracy is not claimed. Synapse energy figures reuse Omega's energy preflight discipline (refuse with `INSTRUMENT_UNAVAILABLE` rather than substitute) and are labelled provisional until that instrument is calibrated.

### 6.3 Every layer between the agent and the metal

| Layer | Measured cost today | Fate |
| :--- | :--- | :--- |
| JSON request encoding (`serde_json` writes bytes as decimal arrays) | Median signed request 16,653 bytes for 3,967 bytes of new content (Gate 4 section 7, supporting fact); JSON plus signing is the gap between 17.7 ms total and 11.4 ms API-only for a tree query | Removed: binary frames (PR G1) |
| JSON WAL payloads and checkpoints | Replay at 0.138 of the hashing bound | Removed: binary codec (PR A1) |
| CPU per change outside cryptography | 0.88 ms per change at 1 agent (Gate 4 section 3.3), of which one signature verification plus hashing (46.93 microseconds, calc:f73ac048) is a fraction 0.0533 (calc:50498e49) | Profile and remove (PRs A1, A2, G1) |
| File per blob, temporary file, rename, directory flush | 17,818 allocated against 11,949 apparent bytes per change (supporting fact); several flushes per change | Removed: segments (PR A2) |
| Flush and file work per change | S1 at 1 agent: p50 latency 11.8 ms, 13.8 ms between acknowledgements (calc:80d09f2c), flat from 1 to 32 agents; the flush share of that time is W1's measurement | Group commit (W1) |
| Virtual tree built per changeset | 11.394 ms API-only for 4,376 entries, 2.604 microseconds per entry (calc:e624b06b); unbounded memory | Shared Merkle tree with bounded cache (PR C1) |
| Kernel copies and system calls on the write path | Not measured | Candidate X4 (io_uring) |
| Process boundary between agent and Synapse | Not measured (Gate 4 ran in-process) | Candidate X5 (shared-memory ring) |
| The filesystem and page cache | Not measured separately | End state: AIENOS raw block store (section 5.12) |
| Process spawns | None in Synapse; Git bridge only | Bridge stays off the hot path |

### 6.4 Experiments that decide the candidates

Each experiment reports seconds and joules per unit of work, the bound, the instrument, and the raw samples, and states the decision rule before running.

| Id | Question | Method and decision rule |
| :--- | :--- | :--- |
| X0 | Host bounds not yet measured: memory bandwidth, device energy per flushed byte | Streaming copy and read probes; flush loop with energy counters (coordinate with W1 so the storage figures are measured once) |
| X1 | SHA-256 (hardware instructions) or BLAKE3 (NEON, multithreaded, internal Merkle tree [S28]) | Seconds and joules per byte at 1 KiB to 1 MiB, 1 thread and all cores. Change only if BLAKE3 is lower in seconds and joules per accepted change beyond run-to-run spread; a change is a versioned migration because the Omega `SEMANTIC_ID`, the AIENOS kernel, Radicle, and Git's SHA-256 transition all use SHA-256 |
| X2 | Batch Ed25519 verification | `ed25519-dalek` `verify_batch` (feature `batch`; its documentation states no speedup figure and reports failure without naming the bad signature [S29]) at batch sizes 1 to 256 inside group commit; on batch failure, verify individually. Adopt if seconds and joules per accepted change fall beyond spread. The Ed25519 paper's batch speedup claim was not fetched (UNVERIFIED) |
| X3 | Withdrawn after review | Session MACs plus a batch-root machine signature were proposed to remove per-request signatures. Withdrawn: a MAC is a shared secret other replicas cannot verify, and a batch signature does not bind each mutation to its agent (threat model T1, T3). Every mutation keeps its agent signature; the cost is attacked by X2 and by verifying on all cores off the serial path |
| X4 | io_uring for segment appends and flushes [S30] | Against `pwrite` plus `fdatasync`, inside group commit |
| X5 | Shared-memory ring for local agents | Against a Unix socket with the same binary frames |
| X6 | Content-defined chunking threshold and chunk sizes [S20] | On real AIEN repository histories; seconds and joules per accepted change and per read |
| X7 | Materialization for builds (section 5.6) | Seconds and joules per build against the bound of bytes actually read divided by memory bandwidth |
| X8 | Omega `SEMANTIC_ID` as native identity for Omega code | After the Omega toolchain can emit it for a real corpus |

## 7. A Level 0 Turing-Unit Proposal: How Well the Change Representation Describes Code History

Performance stays in seconds, joules, and watts (section 6). The Turing unit fits a different question: how well Synapse's change representation predicts real code history. This section is **Level 0 (definition only)**. No result is claimed; energy is provisional. It is not a performance measure: P3 and section 6 govern performance, and no turing or turing-per-joule figure may stand in for seconds, joules, or watts.

**The unit.** 1 turing (T) is one bit of net held-out description-length saving against a declared baseline, after charging the model's own size: T = [L(B) + L(D|B)] - [L(M) + L(D|M)], in bits. Turing yield is T per joule and exists only when joules are measured. (Definition from the preprint "Computing Machinery and Understanding", live copy at aienos.com/research/computing-machinery-and-understanding, as summarised in the Turing unit brief of 2026-10-14. "T" is also the SI symbol for tesla, so the unit is written "turing (T)" at first use.)

**Prediction task.** Observations D are the held-out sequence of tree transitions of real AIEN repositories: for each held-out commit in first-parent order, the resulting repository tree given every earlier tree. Each observation must be reconstructed byte for byte; L(D|M) is the code length in bits of M's lossless encoding of D given the training history (equivalently, the sum of -log2 p_M over the observations).

**Model M.** Synapse's representation and coder for the same transitions: structured and semantic deltas (path, region, and syntax-tree edit scripts), content-defined chunks, and deduplication against all earlier history. L(M) is the size in bits of everything needed to decode: the decoder artifact and all fixed tables, including every tree-sitter grammar the semantic tiers use, so semantic merging pays for its parsers.

**Baseline B.** Git's own delta coding of the same history: thin packs (`git pack-objects --thin --stdout`) of each held-out commit against the training history, with the Git version and every pack option (window, depth, compression level) fixed in the profile. L(B) is charged with the same rule as L(M) (the decoder artifact needed to read the pack).

**Held-out split.** A chronological cut per repository, fixed before any coder is tuned: training is history up to the cut; held-out is everything after it. The held-out commit list and tree digests are sealed (hash recorded, contents blinded from whoever tunes M) and audited for overlap (no held-out tree, or cherry-pick of one, present in training).

**Measurement profile (fixed and versioned before the data is seen).** Baseline and its options; the encoding rule for L(M) and L(B); quantizer (none: lossless code lengths, whole bytes times 8); the split, seal hash, and blinding; the energy instrument (`aien_spbm` `pkg` channel, 10 Hz, 1 mJ step, idle-subtracted, with the attribution rule I_AB = E_AB - E_A - E_B + E_0 when anything else runs); the uncertainty method (per-observation distribution and a resampling interval over held-out commits); the shared-background record; and the overlap audit. Numbers compare only within one profile and are not comparable to any Omega Turing-yield figure.

**Yield.** Turing yield = T divided by the idle-subtracted joules of encoding and decoding the held-out split with M, once the energy instrument meets its calibration level; until then any T per joule figure is labelled provisional.

## 8. Crate Map

| Crate | Keep | Change | New |
| :--- | :--- | :--- | :--- |
| `synapse-core` | Distinct identity newtypes, path validation, `RefusalCode`, `did:key` | Envelope v2: native base, `ChangeId`, `IntentRecord`, footprint, conflict terms, identity excluding author and time; binary codecs for every record | `TreeDigest`, `ChunkDigest`, `ChangeId`, `AdmissionWitness`, `OperationId`, `ActionDigest`, `EvidenceReceipt`, `AuthorshipAttestation`, `ObsolescenceMarker`, `ConflictTerm`, `ChangeGroup` |
| `synapse-store` | WAL framing discipline, CRC32C and hash chain, recovery policies, fault injection | `serde_json` to binary; file per blob to segments; group commit (W1) | Operation views and undo; chunk index; GC roots (K1) |
| `synapse-auth` | Ed25519 grants, expiry and replay guards, audit chain | Grants to attenuated delegation chains with path and reference scope | Batch verification path (X2); `Undo` capability |
| `synapse-api` | Paginated queries, read-your-writes, watch cursors, path index | Virtual tree to shared Merkle tree with bounded cache; JSON to binary frames | Workspaces, automatic evolution, conflict terms, footprint subscriptions, predictive conflicts, evidence queries, promotion queue, trigram search, change groups (L1) |
| `synapse-git` | Deterministic materialization, OID map | Loose objects to packfiles; map made persistent | Full-history import and export; remote helper |
| `synapse-git` (legacy) | Until Phase 8 | | Removed after Phase 8: `project_github_pull_request`, `advance_human_branch_fast_forward` |
| `synapse-radicle` | Identity and sigrefs verifier, split-brain refusal | Quorum engine accepts native digests and machine delegates | |
| `synapse-bench` | Harness, conformance suites, evidence format | Reports SI units, bounds, fractions, and energy | Host bound probes (X0, X1, X2) |
| New `synapse-merge` | | | Merge tiers T1 and T2, edit scripts |
| New `synapse-evidence` | | | Action digests, receipts, action cache, in-toto export |
| New `synapse-wire` | | | Binary frames, have-want chunk negotiation, transports |

New crates and workspace changes go through the integrator role, which alone edits the root `Cargo.toml` (handoff Plan v4).

## 9. Implementation Sequence

Every PR is small, owns one subsystem, and lands with a test that fails before the change and passes after it. Performance results follow section 6 (SI units, bound, fraction, raw samples). Correctness acceptance is stated as exact pass conditions.

| PR | Scope | Acceptance |
| :--- | :--- | :--- |
| A0 | Host bound probes in `synapse-bench` (hash, signature, memory, energy preflight; flush taken from W1) | Sealed evidence with instrument, resolution, and raw samples; the number of repetitions and the spread statistic are fixed before the runs; someone holding only the sealed raw data recomputes every reported figure exactly |
| A1 | Binary canonical codec for WAL records and checkpoints only (envelope and identities unchanged), versioned | Every record kind decodes to the same logical record as its v1 JSON form, in both directions; the first v2 checkpoint records the last v1 `state_root_digest` and chains its own root to it; WAL conformance 11 of 11; replay seconds per changeset reported against the hashing bound |
| A2 | Segment store replacing file per blob | Extended crash suite (torn segment, crash between payload and index, flush failure, crash after a new segment file before its directory flush); every acknowledged change survives; seconds and joules per accepted change against the flush bound |
| B1 | `ChangeId`, `AdmissionWitness`, obsolescence markers, envelope v2 with native base (a migration separate from A1) | A rewrite keeps `ChangeId` and gets a new `ChangesetId`; divergence (two live successors) is detected; identical content from two agents under one `ChangeId` yields one revision with two attestations and two admission witnesses; a repeat with the same repository, DID, and `IdempotencyKey` returns the first `WalSeq`; every v1 `ChangesetId` still resolves to its record |
| B2 | Operation views and undo, including checkpoint and compaction | After a random operation sequence, undo to any earlier operation in the window restores that exact view digest, also after a checkpoint and compaction; undo is undoable; per-actor undo leaves other actors' operations intact; undo of a canonical promotion, revocation, or accepted receipt is refused; undo by an actor without a dominating chain is refused |
| B3 | `IntentRecord` and claims | Envelopes with only free text are refused; every claim kind maps to a predicate type |
| C1 | `TreeDigest` Merkle trees with shared, bounded cache | Tree and diff parity with `git ls-tree -r` and `git diff-tree` on the Gate 4 fixture; memory stays under the configured bound under the Gate 4 query load; seconds per entry against the memory-bandwidth bound |
| C2 | Workspaces: fork, auto-snapshot, discard | Fork time on the Gate 4 fixture and on a larger fixture fixed in advance differs by no more than the run-to-run spread; a `Private` workspace is invisible to a key outside its owner chain; discarded workspace content is reclaimed by GC after retention |
| D1 | Merge tier T1 (region) | Gate 4 conflict scenario: the 3 disjoint-hunk pairs, which path-level merging refuses today (so the test fails before the change), now merge; every merged tree equals Git's merge result; no pair that `git merge-tree` reports as conflicting is merged (all 253 pairs); each result records its tier and merge order |
| D2 | First-class conflict terms and automatic evolution | Rebase twice cancels to a plain three-way conflict; revert returns a clean tree; conflicted trees refuse materialization and promotion |
| D3 | Merge tier T2 (syntax tree), Rust grammar first | A corpus of real merges from AIEN repository histories is sealed before the T2 code is written and includes cases labelled T2-mergeable (concurrent edits to different syntax nodes in one region), so a stub that sends everything to T3 fails; every labelled case merges at T2; every T2 result meets the acceptance rule of section 5.3 and builds and passes the same tests as the resolution recorded in history |
| E1 | Registered executors, evidence receipts on `ActionDigest`, action cache with the contradiction rule | Property test: a receipt for tree T never satisfies policy for any other tree; a receipt signed by an unregistered key is refused; two receipts for one `ActionDigest` with different results fail closed and remove the cache entry; a receipt whose inputs or outputs are no longer retained is not served; the stale-PASS scenario of aien-sovereign-core#516 reproduced red, then green; an identical action returns the cached result |
| E2 | Promotion queue with machine delegate quorum over native digests | Canonical advances only to a tree with every required receipt and the threshold of signatures over the section 5.5 payload; a signature over a different receipt set is refused; two DIDs under one delegation root count as one independent execution; a failing batch is bisected to the failing candidate; Radicle conformance stays 11 of 11 |
| F1 | Attenuated capability chains | Property test: no derived grant exceeds its parent in operations, paths, references, quotas, or expiry; child quotas never sum above the parent's; forged, stripped, and reordered chains, and a link bound to another repository or audience, are each refused; out-of-scope path refused; a chain with an ancestor revoked at the request's `WalSeq` is refused |
| F2 | Footprint subscriptions and predictive conflicts | Subscriber receives every operation touching its footprint, resumes from its cursor after restart without loss, and the delay from commit to delivery is reported in seconds; a subscriber scoped to one path prefix never receives an event, path, or prediction outside that prefix or from another owner's `Private` revision |
| G1 | Binary wire frames and have-want negotiation | Seconds and joules per accepted change across the transport against the bound; bytes sent recorded as a supporting fact |
| G2 | Content-defined chunking (after X6) | Every blob round-trips byte for byte through chunking with an unchanged `BlobDigest`; deduplication between two revisions that share content follows the rule X6 fixed before its runs |
| H1 | Git bridge: persistent map, full-history import and export from stored headers, packfiles | Imported real repository history exports with identical Git object IDs, using the stored original headers; native revisions export deterministically (two exports give identical IDs); `git fsck --full --strict` clean |
| H2 | `git-remote-synapse` | `git clone`, `git fetch`, `git push` against `synapse://` on a real repository |
| I1 | Remove legacy human adapters (after Phase 8 cutover) | First, the two human-branch cases of the Gate 4 Git suite (fast-forward allowed; non-fast-forward refused) are replaced by native compare-and-swap reference cases that pass, so the suite stays green as ADR 0002 section 5 requires; then the adapter code and tests in section 5.11 are removed; old WAL logs still replay |
| J | Omega port on AIENOS, one subsystem at a time | The same conformance suites pass byte for byte against the Omega implementation; SI results against the same bounds |
| K1 | GC roots for admission witnesses, the undo window, and receipts | GC never removes an object reachable from an admission witness inside retention, a view inside the undo window, or a receipt the action cache can still serve; GC that would remove an in-window view fails closed; retention is counted in `WalSeq`, not wall-clock time |
| L1 | Cross-repository change groups (N13) | On two test repositories, a group either ends with every member canonical or, after a forced compare-and-swap failure on the later member, with a recorded revert in the earlier one; a pin in one repository never names a revision of the other outside a completed group |

Order: A0 and A1 first (they make every later measurement honest), then B1, B2, C1 in parallel with K1 (no GC runs on v2 data before K1), then D1, E1, F1, then the rest; L1 after E2. Phase 6 bridge work (H1, H2) can run beside B to D once the A1 and B1 formats are fixed.

## 10. Rejected Ideas and the Independent Review

### 10.1 Top rejections

1. **Line-graph patch storage (Pijul, Darcs) as the native store:** evidence must name a concrete tree, and reads must not rebuild a graph; the algebra is kept without the storage.
2. **Git's index, staging area, and checkout-first workflow:** human editing aids; agents write changes and read by query.
3. **Character-level text CRDTs:** per-character metadata for real-time co-editing that agents do not do.
4. **SQLite or any general database engine as the core store (Fossil):** a layer between the agent and the metal; the idea of queryable history is kept.
5. **Prose messages, tickets, wiki, review comments, display diffs:** no AI reader needs them.

Also withdrawn after review: session MACs in place of per-request agent signatures (X3, section 6.4), because they break per-agent attribution.

### 10.2 Review record

* **Reviewer:** Grok 4.7 at high reasoning effort, read-only, given this ADR, ADR 0001 and 0002, the Gate 0 and Gate 4 reports, the schema and threat model documents, and the crates. Verdict: **revise**.
* **Why not Codex:** the planned reviewer, Codex `gpt-6-astra`, was rate-limited on 2026-10-14 until 12:23 CDT, and a Fable 5.1 attempt was also rate-limited (HTTP 429). A Codex attack pass on this PR is still wanted once its limit resets.
* Every finding below was checked against the cited repository documents before it was accepted or rejected.

### 10.3 Review findings and dispositions

| # | Finding (severity) | Disposition |
| :--- | :--- | :--- |
| 1 | Unmeasured assumptions stated as facts: footprints equal mutations, disjoint regions commute, executors set the hermetic flag honestly, one flush is power-loss durable, one unsealed probe is the bound (blocker) | Accepted. Mutations outside the footprint are refused (5.2); the commutation promise is T0 only, with a permutation test (5.3); registered executors set the hermetic flag (5.5); durability contract with power-loss behaviour UNVERIFIED until X0 and W1 (5.9); probes provisional until A0 (6.2) |
| 2 | Content identity without author and time breaks idempotency, retention, and self-review rules (blocker) | Accepted. `AdmissionWitness` (5.1); idempotency keyed on repository, DID, and key; retention by `WalSeq`; quorum payload includes the witness digest and receipt-set root; later attestations never revoke an accepted receipt; independence judged by machine key or delegation root |
| 3 | Action cache and machine quorum trust the executor; one forged success is permanent (blocker) | Accepted: registered executors, fail-closed contradiction rule, receipts served only while retained, delegates sign the receipt-set root, identity-document edits need the threshold (5.5). Adapted: "every action re-run by an independent key" became a policy defaulting to the threshold, with joules reported, because each re-run costs energy. Rejected: "bisect bypasses the cache", since a receipt from a registered executor with no contradiction is evidence, and re-running it spends joules without adding any |
| 4 | Subscriptions, search, and predictions leak content beyond path scope; abandoned speculative work is readable (blocker) | Accepted. Every query, prediction, and event filtered to `Read` scope; events carry kind, `ChangesetId`, and in-scope paths only (5.7); `Private` state and need N14 (5.3) |
| 5 | Undo has no capability, can move canonical, does not survive compaction or GC (blocker) | Accepted. `Undo` capability with a dominating chain; undo moves references only and never deletes objects; canonical promotions, revocations, accepted receipts, and identity changes are not undoable; view roots kept in checkpoints; the undo window is a `GarbageRoot` (5.4); B2 includes compaction; new PR K1 |
| 6 | Commutation, tiers, conflict terms, and auto-rebase are not sound as written (blocker) | Accepted. Commutation promised for T0 only; T1 and T2 record order and tier; T2 acceptance rule defined; `Verified` revisions never rebased; typed conflict terms with a stated cancellation rule (5.3). The Darcs line-graph store stays rejected; its algebra is kept only where it is provable |
| 7 | X3 session MACs break attribution; delegation links, quotas, and revocation underspecified (major) | Accepted. X3 withdrawn (6.4); links sign parent digest, repository, audience, and caveats; quotas partitioned; every ancestor must be unrevoked at the request's `WalSeq`; grants and receipts are not merged as CRDTs (5.8, section 4) |
| 8 | Figures disagree with the repository's reports (major) | Accepted: 13.8 ms is the interval between acknowledgements, beside p50 11.8 ms; 0.0533 is a fraction of 880 microseconds; replay bytes named as Gate 4's store column, with the bound stated as a lower bound; hive counts are a later snapshot than Gate 0, and both are quoted. Rejected: deleting the Landauer row, which the owner asked for; its erasure assumption is now stated (6.2) |
| 9 | Missed needs, adoptions from unfetched sources, tests that cannot fail, migration and bridge gaps (major) | Accepted: needs N13 and N14; verify and benchmark lanes produce receipts, not revisions (5.2); derived-file rule; evolve downgraded to Adapt and structured merge gated by D3; acceptance tests that a stub now fails (A0, C2, D1, D3, E1, F1, F2, G2); A1 and B1 split; H1 exports from stored headers; I1 replaces the two human-branch Git cases first; new PRs K1 and L1. Rejected: removing section 7, which the owner asked for; it is Level 0, claims no result, and is explicitly not a performance measure. Left undone and named: Byzantine replication between Synapse servers (one writer per repository; the delegate threshold is the trust boundary) |

## 11. Consequences

* Agents stop doing checkouts, rebases, and repeated identical test runs; the server does rebases, the action cache returns repeated results, and builds read inputs by digest where possible.
* Every performance claim becomes a fraction of a physical bound with open data; there are no headline multipliers.
* Envelope v2 changes `ChangesetId` semantics (content only); v1 records stay readable through a versioned migration.
* The design adds state (operation views, markers, receipts, footprints, admission witnesses, change groups) that the cutover gates of ADR 0002 section 4 must cover: backup and restore, repair, history-safe GC, bounded memory.
* Independent re-execution for promotion costs energy: each required action runs as many times as the policy demands (by default the delegate threshold). Those joules are reported per accepted change, so the price of trust is measured rather than hidden.
* Keeping one agent signature per mutation puts a floor of one Ed25519 verification per accepted change on the CPU budget; it runs on all cores off the serial path, and X2 measures whether batching lowers it.

## 12. Sources

* [S1] Git pack format, git-scm.com/docs/gitformat-pack (Git 2.54.0 manual).
* [S2] Git hash function transition, git-scm.com/docs/hash-function-transition.
* [S3] Pijul theory, pijul.org/manual/theory.html.
* [S4] Pijul FAQ, pijul.org/faq.
* [S5] Jujutsu glossary, docs.jj-vcs.dev/latest/glossary/.
* [S6] Jujutsu operation log, docs.jj-vcs.dev/latest/operation-log/.
* [S7] Jujutsu first-class conflicts, docs.jj-vcs.dev/latest/technical/conflicts/.
* [S8] Mercurial evolve terminology (obsolescence markers, predecessors, successors), mercurial-scm.org/doc/evolution/obs-terms.html (read through a search summary; the page returned HTTP 404 to a direct fetch).
* [S9] Sapling introduction, sapling-scm.com/docs/introduction/.
* [S10] Fossil versus Git, fossil-scm.org/home/doc/trunk/www/fossil-v-git.wiki.
* [S11] Radicle protocol guide, radicle.dev/guides/protocol.
* [S12] Potvin and Levenberg, "Why Google Stores Billions of Lines of Code in a Single Repository", CACM 59(7), 2016, DOI 10.1145/2854146. Primary text not fetched (HTTP 403); claims taken from acawiki.org and search summaries.
* [S13] Scion, github.com/GoogleCloudPlatform/scion.
* [S14] Bazel Remote Execution API, github.com/bazelbuild/remote-apis, `build/bazel/remote/execution/v2/remote_execution.proto`.
* [S15] Nix manual, content-addressed derivation outputs, nix.dev/manual/nix/stable/store/derivation/outputs/content-address.
* [S16] Unison, "The big idea", unison-lang.org/docs/the-big-idea/.
* [S17] Mergiraf, mergiraf.org and mergiraf.org/architecture.html (Spork architecture, GumTree classic matching, tree-sitter parsing).
* [S18] Falleri, Morandat, Blanc, Martinez, Monperrus, "Fine-grained and accurate source code differencing", ASE 2014 (citation from github.com/GumTreeDiff/gumtree; paper text not fetched).
* [S19] difftastic, difftastic.wilfred.me.uk.
* [S20] Xia et al., "FastCDC", USENIX ATC 2016, usenix.org/conference/atc16/technical-sessions/presentation/xia.
* [S21] Birgisson et al., "Macaroons: Cookies with Contextual Caveats for Decentralized Authorization in the Cloud", NDSS 2014, DOI 10.14722/ndss.2014.23212.
* [S22] UCAN specification, github.com/ucan-wg/spec.
* [S23] in-toto attestation framework, github.com/in-toto/attestation/blob/main/spec/README.md.
* [S24] bors-ng, github.com/bors-ng/bors-ng (staging merge commit, fast-forward on pass, batching, bisection).
* [S25] Russ Cox, "Regular Expression Matching with a Trigram Index", swtch.com/~rsc/regexp/regexp4.html.
* [S26] Landauer, "Irreversibility and Heat Generation in the Computing Process", IBM Journal of Research and Development 5, 183 to 191, 1961 (bibliographic details from search results; DOI not confirmed on the publisher's page).
* [S27] Linux hwmon sysfs interface, docs.kernel.org/hwmon/sysfs-interface.html (energy inputs in microjoules).
* [S28] BLAKE3, github.com/BLAKE3-team/BLAKE3.
* [S29] `ed25519-dalek` `verify_batch`, docs.rs/ed25519-dalek/latest/ed25519_dalek/fn.verify_batch.html.
* [S30] io_uring(7), man7.org/linux/man-pages/man7/io_uring.7.html.
