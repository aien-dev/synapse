# ADR 0002: Synapse-First Source Control for AI Agents, with Git as a Bridge

* **Status**: Accepted
* **Date**: 2026-10-14
* **Decided by**: Drake (owner)
* **Tracking Issue**: [aien-spark/synapse#8](https://github.com/aien-spark/synapse/issues/8) (Phases 5 to 9); Gates 0 to 4 were tracked in aien-sovereign-core#515, now closed
* **Supersedes in part**: [ADR 0001](0001-synapse-architecture-and-boundaries.md) (section 2.2 items 1 and 2) and the non-goal "Replacing Git" in [aien-spark/aien-sovereign-core#515](https://github.com/aien-spark/aien-sovereign-core/issues/515)
* **Evidence**: [Gate 4 Comparative Qualification Report](../GATE4_QUALIFICATION.md) and [`evidence/gate4-qualification/`](../../evidence/gate4-qualification/)

## 1. Context

ADR 0001 scoped Synapse as an accelerator for the agent inner loop that sits beside Git. Git was the portable repository history format (ADR 0001 section 2.2 item 1), GitHub was the human-facing forge projection (item 2), and the tracking issue aien-sovereign-core#515 listed "Replacing Git, forking Git semantics, or forcing external contributors off normal Git tooling" as an explicit non-goal.

Gate 4 measured Synapse against Git worktree and Git plumbing workflows on the same host and fixture. The numbers are in the Gate 4 report and are cited here by section only:

* Synapse is ahead on page-cache ingest throughput, CPU per proposal, and a path-level conflict query with no false negatives (sections 1, 3.1, 3.3, 5).
* Git plumbing is ahead on durable write throughput from 8 agents up, because Synapse has one durable writer (section 3.1), and on read latency through a persistent `git cat-file --batch` (section 4).
* Synapse has an unbounded virtual tree cache (section 4) and no compact wire format; its JSON request is many times the size of a Git thin pack (section 7, ESTIMATE).
* Synapse flags 3 disjoint-hunk pairs as conflicts that Git merges cleanly, because it compares at path level (section 5).
* Gate 4 section 13 recommended Option C: Git plumbing now, a Synapse pilot later.

The owner then decided (Drake, 2026-10-14, verbatim):

> "I want Synapse to do everything Git does and I want a simple small interface with Git. I want us to use both the power of Git and the benefits of Synapse. Eventually Synapse will take over Git from our actual hardware."
>
> "I want Synapse to be the new Git for AI."
>
> "Don't just copy features because we feel like we need them. I want you to take the good parts of everything and make the best system possible."
>
> "This is going to be for AI only. AI is going to be the only one writing code in the future and this is not going to be for humans. Nothing human-related needs to be in this."

## 2. Decision

### 2.1 Synapse Is Source Control for AI Agents Only

Synapse becomes the primary source control system for AI agents. Agents are its only writers and readers. No human-facing features are in scope: no human review UI, no blame views, no human commit messages, no human branch protection.

### 2.2 The Best Parts of Every System, Not a Copy of Git

"Do everything Git does" means Synapse covers every job source control does for agents (store and verify history, branch, merge, synchronize, prove provenance), each with the best design available. It does not mean a feature-by-feature clone of Git. Every adopted idea must name the concrete AI-agent need it serves; a feature is not adopted only because another system has it.

### 2.3 Git Is a Small Machine Bridge

Git stays as a minimal machine interface for ecosystem interop: importing existing Git repositories with full history, exporting Synapse history as standard Git objects, and letting existing tooling and hosting that speak Git (CI systems, package managers, Git hosts) read and write through a remote helper. The bridge is not a human path.

Deterministic Git materialization (ADR 0001 section 2.2 item 1) remains the export mechanism and must stay `git fsck` clean. Git is no longer the primary history format; it is the import and export format at the edge.

### 2.4 Human-Oriented Pieces Become Legacy Edge Adapters

The GitHub pull request projection (`GitHubPullRequestProjection` in `synapse-core` and `project_github_pull_request` with its markdown body in `synapse-git`) and the human branch fast-forward guard (`advance_human_branch_fast_forward` and `RefusalCode::GitRefNonFastForward`) serve humans. They are reclassified as legacy edge adapters. They keep working, with their tests, until agent cutover (Phase 8) and are then removed. This ADR deletes no code.

### 2.5 Trust Model Unchanged

Radicle delegate quorum (ADR 0001 section 2.2 item 3) stays the trust model for canonical promotion unless ADR 0003 changes it. Delegates can be agents or machines. Ingest order (`WalSeq`) and forge merge state never confer promotion authority.

## 3. Roadmap

### Phase 5: Close the Measured Gaps

The four gaps Gate 4 measured are the work list. Each fix is re-measured with the Gate 4 harness against the Gate 4 numbers.

1. **Durable single-writer ceiling.** Group commit across `synapse-store` and the `synapse-api` submission path, so one fsync covers every queued submitter. Blobs, directories, and the WAL are fsynced before any acknowledgement. The queue is bounded and has a maximum batch delay. Tests cover a crash mid-batch, a failed flush (no acknowledgement; every waiter gets the error), retry, and shutdown drain. Acceptance: S1 re-measured at 1, 4, 8, and 32 agents; no regression at 1 agent; at least 5 times the durable throughput at 32 agents; stretch target p99 at 32 agents below G3F's 119 ms.
2. **Slower reads than `git cat-file --batch`.** A faster read path for file, tree, and diff queries, measured against the Git methods in Gate 4 section 4.
3. **Unbounded virtual tree cache.** A memory bound with eviction, and a measured peak under the Gate 4 query load.
4. **No compact wire format.** A compact binary wire format and a local daemon socket, replacing the JSON approximation, measured against the Git thin pack size in Gate 4 section 7.

### Phase 6: The Small Git Bridge

1. Native contracts first: history, durable refs, atomic compare-and-swap ref updates, authorization on refs, a persistent `ChangesetId` to `GitOid` identity mapping, and full-history round trip that preserves merge parents, tags, signatures, and file modes.
2. Full-history import of existing Git repositories and full-history export.
3. `git-remote-synapse`, a Git remote helper, so that `git clone`, `git fetch`, and `git push` against a `synapse://` address work for existing tooling. Built only after the contracts in step 1 land.

### Phase 7: AI-Native Model

Take the best ideas from every system, each adopted only for a concrete AI-agent need:

* Git (content-addressed objects, cheap branches, the wider ecosystem);
* Pijul and Darcs (patch commutation);
* Jujutsu (operation log and first-class conflicts);
* Radicle (signed delegate quorum);
* Google Piper/CitC and Scion (server-side virtual workspaces);
* Bazel and Nix (content-addressed inputs);
* Unison (content-addressed code);
* semantic and AST-aware merge (for example, removing the path-level over-flags Gate 4 section 5 measured).

Designed in ADR 0003 (in progress).

### Phase 8: Agent Cutover

Hive agents submit, read, and merge through Synapse. Git is used only through the bridge. The legacy edge adapters (section 2.4) are removed after cutover. Phase 8 starts only after every cutover gate in section 4 passes.

### Phase 9: Native on AIEN Hardware

The Synapse store runs natively on AIEN hardware under AIENOS. Git is an import and export edge only.

## 4. Cutover Gates Before Phase 8

Each gate needs recorded, reproducible evidence before any agent workload moves to Synapse as its primary system:

1. Tested backup and restore.
2. Corruption diagnosis and repair.
3. History-safe garbage collection.
4. Bounded memory.
5. A native checkout and build workflow, so agents that build or test get a working directory from Synapse without Git (Gate 4 section 9 notes that agents that build or test still need a checkout).
6. Staged migration with reconciliation and rollback.

## 5. What Stays True

* Radicle delegate quorum governs canonical promotion unless ADR 0003 changes it (section 2.5).
* Deterministic Git materialization stays `git fsck` clean; it is the bridge's export path, and the Gate 4 Git conformance suite stays green.
* Git hosts such as GitHub stay reachable through the bridge as ordinary Git interop for existing tooling and hosting.
* ADR 0001 sections 2.1 (owning repository), 2.2 item 3 (Radicle canonical authority), 2.3 (distinct identity invariant), and 2.4 (crate ownership map) are unchanged.

## 6. Relationship to ADR 0001 and #515

* ADR 0001 section 2.2 item 1 is superseded in part: Git is no longer the primary history format; deterministic materialization stays as the export mechanism.
* ADR 0001 section 2.2 item 2 is superseded: the GitHub human projection is a legacy edge adapter until Phase 8, then removed.
* The non-goal "Replacing Git, forking Git semantics, or forcing external contributors off normal Git tooling" was stated in aien-sovereign-core#515, which ADR 0001 tracked; ADR 0001 itself does not contain that sentence. This ADR supersedes that non-goal.
* The Gate 4 Option C recommendation is superseded by the decision recorded in Gate 4 section 13.

## 7. Consequences

* Synapse must meet the operating standard of a primary system (backup, repair, garbage collection, bounded memory) before cutover; the gates in section 4 make that explicit.
* While both systems are live, the bridge must keep Synapse and Git history consistent in both directions; full-history round trip tests guard this.
* Features are justified by agent needs rather than by Git parity, so some Git features may never be built and some Synapse features will have no Git equivalent.
* Phases 5 and 6 can proceed in parallel: Phase 5 owns the store and the submission path; Phase 6 builds on the public `SynapseService` API and new crates.
