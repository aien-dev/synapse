# One changeset through Synapse and Git

I use Synapse to accept many agent proposals without making ingestion order into branch authority. [ADR 0001](docs/adr/0001-synapse-architecture-and-boundaries.md) records the identities and boundaries. `ChangesetId` names a proposal, `WalSeq` orders durable ingestion, and `GitOid` names a materialized Git object. None alone authorizes a canonical Radicle head; that check is in [synapse-radicle](crates/synapse-radicle/src/lib.rs).

The existing [Git conformance fixture](crates/synapse-bench/src/conformance.rs) makes a small base Git repository, submits envelopes through [`SynapseService::submit`](crates/synapse-api/src/lib.rs), and uses the [store](crates/synapse-store/src/lib.rs) for durable WAL records. It obtains checkout-free trees and diffs with [`materialize_virtual_tree` and `diff_trees`](crates/synapse-api/src/lib.rs). [`materialize_changeset_to_git`](crates/synapse-git/src/lib.rs) writes standard Git objects and records the mapping. The fixture asks independent `git fsck --full --strict` to check the result. Its negative control damages a materialized loose object and requires fsck to exit nonzero. This is a refusal of corrupt output, not a demonstration that accepted WAL order grants publishing authority. The [schema and consistency specification](docs/SCHEMA_AND_CONSISTENCY.md) explains why these IDs stay distinct.

## Replay

Use a fresh checkout at `5b732e5d353bbcc3f6d0cd1eac60f2e543601521`, Rust 1.98.1 (the replay host version), cargo, git and cached locked dependencies on Linux. No model, account or Radicle network is needed.

```sh
git clone https://github.com/aien-dev/synapse.git synapse-lesson
cd synapse-lesson
git checkout --detach 5b732e5d353bbcc3f6d0cd1eac60f2e543601521
cargo test --locked --offline --lib -p synapse-bench conformance::tests::git_suite_cases_pass -- --exact
```

Expected exit is 0 with the named test passed. It asserts all seven Git suite cases, including the corrupt-object negative case. [TEACHING-REPLAY.txt](TEACHING-REPLAY.txt) records the observed attempt and whether dependencies were available. This is a host fixture, not a live Radicle promotion or full service deployment. The [qualification report](docs/GATE4_QUALIFICATION.md) and [pipeline](docs/PIPELINE.md) cover broader, separately pinned claims.


### Parent fresh-checkout replay

A separate coordination replay is retained in [the parent receipt](docs/parent-replay-2026-10-22.txt). Its scope and observed exit are explicit; source review and final desk qualification remain separate. A recorded absence or expected failing baseline is not a passing implementation.
