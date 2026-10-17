# B4: Revision State Machine

ADR 0003 section 9 step B4 (issue aien-dev/synapse#28). Section 5.3 ("States") and need N14: a revision is `Private` (visible only to its owner's delegation chain) or `Draft` (visible within `Read` scope), then `Proposed`, then `Verified` (every claim and required action discharged on its exact tree), then `Canonical` (promoted by quorum, immutable). Revisions never change state backwards; replacing one creates a new revision and an obsolescence marker (B1). Builds on B1 (revisions, admission witnesses, chain dominance) and F1 (capability chains).

Code: `crates/synapse-core/src/revision_state.rs` (`RevisionState`, the order rule, the owner-move rule), `crates/synapse-store/src/revision.rs` (state in the ledger, visibility, moves), `crates/synapse-store/src/{lib,codec}.rs` (WAL kind 9, replay, checkpoint), `crates/synapse-api/src/lib.rs` (`advance_revision_state`, `read_revision`). Tests: unit tests in `crates/synapse-core/src/revision_state.rs` and `crates/synapse-store/src/revision.rs` (`b4_tests`), `crates/synapse-store/tests/b4_revision_states.rs`, `crates/synapse-api/tests/b4_revision_states.rs`. Evidence: `evidence/b4-revision-states/`.

## 1. Model and invariants

* **States and order.** `Private < Draft < Proposed < Verified < Canonical`. The only moves are five forward edges: `Private -> Draft`, `Private -> Proposed`, `Draft -> Proposed`, `Proposed -> Verified`, `Verified -> Canonical`. Every edge strictly raises the rank; a move backwards, in place, or skipping a state is `RevisionStateMoveInvalid`.
* **Owner chain.** A chain owns a revision when it is, or dominates, the chain of the revision's first admission witness (B1): the key that submitted it and the keys its grant descends from. A sub-delegate of the submitter (a chain that descends from it) is not an owner, and neither is a sibling or an outsider. Section 5.3 names "the key that submitted it" but does not say what a later identical submission (a B1 join) grants; B4 takes the most restrictive reading: a join adds a witness and an attestation, never an owner.
* **Initial state.** Every admission starts `Private` (fails closed; see section 5 on the grant default). A second admission of identical content (B1 join) adds a witness and leaves the state and the owner chain unchanged: a joiner outside the owner chain cannot read the revision (so not the owner's witness or attestation), cannot find it in the change, and cannot move it; once the owner shares it, the joiner may read it but still not move it.
* **Visibility.** A `Private` revision is visible only to its owner chains; any other state is visible to every chain the caller's `Read` scope allows. A revision a chain may not see behaves exactly like one that does not exist: reads, moves, parent references, and obsolescence markers naming it are refused with `ChangesetNotFound` and the same message as for an unknown revision. Change status seen by a chain lists only the revisions and markers it may see, and recomputes live, obsolete, and divergent from them.
* **Who may move.** The owner chain may move its revision to `Draft` or `Proposed`. A move to `Verified` is refused to the owner (`RevisionStateMoveInvalid`): it needs claims (B3) and required-action receipts (E1) discharged on the exact tree, which no chain can assert by itself. Any move to `Canonical` is refused with `CanonicalOutsidePromotionQueue`, checked first, whatever the revision or chain: `Canonical` is reached only through the promotion queue's compare-and-swap (E2).
* **Determinism and replay.** The ledger is a pure function of the kind 7, 8, and 9 records in sequence order. Kind 9 is permanently the owner-move record: `Verified` and `Canonical` come only from the evidence-bearing records of B3, E1, and E2, never from kind 9. Kind 9 records are unsigned and the WAL seal is unkeyed (CRC32C and an unkeyed hash chain detect corruption, not forgery), so replay accepts a kind 9 record only when it is an owner move: `Private -> Draft`, `Private -> Proposed`, or `Draft -> Proposed`, by a chain that is or dominates the first admission's chain. Both rules are pure functions of the log that never change, so an old log keeps its meaning. Any other record (forged or corrupt) is kept in the log and in the state root but changes nothing, so replay, a checkpoint, and a live store rebuild the same states and no record sequence moves a revision backwards or past `Proposed`.

## 2. Operations

| Operation | Store | API (F1 chained request) |
|---|---|---|
| Move | `advance_revision_state(repo, changeset_id, to, chain, now_ms) -> WalSeq` | `advance_revision_state(req, now_ms)`: capability `Propose`; payload = `RevisionStateMovePayload`; chain = the request's chain |
| Read | `get_revision_visible_to(repo, id, viewer)`, `change_status_visible_to(repo, change_id, viewer)` | `read_revision(req, now_ms)`: capability `Read`; payload = the 32-byte `ChangesetId`; every mutation path of the revision must be in the leaf's path scope, otherwise `ChangesetNotFound` |
| Server-side read | `get_revision(repo, id)`, `change_status(repo, change_id)` (unfiltered) | through `store()` |

Move check order: `to == Canonical` (`CanonicalOutsidePromotionQueue`), then visibility (`ChangesetNotFound`), then owner chain (`AuthChainNotDominant`), then the owner-move rule (`RevisionStateMoveInvalid`). A store still writing v1 JSON records refuses moves with `EnvelopeVersionUnsupported`, as for B1 records. Nothing is written on a refusal.

## 3. Canonical binary layout (principle P5)

All integers little-endian; `str` = `u32 len | UTF-8`; trailing bytes refused.

* State tag: `Private` = 1, `Draft` = 2, `Proposed` = 3, `Verified` = 4, `Canonical` = 5; 0 and 6..=255 are not states.
* WAL kind 9 `RevisionStateMoved`: `repo str | changeset_id [32] | to u8 | u32 len | chain | moved_at_ms u64`. Binary only (no v1 JSON form); an unknown state tag is `CodecRefusal::UnknownTag { field: "revision state" }`.
* `RevisionStateMovePayload`: exactly `changeset_id [32] | to u8` (33 bytes); anything else, or an unknown tag, is `EnvelopeMalformed`.
* Checkpoint v2: the revision section of B1 now holds kind 7, 8, or 9 records.
* State root: kind 9 records join the revision part of the root (B1) with digest input `u64 repo len | repo | changeset_id | tag | chain | moved_at_ms`; stores without revision records keep every existing root.

## 4. Acceptance

| Acceptance (issue #28) | Test |
|---|---|
| Over random operation sequences no revision moves backwards | `b4_property_random_operation_sequences_never_move_a_revision_backwards` (store: 12 seeded cases of 40 random admissions, joins, moves by any chain to any state, reopens, and checkpoint-compact-reopens, checked against a model, under the `EveryCommit` and group-commit fsync policies); `b4_property_forged_record_sequences_never_move_a_revision_backwards` (ledger: 200 seeded cases of 60 raw records including forged moves, rebuilt from the log); `b4_replay_refuses_a_forged_move_to_verified`; `b4_property_random_move_sequences_never_move_backwards` (core: 2000 cases of 32 moves) |
| A `Private` revision is invisible to every key outside its owner chain | `b4_private_revision_is_invisible_to_every_key_outside_its_owner_chain` (read, change status, parent, marker, and move, for the delegation tree and 200 random chains, after replay and a checkpoint); `b4_api_private_revision_is_invisible_outside_its_owner_chain_with_real_f1_chains`; joins: `b4_joining_identical_content_grants_no_ownership_of_a_private_revision` (also after replay and a checkpoint), `b4_api_joining_identical_content_grants_no_ownership_of_a_private_revision` |
| Any move to `Canonical` outside the promotion queue is refused | `b4_any_move_to_canonical_outside_the_promotion_queue_is_refused`; `b4_api_move_to_canonical_outside_the_promotion_queue_is_refused` (including a grant with `Publish` and `CanonicalViaPromotionQueue`); `b4_owner_moves_never_reach_verified_or_canonical` |

Also: `b4_state_move_records_round_trip_and_malformed_bytes_are_refused_typed`, `b4_state_tags_round_trip_and_unknown_tags_are_not_states`, `b4_every_allowed_move_raises_the_rank_and_every_other_pair_is_refused`. The B1 prune tests now share the orchestrator's revision (`Private -> Draft`) before checking that other chains are refused for dominance, since a `Private` revision is now unknown to them.

Red before green: each acceptance test was run against the B4 commit with one mutation that removes the behaviour it proves (`evidence/b4-revision-states/red-green/red.txt`), and fails; `green.txt` holds the passing runs. The join tests (review of PR #88) were committed before their fix and fail on the earlier implementation (`red-join.txt`); so was the replay test `b4_replay_refuses_a_forged_move_to_verified` (`red-replay.txt`).

## 5. Limits and deviations

* **Grant default.** Section 5.3 says the grant sets the default between `Private` and `Draft`. F1's link caveats have no such field, so every admission starts `Private` and the owner moves it to `Draft`. Adding the default needs a new F1 caveat field and link version; it is not part of B4.
* `Verified` is not reachable yet: it is recorded when claims (B3) and required-action receipts (E1) are discharged on the exact tree. `Canonical` is reached only by the promotion queue (E2), which does not exist yet; `CanonicalPromoted` (the canonical reference head) is unchanged and does not consult revision states.
* An identical-content admission from a chain that may not see the existing `Private` revision joins it (B1 identity covers content only) and reports `joined_existing_revision`. That reveals only that the same content already exists under the change (which the joiner already holds); the joiner gains no ownership, cannot read the owner's witnesses or attestations, and cannot publish the revision.
* The cost of that restrictive reading: a joiner outside the owner chain cannot read, name as a parent, or mark the revision it submitted itself until the owner shares it. The reverse exposure remains: when the owner publishes, every joiner's attestation (its authorship) becomes visible with the revision without that joiner's consent; this matters only for a joiner the owner could not already see (a change-scope joiner outside the owner's subtree). Low.
* Kind 9 records are not signed, so a forged owner move (for example publishing a `Private` revision to `Draft`) written straight into the WAL and resealed would apply on replay; it can never reach `Verified` or `Canonical` or move backwards. Signing state moves and verifying the mover at replay is issue #89. Replay does not re-verify kind 7 and 8 signatures either.
* Change-existence oracle (B1, low): when every revision of a change is another owner's `Private` revision, a chain that neither descends from the creating chain nor names the change gets `AuthChangeOutOfScope` where an unknown change would admit it as creator. `ChangeId`s are 16 random bytes, so this needs the ID.
* Upgrade: revisions admitted before B4 replay as `Private` (no kind 9 record), so after the upgrade they are invisible to non-owners until an owner moves them. This fails closed.
* Store-level `get_revision` and `change_status`, and `SynapseService::store()`, are unfiltered server-side reads; callers acting for an agent use the `_visible_to` reads or `read_revision`. Subscriptions, search, and predictions (section 5.7) do not exist yet and must filter the same way when they are built.
* Revision reads are not snapshot-bounded yet (as in B1).
* No performance figures: B4 has no hot-path acceptance, and none were measured.
