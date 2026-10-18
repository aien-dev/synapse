# D2: First-class conflict terms

ADR 0003 section 9 step D2 (issue aien-dev/synapse#40), section 5.3: a conflict is data. When a rebase meets a path that changed on both sides, the derived revision records the conflict as a typed term in the tree instead of being refused. A later rebase or a revert sums with that term, so conflicts cancel when their sides cancel.

Code:

* `crates/synapse-core/src/conflict.rs`: `EntryState`, `ConflictTerm`, `ConflictKind`, `reduce`, `sum_trees`, `diff_mutations`, the `ConflictTrees` node access.
* `crates/synapse-core/src/derivation.rs`: the rebase rule uses the sum when paths collide; `DerivationRule::Revert` (rule tag 4); tier T1 refuses a recorded term.
* `crates/synapse-core/src/lib.rs`, `revision.rs`, `tree.rs`: `MutationOp::Conflict`, its encodings, tree entry tag 5, refusal codes `ConflictNotDerived` and `TreeConflicted`.
* `crates/synapse-store/src/revision.rs`, `codec.rs`: the `Verified` gate, the v1 codec refusal.
* `crates/synapse-api/src/tree.rs`: conflict entries in the C1 tree store, listings refuse them, `TreeAlgebra`, the accounting fix (section 6).
* `crates/synapse-api/src/derivation.rs`: Git blob OIDs and base-tree blobs for sums; `revision_tree`, `tree_conflicts`, `materialize_tree`, `check_promotion`.

Tests:

* `conflict::tests::d2_*` in synapse-core (7 tests, over an in-memory node store).
* `crates/synapse-api/tests/d2_conflict_tree.rs`: conflict entries in the real tree store.
* `crates/synapse-api/tests/d2_conflict_terms.rs`: derivation, admission, replay and replica verification through the service.
* `crates/synapse-api/tests/d2_conflict_heap.rs`: accounting with a counting allocator (its own binary).
* `crates/synapse-api/tests/b5_derivation_attestation.rs`: the colliding rebase that B5 refused now records a content term.

Evidence: `evidence/d2-conflict-terms/`.

## 1. The model

An **entry state** is the whole state of one tree entry: `Absent`, `File { mode, blob_digest, size_bytes }` (regular, executable or symlink), or `Dir(TreeDigest)`.

A **conflict term** is a sum of entry states, as in Jujutsu: a sorted multiset of `adds` and one of `removes`, with exactly one more add than remove, and 1 to 32 removes (`MAX_CONFLICT_REMOVES`). Terms are always stored reduced.

**Reduction** is the only rule: remove the multiset intersection of adds and removes. The result does not depend on the order of the terms. If one add and no removes remain, the entry is resolved to that state (absent when it is `Absent`). Two sides that made the same change still form a conflict: reduction cancels a state only against a removed copy of itself, and there is no Git-style "both sides did the same thing" rule. A sum past 32 removes is refused, never truncated.

**Kind**, from the adds, in this order: `ModifyDelete` (some add is `Absent`), `FileDirectory` (some add is a directory), `Mode` (all files, modes differ), else `Content`.

**Tree sum.** `sum_trees(adds, removes)` sums whole trees entry by entry over the Merkle tree:

* equal states cancel before anything is read, so an unchanged subtree is never opened;
* when only directories and absences remain, their entries are summed recursively (an absence counts as an empty directory);
* a conflict entry already in a tree contributes its own terms (added as a whole: its adds add and its removes remove; removed as a whole: the other way round);
* whatever does not reduce to one state becomes a conflict entry.

A rebase of revision `r` onto `o` is `o + tree(r) - base(r)`. A revert of `x` on top of `o` is `o + base(x) - tree(x)`.

**Mutations.** `diff_mutations(from, to)` turns the result back into the path mutations a revision carries, sorted by path: `Upsert`, `Delete`, and `Conflict(term)`. A directory that becomes a file or term is one mutation. A file that becomes a directory writes each leaf. A removed directory deletes each leaf. Applying the mutations to `from` gives `to` exactly; the rules check this (`applied_sum`).

## 2. Encodings

* Entry state: `0` (absent) | `mode tag u8 (1..=3) | blob_digest [32] | size u64` (file) | `4 | tree [32]` (directory).
* Term: `n u8 | n+1 add states | n remove states`. The decoder refuses (`EnvelopeMalformed`) a count outside 1..=32, an unsorted side, a state on both sides, and trailing bytes.
* Envelope v2 / revision content mutation: op tag `3 | term`.
* Tree node entry: tag `5 | name | term`, ordered as a non-directory. The node digest covers the term, so two trees with different terms at one path differ.
* Envelope v1 cannot carry a term: `MutationOp::Conflict` is skipped by serde (the JSON encoder fails), the v1 binary codec refuses it, and v1 validation refuses it (`ConflictNotDerived`).

## 3. Who may record a term

Only derivation rules. An agent-submitted revision (envelope v2) that carries a term is refused with `ConflictNotDerived`. A server-derived revision (B5) carries terms as ordinary content, signed by its attestation, and every replica recomputes them.

## 4. The rules

* **Rebase.** When no path of `r` collides with a path that differs between `r`'s base and `onto`, nothing changes from B5. When paths collide, the output tree is the sum and its mutations turn `onto` into it. The output keeps `r`'s `ChangeId`, parents and intent. Refused (`DerivationRecomputeMismatch`) when the sum equals `onto`.
* **Revert** (rule tag 4, new). Inputs exactly `[Revision(x), Tree(onto)]`. The output tree is `onto + base(x) - tree(x)`, its parents are `[x]`, its intent is `revert of {x}`, and its `ChangeId` is the first 16 bytes of `SHA-256("SYNAPSE_DERIVED_REVERT_CHANGE_V1\0" || x || onto)`. Refused when the result equals `onto`.
* **Merge tier T1** refuses a path where one source records a term and another writes the path differently. T0 still takes the union of mutations, terms included.

When a sum restores a file that only a registered base tree holds (for example, a revert that cancels a term back to the base version), the service hands the bytes to the store as a blob the derivation produced. The store checks the digest and writes the bytes with the derived revision, as D1 does for merged files, so every replica of the log can read them.

## 5. Reading and the gates

* A conflicted tree can always be read: `SynapseService::tree_conflicts(tree)` lists each conflict entry with its path, and a path lookup of a conflict finds no file.
* Every node carries `conflict_count` for its subtree. Whole-tree file listings (`files`, `page_files`, `count_files`, so `materialize_tree`) and Git-shaped diffs refuse a conflicted tree with `TreeConflicted`.
* A resolution is an ordinary mutation at the path: an upsert, a delete, or an upsert below the path (which replaces the term with a directory).
* **Promotion.** The store refuses a move to `Verified` of a revision whose own mutations record a term (`TreeConflicted`). `SynapseService::check_promotion(id)` refuses any revision whose tree holds a term, including one based on a conflicted tree it did not resolve.

## 6. Correction to C1: hash table accounting

The D2 heap test found a C1 bug. The tree store accounted its hash tables by `HashMap::capacity()`, which reports less once deletions leave tombstones. Under heavy eviction, the accounted total dropped below what the tables still held, and the recorded high water passed the bound. The store now accounts each table at the highest capacity it has reached. The failure depends on hash table layout, so it is not certain on every run: with the old accounting restored, the heap test failed 4 of 6 runs in the recorded red run (`red.txt`, `node-table-capacity-not-high-water`) and 6 of 6 in an earlier one; with the fix it passed every run (`green.txt`).

## 7. Acceptance

| Condition (issue #40) | Tests |
|---|---|
| Rebase twice cancels to a plain three-way conflict | `d2_rebase_twice_cancels_to_a_plain_three_way_conflict_and_revert_is_clean` (core); `d2_tree_algebra_over_the_store_round_trips_through_mutations`; `d2_api_rebase_twice_cancels_to_a_plain_three_way_conflict_and_revert_is_clean` (rebasing `c` from B0 to B1, then to B2, equals one rebase onto B2, mutations and tree) |
| Revert returns a clean tree | the same three tests: reverting `c` on the conflicted rebase output gives B1's tree with no conflict entries; admitted, replayed after a reopen, recomputed by a replica |
| Modify/delete, file/directory and mode conflicts round-trip as typed terms | `d2_modify_delete_file_directory_and_mode_conflicts_are_typed_terms`, `d2_typed_terms_round_trip_and_malformed_terms_are_refused` (core); `d2_api_typed_conflict_terms_round_trip_through_the_revision_log` (all four kinds, plus content, through derivation, admission, reopen, checkpoint plus compaction and replica recomputation) |
| Conflicted trees refuse materialization and promotion | `d2_tree_conflict_entries_are_counted_read_and_refused_for_materialization`; `d2_api_conflicted_trees_refuse_materialization_and_promotion` (`materialize_tree`, the store's `Verified` gate, `check_promotion`) |
| Only derivations record terms | `d2_api_agent_revisions_cannot_carry_conflict_terms` (envelope v2 admission, v1 JSON, v1 validation, v1 binary codec) |

Red before green: `evidence/d2-conflict-terms/red-green/run.sh` applies one mutation per behaviour and runs the named tests. Every mutation turns its tests red (`red.txt`); the unmutated tree passes (`green.txt`).

## 8. Limits

* **No merge tier T3.** Promotion merges (section 5.5) do not record conflict terms yet; T0 and T1 still refuse what they cannot merge.
* **Cancellation only.** Identical adds stay a conflict (section 1).
* **Directory states are references.** A term holding `Dir(d)` names a subtree; reading or summing it needs that subtree in the tree store (`DerivationInputMismatch` or a tree store error otherwise).
* **Blobs inside terms are not pinned.** `upsert_blobs` skips conflict mutations, so the blobs a term names are held only because the revisions that wrote them hold them. There is no blob GC yet (K1); GC must count term references.
* **Two promotion gates.** The store gate is content-level (the revision's own mutations). The tree-level gate is `check_promotion`, and the promotion queue (E2) must call it.
* **Canonical moves** are still refused by B4 before the conflict gate is reached.
* **`ResolveConflict` intent** (B3) is not enforced: any revision may resolve a term.
* **No performance measured.** No figure is claimed for sums or diffs.
* `.crumb` files are not recompiled in this branch.
