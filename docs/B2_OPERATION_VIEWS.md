# B2: Operation views, undo, plain and final discard

ADR 0003 section 9 step B2 (issue aien-dev/synapse#30), section 5.4 "Operation log and undo": every repository has an operation log, every operation produces a view, undo restores an earlier view, and facts are never undone.

Code: `crates/synapse-store/src/operation.rs` (operations, view fold, undo rules, store API), `crates/synapse-store/src/codec.rs` (WAL kind 12), `crates/synapse-store/src/revision.rs` (record digest, ledger log), `crates/synapse-api/src/lib.rs` (`undo`, `discard`, `revoke_link`, `UndoPayload`, `DiscardPayload`). Tests: `crates/synapse-store/src/operation_tests.rs` (`b2_*`), `crates/synapse-api/tests/b2_operation_views.rs` (`b2_api_*`). Evidence: `evidence/b2-operation-views/`.

## 1. Model

* **Operation log.** The revision records already in the WAL are operations with an actor chain: admissions (kinds 7 and 11), obsolescence markers (kind 8), state moves (kind 9). B2 adds WAL kind 12, `ViewOperationRecorded`, carrying a `ViewOperation`: `Undo { target, actor }`, `Discard { changeset_id, final_discard }`, `Revoke { revoked }`, with the actor chain and the server time. No separate log is kept: the log is the WAL, so replay, checkpoints and compaction carry it like every other revision record.
* **View.** The references of one repository after an operation: for every change, its visible heads (an admitted revision in effect that no marker in effect names as predecessor and no discard in effect names), the discarded revisions (`true` for a final discard), and conflict data. `View::digest` is a two-level Merkle root (`SYNAPSE_VIEW_V1`, per change `SYNAPSE_VIEW_HEADS_V1`), so two views compare in one step. `SynapseStore::view`, `view_at(seq)`.
* **Revision states (B4) are not references.** They stay facts of the revision; undo never moves a state backwards and the view does not contain them. `ChangeStatus` stays the object history (every revision and marker ever admitted).

## 2. Rules

* **Undo.** An undo to operation `T` disables every operation of the repository after `T` (whole undo), or only those whose actor chain is or descends from `actor` (per-actor undo). An operation is in effect unless an undo in effect disables it. An undo only reaches earlier operations, so one pass from the newest operation decides every operation after every undo that could reach it.
  * A whole undo to `T` gives back exactly the view of `T`.
  * Undoing an undo (an undo to the operation just before it) re-enables what it disabled, so undo is undoable.
  * Undo changes references only. No object, blob or record is deleted.
* **Who may undo what.** The undoer's chain must be, or dominate, the actor chain of every operation the undo reaches (`AuthChainNotDominant`). Through the API the request chain must also grant `Undo` (`AuthCapabilityDenied`).
* **Facts are never undone.** An undo that reaches a revocation or a final discard is refused (`UndoIrreversible`). An undo that stops after the fact, or a per-actor undo whose filter excludes it, is fine.
* **Discard.** A discard removes a revision from the view. Only a chain that owns the revision (is or dominates the chain of its first admission) may discard it (`AuthChainNotDominant`); an unknown revision is `ChangesetNotFound`. A plain discard is undoable. A final discard is the owner's choice to give up undo; a revision already finally discarded cannot be discarded again (`DiscardInvalid`). Through the API a discard needs `Propose`.
* **Revocation.** `SynapseService::revoke_link(revoked, by, now)` is the operator path. Checks, in order, before anything is written:
  * `by` must be or dominate `revoked` (`AuthChainNotDominant`).
  * The leaf link must have been granted (`AuthChainBroken`).

  The store then writes the revocation as a kind 12 fact. The policy enforcer revokes the leaf link at that same sequence, so every chain through it is `AuthGrantRevoked` from then on.
* **Conflicts are data.** A per-actor undo can remove an admission that another actor's later marker or discard names. That operation stays in effect and its sequence is listed in `View::conflicts` (and `ViewOutcome::conflicts`); nothing is dropped. Undoing the undo resolves it.
* **Admission equals replay.** The store checks an undo against the sequence it is written at (`checked_at`, `WalSequenceGap` otherwise) with the same function replay uses. A kind 12 record written without the store has no effect on replay, and `view_replay_report` counts it by reason. Such records are:
  * an undo reaching an operation its actor may not undo, or reaching a fact;
  * a discard by a non-owner;
  * a revocation by a chain that does not dominate the revoked link.

## 3. Kind 12 layout

`codec v2 | kind 12 | op | chain path (u32 len | core encoding) | recorded_at_ms u64`, with `op`:

* `1 | repo str | target u64 | 0` or `1 | repo str | target u64 | 1 | chain path` (undo, whole or per actor)
* `2 | repo str | changeset_id [32] | final u8 (0 or 1)` (discard)
* `3 | repo str | chain path` (revocation)

An unknown operation tag, actor flag, or final flag is `UnknownTag`. Checkpoints accept kind 12 in the revision section. The state-root record digest covers every field (`ViewOperation::digest_bytes`). Kind 12 needs the binary codec: a store still writing v1 JSON refuses it (`EnvelopeVersionUnsupported`), like every envelope v2 record.

## 4. Acceptance

| Acceptance (issue #30) | Test |
|---|---|
| Undo to `T` restores the exact view digest of `T` (property, across replay and compaction) | `b2_property_undo_to_t_restores_the_view_of_t_across_replay_and_compaction`: 6 rounds of 40 random admissions, rewrites, plain and final discards, revocations, whole and per-actor undos, and undos of undos. Every admitted whole undo and every undo of an undo matches the recorded digest. Every refusal writes nothing. All recorded digests still match after reopen, after `checkpoint_and_compact`, and after a strict reopen. |
| Undo is undoable | Property above; `b2_per_actor_undo_leaves_other_actors_intact`; `b2_api_undo_requires_the_undo_capability` |
| Per-actor undo leaves other actors intact | `b2_per_actor_undo_leaves_other_actors_intact`, `b2_per_actor_undo_records_conflicts_with_other_actors_markers` |
| Undo of a revocation or final discard is refused | `b2_undo_of_a_revocation_or_a_final_discard_is_refused`, `b2_api_final_discard_can_never_be_undone`, `b2_api_revocation_is_a_fact_and_is_enforced` |
| Undo of another actor's work needs a dominating chain | `b2_undo_by_a_non_dominating_chain_is_refused`, `b2_api_undo_and_discard_of_another_actor_need_a_dominating_chain` |

Also covered:

* `b2_forged_view_operations_change_nothing_on_replay`: four forged kind 12 records, counted by reason, survive compaction as no-ops.
* `b2_kind_12_codec_round_trips_and_refuses_unknown_tags`.

Red before green: `evidence/b2-operation-views/red-green/red.txt` holds 14 mutations from `run.sh`, one per behaviour, and each turns its tests red. `green.txt` holds the passing runs.

The 14 behaviours:

* undo effect;
* the fact rule;
* undo dominance;
* the actor filter;
* replay discard check and replay revocation check;
* conflict data;
* final discard repeat;
* store revocation dominance;
* record digest coverage;
* checkpoint kinds;
* ledger log;
* the API `Undo` capability;
* API revocation enforcement.

## 5. Limits and deviations

* **No window or GC.** ADR 0003 bounds the undo window per owner and lets K1 GC release objects outside it. Neither exists yet: any earlier sequence is a valid target and nothing is released (K1).
* **Grants and revocations are not rebuilt at open.** The policy enforcer's grant table lives in memory, as before B2. The kind 12 revocation fact is durable in the WAL, but a reopened `SynapseService` does not yet re-apply it to the enforcer.
* **No agent signature in the record.** A kind 12 record carries the actor chain but no agent signature over the operation. The API request is signed and verified at admission, but replay cannot check the signer. The replay rules make a forged record a no-op only when its chain may not perform it; a forged record naming a chain that may perform it is indistinguishable. Kinds 7, 8, 9 and 11 carry a signature replay can verify; kind 12 does not, so the WAL seal from #101 (`open_sealed`) is what protects it, and a signed operation statement is follow-up work.
* **Re-admission of an undone revision.** Submitting the same envelope again returns its first admission (B1 idempotency), which stays undone in the view. To restore it, undo the undo.
* **Conflicts are computed, not stored.** Conflict data is recomputed from the log by every view fold.
* **Other facts.** Canonical promotions, accepted receipts, and erasures join the fact list when E2, E1, and M2 create them. Discarding a `Canonical` revision has no extra rule, since no revision can be `Canonical` before E2.
* **Revocation scope.** A revocation is recorded in the log of the service's repository; links are per repository.
* **No performance figures.** View folds are linear in the repository's operations. B2 has no hot-path acceptance and nothing was measured.
