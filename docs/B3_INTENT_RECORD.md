# B3: IntentRecord and Claims

ADR 0003 section 9 step B3 (issue aien-dev/synapse#31), section 5.2 "Intent as data, not prose": the free-text `intent_summary` of envelope v2 content is replaced by a machine-structured `IntentRecord`.

Code: `crates/synapse-core/src/intent.rs` (types, canonical codec, rules), `crates/synapse-core/src/revision.rs` (`RevisionIntent`, content version 3), `crates/synapse-store/src/revision.rs` (admission), `crates/synapse-store/src/lib.rs` (replay presence check and retention of the context blob), `crates/synapse-api/src/lib.rs` (`submit_revision` scope). Tests: `intent::tests` in `synapse-core`, `b3_*` in `synapse-store` `revision::b4_tests`, `b3_api_*` in `crates/synapse-api/tests/b1_chained_revisions.rs`. Evidence: `evidence/b3-intent-record/`.

## 1. Model and rules

* **`IntentRecord`** = `kind` (closed `IntentKind`: `Fix`, `Feature`, `Refactor`, `Revert`, `Merge`, `ResolveConflict`, `Format`, `DependencyUpdate`, `Generated`), optional `task` (`TaskRef`: a tracker issue `repo` + `number >= 1`, or a ledger lane of 1..=64 bytes of `[a-z0-9._-]` starting with `[a-z0-9]`; never free text), `claims`, `footprint`, `supersedes`, optional `context`.
* **Claims.** `Claim` is one of `ActionPasses { action }` (32-byte action digest; `synapse_evidence::EvidenceActionDigest` until E1 defines `ActionDigest`), `InterfaceUnchanged { module }` (a repository path), `BehaviourUnchanged`, `RevertsRevision { revision }`. Every `ClaimKind` maps to exactly one `PredicateType` (`ActionResult`, `InterfaceEquivalence`, `BehaviourEquivalence`, `ExactRevert`), each with a stable name (`synapse.predicate.<name>.v1`); the mapping is a bijection. Discharging claims with receipts is E1 and E2; B4 already refuses an owner move to `Verified`.
* **Footprint.** Path prefixes with the F1 `PathScope` segment rule: an entry covers itself and every path below it after a `/`. Canonical form: 1..=256 valid repository paths, strictly ascending, none covering another. Every mutation path must be covered (`MutationOutsideFootprint`). A content-rule check, so it holds for every signed envelope wherever it is validated.
* **Footprint inside `Propose` scope.** Through the API the request scope of a revision is exactly its footprint, so F1 checks every footprint entry against the chain's path scope (`AuthPathOutOfScope`). Since an F1 prefix covering a footprint entry covers every path below it, this also covers every mutation.
* **Supersedes**: strictly ascending `ChangesetId`s, at most 256. Obsolescence markers (B1) stay the authority on replacement; `supersedes` is the declared intent.
* **Context**: the `BlobDigest` of a machine-readable rationale blob. Admission needs it provided (digest checked) or already stored (`BlobNotFound`); it is written with the revision's new blobs, required present at replay, and kept by compaction like a mutation blob. It is never part of a decision rule.

## 2. Content versions and canonical layout

`RevisionContent.intent` is a `RevisionIntent`: `Summary(String)` encodes as content version 2 (B1, unchanged byte for byte), `Record(IntentRecord)` as content version 3. Both use the `SYNAPSE_CHANGESET_V2\0` domain; the version is the first content field, so the two never share a `ChangesetId`. Any other version is `EnvelopeVersionUnsupported`.

Version 3 content: `version u16 = 3 | change_id [16] | base_tree [32] | u32 n | parent [32]*n | u32 m | (path str | op)*m | intent record`, with the record:

`kind u8 (1..=9) | task | u32 n (<= 64) | claim* | u32 n (<= 256) | path str* | u32 n (<= 256) | id [32]* | context`

* `task` = `0` | `1 | repo str | number u64` | `2 | lane str`
* `claim` = `1 | action [32]` | `2 | module str` | `3` | `4 | revision [32]`; claims strictly ascending by these bytes
* `context` = `0` | `1 | blob [32]`

All integers little-endian, `str` = `u32 len | UTF-8`, every count checked against the bytes that remain before anything is reserved, and any encoding that is not canonical (unknown tag, order, covering footprint entries, bad path or lane, issue 0) refused with `EnvelopeMalformed`.

## 3. Where free text is refused

* `SynapseStore::admit_revision` (agent envelopes, every path that admits one) refuses content version 2 with `IntentRecordRequired` before any idempotency, join, parent, or blob check, and writes nothing. `SynapseService::submit_revision` refuses it the same way before authorization.
* Replay, checkpoints, and compaction keep applying B1-era version 2 records unchanged, so every existing v2 `ChangesetId` still resolves (`b3_free_text_envelope_is_refused_at_admission_and_b1_records_still_replay`; golden v2 ID computed on main 2f06c45 in `b3_content_version_2_keeps_its_bytes_and_changeset_id`).
* Server-derived revisions (B5) are not agent envelopes. The B5 rules are unchanged: a rebase keeps its input's intent (so a version 3 input stays version 3), and a T0 merge still writes its fixed version 2 summary, so recomputation at replay of existing derivations gives the same digests.

## 4. Acceptance

| Acceptance (issue #31) | Test |
|---|---|
| Envelopes with only free text are refused | `b3_free_text_envelope_is_refused_at_admission_and_b1_records_still_replay` (store), `b3_api_free_text_only_envelope_is_refused` (API, real F1 chain) |
| Every claim kind maps to a predicate type | `b3_every_claim_kind_maps_to_a_predicate_type` |
| A mutation outside the declared footprint is refused | `b3_mutation_outside_declared_footprint_is_refused` (core, signed envelope and decoded bytes), `b3_api_mutation_outside_declared_footprint_is_refused` (API) |

Also: `b3_api_footprint_must_lie_inside_the_propose_scope`, `b3_intent_record_round_trips_and_non_canonical_bytes_are_refused`, `b3_context_blob_is_stored_retained_and_required`, `b3_content_version_2_keeps_its_bytes_and_changeset_id`, and `b3_sealed_replay_refuses_an_edited_intent_record` (the issue #101 seal covers the whole envelope, so a rewritten log that edits an admitted intent kind, claim, or footprint does not verify on sealed replay; without a seal key the same edit applies, which shows the seal is what refuses it).

Red before green: `evidence/b3-intent-record/red-green/red.txt` holds one mutation per behaviour (free-text refusal, footprint containment, request scope = footprint, context blob stored, context blob retained, predicate mapping, content version, seal coverage of the intent), each turning its test red; `green.txt` holds the passing runs. With the API's own free-text check removed, the API test stays green because the store refuses the same envelope: the store is the authority, the API check is an early exit.

## 5. Limits and deviations

* **Envelope v1 is not touched.** The legacy `submit` path (`ChangesetEnvelope`, free-text `intent_summary`) is the human-era adapter kept until Phase 8 and removed by I1 (ADR 0002). Its free-text envelopes are still admitted; B3's refusal covers the native envelope v2.
* The footprint quota charged by breadth, footprint subscriptions, and predictive conflicts are F2. Symbol footprints ("later, symbols") are not in B3.
* Kind-specific rules (for example a `Revert` that must carry `RevertsRevision`) are not enforced; any kind may carry any claims. A change that claims nothing beyond the required actions is valid (ADR 0003 section 5.2).
* `task` is optional so that work with no tracker item can still be described; when present it is typed.
* The M1 secret scan (PR #108 at the time of writing) runs on mutation blobs; the context blob now exists and needs the same scan once both land.
* No performance figures: B3 has no hot-path acceptance and none were measured.
