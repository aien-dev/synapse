# B1: Change Identity, Admission Witnesses, Obsolescence Markers, Envelope v2

ADR 0003 section 9 step B1 (issue aien-spark/synapse#27). Sections 5.1 ("Identity"), 5.3 (rewrites and markers) and 5.8 (change scope): a `ChangeId` names one unit of intended work across all its rewrites and retries and is bound to its **creating chain**; a revision's `ChangesetId` covers its content only; every admission leaves an immutable `AdmissionWitness`; obsolescence markers record which revision replaced which.

Code: `crates/synapse-core/src/revision.rs` (types and codecs), `crates/synapse-store/src/revision.rs` (ledger, admission, markers), `crates/synapse-store/src/{lib,codec}.rs` (WAL kinds 7 and 8, replay, checkpoint, compaction), `crates/synapse-api/src/lib.rs` (`submit_revision`, `record_obsolescence`). Tests: `crates/synapse-store/tests/b1_change_identity.rs`, `crates/synapse-api/tests/b1_chained_revisions.rs`, unit tests in `crates/synapse-core/src/revision.rs`. Evidence: `evidence/b1-change-identity/`.

## 1. Model and invariants

* **Revision content and identity.** `RevisionContent` = `ChangeId`, native base `TreeDigest` (C1), parents (strictly ascending), mutations (non-empty, strictly ascending valid paths), intent summary (1..=4096 bytes). Its v2 `ChangesetId` is `SHA-256("SYNAPSE_CHANGESET_V2\0" || u64 len || content)`. Author, time, repository and idempotency key are excluded, so a rewrite (new content, same `ChangeId`) gets a new `ChangesetId` and identical content from two agents is one revision.
* **Envelope v2** = content + one `AuthorshipAttestation`: repository, `ChangesetId`, author key, `IdempotencyKey`, the agent's time, Ed25519 signature (strict) under `SYNAPSE_AUTHORSHIP_SIGN_V2\0`. The attestation must name the content's ID.
* **v1 is unchanged.** `ChangesetEnvelope` keeps its encoding, signature and ID (`SYNAPSE_CHANGESET_V1\0` domain), so v1 and v2 IDs never collide. v1 records stay in their own map; `get_changeset` resolves only v1 IDs and `get_revision` only v2 IDs.
* **Chains and dominance.** A `ChainPath` is the F1 link digests of a chain, root first (1..=16). Chain A dominates chain B when A is B or a prefix of it; B then descends from A.
* **Admission witness.** Every admission records (repository, `ChangesetId`, signer key and signature, `IdempotencyKey`, admission `WalSeq` = the frame's sequence, server time, chain). The first admission under a `(repository, ChangeId)` fixes the creating chain.
* **Join rule.** A revision under an existing `ChangeId` is admitted only from a chain that descends from the creating chain, or when the leaf grant names that `ChangeId` in its change scope. A grant for any change (`ChangeScope::any`) names none. Otherwise `AuthChangeOutOfScope`.
* **Markers.** `ObsolescenceMarker` (predecessor, successors strictly ascending, at most 256, never the predecessor; signed under `SYNAPSE_OBSOLESCENCE_SIGN_V1\0`): zero successors = pruned, one = rewritten, several = split. A prune needs a chain that is or dominates the creating chain. A rewrite or split needs that, or a chain that is or dominates the chain of the predecessor's first admission (a worker may rewrite its own attempt but not prune it). Otherwise `AuthChainNotDominant`. Predecessor and successors must be revisions of the marker's change (`ChangesetNotFound`); a marker that would close a cycle is `ObsolescenceMarkerInvalid`. Several markers per predecessor are allowed: that is how divergence arises.
* **Live and divergent.** A revision is live while no marker names it as predecessor. More than one live revision of one change is divergence (`ChangeStatus::divergent`).
* **Idempotency** is keyed on (repository, signer key, `IdempotencyKey`): a repeat with the same revision returns the first `WalSeq` and writes nothing; another revision under the same key is `IdempotencyKeyConflict`. Another DID with the same key is its own admission.

## 2. Operations

| Operation | Store | API (F1 chained request, `Propose`) |
|---|---|---|
| Admit | `admit_revision(envelope, blobs, AdmissionAuthority, now_ms)` | `submit_revision(req, blobs, now_ms)`: payload = envelope bytes; `scope.join_change` = its `ChangeId`; `scope.paths` = exactly its mutation paths (so F1 enforces change and path scope); attestation author = request agent; base tree registered or held by the tree store (`BaseTreeNotFound`) |
| Mark | `record_obsolescence(marker, chain, now_ms)` | `record_obsolescence(req, now_ms)`: payload = marker bytes; `scope.join_change` = its `ChangeId`; signer = request agent |
| Read | `get_revision(repo, id)`, `change_status(repo, change_id)` | through `store()` |

Admission check order: envelope (content rules, attestation names the content, signature), idempotency, path-count limit, join rule, parents (an admitted revision, or a v1 changeset, of the same repository), blobs (provided with digest and size, or already visible). Nothing is written on a refusal. A store still writing v1 JSON records refuses both writes with `EnvelopeVersionUnsupported` until its migration checkpoint.

## 3. Canonical binary layout (principle P5)

All integers little-endian; `str` = `u32 len | UTF-8`; every length checked against the bytes that remain before allocation; trailing bytes refused. Core decoders refuse with `EnvelopeMalformed` (`EnvelopeVersionUnsupported` for a content version other than 2).

* Content: `version u16 = 2 | change_id [16] | base_tree [32] | u32 n | parent [32]*n | u32 m | (path str | op)*m | intent str`; `op` = `1 | mode u8 | blob_digest [32] | size u64` or `2`.
* Attestation: `repo str | changeset_id [32] | author_key [32] | idempotency_key [32] | attested_at_ms u64 | signature [64]` (signed bytes = domain tag + all but the signature).
* Envelope v2: `u32 content_len | content | attestation`.
* Chain path: `count u8 (1..=16) | digest [32]*`.
* Witness: `repo str | changeset_id [32] | 1 | author_key [32] | signature [64] | idempotency_key [32] | admission_seq u64 | admitted_at_ms u64 | chain`; tag 2 is reserved for the server-derived signer of B5. Digest = `SHA-256("SYNAPSE_ADMISSION_WITNESS_V1\0" || encoding)`.
* Marker: `repo str | change_id [16] | predecessor [32] | u32 n (<= 256) | successor [32]*n | signer_key [32] | signed_at_ms u64 | signature [64]`.
* WAL kind 7 `RevisionAdmitted`: `u32 len | envelope v2 | u32 len | chain | admitted_at_ms u64 | u32 n | new_blob [32]*n`. Kind 8 `ObsolescenceRecorded`: `u32 len | marker | u32 len | chain | recorded_at_ms u64`. Both are binary only (no v1 JSON form); an embedded value refused by its core decoder is `CodecRefusal::EmbeddedMalformed`. In the segment store a revision's new blobs are stored inline as for v1 ingests; in the `wal.log` layout they are blob files written before the frame.
* Checkpoint v2 content: after the canonical-head section, a revision section `u32 n (>= 1) | (seq u64 | u32 len | kind 7 or 8 record)*n`, sequences strictly ascending and at most the checkpoint sequence. It is written only when revision records exist (an empty present section is refused as not canonical), so checkpoints of stores without revisions keep their exact bytes.
* State root: when revision records are visible at the snapshot, the v1 root hash continues with `"SYNAPSE_STATE_ROOT_REVISIONS_V1\0" | u64 count | (seq u64 | record digest [32])*`; with none, every existing root is unchanged.

The ledger is a pure function of the kind 7 and 8 records in sequence order, so replay, a checkpoint (which keeps the records) and a live store rebuild the same state. Compaction keeps every revision record, every blob a revision references, and every v1 changeset a revision names as parent (no sweep before K1).

## 4. Acceptance

| Acceptance (issue #27) | Test |
|---|---|
| A rewrite keeps `ChangeId` and gets a new `ChangesetId` | `b1_rewrite_keeps_change_id_and_gets_new_changeset_id` |
| Divergence (two live successors) is detected | `b1_divergence_two_live_successors_is_detected` |
| Identical content from two agents of one chain under one `ChangeId` yields one revision with two attestations and two admission witnesses | `b1_identical_content_two_agents_one_chain_one_change_is_one_revision_two_attestations_two_witnesses` (wal.log and segment stores, through replay and a checkpoint) |
| A join from a key outside the creating chain without change scope is refused | `b1_join_from_key_outside_creating_chain_without_change_scope_is_refused` |
| A prune by a chain that does not dominate the creating chain is refused | `b1_prune_by_chain_not_dominating_creating_chain_is_refused` |
| A repeat with the same repository, DID, and `IdempotencyKey` returns the first `WalSeq` | `b1_repeat_same_repo_did_idempotency_key_returns_first_wal_seq` (also after replay and a checkpoint) |
| Every v1 `ChangesetId` still resolves to its record | `b1_every_v1_changeset_id_still_resolves_to_its_record` (both v1 fixtures through the migration checkpoint and reopen; a v1 parent outside retention kept by the revision naming it) |

Also: `b1_revision_records_round_trip_and_malformed_bytes_are_refused_typed`, the core unit tests (`b1_v2_changeset_id_covers_content_only_not_author_or_time`, codec and signature tests), and the API tests with real signed F1 chains (`b1_api_*`).

Red before green: each acceptance test was run against the B1 commit with one mutation that removes the behaviour it proves (`evidence/b1-change-identity/red-green/red.txt`), and fails; `green.txt` holds the passing runs.

## 5. Limits and deviations

* `IntentRecord` (B3), footprints, conflict terms (D2), `DerivationAttestation` and the server-derived witness signer (B5), revision states and visibility (`Private`, `Draft`, ...) are not part of B1. Envelope v2 carries the intent summary of v1; B3 and D2 extend the content under a new content version.
* Envelope v2 has no `evidence_receipts` field: receipts bind to a `TreeDigest` in E1.
* Revision reads are not snapshot-bounded (`min_visible_seq`, `snapshot_seq`) yet; `change_status` reflects the latest state.
* The group-commit `SharedStore` path does not batch revision admissions: they are written one frame at a time through the store.
* Markers are authorized by chain dominance only; the `Undo` capability of B2 is separate.
* No performance figures: B1 has no hot-path acceptance, and none were measured.
