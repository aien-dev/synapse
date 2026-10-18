# B5: DerivationAttestation for Server-Derived Revisions

ADR 0003 section 9 step B5 (issue aien-dev/synapse#29), row 9. Sections 5.1 (`AdmissionWitness`, `DerivationAttestation`), 5.3 (lazy rebase), 5.5 (promotion merges) and 5.8 (every admitted mutation is signed): a revision the server produces rather than an agent carries a `DerivationAttestation` signed by the server machine key that the repository identity document (E0) registers as `server_key`. It names the inputs and the rule; every rule is deterministic, so a replica recomputes the output and refuses an attestation that does not match. No derived revision claims an agent signature it does not have.

Code: `crates/synapse-core/src/derivation.rs` (types, codecs, the one recomputation `derive_revision_output`), `crates/synapse-core/src/revision.rs` (witness signer tag 2), `crates/synapse-store/src/revision.rs` (`check_derivation`, `admit_derived_revision`, `verify_revision_log`), `crates/synapse-store/src/{lib,codec}.rs` (WAL kind 11, replay, checkpoint, state root), `crates/synapse-radicle/src/identity.rs` (`IdentityLog` as `ServerKeyRegistry`), `crates/synapse-api/src/derivation.rs` (tree store as `DerivationTrees`, `derive_revision`, `admit_derived_revision`, `verify_revision_records`, `verify_revision_log`). Tests: `crates/synapse-api/tests/b5_derivation_attestation.rs`, `crates/synapse-store/tests/b5_derived_record.rs`, unit tests in `crates/synapse-core/src/derivation.rs`. Evidence: `evidence/b5-derivation-attestation/`.

## 1. Model and invariants

* **Rules.** `DerivationRule::Rebase` (path level) and `DerivationRule::Merge { tier: MergeTier::T0Path }` (the path-level merge tier) and `MergeTier::T1Region` (the region merge tier, added by D1: [D1_MERGE_TIER_T1.md](D1_MERGE_TIER_T1.md)), and `DerivationRule::Revert` (added by D2: [D2_CONFLICT_TERMS.md](D2_CONFLICT_TERMS.md)). The derived-file action rule (`ActionDigest`) is reserved and not decodable yet (section 5).
* **Rebase.** Inputs exactly `[Revision(r), Tree(onto)]`. The output keeps `r`'s `ChangeId`, parents, mutations and intent, takes `onto` as base, and its tree is `r`'s mutations applied to `onto`. Refused when `onto` is already `r`'s base. Since D2, when a path `r` mutates is equal to, or an ancestor or descendant of, a path that differs between `r`'s base and `onto`, the rebase is no longer refused: its tree is the conflict sum `onto + tree(r) - base(r)`, its mutations turn `onto` into that tree, and paths that do not cancel are recorded as conflict terms ([D2_CONFLICT_TERMS.md](D2_CONFLICT_TERMS.md)). Such a rebase is refused when the sum equals `onto` (nothing to rebase).
* **Merge tier T0.** Inputs `[Tree(base), Revision(a1), ..., Revision(an)]`, n >= 2, revisions strictly ascending by `ChangesetId` (the canonical merge order). Every `ai` must be based on `base`, and no two may touch colliding paths (equal or one below the other). The output's parents are the `ai` in that order, its mutations are their union sorted by path, its intent is `merge tier T0 of {n} revisions`, and its `ChangeId` is the first 16 bytes of `SHA-256("SYNAPSE_DERIVED_MERGE_CHANGE_V1\0" || base || u32 n || a1 || ... || an)`, so the same merge always gets the same identity.
* **Attestation.** `DerivationAttestation` = repository, rule, inputs (1..=256), output `ChangesetId`, output `TreeDigest`, server key, Ed25519 signature (strict) over `"SYNAPSE_DERIVATION_SIGN_V1\0" || body`. Its digest is `SHA-256("SYNAPSE_DERIVATION_ATTESTATION_V1\0" || encoding)`. It carries no time, so a derivation is a pure function of its inputs and key, and a second presentation of one attestation is a replay.
* **Derived revision** = `RevisionContent` + `DerivationAttestation`; the attestation must name the content's `ChangesetId`. It carries no `AuthorshipAttestation`. The input revisions keep their own agent signatures.
* **Witness.** Admission records an `AdmissionWitness` with signer tag 2 (`WitnessSigner::Server`: server key, the attestation's signature, the attestation digest) instead of an agent signature; its idempotency key is the attestation digest. `StoredRevision.derivations` lists the attestations; `attestations` (agent) stays empty for a revision only the server produced.
* **One recomputation.** `derive_revision_output` is the only implementation of the rules. The server uses it to derive, admission uses it to check, and replay verification uses it to recompute, so the three cannot drift apart.
* **Server key registration.** `ServerKeyRegistry::registered_server_key(repo, at)` returns the `server_key` of `repo`'s identity document in effect at `WalSeq` `at` (`ServerKeyLookup::Registered`), `NoDocument` before genesis, or `OtherRepository` when the registry holds another repository's documents; `IdentityLog` implements it with E0's `server_key_at` and answers only for its own repository. The repository is part of the question, so one repository's identity log never vouches for another repository's derivations, even when both register the same server machine key. An attestation is checked at the sequence of its own admission, so a rotation does not invalidate earlier derivations and an old key is refused after the rotation.

## 2. Checks, in order

At admission (`SynapseStore::admit_derived_revision`, sequence `at` = the next `WalSeq`) and at replay (`verify_revision_log`, sequence = the record's own):

| Check | Refusal |
|---|---|
| Content rules; attestation names this content; input count 1..=256; server key is a valid Ed25519 point and the strict signature verifies | `DerivationSignatureInvalid` (count: `DerivationInputMismatch`) |
| The identity documents checked belong to the attestation's repository | `DerivationIdentityRepoMismatch` |
| Server key equals the identity document's `server_key` at the sequence | `DerivationServerKeyUnregistered` |
| Attestation digest not already admitted in this repository | `DerivationAttestationReplayed` |
| Inputs fit the rule's shape and order; every named revision is admitted; every named tree is held | `DerivationInputMismatch` |
| The rule applies (rebase target differs from the base, merge revisions share the base, a colliding rebase or a revert changes something) and the recomputed `ChangesetId` and `TreeDigest` equal the attested ones | `DerivationRecomputeMismatch` |

Admission then applies B1's checks: path-count limit, join rule under the asking or proposing chain (`AuthChangeOutOfScope`), parents (`ParentChangesetNotFound`), and every upserted blob already visible (`BlobNotFound`); nothing is written on any refusal. The record must then be written at exactly the sequence `at` it was checked at: a writer whose next sequence differs is refused before anything is written, and a frame that lands at another sequence anyway is not applied and poisons the store until it is reopened (`WalSequenceGap` in both cases, a real check in every build profile). The API also refuses an attestation for another repository (`AuthCrossRepoDenied`).

Replay verification walks the revision records in sequence order with a fresh ledger: kind 7 records are checked with `ChangesetEnvelopeV2::validate` (so a derived revision dressed in a borrowed agent attestation is `AuthSignatureInvalid`), kind 8 with `ObsolescenceMarker::validate`, kind 11 with the checks above; sequences must strictly ascend (`WalSequenceGap`) and any other kind is `WalRecordMalformed`. Refusals keep their code and prefix the message with the record's sequence.

## 3. Canonical binary layout (principle P5)

Conventions as in B1 (little-endian, `str` = `u32 len | UTF-8`, lengths checked before allocation, trailing bytes refused, core decoders refuse with `EnvelopeMalformed`).

* Rule: `1` (rebase), `2 | tier u8` (merge; tier `0` = T0, `1` = T1) or `4` (revert, D2). Tag 3 is reserved for the derived-file action.
* Input: `1 | changeset_id [32]` (revision) or `2 | tree_digest [32]` (tree).
* Attestation: `repo str | rule | u32 n (1..=256) | input*n | output_changeset [32] | output_tree [32] | server_key [32] | signature [64]` (signed bytes = domain tag + all but the signature).
* Derived revision: `u32 content_len | content | attestation`.
* Witness signer tag 2: `2 | server_key [32] | signature [64] | attestation_digest [32]`, in the B1 witness layout.
* WAL kind 11 `DerivedRevisionAdmitted`: `u32 len | derived revision | u32 len | chain | admitted_at_ms u64`. Binary only (no v1 JSON form), no inline blobs (every blob is already visible). Kinds 9 and 10 are taken by open PRs (B4 #88 and the Git bridge cut 2 of #48).
* Checkpoint v2 revision section and state root: as in B1, now holding kind 7, 8 and 11 records. The state root's record digest covers kind 11 records, so a checkpoint that lost one is `CheckpointCorrupt` on load (red case in the evidence).

## 4. Acceptance

| Acceptance (issue #29) | Test |
|---|---|
| A replica recomputes every derived revision from the inputs and rule its attestation names and gets the same digests | `b5_replica_recomputes_every_derived_revision_and_gets_the_same_digests` (rebase and T0 merge equal independently built trees; reopen from the WAL and after a checkpoint; recomputation on the replica is byte-identical) |
| An attestation naming different inputs is refused at admission and at replay | `b5_attestation_naming_different_inputs_is_refused_at_admission_and_replay` (another real revision, an unknown revision, an unknown tree) |
| An attestation naming a different rule is refused at admission and at replay | `b5_attestation_naming_a_different_rule_is_refused_at_admission_and_replay` |
| An attestation by an unregistered server key is refused at admission and at replay | `b5_unregistered_server_key_is_refused_at_admission_and_replay` (a rogue key, a delegate's key, the old key after a rotation; the earlier derivation still verifies) |
| A derived revision presented with an agent signature it does not have is refused | `b5_derived_revision_presented_with_an_agent_signature_it_does_not_have_is_refused` (the input's attestation as is and re-pointed, at admission and as a replayed kind 7 record) |

Also: `b5_attestation_signed_by_another_key_is_refused_at_admission_and_replay`, `b5_identity_log_of_another_repository_is_refused_at_admission_and_replay` (same server key, same delegates, other repository: refused at admission and at replay), `b5_derivation_written_at_another_sequence_than_it_was_checked_at_is_refused` (typed refusal, not applied, store poisoned), `b5_replayed_attestation_is_refused_at_admission_and_replay`, `b5_recomputation_that_disagrees_is_refused_at_admission_and_replay`, `b5_derived_revision_records_round_trip_and_malformed_bytes_are_refused_typed`, and the core unit tests (codec, signature binding, server witness, path collision). Test keys and identifiers are derived from labels by SHA-256; no literal is used as key material.

Red before green: each acceptance test was run against the B5 commit with one mutation that removes the behaviour it proves (`evidence/b5-derivation-attestation/red-green/red.txt`, 11 cases), and fails; `green.txt` holds the passing runs. The two review fixes (repository-bound key lookup, release-mode sequence check) were written test first: `review-fixes.txt` holds their red runs (the other repository's log was accepted; the misplaced record panicked in a debug build and was admitted in a release build) and green runs.

## 5. Limits and deviations

* **Derived-file rule not implemented.** The `ActionDigest` rule for derived files (lockfiles) needs registered executors and action receipts (E1, E3); rule tag 3 is reserved and refused by the decoder. Rebase, revert (D2) and merge tiers T0 and T1 are implemented.
* **When the server derives is not decided here.** B5 provides derivation, admission and verification. Lazy rebase policy (who may ask, the obsolescence marker that accompanies an admitted rebase, quota charging: D4) and the promotion queue (E2) are later steps.
* **Identity log in memory.** E0's identity log is not persisted yet, so the caller passes it to admission and to replay verification. Replay verification is an explicit call (`verify_revision_log`) after reopening: the store's own replay rebuilds state from the records without the identity log or the tree store.
* **Open and checkpoint load do not verify kind 11 records.** They trust the store's own WAL, as for kind 7; a caller that skips `verify_revision_log` gets no error. A later step could make `open` take a `ServerKeyRegistry` or record "verified up to seq N".
* **Rotation sequence not authenticated (E0 scope).** `applied_at` is supplied by the caller and is not covered by the edit signatures or written to the store WAL, so a replica must learn rotation sequences from the server, which limits what replica verification proves today.
* **Re-signing after rotation.** After a rotation the new key can re-sign a derivation the old key already attested; the digest differs, so it is admitted again as a second witness on the same revision. Each admission is a valid server statement at its own sequence.
* **Replay verification checks signatures and recomputation, not authority.** It does not recheck the join rule, quotas or blob visibility, which depend on F1 grants and blob state at admission time.
* **Conservative T0.** Two revisions that touch the same path, even identically, do not merge at T0.
* **B4 interaction.** Built against main. B4 (#88, open) adds revision states and WAL kind 9 to the same store files (`revision.rs`, `codec.rs`, `lib.rs`); whichever merges second needs a rebase, and the checkpoint kind list and state-root digest must then cover 7, 8, 9 and 11. A derived revision's initial B4 state is not defined here.
* **No performance figures:** B5 has no hot-path acceptance, and none were measured.
