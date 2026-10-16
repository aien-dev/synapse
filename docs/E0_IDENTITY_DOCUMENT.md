# E0: Repository Identity Document

ADR 0003 section 9 step E0 (issue aien-spark/synapse#26). Section 5.5 "Trust root": delegates and threshold live in a Synapse identity document that mirrors the Radicle `refs/rad/id` delegates and threshold; changing it, including registering executors and the server's own machine key, needs the current threshold.

Code: `crates/synapse-radicle/src/identity.rs`. Tests: `crates/synapse-radicle/tests/e0_identity_document.rs`. Evidence: `evidence/e0-identity-document/`.

## 1. What the document holds

| Field | Meaning | Consumed by |
| :--- | :--- | :--- |
| `repo_id` | The repository the document governs | every check |
| `revision` | 0 for genesis, each edit adds exactly 1 | chaining |
| `prev` | Digest of the document this one replaces; zero for genesis (and only for genesis) | chaining |
| `threshold` | Distinct delegate signatures an edit of *this* document needs, 1 to the delegate count | E2 (promotion quorum), M2 (erasure quorum) through `verify_quorum` |
| `delegates` | Ed25519 keys allowed to sign edits; strictly ascending, at most 256, at least 1 | same |
| `executors` | Registered executor machine keys; strictly ascending, at most 4096 | E1 (`executor_registered_at`, `admit_executor_receipt`) |
| `server_key` | The server's machine key, which signs derivation attestations | B5 (`server_key_at`) |

Every key must decode to an Ed25519 point that is not of small order. All refusals use existing `RefusalCode` variants; no new code was added.

## 2. Rules

* **Genesis** (`IdentityLog::genesis`): revision 0, zero `prev`, valid, and signed by at least its own threshold of its own delegates.
* **Edit** (`IdentityLog::apply`): the full next document plus delegate signatures. It applies only if the `WalSeq` moves forward, the next document is valid, names the same repository, has revision `current + 1`, has `prev` equal to the current document's digest, and at least the *current* threshold of *current* delegates signed it. A key the edit itself would add cannot sign it into effect. A refused edit changes nothing.
* **Quorum** (`RepositoryIdentityDocument::verify_quorum`): fails closed. A signer that is not a delegate: `RadicleIdentityInvalid`. A signature that does not verify (strict Ed25519): `RadicleSignatureInvalid`. Fewer distinct delegates than the threshold: `RadicleQuorumInsufficient`. A delegate signing twice counts once.
* **Time** (`IdentityLog::document_at`): each revision is in effect from the `WalSeq` it was applied at. The question "was executor X registered when receipt R was accepted" is answered from the document in effect at R's acceptance `WalSeq`, so a later removal refuses only later receipts and never revokes one already accepted (section 5.1, "an attestation added later never revokes a receipt already accepted").
* **Receipt admission** (`IdentityLog::admit_executor_receipt`): the existing `synapse_evidence::EvidenceReceipt` is verified with its own `verify` (structure, executor `did:key`, strict signature; refusal `ReceiptRefusal::Receipt`), then its executor key must be registered in the document in effect at the acceptance `WalSeq` (refusal `ReceiptRefusal::Identity` with `RadicleIdentityInvalid`). This checks registration only; what a receipt counts toward (input root, policy, independence) is E1.

## 3. Byte layout (record version 1, principle P5)

All integers little-endian, all lengths and counts fixed-width and checked against their caps and against the remaining bytes before anything is allocated. Every decode refusal is `RadicleIdentityInvalid`; a truncated record, trailing bytes, a wrong tag, or a wrong version are each refused.

Document:

| Field | Bytes |
| :--- | :--- |
| tag `SYNAPSE_IDENTITY_DOCUMENT_V1\0` | 29 |
| version (`1`) | u16 |
| `repo_id` length, then UTF-8 bytes (at most 4096) | u32 + n |
| `revision` | u64 |
| `prev` | 32 |
| `threshold` | u32 |
| delegate count, then each key | u32 + 32 each |
| executor count, then each key | u32 + 32 each |
| `server_key` | 32 |

Digest: SHA-256 over `SYNAPSE_IDENTITY_DOCUMENT_DIGEST_V1\0`, the record length as u64, and the record.

Signed bytes (domain separated): `SYNAPSE_IDENTITY_EDIT_SIGN_V1\0` followed by the 32-byte digest. Because the digest covers `repo_id`, `revision`, and `prev`, a signature cannot be replayed onto another repository, another revision, or a fork.

Edit:

| Field | Bytes |
| :--- | :--- |
| tag `SYNAPSE_IDENTITY_EDIT_V1\0` | 25 |
| version (`1`) | u16 |
| document length, then the document record | u32 + n |
| signature count (at most 256), then each 32-byte key and 64-byte signature | u32 + 96 each |

## 4. Acceptance

| Acceptance (ADR 0003 section 9, row 6) | Test | Result |
| :--- | :--- | :--- |
| An edit signed by fewer than the threshold is refused | `e0_edit_signed_by_fewer_than_threshold_is_refused` (1 of threshold 2; the same delegate twice; no signature; a key the edit would add; a forged delegate signature) | pass |
| An edit signed by the threshold applies | `e0_edit_signed_by_threshold_applies` (2 of 3 applies, raises the threshold to 3, rotates the server key; the next edit then needs 3) | pass |
| A removed executor's later receipts are refused | `e0_removed_executor_later_receipts_are_refused` (real signed `EvidenceReceipt`s; removal at `WalSeq` 10; refused at 10 and 11, still admitted on replay at 5; unregistered key, pre-genesis, forged receipt refused) | pass |
| Radicle conformance stays 11 of 11 | `synapse-bench child --kind conformance` with the live Radicle repository, before (main 91733a3) and after | 11 of 11 both; case results identical |

Supporting tests: `e0_edits_chain_and_cannot_be_replayed_or_reordered`, `e0_genesis_needs_its_own_threshold_and_a_valid_document`, `e0_binary_format_round_trips_and_refuses_malformed_bytes`.

Red then green: `evidence/e0-identity-document/red-green/red.txt` (all 6 tests fail on their assertions against a fail-open stub that accepts every edit and receipt and changes nothing) and `green.txt` (all 6 pass).

Radicle conformance reproduction: write `{"suites":["radicle"],"work_dir":"<tmp>","radicle_repo":"<radicle storage repo>"}` to a spec file and run `synapse-bench child --kind conformance --spec <spec> --result <out>`. Raw results: `evidence/e0-identity-document/radicle-conformance/`.

## 5. Performance

E0 is not a hot-path step. No figure is reported, so no bound is needed.

## 6. Limits and disclosures

* The document is in memory only; persisting edits in the WAL is not part of E0 (the binary record format is fixed here so that a later step can store it unchanged).
* The mirror between this document's delegates and threshold and Radicle `refs/rad/id` is not checked by E0; while the Git edge exists, E2 keeps the existing Radicle check and refuses disagreement as `SplitBrainDivergence`.
* Small-order key refusal and the `verify_quorum` signature-count cap were added beside the tested rules and have no test of their own.
* `synapse-radicle` now depends on `synapse-evidence` (and on `synapse-crumb` for tests only); `Cargo.lock` was regenerated by cargo.
