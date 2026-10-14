# F1: Attenuated Capability Chains

ADR 0003 section 9 step F1 (issue aien-spark/synapse#25). Section 5.8 "Agent identity and capabilities": grants become delegation chains issued from a repository authority, where each derived link may only narrow operations, path prefixes, reference scope, change scope, quotas, and validity window, and where request rate, storage, and footprint quotas are partitioned across children.

Code: `crates/synapse-auth/src/chain.rs`, `crates/synapse-core/src/lib.rs` (`ChangeId` and chain refusal codes). Tests: `crates/synapse-auth/tests/f1_capability_chains.rs`. Evidence: `evidence/f1-capability-chains/`.

## 1. Model and invariants

| Concept | Meaning | Rule |
| :--- | :--- | :--- |
| `Capability` | `Read` (1), `Propose` (2), `Evaluate` (3), `Review` (4), `Publish` (5), `Undo` (6) | Bitmask in `OperationSet`; child bits must be a subset of parent bits |
| `PathScope` | Canonical sorted set of repository-relative path prefixes (empty string means whole repository) | Prefix match on path segment boundaries (`""`, exact match, or followed by `/`); child prefixes must each be covered by a parent prefix |
| `ReferenceScope` | Bitmask over `ReferenceKind::OwnDrafts` (1) and `ReferenceKind::CanonicalViaPromotionQueue` (2) | Child bits must be a subset of parent bits |
| `ChangeScope` | `any` (`None`) or a strictly ascending list of `ChangeId`s (`Some(Vec<ChangeId>)`) | `any` narrows to `any` or `only(...)`; `only(P)` narrows only to `only(C)` with `C` a subset of `P` |
| `ChainQuotas` | `max_ops_per_window`, `window_duration_ms`, `storage_bytes`, `footprint_paths`, `max_bytes_per_op` | `window_duration_ms` must equal parent's; `max_bytes_per_op` may only narrow; `max_ops_per_window`, `storage_bytes`, and `footprint_paths` are partitioned across granted children so child sums never exceed the parent's grant, and the parent keeps only its unallocated remainder |
| `CapabilityLink` | One signed delegation link (`version`, `nonce`, `parent`, `repo_id`, `issuer_key`, `audience_key`, `caveats`, `signature`) | Root link has `parent = [0u8; 32]` and issuer in `trusted_authorities[repo_id]`; child link has `parent = parent_link.digest()` and `issuer_key = parent_link.audience_key` |
| `CapabilityChain` | Root-first sequence of 1 to 16 `CapabilityLink`s | Every link must be granted at or before the request's `WalSeq`, unrevoked at `request_seq`, unexpired at `now_ms`, bound to `expected_repo_id`, and signed with strict Ed25519 verification |

## 2. Operations and lifecycle

* **Granting (`PolicyEnforcer::grant_link`)**: records the leaf link of a verified chain as granted at `seq`. Every ancestor link must already be granted at or before `seq` and unrevoked at `seq`. If the leaf has a parent link, its `max_ops_per_window`, `storage_bytes`, and `footprint_paths` are added to the parent's allocated totals; if any dimension would exceed the parent's quota, granting fails with `RefusalCode::QuotaPartitionExceeded` and state is unchanged.
* **Revocation (`PolicyEnforcer::revoke_link`)**: marks a granted link revoked at `seq` (keeping the earliest revocation sequence if called more than once). Revocation is monotone and cannot be undone. Any chain containing a link with `revoked_at <= request_seq` is refused with `RefusalCode::AuthGrantRevoked`.
* **Unallocated quota (`PolicyEnforcer::unallocated_quota`)**: returns a granted link's remaining `max_ops_per_window`, `storage_bytes`, and `footprint_paths` after subtracting what it has partitioned to granted children.
* **Request authorization (`PolicyEnforcer::authorize_chain`)**: verifies the chain, checks that every link was granted at or before `request_seq` and unrevoked at `request_seq`, verifies that the presenting agent is the leaf link's audience and signed the canonical request transcript (`DOMAIN_CHAIN_REQUEST_V1`), checks required capability, path scope (segment boundary), reference scope, change scope, payload size, and the leaf's unallocated request rate window, checks mutation nonce replay, and appends an entry to the hash-chained audit log.

## 3. Canonical binary layout (principle P5)

All integers are little-endian. Counts and byte lengths are bounds-checked against caps and remaining buffer bytes before allocation. Any malformed byte sequence, unknown bit, non-canonical path or `ChangeId` ordering, or trailing byte fails closed with `RefusalCode::AuthChainMalformed`.

`CapabilityLink` body:
* `version`: `u16` (`1`)
* `nonce`: `[u8; 32]`
* `parent`: `[u8; 32]` (`LinkDigest`, zero for root)
* `repo_id`: `u32` byte length + UTF-8 bytes (at most 128 bytes)
* `issuer_key`: `[u8; 32]`
* `audience_key`: `[u8; 32]`
* `operations`: `u8` bitmask (bits 0..5)
* `references`: `u8` bitmask (bits 0..1)
* `paths`: `u32` count (at most 256) + each prefix as `u32` byte length + UTF-8 bytes in canonical order
* `changes`: `u8` tag (`0` = any, `1` = `u32` count at most 1024 + strictly ascending 16-byte `ChangeId`s)
* `quotas`: `max_ops_per_window: u32`, `window_duration_ms: u64`, `storage_bytes: u64`, `footprint_paths: u64`, `max_bytes_per_op: u64`
* `issued_at_ms`: `u64`
* `expires_at_ms`: `u64`

Link signature: Ed25519 signature over `SYNAPSE_CAPABILITY_LINK_SIGN_V1\0 || body`.
Encoded link: `body || signature` (64 bytes).
Link digest (`LinkDigest`): `SHA-256(SYNAPSE_CAPABILITY_LINK_ID_V1\0 || encode())`.
Encoded chain (`CapabilityChain`): `version: u16 (1) || count: u8 (1..=16) || (link_len: u32 || link_bytes)*`.

## 4. Acceptance

| Acceptance (ADR 0003 section 9, row 5) | Test | Result |
| :--- | :--- | :--- |
| Property test: no derived grant exceeds its parent in operations, paths, references, change scope, quotas, or expiry | `f1_property_no_derived_grant_exceeds_its_parent` (seeded SplitMix64 `0xF1F1_0003_0025_5EED`, 256 cases, 843 narrowed links accepted, widened links refused across all 6 dimensions) | pass |
| Property test: child quotas never sum above the parent's | `f1_property_child_quotas_never_sum_above_the_parent` (256 cases, 1799 children accepted, 2297 refused with `QuotaPartitionExceeded`) | pass |
| Forged, stripped, and reordered chains refused | `f1_forged_chains_are_refused`, `f1_stripped_chains_are_refused`, `f1_reordered_chains_are_refused` | pass |
| Link bound to another repository or audience refused | `f1_link_bound_to_another_repository_is_refused`, `f1_link_bound_to_another_audience_is_refused` | pass |
| Out-of-scope path refused | `f1_out_of_scope_path_is_refused` (plus reference and change scope checks and path traversal refusal) | pass |
| Chain with an ancestor revoked at the request's `WalSeq` refused | `f1_chain_with_an_ancestor_revoked_at_the_request_walseq_is_refused` | pass |

Additional tests: `f1_partitioned_rate_parent_keeps_only_what_it_has_not_handed_down`, `f1_link_and_chain_binary_encoding_is_canonical_and_malformed_bytes_are_refused`.

Red then green logs: `evidence/f1-capability-chains/red-green/red.txt` (all 11 acceptance tests fail on assertion against stubs at commit `f377f41`) and `evidence/f1-capability-chains/red-green/green.txt` (all 11 pass).
