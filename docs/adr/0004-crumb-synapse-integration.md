# ADR 0004: Directory Crumb Context over Synapse Snapshots

* **Status**: Proposed
* **Date**: 2026-10-14
* **Decided by**: Drake (owner), goal statement of 2026-10-14 ("Crumb = directory context + coordination; Synapse = durable source history; AEGIS = execution authority")
* **Tracking Issue**: [aien-spark/synapse#8](https://github.com/aien-spark/synapse/issues/8)
* **Related**: [ADR 0001](0001-synapse-architecture-and-boundaries.md), [ADR 0002](0002-synapse-first-git-as-bridge.md); ADR 0003 (AI-native model, in progress on its own branch; not changed here)
* **Pinned sources**:
  * Reference tool: `aien-dev/aien-architecture` `tools/crumb/crumb.c` at `29780e56c9e6b9111d884e0d4b146737228c19f6` (sha256 of the file `ef0f6566fb838917a750eb898f66596b76aa15a53d7d61bedac03c4c963ee147`).
  * RFC-0001 field rules: `aien-architecture` `docs/CRUMB_PROTOCOL.md` at the same commit, line 28.
  * Pre-RFC dialect: `aien-sovereign-core` `crates/spark-crumbs/src/lib.rs` (`DirCrumb`) at `d01201b3015575a9868ff5a733c9d8ae7c561ec6`.
  * Crumbline: `aien-sovereign-core` `crates/crumbs/SPEC.md` at the same commit.
  * Verified Crumb: `aien-architecture` `docs/adr/0029-verified-crumbs-single-dependency-resolver.md` (ARCH-0029) and omega `src/omega_vcstore.c`.

## 1. Context

Agents on the Spark read `.crumb` files before they touch a directory. Today they read them from a Git working tree with `crumb.c`. Synapse is becoming the primary history for agents (ADR 0002), and agents increasingly read through a `VirtualTree` snapshot without a checkout. They need the same directory context from a snapshot, with the same meaning the Git-backed tool gives it.

Inspection found that the word "crumb" names three unrelated things in AIEN, and that `.crumb` files on disk come in more than one format.

### 1.1 Three meanings of "crumb"

1. **Directory Crumb.** A `.crumb` file in a directory: architectural context (name, purpose, invariants) for agents, plus the coordination plane `crumb.c` keeps beside it (RFC-0001, RFC-0002). This ADR is about this meaning only.
2. **Verified Crumb (VC).** A content-addressed, receipt-bound library object that Omega programs depend on (ARCH-0029; stored by omega `omega_vcstore`). It is program-verification evidence. ARCH-0029 requires it always be written in full, never "crumb" alone. Synapse does not read, store, or interpret Verified Crumbs through this work.
3. **Crumbline.** The learning curriculum in `aien-sovereign-core` `crates/crumbs`. Its SPEC (status "ACCEPTED: Crumb v1 Architecture; implementation qualification pending") defines a crumb as one learning problem presented as observations only, with a sealed side the learner never sees (`SealedCrumb`, held-out tiers) and an append-only ledger. SPEC section 3 states the curriculum "takes zero dependency" on `crumb-spec` and `spark-crumbs` and that the two "share no code, schemas or identity spaces". No ADR file for Crumbline was found in `aien-sovereign-core` `docs/`; the SPEC is the defining document. Synapse never exposes, indexes, merges, or derives context from Crumbline records, sealed or visible.

### 1.2 Dialects of Directory Crumb found on disk

| Tag | Dialect | Shape | Known writer | `crumb.c` today |
|---|---|---|---|---|
| D1 | RFC-0001 JSON | object, `schema_version` = `"1.0.0"`, `name`, `purpose` required; `layer`, `above`, `below`, `invariants`, `exports`, `extensions` optional | `crumb.c` `seed` and `create` | `validate`: valid (prints nothing); `sniff`: name, purpose, invariants |
| D2 | Pre-RFC Atlas / `spark-crumbs` JSON | object with `version` (u32), `dir_path`, `dir_name`, `description`, optional `purpose` object `{statement, ...}`, optional `above`, required arrays `below`, `history`, `whispers`; no `schema_version` | `spark-crumbs` `save_dir_crumb` | `validate`: `LEGACY ... (pre-RFC format, not validated)`; `sniff`: `? \| (legacy format)` |
| D3 | YAML-like `schema: "crumb/v1"` | top-level `key: "string"` lines and a `components:` list of `name`/`path`/`role` | none known; the Synapse repository root `.crumb` was the one instance found (migrated to D1, see section 3) | `validate`: `INVALID ...: not a JSON object`; `sniff`: `no .crumb here` (the JSON parse fails) |

Anything else is outside D1 to D3 and Synapse refuses it with a typed reason (section 2.2). `crumb.c` has no notion of dialect and reads some of those files anyway (for example non-UTF-8 bytes, or an unknown JSON object); section 2.3 lists every known case where the two tools disagree.

## 2. Decision

### 2.1 Responsibility split

* **Directory Crumb** carries architectural context and coordination. Its context half (the committed `.crumb` file) is read by Synapse. Its coordination half (claims, scents, whispers) stays outside Synapse history: it is ephemeral state and is never committed as changesets.
* **Synapse** is durable source history. It stores `.crumb` bytes like any other blob and, through this ADR, answers "which Directory Crumb context applies to this path in this snapshot". It adds no authority: the context read runs under the existing `Read` capability only.
* **AEGIS** is the sole execution and publication authority. A Crumb context, a passing test, or a Synapse receipt never grants publication on its own. How AEGIS consumes the receipts of deliverable D4 is decided with AEGIS, not here (UNVERIFIED: no AEGIS interface was inspected for this ADR).

### 2.2 Dialects are typed, never coerced

Each dialect parses into its own typed variant (`DirectoryCrumb::Rfc0001`, `DirectoryCrumb::Atlas`, `DirectoryCrumb::YamlV1`). A file is never converted into another dialect's shape, and fields of one dialect are never read as if they were another's (a D2 `purpose` object is not a D1 `purpose` string). Anything outside D1 to D3 is refused with a typed reason (`InvalidReason`), and the refusal is reported, not hidden.

The parser is strict and bounded, and its cost is linear in the document size. A document larger than 64 KiB, not valid UTF-8, or nested deeper than 32 containers is refused; JSON must follow RFC 8259 exactly (no duplicate object keys, no raw control characters in strings, no lone UTF-16 surrogate escapes, no bytes after the value). A context chain longer than 256 directories (`MAX_CHAIN_LEN`, root included) is refused as an invalid path. Each of these is a deliberate divergence from `crumb.c`; section 2.3 lists them against the pinned source.

Textual invariants (the `invariants` strings) are guidance for agents. They are surfaced verbatim and enforced by nothing until a specific invariant is turned into a deterministic check.

### 2.3 Crumb context and its digest

`CrumbContext` for a repository path in a snapshot is the chain of `.crumb` entries from the repository root down to the path's directory (the path itself if it is a directory, else its parent), root first. Each entry records the directory, a status (`Present`, `Missing`, or `Invalid(reason)`), the dialect when one was recognised, and the `BlobDigest` of the bytes when a file exists. Missing and invalid entries are part of the context.

Semantics follow `crumb.c` (pinned above): the leaf entry matches what `sniff` and `validate` report for that directory, and `nearest` plus `inherited_invariants` match `explain` sections "NEAREST CRUMB" and "INHERITED INVARIANTS". The known divergences, each checked against the pinned `crumb.c` source, are:

1. **Unknown or incomplete JSON objects.** `sniff` and `explain` treat any JSON object as a crumb, so an unknown JSON object or a D1 file missing required fields can become the "nearest" crumb. Synapse reports those entries as invalid and skips them. Fixture `unknown`.
2. **D3.** `crumb.c` cannot parse D3 and falls back to the crumb above; Synapse reports a D3 entry as present. Fixture `d3`.
3. **Top-level JSON that is not an object.** `sniff` prints `? | (legacy format)` for any parsed JSON value, including a top-level string or array; `validate` and `explain` agree with Synapse that it is not a crumb. Fixture `scalar`.
4. **Non-UTF-8 bytes.** `crumb.c` copies string bytes as they are and never checks UTF-8 (`pstring`), so a Latin-1 byte is accepted. Synapse refuses the file (`NotUtf8`). Fixture `latin1`.
5. **Duplicate object keys.** `crumb.c` stores members with `jset`, which overwrites an existing key, so the last duplicate wins. Synapse refuses the file (`DuplicateKey`). Fixture `dupkey`.
6. **Bytes after a NUL.** `crumb.c` reads the file as a C string, so a valid document followed by a NUL byte and anything else is accepted. Synapse refuses the trailing bytes. Fixture `nuljunk`.
7. **Lone UTF-16 surrogate escapes.** `crumb.c` turns a lone `\ud800`-style escape into U+FFFD (`putf8`). Synapse refuses it. Fixture `surrogate`.
8. **Looser JSON grammar** (from the source and a manual probe, no fixture): `crumb.c` accepts numbers `strtod` accepts (`01`, `1.`), raw control characters inside strings, and truncates a string at an escaped `\u0000`. Synapse refuses the first two and keeps the NUL in the string.
9. **Size, depth and chain bounds** (no fixture against `crumb.c`): `crumb.c` reads any file size, allows 64 nested values (scalars included), and has no chain cap (its upward walk is bounded only by the `PATH_MAX` path buffer). Synapse caps a file at 64 KiB, nesting at 32 containers, and a chain at 256 directories. Unit tests in `synapse-crumb` pin the Synapse side.
10. **Field types** (no fixture against `crumb.c`): D1 `layer` must be a string and `invariants` an array of strings (`crumb.c explain` also prints a lone string or non-string items), and D2 must match the `spark-crumbs` `DirCrumb` shape (`crumb.c` calls any object with `version` and no `schema_version` legacy).

A UTF-8 byte order mark is not a divergence: both tools refuse it (fixture `bom`). The parity script's golden outputs and the Rust parity tests assert items 1 to 7 on both sides, so a change in either tool fails a test. Fixture `.crumb` files are stored as `dot.crumb` so tools reading this repository never treat them as real Directory Crumbs.

`CrumbContextDigest` is its own 32-byte type: SHA-256 over the domain tag `"SYNAPSE_CRUMB_CONTEXT_V1\0"`, the target directory, the entry count, and for each entry the length-prefixed directory path, a dialect tag, a status tag, the invalid-reason code, and the `BlobDigest` (or an absent marker). Missing and invalid entries change the digest. It is never a `BlobDigest`, `ChangesetId`, or `GitOid`.

### 2.4 Placement in the ADR 0002 roadmap

This workstream sits at the Phase 7 to Phase 8 boundary: after the AI-native model (Phase 7) and before Agent Cutover (Phase 8), because agents cutting over to Synapse must get their directory context from Synapse instead of a Git checkout. Deliverable D1 below builds only on the public `SynapseService` read API and a new crate. ADR 0002 section 7 lets Phases 5 and 6 proceed in parallel for that same reason; it says nothing about Phase 7. This ADR proposes, on the same reasoning, that D1 land ahead of the Phase 7 to 8 boundary, in parallel with Phases 5 to 7; that is decided by accepting this ADR, not inherited from ADR 0002. Deliverables D3 to D5 wait for the Phase 5 submission path and ADR 0003.

### 2.5 Deliverables

1. **D1 Snapshot context API (this ADR's first PR).** Crate `synapse-crumb` (typed dialects, bounded parser, `CrumbContext`, `CrumbContextDigest`); a read-only `SynapseService::crumb_context` under `Capability::Read`; a parity script that builds the pinned `crumb.c` with `cc` and checks golden outputs over a fixture tree.
2. **D2 Shared claims.** Crate `synapse-coord`: the RFC-0002 coordination plane without Git. Separate PR. The two tools share a store only by configuration, so a wrong root would let each grant the same claim (split brain). Each store therefore carries a random identity marker `<root>/STORE_ID` (created under the store lock on its first Synapse mutation; ignored by `crumb.c`), and an agent opened expecting a registered id is refused with a typed error when the marker is missing or different (issue #15, `crates/synapse-coord/README.md`). Not yet done: Synapse storing the registered id per repository and opening agents with it, and `crumb.c` printing or checking the id.
3. **D3 Pre-submit advisory.** Before a changeset is submitted, report applicable Crumb context and conflicting claims. Advisory only; it never blocks or grants.
4. **D4 Evidence receipts.** A receipt binding `ChangesetId`, `CrumbContextDigest`, and the source revision, so evidence states which context it was produced under. Crate `synapse-evidence` and the read-only checks in `synapse-api` `evidence.rs`; section 2.7.
5. **D5 Combined qualification.** One qualification run over D1 to D4, including forged records and a Git round trip. Done (issue #12): twelve scenarios in `crates/synapse-bench/tests/crumb_synapse_qualification.rs`, run with the pinned `crumb.c`, D1 parity and D2 interop by `scripts/qualify-crumb-synapse.sh`; evidence in `evidence/crumb-synapse/`, scope and limits in `docs/CRUMB_SYNAPSE_QUALIFICATION.md`. Eleven scenarios pass; self-signed receipts are a known gap until ADR 0003 E0/E1. Defect found and fixed: unbounded coordination record reads (issue #58). A refused store file fails every coordination operation store-wide, including claims on unrelated directories, until an operator moves the named file aside. Not covered: AEGIS (separate repository); the exit rule is proven against Synapse's `Capability::Publish` and Radicle canonical promotion only.

### 2.6 Pre-submit advisory (D3) behaviour

`SynapseService::changeset_advisory` is a read beside the submission path, not part of it: it authorizes once under `Capability::Read` and changes nothing in `submit`, `synapse-store` or `synapse-coord`. For each path a changeset would mutate it returns:

* the `CrumbContext` and `CrumbContextDigest` of the path's directory at the base snapshot (a path absent from the base, such as a new file, gets its parent directory);
* unexpired claims on the path, or on a directory above it, held by agents other than the caller, read from a supplied `CoordStore` with its read-only `sniff` (no lock taken, nothing written). A lock record with no holder is malformed and skipped. Claim keys resolve through a `PathOracle` over the base snapshot, as `crumb claim` resolves them against a checkout. The caller's agent name is self-declared, so it can only hide the caller's own claims. If the store cannot be read, the advisory still answers and says so;
* overlapping open proposals: visible changesets outside the base's lineage and the canonical head's promoted lineage that mutate the same path or collide as file and directory. Synapse has no other "closed" state for a changeset today, so this is the working definition of open;
* pending `.crumb` changes: open proposals that mutate the `.crumb` of the path's directory or of any directory above it, whether or not they touch the path itself. Each also adds a guidance note, so a pending rewrite of the guidance is never silent;
* the context's invariants as guidance notes (nearest crumb first, then inherited), enforced by nothing;
* two staleness flags, each the path's context digest at the base against the same directory at a later snapshot. `staleness` compares against the snapshot the caller names, or by default the most recently committed visible changeset, promoted or not (`Unknown` when there is none). `canonical_staleness` compares against the changeset the canonical head promotes (`Unknown` when there is none). An unrelated newer proposal can mask a pending `.crumb` rewrite from `staleness`; the pending `.crumb` changes above cannot be masked.

All reads use one pinned snapshot (`snapshot_seq`, default the committed state). The store keeps only the current canonical head, with no history, so the head is used only when the pinned snapshot is the committed state; at an older snapshot the result says `NotAtSnapshot`, the canonical lineage is not settled, and its proposals are reported as open.

A request naming more than 256 paths is refused (`QuotaTooManyPaths`), as are repeated (`PathDuplicate`) and invalid (`PathInvalid`) paths. Nothing in the result blocks or authorizes a submit; Synapse source conflicts stay the only hard refusal at this layer.

### 2.7 Evidence receipts (D4)

An `EvidenceReceipt` is its own versioned record (`record_version` 1), signed by the runner's Ed25519 key (named as a `did:key`, verified strictly). The executor DID must be the canonical spelling `did:key:z6Mk...` of its key; any other spelling of the same key (for example the bare `z6Mk...` Radicle form) is refused, so one key gives one receipt identity. It references a changeset by `ChangesetId`; it does not change the `ChangesetEnvelope` or its `EvidenceAttachment` list, and it does not touch the submission path. It binds:

* the repository and the `ChangesetId`;
* the source revision: the envelope's base `GitOid` and parent `ChangesetId`s;
* two `CrumbContextDigest`s per distinct directory of the changed path set (each mutated path's parent directory, `.` for the root), sorted by directory: one at the changeset's base (the context the author saw) and one in the changeset's own tree, which is the input root (the context the runner tested under). The two differ when the changeset edits a `.crumb` on that directory's chain; binding only the base would let a runner test under the edited context while the receipt names the old one. Per directory rather than per path, because the digest names a directory's context chain and every path in one directory shares it; a single digest over the whole set would hide which directory changed;
* the inputs, as an `InputRootDigest` over a list of repository members. Version 1 allows exactly one member, the receipt's own repository and changeset. ADR 0003 step L1's composite multi-repository input root is the same digest over several members sorted by repository; a later member kind can name a `TreeDigest` (ADR 0003 step C1) instead of a changeset. Both changes come with a new `record_version`;
* the test identity: name, argument vector, toolchain, platform, environment;
* the result: exit status, a typed outcome (`Pass`, `Fail`, `Flaky`, `Error`), and the digests of declared outputs. Only `Pass` counts as a pass. `Pass` requires exit code 0 and `Fail` requires anything else;
* an observation (log bytes, start time, duration), signed with the receipt.

Every digest has its own type and domain tag (`"SYNAPSE_EVIDENCE_RECEIPT_V1\0"` opens the record; separate tags for the signature, `EvidenceReceiptId`, `EvidenceActionDigest`, `ResultDigest`, `InputRootDigest`, `OutputDigest`). None is ever a `BlobDigest`, `ChangesetId`, or `CrumbContextDigest`.

**Identity.** The `ResultDigest` covers exit status, outcome, and declared output digests. The receipt identity, `EvidenceReceiptId`, covers the record version, the action digest (repository, changeset, source revision, contexts, input root, test identity), the `ResultDigest`, and the executor. Logs and timings are excluded, so two runs differing only in their observation share an identity (ADR 0003 section 5.5). The outcome is inside the `ResultDigest` so a `Flaky` and a `Pass` with the same exit status never share an identity. This departs from ADR 0003 E1, whose deterministic part is exit status plus declared outputs only, and has a known E3 consequence: two runners that agree on exit status and outputs but label the run differently (say `Pass` and `Error`) have different result digests, so under E3's rule they turn the action-cache entry `Flaky` although the deterministic behaviour agreed. A single-run `Flaky` outcome also overlaps E3's derived `Flaky` cache state: in version 1 it is the runner's own verdict (it saw the same action disagree within one run), not a cache entry derived across receipts. The E1 migration resolves both under a new `record_version`: the outcome moves out of the result digest into a runner label beside it (or is derived from exit status and outputs), and `Flaky` is left to the cache. Version 1 receipts keep their identity and are read as version 1.

**Verification.** Decoding first refuses a record longer than 2 MiB (the 1 MiB log cap plus 1 MiB for every other field; the per-field caps alone would allow about 100 MB), then a wrong domain tag and an unknown version before reading further, and checks every length against its cap before allocating. Signing and encoding refuse a body that breaks a version 1 rule or would exceed the total cap, so no count is truncated and no producible receipt is refused on decode. `SynapseService::verify_evidence_receipt` (`Capability::Read`) then checks the signature, loads the changeset, compares the source revision and the directory set, and recomputes both `CrumbContextDigest`s of each directory, at the changeset's base and in its tree, with the D1 resolver. The typed result is `Current`, `Stale` (a bound context differs, listing each directory with its side, `AtBase` or `InChangeset`, the bound digest, and the expected one), `Mismatch` (other repository, other source revision, other directory set), or `Refused` (bad signature, wrong domain, unknown version, malformed). A stale context is never silently accepted. `SynapseService::evidence_base` gives a runner the source revision and contexts to bind.

**Authority.** A receipt never grants publication: AEGIS stays the sole execution and publication authority, and Radicle canonical promotion stays independent of receipts. A `Current` verdict means only that the receipt describes this changeset under the contexts at its base and in its tree. Version 1 has no executor registry, so any key reaches `Current`, including the changeset author's own; executor independence is deferred to ADR 0003 E0 and E1.

**Coordination stays out.** Claims, scents, whispers, and presence are never evidence. No receipt field holds or references a coordination record, and neither the record nor its verification reads the coordination plane.

**Not in version 1 (room kept by `record_version`).** From ADR 0003 E1: resources in SI units (joules), the hermetic flag decided by a registered executor, registered executor keys and the independence rule (they need the step E0 identity document), the content-tree `ActionDigest` input root (needs C1), the composite input root over more than one repository (L1), scanning receipt logs for secrets (M1), and the action cache with its `Flaky` entry (E3). Storage of receipts is out of scope: receipts are encoded, signed, and verified, not persisted.

## 3. Consequences

* Agents get the same directory context from a Synapse snapshot as from a Git checkout, with every gap (missing, invalid, unknown dialect) visible.
* The Synapse root `.crumb` was D3, which `crumb.c` could not read. It has been migrated to D1 (all fields kept: components as `below` plus `extensions.synapse`), and `crates/synapse-crumb/tests/repo_root.rs` asserts it stays D1.
* A new dialect needs a new typed variant, a new dialect tag, and new golden fixtures; nothing is accepted by default.
* `CrumbContextDigest` binds the exact bytes and statuses seen, so a later receipt (D4) can prove which context was in force.
