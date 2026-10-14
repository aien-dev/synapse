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
| D3 | YAML-like `schema: "crumb/v1"` | top-level `key: "string"` lines and a `components:` list of `name`/`path`/`role` | none known; the Synapse repository root `.crumb` is the one instance found | `validate`: `INVALID ...: not a JSON object`; `sniff`: `no .crumb here` (the JSON parse fails) |

Anything else (non-UTF-8, unknown JSON object, non-object JSON, unrecognised text) has no defined meaning.

## 2. Decision

### 2.1 Responsibility split

* **Directory Crumb** carries architectural context and coordination. Its context half (the committed `.crumb` file) is read by Synapse. Its coordination half (claims, scents, whispers) stays outside Synapse history: it is ephemeral state and is never committed as changesets.
* **Synapse** is durable source history. It stores `.crumb` bytes like any other blob and, through this ADR, answers "which Directory Crumb context applies to this path in this snapshot". It adds no authority: the context read runs under the existing `Read` capability only.
* **AEGIS** is the sole execution and publication authority. A Crumb context, a passing test, or a Synapse receipt never grants publication on its own. How AEGIS consumes the receipts of deliverable D4 is decided with AEGIS, not here (UNVERIFIED: no AEGIS interface was inspected for this ADR).

### 2.2 Dialects are typed, never coerced

Each dialect parses into its own typed variant (`DirectoryCrumb::Rfc0001`, `DirectoryCrumb::Atlas`, `DirectoryCrumb::YamlV1`). A file is never converted into another dialect's shape, and fields of one dialect are never read as if they were another's (a D2 `purpose` object is not a D1 `purpose` string). Anything outside D1 to D3 is refused with a typed reason (`InvalidReason`), and the refusal is reported, not hidden.

The parser is strict and bounded. A document larger than 64 KiB or nested deeper than 32 levels is refused before or during parsing; duplicate JSON object keys are refused. This is a deliberate divergence from `crumb.c`, which reads any size and nests to 64 levels; a test records the divergence.

Textual invariants (the `invariants` strings) are guidance for agents. They are surfaced verbatim and enforced by nothing until a specific invariant is turned into a deterministic check.

### 2.3 Crumb context and its digest

`CrumbContext` for a repository path in a snapshot is the chain of `.crumb` entries from the repository root down to the path's directory (the path itself if it is a directory, else its parent), root first. Each entry records the directory, a status (`Present`, `Missing`, or `Invalid(reason)`), the dialect when one was recognised, and the `BlobDigest` of the bytes when a file exists. Missing and invalid entries are part of the context.

Semantics follow `crumb.c` (pinned above): the leaf entry matches what `sniff` and `validate` report for that directory, and `nearest` plus `inherited_invariants` match `explain` sections "NEAREST CRUMB" and "INHERITED INVARIANTS". Two documented divergences follow from section 2.2: `explain` treats any JSON object as a crumb, so an unknown JSON object or a D1 file missing required fields can become its "nearest" crumb, while Synapse reports those entries as invalid and skips them; and `explain` cannot parse D3, while Synapse reports a D3 entry as present. Golden outputs and the Rust parity tests pin both. Synapse is also stricter than `crumb.c` on field types, which the fixtures do not exercise against `crumb.c`: D1 `layer` must be a string and `invariants` an array of strings (`crumb.c explain` also prints a lone string or non-string items), and D2 must match the `spark-crumbs` `DirCrumb` shape (`crumb.c` calls any object with `version` and no `schema_version` legacy). Fixture `.crumb` files are stored as `dot.crumb` so tools reading this repository never treat them as real Directory Crumbs.

`CrumbContextDigest` is its own 32-byte type: SHA-256 over the domain tag `"SYNAPSE_CRUMB_CONTEXT_V1\0"`, the target directory, the entry count, and for each entry the length-prefixed directory path, a dialect tag, a status tag, the invalid-reason code, and the `BlobDigest` (or an absent marker). Missing and invalid entries change the digest. It is never a `BlobDigest`, `ChangesetId`, or `GitOid`.

### 2.4 Placement in the ADR 0002 roadmap

This workstream sits at the Phase 7 to Phase 8 boundary: after the AI-native model (Phase 7) and before Agent Cutover (Phase 8), because agents cutting over to Synapse must get their directory context from Synapse instead of a Git checkout. Deliverable D1 below builds only on the public `SynapseService` read API and a new crate, so, as ADR 0002 section 7 allows for Phase 6, it can land in parallel with Phases 5 to 7. Deliverables D3 to D5 wait for the Phase 5 submission path and ADR 0003.

### 2.5 Deliverables

1. **D1 Snapshot context API (this ADR's first PR).** Crate `synapse-crumb` (typed dialects, bounded parser, `CrumbContext`, `CrumbContextDigest`); a read-only `SynapseService::crumb_context` under `Capability::Read`; a parity script that builds the pinned `crumb.c` with `cc` and checks golden outputs over a fixture tree.
2. **D2 Shared claims.** Crate `synapse-coord`: the RFC-0002 coordination plane without Git. Separate PR.
3. **D3 Pre-submit advisory.** Before a changeset is submitted, report applicable Crumb context and conflicting claims. Advisory only; it never blocks or grants.
4. **D4 Evidence receipts.** A receipt binding `ChangesetId`, `CrumbContextDigest`, and the source revision, so evidence states which context it was produced under.
5. **D5 Combined qualification.** One qualification run over D1 to D4, including forged records and a Git round trip.

## 3. Consequences

* Agents get the same directory context from a Synapse snapshot as from a Git checkout, with every gap (missing, invalid, unknown dialect) visible.
* The Synapse root `.crumb` is D3. It is reported as present and typed, but `crumb.c` does not read it. Migrating it to D1 is a separate change.
* A new dialect needs a new typed variant, a new dialect tag, and new golden fixtures; nothing is accepted by default.
* `CrumbContextDigest` binds the exact bytes and statuses seen, so a later receipt (D4) can prove which context was in force.
