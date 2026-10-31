# D1: Merge tier T1 (region)

ADR 0003 section 9 step D1 (issue aien-dev/synapse#39), section 5.5 merge tiers: a T1 merge combines revisions that change different regions of the same file. Path-level merging (T0, B5) refuses them.

Code:

* `crates/synapse-core/src/merge.rs`: `region_merge`, the line-level three-way merge.
* `crates/synapse-core/src/derivation.rs`: `MergeTier::T1Region`, tier tag 1, `t1_mutations`, and the `DerivationTrees` blob methods.
* `crates/synapse-api/src/derivation.rs`: blob preload for derivation, admission and verification.
* `crates/synapse-store/src/revision.rs`: the store writes the merged blob with the derived revision.

Tests:

* `merge::tests::d1_*` in synapse-core.
* `crates/synapse-api/tests/d1_merge_tier_t1.rs` (`d1_api_*`).
* `merge_t1::tests::d1_*` in synapse-bench: the comparison with Git.

Evidence: `evidence/d1-merge-tier-t1/`.

## 1. The merge rule

`region_merge(base, versions)` merges the versions of one file that several revisions wrote against the same base version. The result does not depend on which line diff is chosen.

1. **Forced lines.** For one version, a base line is *forced* when every longest common subsequence of base and version matches it, and always to the same version line. It is computed from a prefix table and a suffix table of LCS lengths. Base line `i` is forced when:
   * no version position `j` gives `prefix[i][j] + suffix[i+1][j] == total`, so skipping the line always loses a match; and
   * exactly one `j` gives `prefix[i][j] + 1 + suffix[i+1][j+1] == total`.
2. **Anchors.** The anchors are the base lines forced for every version.
3. **Segments.** The anchors cut the base and every version into matching segments. In each segment at most one version may differ from the base, and the merged file takes that version's segment. If two versions change one segment, the merge is refused (`RegionConflict::Overlap`).

Why it agrees with Git:

* Every minimal diff matches every anchor, so one version's changed regions stay inside its changed segments.
* Two versions' regions are then always separated by at least one unchanged anchor line. That is the condition Git's three-way merge needs for a clean result, and the clean result is the same file.

The brute-force test `d1_forced_matches_are_exactly_the_pairs_every_optimal_alignment_shares` checks the forced-line computation against every optimal alignment on small inputs.

A first design used one Myers diff and then widened each change to cover the lines the diff could have slid. The differential test against `git merge-file` found merges Git refuses, because a different minimal diff can re-pair lines far from the change. The forced-anchor rule replaced it; `d1_edits_that_some_minimal_diff_places_together_conflict` holds the counterexample.

## 2. In the derivation rule

`DerivationRule::Merge { tier: MergeTier::T1Region }` is encoded with tier tag 1. The rule is the same B5 rule: the server derives it, the store recomputes it at admission (`check_derivation`), and replicas recompute it at verification. The attestation records the tier and the canonical merge order (strictly ascending `ChangesetId`), as for T0.

Per path, `t1_mutations`:

* takes a mutation that every source wrote identically once;
* refuses a path that lies below a path another source wrote;
* refuses a delete against a change ("deleted by one revision and changed by another");
* refuses a file that several sources added with different content;
* refuses any version whose mode differs from the base mode (checked against the base, so the order of sources does not matter);
* otherwise runs `region_merge` on the base blob and each version's blob, and stores the merged blob through `DerivationTrees::put_blob`.

The merged blob is new content that no source carried. The API preloads the blobs the rule reads (each upsert blob, and the base file at each mutated path, for T1 only). `admit_derived_revision` takes merged blobs that are not yet visible from `produced_blob`, checks their digest, and writes them in the same WAL record as the derived revision. Replay and verification recompute the same bytes. A forged T1 output, with a blob other than the recomputed one, is refused (`d1_api_forged_t1_merge_output_is_refused`).

T0 and T1 merges of the same sources share one `ChangeId` (`merge_change_id`). They are revisions of the same change.

## 3. Acceptance

| Acceptance (issue #39) | Result |
|---|---|
| The 3 disjoint-hunk pairs of the Gate 4 conflict scenario, refused by T0, now merge | 3 of 3 merged (`d1_gate4_conflict_scenario_t1_merges_match_git_on_all_253_pairs`); with the T1 arm switched to T0 (mutation `t1-is-t0`) the test fails |
| Every merged tree equals Git's merge result | 245 merged pairs, 0 differ from `git merge-tree --write-tree` on any touched path (blob digest and mode) |
| No pair `git merge-tree` reports as conflicting is merged (all 253 pairs) | 0 merged Git conflicts, 0 merge-tree errors. Per class, as (pairs, Synapse merged, Git clean): distinct paths (240, 240, 240), disjoint hunks (3, 3, 3), identical change (2, 2, 2), hotspot rewrite (6, 0, 0), modify/delete (1, 0, 0), file/directory collision (1, 0, 0) |
| Each result records its tier and merge order in its `DerivationAttestation` | 0 attestations without tier T1 and the canonical order; the API test checks the attestation's rule and inputs, and `verify_revision_log` checks every signature and recomputes every T1 record, also after a reopen and after checkpoint plus compaction |

Also covered:

* **Differential test against `git merge-file`.** `d1_region_merge_never_merges_what_git_merge_file_refuses` runs 10,000 random three-way cases (seed `0xD1`):
  * 3,947 merged, every result byte-identical to Git's;
  * 0 merged where Git conflicts;
  * 1,255 refused that Git merges cleanly (see Limits).
* **Refusals.** Touching regions, modify/delete, and a mode change are refused end to end (`d1_api_t1_refuses_touching_regions_and_modify_delete`). Binary content, a missing final newline, and oversized files are refused (`d1_binary_missing_final_newline_and_oversized_files_are_refused`).

Red before green: `evidence/d1-merge-tier-t1/red-green/red.txt` holds 10 mutations from `run.sh`, one per behaviour, and each turns its tests red. `green.txt` holds the passing runs. The behaviours:

* forced-line check: unmatched lines, unique partner;
* one version per segment;
* tier tag decoding;
* T1 not being T0;
* identical mutations taken once;
* delete check;
* mode check;
* the store writing the merged blob;
* the API blob preload.

## 4. Limits

* **The proof covers minimal diffs.** Git's default Myers diff is minimal except when its cost limit cuts in on very large inputs, and its histogram diff is not always minimal. Agreement there rests on the tests, not on the argument.
* **Conservative.** T1 refuses some merges Git makes cleanly (1,255 of 10,000 random cases):
  * the same edit made by two versions in one region, unless the whole file is byte-identical;
  * changes separated only by lines that some minimal alignment leaves unmatched (for example repeated lines), where Git's chosen diff keeps them apart.

  The refused cases were counted, not sorted by cause.

  A refusal is always safe: the revisions stay separate, and a later tier or a human resolves them.
* **Refused inputs.** Binary files (any NUL byte), files without a final newline, and base/version pairs larger than `MAX_ALIGNMENT_CELLS` (2^22 table cells, about 2,047 by 2,047 lines).
* **Modes and paths.** A mode change on a merged path, a delete against a change, and an add/add with different content are refused, never merged.
* **No performance figures.** The alignment is quadratic in the line count of each file, bounded by `MAX_ALIGNMENT_CELLS`. D1 has no section 6 hot-path acceptance, and nothing was measured.
* **`.crumb` not recompiled.** The orchestrator recompiles it at rebase.
