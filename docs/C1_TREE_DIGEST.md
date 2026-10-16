# C1: TreeDigest Merkle Trees with a Shared, Bounded Cache

ADR 0003 section 9 step 4, C1 (issue aien-spark/synapse#24). Section 5.1 names `TreeDigest`: "a whole repository state as a Merkle tree of directories", native encoding, "Git tree IDs are computed only at the bridge". Section 8 gives `synapse-core` the `TreeDigest` type and changes `synapse-api` from "virtual tree" to "shared Merkle tree with bounded cache".

Code: `crates/synapse-core/src/tree.rs` (`TreeDigest`, canonical node encoding, entry order), `crates/synapse-api/src/tree.rs` (`TreeStore`, `TreeEdit`, paging, diff), `crates/synapse-api/src/lib.rs` (service wiring). Tests: `crates/synapse-bench/tests/c1_tree_parity.rs`, `crates/synapse-bench/tests/c1_tree_cache_bound.rs`, `crates/synapse-api/tests/c1_tree_digest.rs`, plus unit tests in both `tree.rs` files. Measurement: `synapse-bench c1` (`crates/synapse-bench/src/c1.rs`). Evidence: `evidence/c1-tree-digest/`.

## 1. Model

| Concept | Meaning | Rule |
| :--- | :--- | :--- |
| Tree node | One directory: its entries in canonical order, each a file (mode, `BlobDigest`, size) or a subdirectory named by its own `TreeDigest` | Immutable and content addressed; a name appears once per node; a directory never names the empty node |
| `TreeDigest` | `SHA-256("SYNAPSE_TREE_V1\0" \|\| len(node):u64 \|\| node)` of the root node | Two repository states are equal exactly when their root digests are equal; every unchanged subtree keeps its digest across revisions (structural sharing) |
| Entry order | Byte order of the name, a directory compared as if its name ended in `/` (Git's tree order) | A depth-first walk yields full paths in plain byte order, the order of `git ls-tree -r` and `git diff-tree -r` |
| `TreeStore` | The service's one store of tree nodes, shared by every base tree, changeset tree, and query | Bounded by `TreeCacheConfig::max_bytes` (default 64 MiB, minimum 1 MiB); base trees pinned; everything else evicted least recently used first |
| `TreeEdit` | An edit of one tree that opens only the directories on touched paths | Writes back only the changed path to the root, so a changeset costs about depth x edited paths new nodes |
| Git blob OID | Kept beside each file entry as a bridge attribute | Not part of the native encoding or the digest; used only to answer listings in Git terms |

Canonical node encoding, version 1 (little-endian):

```text
node    = count:u32 entry*
entry   = tag:u8 name_len:u16 name body
tag     = 1 regular (100644) | 2 executable (100755) | 3 symlink (120000) | 4 directory
body    = blob:[u8; 32] size:u64      (tags 1 to 3)
        | tree:[u8; 32]               (tag 4)
```

Malformed nodes are refused with `RefusalCode::TreeNodeMalformed`; a walk that reaches an evicted node gets `RefusalCode::TreeNodeNotFound`, rebuilds that tree once from its source (base tree plus changeset mutations, which reproduces the same digests), and only if the bound is too small to hold one tree refuses with `BackpressureOverCapacity`.

## 2. The bound

Accounted bytes are every node's heap allocations (requested size plus 16 bytes per allocation for allocator headers), the hash tables by bucket capacity (including the growth an insertion would cause), and the changeset root memo. Before any insertion the store evicts down to seven eighths of the bound if the insertion would cross it, so the accounted total never exceeds the bound. `crates/synapse-api/tests/c1_tree_digest.rs` checks the accounting with a counting global allocator: the live heap the store really holds never exceeded its accounted total (worst ratio 0.884) while 2,000 edits drove it through 21,355 evictions.

Each sample of the measurement records whether it built a tree, so a rebuild after eviction is counted as cold, never as warm.

## 3. Acceptance

| Acceptance (issue #24) | Test or evidence | Result |
| :--- | :--- | :--- |
| Tree parity with `git ls-tree -r` on the Gate 4 fixture | `c1_tree_and_diff_parity_with_git_on_gate4_fixture` (ignored on CI, run locally with `--ignored`): the base tree and all 400 changeset trees of the Gate 4 query population, every entry's mode, type, object id, path, and order. `synapse-bench c1`: 401 trees, 1,754,839 entries, 0 mismatches. CI: `c1_tree_parity_with_git_ls_tree_r_on_gate4_shaped_population` (synthetic repository, same 8 x 50 population shape) | pass |
| Diff parity with `git diff-tree` on the Gate 4 fixture | Same ignored test and `synapse-bench c1`: 400 diffs (base to changeset), 660 entries, compared as `git diff-tree -r --raw --no-renames --no-abbrev` lines (modes, object ids, status, path, order), 0 mismatches. CI: `c1_tree_and_diff_parity_with_git_on_edge_cases` (add, modify, delete, mode change, symlink to file and file to symlink `T`, file replaced by directory, directory replaced by file, upsert below a file, upsert over a directory) | pass |
| Memory stays under the configured bound under the Gate 4 query load | `c1_memory_stays_under_the_configured_bound_under_the_gate4_query_load`: 400 proposals, then 400 samples each of `tree` (every page), `diff`, and `read_file`, bound 1 MiB; accounted bytes checked after every query; 2,188 nodes and 637 roots evicted; every answer still equal to Git per entry. `c1_tree_store_accounting_covers_the_real_heap_under_eviction` (counting allocator). `synapse-bench c1` on the real fixture: bound 4 MiB, high water 4,194,114 B; bound 64 MiB, high water 10,231,333 B | pass |
| Cold (build) and warm (paging) query times reported separately against the memory-bandwidth bound | `c1_cold_build_then_warm_paging_with_structural_sharing` (a first query builds, repeated queries and full paged listings build nothing; a cold build inserts at most depth x edits nodes). Figures in section 4 | pass (figures reported; a report is not the acceptance) |

Red before green (`evidence/c1-tree-digest/red-green/`): on main (e863c87) the edge case parity test fails because main reports `M` where Git reports `T` (symlink to file, file to symlink); main already listed the Gate 4 shaped population correctly, so the population test is a regression guard there. The bound, cold/warm, and heap tests do not compile on main (no bounded store exists); they were run red against two stubs in `tree.rs` (eviction disabled: "tree cache holds 1051644 accounted bytes, over the 1048576 byte bound" and "accounted 2099129 > bound 2097152"; root memo disabled: "warm queries build nothing").

## 4. Results on the Gate 4 fixture

`synapse-bench c1`, release build, `aien-sovereign-core` at `1b6e340d48417dfbcfe2df56d48a0696a3a9b250` (4,376 files; base tree 488 distinct nodes, 303,468 encoded bytes), Gate 4 seed, 8 agents x 50 proposals, 400 samples, one reader thread, 2026-10-16. Host load average 4.3 to 4.7 during the runs from other sessions (`host-load.txt`). Raw samples: `bench-64m/traces.jsonl`, `bench-4m/traces.jsonl` (nanoseconds per sample, with bound bytes, fraction, and whether it built a tree).

Bound: the physical memory bandwidth 273 GB/s (A0, `docs/A0_HOST_BOUNDS.md`). Cold: (upserted blob bytes read + new node encoded bytes written) / 273 GB/s; median 16,603 B, 60.8 ns (calc:70c89d56). Warm: encoded bytes of the tree's distinct nodes / 273 GB/s; 303,468 B, 1.1116 us (calc:edf8028a). Fraction = bound / measured, median of the per-sample fractions.

| Phase (cache bound 64 MiB) | n | built | p50 | p95 | Bound (p50) | Fraction of bound (p50) |
| :--- | ---: | ---: | ---: | ---: | ---: | ---: |
| Cold build (`tree_digest`, engine) | 400 | 400 | 0.064 ms | 0.170 ms | 60.8 ns | 0.00091 |
| Warm full listing, engine (`tree_page`, 18 pages of 256) | 400 | 0 | 0.218 ms | 0.225 ms | 1.1116 us | 0.0051 |
| Warm full listing, API (`tree`, authorization per page) | 400 | 0 | 1.251 ms | 1.271 ms | 1.1116 us | 0.00089 |
| Warm diff base to changeset (engine) | 400 | 0 | 0.003 ms | 0.007 ms | not derived | not derived |

| Phase (cache bound 4 MiB, evicting) | n | built | p50 | p95 | Fraction of bound (p50) |
| :--- | ---: | ---: | ---: | ---: | ---: |
| Cold build | 400 | 400 | 0.073 ms | 0.210 ms | 0.00086 |
| Warm full listing, engine | 400 | 0 | 0.213 ms | 0.359 ms | 0.0052 |
| Warm full listing, API | 400 | 0 | 1.196 ms | 1.212 ms | 0.00093 |
| Diff base to changeset (engine; 246 samples rebuilt an evicted tree) | 400 | 246 | 0.021 ms | 0.100 ms | not derived |

Cache after the 4 MiB run: 1,181 root builds, 6,749 nodes and 1,042 roots evicted, high water 4,194,114 B. Peak process RSS 307,452 KiB, against 782,316 to 789,720 KiB in Gate 4 with its unbounded flat cache (0.393 of the lower Gate 4 figure, calc:8af7d9bd); the RSS covers the whole process, including the loaded base blobs and the parity pass. For comparison only, the Gate 4 API-only tree time was 11.394 ms p50 (9.108 times the 1.251 ms here, calc:6c797e35); the Gate 4 figure covered the flat per-changeset copy.

Before each warm listing sample an untimed walk computes the bound's byte count; it also makes sure the tree is resident, so "warm" here means "tree resident in the cache". Under the 4 MiB bound the diff samples show the cost of rebuilding evicted trees.

What the fractions say: cold builds run at about 0.1% of the memory bound and warm engine listings at about 0.5%. The bound charges memory traffic only; the cold path also hashes each upserted blob for its Git id, reads the blob from the store, and SHA-256 hashes each new node, and the warm path allocates one path string per entry. Those are the next costs to remove; the warm API path is dominated by per-page request authorization (1.251 ms against 0.218 ms at the engine).

Energy: whole-phase SPBM windows are recorded in `report.json`, but the windows are 0.03 to 0.14 s long against a counter that updates about every 0.1 s in 1 mJ steps (the cold window reads 0 J), so no joule figure is claimed: **UNVERIFIED** (instrument resolution too coarse for these windows).

Reproduce: `synapse-bench c1 --clone <no-checkout clone of the fixture> --base 1b6e340d48417dfbcfe2df56d48a0696a3a9b250 --work-dir <dir> --out <dir> [--cache-bytes N] [--skip-parity 1]`.

## 5. Behaviour changes and deviations

* Multi-parent overlays now resolve a file and directory collision to the later parent, the same rule as an upsert. The old flat overlay kept both the file and the paths below it, a state no Git tree can hold.
* `DiffStatus::TypeChanged` (`T`) is new: a change between a symlink and a regular or executable file, as Git reports it. Executable bit changes stay `M`, as in Git.
* `PathIndex` no longer holds a per-changeset flat `VirtualTree` cache; `status.cached_virtual_trees` now counts memoized changeset roots.
* New public engine methods on `SynapseService`: `tree_digest`, `tree_page`, `tree_encoded_bytes`, `diff_trees`, `tree_store`, `set_tree_cache_config`. They skip request authorization like `materialize_virtual_tree` already did; the signed APIs (`tree`, `diff`, `read_file`) are unchanged in shape.
* ADR section 5.1 says evidence binds to `TreeDigest`; this step provides the digest only. Envelope v2 and evidence binding are later steps (B1, C2, C3, H1 build on this API).
* The Gate 4 fixture is not on CI runners, so CI runs the parity tests on a synthetic repository; the fixture runs are local and recorded under `evidence/c1-tree-digest/`.
