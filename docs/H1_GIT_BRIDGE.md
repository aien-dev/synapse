# H1: Git Bridge: Native Git Objects, the Persistent Map, Import and Export

ADR 0003 section 9 step 28, H1 (issue aien-spark/synapse#48). Section 5.10: "Import: full history into native objects, with a persistent `GitOid` to (`ChangesetId`, `TreeDigest`) map; merge parents, tags, modes, and signatures preserved (signatures as opaque data). Export: ... written as packfiles, not loose objects". Section 4 adapts Git packfiles; section 6 keeps deltas "only on the bridge wire".

H1 is delivered in two ordered cuts. **Cut 1** (sections 1 and 1a) is the Git side of the bridge: reading a real repository's whole object graph natively and writing an object set back as a pack that Git accepts byte for byte. **Cut 2** (section 1b) is the native side: the persistent `GitOid` to (`ChangesetId`, `TreeDigest`) map in the store (WAL record kind 10), imported blobs as store blobs, Git trees as canonical `TreeDigest` nodes, commits as imported revisions keeping their original headers as opaque bytes, export of that stored state with identical Git object IDs, and deterministic export of native (B1) revisions.

Code: `crates/synapse-git/src/{object,inflate,pack,repo,bridge}.rs` and `crates/synapse-store/src/git_bridge.rs`. Tests: `crates/synapse-git/tests/{h1_git_bridge,h1_hostile_repo,h1_read_limits,h1_bridge_import}.rs` and unit tests in each module. Evidence: `evidence/h1-git-bridge/`.

## 1. What cut 1 provides

| Part | Module | Rule |
| :--- | :--- | :--- |
| Object model | `object` | Kinds `commit`, `tree`, `blob`, `tag` (pack types 1 to 4); ID = SHA-1 of `<kind> <size>\0<payload>` (`GitOid::compute_git_object`, the `sha1` crate already in the workspace); tree entries, a commit's tree and parents in written order, a tag's target. Every other commit and tag byte (author, committer, `gpgsig`, `mergetag`, `encoding`, message) is opaque and never rewritten |
| zlib and DEFLATE decoder | `inflate` | RFC 1950 and 1951: stored, fixed and dynamic Huffman blocks; reports the input bytes a stream used (a pack entry does not record its compressed length); output bounded by the caller's cap; Adler-32 checked |
| Pack and index codec | `pack` | Pack version 2 (reads 2 and 3) and index version 2 per `gitformat-pack`: entry header, `OBJ_OFS_DELTA` offset encoding, `OBJ_REF_DELTA` base name, delta copy and insert instructions, CRC-32 (IEEE) per entry, 31-bit and 8-byte offsets, pack and index SHA-1 trailers. `PackReader::with_index` reads a pack through Git's index; `PackReader::index` indexes a pack with no index file (native `index-pack`) |
| Repository reader | `repo` | `GitRepository::open` reads loose objects and every `objects/pack/*.pack` with its `.idx`; refs from loose files and `packed-refs`; `HEAD`. `full_history` walks every object reachable from every reference, checking each object's kind against its link |
| Exporter | `repo` | `export_repository` creates a **new** bare repository holding the object set as one pack plus index (no loose objects), the references, and `HEAD`. An existing destination is refused, so it cannot move a branch of an existing repository |

Writer determinism: the pack holds whole objects in object ID order, compressed as zlib stored blocks (the existing `zlib_compress_store`), so the bytes are a function of the object set alone; input order and duplicates do not matter.

Every malformed input is refused with `RefusalCode::GitObjectCorrupt` and never panics: bad zlib header or checksum, truncated or over-declared streams, over-subscribed Huffman codes, distances before the output start, pack or index checksum mismatch, offsets outside the pack, non-monotone fan-out, unsorted names, delta size mismatches, copies past the base, delta chain loops or chains over 4096, reference-delta bases missing from the pack (thin packs), an object whose content does not hash to its ID, missing objects, shallow repositories, and alternates. Exceeding a read limit is refused with `QuotaPayloadTooLarge` and a non-regular file with `PathInvalid` (section 1a).

The system `git` binary is used only by the tests, as an independent oracle. `synapse-git` starts no Git process on any cut 1 path.

## 1a. Hostile repositories (review of PR #90, findings B1 and B2)

A repository handed to the bridge is untrusted input. The reader may not hang on it, read outside it, or allocate without bound because of it:

| Threat | Rule | Refusal |
| :--- | :--- | :--- |
| A reference, `packed-refs`, `HEAD`, loose object, `.pack` or `.idx` that is a pipe, socket, device or symbolic link (a pipe blocks a reader forever; a link to `/dev/zero` reads without end; a link can lead outside the repository) | Every file is inspected with `symlink_metadata` and opened only if it is a regular file; the opened file must be the inspected one (same device and inode); at most cap + 1 bytes are read even if it grows. The `refs/` walk uses `DirEntry::file_type`, which does not follow links; `refs/`, `objects/` and `objects/pack/` must be real directories | `PathInvalid` |
| Oversized small files | Loose reference and `HEAD` at most 4 KiB, `packed-refs` at most 64 MiB, every `.pack` and `.idx` together at most 2 GiB (held in memory) | `QuotaPayloadTooLarge` |
| Delta amplification (a 4 KiB delta copying a 64 KiB base 4,096 times resolves to 256 MiB) | **Total budget**: at `open`, the size every pack entry declares it resolves to is summed from the entry headers and the first 20 inflated bytes of each delta stream (`PackReader::declared_bytes`, nothing resolved); each loose object's declared size is read from the first 64 inflated bytes before it is inflated. The sum may not pass `max_total_object_bytes`, **default 1 GiB** (omega, the largest repository the bridge has read, holds 374,301,457 bytes of objects). A resolved entry always has exactly its declared size (checked on every read), so the budget bounds what a read holds | `QuotaPayloadTooLarge` |
| One huge object | Per-object cap `max_object_bytes`, default 1 GiB, on every whole entry, delta stream, delta result and loose object, checked against the declared size before allocation. `apply_delta` no longer reserves the declared result size up front: it reserves at most base + delta length and grows as instructions produce bytes, never past the declared size | `QuotaPayloadTooLarge` |

All five limits are fields of `ReadLimits` (`GitRepository::open_with_limits`); `GitRepository::open` uses the defaults. Also from the review: `*.lock` files under `refs/` are skipped as Git skips them, and a detached `HEAD`'s commit is collected with its history (`GitHistory::detached_head`). A symbolic link as `HEAD` is now refused instead of read as "no `HEAD`".

A file swapped between the check and the open is refused too: the open uses `O_NOFOLLOW | O_NONBLOCK` (`OpenOptionsExt::custom_flags`, constants from the workspace `libc` dependency), so a swapped-in link fails with `ELOOP` and a swapped-in pipe opens at once and fails the device, inode and regular-file check (unit test `a_file_swapped_for_a_pipe_or_link_after_the_check_is_refused_without_blocking`).

Re-review of PR #90 at `28d783c` (non-blocking findings, folded into cut 2): (a) a fan-out directory under `objects/` (`objects/ab/`) that is a symbolic link could lead reads outside the repository; it must now be a real directory like `objects/` itself, or the read is refused `PathInvalid` (`h1_hostile_linked_object_fanout_directory_is_refused`). Directories under `refs/` were already refused unless real (the walk's `DirEntry::file_type` does not follow links, and anything that is neither a directory nor a regular file is `PathInvalid`). (b) The standalone pack indexer (`PackReader::index`, native `index-pack`) now goes through `ReadLimits` too (`PackReader::index_with_limits`; `index` uses the defaults): the declared size of every entry is summed against `max_total_object_bytes` before anything is resolved, and reference deltas whose base comes later in the pack wait on that base instead of being retried in rounds (unit test `indexer_resolves_a_reference_delta_stored_before_its_base_within_the_budget`: the exact budget passes, one byte less is refused, the per-object cap is refused, a thin pack is refused). (c) Peak RSS against the budget is stated in section 4.

## 1b. Cut 2: the persistent map, native import, export from the store

### WAL record kind 10

`WalRecord::GitBridgeImported { repo_id, entry }`, WAL record **kind 10**, binary codec only (no v1 JSON form; a store still writing v1 refuses it as kinds 7 and 8 are refused). Open PR #88 claims kind 9, so the bridge takes 10. Body: `repo_id | entry tag (u8) | entry body` (layout in `codec.rs` beside `put_git_bridge_entry`):

| Entry | Tag | Body |
| :--- | ---: | :--- |
| `Objects` | 1 | `u32 n \| (git oid [20] \| blob [32] \| size u64)* \| u32 m \| (git oid [20] \| u32 len \| C1 tree node)*` |
| `Commit` | 2 | `git oid [20] \| tree [32] \| u32 n \| parent ChangesetId [32]* \| u32 len \| headers` |
| `Tag` | 3 | `git oid [20] \| target \| u32 len \| rest` |
| `Refs` | 4 | `u32 n \| (name \| target)* \| option HEAD` |

A target is `1 | ChangesetId`, `2 | TreeDigest`, `3 | BlobDigest` or `4 | tag git oid`. Blob bytes travel inline in the WAL frame as for every v2 record (only blobs not already committed). Replay, checkpoints and compaction treat kind 10 like the B1 records: the records stay in the revision log, a checkpoint load rebuilds the map from them (`GitBridgeLedger::from_log`), the state root covers them, and compaction keeps every blob the map names.

### The map

`SynapseStore::git_bridge_repo(repo)` gives, per repository: Git blob to (`BlobDigest`, size); Git tree to `TreeDigest` (the canonical C1 node is stored, so the tree is rebuilt at export, never kept as Git bytes); Git commit to (`ChangesetId`, `TreeDigest`) and back; Git tag to its target and remaining bytes; the references and `HEAD`. An imported commit is a revision whose ID is `SHA-256("SYNAPSE_GIT_IMPORTED_REVISION_V1\0" || u64 len || version 1 | tree | parents | headers)`: the tree, the parents in written order and every byte after the `tree` and `parent` lines (author, committer, `gpgsig`, `mergetag`, `encoding`, message) byte for byte. The Git ID is not hashed in, so it is checked, not trusted: every export recomputes it. A B1 revision may name an imported commit of its repository as a parent.

`SynapseStore::record_git_import` is the only writer. Before anything is written it refuses: a Git ID mapped again to different content (`GitObjectCorrupt`); a blob whose bytes or declared size do not match (`BlobDigestMismatch`); a blob neither provided nor committed (`BlobNotFound`); a non-canonical tree node (`TreeNodeMalformed`) or one naming an unknown child or blob; a commit on an unknown tree (`TreeNodeNotFound`) or parent (`ParentChangesetNotFound`); a reference name that is not a safe `refs/...` path, out of order, or both a file and a directory (`PathInvalid`); a target never imported (`GitObjectCorrupt`). An entry already fully recorded writes nothing, so importing the same history twice writes no record.

### Import

`import_repository(store, repo, git_dir, limits)` reads the full history with the cut 1 reader (bounded by `ReadLimits`), converts all of it in memory, and only then writes: `Objects` records (at most 4,096 mappings and `max_total_changeset_bytes` of inline bytes each), one `Commit` record per commit (parents first), one `Tag` record per tag (inner tags first), one `Refs` record. A repository with anything that has no exact native form is refused `GitObjectNotRepresentable` before the first record, leaving the store unchanged:

* tree entry modes other than `100644`, `100755`, `120000` and `40000` (gitlinks `160000`, legacy `100664`, zero-padded `040000`);
* entry names that are not UTF-8 or that C1 refuses (`.git`, `.`, `..`, a `/` or `\`, empty, over 2,048 bytes);
* an empty subtree, or a tree whose canonical node does not rebuild the same Git tree (order, duplicates);
* a commit whose bytes do not start with exactly its `tree` and `parent` lines, or a tag without its leading `object` line.

A blob over the store's `max_blob_bytes` is `QuotaPayloadTooLarge`, and the reference names are checked by the same rule the store applies, also before the first record.

### Export

`export_store(store, repo, native_refs, dest)` writes a new bare repository from the store alone. Every imported blob, tree, commit and tag is rebuilt from the map and the stored blobs and must hash to its imported Git ID (`GitObjectCorrupt` otherwise); the imported references and `HEAD` follow. Each entry of `native_refs` adds a reference to a native revision, written with its native ancestors by this rule:

* tree: the revision's `base_tree` (the empty tree, an imported tree, or the result tree of a native revision exported before it) with its mutations applied as the tree store applies them (an upsert replaces a file at an ancestor path and everything below its own path; a delete removes a file);
* parents in the revision's order (imported parents by their Git IDs);
* `author <DID of the first attestation> <agent@synapse.aienos.local> 0 +0000`, `committer Synapse Engine <synapse@aienos.local> 0 +0000`;
* message: the intent summary, a blank line, `Synapse-Changeset-Id: <hex>` and `Synapse-Change-Id: <hex>`.

Nothing depends on the clock or on order of insertion, so the same store state gives the same pack bytes. A native reference that names an imported reference is `PathInvalid`.

## 2. Acceptance status (issue #48)

| Acceptance (issue #48) | Status | Evidence |
| :--- | :--- | :--- |
| Imported real repository history with no erased content exports with identical Git object IDs, using the stored original headers | Done: full history imported into the store (blobs, C1 trees, imported revisions with their original headers, tags, references), then exported from the store alone with identical IDs, for the fixture and two real repositories; the map survives reopen, checkpoint and compaction with the same export | `h1_import_then_export_from_the_store_gives_identical_ids_refs_and_fsck_strict_clean`, `h1_bridge_map_survives_reopen_and_checkpoint_with_the_same_export`, `h1_real_repository_round_trips_through_the_store_with_identical_ids` (ignored by default; real repositories below) |
| Native revisions export deterministically (two exports give identical IDs) | Done: a native revision on imported history (a file edited, a file deleted, a file turned into a directory) exports to the same pack twice and after a reopen; a native child of it exports on its parent's result tree | `h1_native_revisions_export_deterministically_on_imported_history`, `h1_a_native_child_of_a_native_revision_exports_on_its_parents_result_tree` |
| `git fsck --full --strict` clean | Done for every exported repository, fixture and real, cut 1 and cut 2 | same tests |

Cut 2 hostile input at the import boundary (`h1_import_refuses_*`, `h1_store_refuses_crafted_bridge_entries`): each case is refused typed with the store's committed sequence unchanged and no map created; reference names that would write outside the export directory never reach a write.

Real repositories through the store (`evidence/h1-git-bridge/red-green/cut2-green.txt`): the same mirror clones, imported into a fresh store (`max_blob_bytes` raised to 1 GiB), the store reopened (WAL replay), exported from the store, then the cut 1 Git checks. Release test binary, `/usr/bin/time -v`:

| Repository | Objects (blobs, trees, commits, tags) | References | Records | Import | Export | Peak RSS | Result |
| :--- | ---: | ---: | ---: | ---: | ---: | ---: | :--- |
| `aien-dev/synapse` (main `3d78efe`) | 1,915 (876, 859, 180, 0) | 75 | 183 | 7.5 s | 1.0 s | 197,116 KiB | identical IDs and references, fsck strict clean |
| `aien-dev/omega` (main `f4a9849`) | 29,636 (16,867, 10,345, 2,413, 11) | 633 | 2,433 | 123.3 s | 5.8 s | 976,824 KiB | identical IDs and references, fsck strict clean |

Reopening the store (WAL replay of the records) took 0.1 s and 0.3 s. The cut 2 mirrors are newer clones (same `main`, more pull request references), so the counts differ from the cut 1 table.

Cut 1 runs (`evidence/h1-git-bridge/red-green/green.txt`), each a `git clone --mirror` (full history, every reference including pull request refs): native read, native export, then Git checks that every reference resolves to the same object, that the exported database holds exactly the source's reachable objects (`rev-list --objects --all`), and `fsck --full --strict`:


| Repository | Objects | Commits | References | Result |
| :--- | ---: | ---: | ---: | :--- |
| `aien-dev/synapse` (main `3d78efe`) | 1,784 | 165 | 69 | identical IDs, fsck strict clean |
| `aien-dev/omega` (main `f4a9849`) | 29,635 | 2,412 | 631 | identical IDs, fsck strict clean |

The fixture (built by Git in the test) covers nested trees, executable files, a symlink, an empty file, an incompressible binary, a large text file revised twelve times (delta material), a two-parent merge, an octopus merge, an empty commit, annotated tags of a commit, a tree, a blob and another tag, a blob and an inner tag reachable only through a tag, a lightweight tag, and a commit with a multi-line `gpgsig` header and an `encoding` header. Git's own `cat-file --batch-all-objects` output is compared object by object (kind and payload) with what the native reader returns, from loose objects, from a `repack -f --depth=50` pack (offset deltas present, checked by entry type), and from a `pack-objects --stdout` pack (reference deltas present). The native index of Git's pack equals Git's `.idx` entry for entry (name, offset, CRC-32).

## 3. Red before green

`evidence/h1-git-bridge/red-green/red.txt`: six stubs, each removing one behaviour, run against the tests on base `3d78efe` before the first commit; every failure is an assertion or a typed refusal, no compile error:

1. inflate refuses dynamic Huffman blocks: 6 of 6 fail.
2. the pack reader refuses offset deltas: the offset delta and export tests fail.
3. the pack reader refuses reference deltas: the reference delta test fails.
4. the history walk does not follow tags: 3 fail (objects reachable only through a tag are missed).
5. the pack writer records CRC-32 0 in the index: the export test fails (`git verify-pack`).
6. the pack writer keeps input order: the determinism test fails.

`green.txt` holds the passing runs and the two real repository runs.

`evidence/h1-git-bridge/red-green/hostile-red.txt` (review findings B1 and B2): `tests/h1_hostile_repo.rs` uses only `GitRepository::open` and `full_history`, so the same file runs unchanged against the reviewed head `b4fe463`. There all 8 cases fail: the pipe cases (a reference, `packed-refs`, a loose object) block until the test's 10 s deadline releases them, the `/dev/zero` link fails with `IoFailure: out of memory` under the run's `ulimit -v 4000000` guard, the link to a file outside the repository and the 1 MiB reference are read as references, the 82 KB delta bomb resolves 5 objects of 256 MiB, and the detached `HEAD` commit is missing. Three further stubs on the fixed code: (A) the total budget check removed: the budget test fails; (B) links followed (`metadata` instead of `symlink_metadata`, and in the `refs/` walk): the outside-link test fails; (C) files opened without `O_NOFOLLOW | O_NONBLOCK`: the swap test blocks on the pipe until its 10 s deadline. `hostile-green.txt` holds the passing runs.

Re-review of #90 (`rereview-red.txt`): stub N1 (fan-out directory check removed) makes `h1_hostile_linked_object_fanout_directory_is_refused` fail; stub N3 (indexer budget check removed) makes the indexer unit test fail ("one byte short: indexed 2 entries instead of refusing").

Cut 2 (`cut2-red.txt`): seven stubs, each removing one behaviour, each applied alone to the finished code; the named test fails by assertion or by the test's own typed check, never by a compile error:

1. S1 the canonical-form check skipped (legacy and zero-padded modes accepted, tree rebuild not compared): the no-native-form test fails, "legacy mode 100664: imported instead of refusing".
2. S2 commit headers dropped on import: the round trip fails, export refused `GitObjectCorrupt` (the stored commit rebuilds under another ID).
3. S3 the map not rebuilt on a checkpoint load: the persistence test fails, "a checkpoint load rebuilds the same map".
4. S4 native commit time taken from the clock: the determinism test fails, "two exports give the same pack".
5. S5 reference names left to the store's check (after the objects are written): the reference test fails, "dot-dot path: nothing written" (`WalSeq(2)` against `WalSeq(0)`).
6. S6 compaction drops the blobs the map holds: the persistence test fails, export refused `BlobNotFound`.
7. S7 native result trees not remembered: the native child test fails, export refused `TreeNodeNotFound`.

`cut2-green.txt` holds the passing workspace run and the two real repository runs through the store.


## 4. Limits and what remains

* WAL kind 10 is taken because open PR #88 claims kind 9; if #88 changes its kind, nothing here depends on 9 staying free.
* A detached `HEAD`'s commit is imported (with its history) but no reference names it, and the exported `HEAD` then names `refs/heads/main` (the exporter's default); `git fsck` accepts it, the objects are identical, but the detached state is not reproduced.
* A native revision exports only when its `base_tree` is the empty tree, an imported tree, or the result of a native revision exported in the same call (its parent chain). A base registered only in the API tree store (`register_base_tree`) is `TreeNodeNotFound`. Native references are passed by the caller; the store keeps no native reference state in this cut. Native commits carry no signature.
* An import refused by the checks writes nothing. An I/O failure part way through the writes leaves the records written so far; importing again skips them and writes the rest (each record is checked against the map), so the import resumes, but the store is between states until then.
* The fan-out and `refs/` directories are checked with `symlink_metadata` and then the file below is opened with `O_NOFOLLOW`, which guards only the last path component: a directory swapped for a link between the check and the open would be followed. Closing that needs a walk relative to opened directory handles (`openat` with `O_DIRECTORY | O_NOFOLLOW` per component); not in this change.
* Exported packs are not compressed beyond zlib stored blocks and hold no deltas: the omega export is 374,712,257 bytes in cut 1 and 374,713,444 bytes in the cut 2 run through the store against 50,117 KiB for Git's own pack (`count-objects -v`). Correct and accepted by Git, but large; a native compressor is a later change.
* SHA-1 object format only. A SHA-256 Git repository (`extensions.objectformat = sha256`) is not read.
* The existing per-changeset `materialize_changeset_to_git` still writes loose objects; it is a legacy path, `export_store` is the bridge's export, and removing the legacy path is not part of this change.
* **Memory against the budget (review item c).** `ReadLimits::max_total_object_bytes` (default 1 GiB = 1,048,576 KiB) bounds the resolved object bytes a read holds, not the whole process: pack files are held whole, and the history map, the import's converted records and the export's object set sit beside them. Measured peak RSS (`/usr/bin/time -v`) for omega (374,301,457 bytes of objects): cut 1 read and export 1,114,576 KiB, 1.063 times the budget (calc:f4b7563320d5) and 3.049 times the object bytes (calc:b42240ae452f); cut 2 import, reopen and export through the store 976,824 KiB, 0.9316 times the budget (calc:3499282d5a7c) and 2.672 times the object bytes (calc:15f1957f5764). The breakdown between those parts was not profiled. A repository larger than the defaults needs the caller to raise them.
* No performance figure is claimed against a section 6 bound; the import and export times above are measurements of the test runs, not profiled (the test store uses `FsyncPolicy::EveryCommit`, one WAL record per imported commit).
