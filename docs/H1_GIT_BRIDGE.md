# H1: Git Bridge, Cut 1 of 2: Native Git Objects, Packfiles, Full-History Read and Export

ADR 0003 section 9 step 28, H1 (issue aien-spark/synapse#48). Section 5.10: "Import: full history into native objects, with a persistent `GitOid` to (`ChangesetId`, `TreeDigest`) map; merge parents, tags, modes, and signatures preserved (signatures as opaque data). Export: ... written as packfiles, not loose objects". Section 4 adapts Git packfiles; section 6 keeps deltas "only on the bridge wire".

H1 is delivered in two ordered cuts. This document covers **cut 1**, the Git side of the bridge: reading a real repository's whole object graph natively and writing an object set back as a pack that Git accepts byte for byte. **Cut 2** (not in this change) adds the persistent map and the native side: imported blobs into the store, Git trees to `TreeDigest`, commits to revisions with their original headers kept as opaque bridge data, and export of imported and native history from that stored state.

Code: `crates/synapse-git/src/{object,inflate,pack,repo}.rs`. Tests: `crates/synapse-git/tests/h1_git_bridge.rs` and unit tests in each module. Evidence: `evidence/h1-git-bridge/`.

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

Residual, stated: the file checks assume the repository is not being changed while it is read. An attacker who swaps a regular file for a pipe between the `symlink_metadata` check and the `open` can still block that `open` (the inode check runs after it). Closing that needs `O_NOFOLLOW | O_NONBLOCK`, which `std` does not name portably; not done here.

## 2. Acceptance status (issue #48)

| Acceptance (issue #48) | Status | Evidence |
| :--- | :--- | :--- |
| Imported real repository history with no erased content exports with identical Git object IDs, using the stored original headers | Git side done: real full history read natively and exported with identical IDs. The native import and the stored-header path are cut 2 | `h1_full_history_exports_as_a_pack_with_identical_object_ids_and_fsck_strict_clean`; real repositories below |
| Native revisions export deterministically (two exports give identical IDs) | Pack writer deterministic (two exports, either input order, give identical pack and index bytes). Native revisions are cut 2 | `h1_export_is_deterministic_and_never_overwrites_a_repository` |
| `git fsck --full --strict` clean | Done for every exported repository, fixture and real | same tests |

Real repositories (`evidence/h1-git-bridge/red-green/green.txt`), each a `git clone --mirror` (full history, every reference including pull request refs): native read, native export, then Git checks that every reference resolves to the same object, that the exported database holds exactly the source's reachable objects (`rev-list --objects --all`), and `fsck --full --strict`:

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

`evidence/h1-git-bridge/red-green/hostile-red.txt` (review findings B1 and B2): `tests/h1_hostile_repo.rs` uses only `GitRepository::open` and `full_history`, so the same file runs unchanged against the reviewed head `b4fe463`. There all 8 cases fail: the pipe cases (a reference, `packed-refs`, a loose object) block until the test's 10 s deadline releases them, the `/dev/zero` link fails with `IoFailure: out of memory` under the run's `ulimit -v 4000000` guard, the link to a file outside the repository and the 1 MiB reference are read as references, the 82 KB delta bomb resolves 5 objects of 256 MiB, and the detached `HEAD` commit is missing. Two further stubs on the fixed code: (A) the total budget check removed: the budget test fails; (B) links followed (`metadata` instead of `symlink_metadata`, and in the `refs/` walk): the outside-link test fails. `hostile-green.txt` holds the passing runs.

## 4. Limits and what remains

* **Cut 2 remains**: the persistent `GitOid` to (`ChangesetId`, `TreeDigest`) map; imported blobs stored natively; Git trees converted to `TreeDigest` and recomputed at export; commits as revisions whose original commit and tag headers are kept as opaque bridge data; export of imported history from stored headers and of native revisions with deterministic generated message and author fields (section 5.10). It needs a new WAL record kind; open PR #88 claims kind 9, so cut 2 will use kind 10.
* Exported packs are not compressed beyond zlib stored blocks and hold no deltas: the omega export is 374,712,257 bytes against 50,117 KiB for Git's own pack (`count-objects -v`). Correct and accepted by Git, but large; a native compressor is a later change.
* SHA-1 object format only. A SHA-256 Git repository (`extensions.objectformat = sha256`) is not read.
* The existing per-changeset `materialize_changeset_to_git` still writes loose objects; it is a legacy path and is replaced by the cut 2 export.
* `GitRepository` reads whole pack files into memory and `full_history` holds every object, both bounded by `ReadLimits` (section 1a). A repository larger than the defaults needs the caller to raise them. Peak RSS of the test process for the omega round trip with the defaults: 1,114,576 KiB (`/usr/bin/time -v`).
* No performance figure is claimed: none is part of this cut's acceptance and no run was measured against a section 6 bound.
