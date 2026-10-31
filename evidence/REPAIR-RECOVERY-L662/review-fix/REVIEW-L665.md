# L665 independent whole-candidate review - Synapse105

**Reviewed source:** `0d95893afc6309dc280befe77806975734af8148` (frozen candidate SHA). Base: `5b732e5d353bbcc3f6d0cd1eac60f2e543601521`.

## Finding

- **Important - backup durability is not guaranteed for a common relative backup path.** In `crates/synapse-store/src/blockdev/repair.rs`, `write_backup` creates and syncs the backup file, then syncs its parent only when `path.parent()` is non-empty (around lines 839-840). For a bare relative name such as `backup.bin`, the parent is the empty path and is filtered out. The CLI accepts relative backup paths. Thus the backup contents can be `sync_all`ed while the directory entry is not; a crash can lose the backup name even though repair proceeds to overwrite superblocks/metadata (and, for adopt, acknowledged data). This violates the documented prerequisite that the recovery backup be durable before the first device write. Sync the current directory for a bare relative path, or reject relative backup paths; add a regression covering that path. I did not execute a crash test.

No other important source correctness defect was established in this read-only review. The source implements explicit actions, no-write diagnosis/healthy no-op, foreign-device refusal, exclusive locking, signed/chained history verification, backup-before-write ordering, roll-forward/adopt and interrupted-adopt handling; H1 alias resolution resolves through parsed loose/packed ref maps and refuses malformed, escaping, cyclic, and dangling aliases. This is not a release authorization.

## Inspection and verification actually performed

- Read the full task brief, candidate diff inventory/status, and source for repair, block-device I/O/mount/commit behavior, CLI, H1 reference resolution, and relevant tests/docs; inspected available qualification and behavioral/fixture receipts.
- Confirmed checkout `HEAD` equals the reviewed SHA above. Confirmed source SHA-256s for repair implementation, blockdev implementation, repair tests, H1 source/tests, and CLI; repair/blockdev/test hashes match the recorded qualification input hashes. H1 files and CLI hashes were also recorded from this checkout.
- Ran `git diff --check BASE..HEAD` (non-mutating). It reported whitespace-only issues in preserved evidence logs (trailing spaces/new blank lines); it did not report source-code whitespace issues.
- No tests, builds, rebuilds, source/evidence edits, or external writes were performed. Checkout still has the pre-existing untracked `evidence/REPAIR-RECOVERY-L662/h1-fix/`; left untouched.

## Limits

The historical receipts report 504 passed / 0 failed / 2 ignored, C1 fixture pass, and the pre-H1-fix real-repository H1 failure; those are inspected receipts, not runs by this reviewer. Per the brief, the parent’s integrated locked Linux replay was active and its result was not inspected or inferred. No Mac runtime qualification or crash-durability experiment was performed. No production device or operator key was used.
