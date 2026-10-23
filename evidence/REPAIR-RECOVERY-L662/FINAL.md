# Final host qualification and review disposition — L662

Functional source after the one review fix: `df542c9127d216822d655e75accfa2c79859dd63`.
Base: `5b732e5d353bbcc3f6d0cd1eac60f2e543601521`.

## Result

All509 executed native tests passed:507 ordinary workspace tests and the two normally ignored fixture tests explicitly run with their required real inputs. No assertion was filtered to remove the H1 reference failure. Actual CLI, workspace fmt, all-target Clippy and pinned crumb verification passed. Linux host correctness only: no real partition/power-loss, live service, model/GPU or production store was tested.

The full recovered issue105 source is carried for existing PR110, not a second implementation/PR. Parent source work and its local qualification do not grant publication, exact-head signed-gate acceptance, merge or issue closure. L663 remains the authorized publisher/integration owner and must preserve paused lanes.

## Independent review and one fix pass

L665 independently inspected the whole candidate at0d95893 and established one Important finding: bare relative backup names synced the file but skipped the containing directory. The original report is preserved verbatim at [review-fix/REVIEW-L665.md](review-fix/REVIEW-L665.md). It ran source/receipt checks, not the runtime suite; it did not authorize release.

The parent reproduced that finding against real Linux syscalls, without a mocked filesystem: a synthetic damaged in-memory device repaired successfully and the backup-file fsync occurred, but `strace -f -yy` recorded **no fsync of its containing directory**. The paired observer returned1. The fix preserves relative paths and syncs `.` when a bare name has an empty parent. `write_backup` returns only after file and directory sync succeed, before the repair's device writes. The same observer then returned0 and recorded successful backup-file fsync followed by containing-directory fsync. This is syscall-order evidence, not a physical crash experiment.

After the fix, the full locked workspace suite, every ignored fixture, actual CLI, fmt, Clippy and pinned verifier all passed again. This is the workflow's one author fix pass, verified by behavioral RED/GREEN and the full suite, not a claim that a second independent reviewer judged the changed lines. The review reported no other established Important source defect. Raw evidence whitespace was preserved rather than editing receipts for presentation.

## Evidence map

- `initial/`: original full recovered source,502passed/2fixture-dependent ignored; no original source replaced wholesale.
- `behavioral-red/`: actual backup-length panic101 and helper-inherited-lock refusal101.
- `postfix/`: both corrected;504ordinary tests passed, CLI/fmt/Clippy passed.
- `fixture-gates/`: actual C1 fixture PASS and H1 missing-originHEAD FAIL101; retained unchanged.
- `h1-fix/`: separate fixer semantic RED, native506ordinary tests, hostile/read-limit checks and unchanged full-history PASS, with verified source/log hashes and original handoff.
- `final/`: first parent integrated locked506ordinary plus2explicit fixtures, CLI/fmt/Clippy and current pinned12ad0141 crumb verifier PASS.
- `review-fix/red/` and `green/`: actual strace, producing-binary/source hashes and machine-readable relative-backup durability regression outcomes. The Rust data-path test alone passed before the fix; the syscall observer correctly discriminated the missing directory sync.
- `review-fix/full/`: last full locked suite507ordinary plus2explicit fixtures, CLI/fmt/Clippy/pinned verifier PASS on exact source bytes in `df542c9`.

The earlier `qualification.json` and README explicitly describe their intermediate NOT-PASS checkpoint; they are immutable history, not overwritten by this final result. `final-qualification.json` binds the final inputs and archive. Every old failure remains available.

## Replay

Use the commands and environment in the state files. For the review regression specifically, Linux with `strace`, Cargo/Rust and an owned writable scratch directory is required:

```sh
python3 evidence/REPAIR-RECOVERY-L662/review-fix/relative-backup-qualify.py \
  --root "$PWD" --out "$TMPDIR/relative-backup-new-run"
cargo test --locked -j 6 --workspace --no-fail-fast
C1_FIXTURE_REPO=/path/to/full/source-containing-1b6e340d48417dfbcfe2df56d48a0696a3a9b250 \
SYNAPSE_H1_REAL_REPO=/path/to/full/git-directory \
  cargo test --locked -j 6 --workspace -- --ignored --nocapture --test-threads=1
cargo test --locked -j 6 -p synapse-bench --test store_repair_cli
cargo fmt --all --check
cargo clippy --locked -j 6 --workspace --all-targets -- -D warnings
```

The observer refuses an existing output directory. Spark runs used `quiet-build`, own source-bound target/TMPDIR and bounded commands, with exact invocations retained. Signing-key fixtures are synthetic and no operator credential was requested. The source gate continues to require CRUMB-VERIFY; the on-demand root note was verified with base-pinned tool12ad0141, without changing generated metadata or weakening a gate.
