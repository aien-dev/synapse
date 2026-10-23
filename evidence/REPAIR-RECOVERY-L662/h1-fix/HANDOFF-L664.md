# L664 H1 symbolic-reference repair handoff

## Outcome
- Fixed native Git ref collection to resolve symbolic ref aliases from the already-parsed loose/packed ref map. Every alias name maps to its resolved `GitOid`; loose refs override packed refs, including loose symbolic-over-packed direct refs.
- Symbolic chains work; malformed, escaping, cyclic, and dangling targets refuse with `GitObjectCorrupt`. Resolution does not open target paths. Existing loose-ref file/type/cap checks and HEAD behavior remain intact.
- The API exports resolved object IDs only; this does **not** preserve the original symbolic-edge structure.
- The original real-history assertion/test was not changed, skipped, filtered, or weakened.

## Commit and files
- Mac worktree: `/Users/drakestapleton/.hermes/cache/scratch/loop16-synapse-h1-L664`
- Branch: `fix/h1-reference-aliases-L664`
- Commit: `584f3dd1aa6be33998de5a78e0aaf7c3ac81ba04` (`fix(synapse-git): resolve symbolic refs in history`)
- Changed files only:
  - `crates/synapse-git/src/repo.rs`
  - `crates/synapse-git/tests/h1_git_bridge.rs`
- Parent base: `e7ec679cfed7fd0fa27b727964ca337ce77ce45f`
- Spark Linux test clone: `~/workspace/hermes-loop-synapse-H1-L664` (the exact changed source files were hash-checked against the committed Mac worktree; no commit/push made there).
- SHA-256: `repo.rs` `58969be5112e94de5ad5641e40b50f55e02de66bb8702a0bab0e082dfe81edc4`; `h1_git_bridge.rs` `b0b2396b502674bd6bf979eaacef2defa26a8ff5996cd309e2875a6309cfff0d`.

## TDD and qualification evidence
- RED: `cargo test -p synapse-git --test h1_git_bridge h1_native_reader_resolves_symbolic_remote_head_refs -- --exact --nocapture` failed semantically as expected: alias lookup was `None`, expected a resolved Git OID. Raw log: `spark:~/handoffs/L664-tests/red-symbolic-ref.log` (SHA-256 `411ef57a0e6bee431e67f3d89d573ed1b517baaa409cd9fadcb0615ac7ba15b9`).
- GREEN: chain + packed-target/loose-shadowing test passed; malformed/escaping/cycle/dangling refusal tests passed; hostile repo tests 8/8 passed; read-limit tests 4/4 passed. Raw logs in `spark:~/handoffs/L664-tests/green-*.log`.
- Full Linux workspace: `cargo test --workspace` passed; aggregate 506 passed, 0 failed, 2 ignored (53 test-result lines). Ignored by default: `c1_tree_and_diff_parity_with_git_on_gate4_fixture` (needs Gate 4 fixture) and `h1_real_repository_full_history_round_trips_with_identical_object_ids` (explicitly rerun and passed below). Raw log: `spark:~/handoffs/L664-tests/final-workspace.log` (SHA-256 `7f9d75537147ff1fee006606a50334a004af5f49ba5448682148634d25091fa1`).
- Formatting: `cargo fmt --all -- --check` passed, raw `spark:~/handoffs/L664-tests/final-fmt.log`.
- Clippy: `cargo clippy --workspace --all-targets -- -D warnings` passed, raw `spark:~/handoffs/L664-tests/final-clippy.log`.
- Unchanged real-history qualification: `SYNAPSE_H1_REAL_REPO="$HOME/workspace/hermes-loop-synapse105-L662/.git" cargo test -p synapse-git --test h1_git_bridge h1_real_repository_full_history_round_trips_with_identical_object_ids -- --ignored --exact --nocapture` passed against the parent-owned full fixture: 2,547 objects, 211 commits, 30 refs, 85,250,344-byte pack. Raw log: `spark:~/handoffs/L664-tests/final-real-history.log` (SHA-256 `67454f66f8930f7655bbd69d5f4de6b188e6a4b78e39cc6d47b090d3a61bc7aa`).
- Existing pre-fix failure remains preserved at `spark:~/handoffs/L662-fixture-gates/h1-real-repository.log` (SHA-256 `c3df93b712257606d0566c7435eed5d643b73798046ecf76fab32ca095d114f5`).

## Runtime pins
- Spark: Linux aarch64, `rustc 1.98.1 (48a229cea 2026-09-01)`, `cargo 1.98.1 (797e8a9bc 2026-08-05)`, `git 2.43.0`.
- Tests used per-task `CARGO_TARGET_DIR=~/workspace/targets/L664/final`, `TMPDIR=~/handoffs/L664-tests/tmp`; no hardware/model/service calls.

## Notes
- Initial bundle fetch into the clone's checked-out `qualification/105-recovered` branch was correctly refused by Git; fetched the base to a separate remote-tracking ref instead, then checked out the exact e7ec base. Parent source was not modified.
- No publication, push, ledger transition, trust/gate change, or store-repair edit was performed. Parent owns independent review and source carry.
