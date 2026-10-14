# synapse-coord

Shared agent coordination (claims, presence, whispers) for agents working through Synapse,
on the **same store** as the Crumb tool `crumb.c`. Deliverable 2 of the Crumb-Synapse
workstream (ADR 0004): move shared agent coordination off Git without creating a second,
invisible lock set.

Reference implementation: `tools/crumb/crumb.c` in aien-architecture at `29780e5`
(sha256 of the file: `ef0f6566fb838917a750eb898f66596b76aa15a53d7d61bedac03c4c963ee147`;
identical to `origin/main` on 2026-10-14), RFC-0002 plane from the comment
"RFC-0002 common coordination plane", and `docs/CRUMB_PROTOCOL_RFC_0002.md`.

## The problem this prevents

During the transition some agents claim through `crumb` in Git worktrees and some through
Synapse. If each side kept its own locks, two agents could both "own" `src/runtime.c` and
neither would know. Here both tools read and write one store under one OS lock, so a claim
made by either is refused by the other, and each sees the other in `sniff`.
`scripts/crumb-coord-interop.sh` proves this against the pinned C tool.

## Compatibility contract with crumb.c (what is kept identical)

| Aspect | Rule (same as crumb.c) |
|---|---|
| Store root | Passed in explicitly. crumb.c uses `CRUMB_COORD_ROOT`, else `git config crumb.coordinationRoot`, else `<git-common-dir>/crumb/v1`. Synapse points both at one directory beside its repository store. This crate never calls Git. |
| Layout | `dirs/<repo-relative dir>.json` (`dirs/_root.json` for `.`), `agents/<agent>.json` (bytes outside `[A-Za-z0-9._-]` become `_`), `continuations/`, `ledger/`, lock file `.lock`. |
| Transaction lock | `fcntl(F_SETLKW, F_WRLCK)` on `<root>/.lock`, whole file, held for the read-modify-write of one command. Readers (`sniff`) take no lock. |
| Durable write | `<record>.tmp<pid>`, write, fsync, close, rename over the record, fsync the directory. Only changed records are written. |
| Keys | `norm_path` collapses `.`, `..`, `//`; a path that climbs above the root is refused. Target key: `<dir>/<target>` if it exists, else `<target>` from the root if it exists, else the repo-relative form when the target contains `/`, else `<dir>/<target>`. Absolute targets must lie inside the workspace. |
| TTLs | lock 1800 s, scent 3600 s, whispers kept 24 h; a claim's presence lasts `max(3600, lock ttl)`. Expired = `now - stamp > ttl`, or the stamp is unparseable. |
| Pruning | Every mutation loads every record, drops expired locks/scents/whispers, unlinks expired agent records, and writes back what changed. |
| Records | Byte-identical JSON: key order kept, two-space indent, `": "`, trailing newline, `\u007f` and control bytes escaped as crumb.c does, numbers kept as written, unknown fields preserved. Strings are bytes (no UTF-8 requirement). History capped at 20. |
| Exit semantics | claim on a key held by another agent: blocked with holder info (C exit 2); close by a non-holder: refused (exit 2). |
| Session id | `CRUMB_SESSION` if set, else `agent@host`; never a PID. A caller may pass one explicitly. |

## What replaces branch / head / base for Synapse agents (decision)

RFC-0002 says branch, worktree, head and base are **holder metadata, never identity**.
crumb.c writes them from Git. A Synapse agent has no Git branch, so `Holder::synapse(lane,
revision, base)` fills the same fields and adds one:

| Field | Git agent (crumb.c) | Synapse agent (this crate) |
|---|---|---|
| `worktree` | `git rev-parse --show-toplevel` | the agent's workspace path or a stable absolute label (e.g. `/synapse/ws/<agent>`) |
| `branch` | short branch name | the Synapse lane/ref name |
| `head` | 12-hex short commit | first 12 hex of the ChangesetId the agent works from |
| `base` | 12-hex merge-base with origin/main | first 12 hex of the base ChangesetId |
| `synapse_revision` | absent | full ChangesetId hex (new, appended last) |

The extra field is only appended; every field crumb.c reads keeps its meaning, so crumb.c's
displays (`held by X [branch]`, `BLOCKED ... on branch ...`) stay readable. crumb.c's JSON
model keeps unknown fields, and the interop script checks that crumb.c rewriting the same
directory record keeps `synapse_revision` (I5). The crate takes strings, not
`synapse_core::ChangesetId`, so it has no dependency on Synapse internals.

## Crash safety

- A writer that dies before `rename` leaves the old record intact plus a `*.tmp<pid>` file.
  Neither tool ever loads it (records are only names ending in `.json`). Tested by killing a
  real process at that point (`SYNAPSE_COORD_FAULT=before-rename`, test-only) and by planting
  torn tmp files.
- The OS releases the `fcntl` lock when the holding process dies, so a crash never wedges the store.
- A record that is not a JSON object is refused with an error and left untouched (as crumb.c).
- POSIX record locks belong to the process, not the thread. A process-wide mutex serializes
  transactions inside one process; the `fcntl` lock serializes processes. A negative control
  (mutex removed) made the 16-thread race test fail, so both layers are needed.

## What coordination state is not

Coordination state is ephemeral. It is **never written into Synapse history**, is **never an
evidence receipt**, and is **never an authority**: a claim is advisory, it does not grant
publication or merge rights (AEGIS stays the sole publication authority). Nothing in this
crate touches `synapse-store`, changesets or refs.

## Known differences and limits

- No legacy `.crumb.local` import. crumb.c merges a worktree's `.crumb.local` into the store
  on its next mutation; Synapse workspaces have no `.crumb.local`. Until crumb.c has run once in
  such a worktree, a legacy lock there is invisible to this crate.
- `sniff` lists "other workspaces" from the records themselves (any `worktree` value other
  than the caller's); crumb.c lists Git worktrees from `git worktree list`, so crumb.c's
  OTHER WORKTREES section does not list Synapse workspaces (their agents and locks still
  appear under ACTIVE AGENTS and LOCKS).
- Key resolution consults a `PathOracle` for "does this path exist". With `NoOracle` a bare
  name like `README` claimed from `src` becomes `src/README`, whereas crumb.c in a worktree
  that has `README` at the root picks `README`. Synapse callers should pass repo-relative
  targets containing `/`, or supply an oracle over their snapshot.
- Directories are taken as given (normalized), not through `realpath`, so symlinked
  directories are not resolved the way crumb.c resolves them.
- `continuations/` and `ledger/` are created but not used; checkpoint/resume stay in `cc.sh`.

## Using it

```rust
let store = CoordStore::open("/path/beside/synapse/store/crumb/v1");
let ws = Workspace::with_oracle("/synapse/ws/agent-7",
    Holder::synapse("lane/main", &changeset_hex, &base_hex), Box::new(NoOracle));
match store.claim(&ws, "agent-7", ".", "crates/x/src/lib.rs", "refactor", None)? {
    ClaimOutcome::Claimed { key } => { /* work */ }
    ClaimOutcome::Blocked { key, holder } => { /* someone else owns it */ }
}
```

The `synapse-coord` binary mirrors `crumb claim|update|whisper|close|sniff` lines and exit
codes for scripts: `synapse-coord --store DIR --top WS [--synapse LANE REV BASE] claim ...`.

## Verification

- `cargo test -p synapse-coord`: unit tests (JSON layout, ISO time, paths) and
  `tests/plane.rs` (test.sh claim/block/close, T1-T7, threads and processes racing,
  crash before rename, torn tmp files, corrupt record refusal, byte layout, history cap).
- `scripts/crumb-coord-interop.sh [aien-architecture checkout]`: builds crumb.c at `29780e5`
  with `cc` only and runs both tools against one store (I1-I10).
