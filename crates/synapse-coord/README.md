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

## Store identity: catching split coordination roots (issue #15)

The two tools agree on one store only by configuration (`CRUMB_COORD_ROOT` /
`crumb.coordinationRoot` for crumb.c, `--store` or the path given to `CoordStore` here). A
wrong root used to fail silently: each tool granted a claim on the same file in its own store.

- **Marker.** `<root>/STORE_ID` holds one line, `crumb-coord-store-id/1 <32 lowercase hex>`
  (128 random bits from `/dev/urandom`). Any other content is refused (`StoreIdUnreadable`),
  never rewritten.
- **Creation.** The first mutating transaction of a plain `CoordStore::open` handle (or
  `ensure_store_id`) creates it while holding the store lock (process mutex plus `fcntl` on
  `.lock`). It is written to `STORE_ID.tmp<pid>`, fsynced, and published with `link(2)`, which
  never replaces an existing file; then the directory is fsynced. Concurrent first opens
  (16 threads plus 8 processes, 5 rounds) all read one id. Either layer alone holds: a
  negative control with `rename` outside the lock made the race test fail; `link` outside the
  lock still passed. Reads (`sniff`, `store_id`) never create it.
- **Expecting open.** Synapse is to register a store's id per repository (taken from
  `ensure_store_id`; that registration is not built yet) and open agents with
  `CoordStore::open_expecting(root, id)`. That
  refuses with `StoreIdMissing` (no marker) or `StoreIdMismatch` (another store), before
  creating anything, and re-checks inside every transaction under the lock. An expecting handle
  never creates a marker, so a misconfigured root is never adopted. CLI:
  `--expect-store-id ID`; `synapse-coord --store DIR id` prints (and if needed creates) the id.
- **crumb.c ignores it.** The pinned crumb.c never names `STORE_ID`; it touches only `.lock`,
  `dirs/`, `agents/`, `continuations/`, `ledger/`, and its `collect_json` walks only those
  record directories. The interop script checks crumb.c never creates it and that it is
  byte-identical after crumb.c's claims, closes, whispers and prunes (I11).
- **sniff** shows `store id: <hex>` (or `(none yet)`). crumb.c's sniff does not print it;
  that needs a crumb.c change in aien-architecture (not done here). A crumb.c-side check of the
  id is likewise out of scope: today only the Synapse side refuses a wrong root.
- **Root helper.** `resolve_coord_root(env, git_config, git_common_dir)` mirrors crumb.c's
  order as a pure function (no Git calls): non-empty `CRUMB_COORD_ROOT`, else non-empty
  `crumb.coordinationRoot` (trailing `\n`/`\r` stripped), else `<common dir>/crumb/v1` with the
  common dir already absolute and resolved. Env and config values are returned as given
  (crumb.c does not canonicalize them); a config value of 511 bytes or more is refused because
  crumb.c would truncate it.

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

## Hostile store files (issue #58)

Anyone who can write into the shared store can plant a FIFO, a device, a symlink to
`/dev/zero` or a huge file under a record name. Every store file this crate reads
(`dirs/**/*.json`, `agents/*.json`, `STORE_ID`, and the `.lock` file a mutation opens) goes
through one bounded read (`src/record.rs`):

- `lstat` first: anything that is not a regular file is refused without being opened;
- then `open(O_NOFOLLOW | O_NONBLOCK)` and `fstat` the descriptor, refusing anything that is
  not a regular file (catches a swap between the two steps);
- read at most cap + 1 bytes. Caps: `MAX_RECORD_BYTES` = 1 MiB per record (crumb.c records
  are a few KiB), `MAX_MARKER_BYTES` = 4 KiB for `STORE_ID`.

A refusal is `CoordError::RefusedRecord { path, reason }` with `reason` one of `Symlink`,
`NotRegular("fifo" | "socket" | "char device" | ...)` or `TooLarge { limit }`. It is handled
exactly like a corrupt record: the operation fails, nothing is written, the file is left as
found, and the D3 pre-submit advisory reports `CoordinationStatus::Unavailable`. The scope is
store-wide, because every mutation and `sniff` load every record: a FIFO planted at
`dirs/sub/x.json` also fails `claim . other/y.c`. The error names the file; an operator
moves it aside to restore the store. Mutations
also refuse to rename over a non-regular file and to write a record over the cap; their
temporary file is created fresh with `O_EXCL | O_NOFOLLOW`. Directory listing never opens an
entry: it uses the entry type, does not walk symlinked directories, and ignores names that
do not end in `.json`.

crumb.c at 29780e5 has the same defect (a FIFO `dirs/*.json` hangs its `sniff` and `claim`);
that fix belongs in aien-architecture and is out of scope here.

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
- Key resolution consults a `PathOracle` for "does this path exist". crumb.c resolves a
  relative target named from a subdirectory by file existence (`README` from `src` may mean
  `README` or `src/README`), so with `NoOracle` such targets are refused
  (`AmbiguousWithoutTree`) instead of guessed: a guess could key one file twice and let two
  agents hold it. Without a tree, name targets from the root (dir `.`) or by absolute path,
  or supply an oracle over the snapshot.
- Directories are taken as given (normalized), not through `realpath`, so symlinked
  directories are not resolved the way crumb.c resolves them.
- Store files are never followed (#58): a symlinked record is refused and a symlinked
  directory under `dirs/` is not walked, where crumb.c follows both. A store written by
  either tool contains neither.
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
  crash before rename, torn tmp files, corrupt record refusal, byte layout, history cap) and
  `tests/identity.rs` (store identity marker: creation, thread and process race, mismatch and
  missing marker refused, recheck per transaction, crash before link, split-root control).
- `scripts/crumb-coord-interop.sh [aien-architecture checkout]`: builds crumb.c at `29780e5`
  with `cc` only and runs both tools against one store (I1-I10), checks crumb.c ignores the
  identity marker (I11), and reproduces then catches the split-root case (I12).
