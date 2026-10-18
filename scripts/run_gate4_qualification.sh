#!/usr/bin/env bash
set -euo pipefail

# Gate 4 comparative qualification run for Synapse (aien-sovereign-core#515).
#
# Builds the synapse-bench harness, then measures Synapse changeset ingest and
# checkout-free queries against Git worktree and Git plumbing workflows on a pinned
# commit of a real repository, runs the WAL, Git, and Radicle conformance suites,
# and writes evidence/gate4-qualification/ (report.json, manifest.json,
# traces/*.jsonl, SHA256SUMS).
#
# The fixture repository is only read: the harness clones it once with
# --no-checkout --no-hardlinks into a temporary work directory and records a digest
# of its refs before and after the run.
#
# Environment overrides:
#   FIXTURE_REPO   real repository to clone (default ~/workspace/aien-sovereign-core)
#   FIXTURE_REV    pinned commit (default: the Gate 0 baseline commit)
#   OUT_DIR        evidence directory (default <repo>/evidence/gate4-qualification)
#   WORK_PARENT    parent of the temporary work directory (default ${TMPDIR:-/tmp})
#   REPS, TIERS, ARMS, SEED   override run dimensions (see synapse-bench docs)
#   RADICLE_REPO   bare Radicle storage repo for the live conformance case; unset uses
#                  the aien-sovereign-core storage repo when present, empty disables
#   SMOKE=1        tiny end-to-end run for checking the harness

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FIXTURE_REPO="${FIXTURE_REPO:-$HOME/workspace/aien-sovereign-core}"
FIXTURE_REV="${FIXTURE_REV:-1b6e340d48417dfbcfe2df56d48a0696a3a9b250}"
OUT_DIR="${OUT_DIR:-$REPO_ROOT/evidence/gate4-qualification}"
WORK_PARENT="${WORK_PARENT:-${TMPDIR:-/tmp}}"
SMOKE="${SMOKE:-0}"
DEFAULT_RADICLE_REPO="$HOME/.radicle/storage/z2kdkm8HpiyFbMFpFmzzWZQgTn1EQ"
if [ -z "${RADICLE_REPO+set}" ]; then
  if [ -d "$DEFAULT_RADICLE_REPO" ]; then
    RADICLE_REPO="$DEFAULT_RADICLE_REPO"
  else
    RADICLE_REPO=""
  fi
fi

started=$(date +%s)
echo "== free disk at $WORK_PARENT"
df -h "$WORK_PARENT"

echo "== building synapse-bench (release)"
(cd "$REPO_ROOT" && cargo build --release -p synapse-bench --offline)
# CARGO_TARGET_DIR, when set, is where cargo put the binary (relative to REPO_ROOT, where it ran).
TD=${CARGO_TARGET_DIR:-target}; case $TD in /*) ;; *) TD="$REPO_ROOT/$TD" ;; esac
BIN="$TD/release/synapse-bench"

# Identity of the harness source that produced the evidence.
SOURCE_REV="$(git -C "$REPO_ROOT" rev-parse HEAD)"
if [ -n "$(git -C "$REPO_ROOT" status --porcelain -- crates Cargo.toml Cargo.lock scripts)" ]; then
  SOURCE_DIRTY="dirty"
else
  SOURCE_DIRTY="clean"
fi
SOURCE_DIGEST="$(cd "$REPO_ROOT" \
  && git ls-files -z -co --exclude-standard -- crates Cargo.toml Cargo.lock scripts \
  | LC_ALL=C sort -z | xargs -0 sha256sum | sha256sum | cut -d' ' -f1)"

WORK_DIR="$(mktemp -d "$WORK_PARENT/synapse-gate4.XXXXXX")"
cleanup() { rm -rf "$WORK_DIR"; }
trap cleanup EXIT

# Replace only the files this script produces.
mkdir -p "$OUT_DIR"
rm -rf "$OUT_DIR/traces"
rm -f "$OUT_DIR/report.json" "$OUT_DIR/manifest.json" "$OUT_DIR/SHA256SUMS"

args=(run
  --fixture-repo "$FIXTURE_REPO"
  --fixture-rev "$FIXTURE_REV"
  --out "$OUT_DIR"
  --work-dir "$WORK_DIR"
  --source-rev "$SOURCE_REV"
  --source-dirty "$SOURCE_DIRTY"
  --source-digest "$SOURCE_DIGEST")
[ -n "${REPS:-}" ] && args+=(--reps "$REPS")
[ -n "${TIERS:-}" ] && args+=(--tiers "$TIERS")
[ -n "${ARMS:-}" ] && args+=(--arms "$ARMS")
[ -n "${SEED:-}" ] && args+=(--seed "$SEED")
[ -n "$RADICLE_REPO" ] && args+=(--radicle-repo "$RADICLE_REPO")
[ "$SMOKE" = "1" ] && args+=(--smoke)

echo "== running qualification (work dir $WORK_DIR)"
"$BIN" "${args[@]}"

# Keep raw traces reasonably sized: compress them when they exceed 20 MiB.
trace_bytes="$(du -sb "$OUT_DIR/traces" | cut -f1)"
if [ "$trace_bytes" -gt $((20 * 1024 * 1024)) ]; then
  echo "== traces total $trace_bytes bytes; compressing with gzip -n"
  gzip -n -9 "$OUT_DIR"/traces/*.jsonl
fi

(cd "$OUT_DIR" && find . -type f ! -name SHA256SUMS -printf '%P\n' | LC_ALL=C sort \
  | xargs -d '\n' sha256sum > SHA256SUMS)

finished=$(date +%s)
echo "== done in $((finished - started)) s; evidence in $OUT_DIR"
