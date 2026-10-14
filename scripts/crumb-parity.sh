#!/usr/bin/env bash
# Parity check between synapse-crumb and the reference crumb.c (ADR 0004).
#
# Builds tools/crumb/crumb.c from aien-architecture at the pinned commit with `cc` only,
# copies the fixture tree (crates/synapse-crumb/tests/fixtures/tree, where `dot.crumb`
# stands for `.crumb` so this repository's own crumb tooling never reads the fixtures)
# into a throwaway Git repository, runs `validate`, `sniff`, and `explain`, and compares
# the normalised output with the golden files the Rust parity tests read.
#
# Usage: scripts/crumb-parity.sh [--update]
#   --update  rewrite the golden files instead of comparing.
# Env:   AIEN_ARCHITECTURE_REPO  path to an aien-architecture clone
#        (default: $HOME/workspace/aien-architecture).
#
# Dependencies: bash, git, cc, sha256sum, diff, coreutils. No jq, no Python.
set -euo pipefail

PIN_COMMIT=29780e56c9e6b9111d884e0d4b146737228c19f6
PIN_SOURCE_SHA256=ef0f6566fb838917a750eb898f66596b76aa15a53d7d61bedac03c4c963ee147
TARGETS=(. d1 d1/nested d1/nested/deeper d2 d3 badjson gap gap/inner unknown)

here=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
fixtures="$here/crates/synapse-crumb/tests/fixtures/tree"
golden="$here/crates/synapse-crumb/tests/golden"
arch="${AIEN_ARCHITECTURE_REPO:-$HOME/workspace/aien-architecture}"
update=0
case "${1:-}" in
  --update) update=1 ;;
  "") ;;
  *) echo "usage: $0 [--update]" >&2; exit 2 ;;
esac

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# 1. Pinned source and build.
git -C "$arch" cat-file -e "$PIN_COMMIT^{commit}" \
  || { echo "FAIL: $arch lacks commit $PIN_COMMIT (git fetch it first)" >&2; exit 1; }
git -C "$arch" show "$PIN_COMMIT:tools/crumb/crumb.c" > "$work/crumb.c"
src_sha=$(sha256sum "$work/crumb.c" | cut -d' ' -f1)
if [ "$src_sha" != "$PIN_SOURCE_SHA256" ]; then
  echo "FAIL: crumb.c sha256 $src_sha != pinned $PIN_SOURCE_SHA256" >&2; exit 1
fi
cc -O2 -o "$work/crumb" "$work/crumb.c"
bin_sha=$(sha256sum "$work/crumb" | cut -d' ' -f1)
cc_ver=$(cc --version | head -n1)
echo "crumb.c  $PIN_COMMIT sha256 $src_sha"
echo "binary   sha256 $bin_sha ($cc_ver)"

# 2. Fixture tree in a throwaway Git repository (bounds explain's upward walk at its root).
mkdir -p "$work/tree"
root=$(cd "$work/tree" && pwd -P)
while IFS= read -r -d '' f; do
  rel=${f#"$fixtures"/}
  dest="$root/$rel"
  [ "$(basename "$rel")" = dot.crumb ] && dest="$(dirname "$dest")/.crumb"
  mkdir -p "$(dirname "$dest")"
  cp "$f" "$dest"
done < <(find "$fixtures" -type f -print0)
git -C "$root" init -q
export CRUMB_COORD_ROOT="$work/coord"
mkdir -p "$CRUMB_COORD_ROOT"

norm() { sed "s#$root#<ROOT>#g"; }
out="$work/out"
mkdir -p "$out"

# 3. validate: whole tree. Exit 1 is expected (the fixtures include invalid crumbs).
set +e
"$work/crumb" validate "$root" > "$out/validate.raw"
validate_rc=$?
set -e
{ norm < "$out/validate.raw"; echo "exit $validate_rc"; } > "$out/validate.txt"

# 4. sniff: keep the directory's own .crumb lines (coordination state is not compared).
: > "$out/sniff.txt"
for t in "${TARGETS[@]}"; do
  echo "### sniff $t" >> "$out/sniff.txt"
  "$work/crumb" sniff parity "$root/$t" 2>/dev/null \
    | sed '/^shared coordination:/,$d' | norm >> "$out/sniff.txt"
done

# 5. explain: keep NEAREST CRUMB and INHERITED INVARIANTS.
: > "$out/explain.txt"
for t in "${TARGETS[@]}"; do
  echo "### explain $t" >> "$out/explain.txt"
  "$work/crumb" explain "$root/$t" 2>/dev/null \
    | sed -n '/^== NEAREST CRUMB ==$/,/^== SHARED COORDINATION ==$/p' \
    | sed '$d' | norm >> "$out/explain.txt"
done

printf 'commit %s\ncrumb.c sha256 %s\n' "$PIN_COMMIT" "$PIN_SOURCE_SHA256" > "$out/PIN"

if [ "$update" = 1 ]; then
  mkdir -p "$golden"
  cp "$out/validate.txt" "$out/sniff.txt" "$out/explain.txt" "$out/PIN" "$golden/"
  # Build record: informational, differs by compiler, never compared.
  printf 'binary sha256 %s\ncompiler %s\n' "$bin_sha" "$cc_ver" > "$golden/BUILD.txt"
  echo "UPDATED golden files in $golden"
  exit 0
fi

status=0
for f in PIN validate.txt sniff.txt explain.txt; do
  if diff -u "$golden/$f" "$out/$f"; then
    echo "PASS $f"
  else
    echo "FAIL $f differs from golden" >&2
    status=1
  fi
done
[ "$status" = 0 ] && echo "PARITY OK: crumb.c output matches the golden files"
exit "$status"
