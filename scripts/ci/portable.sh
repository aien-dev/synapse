#!/usr/bin/env bash
# Portable conformance only. No hardware, energy or performance qualification.
set -euo pipefail
cd "$(dirname "$0")/../.."
mode=${1:?usage: portable.sh workspace|conformance}
out=${CI_EVIDENCE_DIR:-$PWD/target/ci-evidence}
mkdir -p "$out"
exec > >(tee "$out/$mode.log") 2>&1
printf 'synapse_sha=%s\n' "$(git rev-parse HEAD)"
printf 'source_status:\n'; git status --porcelain
rustc -Vv
cargo -V
cc --version
git --version
uname -a
case "$mode" in
  workspace)
    cargo fmt --all --check
    cargo metadata --format-version 1 --locked >/dev/null
    cargo clippy --locked --workspace --all-targets -- -D warnings
    cargo test --locked --workspace
    ;;
  conformance)
    arch=${AIEN_ARCHITECTURE_REPO:?pinned architecture checkout required}
    pin=29780e56c9e6b9111d884e0d4b146737228c19f6
    test "$(git -C "$arch" rev-parse HEAD)" = "$pin"
    printf 'architecture_sha=%s\n' "$pin"
    OUT_DIR="$out/qualification" bash scripts/qualify-crumb-synapse.sh "$arch"
    python3 - "$out/qualification/results.json" <<'PY'
import json, sys
r = json.load(open(sys.argv[1]))
assert r['qualified'] is True
assert r['suite']['exit'] == r['parity']['exit'] == r['interop']['exit'] == 0
assert {s['id'] for s in r['scenarios']} == {f'S{i:02}' for i in range(1, 13)}
assert all(s['status'] in ('PASS', 'KNOWN-GAP') for s in r['scenarios'])
assert next(s for s in r['scenarios'] if s['id'] == 'S05')['status'] == 'PASS'
PY
    (cd "$out/qualification" && sha256sum -c SHA256SUMS)
    ;;
  *) echo "unknown gate: $mode" >&2; exit 2 ;;
esac
printf 'PASS portable %s; GB10 performance and energy: NOT_RUN\n' "$mode"
