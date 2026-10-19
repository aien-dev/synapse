#!/usr/bin/env bash
# tests/gates/run.sh: the one entry point for the local verification gates of synapse.
# Every step runs the SAME command as the hosted job it mirrors (.github/workflows/portable.yml,
# matrix gate workspace|conformance: `bash scripts/ci/portable.sh <gate>`). Manifests under tests/gates/ name this script plus one step word, so no
# manifest needs shell expansion (ADR 0028 P6). Observations print as "AIEN-OBS <name> <json>".
#
# Sibling checkout: the hosted conformance job checks out aien-spark/aien-architecture at the pin
# below as .ci-architecture. Here the worker provides ../aien-architecture (main, read-only); this
# script makes a local clone of it at the pin in a temp dir (no network), so the pinned checkout
# portable.sh insists on (HEAD == pin) exists without touching the sibling.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
step="${1:?usage: tests/gates/run.sh <step>}"
obs() { printf 'AIEN-OBS %s %s\n' "$1" "$2"; }
ARCH_PIN=29780e56c9e6b9111d884e0d4b146737228c19f6
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
# Evidence goes outside the tree (hosted: target/ci-evidence, uploaded as an artifact).
export CI_EVIDENCE_DIR="$tmp/ci-evidence"
export CARGO_TERM_COLOR=never

need_sibling() {
  local name="$1"
  if [ ! -d "../$name" ]; then
    echo "run.sh: ../$name is missing; the hosted job checks out aien-spark/$name as a sibling" >&2
    exit 3
  fi
  obs "sibling_${name//-/_}_commit" "\"$(git -C "../$name" rev-parse HEAD 2>/dev/null || echo unknown)\""
}

case "$step" in
  # Retired: crumbs are advisory (RFC-0003 Am2). Kept so the CRUMB-VERIFY manifest still resolves.
  crumb-verify)
    echo "CRUMB-VERIFY retired: crumbs are advisory notes (RFC-0003 Am2); nothing to check"
    ;;
  workspace)
    bash scripts/ci/portable.sh workspace
    ;;
  conformance)
    need_sibling aien-architecture
    git clone -q --no-checkout ../aien-architecture "$tmp/arch"
    git -C "$tmp/arch" checkout -q --detach "$ARCH_PIN"
    obs architecture_pin "\"$ARCH_PIN\""
    AIEN_ARCHITECTURE_REPO="$tmp/arch" bash scripts/ci/portable.sh conformance
    ;;
  zero-disk-secrets)
    # Not a hosted step in this repository; the same invariant the Rust repos enforce.
    echo "Auditing repository for prohibited plaintext secret files..."
    if find . -maxdepth 4 -name ".env*" -not -path "*/.git/*" -not -path "*/target/*" | grep -q .; then
      echo "::error::Prohibited plaintext .env file found. Use an approved AIEN SecretProvider."
      obs env_files_found true
      exit 1
    fi
    obs env_files_found false
    echo "Zero plaintext .env files verified."
    ;;
  *)
    echo "run.sh: unknown step '$step'" >&2
    exit 2
    ;;
esac
