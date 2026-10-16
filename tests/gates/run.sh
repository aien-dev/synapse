#!/usr/bin/env bash
# tests/gates/run.sh: the one entry point for the local verification gates of synapse.
# Every step runs the SAME command as the hosted job it mirrors (.github/workflows/portable.yml,
# matrix gate workspace|conformance: `bash scripts/ci/portable.sh <gate>`). Manifests under
# tests/gates/ name this script plus one step word, so no manifest needs shell expansion
# (ADR 0028 P6). Observations print as "AIEN-OBS <name> <json>".
#
# Sibling checkout (conformance): the hosted job checks out aien-spark/aien-architecture at the
# pin below as .ci-architecture. Here the worker provides ../aien-architecture (main); this
# script makes a local clone of it at the pin in a temp dir (no network), so the pinned
# checkout portable.sh insists on (HEAD == pin) exists without touching the sibling.
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

case "$step" in
  workspace)
    bash scripts/ci/portable.sh workspace
    ;;
  conformance)
    if [ ! -d ../aien-architecture ]; then
      echo "run.sh: ../aien-architecture is missing; the hosted job checks out aien-spark/aien-architecture at $ARCH_PIN" >&2
      exit 3
    fi
    obs sibling_aien_architecture_commit "\"$(git -C ../aien-architecture rev-parse HEAD 2>/dev/null || echo unknown)\""
    git clone -q --no-checkout ../aien-architecture "$tmp/arch"
    git -C "$tmp/arch" checkout -q --detach "$ARCH_PIN"
    obs architecture_pin "\"$ARCH_PIN\""
    AIEN_ARCHITECTURE_REPO="$tmp/arch" bash scripts/ci/portable.sh conformance
    ;;
  zero-disk-secrets)
    echo "Auditing repository for prohibited plaintext secret files..."
    if find . -maxdepth 4 -name ".env*" -not -path "*/.git/*" -not -path "*/target/*" | grep -q .; then
      echo "Prohibited plaintext .env file found. Use an approved AIEN SecretProvider."
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
