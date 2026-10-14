#!/usr/bin/env bash
# Combined Crumb-Synapse qualification (ADR 0004 deliverable D5, issue #12).
#
# Builds the pinned reference crumb.c with `cc` only, runs the D5 scenario suite
# (crates/synapse-bench/tests/crumb_synapse_qualification.rs) with crumb.c available,
# re-checks every known defect test, runs the D1 parity and D2 interop scripts, and
# writes evidence/crumb-synapse/ (results.txt, results.json, SHA256SUMS).
#
# Usage: scripts/qualify-crumb-synapse.sh [path-to-aien-architecture-checkout]
# Env:   OUT_DIR  evidence directory (default <repo>/evidence/crumb-synapse)
# Needs: bash, git, cc, cargo, sha256sum, timeout, coreutils. No Python, no jq.
#
# Exit status: 0 when every scenario is PASS or KNOWN-GAP, each known defect still
# reproduces as recorded, and both sibling scripts pass; 1 otherwise; 3 when the pinned
# crumb.c cannot be found.
set -uo pipefail

PIN=29780e56c9e6b9111d884e0d4b146737228c19f6
PIN_SHA256=ef0f6566fb838917a750eb898f66596b76aa15a53d7d61bedac03c4c963ee147
ARCH=${1:-${AIEN_ARCHITECTURE_REPO:-$HOME/workspace/aien-architecture}}
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
OUT_DIR=${OUT_DIR:-$HERE/evidence/crumb-synapse}
SCENARIOS=(S01 S02 S03 S04 S05 S06 S07 S08 S09 S10 S11 S12)
# Known defects: "<ignored test name>|<issue URL>". Each must still fail when run.
DEFECTS=("s05_defect_fifo_record_hangs_advisory|https://github.com/aien-spark/synapse/issues/58")
T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT
overall=0

# ---- pinned crumb.c ----
git -C "$ARCH" cat-file -e "$PIN^{commit}" 2>/dev/null || { echo "NOT_RUN: $ARCH has no commit $PIN"; exit 3; }
git -C "$ARCH" show "$PIN:tools/crumb/crumb.c" > "$T/crumb.c" || exit 3
CRUMB_SHA=$(sha256sum "$T/crumb.c" | cut -c1-64)
[ "$CRUMB_SHA" = "$PIN_SHA256" ] || { echo "FAIL crumb.c sha256 $CRUMB_SHA != pinned $PIN_SHA256"; exit 1; }
cc -O2 -std=c11 -o "$T/crumb" "$T/crumb.c" || { echo "FAIL cc build of crumb.c"; exit 1; }
echo "crumb.c @ ${PIN:0:7} sha256 $CRUMB_SHA built with $(cc --version | head -1)"

COMMIT=$(git -C "$HERE" rev-parse HEAD)
DIRTY=clean
[ -n "$(git -C "$HERE" status --porcelain -- crates scripts Cargo.toml Cargo.lock)" ] && DIRTY=dirty
STARTED=$(date -u +%Y-%m-%dT%H:%M:%SZ)

# ---- D5 scenario suite ----
cd "$HERE" || exit 1
CRUMB_C_BIN="$T/crumb" cargo test -q -p synapse-bench --test crumb_synapse_qualification \
  -- --nocapture --test-threads=1 > "$T/suite.log" 2>&1
suite_rc=$?
suite_summary=$(grep -E '^test result:' "$T/suite.log" | tail -1)
echo "suite: exit $suite_rc; $suite_summary"
[ $suite_rc -eq 0 ] || { overall=1; grep -E 'panicked|FAILED' "$T/suite.log" | head -20; }

declare -A STATUS DETAIL
while IFS= read -r line; do
  rest=${line#*D5-RESULT }
  id=${rest%% *}; rest=${rest#* }
  STATUS[$id]=${rest%% *}; DETAIL[$id]=${rest#* }
done < <(grep -o 'D5-RESULT .*' "$T/suite.log")
for id in "${SCENARIOS[@]}"; do
  if [ -z "${STATUS[$id]:-}" ]; then
    STATUS[$id]=FAIL; DETAIL[$id]="no result line (scenario panicked or did not run)"
  fi
  case ${STATUS[$id]} in PASS|KNOWN-GAP) ;; *) overall=1 ;; esac
done

# ---- known defects: each ignored test must still reproduce ----
DEFECT_ROWS=()
for d in "${DEFECTS[@]}"; do
  name=${d%%|*}; url=${d#*|}
  timeout 120 cargo test -q -p synapse-bench --test crumb_synapse_qualification \
    -- --ignored --exact "$name" > "$T/defect.log" 2>&1
  if [ $? -ne 0 ]; then
    DEFECT_ROWS+=("$name|DEFECT|still reproduces; $url")
  else
    DEFECT_ROWS+=("$name|DEFECT-NOT-REPRODUCED|test now passes: un-ignore it and close $url")
    overall=1
  fi
done

# ---- sibling scripts (D1 parity, D2 interop) ----
AIEN_ARCHITECTURE_REPO="$ARCH" bash "$HERE/scripts/crumb-parity.sh" > "$T/parity.log" 2>&1
parity_rc=$?
parity_line=$(grep -E 'PARITY OK|FAIL' "$T/parity.log" | tail -1)
bash "$HERE/scripts/crumb-coord-interop.sh" "$ARCH" > "$T/interop.log" 2>&1
interop_rc=$?
interop_line=$(grep -E '^interop:' "$T/interop.log" | tail -1)
[ $parity_rc -eq 0 ] && [ $interop_rc -eq 0 ] || overall=1
FINISHED=$(date -u +%Y-%m-%dT%H:%M:%SZ)

# ---- evidence ----
mkdir -p "$OUT_DIR"
esc() { printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'; }
{
  echo "Crumb-Synapse combined qualification (ADR 0004 D5, aien-spark/synapse#12)"
  echo "synapse commit   $COMMIT ($DIRTY)"
  echo "crumb.c          aien-architecture $PIN sha256 $CRUMB_SHA"
  echo "run              $STARTED .. $FINISHED"
  echo "suite            exit $suite_rc; $suite_summary"
  echo
  printf '%-4s %-11s %s\n' ID STATUS DETAIL
  for id in "${SCENARIOS[@]}"; do printf '%-4s %-11s %s\n' "$id" "${STATUS[$id]}" "${DETAIL[$id]}"; done
  echo
  for r in "${DEFECT_ROWS[@]}"; do IFS='|' read -r n s dd <<< "$r"; echo "defect $s $n: $dd"; done
  echo "parity           exit $parity_rc; $parity_line"
  echo "interop          exit $interop_rc; $interop_line"
  echo "overall          $([ $overall -eq 0 ] && echo QUALIFIED || echo NOT-QUALIFIED)"
  echo "limit            AEGIS (aienos crates/aienos-aegis) not integrated; exit rule proven against Synapse's Publish capability and Radicle canonical promotion only"
} > "$OUT_DIR/results.txt"
{
  echo "{"
  echo "  \"schema\": \"synapse-crumb-synapse-qualification/v1\","
  echo "  \"issue\": \"https://github.com/aien-spark/synapse/issues/12\","
  echo "  \"synapse_commit\": \"$COMMIT\","
  echo "  \"source_tree\": \"$DIRTY\","
  echo "  \"crumb_c\": {\"repo\": \"aien-dev/aien-architecture\", \"commit\": \"$PIN\", \"sha256\": \"$CRUMB_SHA\"},"
  echo "  \"started_at_utc\": \"$STARTED\","
  echo "  \"finished_at_utc\": \"$FINISHED\","
  echo "  \"suite\": {\"exit\": $suite_rc, \"summary\": \"$(esc "$suite_summary")\"},"
  echo "  \"scenarios\": ["
  n=${#SCENARIOS[@]}; i=0
  for id in "${SCENARIOS[@]}"; do
    i=$((i + 1)); sep=,; [ $i -eq "$n" ] && sep=
    echo "    {\"id\": \"$id\", \"status\": \"${STATUS[$id]}\", \"detail\": \"$(esc "${DETAIL[$id]}")\"}$sep"
  done
  echo "  ],"
  echo "  \"defects\": ["
  n=${#DEFECT_ROWS[@]}; i=0
  for r in "${DEFECT_ROWS[@]}"; do
    IFS='|' read -r dn ds dd <<< "$r"
    i=$((i + 1)); sep=,; [ $i -eq "$n" ] && sep=
    echo "    {\"test\": \"$dn\", \"status\": \"$ds\", \"detail\": \"$(esc "$dd")\"}$sep"
  done
  echo "  ],"
  echo "  \"parity\": {\"exit\": $parity_rc, \"summary\": \"$(esc "$parity_line")\"},"
  echo "  \"interop\": {\"exit\": $interop_rc, \"summary\": \"$(esc "$interop_line")\"},"
  echo "  \"qualified\": $([ $overall -eq 0 ] && echo true || echo false),"
  echo "  \"limits\": [\"AEGIS not integrated (separate repository); publication gates tested are synapse-auth Capability::Publish and synapse-radicle canonical promotion\"]"
  echo "}"
} > "$OUT_DIR/results.json"
(cd "$OUT_DIR" && sha256sum results.json results.txt > SHA256SUMS)

cat "$OUT_DIR/results.txt"
exit $overall
