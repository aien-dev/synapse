#!/usr/bin/env bash
# D1 red-before-green: one mutation per behaviour; each must turn its named tests red.
set -u
cd "$HOME/workspace/syn-39"
export CARGO_TARGET_DIR=$HOME/workspace/targets/syn-39
OUT=${OUT:-/tmp/d1-red.txt}
: > "$OUT"
M=crates/synapse-core/src/merge.rs
D=crates/synapse-core/src/derivation.rs
RV=crates/synapse-store/src/revision.rs
AD=crates/synapse-api/src/derivation.rs
mutate() { A="$2" B="$3" perl -0pi -e 'BEGIN{$a=$ENV{A};$b=$ENV{B}} $n = s/\Q$a\E/$b/; die "no match\n" unless $n' "$1"; }
run() { # name file old new -- cargo test args (one or more ';'-separated runs)
  local name=$1 file=$2 old=$3 new=$4; shift 4
  cp "$file" /tmp/d1-red-backup
  if ! mutate "$file" "$old" "$new"; then echo "MUTATION DID NOT APPLY: $name" | tee -a "$OUT"; cp /tmp/d1-red-backup "$file"; return; fi
  echo "=== $name ($file): '$old' -> '$new'" >> "$OUT"
  local log="" red=0
  IFS=';' read -ra runs <<< "$*"
  for r in "${runs[@]}"; do
    local l; l=$(eval "cargo test $r" 2>&1)
    echo "$l" | grep -E '^test .* (ok|FAILED)$|test result|^error' >> "$OUT"
    echo "$l" | grep -q 'test result: FAILED\|^error' && red=1
  done
  if [ $red = 1 ]; then echo "RED $name" | tee -a "$OUT"; else echo "STILL GREEN $name" | tee -a "$OUT"; fi
  cp /tmp/d1-red-backup "$file"
}
CORE="-p synapse-core --lib d1_"
BENCH="-p synapse-bench --lib d1_"
API="-p synapse-api --test d1_merge_tier_t1"
run unmatched-lines-forced $M '        if (0..=m).any(|j| f[i * w + j] + s[(i + 1) * w + j] == total) {' '        if false {' "$CORE;$BENCH"
run first-partner-forced $M '        if let (Some(j), None) = (partners.next(), partners.next()) {' '        if let Some(j) = partners.next() {' "$CORE;$BENCH"
run segment-shared $M '                if let Some((first, _)) = changed {' '                if let Some((first, _)) = changed.filter(|_| false) {' "$CORE;$BENCH;$API"
run t1-tag-undecodable $D '                TIER_TAG_T1 => Ok(DerivationRule::Merge {' '                99 => Ok(DerivationRule::Merge {' "-p synapse-core --lib b5_;$API"
run t1-is-t0 $D '                MergeTier::T1Region => t1_mutations(*base, &sources, trees)?,' '                MergeTier::T1Region => t0_mutations(&sources)?,' "$API;$BENCH"
run identical-not-deduped $D '            if !distinct.contains(m) {' '            if true {' "$BENCH"
run delete-unchecked $D '                MutationOp::Delete => {
                    return Err(conflict(' '                MutationOp::Delete => {
                    continue;
                    #[allow(unreachable_code)]
                    return Err(conflict(' "$API;$BENCH"
run mode-unchecked $D '        if versions.iter().any(|(mode, _)| *mode != base_mode) {' '        if false {' "$API"
run produced-blob-not-written $RV '        let wal_seq = self.append_revision_record(record, &blobs, Some(at))?;' '        let _ = &blobs;
        let wal_seq = self.append_revision_record(record, &[], Some(at))?;' "$API"
run no-blob-preload $AD '        if rule
            != (DerivationRule::Merge {' '        if true || rule
            != (DerivationRule::Merge {' "$API;$BENCH"
