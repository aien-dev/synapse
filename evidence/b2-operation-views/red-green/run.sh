#!/usr/bin/env bash
# B2 red-before-green: one mutation per behaviour; each must turn its named test red.
set -u
cd "$HOME/workspace/syn-30"
export CARGO_TARGET_DIR=$HOME/workspace/targets/syn-30
OUT=${OUT:-/tmp/b2-red/red.txt}
: > "$OUT"
OP=crates/synapse-store/src/operation.rs
CO=crates/synapse-store/src/codec.rs
RV=crates/synapse-store/src/revision.rs
API=crates/synapse-api/src/lib.rs
mutate() { # file old new
  A="$2" B="$3" perl -0pi -e 'BEGIN{$a=$ENV{A};$b=$ENV{B}} $n = s/\Q$a\E/$b/; die "no match\n" unless $n' "$1"
}
run() { # name file old new pkg testargs...
  local name=$1 file=$2 old=$3 new=$4 pkg=$5; shift 5
  cp "$file" /tmp/b2-red/backup
  if ! mutate "$file" "$old" "$new"; then echo "MUTATION DID NOT APPLY: $name" | tee -a "$OUT"; cp /tmp/b2-red/backup "$file"; return; fi
  echo "=== $name ($file): '$old' -> '$new'" >> "$OUT"
  local log; log=$(cargo test -p "$pkg" "$@" 2>&1)
  echo "$log" | grep -E '^test .* (ok|FAILED)$|test result|^error' >> "$OUT"
  if echo "$log" | grep -q 'test result: FAILED\|^error'; then echo "RED $name" | tee -a "$OUT"; else echo "STILL GREEN $name" | tee -a "$OUT"; fi
  cp /tmp/b2-red/backup "$file"
}
S="--lib b2_"
run undo-has-no-effect $OP 'on[k] = false;' 'on[k] = on[k];' synapse-store $S
run facts-undoable $OP 'if op.is_fact() {' 'if false && op.is_fact() {' synapse-store $S
run no-undo-dominance $OP 'if !undoer.dominates(&op.actor) {' 'if false {' synapse-store $S
run filter-ignored $OP 'if filter.is_some_and(|f| !f.dominates(&op.actor)) {' 'if false {' synapse-store $S
run replay-discard-unchecked $OP 'if !first_admitter(ops, *id, i).is_some_and(|c| op.actor.dominates(c)) =>' 'if false =>' synapse-store $S
run replay-revoke-unchecked $OP 'OpKind::Revoke { revoked } if !op.actor.dominates(revoked) => {' 'OpKind::Revoke { .. } if false => {' synapse-store $S
run conflicts-dropped $OP 'view.conflicts.insert(*seq);' '{}' synapse-store $S
run final-discard-repeatable $OP 'if fold(&ops).discarded.get(&id) == Some(&true) {' 'if false {' synapse-store $S
run store-revoke-undominated $OP 'if !chain.dominates(&revoked) {' 'if false {' synapse-store $S
run digest-ignores-kind-12 $RV 'let o = op.digest_bytes();' 'let o: Vec<u8> = Vec::new(); let _ = op;' synapse-store $S
run checkpoint-drops-kind-12 $CO '7..=9 | 11 | 12)' '7..=9 | 11)' synapse-store $S
run ledger-skips-kind-12 $RV 'WalRecord::ViewOperationRecorded { .. } => {}' 'WalRecord::ViewOperationRecorded { .. } => return,' synapse-store $S
run api-undo-capability $API '            "undo",
            &self.repo_id,
            Capability::Undo,' '            "undo",
            &self.repo_id,
            Capability::Propose,' synapse-api --test b2_operation_views
run api-revoke-not-enforced $API '        self.auth.revoke_link(leaf, out.wal_seq)?;' '' synapse-api --test b2_operation_views
