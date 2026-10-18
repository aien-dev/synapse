#!/usr/bin/env bash
# D2 red-before-green: one mutation per behaviour; each must turn its named tests red.
set -u
cd "$HOME/workspace/syn-40"
export CARGO_TARGET_DIR=$HOME/workspace/targets/syn-40
OUT=${OUT:-/tmp/d2-red.txt}
: > "$OUT"
C=crates/synapse-core/src/conflict.rs
D=crates/synapse-core/src/derivation.rs
RC=crates/synapse-core/src/revision.rs
L=crates/synapse-core/src/lib.rs
SC=crates/synapse-store/src/codec.rs
RV=crates/synapse-store/src/revision.rs
T=crates/synapse-api/src/tree.rs
AD=crates/synapse-api/src/derivation.rs
mutate() { A="$2" B="$3" perl -0pi -e 'BEGIN{$a=$ENV{A};$b=$ENV{B}} $n = s/\Q$a\E/$b/; die "no match\n" unless $n' "$1"; }
run() { # name file old new -- cargo test args (one or more ';'-separated runs)
  local name=$1 file=$2 old=$3 new=$4; shift 4
  cp "$file" /tmp/d2-red-backup
  if ! mutate "$file" "$old" "$new"; then echo "MUTATION DID NOT APPLY: $name" | tee -a "$OUT"; cp /tmp/d2-red-backup "$file"; return; fi
  echo "=== $name ($file): '$old' -> '$new'" >> "$OUT"
  local red=0
  IFS=';' read -ra runs <<< "$*"
  for r in "${runs[@]}"; do
    local l; l=$(eval "cargo test $r" 2>&1)
    echo "$l" | grep -E '^test .* (ok|FAILED)$|test result|^error' >> "$OUT"
    echo "$l" | grep -q 'test result: FAILED\|^error' && red=1
  done
  if [ $red = 1 ]; then echo "RED $name" | tee -a "$OUT"; else echo "STILL GREEN $name" | tee -a "$OUT"; fi
  cp /tmp/d2-red-backup "$file"
}
CORE="-p synapse-core --lib d2_"
TREE="-p synapse-api --test d2_conflict_tree"
TERMS="-p synapse-api --test d2_conflict_terms"
B5="-p synapse-api --test b5_derivation_attestation"
HEAP="-p synapse-api --test d2_conflict_heap"
# The conflict algebra (core).
run reduce-keeps-identical-states $C '            Ordering::Equal => {
                i += 1;' '            Ordering::Equal => {
                a.push(adds[i]);
                r.push(removes[j]);
                i += 1;' "$CORE;$TERMS"
run nested-term-not-flattened $C '                plus.extend_from_slice(&c.adds);
                minus.extend_from_slice(&c.removes);' '                plus.extend_from_slice(&c.removes);
                minus.extend_from_slice(&c.adds);' "$CORE;$TERMS"
run directories-not-summed-by-entry $C '        .all(EntryState::is_dir_or_absent)' '        .all(|_| false)' "$CORE;$TREE;$TERMS"
run term-bound-unchecked $C '    if r.len() > MAX_CONFLICT_REMOVES {' '    if false {' "$CORE"
run diff-writes-unchanged-entries $C '        if x == y {
            continue;
        }' '        if x == y && false {
            continue;
        }' "$CORE;$TREE;$TERMS"
run diff-deletes-directory-not-leaves $C '            (Some(xe), None) if xe.is_dir() => delete_all(t, dir_of(x), &path, out)?,' '            (Some(xe), None) if xe.is_dir() => out.push(PathMutation {
                path,
                op: MutationOp::Delete,
            }),' "$CORE"
# Only derivation rules record conflict terms.
run agent-v2-may-carry-a-term $RC '        crate::refuse_conflict_terms(&self.content.mutations, "an agent-submitted revision")?;' '' "$TERMS"
run envelope-v1-may-carry-a-term $L '        refuse_conflict_terms(&self.mutations, "an envelope v1")?;' '' "$TERMS"
run v1-codec-writes-a-term $SC '            MutationOp::Conflict(_) => {
                return Err(SynapseError::new(
                    RefusalCode::ConflictNotDerived,
                    format!("envelope v1 cannot carry the conflict term at {}", m.path),
                ))
            }' '            MutationOp::Conflict(t) => {
                w.u8(3);
                w.raw(&t.encode());
            }' "$TERMS"
# Rules.
run rebase-collision-refused-as-before-d2 $D '            // Colliding paths: onto + tree(r) - base(r), conflicts recorded as terms.' '            if true {
                return Err(recompute_mismatch(format!("rebasing {r} onto {onto} collides")));
            }' "$B5;$TERMS"
run revert-sums-like-a-rebase $D '            let summed = crate::sum_trees(trees, &[*onto, source.base_tree], &[source_tree])?;' '            let summed = crate::sum_trees(trees, &[*onto, source_tree], &[source.base_tree])?;' "$TERMS"
run revert-tag-undecodable $D '            RULE_TAG_REVERT => Ok(DerivationRule::Revert),' '            99 => Ok(DerivationRule::Revert),' "$TERMS"
run t1-merges-past-a-term $D '                MutationOp::Conflict(_) => {
                    return Err(conflict(' '                MutationOp::Conflict(_) => {
                    continue;
                    #[allow(unreachable_code)]
                    return Err(conflict(' "$TERMS"
# The tree store and the gates.
run conflict-entries-not-counted $T '                    enc.conflict(&e.name, term)?;
                    conflict_count += 1;' '                    enc.conflict(&e.name, term)?;
                    conflict_count += 0;' "$TREE;$TERMS"
run conflicted-trees-not-refused $T '        let n = self.get(root)?.conflict_count;
        if n == 0 {' '        let n = self.get(root)?.conflict_count;
        if n == 0 || n > 0 {' "$TREE;$TERMS"
run set-conflict-deletes $T '        self.put_leaf(store, path, EditEntry::Conflict(term))' '        let _ = term;
        self.delete(store, path)' "$TREE;$TERMS"
run store-verified-gate-open $RV '                .find(|m| matches!(m.op, synapse_core::MutationOp::Conflict(_)))' '                .find(|_| false)' "$TERMS"
run promotion-gate-open $AD '        self.trees.refuse_conflicted(tree, "promotion")' '        let _ = tree;
        Ok(())' "$TERMS"
# Blobs of files a conflict sum restores.
run restored-file-oid-not-looked-up $AD '                self.git_oid(*blob_digest);' '                let _ = blob_digest;' "$TERMS"
run base-tree-blob-not-written $AD '            .or_else(|| self.base_blobs.get(&digest))
            .map(Vec::as_slice)' '            .map(Vec::as_slice)' "$TERMS"
# The C1 heap accounting fix (capacity high water); the heap test runs six times.
run node-table-capacity-not-high-water $T '        self.nodes_cap = self.nodes_cap.max(self.nodes.capacity());' '        self.nodes_cap = 0;' "$HEAP;$HEAP;$HEAP;$HEAP;$HEAP;$HEAP"
git diff --stat
