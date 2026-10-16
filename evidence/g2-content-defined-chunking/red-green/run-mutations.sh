#!/usr/bin/env bash
# Mutation runs for ADR 0003 G2 (issue #45): each mutation breaks one rule of the chunk
# store, the G2 tests run, the output excerpt is saved, and the source is restored.
# Run from the repository root on a clean tree: evidence/g2-content-defined-chunking/red-green/run-mutations.sh
set -u
out=evidence/g2-content-defined-chunking/red-green
src=crates/synapse-store/src
run() { # id file perl-substitution description
  local id=$1 file=$2 subst=$3 desc=$4
  cp "$src/$file" "/tmp/g2-mut-$file.bak"
  perl -0pi -e "$subst" "$src/$file"
  if cmp -s "$src/$file" "/tmp/g2-mut-$file.bak"; then echo "mutation $id did not apply" >&2; exit 1; fi
  {
    echo "## mutation $id: $desc"
    cargo test --locked -p synapse-store --lib g2_tests 2>&1 \
      | grep -E '^test .* \.\.\. |panicked at|^[a-z].*(assertion|must|differ|adds|chunk|refuse)|test result' \
      | grep -v '^test result: ok. 0' | head -40
  } > "$out/mutation-$id.txt"
  cp "/tmp/g2-mut-$file.bak" "$src/$file"
  grep -c 'FAILED$' "$out/mutation-$id.txt" | sed "s/^/$id failed tests: /"
}
run M1 lib.rs 's/        if drops \{\n            let rebuilt/        if false && drops {\n            let rebuilt/' \
  "commit keeps every chunk (no deduplication against the chunk index)"
run M2 segment.rs 's/let v2 = !self.chunks.is_empty\(\) \|\| !self.manifests.is_empty\(\);/let v2 = false;/' \
  "the checkpoint segment index drops chunks and manifests"
run M3 lib.rs 's/Some\(loc\) if loc.len == \*clen => \{\}/Some(_) | None if true => {}/' \
  "replay accepts a manifest whose chunks are not indexed"
run M4 chunk.rs 's/len as u64 > self.threshold_bytes/len as u64 >= self.threshold_bytes/' \
  "a blob of exactly T bytes is chunked (threshold off by one)"
run M5 lib.rs 's/if at != len \|\| computed != digest \{/if at != len {/' \
  "a chunked read skips the BlobDigest check"
run M6 lib.rs 's/overlay\.chunks\.extend\(enc\.chunks\.iter\(\)\.map\(\|\(d, _, _\)\| \*d\)\);/let _ = &enc.chunks;/' \
  "chunks of records earlier in the same batch do not count as indexed"
run M7 lib.rs 's/self\.blob_chunks\.entry\(m\.blob\)\.or_insert\(m\);/let _ = m;/' \
  "replay forgets the manifests of replayed frames"
run M8 wal2.rs 's/if ChunkDigest::compute\(bytes\) != d \{/if false \&\& ChunkDigest::compute(bytes) != d {/' \
  "WAL v2 decode skips the chunk digest check"
