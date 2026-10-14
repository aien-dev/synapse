#!/usr/bin/env bash
# Interop proof: crumb.c (aien-architecture @ 29780e5, built with `cc` only) and the Rust
# synapse-coord crate share ONE coordination store, so there is no split brain:
# a claim made by either tool is refused by the other, and each sees the other in sniff.
# I11/I12 cover the store identity marker (issue #15): crumb.c ignores STORE_ID, and a
# misconfigured root is caught by --expect-store-id.
#
# usage: scripts/crumb-coord-interop.sh [path-to-aien-architecture-checkout]
# needs: bash, git, cc, cargo, sha256sum, grep. No Python.
set -u
PIN=29780e5
ARCH=${1:-${AIEN_ARCH:-$HOME/workspace/aien-architecture}}
HERE=$(cd "$(dirname "$0")/.." && pwd)
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
pass=0; fail=0
ok() { echo "PASS $1"; pass=$((pass + 1)); }
bad() { echo "FAIL $1"; fail=$((fail + 1)); }

# ---- build both tools ----
git -C "$ARCH" cat-file -e "$PIN^{commit}" 2>/dev/null || { echo "NOT_RUN: $ARCH has no commit $PIN"; exit 3; }
git -C "$ARCH" show "$PIN:tools/crumb/crumb.c" > "$T/crumb.c" || exit 3
echo "crumb.c @ $PIN sha256 $(sha256sum "$T/crumb.c" | cut -c1-64)"
cc -O2 -std=c11 -o "$T/crumb" "$T/crumb.c" || { echo "FAIL cc build"; exit 1; }
(cd "$HERE" && cargo build -q -p synapse-coord --bin synapse-coord) || { echo "FAIL cargo build"; exit 1; }
RS="$HERE/target/debug/synapse-coord"
C="$T/crumb"

# ---- one Git repository with a linked worktree for crumb.c; one shared store ----
mkdir "$T/rc" && cd "$T/rc" || exit 1
git init -q -b main . && mkdir src && echo a > src/runtime.c && echo b > src/other.c && echo c > src/race.c
git add -A && git -c user.name=t -c user.email=t@t commit -qm init
git worktree add -q -b laneC "$T/wa"
STORE="$T/store/crumb/v1"
export CRUMB_COORD_ROOT="$STORE"   # crumb.c: explicit store root instead of <git-common-dir>/crumb/v1
REV=$(printf 'ab%.0s' $(seq 32)); BASE=$(printf 'cd%.0s' $(seq 32))
# The Rust side acts as a Synapse agent: workspace label, no Git, no files on disk (--no-tree).
rs() { "$RS" --store "$STORE" --top /synapse/ws/rust-agent --synapse lane/main "$REV" "$BASE" --session rust-sess --no-tree "$@"; }
cc_() { (cd "$T/wa" && "$C" "$@"); }

# I1 crumb.c claim is refused by Rust
cc_ claim c-agent src runtime.c "C rewrite" | grep -q 'CLAIMED src/runtime.c' && ok "I1 crumb.c claims src/runtime.c" || bad "I1 crumb.c claim"
# I11a crumb.c alone never creates a store identity marker (it has no notion of one)
[ ! -e "$STORE/STORE_ID" ] && ok "I11 crumb.c-only store has no STORE_ID marker" || bad "I11 crumb.c created STORE_ID"
out=$(rs claim rust-agent . src/runtime.c "rust wants it"); rc=$?
[ $rc -eq 2 ] && echo "$out" | grep -q 'BLOCKED src/runtime.c held by c-agent on branch laneC' && ok "I1 Rust claim refused (exit 2) with crumb.c holder info" || bad "I1 Rust not refused (rc=$rc: $out)"
# I2 Rust claim is refused by crumb.c
rs claim rust-agent . src/other.c "synapse edit" | grep -q 'CLAIMED src/other.c' && ok "I2 Rust claims src/other.c" || bad "I2 Rust claim"
# I11b the first Rust mutation (the blocked claim in I1 already counts) created the marker
cp "$STORE/STORE_ID" "$T/marker0" 2>/dev/null && ID=$("$RS" --store "$STORE" id) && grep -q "^crumb-coord-store-id/1 $ID\$" "$T/marker0" && ok "I11 first Rust mutation wrote STORE_ID ($ID)" || bad "I11 no marker after Rust mutation"
out=$(cc_ claim c-agent src other.c "C wants it"); rc=$?
[ $rc -eq 2 ] && echo "$out" | grep -q 'BLOCKED src/other.c held by rust-agent on branch lane/main (worktree /synapse/ws/rust-agent)' && ok "I2 crumb.c claim refused (exit 2) with Rust holder info" || bad "I2 crumb.c not refused (rc=$rc: $out)"
# I3 each sees the other in sniff
out=$(cc_ sniff c-agent src)
echo "$out" | grep -q 'agent   rust-agent .*branch lane/main' && echo "$out" | grep -q 'lock    src/other.c .*held by rust-agent \[lane/main\]' && ok "I3 crumb.c sniff shows Rust agent and lock" || { echo "$out"; bad "I3 crumb.c sniff"; }
out=$(rs sniff rust-agent src)
echo "$out" | grep -q 'agent   c-agent .*branch laneC' && echo "$out" | grep -q 'lock    src/runtime.c .*held by c-agent \[laneC\]' && echo "$out" | grep -q "$T/wa: agent c-agent; CONFLICT: src/runtime.c" && ok "I3 Rust sniff shows crumb.c agent, lock and conflicting workspace" || { echo "$out"; bad "I3 Rust sniff"; }
# I4 whispers cross both ways
cc_ whisper c-agent src rust-agent "from C" high >/dev/null && rs sniff rust-agent src | grep -q 'whisper c-agent -> rust-agent: from C' && ok "I4 crumb.c whisper visible to Rust" || bad "I4 C->Rust whisper"
rs whisper rust-agent src c-agent "from Rust" normal >/dev/null && cc_ sniff c-agent src | grep -q 'whisper rust-agent -> c-agent: from Rust' && ok "I4 Rust whisper visible to crumb.c" || bad "I4 Rust->C whisper"
# I5 crumb.c tolerates and preserves the Synapse holder field when it rewrites the same record
cc_ claim c-agent src extra.c "touch same record" >/dev/null
grep -q "\"synapse_revision\": \"$REV\"" "$STORE/dirs/src.json" && grep -q '"src/extra.c"' "$STORE/dirs/src.json" && ok "I5 crumb.c rewrote dirs/src.json and kept synapse_revision" || bad "I5 synapse_revision lost"
# I7 release semantics cross tools
cc_ close c-agent src other.c >/dev/null; [ $? -eq 2 ] && ok "I7 crumb.c cannot close Rust's lock (exit 2)" || bad "I7 C closed Rust lock"
rs close intruder . src/runtime.c >/dev/null; rc=$?
[ $rc -eq 2 ] && cc_ sniff x src | grep -q 'lock    src/runtime.c .*held by c-agent' && ok "I7 Rust close by a non-holder refused (exit 2), crumb.c lock kept" || bad "I7 Rust non-holder close (rc=$rc)"
rs close rust-agent . src/other.c modify "synapse done" | grep -q 'CLOSED src/other.c' && cc_ claim c-agent src other.c "now mine" | grep -q CLAIMED && ok "I7 Rust releases, crumb.c then claims" || bad "I7 release Rust->C"
cc_ close c-agent src runtime.c modify "C done" | grep -q 'CLOSED src/runtime.c .*(modify)$' && rs claim rust-agent . src/runtime.c "now mine" | grep -q CLAIMED && ok "I7 crumb.c releases, Rust then claims" || bad "I7 release C->Rust"
# I8 expiry rules agree
rs claim rust-agent . src/ttl.c "dies" 1 >/dev/null; sleep 2
cc_ claim c-agent src ttl.c "takes over" | grep -q CLAIMED && ok "I8 crumb.c prunes Rust's expired lock" || bad "I8 expiry Rust->C"
cc_ claim c-agent src ttl2.c "dies" 1 >/dev/null; sleep 2
rs claim rust-agent . src/ttl2.c "takes over" | grep -q CLAIMED && ok "I8 Rust prunes crumb.c's expired lock" || bad "I8 expiry C->Rust"
# I9 mixed race: 4 crumb.c + 4 Rust processes on one target, one shared fcntl lock -> exactly one winner
for i in 1 2 3 4; do
  ( cc_ claim "c$i" src race.c race >/dev/null; echo $? > "$T/rcC$i" ) &
  ( rs claim "r$i" . src/race.c race >/dev/null; echo $? > "$T/rcR$i" ) &
done; wait
w=$(cat "$T"/rcC* "$T"/rcR* | grep -c '^0$'); b=$(cat "$T"/rcC* "$T"/rcR* | grep -c '^2$')
[ "$w" -eq 1 ] && [ "$b" -eq 7 ] && ok "I9 mixed 8-way race: exactly 1 winner, 7 refused" || bad "I9 mixed race (wins=$w blocked=$b)"
nl=$(cc_ sniff x src | grep -c 'lock    src/race.c'); [ "$nl" -eq 1 ] && ok "I9 one lock record for the raced target" || bad "I9 lock count $nl"
# I6 byte format parity: Rust parse+print is the identity on every record in the store,
# whichever tool wrote it last (the Rust-only golden test pins Rust's own output layout)
n=0; same=0
for f in $(find "$STORE/dirs" "$STORE/agents" -name '*.json'); do n=$((n + 1)); "$RS" canon "$f" | cmp -s - "$f" && same=$((same + 1)); done
[ $n -gt 0 ] && [ $n -eq $same ] && ok "I6 all $n records byte-identical after Rust re-serialization" || bad "I6 format drift ($same of $n identical)"
# I10 no Synapse or Git state was written by the Rust side outside the store
[ ! -e "$T/wa/src/.crumb.local" ] && [ -z "$(git -C "$T/wa" status --porcelain)" ] && ok "I10 worktree untouched; all state lives in the store" || bad "I10 stray state"

# I11c crumb.c ignores the marker: the pinned source never names it, its record walks never
# load it, and after every crumb.c claim/close/whisper/prune above it is byte-identical.
! grep -q STORE_ID "$T/crumb.c" && ok "I11 crumb.c @ $PIN never names STORE_ID" || bad "I11 crumb.c mentions STORE_ID"
cc_ update c-agent src "after all" >/dev/null && cc_ sniff c-agent src >/dev/null && cmp -s "$STORE/STORE_ID" "$T/marker0" && ok "I11 marker byte-identical after all crumb.c mutations and prunes" || bad "I11 marker changed"
rs sniff rust-agent src | grep -q "^  store id: $ID\$" && ok "I11 Rust sniff prints the store id" || bad "I11 sniff id line"

# I12 negative control, the split brain from the #14 review: crumb.c on the right root,
# a Synapse agent misconfigured onto another root.
WRONG="$T/wrong/crumb/v1"
rsw() { "$RS" --store "$WRONG" --top /synapse/ws/rust-agent --synapse lane/main "$REV" "$BASE" --session rust-sess --no-tree "$@"; }
cc_ claim c-agent src split.c "C owns it" | grep -q 'CLAIMED src/split.c' || bad "I12 setup crumb.c claim"
out=$(rsw claim rust-agent . src/split.c "also mine"); rc=$?
[ $rc -eq 0 ] && echo "$out" | grep -q 'CLAIMED src/split.c' && ok "I12 reproduced: without an expected id both tools grant src/split.c (silent split brain)" || bad "I12 split brain not reproduced (rc=$rc: $out)"
out=$(rsw --expect-store-id "$ID" claim rust-agent . src/split2.c "x" 2>&1); rc=$?
[ $rc -eq 1 ] && echo "$out" | grep -q "expected $ID; refusing" && ok "I12 expecting open refuses the wrong root (marker mismatch, exit 1)" || bad "I12 mismatch not refused (rc=$rc: $out)"
FRESH="$T/fresh/crumb/v1"
(cd "$T/wa" && CRUMB_COORD_ROOT="$FRESH" "$C" claim c-agent src runtime.c "fresh store" >/dev/null)
out=$("$RS" --store "$FRESH" --top /synapse/ws/rust-agent --expect-store-id "$ID" --no-tree claim rust-agent . src/runtime.c x 2>&1); rc=$?
[ $rc -eq 1 ] && echo "$out" | grep -q 'has no STORE_ID marker; refusing' && [ ! -e "$FRESH/STORE_ID" ] && ok "I12 expecting open refuses a crumb.c-only root with no marker, creates none" || bad "I12 missing marker not refused (rc=$rc: $out)"
out=$(rs --expect-store-id "$ID" claim rust-agent . src/split.c "x"); rc=$?
[ $rc -eq 2 ] && echo "$out" | grep -q 'BLOCKED src/split.c held by c-agent' && ok "I12 expecting open on the right root sees crumb.c's claim (blocked, exit 2)" || bad "I12 right root (rc=$rc: $out)"

echo "interop: $pass passed, $fail failed"
[ $fail -eq 0 ]
