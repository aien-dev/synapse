#!/usr/bin/env bash
# Swarm board bench (issue #83). The rule is evidence/swarm-board/RULE.md (fixed before the
# run). Measures post -> availability at the addressed agent, board vs our own pre-board
# flow (agent-mail + crumb whisper, busy-poll peek + sniff + read), at 1/4/8/32 writers.
#
# usage: scripts/board-bench.sh [out-dir]
#   SYNAPSE_COORD_BIN  release synapse-coord binary (default: $CARGO_TARGET_DIR or ./target, release)
#   CRUMB_BIN          pinned crumb.c binary (required)
#   AGENT_MAIL         agent-mail script (default ~/.local/bin/agent-mail)
#   BENCH_SCRATCH      parent of the scratch directory (must be on the disk under test)
#
# Never touches the real ~/shared/agents: every pre-board command runs with HOME set to a
# scratch directory. No Python; bash and awk only.
set -euo pipefail
HERE=$(cd "$(dirname "$0")/.." && pwd)
OUT=${1:-$HERE/evidence/swarm-board}
BIN=${SYNAPSE_COORD_BIN:-${CARGO_TARGET_DIR:-$HERE/target}/release/synapse-coord}
CRUMB=${CRUMB_BIN:?set CRUMB_BIN to the pinned crumb binary}
MAIL=${AGENT_MAIL:-$HOME/.local/bin/agent-mail}
TOTAL=${BENCH_TOTAL:-128}   # the record uses 128 (RULE.md); smaller only for smoke runs
WRITERS=(1 4 8 32)
[ -x "$BIN" ] || { echo "no synapse-coord at $BIN"; exit 3; }
[ -x "$CRUMB" ] || { echo "no crumb at $CRUMB"; exit 3; }
[ -x "$MAIL" ] || { echo "no agent-mail at $MAIL"; exit 3; }
S=$(mktemp -d "${BENCH_SCRATCH:-$HERE}/.board-bench.XXXXXX")
trap 'rm -rf "$S"' EXIT
mkdir -p "$OUT/raw" "$S/bin"
ln -s "$CRUMB" "$S/bin/crumb"

energy_file=""
for d in /sys/class/hwmon/hwmon*; do
  if [ "$(cat "$d/name" 2>/dev/null)" = aien_spbm ] && [ "$(cat "$d/energy1_label" 2>/dev/null)" = pkg ]; then
    energy_file=$d/energy1_input
  fi
done
energy() { if [ -n "$energy_file" ]; then cat "$energy_file"; else echo NOT_METERED; fi; }

# $EPOCHREALTIME "sec.usec" -> ns since BASE (string arithmetic: no float rounding)
BASE=$(date +%s)
to_ns='function ns(t,  a){ split(t, a, "."); return (a[1]-BASE)*1000000000 + substr(a[2] "000000", 1, 6)*1000 }
       function nsr(s,  n){ n=length(s); return (substr(s,1,n-9)-BASE)*1000000000 + substr(s,n-8)+0 }'

# stats <file of latencies in us> -> "n p50 p95 max"
stats() {
  sort -n "$1" | awk '{v[NR]=$1} END {
    if (NR==0) { print 0, "NA", "NA", "NA"; exit }
    i50=int((NR*50+99)/100); i95=int((NR*95+99)/100);
    printf "%d %.0f %.0f %.0f\n", NR, v[i50], v[i95], v[NR] }'
}

# join <send files glob dir> <recv file> <out latencies> ; prints "delivered dups"
join_lat() {
  local sends=$1 recv=$2 lat=$3
  cat "$sends"/send.* > "$S/send.all"
  awk -v BASE="$BASE" "$to_ns"'
    FNR==NR { t0[$1]=ns($2); next }
    { k=$1; if (k in seen) { dup++; next } seen[k]=1
      if (!(k in t0)) next
      t1 = ($3=="ns") ? nsr($2) : ns($2)
      printf "%.0f\n", (t1 - t0[k]) / 1000; got++ }
    END { print got+0, dup+0 > "/dev/stderr" }' "$S/send.all" "$recv" > "$lat" 2> "$S/joinres"
  cat "$S/joinres"
}

{
  echo "host: $(uname -srm)"
  echo "fs: $(df -T "$S" | tail -1 | awk '{print $1, $2}')"
  echo "binary: $BIN ($(sha256sum "$BIN" | cut -c1-16))"
  echo "crumb: $CRUMB ($(sha256sum "$CRUMB" | cut -c1-16))"
  echo "agent-mail: $MAIL ($(sha256sum "$MAIL" | cut -c1-16))"
  echo "commit: $(git -C "$HERE" rev-parse HEAD)"
} > "$OUT/raw/env.txt"

# fsync floor on the same filesystem
dd_line=$(dd if=/dev/zero of="$S/dd.bin" bs=512 count=500 oflag=dsync 2>&1 | tail -1)
dd_s=$(echo "$dd_line" | awk '{for (i=1;i<=NF;i++) if ($i=="s," || $i=="s") print $(i-1)}' | head -1)
rm -f "$S/dd.bin"
echo "dd 500 x 512 B oflag=dsync: $dd_line" > "$OUT/raw/fsync.txt"

e_idle0=$(energy); sleep 5; e_idle1=$(energy)
echo "idle_5s_uJ $e_idle0 $e_idle1" > "$OUT/raw/energy-idle.txt"

wait_for() { local i=0; while ! eval "$1"; do i=$((i+1)); [ $i -gt 500 ] && return 1; sleep 0.01; done; }

board_run() {
  local W=$1 per=$((TOTAL / $1)) root=$S/board-$1 d=$S/b$1
  mkdir -p "$d"
  local B=("$BIN" board --board-root "$root")
  "${B[@]}" init > /dev/null
  "${B[@]}" --session sub-s register sub > /dev/null
  for ((w = 0; w < W; w++)); do "${B[@]}" --session "ws$w" register "w$w" > /dev/null; done
  "${B[@]}" --session sub-s watch --follow "$TOTAL" --stamp --timeout-ms 60000 > "$d/recv.json" &
  local wpid=$!
  wait_for "ls '$root'/wake/*.sock > /dev/null 2>&1"
  local e0 e1 t_start t_end
  e0=$(energy); t_start=$EPOCHREALTIME
  local pids=()
  for ((w = 0; w < W; w++)); do
    (
      for ((n = 0; n < per; n++)); do
        t0=$EPOCHREALTIME
        "${B[@]}" --session "ws$w" post --thread bench --topic "bench/w$W" --to sub --text "w$w-$n" > /dev/null
        echo "w$w-$n $t0" >> "$d/send.$w"
      done
    ) &
    pids+=($!)
  done
  wait "${pids[@]}"
  wait "$wpid" || true
  t_end=$EPOCHREALTIME; e1=$(energy)
  sed -n 's/.*"text":"\([^"]*\)".*"recv_unix_ns":\([0-9]*\).*/\1 \2 ns/p' "$d/recv.json" > "$d/recv"
  read -r got dup < <(join_lat "$d" "$d/recv" "$d/lat")
  cp "$d/lat" "$OUT/raw/board-w$W.lat_us"
  "${B[@]}" check > /dev/null && chk=clean || chk=PROBLEMS
  echo "board $W $got $dup $(stats "$d/lat") $t_start $t_end $e0 $e1 $chk"
}

old_run() {
  local W=$1 per=$((TOTAL / $1)) d=$S/o$1 H=$S/home-$1
  mkdir -p "$d" "$H/shared/agents"
  local ENVV=(env HOME="$H" PATH="$S/bin:$PATH" CRUMB_COORD_ROOT="$S/coord-$1")
  : > "$d/recv"
  (
    # agent-mail read exits 1 when it found mail (its last test is `[ $found = 0 ]`), so
    # the receiver runs without errexit and takes every exit status as-is.
    set +e
    got=0
    deadline=$(( $(date +%s) + 60 ))
    while [ "$got" -lt "$TOTAL" ] && [ "$(date +%s)" -lt "$deadline" ]; do
      n=$("${ENVV[@]}" "$MAIL" peek sub)
      "${ENVV[@]}" crumb sniff sub "$H/shared/agents" > /dev/null 2>&1
      if [ "${n:-0}" -gt 0 ]; then
        out=$("${ENVV[@]}" "$MAIL" read sub)
        t1=$EPOCHREALTIME
        while read -r k; do
          echo "$k $t1 us" >> "$d/recv"
          got=$((got + 1))
        done < <(printf '%s\n' "$out" | grep -E '^w[0-9]+-[0-9]+$')
      fi
    done
  ) &
  local rpid=$!
  local e0 e1 t_start t_end
  e0=$(energy); t_start=$EPOCHREALTIME
  local pids=()
  for ((w = 0; w < W; w++)); do
    (
      for ((n = 0; n < per; n++)); do
        t0=$EPOCHREALTIME
        "${ENVV[@]}" "$MAIL" send "w$w" sub "w$w-$n" > /dev/null
        echo "w$w-$n $t0" >> "$d/send.$w"
      done
    ) &
    pids+=($!)
  done
  wait "${pids[@]}"
  wait "$rpid" || true
  t_end=$EPOCHREALTIME; e1=$(energy)
  read -r got dup < <(join_lat "$d" "$d/recv" "$d/lat")
  cp "$d/lat" "$OUT/raw/preboard-w$W.lat_us"
  echo "preboard $W $got $dup $(stats "$d/lat") $t_start $t_end $e0 $e1 -"
}

{
  echo "# flow writers delivered dups n p50_us p95_us max_us t_start t_end energy0_uJ energy1_uJ check"
  for W in "${WRITERS[@]}"; do
    board_run "$W"
    old_run "$W"
  done
} | tee "$OUT/raw/runs.txt"
echo "fsync: $dd_line"
echo "raw results in $OUT/raw"
