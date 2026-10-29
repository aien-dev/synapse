#!/usr/bin/env bash
# Issue #65 Stage A: wall-clock stack sampler for unprivileged hosts (perf_event_paranoid = 4 blocks
# perf and the PMU). gdb launches the program as its own child (allowed under yama ptrace_scope 1);
# a loop sends SIGINT to the running inferior every INTERVAL seconds of its run time, gdb stops it,
# prints every thread's backtrace, and continues. Stopped time is not sampled (the loop skips a
# stopped inferior), so samples fall in running time.
# Usage: p65-gdb-sample.sh <out-samples.txt> <max-samples> <interval-s> -- <program> [args...]
set -euo pipefail
out=$1; max=$2; interval=$3; shift 3
[ "$1" = "--" ] && shift
cmds=$(mktemp)
{
  echo "set pagination off"; echo "set confirm off"; echo "set print thread-events off"
  echo "set startup-with-shell off"; echo "set print frame-arguments none"
  echo "handle SIGINT stop print nopass"; echo "handle SIGPIPE nostop noprint pass"
  echo "run"
  for _ in $(seq "$max"); do echo 'echo ==SAMPLE==\n'; echo "thread apply all bt 48"; echo "continue"; done
} > "$cmds"
gdb -q -batch -x "$cmds" --args "$@" > "$out" 2>&1 &
gdbpid=$!
child=""
while [ -z "$child" ] && kill -0 "$gdbpid" 2>/dev/null; do child=$(pgrep -P "$gdbpid" | head -1 || true); sleep 0.05; done
echo "inferior pid $child comm $(cat /proc/$child/comm 2>/dev/null)" >&2
n=0
while kill -0 "$child" 2>/dev/null; do
  sleep "$interval"
  st=$(awk '{print $3}' "/proc/$child/stat" 2>/dev/null || echo X)
  [ "$st" = "t" ] || [ "$st" = "T" ] || [ "$st" = "X" ] && continue
  kill -INT "$child" 2>/dev/null && n=$((n+1)) || true
done
echo "signals sent: $n" >&2
wait "$gdbpid" || true
rm -f "$cmds"
echo "samples: $(grep -c '^==SAMPLE==' "$out")"
