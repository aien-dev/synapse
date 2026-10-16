#!/bin/bash
set -eu
B=~/workspace/backlog-sweep/synapse/23/bench
A2=~/workspace/backlog-sweep/synapse/23/synapse/target/release/synapse-bench
MAIN=/tmp/a2main/target-probe/release/synapse-bench
wait_quiet() { while ! quietlock check >/dev/null 2>&1; do sleep 5; done; }
date -u +%FT%TZ > $B/out/start.txt
cat /proc/loadavg >> $B/out/start.txt
wait_quiet; $A2 floor --dir $B/floor --out $B/out/floor.json --iterations 300
wait_quiet; $A2 segments --dir $B/a2 --out $B/out/raw-a2.json 2> $B/out/a2.log
wait_quiet; $MAIN segments --dir $B/main --out $B/out/raw-main.json 2> $B/out/main.log
date -u +%FT%TZ > $B/out/end.txt
cat /proc/loadavg >> $B/out/end.txt
echo DONE
