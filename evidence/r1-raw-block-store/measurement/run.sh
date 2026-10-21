#!/bin/bash
# R1 (issue #47) measurement at 222c24d: R1 raw block store on an O_DIRECT device file vs the
# A2 store on ext4, same NVMe, same session, invocations interleaved R1/A2 x3.
# The bench creates the device file itself for every cell (the path must not exist) and
# removes it after the cell.
set -eu
B=~/workspace/r1-bench
BIN=~/workspace/synapse-47/target/release/synapse-bench
OUT=$B/out
mkdir -p $OUT
wait_quiet() { while ! quietlock check >/dev/null 2>&1; do sleep 5; done; }
date -u +%FT%TZ > $OUT/start.txt
cat /proc/loadavg >> $OUT/start.txt
wait_quiet; $BIN floor --dir $B/floor --out $OUT/floor.json --iterations 300
for r in 0 1 2; do
  wait_quiet; $BIN segments --dir $B/r1 --out $OUT/raw-r1-$r.json --reps 1 --block-device $B/device.img 2> $OUT/r1-$r.log
  wait_quiet; $BIN segments --dir $B/a2 --out $OUT/raw-a2-$r.json --reps 1 2> $OUT/a2-$r.log
done
for f in $OUT/raw-*.json; do
  $BIN segments-report --raw $f --floor $OUT/floor.json > ${f/raw-/report-}
done
date -u +%FT%TZ > $OUT/end.txt
cat /proc/loadavg >> $OUT/end.txt
echo DONE
