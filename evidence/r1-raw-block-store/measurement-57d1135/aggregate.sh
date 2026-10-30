#!/bin/bash
# Median and range over the three interleaved invocations per arm and agent count.
set -eu
O=${1:-$HOME/workspace/r1-bench/out}
jq -n --slurpfile r1 <(jq -c '.cells[] + {arm:"r1"}' $O/report-r1-*.json) \
      --slurpfile a2 <(jq -c '.cells[] + {arm:"a2"}' $O/report-a2-*.json) '
  def med: sort | .[(length/2|floor)];
  def stat(f): [ .[] | f ] | {median: med, min: min, max: max, samples: .};
  ($r1 + $a2) | group_by(.arm, .agents) | map({
    arm: .[0].arm, agents: .[0].agents,
    interval_ms: stat(.interval_s*1000),
    interval_bound_ms: (.[0].interval_bound_s*1000),
    interval_fraction: stat(.interval_fraction),
    latency_p50_ms: stat(.latency.p50_ms), latency_p99_ms: stat(.latency.p99_ms),
    latency_fraction_p50: stat(.latency_fraction),
    pkg_mj_per_change: stat(.pkg_j_per_change*1000),
    energy_bound_mj: stat(.energy_bound_j*1000),
    energy_fraction: stat(.energy_fraction),
    mean_batch: stat(.mean_batch)
  })'
