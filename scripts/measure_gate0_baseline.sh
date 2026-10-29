#!/usr/bin/env bash
set -euo pipefail

# Reproducible Gate 0 baseline measurement script for Synapse (Issue #515).
# Measures actual AIEN multi-agent development traces on the host:
# 1. Active/retained Git worktree counts and disk footprint across hive-worktrees and workspace.
# 2. Historical multi-agent lane outcomes and conflict/rebase incidence in hive-ledger.md.
# 3. Empirical Git worktree creation, checkout, tree listing, diff, and merge-tree latency on aien-sovereign-core.

OUT_DIR="${1:-$(pwd)/evidence/gate0-baseline}"
mkdir -p "$OUT_DIR"

WORKSPACE_ROOT="${WORKSPACE_ROOT:-$HOME/workspace}"
SC_REPO="${WORKSPACE_ROOT}/aien-sovereign-core"
OMEGA_REPO="${WORKSPACE_ROOT}/omega"
HIVE_WT_DIR="${WORKSPACE_ROOT}/hive-worktrees"
HIVE_LEDGER="${WORKSPACE_ROOT}/hive-ledger.md"

python3 - "$OUT_DIR" "$WORKSPACE_ROOT" "$SC_REPO" "$OMEGA_REPO" "$HIVE_WT_DIR" "$HIVE_LEDGER" <<'PY'
import json
import os
import platform
import re
import shutil
import statistics
import subprocess
import sys
import tempfile
import time

out_dir, ws_root, sc_repo, omega_repo, hive_wt_dir, hive_ledger = sys.argv[1:7]

def run_cmd(cmd, cwd=None):
    return subprocess.check_output(cmd, cwd=cwd, text=True, stderr=subprocess.DEVNULL).strip()

# 1. Empirical trace inventory from hive-worktrees and workspace
hive_wt_count = 0
hive_wt_bytes = 0
if os.path.isdir(hive_wt_dir):
    entries = [os.path.join(hive_wt_dir, d) for d in os.listdir(hive_wt_dir)]
    hive_wt_count = sum(1 for e in entries if os.path.isdir(e))
    du_out = run_cmd(["du", "-sb", hive_wt_dir]).split()[0]
    hive_wt_bytes = int(du_out)

ws_agent_dirs = []
if os.path.isdir(ws_root):
    prefixes = ("omega-", "sc-", "interplane-", "physics-", "aienos-")
    for d in os.listdir(ws_root):
        p = os.path.join(ws_root, d)
        if os.path.isdir(p) and d.startswith(prefixes):
            ws_agent_dirs.append(p)

sc_worktree_registered = 0
if os.path.isdir(sc_repo):
    sc_worktree_registered = len(run_cmd(["git", "worktree", "list"], cwd=sc_repo).splitlines())

omega_worktree_registered = 0
if os.path.isdir(omega_repo):
    omega_worktree_registered = len(run_cmd(["git", "worktree", "list"], cwd=omega_repo).splitlines())

# 2. Parse hive-ledger.md for lane counts and conflict/rebase mentions
ledger_total_rows = 0
ledger_merged_rows = 0
ledger_retired_rows = 0
ledger_active_rows = 0
ledger_conflict_mentions = 0

if os.path.isfile(hive_ledger):
    with open(hive_ledger, "r", encoding="utf-8") as f:
        text = f.read()
    ledger_conflict_mentions = len(re.findall(r"conflict|rebase|stale|diverge", text, re.IGNORECASE))
    for line in text.splitlines():
        if line.startswith("|") and not line.startswith("|---") and not line.startswith("| lane") and not line.startswith("| id"):
            ledger_total_rows += 1
            lower = line.lower()
            if "merged" in lower:
                ledger_merged_rows += 1
            elif "retired" in lower:
                ledger_retired_rows += 1
            elif any(k in lower for k in ("briefed", "running", "tested", "inspected")):
                ledger_active_rows += 1

# 3. Measure Git operation latencies on aien-sovereign-core (non-destructive)
head_sha = run_cmd(["git", "rev-parse", "origin/main"], cwd=sc_repo)
parent_sha = run_cmd(["git", "rev-parse", "origin/main~1"], cwd=sc_repo)

def bench_op(fn, iterations=9):
    samples_ms = []
    for _ in range(iterations):
        t0 = time.perf_counter()
        fn()
        t1 = time.perf_counter()
        samples_ms.append((t1 - t0) * 1000.0)
    samples_ms.sort()
    return {
        "iterations": iterations,
        "p50_ms": round(samples_ms[len(samples_ms) // 2], 3),
        "p95_ms": round(samples_ms[int(len(samples_ms) * 0.95)], 3),
        "max_ms": round(samples_ms[-1], 3),
        "mean_ms": round(statistics.mean(samples_ms), 3),
    }

ls_tree_stats = bench_op(lambda: run_cmd(["git", "ls-tree", "-r", head_sha], cwd=sc_repo))
diff_stats = bench_op(lambda: run_cmd(["git", "diff", "--stat", parent_sha, head_sha], cwd=sc_repo))
log_stats = bench_op(lambda: run_cmd(["git", "log", "-n", "50", "--oneline", head_sha], cwd=sc_repo))
merge_tree_stats = bench_op(lambda: run_cmd(["git", "merge-tree", "--write-tree", parent_sha, head_sha], cwd=sc_repo))

# Measure full worktree add + remove cost in a temporary directory
wt_add_samples_ms = []
wt_disk_bytes = 0
for i in range(3):
    tmp_wt = tempfile.mkdtemp(prefix="synapse-gate0-wt-")
    os.rmdir(tmp_wt)
    try:
        t0 = time.perf_counter()
        subprocess.run(
            ["git", "worktree", "add", "--detach", tmp_wt, head_sha],
            cwd=sc_repo,
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        t1 = time.perf_counter()
        wt_add_samples_ms.append((t1 - t0) * 1000.0)
        if i == 0:
            wt_disk_bytes = int(run_cmd(["du", "-sb", tmp_wt]).split()[0])
    finally:
        subprocess.run(
            ["git", "worktree", "remove", "--force", tmp_wt],
            cwd=sc_repo,
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        shutil.rmtree(tmp_wt, ignore_errors=True)

wt_add_samples_ms.sort()
worktree_checkout_stats = {
    "iterations": len(wt_add_samples_ms),
    "p50_ms": round(wt_add_samples_ms[len(wt_add_samples_ms) // 2], 3),
    "max_ms": round(wt_add_samples_ms[-1], 3),
    "mean_ms": round(statistics.mean(wt_add_samples_ms), 3),
    "single_worktree_bytes": wt_disk_bytes,
    "single_worktree_mib": round(wt_disk_bytes / (1024.0 * 1024.0), 2),
    "implied_throughput_worktrees_per_sec": round(1000.0 / statistics.mean(wt_add_samples_ms), 3),
}

report = {
    "schema_version": 1,
    "gate": "GATE_0_BASELINE",
    "measured_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    "host": {
        "hostname": platform.node(),
        "os": platform.platform(),
        "arch": platform.machine(),
        "cpu_model": "ARM Cortex-X925 + Cortex-A725 (20 cores, NVIDIA DGX Spark GB10)",
        "git_version": run_cmd(["git", "--version"]),
    },
    "empirical_workspace_traces": {
        "hive_worktrees_directory": hive_wt_dir,
        "hive_worktrees_count": hive_wt_count,
        "hive_worktrees_total_bytes": hive_wt_bytes,
        "hive_worktrees_total_gib": round(hive_wt_bytes / (1024.0 ** 3), 2),
        "workspace_agent_clones_count": len(ws_agent_dirs),
        "sovereign_core_registered_worktrees": sc_worktree_registered,
        "omega_registered_worktrees": omega_worktree_registered,
        "total_registered_worktrees_sc_plus_omega": sc_worktree_registered + omega_worktree_registered,
        "hive_ledger_total_rows": ledger_total_rows,
        "hive_ledger_merged_rows": ledger_merged_rows,
        "hive_ledger_retired_rows": ledger_retired_rows,
        "hive_ledger_active_rows": ledger_active_rows,
        "hive_ledger_conflict_or_rebase_mentions": ledger_conflict_mentions,
    },
    "sovereign_core_git_baseline": {
        "repository": sc_repo,
        "head_commit": head_sha,
        "parent_commit": parent_sha,
        "worktree_checkout": worktree_checkout_stats,
        "git_ls_tree_recursive": ls_tree_stats,
        "git_diff_stat": diff_stats,
        "git_log_50": log_stats,
        "git_merge_tree": merge_tree_stats,
    },
}

out_path = os.path.join(out_dir, "baseline_report.json")
with open(out_path, "w", encoding="utf-8") as f:
    json.dump(report, f, indent=2, sort_keys=True)
    f.write("\n")

print(json.dumps(report, indent=2, sort_keys=True))
PY

(cd "$OUT_DIR" && sha256sum baseline_report.json > SHA256SUMS)
