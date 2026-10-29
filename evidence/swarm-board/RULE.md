# Swarm board bench: the rule (fixed before the measurement run)

Committed before `scripts/board-bench.sh` is run for the record. Changing this file after
the run invalidates the run.

## Question

How long does a message take from "a writer starts sending it" to "the addressed agent has
it in hand", on the board versus on our own pre-board flow, at 1, 4, 8 and 32 concurrent
writers? How close is the board to the disk's fsync floor?

Only our own two flows are compared. No outside system is measured or cited.

## Flows (same host, same disk, same workload)

- **board**: writer runs `synapse-coord board post --to sub ...` (release build). The
  subscriber runs one `synapse-coord board watch --follow TOTAL --stamp` that waits on its
  wake socket and stamps each event when it reads it.
- **pre-board**: writer runs `agent-mail send <w> sub <msg>`, which writes the mail file and
  runs `crumb whisper` (crumb.c, the pinned tool). The receiver is the best case for the old
  flow: a busy loop of `agent-mail peek sub`, `crumb sniff sub <dir>`, `agent-mail read sub`
  with no sleep, stamping each message when `read` returns it. `HOME` is a temporary
  directory so the real `~/shared/agents/inbox` is never touched; `CRUMB_COORD_ROOT` is
  temporary; `crumb` is put on `PATH` through a temporary bin directory.
- Excluded from both, said out loud: the orchestrator's repost of a message to other agents
  (an LLM turn) that the pre-board flow needs and the board removes. Including it would only
  add seconds to the pre-board side.

## Workload

128 messages per run, split evenly over W writers: W=1 (128 each), 4 (32), 8 (16), 32 (4).
Each writer sends its messages one after another; all writers start together. Every message
carries a unique key `w<writer>-<n>`. One run per (flow, W).

## Measurements (all host-observed)

- latency per message = receiver stamp minus the writer's stamp taken immediately before it
  invokes the send command (bash `$EPOCHREALTIME`, the receiver's `recv_unix_ns` or
  `$EPOCHREALTIME`). Both flows include process start of the send command.
- p50 and p95 of latency, delivered count, duplicates, wall time of the run.
- fsync floor: `dd bs=512 count=500 oflag=dsync` on the same filesystem, run by the script
  before the measurements (t_fsync = dd time / 500). A board post is acknowledged after two
  serial fsync rounds (journal; then table and indexes in one parallel group), so the floor
  for one post's latency is 2 x t_fsync. The writer lock is never held across an fsync
  (group commit), so concurrent posts share flushes and the floor does not grow with W.
  Reported: floor / p50 at each W (1.0 would be the disk's limit).
- energy: package energy meter `hwmon aien_spbm energy1 (pkg)` in microjoules, read at the
  start and end of each run; whole-package, so background load on the host is included and
  is reported alongside as the idle reading over 5 s before the runs.

## Verdict rule

The board **PASSES** when, at every W in {1, 4, 8, 32}:

1. it delivers 128 of 128 messages with no duplicate, and
2. its p50 latency is at most the pre-board flow's p50 latency.

Otherwise it **FAILS**, and the failing W and numbers are reported as they are. p95, the
fraction of the fsync floor and energy are reported but do not decide the verdict. The
pre-board flow does not fsync its mail files, so it is not durable; the board is. That
difference is reported, not corrected for.
