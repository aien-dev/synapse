# G2: Content-Defined Chunking

ADR 0003 section 9 step G2 (issue #45), design in section 5.9, parameters chosen by experiment X6
(section 6.4). A blob above a threshold is cut into content-defined chunks by a FastCDC-style gear
chunker and stored in the segments as chunks, one copy per `ChunkDigest`. A blob's identity stays its
`BlobDigest` over the whole content (CONTEXT.md), so changing the parameters never changes an identity.

This branch is based on A2 (`feat/adr0003-a2`, not yet merged); the A2 commits come first.

## 1. Design

- **Chunker** (`crates/synapse-store/src/chunk.rs`, fixed by `evidence/g2-content-defined-chunking/x6/
  RULE.md` before its runs): gear table from SplitMix64 (seed `SYNAPSE1`), rolling hash
  `h = (h << 1) + G[byte]`, normalized cut (`bits + 2` mask below the average, `bits - 2` above), skip to
  `min`, cut at `max`. `ChunkDigest = SHA-256("SYNAPSE_CHUNK_V1\0" || u64 LE length || bytes)`.
  Written in-house; no new crates.
- **Parameters** `StoreLimits.chunking` (`ChunkParams`): a blob of at most `threshold_bytes` is stored
  whole, a longer one is chunked. Invalid parameters are refused at open. Default is the X6 winner K1:
  T = 16 KiB, min 1 KiB, avg 4 KiB, max 16 KiB. `ChunkParams::OFF` turns chunking off.
- **Chunked WAL v2 frames** (frame flag `0x02`, `wal2.rs`): after the inline blobs the payload carries
  manifests (blob digest, length, chunk list), a chunk table, and the chunk bytes. The payload digest
  covers everything before the chunk bytes; the chunk bytes are bound through their digests, and
  recovery verifies every chunk against its `ChunkDigest` before the frame digest.
- **Commit** (`conform_v2`): chunks already in the chunk index, or carried by an earlier record of the
  same batch, are dropped from the frame; a manifest of a blob already stored is dropped. A frame holds
  only new chunk bytes (RULE.md section 5.3).
- **Reads**: the blob's chunks in manifest order, contiguous runs of one segment in a single read, then
  the `BlobDigest` over the reassembled bytes (`BlobDigestMismatch` on any difference).
- **Index**: replay rebuilds the chunk index and manifests (and refuses a manifest naming a chunk that
  is nowhere indexed). The checkpoint segment index is version 2 only when it holds chunks; otherwise it
  stays version 1.
- **Old stores**: whole-blob stores (A1 files, A2 segments) read as before; a blob already stored whole
  is never re-chunked.

## 2. Acceptance and Tests

Tests in `crates/synapse-store/src/g2_tests.rs`; expected chunk bytes are computed from the chunker alone.

| Acceptance item | Test | What it shows |
| :--- | :--- | :--- |
| Every blob round-trips byte for byte with unchanged `BlobDigest` | `g2_every_blob_round_trips_byte_for_byte_with_unchanged_blob_digest` | Sizes 0, 1, T-1, T, T+1, 3 MB random, repetitive, zeros, text; read back after commit, checkpoint, reopen from the index, reopen by replay; manifest equals the chunker's cut, blobs at most T stay whole |
| Dedup between two revisions follows the X6 rule | `g2_dedup_between_two_revisions_follows_the_x6_rule` | Revision B stores exactly its chunks not already indexed; an identical revision adds nothing; chunks shared inside one record; a blob of at most T is not cut; same after checkpoint and reopen |
| Dedup inside a batch | `g2_dedup_inside_one_batch_counts_earlier_records` | Four revisions in one group-commit batch store each chunk once |
| Parameters change without changing identity | `g2_parameters_change_without_changing_identity` | OFF-then-K1 stores and a store opened with other parameters read everything |
| Fail closed | `g2_damaged_chunk_is_refused`, `g2_manifest_naming_an_unindexed_chunk_is_refused_at_replay`, `g2_invalid_chunk_parameters_are_refused_at_open`, `g2_segment_index_v2_round_trips_and_refuses_damage` | A damaged chunk byte (also with CRC and frame digest repaired) is refused at replay or read; orphan manifests, bad parameters and malformed index v2 are refused |
| Crash | `g2_crash_after_chunked_batch_sync_before_index_keeps_every_ack` | Process crash after a chunked batch is durable: every acknowledged change survives, the pending one reads back |
| Old stores readable | `g2_old_stores_stay_readable`, `g2_chunking_off_writes_the_a2_formats` | A1 fixtures and an A2 segment store written by the A2 code (`tests/fixtures/g2-a2`, generator in `evidence/.../fixture-generator`); OFF writes the A2 formats |

### 2.1 Red before green

`evidence/g2-content-defined-chunking/red-green/`: `red-a2-compile.txt` (the G2 tests do not build on
A2 `6431fcf`), `red-a2-behaviour.txt` (on A2, revision B of a 430 KB blob sharing all but about 30 KB
with A appends 434,176 log bytes), `mutation-M1.txt` to `mutation-M8.txt` (`run-mutations.sh`: each
defect put back makes at least one test fail; `green.txt` is the clean run):

| Mutation | Defect put back | Tests that fail |
| :--- | :--- | :--- |
| M1 | No dedup against the chunk index | 4 |
| M2 | Checkpoint index drops chunks and manifests | 6 |
| M3 | Replay accepts manifests with unindexed chunks | 1 |
| M4 | Threshold off by one (T bytes chunked) | 2 |
| M5 | Chunked read skips the `BlobDigest` check | 1 |
| M6 | Earlier records of a batch do not count as indexed | 1 |
| M7 | Replay forgets manifests | 5 |
| M8 | WAL decode skips the chunk digest check | 1 |

## 3. Experiment X6 and Measurement

Rule: `evidence/g2-content-defined-chunking/x6/RULE.md`, committed alone before any run. Results and
decision: `x6/RESULTS.md`. Real AIEN histories (1,037 changes, 24,093 revisions, 433.8 MB); eight
configurations, three repetitions, order rotated. **K1 wins** (the only eligible candidate): 20.7 % fewer
log bytes than no chunking (329,252,864 vs 415,395,840), 1.095 times the seconds per accepted change
(2.133 ms vs 1.947 ms; the limit was 1.10, a thin margin on a shared host), 1.068 times the seconds per
read. Against the A2 flush bound of 1.006 ms, K1 reaches 0.471 of the bound at one agent (no chunking:
0.516). Joules per change from the SoC package meter are inside the noise above idle (RESULTS.md).

## 4. Deviations from ADR Section 5.9

- `ChunkDigest` lives in `synapse-store`, not `synapse-core`, to keep this change out of the envelope
  work (B1) running in parallel; it can move later.
- A small blob (at most T) that is provided again is stored again, as in A2 (the rule applies dedup to
  blobs above T and to blobs already stored by `BlobDigest`).
- No format marker bump: builds before G2 fail closed on chunked frames (`WalFlagsNonZero`) and chunked
  segment indexes (`CheckpointCorrupt`); a store that never chunked stays readable by them.
- Chunked payload digest covers the prefix and the chunk digests, not every chunk byte, so that
  recovery can name the damaged chunk (`BlobDigestMismatch`).

## 5. Limits

- X6 is one agent, warm page cache, shared host, single run of three repetitions; K1 vs the ingest limit
  is within host noise (UNVERIFIED on a quiet host).
- Chunk bytes are not reclaimed (no garbage collection before K1).
- No cold-read or multi-agent measurement with chunking; energy is SoC package only, NVMe UNMEASURED.
- Power-loss behaviour is UNVERIFIED (as A2).
