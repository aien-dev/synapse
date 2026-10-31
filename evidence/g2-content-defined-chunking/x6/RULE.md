# X6 Rule: Content-Defined Chunking Threshold and Chunk Sizes

ADR 0003 section 6.4 row X6, for step G2 (issue #45). This file fixes the candidates, the corpus,
the measurements, the deduplication rule, and the decision criterion BEFORE any X6 run. It is
committed on its own; the runs, the raw samples, and the outcome are added in later commits and
must not change anything below.

## 1. The Chunker (fixed for every candidate)

A FastCDC-style gear chunker [S20] with normalized chunking, written in `synapse-store`:

- **Gear table.** `G[i]`, `i = 0..255`, is the `i`-th output (first output is `G[0]`) of SplitMix64
  seeded with `0x5359_4E41_5053_4531` (ASCII `SYNAPSE1`): `state += 0x9E37_79B9_7F4A_7C15;
  z = state; z = (z ^ (z >> 30)) * 0xBF58_476D_1CE4_E5B9; z = (z ^ (z >> 27)) * 0x94D0_49BB_1331_11EB;
  out = z ^ (z >> 31)` (wrapping arithmetic on `u64`).
- **Rolling hash.** `h = (h << 1) + G[byte]` (wrapping), reset to 0 at the start of every chunk.
- **Cut rule** for the remaining bytes `src` of a blob, with `bits = log2(avg)`, `mask_s` = the top
  `bits + 2` bits of a `u64` set, `mask_l` = the top `bits - 2` bits set:
  if `len(src) <= min` the rest is one chunk; otherwise `n = min(len(src), max)`, hashing starts at
  byte `min` (bytes before it are skipped), the cut is after byte `i` at the first `i` with
  `h & mask_s == 0` while `i < min(avg, n)`, else the first `i` with `h & mask_l == 0` while `i < n`,
  else at `n`.
- **Threshold.** A blob of `len <= T` bytes is stored whole (one copy per `BlobDigest`, as before
  G2). A blob of `len > T` bytes is cut into chunks; each chunk is stored once per `ChunkDigest`.
- **Chunk identity.** `ChunkDigest = SHA-256("SYNAPSE_CHUNK_V1\0" || u64 LE length || bytes)`. A
  blob's identity stays its `BlobDigest` over the whole content (CONTEXT.md).

## 2. Candidates

`min = avg / 4`, `max = 4 * avg` for every chunked candidate.

| Id | Threshold T | min | avg | max |
| :--- | ---: | ---: | ---: | ---: |
| C0 | no chunking (control: every blob whole, the A2 behaviour) | | | |
| K1 | 16 KiB | 1 KiB | 4 KiB | 16 KiB |
| K2 | 16 KiB | 2 KiB | 8 KiB | 32 KiB |
| K3 | 64 KiB | 2 KiB | 8 KiB | 32 KiB |
| K4 | 64 KiB | 4 KiB | 16 KiB | 64 KiB |
| K5 | 64 KiB | 8 KiB | 32 KiB | 128 KiB |
| K6 | 256 KiB | 4 KiB | 16 KiB | 64 KiB |
| K7 | 256 KiB | 16 KiB | 64 KiB | 256 KiB |

## 3. Corpus: Real AIEN Repository Histories

Bare clones of four AIEN repositories at these commits (fetched 2026-10-16):

| Repository | Commit |
| :--- | :--- |
| `aien-spark/aien-architecture` | `d2768e9b8730af5f13c0fbbdfbfa4ba788f7605a` |
| `aien-spark/aienos` | `b7ebf7cde234e1ddcc91eb8fcaf378d060cfb3a2` |
| `aien-spark/omega` | `43d8d20da2f64319bcf6196ac7204021c3f280eb` |
| `aien-spark/synapse` | `b9f46b16aa74301f0b330cfb5fa2e06f07d60b43` |

- History: `git log --reverse --first-parent --raw --no-renames` of each commit, repositories in the
  order of the table. Survey before the runs (from `git cat-file --batch-check`, not a run):
  24,093 added or modified regular-file revisions, 434 MB of content, 4,676 revisions above 16 KiB.
- **One accepted change per commit** that adds or modifies at least one regular file (mode `100644`
  or `100755`): one signed changeset with one `Upsert` per such file. Deletions, symlinks, and
  submodules store no content and are left out. Paths are replaced by a stable synthetic path per
  repository path (`p<n>`), since paths do not affect storage.
- The client provides a blob's bytes only the first time its `BlobDigest` appears in the run (as a
  client that asks which blobs the server lacks would); later references name the committed blob.
- Store limits for the run: `max_paths_per_changeset` and `max_total_changeset_bytes` raised so that
  no commit is refused (the largest commit decides; the value is recorded in the raw output); every
  other limit at its default; group commit (`GROUP_COMMIT_DEFAULT`), one agent, strict recovery.

## 4. Measurements

Per candidate and repetition, on a fresh store on the same ext4/NVMe filesystem as the A2 runs:

1. **Ingest phase:** submit every change in order, one agent; record each change's time from submit
   to durable acknowledgement (raw samples) and the phase wall time. Energy: one `aien_spbm` package
   window around the phase (`INSTRUMENT_UNAVAILABLE` when the meter refuses, never a substitute).
2. **Log bytes:** bytes the store appended to its segments during the ingest phase (4 KiB-padded
   batches, so frame headers, metadata, chunk tables, manifests, and padding all count), and the
   content bytes stored (whole blobs plus distinct chunks). Both are deterministic for a sequential
   run; if repetitions of one candidate disagree, the run is invalid.
3. **Read phase:** read every distinct committed blob once, in commit order, through
   `get_blob_visible`; each read is compared byte for byte with the corpus bytes (any difference makes
   the run invalid); record each read's time (raw samples), the phase wall time, and one energy window.

Three repetitions; inside each repetition all eight configurations run once, in an order rotated by
one position per repetition. Bounds (ADR section 6.2): seconds per accepted change against the A2 flush
bound (1.006 ms, `evidence/a2-segment-store/measurement/floor.json`, cheapest
`overwrite_*_fdatasync` p50); a read of `n` bytes against `n` / 273 GB/s plus one index lookup.

## 5. Deduplication Rule (the G2 acceptance)

For a store with chunk parameters `(T, min, avg, max)`:

1. A blob of `len <= T` is stored whole and is never cut.
2. A blob of `len > T` is cut by the chunker of section 1; reading it returns exactly its bytes, and
   its `BlobDigest` is unchanged.
3. The store keeps one copy of every `ChunkDigest` it indexes. Committing a revision `B` of a blob
   above `T` after a committed revision `A` whose chunks are still indexed stores exactly the distinct
   chunks of `B` whose `ChunkDigest` is not already indexed (chunks committed earlier in the same batch
   count as indexed): content bytes added = the sum of their lengths, nothing for the shared chunks.
   A revision whose `BlobDigest` is already stored adds no chunk.

## 6. Decision Criterion

Let, for configuration `k`: `W_k` = median over the three repetitions of (ingest phase wall time /
accepted changes); `R_k` = median of (read phase wall time / reads); `S_k` = log bytes of the ingest
phase.

1. A chunked candidate is **eligible** when all three hold: `W_k <= 1.10 * W_C0` (seconds per accepted
   change at most 10 % above the control), `R_k <= 1.25 * R_C0` (seconds per read at most 25 % above),
   and `S_k <= 0.95 * S_C0` (at least 5 % fewer log bytes).
2. The **winner** is the eligible candidate with the smallest `S_k`. Candidates within 1 % of that
   smallest `S_k` are ties; among ties the larger `avg` wins, then the larger `T` (fewer chunks to
   index and fewer reads).
3. If no candidate is eligible, G2 ships the chunk store with chunking off by default
   (`T` = unlimited) and reports that outcome; the round-trip and deduplication tests still run with
   explicit parameters.
4. Joules per accepted change and per read are measured and reported for every configuration but do
   not enter the decision: on this shared host the A2 package energy above idle was inside the noise
   (some A2 cells read below idle), so a joule criterion would decide on noise.

## Sources

- [S20] Xia et al., "FastCDC", USENIX ATC 2016 (ADR 0003 section 12).
