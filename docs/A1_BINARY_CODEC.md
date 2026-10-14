# ADR 0003 step A1: binary canonical codec v2 (WAL records and checkpoints)

Issue #22. ADR 0003 section 9, row A1. Code: `crates/synapse-store/src/codec.rs`, integration in
`crates/synapse-store/src/{lib.rs,wal2.rs,shared.rs}`. Evidence: `evidence/a1-binary-codec/`.

## What changes

* WAL record payloads (in `wal.log` and `wal.v2.log`) and the checkpoint move from JSON to one
  canonical binary encoding. The changeset envelope, its signature bytes and every identity
  (`ChangesetId`, `BlobDigest`, frame digests) are unchanged; envelope v2 is step B1.
* Frame header byte 7 (`flags`) declares the record codec: `0` = v1 JSON, `1` = binary v2.
  Any other value is refused (`WalFlagsNonZero`).
* `checkpoint.v2` (binary) replaces `checkpoint.v1`; `checkpoint.v1` becomes a `version: 2`
  tombstone so a binary that only knows v1 refuses the store instead of opening it empty.

## Record layout

`CODEC_V2 (u8 = 2) | kind (u8, WalRecord::kind_byte) | body`. Little-endian fixed-width
integers; `usize` as `u64`; `bool` one byte 0 or 1; `Option` tag 0 or 1 then the value;
strings and byte strings `u32 len | bytes` (strings UTF-8); sequences `u32 count | items`;
fixed arrays raw. Field order follows the struct definitions in `synapse-core`. Exactly one
encoding per record: any other tag, trailing byte, invalid UTF-8, invalid `RepoId` or
out-of-order checkpoint key is refused. Every length and count is checked against the bytes
that remain and against the cap before anything is allocated.

## checkpoint.v2 layout (216-byte header, then content)

| Bytes | Field |
| :--- | :--- |
| 0..4 | magic `SCK2` |
| 4..6 | version `u16 = 2` |
| 6 | codec `2` |
| 7 | reserved `0` |
| 8..16 | `checkpoint_seq` |
| 16..48 | `anchor_frame_sha256` |
| 48..80 | `v1_state_root` (last v1 `state_root_digest`; empty-store root for a store that never wrote v1) |
| 80..112 | `prev_checkpoint_root` (`v1_state_root` for the first v2 checkpoint, else the previous `checkpoint_root`) |
| 112..144 | `state_root` (`state_root_digest` of the content) |
| 144..176 | `content_sha256` = SHA-256(`SYNAPSE_CHECKPOINT_CONTENT_V2\0` ‖ content) |
| 176..208 | `checkpoint_root` = SHA-256(`SYNAPSE_CHECKPOINT_ROOT_V2\0` ‖ v1_state_root ‖ prev_checkpoint_root ‖ seq ‖ anchor ‖ state_root ‖ content_sha256) |
| 208..216 | `content_len u64` |

Content: `CODEC_V2`, then changesets, idempotency index, blob visibility, projections and
canonical heads, each `u32 count | items` in strictly increasing key order. Decoding verifies
header, length, content digest, root, canonical content, and recomputes the state root. Every
failure is `CheckpointCorrupt`. The writer decodes its own bytes back before writing.

## Migration rules

* A store with v1 history (a v1 checkpoint or replayed JSON records) keeps writing JSON until
  its first `checkpoint_and_compact`, which writes the first `checkpoint.v2` (the migration
  checkpoint). The v1 root is taken before eviction. Write order: `checkpoint.v2` (temp,
  sync, rename, directory sync), then the tombstone, then log compaction. A crash between
  the two leaves an older `checkpoint.v1`, which the next open replaces with the tombstone.
* A fresh store writes binary from its first record.
* Replay refuses a JSON record after a binary one, and a binary record in a v1 store before
  its migration checkpoint (`WalVersionUnsupported`). Records a checkpoint covers are exempt.
* A record prepared outside the lock before the migration is re-encoded at commit.
* `StoreLimits::max_wal_record_bytes` (default 128 MiB) caps a frame's declared payload. A
  larger declaration is refused before allocation and never taken for a torn tail
  (`QuotaPayloadTooLarge`); the writer refuses such a record before writing any blob.
* A malformed binary record with valid checksums is refused with the new
  `RefusalCode::WalRecordMalformed`.

## Acceptance (issue #22)

| Acceptance | Test | Result |
| :--- | :--- | :--- |
| Every record kind decodes to the same logical record as its v1 JSON form, both directions | `a1_every_record_kind_matches_its_v1_json_form_in_both_directions` (16 records written by main `b04ad31`, all 6 kinds), `a1_edge_records_match_their_json_form_in_both_directions`, `a1_checkpoint_state_matches_its_v1_json_form_in_both_directions`, `a1_documented_layout_decodes_and_every_non_canonical_form_is_refused` | pass |
| First v2 checkpoint records the last v1 `state_root_digest` and chains its root to it | `a1_first_v2_checkpoint_records_last_v1_root_and_chains_wal_log`, `..._wal_v2_log`, `a1_fresh_store_writes_binary_frames_and_records_the_empty_v1_root`, `a1_v1_readers_refuse_the_tombstone`, `a1_damaged_checkpoint_v2_is_refused` | pass |
| WAL conformance 11 of 11 | `wal_suite_cases_pass` (11 cases), `wal_suite_stores_write_binary_codec_frames` (suite stores write binary frames) | pass |
| Truncated, bit-flipped and oversized-length corpus refused typed, no panic, no allocation above the declared cap | `tests/a1_malformed_corpus.rs`: 30,690 cases at cap 2,048 bytes, 0 panics, 0 accepted, largest single allocation 136 bytes | pass |
| Replay seconds per changeset against the replay bound | below | reported |

Corpus tally (`evidence/a1-binary-codec/red-green/green.txt`): truncated 1,502 (`WalTornFrame`);
bit-flipped 12,016 (CRC, chain, magic, version, flags, cap, torn); oversized frame length 18
(`QuotaPayloadTooLarge`); oversized inner length with valid checksums 18
(`WalRecordMalformed`); checkpoint truncated 1,904 and bit-flipped 15,232 (`CheckpointCorrupt`).

## Replay against the bound

Bound (ADR 0003 section 6.2, A0): max(bytes / 273 GB/s memory bandwidth, bytes / 22.25 GB/s
all-core SHA-256 reference) = bytes / 22.25 GB/s, bytes = the store's apparent bytes (replay
re-hashes every committed blob). Fraction = bound / measured, at most 1. Gate 4 workload
(seed 7673641184369446932, fixture rev `1b6e340`), `SynapseStore::open` replaying the full
`wal.log` (EveryCommit), 7 repetitions, median; raw samples in `replay/a1/trace.jsonl`.
Binary built from `b11bd8c` plus the checkpoint-size line in `recovery.rs`.

| Changesets | Store bytes (apparent) | WAL bytes | Measured median s (min to max) | Bound s | Fraction | Achieved s per changeset |
| :--- | ---: | ---: | :--- | ---: | ---: | ---: |
| 100 | 1,212,536 | 64,212 | 0.002622 (0.002604 to 0.002837) | 5.450e-5 | 0.0208 | 2.622e-5 |
| 1,000 | 9,887,858 | 620,587 | 0.023794 (0.023498 to 0.024913) | 4.444e-4 | 0.0187 | 2.379e-5 |
| 10,000 | 107,605,504 | 6,288,321 | 0.261571 (0.259464 to 0.265962) | 4.836e-3 | 0.0185 | 2.616e-5 |

Per changeset at 10,000: achieved 2.616e-5 s against a bound of 4.836e-7 s (fraction 0.0185;
calc:fcac04c7b95f50ba84733216a51372bc2297157faa812a5e73786620f623ada1,
calc:d88fe2f6e7bf4c1c823f597cadc0ca2e73af588d249fa72cb8e253ae7f95861f).

Same-host JSON reference, same day, main `b04ad31` (`replay/main-b04ad31-json/`): 10,000
changesets, 117,195,596 bytes, WAL 15,878,413 bytes, 0.30807 s median, fraction 0.0171
(calc:0d13ae430f18c90800e1e0e2ad92edf353c990871fd8d4bc6cf581a286e098d3). Context only, not an
acceptance. Open after checkpoint at 10,000: 0.018348 s (binary, checkpoint 6,768,446 bytes)
and 0.04421 s (JSON, 17,645,237 bytes).

## Limits

* Energy (J) was not measured: no power instrument was read during these runs.
* Replay is far from the bound (fraction about 0.02); the time is dominated by re-reading and
  re-hashing blob files and per-record work, which A1 does not change. Not an acceptance.
* `RecordCodec` and the frame API are new public items of `synapse-store`;
  `SynapseStore::prepare_ingest` now takes `Option<RecordCodec>` instead of `bool`.
