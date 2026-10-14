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
* Crash window. Between the `checkpoint.v2` rename and the tombstone write, the store still
  holds the old `checkpoint.v1` and the JSON log, so a v1-only binary (main `b04ad31`) can
  still open it. If that binary appends JSON records after the checkpoint's seq, the new code
  refuses the store at replay with `WalVersionUnsupported`, because `checkpoint.v2` makes the
  store binary (`a1_v1_records_appended_in_the_crash_window_are_refused`). If it checkpoints,
  its `checkpoint.v1` is now ahead of `checkpoint.v2`, and the new code refuses the store with
  `CheckpointCorrupt`
  (`a1_v1_checkpoint_ahead_of_checkpoint_v2_is_refused`). Either way the store fails closed;
  nothing is silently merged. Recovery from this window without a v1 writer in between is
  tested on the main-written fixtures: `a1_crash_before_tombstone_recovers_wal_log`,
  `..._wal_v2_log` (stale `checkpoint.v1`, `checkpoint.v2` present, no tombstone),
  `a1_covered_json_frames_then_binary_frames_recover_wal_log`, `..._wal_v2_log` (tombstone
  written, log not yet compacted, then binary frames appended: a mixed log), and
  `a1_stale_checkpoint_v1_beside_checkpoint_v2_recovers_wal_log`. Each reopens with the same
  state root and chain, commits a new binary record, and reopens again with the same root.
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
| Truncated, bit-flipped and oversized-length corpus refused typed, no panic, no allocation above the declared cap | `tests/a1_malformed_corpus.rs`: 30,690 cases at cap 2,048 bytes, 0 panics, 0 accepted, largest single allocation 136 bytes; resealed mode: 31,881 cases with checksums and digests recomputed, all reaching the decoders, 0 panics, every accept canonical, largest allocation 1,224 bytes (records, cap 2,048) and 3,976 bytes (checkpoint, the undamaged decode peak) | pass |
| Replay seconds per changeset against the replay bound | below | reported |

Corpus tally (`evidence/a1-binary-codec/red-green/green.txt`): truncated 1,502 (`WalTornFrame`);
bit-flipped 12,016 (CRC, chain, magic, version, flags, cap, torn); oversized frame length 18
(`QuotaPayloadTooLarge`); oversized inner length with valid checksums 18
(`WalRecordMalformed`); checkpoint truncated 1,904 and bit-flipped 15,232 (`CheckpointCorrupt`).

Most of those stop at a checksum or digest, before the decoder. The resealed mode
(`a1_resealed_corpus_reaches_the_decoder_and_is_refused_or_canonical`) applies the same
kinds of damage (every truncation, every bit flip, and a false `u32` length of remaining + 1,
cap + 1 and `u32::MAX` at every byte offset), then recomputes the frame CRC, payload SHA-256,
`checkpoint.v2` content digest and checkpoint root, so `codec::decode_record` and the
checkpoint content decoder see the garbage. A case passes if the decoder refuses it
(`WalRecordMalformed` for records, `CheckpointCorrupt` naming the content or state root for
checkpoints) or if it decodes to a value whose encoding is exactly the damaged bytes (a flip
that lands inside a hash or a name is still a valid record). Counts reaching the decoder:
record truncated 974 (974 refused), bit-flipped 7,792 (1,225 refused, 6,567 canonical),
false length 2,868 (877 refused, 1,991 canonical); checkpoint truncated 1,688 (1,688
refused), bit-flipped 13,504 (3,094 refused, 10,410 canonical), false length 5,055 (1,983
refused, 3,072 canonical). Total 31,881.

Fixture provenance: `crates/synapse-store/tests/fixtures/a1-v1` is written by
`evidence/a1-binary-codec/fixture-generator`, whose `Cargo.toml` pins `synapse-core` and
`synapse-store` to git rev `b04ad31d2f57725f7fa971d26d6b51062f3b53a6` (main) with its
`Cargo.lock` committed. Regenerating from that pin gives byte-identical fixtures.

## Replay against the bound

Reference used: the J3 all-core SHA-256 reference, 39.46 GB/s (`docs/J3_CRYPTO_REFERENCE.md`,
which supersedes A0's 22.25 GB/s). Bound (ADR 0003 section 6.2): max(bytes / 273 GB/s memory
bandwidth, bytes / 39.46 GB/s) = bytes / 39.46 GB/s, bytes = the store's apparent bytes
(replay re-hashes every committed blob); at 10,000 the memory term is 3.942e-4 s
(calc:bb71a8df8eabb86f50db709efa4104b9f1af6edcfb36f8c86a10e42aa52e97e6). Fraction = bound /
measured, at most 1. Gate 4 workload (seed 7673641184369446932, fixture rev `1b6e340`),
`SynapseStore::open` replaying the full `wal.log` (EveryCommit), 7 repetitions, median; raw
samples in `replay/a1-11c48e5/trace.jsonl`. Release binary built from `11c48e5` (this branch
merged with main `b3473fc`, which includes J3's `sha2` `asm` feature).

| Changesets | Store bytes (apparent) | WAL bytes | Measured median s (min to max) | Bound s | Fraction | Achieved s per changeset |
| :--- | ---: | ---: | :--- | ---: | ---: | ---: |
| 100 | 1,212,536 | 64,212 | 0.001077 (0.001051 to 0.001381) | 3.0728e-5 | 0.0285 | 1.077e-5 |
| 1,000 | 9,887,858 | 620,587 | 0.010559 (0.010369 to 0.011613) | 2.5058e-4 | 0.0237 | 1.056e-5 |
| 10,000 | 107,605,504 | 6,288,321 | 0.120637 (0.119610 to 0.125275) | 2.7270e-3 | 0.0226 | 1.206e-5 |

Calc receipts: bounds calc:382fb7ec, calc:ac060435, calc:c4a298b5; fractions calc:08e61cce,
calc:60712e80, calc:a538f7aa (full ids:
calc:382fb7ec606e6212301994c15cead2ba14695accd07dd0d0f66fb60124fcf415,
calc:ac0604357b52cb16cc5fa32e35fe195e66673be4655f70fad1b1dcdd14a991f3,
calc:c4a298b579a51d980cb40087dcc58b8e3c70ff3b53acd2769cc6e3e8e06b2418,
calc:08e61ccef0c49ba20638f9434369ba13a83fde3438106cc4f91d8995a57cbffa,
calc:60712e80b63bd195c0ee124a3c00c92385e483c1c183e0b3460d835136f5c97c,
calc:a538f7aa5d19fd16a26d3056dc9c565f49c301d63044ea0360c14c6b9d6469dd).
Per changeset at 10,000: achieved 1.206e-5 s against a bound of 2.727e-7 s (fraction 0.0226;
calc:3dd430011f038777914dfe5ce84a5931e3e91f2d3b166767dfe16c09a4ea372c).

Same-host JSON reference, same day, main `b3473fc` (`replay/main-b3473fc-json/`): 10,000
changesets, 117,196,369 bytes, WAL 15,879,186 bytes, 0.156076 s median, bound 2.970e-3 s
(calc:4dbd8acc297504ee2a5cec05d809482e134c1d21643b17ce83193fcf748b45a3), fraction 0.0190
(calc:766eb64a258a43f515d920ce80f7cbf3476a3d2b37058ee48f8eb938bbd8babb). Context only, not an
acceptance. Open after checkpoint at 10,000: 0.008945 s (binary, checkpoint 6,768,446 bytes)
and 0.043907 s (JSON, 17,645,939 bytes).

Superseded: the earlier run (`replay/a1/`, binary from `b11bd8c` before J3, and
`replay/main-b04ad31-json/`) measured 0.261571 s and 0.30807 s at 10,000 and used A0's
22.25 GB/s reference (bound 4.836e-3 s, fractions 0.0185 and 0.0171). Between the two runs the
only change on the store path is J3's workspace dependency change (`sha2` with its `asm`
feature); the drop in measured time is attributed to it, not isolated further.

## Limits

* Energy (J) was not measured: no power instrument was read during these runs.
* Replay is far from the bound (fraction about 0.02 at the J3 reference); the time is
  dominated by re-reading and re-hashing blob files and per-record work, which A1 does not
  change. Not an acceptance.
* `RecordCodec` and the frame API are new public items of `synapse-store`;
  `SynapseStore::prepare_ingest` now takes `Option<RecordCodec>` instead of `bool`.
