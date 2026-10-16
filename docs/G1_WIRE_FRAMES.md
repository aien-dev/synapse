# G1: Binary Wire Frames and Have-Want Negotiation

ADR 0003 section 9 step G1 (issue aien-spark/synapse#44), section 8 crate `synapse-wire`: binary frames with a fuzzed decoder, have-want chunk negotiation, and stream transports. Needs A1 (binary codec) and F1 (capability chains), both merged.

Code: `crates/synapse-wire/` (`frame.rs`, `transport.rs`, `session.rs`, `probe.rs`, `fuzz.rs`, `testkit.rs`, `src/bin/synapse-wire-fuzz.rs`); `crates/synapse-bench/src/bin/wire-transport.rs`; `crates/synapse-store/src/codec.rs` (`encode_envelope`, `decode_envelope`); `crates/synapse-core/src/lib.rs` (`RefusalCode::WireFrameMalformed`, `RefusalCode::WireProtocolViolation`). Tests: `crates/synapse-wire/tests/g1_wire.rs`, `crates/synapse-wire/tests/g1_fuzz.rs`. Evidence: `evidence/g1-wire-frames/`.

## 1. Frame layout

A frame is a 16-byte header and `body_len` bytes of body. Integers are little endian and fixed width.

| Bytes | Field | Rule |
| :--- | :--- | :--- |
| 0..4 | magic `SYNW` | else `BadMagic` |
| 4 | version `1` | else `VersionUnsupported` |
| 5 | kind: 1 Hello, 2 Have, 3 Want, 4 Chunk, 5 Submit, 6 Accepted, 7 Refused | else `UnknownKind` |
| 6 | flags `0` | else `FlagsNonZero` |
| 7 | reserved `0` | else `ReservedNonZero` |
| 8..12 | `request_id` u32 | echoed in the reply |
| 12..16 | `body_len` u32 | at most the reader's `max_frame_body` (default 16 MiB), else `LengthOverCap` before any body byte is read or allocated |

Body primitives follow the A1 codec: byte strings and strings are `u32 len | bytes` (strings UTF-8), sequences are `u32 count | items`, fixed arrays are raw, tags are one byte.

| Kind | Body |
| :--- | :--- |
| Hello | `max_frame_body` u32, `max_pending_chunk_bytes` u64 |
| Have | `repo_id` string, digests (`u32 count`, 32 bytes each, strictly increasing) |
| Want | digests (strictly increasing) |
| Chunk | `digest` [32], `bytes` |
| Submit | the F1 `ChainedRequest`: `chain` bytes (`CapabilityChain::encode`), `target_repo_id` string, `agent_key` [32], capability tag (1 to 6), scope paths (`u32 count`, strings), reference tag (0 none, 1 own drafts, 2 canonical via promotion queue), join change (0, or 1 then [16]), `request_nonce` [32], `timestamp_ms` u64, `payload` bytes (one binary changeset envelope, `CODEC_V2` and the A1 envelope body), `agent_signature` [64] |
| Accepted | `wal_seq` u64, `changeset_id` [32], `duplicate` 0 or 1 |
| Refused | refusal code name (ASCII letters and digits, at most 64), message string |

There is exactly one encoding per frame. A trailing byte, unknown tag, invalid UTF-8, invalid `RepoId`, unsorted or repeated digest, a chain that does not re-encode to its own bytes, or an unknown refusal code name is refused, so decode then encode gives back the input bytes. Each refusal is a typed `WireRefusal` with the absolute byte offset; at the service boundary it becomes `RefusalCode::WireFrameMalformed`.

There is no checksum: frames ride a reliable ordered stream (Unix socket or TCP), and the content that matters is signed (the envelope by its author, the request by the agent, the chain links by their issuers). The decoder takes the body as its own slice, so it cannot read into the next frame; the stream reader takes the header first, checks `body_len` against its cap, and only then allocates and reads exactly that many bytes.

## 2. Have-want negotiation and submission

```text
client                                   server
  Hello ------------------------------->     once per connection, both ways
  <------------------------------- Hello
  Have {repo, digests the change needs} ->
  <---------- Want {offered digests the server lacks}
  Chunk x |Want|, Submit {chained request} ->   one write
  <--------------- Accepted {wal_seq} | Refused {code}
```

The server lacks a digest when no committed changeset references it and no chunk of the current negotiation carried it, so a blob the server holds is never sent again (FindMissingBlobs style, section 5.9). Server rules, each a typed refusal that resets the negotiation:

| Break | Refusal |
| :--- | :--- |
| Any frame before `Hello` (then the connection closes), a second `Hello`, or a frame a server never takes from a client (`Want`, `Accepted`, `Refused`) | `WireProtocolViolation` |
| `Have` for another repository | `AuthCrossRepoDenied` |
| `Chunk` not in the last `Want`, or sent twice | `WireProtocolViolation` |
| `Chunk` bytes that do not hash to its digest | `BlobDigestMismatch` |
| Chunk bytes over `max_pending_chunk_bytes` (default 64 MiB) | `QuotaPayloadTooLarge` |
| `Submit` before every wanted chunk | `WireProtocolViolation` |
| `Submit` payload not one canonical binary envelope | `WireFrameMalformed` |
| Chain, signature, capability (`Propose`), scope, size, rate or nonce check of `PolicyEnforcer::authorize_chain` (F1) | its F1 code |
| Envelope for another repository; envelope author not the chain's leaf audience; request scope not exactly the envelope's paths | `AuthCrossRepoDenied`; `AuthSignatureInvalid`; `AuthPathOutOfScope` |
| Malformed frame (then the connection closes, since framing can no longer be trusted) | `WireFrameMalformed` |

An accepted change is admitted through `SharedStore::submit` with group commit, and `Accepted` is written only after the batch is durable. A resubmission of a committed change returns `Accepted` with `duplicate = 1`.

## 3. Fuzzer: what kind it is

`synapse_wire::fuzz` is an in-repository coverage-guided mutation fuzzer, written for this step (no libFuzzer, AFL or cargo-fuzz, no new external crates). The frame decoder is generic over a `Probe`; production passes `NoProbe` (empty, inlined away), the fuzzer passes `EdgeProbe`, which records an AFL-style edge map (64 Ki slots, edge = previous site xor current site) over 43 instrumented decoder states in `frame.rs` (one per branch; the site id is the source line) and the highest input offset read. An input that reaches a new edge or a new hit-count bucket joins the corpus. Mutations: bit flips, random and boundary bytes, boundary u32 values (0, cap - 1, cap, cap + 1, bytes remaining, u32::MAX and others), truncation, insertion, deletion, duplication, splicing two corpus entries, 32-byte block swaps, kind byte rewrites, and half the time a fix-up of `body_len` to the real body length so mutations reach the body decoder. The random generator is SplitMix64 with a fixed seed; the budget (executions or seconds) and seed are written to `spec.json` before the first execution.

Limits, stated plainly: coverage is only the instrumented states of `frame.rs`. The capability chain decoder (`synapse-auth`) and the envelope decoder (`synapse-store::codec`) run on every accepted `Submit` and their outputs are checked, but they are not instrumented, so the fuzzer does not steer toward their branches.

The target is what the server does with untrusted bytes: `decode_frame`, then `decode_envelope` on a `Submit` payload. Every execution checks:

| Check | How |
| :--- | :--- |
| No panic | `catch_unwind` around the target |
| No read past a frame | the probe's high-water mark never exceeds `16 + body_len`; and the same input followed by random trailing bytes gives the identical result whenever the input held the whole frame (a decision that depends on bytes after the frame shows up as a difference) |
| No allocation above the declared cap | a counting global allocator records the largest single allocation during the decode; it must not exceed `max_frame_body` |
| Canonical accept | an accepted frame re-encodes to exactly the bytes it came from; an accepted payload re-encodes to exactly the payload |
| Typed refusal | anything not accepted is a `WireRefusal` (payloads: a `CodecRefusal`) |

Seeds are one valid frame of every kind (14 frames, including empty lists, an empty chunk, depth 1 and depth 3 chains, an envelope with evidence and a delete, every option tag) and 126 hand-made malformed frames derived from them (wrong magic, version, kind 0 and 8, flags, reserved, length one over the cap, one byte short, one trailing byte).

Negative controls (`negative_control_*` in `tests/g1_fuzz.rs`) plant one bug each in a copy of the target (a panic on a non-zero flags byte, a buffer sized from the declared length before the cap check, an answer that depends on the byte after the frame, a decoder that ignores the reserved byte) and require the same fuzzer and budget to report it. All four are found, so the detectors are live.

## 4. Acceptance

| Acceptance item (issue #44) | Test or evidence | Result |
| :--- | :--- | :--- |
| Every frame kind round-trips to identical bytes | `every_frame_kind_round_trips_to_identical_bytes` (all 7 kinds, singly, back to back in one buffer, and through the stream reader) | PASS |
| Fuzzing for a budget fixed before the run finds no panic, no read past a frame, no allocation above the declared cap | `fuzzing_frame_decoder_finds_no_panic_no_read_past_frame_no_allocation_over_cap` (300,000 executions, seed fixed, in CI); time-budgeted run in `evidence/g1-wire-frames/fuzz/` (FUZZ_SUMMARY) | PASS |
| Every malformed frame in the fuzz corpus is refused with a typed refusal | `every_malformed_frame_in_fuzz_corpus_is_refused_with_typed_refusal` (replays the whole corpus: each entry is a canonical frame or a typed refusal, each hand-made malformed seed is refused); corpus replay in `evidence/g1-wire-frames/fuzz/result.json` | PASS |
| Seconds and joules per accepted change across the transport against the bound | `evidence/g1-wire-frames/transport/` (section 5) | MEASURED (see section 5; this is a report, not a pass/fail gate) |

Supporting tests: `malformed_header_is_refused_with_typed_refusal`, `malformed_body_is_refused_with_typed_refusal`, `decoder_never_reads_past_a_frame`, `stream_reader_refuses_length_over_cap_before_reading_the_body`, `have_want_sends_only_missing_chunks_and_acknowledges_durable_changes` (2 then 1 then 0 chunks as blobs become known; a duplicate is idempotent; a fresh open of the store sees every acknowledged change), `server_refuses_protocol_violations_with_typed_refusals`, `server_closes_connection_on_frame_before_hello_or_malformed_frame`, and the four negative controls.

Red before green: `evidence/g1-wire-frames/red-green/red.txt` (two stub sets: the body decoder unimplemented; the header, trailing-byte and negotiation checks switched off) and `green.txt`.

TRANSPORT_SECTION

## 6. Limits and deviations

* Chunks are whole blobs until step G2 (content-defined chunking); `Have`, `Want` and `Chunk` carry `BlobDigest`s. There is no separate chunk digest type yet.
* The server's set of known digests is built from committed changesets at start and grows with each accepted change. After a future compaction that drops blobs (none exists yet) a stale entry would make the server skip a chunk it needs; the store then refuses the change with its own typed refusal (`BlobNotFound`) rather than accepting it.
* Refused frames carry the refusal code by its stable name, so a code added later is refused by an older peer as `UnknownRefusalCode` rather than misread.
* The transport arm runs client and server in one process over a Unix socket pair. TCP and a separate client process are not measured.
* Joules come from the `aien_spbm` SoC package meter: package only, uncalibrated, NVMe unmeasured.
* Small public additions outside the new crate: `encode_envelope` and `decode_envelope` in `synapse-store::codec` (the envelope body codec the WAL already used), two refusal codes in `synapse-core`, the crate in the root `Cargo.toml` and `.crumb`, and the `wire-transport` binary in `synapse-bench`.
