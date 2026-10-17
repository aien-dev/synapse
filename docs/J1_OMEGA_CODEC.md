# ADR 0003 step J1: Omega port of the binary codec (cross-check corpus)

Issue #53. ADR 0003 section 9, row 33 (J1), needs A1. The Rust codec
(`crates/synapse-store/src/codec.rs`, step A1) stays the specification by test (section 5.12).
This step adds one language-neutral file that says what "decodes and re-encodes every record byte
for byte, refuses the malformed corpus identically" means, so a port in any language is checked
against the Rust outcomes and never against a second reading of the spec.

* Exporter and seal: `crates/synapse-store/src/j1_corpus.rs` (test only).
* Sealed corpus: `evidence/j1-codec-corpus/corpus.bin`, SHA-256 in `CORPUS_SHA256`.
* The Omega port lives in `aien-dev/omega` (`src/synapse/syn_codec.osc`, driver
  `tests/synapse/test_syn_codec.c`, `make test-synapse-codec`); it vendors the file byte for byte.

## 1. What is covered

Codec v2 record payloads (`CODEC_V2 | kind | body`) for every record kind on `main` (1 to 8,
including the embedded `synapse-core` revision envelope v2 and obsolescence marker) and checkpoint
content (`CheckpointState::encode_content` / `decode_content`, including the revision-log
section). The frame layer around them (WAL frame header, CRC, SHA-256 chain, checkpoint frame and
`state_root`) is out of scope: it is hashing, which belongs to J3 and J4.

Kinds 9, 10 and 11 are reserved by open PRs (#88, #96, #95). A kind that merges adds its bases to
`bases()`, its flattener arm to `Lf::record`, its expected set in the coverage test, and a reseal;
the Omega side adds one `if k == N` arm in `record`.

## 2. Cases

* **Bases** (48). 28 accepted, each with its LF: the fixture JSON records, the A1 edge records,
  kind 7 and 8 records, and two checkpoints (fixture, and one with a revision log). 20 hand-made
  refusals that the mutation set cannot reach: reserved kinds 9 to 11, an empty revision section,
  a revision section holding kind 6, projections out of order, equal keys in each of the five
  checkpoint maps, equal revision seqs, and the repository id rules (empty, 129 bytes, leading or
  trailing slash, `//`, `..`, space, non-ASCII).
* **Mutations** of every accepted base marked for mutation, exactly the A1 malformed set
  (`a1_malformed_corpus.rs`): every truncation, every bit flip, and a false `u32` length at every
  offset with declared values `remaining + 1`, `cap + 1` and `u32::MAX`.
* Each case carries the Rust outcome. An accept is asserted canonical (re-encodes to the input)
  before it is written. Today: 55,670 cases, 41,750 accepts, 13,920 refusals.

## 3. Logical form (LF)

A record or checkpoint as a flat list of `u64` cells, the typed fields in encoding order, without
derived lengths or constant bytes. Each field starts with a header cell `type | n << 8`:

| type | id | n | cells after the header |
| --- | --- | --- | --- |
| u16 | 2 | 1 | value |
| u64 | 4 | 1 | value (`usize` fields too) |
| bool | 5 | 1 | 0 or 1 |
| tag | 6 | 1 | tag byte (record kind, Option, mutation op, file mode) |
| fixed bytes | 7 | len | one cell per byte |
| string | 8 | len | one cell per UTF-8 byte |
| byte string | 9 | len | one cell per byte |
| repository id | 10 | len | one cell per byte |
| count | 11 | 1 | element count of the sequence that follows |

The field order per record kind is `Lf::record` and per checkpoint `Lf::checkpoint`. The
checkpoint revision-log count is always present in the LF; the bytes hold that section only when
the count is above zero.

## 4. File format (version 1, little-endian)

```
magic "SYNJ1COD" | version u16 = 1 | reserved u16 = 0 | cap u32 (2048, A1 record cap)
layout: n u32 | n x u32   size_of EvidenceAttachment, PathMutation, ReviewRecord, String
fields: n u32 | n x name  refusal field names, id = index + 1, 0 = none
codes:  n u32 | n x name  embedded synapse-core refusal codes, id = index + 1
kinds:  n u32 | n x name  CodecRefusal kinds, id = index + 1, 0 = accept
bases:  n u32 | n x base
cases:  n u32 | n x case
seal:   SHA-256 of every byte before it
name = len u16 | UTF-8 bytes
base = entry u8 (1 record, 2 checkpoint content) | cap u64 | checkpoint_seq u64 | label name
       | len u32 | bytes | lf_cells u32 (u32::MAX = refused base, no LF) | lf_cells x u64
case = base u16 | op u8 (0 as is, 1 truncate, 2 bit flip, 3 false length) | pos u32
       | [declared u32 when op = 3] | kind u8 | [at u32 | x u32 | y u32 | field u8 when kind > 0]
```

The case input is rebuilt from its base and op: truncate keeps `bytes[..pos]`, bit flip XORs bit
`pos % 8` of byte `pos / 8`, false length writes `declared` at `pos`, op 0 is the base as is.
The `layout` sizes are part of the format because the Rust record decoder checks a sequence's
reservation `n * size_of::<T>()` against the cap (`LengthOverCap`) before reading it.

Outcome fields per refusal kind (`x`, `y` are 0 when unused):

| kind | at | x | y | field |
| --- | --- | --- | --- | --- |
| Truncated | offset | need | | |
| LengthOverCap | offset | declared | cap | |
| TrailingBytes | offset | count | | |
| UnknownTag | tag offset | tag | | field id |
| InvalidUtf8 | offset | | | |
| VersionUnsupported | 0 | found | | |
| NotCanonical | offset | | | field id |
| InvalidRepoId | offset | | | |
| EmbeddedMalformed | length-prefix offset | code id | | field id |

## 5. Reproduce

```
cargo test -p synapse-store --lib j1_corpus                    # checks the seal
J1_CORPUS_WRITE=1 cargo test -p synapse-store --lib j1_corpus  # rewrites the file
```

After a rewrite, update `CORPUS_SHA256` and re-vendor the file into the Omega repository.
Red and green runs: `evidence/j1-codec-corpus/red-green/`.

## 6. Speed against the section 6.2 bound

Omega native AArch64, one core, on the 28 accepted bases (omega `evidence/SYNAPSE-J1/perf.txt`,
`make bench-synapse-codec`): decode 0.0434 GB/s (23.0 ns per record byte, calc:1c31099c), encode
0.0269 GB/s. The bound for moving the bytes once is the 273 GB/s memory bandwidth
(`docs/A0_HOST_BOUNDS.md`), so the fraction reached is 1.59e-4 for decode (calc:2ef7b34c) and
9.85e-5 for encode (calc:a0366c9f). The unit reads one byte per bounds-checked index and writes one
`u64` LF cell per payload byte. The Rust codec's speed on the same bases is not measured here.

## 7. Limits

* The Omega unit refuses inputs above 1,000,000 bytes with a limit refusal (its loop bound);
  the corpus inputs are all below that.
* Encode mirrors the Rust encoder: it does not apply decoder caps, so an LF the decoder would
  refuse for size can still encode.
* Hashing (frame CRC and SHA-256, checkpoint roots) is J3/J4 scope.
