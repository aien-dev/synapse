# J3: SHA-256 and Ed25519 Reference for the Omega Port (Rust Side)

ADR 0003 section 9 step J3 (issue #55): "Omega port: SHA-256 with the hardware instructions and Ed25519
verification". Acceptance: "Digest and signature test vectors match the Rust crates exactly; all-core
throughput reported against the A0 references."

**Scope of this change.** The Omega implementation itself belongs in the `omega` repository and is not
here; it does not exist yet (no SHA-2 instruction or Ed25519 code was found in `omega` at `1edf41a5`).
This change delivers the Synapse half that the acceptance compares against: the sealed vector corpus
that defines "match the Rust crates exactly", the Rust crates themselves on the SHA-2 instructions, and
their all-core throughput against the A0 references. Issue #55 stays open until the Omega side passes
the corpus.

## 1. Acceptance and Where It Stands

| J3 acceptance | Synapse side (this change) | Omega side |
| :--- | :--- | :--- |
| Digest and signature test vectors match the Rust crates exactly | `evidence/j3-crypto-vectors/vectors.bin`: 291 records written by the Rust crates. Every record is recomputed by `ed25519-dalek` and `sha2` in test `sealed_corpus_matches_the_rust_crates_exactly`, and the file equals the corpus the crates produce today byte for byte. FIPS 180-4 and RFC 8032 published answers are checked against the crates and required in the corpus. The same corpus passes with `sha2` forced to its software backend | NOT_RUN: no Omega implementation yet; it must decode this file and give every digest and verdict |
| All-core throughput reported against the A0 references | Section 4: sealed run `evidence/j3-crypto-throughput/` (A0 protocol, unchanged bytes) | NOT_RUN |

Red before green: ten tests were committed against stubs (`8f4975d`) and all ten failed for the stated
reason (`evidence/j3-crypto-vectors/red-green/red.txt`): no corpus records, stub codec, no sealed file,
and `sha2` resolved with features `["default", "std"]`. The implementation turns them green
(`red-green/green.txt`); the portable run is `red-green/fallback-force-soft.txt`.

## 2. The Corpus

Format (ADR 0003 P5: fixed width, little endian, length prefixed), documented in
`crates/synapse-bench/src/crypto_vectors.rs`:

```text
header   magic "SYNJ3VEC" | version u16 = 1 | reserved u16 = 0 | count u32
record   kind 1 (SHA-256): len u32 | message | digest[32]
         kind 2 (Ed25519): verdict u8 | public_key[32] | signature[64] | len u32 | message
         verdict bits: 0 key decodes, 1 `verify` accepts, 2 `verify_strict` accepts
trailer  SHA-256 of every preceding byte
```

Synapse uses both Ed25519 calls (`verify` in `synapse-core`, `synapse-auth`, `synapse-radicle`;
`verify_strict` in `synapse-evidence`), and they disagree on small-order keys, so a port must reproduce
three decisions per case, not one.

Cases: SHA-256 for the four FIPS 180-4 examples, every length from 1 to 257 bytes, 1,000, 4,096, 11,949
(Gate 4 change), 16,384 (A0 block) and 65,536 bytes, and all-zero and all-one messages. Ed25519: RFC 8032
TEST 1 to 3; eight deterministic keys over messages of 0 to 11,949 bytes; changed message, R, S, high
bit of S, S + L, wrong key; the identity and order-2 keys with R = identity and S = 0 (`verify` accepts
the identity case, `verify_strict` refuses it); a non-canonical identity encoding; a key that does not
decode. The decoder refuses bad magic, version, reserved bits, unknown kinds, oversize lengths (cap
1 MiB, checked before allocation), trailing bytes, checksum mismatch and every truncation, each with a
typed error.

## 3. The `sha2` Build Fix

A0 found that `sha2` 0.10.9 was built without `asm`, and on aarch64 that crate then compiles only its
software backend (`sha2/src/sha256.rs`). The workspace dependency now enables `asm`. With it, `sha2` uses
`sha2::sha256::aarch64::sha256_compress` when `cpufeatures` reports `sha2` at run time and its portable
code otherwise; `asm` is the only switch in 0.10 (no target-feature setting selects the backend).
`ed25519-dalek` shares the same `sha2`, so its SHA-512 also gets the aarch64 backend (run-time `sha3`
detection, per the same file for SHA-512).

Proof: test `workspace_sha2_is_built_with_its_aarch64_instruction_backend` reads the resolved features
from `cargo metadata` and fails without cargo. `red-green/backend-disassembly.txt` shows the default
test binary links `sha2::sha256::aarch64::sha256_compress` (with `sha256h`) and the `force-soft` build
does not. The corpus passes under both (`cargo test -p synapse-bench --features sha2/force-soft`).

`Cargo.lock` was updated by cargo, not by hand: it adds `sha2-asm` 0.6.4 (which `sha2` requires for
`asm` but does not call on aarch64), `cc`, `find-msvc-tools` and `shlex`. Building needs a C compiler.

## 4. All-Core Throughput Against the A0 References

Same instrument, protocol and verifier as A0 (`synapse-bench bounds`; `protocol.json` is A0's, byte for
byte, committed and pushed in `000db4e` before the run started at 18:45:17 UTC). Seven repetitions, 20
threads, load average 4.31 to 8.12 at the SHA run starts (A0: 7.73 to 15.85).

| Probe | Achieved (max) | Median | Range | Package W (median) | Package J/B (median) | Above idle (median) |
| :--- | ---: | ---: | :--- | ---: | ---: | ---: |
| SHA-256, `sha2` crate as built (now `asm`) | 39.46 GB/s | 39.19 GB/s | 28.31 to 39.46 | 47.97 | 1.254 nJ/B | 0.738 nJ/B |
| SHA-256, A0's own instruction code | 26.89 GB/s | 26.15 GB/s | 22.36 to 26.89 | 62.30 | 2.490 nJ/B | 1.757 nJ/B |
| Ed25519 verify, `ed25519-dalek` | 397,560 /s | 395,108 /s | 377,163 to 397,560 | 49.84 | 128.6 µJ | 76.9 µJ |

| Reference | A0 value | J3 achieved | Result |
| :--- | ---: | ---: | :--- |
| All-core SHA-256 | 22.25 GB/s (A0 instruction code) | 39.46 GB/s (`sha2` crate) | Above the A0 reference, so under the ADR 6.2 replacement rule the reference becomes 39.46 GB/s; fraction 1 by definition. The A0 figure is 0.564 of it (calc:e7d9638b). Before this fix the crate's A0 maximum, 6.167 GB/s, was 0.277 of the A0 reference (calc:aa382756) |
| All-core Ed25519 verification | 395,192 /s | 397,560 /s | Above by less than A0's own spread (298,004 to 395,192); replaced by the same rule, A0 figure 0.994 of it (calc:771221f6); 2.515 µs of all-core time per verification (calc:4f355c4c) |

In seconds: at the new SHA-256 reference, digesting the Gate 4 replay's 117,196,023 bytes takes
2.970 ms (calc:d25d95ec), now the replay bound (the memory term is 0.429 ms), so Gate 4's measured
344.575 ms replay is **fraction of bound reached = 0.00862 (bound 2.970 ms, measured 344.575 ms)**
(calc:a8960c47); one 11,949-byte change digests in 0.303 µs (calc:b66d96d7). No physical joule bound
exists for SHA-256 or Ed25519 here, so joules carry no fraction.

## 5. Limits

- The new `sha2` crate windows last about 0.50 s (A0 calibrated for 0.7 to 3.3 s against the meter's
  0.1 s update), so its joule figures carry a larger relative edge uncertainty; all 7 windows passed the
  energy checks.
- Shared host; the lower load than A0's run is part of why A0's instruction code also reads higher here.
- Energy is SoC package only and uncalibrated, as in A0. The device and memory rows of this run are in
  `report.json` but are not J3 results.
- The corpus pins the Rust crates' decisions; it does not claim they are the only correct Ed25519
  semantics.

## 6. Reproduction

```
cargo test -p synapse-bench --lib crypto_vectors
cargo test -p synapse-bench --lib --features sha2/force-soft crypto_vectors
synapse-bench crypto-vectors-verify --corpus evidence/j3-crypto-vectors/vectors.bin
synapse-bench bounds-verify --evidence evidence/j3-crypto-throughput
cd evidence/j3-crypto-vectors && sha256sum -c SHA256SUMS
```
