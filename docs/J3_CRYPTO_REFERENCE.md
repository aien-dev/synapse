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
| Digest and signature test vectors match the Rust crates exactly | `evidence/j3-crypto-vectors/vectors.bin`: 299 records written by the Rust crates, SHA-256 `523a6199b9dcc383573c38e3dac9c1480ef85ad3c03ec436786207978721c94b`, pinned as `CORPUS_SHA256` and checked by test `sealed_corpus_digest_is_pinned`. Every record is recomputed by `ed25519-dalek` and `sha2` (`sealed_corpus_matches_the_rust_crates_exactly`). FIPS 180-4 and RFC 8032 published answers are checked against the crates and required in the corpus. Nine Ed25519 edge cases each catch a named wrong implementation (section 2.1). `cargo test` also builds and runs the corpus test on `sha2`'s portable backend | NOT_RUN: no Omega implementation yet; it must decode this file and give every digest and verdict |
| All-core throughput reported against the A0 references | Section 4: two sealed runs of the A0 probes | NOT_RUN |

Red before green: the first ten tests were committed against stubs (`8f4975d`) and failed for the stated
reasons (`evidence/j3-crypto-vectors/red-green/red.txt`); green in `green.txt`. Review round: the edge-case
and pinned-digest tests failed against stubs (`21c90e1`, `red-green/review-red.txt`, which also holds the
negative control for the backend check), green in `review-green.txt`.

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
`verify_strict` in `synapse-evidence`), and they disagree on small-order points, so a port must reproduce
three decisions per case, not one.

SHA-256 cases: the four FIPS 180-4 examples, every length from 1 to 257 bytes, 1,000, 4,096, 11,949
(Gate 4 change), 16,384 (A0 block) and 65,536 bytes, and all-zero and all-one messages. Ed25519 cases:
RFC 8032 TEST 1 to 3; eight deterministic keys over messages of 0 to 11,949 bytes; changed message, R, S,
high bit of S, wrong key; identity, order-2 and non-canonical identity keys; a key that does not decode;
and the edge cases below. The decoder refuses bad magic, version, reserved bits, unknown kinds, oversize
lengths (cap 1 MiB, checked before allocation), trailing bytes, checksum mismatch and every truncation,
each with a typed error.

### 2.1 Edge cases and the wrong implementation each one catches

Classes from Chalkias, Garillot and Nikolaenko, "Taming the many EdDSAs" (SSR 2020, IACR ePrint
2020/1244). Points are built with `curve25519-dalek`; verdicts come from `ed25519-dalek`. The test
`each_edge_case_is_in_the_corpus_and_catches_a_wrong_implementation` runs, for each case, a model that
differs from the right one in one rule and requires its answer to differ from dalek's. The test also
requires each wrong model to accept RFC 8032 TEST 1. `models_reproduce_dalek_on_the_whole_corpus` shows
that the right models (cofactorless, canonical S, R compared as bytes; strict adds R decoding and
small-order checks on A and R) give dalek's answer on all 299 records.

| Case | verify | verify_strict | Wrong implementation caught (compared with) |
| :--- | :---: | :---: | :--- |
| `noncanonical_r_y_p_plus_1`: R = identity as y = p + 1, A = identity, S = 0 | refuse | refuse | decodes R and compares points (`verify`) |
| `noncanonical_r_negative_zero`: R = identity with the x sign bit set | refuse | refuse | decodes R and compares points (`verify`) |
| `noncanonical_a_y_p`: A = order-4 point encoded as y = p | accept | refuse | hashes the re-encoded A instead of the given bytes (`verify`) |
| `small_order_a_and_r`: A of order 8, R of order 4, S = 0 | accept | refuse | strict without small-order checks (`verify_strict`) |
| `small_order_r_valid_key`: R = identity under an ordinary key | accept | refuse | strict that checks A but not R (`verify_strict`) |
| `mixed_order_a_k_not_multiple_of_8`: A = aB + T8 | refuse | refuse | cofactored equation (`verify`) |
| `mixed_order_a_k_multiple_of_8`: A = aB + T8, k a multiple of 8 | accept | accept | refuses keys that are not torsion free (`verify`) |
| `mixed_order_r`: R = rB + T8 | refuse | refuse | cofactored equation (`verify`), and cofactored with strict checks (`verify_strict`) |
| `noncanonical_s_plus_l`: RFC 8032 TEST 1 with S + L | refuse | refuse | reduces S modulo L instead of refusing it (`verify`) |

## 3. The `sha2` Build Fix

A0 found that `sha2` 0.10.9 was built without `asm`, and on aarch64 that crate then compiles only its
software backend. In `sha2/src/sha256.rs` the aarch64 backend is gated on
`all(feature = "asm", target_arch = "aarch64")`, and `asm = ["sha2-asm"]` in its `Cargo.toml`; the only
other aarch64 name, `asm-aarch64`, is an alias for `asm`. So no narrower switch exists in 0.10: enabling
the intrinsics backend also builds `sha2-asm` (unused on aarch64) and its `cc` build script. The
workspace dependency now enables `asm`. `sha2` then uses `sha2::sha256::aarch64::sha256_compress` when
`cpufeatures` reports `sha2` at run time and its portable code otherwise. `ed25519-dalek` shares the
same `sha2`, so its SHA-512 also gets the aarch64 backend (gated the same way in `sha512.rs`, with
run-time `sha3` detection).

Proof, all in `cargo test`:
- `workspace_sha2_is_built_with_its_aarch64_instruction_backend` reads the resolved features from
  `cargo metadata`. It then checks the backend actually in use: the instruction function is linked into
  the running test binary, and the CPU reports `sha2`. It fails without cargo.
- `portable_sha2_backend_gives_the_sealed_corpus` builds the crate again with `sha2/force-soft` in a
  separate target directory. It runs the sealed-corpus test there, plus a check that the portable backend
  is the one in use. `sha2` 0.10 fixes its backend at build time and `cpufeatures` caches the hardware
  answer, so the portable code cannot run inside the same process. The negative control (the portable
  check run in the instruction build fails) is in `red-green/review-red.txt`.
- `red-green/backend-disassembly.txt`: the default build links `sha256_compress` with `sha256h`; the
  `force-soft` build does not.

`Cargo.lock` was updated by cargo, not by hand. It adds `sha2-asm` 0.6.4, `cc`, `find-msvc-tools` and
`shlex`, and `curve25519-dalek` (already in the graph through `ed25519-dalek`) becomes a direct
dependency of `synapse-bench`. Building needs a C compiler.

## 4. All-Core Throughput Against the A0 References

Two runs of the A0 probes (`synapse-bench bounds`, same instrument and verifier; `bounds-verify` passes on
both). Each protocol was committed and pushed before its run:
- `evidence/j3-crypto-throughput/` (`000db4e`, A0's protocol byte for byte). The SHA-256 windows lasted
  0.50 to 0.88 s (7 of 14 below A0's 0.7 s floor), so **its energy figures are not used**; its times
  are valid (1 ns clock).
- `evidence/j3-crypto-throughput-r2/` (`1f25721`). Only change: `sha256.blocks_per_thread` 60,000 to
  180,000, giving SHA-256 windows of 1.59 to 2.81 s, inside A0's calibrated 0.7 to 3.3 s. Ed25519
  windows were 1.02 to 1.08 s. One-minute load average 9.1 to 14.2 at the starts of the SHA-256 and Ed25519 repetitions.

Run 2 figures, with the meter edge uncertainty (`pkg_edge_sd_j`, A0 section 3) beside each energy figure:

| Probe | Achieved (max) | Median | Range | Package W (median) | Package energy per unit (median) | Above idle (median) |
| :--- | ---: | ---: | :--- | ---: | ---: | ---: |
| SHA-256, `sha2` crate (`asm`) | 37.06 GB/s | 29.86 GB/s | 24.46 to 37.06 | 60.53 | 1.946 ± 0.080 nJ/B (calc:61f2c7d7) | 0.801 ± 0.085 nJ/B (calc:162fd42c) |
| SHA-256, A0's own instruction code | 26.80 GB/s | 23.99 GB/s | 20.99 to 26.80 | 73.55 | 3.145 ± 0.102 nJ/B (calc:de7554c5) | 1.641 ± 0.102 nJ/B (calc:7bc75969) |
| Ed25519 verify, `ed25519-dalek` | 392,966 /s | 387,709 /s | 370,159 to 392,966 | 63.37 | 163.9 ± 12.9 µJ (calc:3d33d490) | 79.3 ± 12.8 µJ (calc:20b787b3) |

Each ± figure is `pkg_edge_sd_j` of the repetition that holds that median, divided by its work units
(A0's formula: mean package watts × 0.1 s update × √(2/3)). It does not cover the idle run's own
uncertainty or the meter's calibration, which is unpublished.

| Reference | A0 value | Best J3 achieved | Result |
| :--- | ---: | ---: | :--- |
| All-core SHA-256 | 22.25 GB/s (A0 instruction code) | 39.46 GB/s (`sha2` crate, run 1) | Above the A0 reference, so under the ADR 6.2 replacement rule the reference becomes 39.46 GB/s and its fraction is 1 by definition. A0's figure is 0.564 of it (calc:e7d9638b); run 2's maximum is 0.939 of it (calc:c80a9ab8). Before this fix the crate's A0 maximum, 6.167 GB/s, was 0.277 of the A0 reference (calc:aa382756) |
| All-core Ed25519 verification | 395,192 /s | 397,560 /s (run 1) | Above by less than A0's own spread (298,004 to 395,192), so it is replaced by the same rule. A0's figure is 0.994 of it (calc:771221f6) and run 2's is 0.988 (calc:4b62da69). That is 2.515 µs of all-core time per verification (calc:4f355c4c) |

In seconds: at the new SHA-256 reference, digesting the Gate 4 replay's 117,196,023 bytes takes
2.970 ms (calc:d25d95ec). That is now the replay bound (the memory term is 0.429 ms), so Gate 4's
measured 344.575 ms replay gives **fraction of bound reached = 0.00862 (bound 2.970 ms, measured
344.575 ms, 116 times the bound)** (calc:a8960c47, calc:4cffeef5). One 11,949-byte change digests in
0.303 µs (calc:b66d96d7). No physical joule bound exists here for SHA-256 or Ed25519, so joules carry no
fraction. ADR 0003 section 6.2 and `docs/A0_HOST_BOUNDS.md` mark their earlier figures as superseded
by this section.

## 5. Limits

- The host was shared and busier in run 2 (load 9.1 to 14.2) than in run 1 (4.3 to 8.8), the likely (untested) reason
  run 2's SHA-256 median is below run 1's. The reference uses the best repetition, per the A0 bound
  statistic.
- Energy is SoC package only and uncalibrated, as in A0. The device and memory rows of both runs are in
  their `report.json` files but are not J3 results.
- The corpus pins the Rust crates' decisions. It does not claim they are the only correct Ed25519
  semantics.

## 6. Reproduction

```
cargo test -p synapse-bench --lib crypto_vectors     # includes the portable-backend build
synapse-bench crypto-vectors-verify --corpus evidence/j3-crypto-vectors/vectors.bin
synapse-bench bounds-verify --evidence evidence/j3-crypto-throughput-r2
synapse-bench bounds-verify --evidence evidence/j3-crypto-throughput
```
