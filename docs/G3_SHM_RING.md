# G3: Shared-Memory Ring for Local Agents (experiment X5)

ADR 0003 section 9 step G3 (issue aien-spark/synapse#46), crate `synapse-wire`. A ring buffer in memory shared by two local processes, carrying the G1 frame session without a socket. **Status: not adopted.** The X5 rule did not favour it over the Unix socket (section 5), so the socket stays the default transport and the ring is an optional, tested transport that nothing selects by default.

Code: `crates/synapse-wire/src/ring.rs` (ring, sender, receiver, `RingStream`), `crates/synapse-wire/src/shm.rs` (the only new unsafe code: sealed `memfd`, `mmap`, futex). Tests: `crates/synapse-wire/tests/g3_ring.rs`. Measurement: `crates/synapse-bench/src/bin/wire-transport.rs` (`--arms ring,wire`).

## 1. Layout

One region holds a control block of 32 words (8 bytes each) and two rings, one per direction. The creator sends on ring 0, the attacher on ring 1. Control words: magic `SYNRING1`, capacity, start index, then (per ring) head (written by the sender), closed flag, tail (written by the receiver), receiver-sleeping flag and a doorbell. Indices are byte counts that increase without bound and wrap at `u64::MAX`; the data offset is the index masked by the capacity (a power of two from 64 B to 1 GiB, default 1 MiB).

A record is a 16-byte header (payload length word, sequence word) followed by the payload padded to 8 bytes. A record may wrap past the end of the ring; every word is addressed through the mask. The sender publishes the head with a release store after the record is written, and the receiver reads it with an acquire load.

## 2. Hostile peer rules

The reader treats the writer as hostile. Each header word is loaded once into a local, the checks and the copy use only those locals, and the payload is copied out of the ring into the reader's own buffer, so a writer that changes bytes mid-read cannot change what was checked or make the reader read twice. Refused with a typed `RingRefusal` (surfaced as `RefusalCode::WireRingViolation`): head misaligned, head beyond the sender's own capacity window, head moving backwards, a record length over the configured cap or past the published bytes, a torn record (header not yet complete within published bytes), a wrong sequence number. After any refusal the endpoint is poisoned and refuses all later calls, so a record is never accepted twice. The sender applies the same rules to the tail the receiver publishes.

Memory safety: all shared access goes through `AtomicU64` with explicit orderings; offsets are masked, so no index can address outside the ring.

## 3. Sealing

A reader of a file-backed mapping takes `SIGBUS` if the peer shrinks the file under it. The creator makes a `memfd` and seals it against shrinking, growing and re-sealing before anyone can attach; an attacher refuses a file without the shrink seal or with the wrong size. Test: `attached_peer_cannot_shrink_or_grow_the_sealed_region`, `attach_refuses_an_unsealed_wrong_size_or_mismatched_region`.

## 4. Waiting

The receiver polls for 50 microseconds, then sets a sleeping flag, issues a sequentially consistent fence, re-checks, and sleeps on a shared futex (10 ms timeout, so a missed wake only costs the timeout). The sender wakes the doorbell only when the sleeping flag is set. Linux 64-bit only for the shared mode; other targets get the in-process ring.

## 5. Acceptance

| Acceptance item (issue #46) | Test or evidence | Result |
| :--- | :--- | :--- |
| Hostile writer (bad lengths) cannot make the reader panic or read outside the ring | `hostile_writer_bad_lengths_cannot_make_the_reader_panic_or_read_outside_the_ring` | PASS |
| Hostile writer (index wrap) | `hostile_writer_index_wrap_cannot_make_the_reader_panic_or_read_outside_the_ring`, `honest_indices_wrap_past_u64_max_and_the_ring_end_without_loss` | PASS |
| Hostile writer (torn frames) | `hostile_writer_torn_frames_are_refused_and_payloads_are_copied_out_before_validation` | PASS |
| Reader never accepts a frame twice | `hostile_writer_cannot_make_the_reader_accept_a_record_twice`, `hostile_writer_random_pokes_never_panic_and_never_deliver_a_record_twice` (3,000 seeds, all six peer-fault kinds hit) | PASS |
| Tests can fail | `negative_control_trusting_reader_panics_or_accepts_twice_on_the_same_inputs` | PASS |
| No frame lost or duplicated in a model test | `model_test_no_frame_is_lost_or_duplicated` (400 seeds, over 100,000 records), `model_test_two_threads_two_mappings_no_record_lost_or_duplicated` (200,000), `cross_process_ring_delivers_every_record_once_in_order` | PASS |
| Carries the G1 session | `ring_stream_carries_the_g1_session_and_acknowledges_durable_changes`, `ring_refusal_reaches_the_frame_transport_as_wire_ring_violation` | PASS |
| Adopted only if the X5 rule, fixed in writing before the run, favours it | `evidence/g3-shm-ring/x5/RULE.md` committed in 864aeca before `run1`; verdict in `evidence/g3-shm-ring/x5/RESULTS.md` | NOT ADOPTED |

Red before green: `evidence/g3-shm-ring/red-green/red.txt` (two stubs of `ring.rs`: a trusting reader; unmasked offsets; diffs alongside) and `green.txt`.

## 6. X5 result

Same workload and bound as G1 (`docs/G1_WIRE_FRAMES.md` section 5; t_floor 0.806 ms, E_floor 18.6 mJ). 5 repetitions, 2,000 changes per arm per rep, raw samples in `evidence/g3-shm-ring/x5/run1/result.json`.

| Arm | Median s per change | Fraction of time bound | SoC package J per change | Fraction of energy bound |
| :--- | ---: | ---: | ---: | ---: |
| `ring` | 1.541 x 10^-3 | 0.524 | 46.4 x 10^-3 | 0.401 |
| `wire` (Unix socket) | 1.606 x 10^-3 | 0.502 | 46.1 x 10^-3 | 0.403 |
| `direct_auth` (no transport) | 1.521 x 10^-3 | 0.530 | 40.4 x 10^-3 | 0.461 |

The ring's median is 4 percent faster, but its slowest repetition (1.863 ms) is slower than the socket's fastest (1.466 ms), and joules are level. The rule needs both seconds and joules beyond run-to-run spread, so the verdict is NOT ADOPTED. Supporting echo test (no store): p50 6.8 us per round trip for the ring against 9.1 us for the socket; the commit dominates cost per change, which is why the gain does not show in the table. Details and limits: `evidence/g3-shm-ring/x5/RESULTS.md`. G1's own figures (1.628 ms, 40.6 mJ for `wire`) were a different run on a differently loaded machine; only within-run comparisons are used here.

## 7. Limits and deviations

* Not wired as a default or selected anywhere; ADR 0003 is unchanged.
* Measurement runs client and server as two threads of one process over one region; a separate client process is covered by the safety test only.
* Joules are the `aien_spbm` SoC package meter: package only, uncalibrated, NVMe unmeasured. The machine was shared (load about 5.8 during the idle window), so spread is wide.
* A receiver can block until the peer closes, as a socket reader does; there is no keepalive. A sender facing a full ring waits without a limit.
* Shared mode (memfd, futex) is Linux 64-bit only (aarch64 and x86_64 futex numbers); the system call numbers and constants were taken from the local glibc 2.39 headers and the `libc` 0.2.189 source. No new crates.
* Small additions outside the crate: `RefusalCode::WireRingViolation` in `synapse-core`, the refusal list in `docs/SCHEMA_AND_CONSISTENCY.md`, the `.crumb` role text, the `--arms/--step/--rule/--echo` options of `wire-transport`.
