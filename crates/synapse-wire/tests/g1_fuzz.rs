//! G1 acceptance: coverage-guided fuzzing of the untrusted length-prefixed frame decoder,
//! for a budget fixed before the run, finds no panic, no read past a frame, and no
//! allocation above the declared cap, and every malformed frame in the fuzz corpus is
//! refused with a typed refusal.
//!
//! The budget here is a fixed execution count (deterministic in CI). The time-budgeted
//! evidence run uses the `synapse-wire-fuzz` binary (see `docs/G1_WIRE_FRAMES.md`).
//! Negative controls plant one bug each in a copy of the target and require the same
//! fuzzer, with the same budget, to report it, so a silent detector cannot pass.

use synapse_core::RefusalCode;
use synapse_wire::frame::{WireLimits, WireRefusal, FRAME_HEADER_LEN};
use synapse_wire::fuzz::{
    malformed_seed_corpus, replay_corpus, run, run_target, seed_corpus, server_decode, Budget,
    CountingAlloc, FuzzConfig, FuzzReport, TargetOutcome,
};
use synapse_wire::probe::{EdgeProbe, Probe};

#[global_allocator]
static ALLOC: CountingAlloc = CountingAlloc;

/// Fuzz cap on a frame body (bytes); seeds are all smaller.
const CAP: u32 = 8192;
/// Execution budget, fixed before the run.
const EXECS: u64 = 300_000;
const SEED: u64 = 0x6100_F022;

fn cfg(execs: u64) -> FuzzConfig {
    FuzzConfig {
        seed: SEED,
        budget: Budget::Execs(execs),
        limits: WireLimits {
            max_frame_body: CAP,
        },
        max_corpus: 20_000,
    }
}

fn seeds() -> Vec<Vec<u8>> {
    let s = seed_corpus(&WireLimits {
        max_frame_body: CAP,
    });
    assert_eq!(s.len(), VALID_SEEDS, "every sample frame fits the fuzz cap");
    let mut all = s;
    all.extend(malformed());
    all
}

const VALID_SEEDS: usize = 14;

fn malformed() -> Vec<Vec<u8>> {
    malformed_seed_corpus(&WireLimits {
        max_frame_body: CAP,
    })
}

fn main_run() -> FuzzReport {
    run(cfg(EXECS), &seeds())
}

#[test]
fn fuzzing_frame_decoder_finds_no_panic_no_read_past_frame_no_allocation_over_cap() {
    let r = main_run();
    assert!(r.alloc_tracking, "the counting allocator must be installed");
    assert_eq!(r.execs, EXECS);
    assert_eq!(
        r.violation_total(),
        0,
        "violations: {:?}",
        r.violations
            .iter()
            .map(|v| (v.kind, &v.detail))
            .collect::<Vec<_>>()
    );
    assert!(
        r.peak_alloc as u64 <= u64::from(CAP),
        "peak {}",
        r.peak_alloc
    );
    // The run explored the decoder: new coverage beyond the seeds, most sites reached.
    assert!(r.corpus.len() > r.seeds, "corpus {}", r.corpus.len());
    assert!(
        r.sites_unreached.len() * 10 <= r.sites_total,
        "unreached decoder sites (lines of frame.rs): {:?} of {}",
        r.sites_unreached,
        r.sites_total
    );
    // Both accepted and refused outcomes, for every frame kind, were exercised.
    for kind in [
        "Hello", "Have", "Want", "Chunk", "Submit", "Accepted", "Refused",
    ] {
        assert!(
            r.outcomes.contains_key(&format!("accepted:{kind}")),
            "no accepted {kind}"
        );
    }
}

#[test]
fn every_malformed_frame_in_fuzz_corpus_is_refused_with_typed_refusal() {
    let r = main_run();
    let limits = WireLimits {
        max_frame_body: CAP,
    };
    let replay = replay_corpus(&r.corpus, &limits);
    assert!(replay.violations.is_empty(), "{:?}", replay.violations);
    let refused: usize = replay.refused.values().sum();
    assert_eq!(replay.entries, replay.accepted_canonical + refused);
    // The well-formed seeds are in the corpus and still decode canonically.
    assert!(
        replay.accepted_canonical >= VALID_SEEDS,
        "accepted {} of {VALID_SEEDS} valid seeds",
        replay.accepted_canonical
    );
    // Every hand-made malformed seed (bad magic, version, kind, flags, reserved, length over
    // the cap, truncated, trailing byte) is in the corpus and refused with a typed refusal.
    let bad = malformed();
    assert_eq!(bad.len(), VALID_SEEDS * 9);
    for (i, input) in bad.iter().enumerate() {
        assert_eq!(&r.corpus[VALID_SEEDS + i], input);
        match synapse_wire::fuzz::target(input, &limits) {
            TargetOutcome::Refused(_) => {}
            other => panic!("malformed seed {i} was not refused: {other:?}"),
        }
    }
    assert!(refused > 0);
    assert!(
        replay.refused.len() >= 10,
        "refusal kinds reached: {:?}",
        replay.refused
    );
    // Each refusal maps to the typed service refusal `WireFrameMalformed`.
    for input in &r.corpus {
        if let TargetOutcome::Refused(w) = synapse_wire::fuzz::target(input, &limits) {
            assert_eq!(w.clone().into_error().code, RefusalCode::WireFrameMalformed);
        }
    }
}

// ---------------------------------------------------------------------------------------
// Negative controls: planted bugs the fuzzer must find within the same kind of budget.
// ---------------------------------------------------------------------------------------

const CONTROL_EXECS: u64 = 60_000;

fn control(target: synapse_wire::fuzz::Target, kind: &str) {
    let r = run_target(cfg(CONTROL_EXECS), &seeds(), target);
    assert!(
        r.violation_counts.get(kind).copied().unwrap_or(0) > 0,
        "planted {kind} bug not found; counts {:?}",
        r.violation_counts
    );
}

/// A decoder that panics on a non-zero flags byte (a missing check before a table lookup).
fn planted_panic(input: &[u8], l: &WireLimits, p: &mut EdgeProbe) -> TargetOutcome {
    if input.len() >= FRAME_HEADER_LEN && input[0..4] == *b"SYNW" && input[6] != 0 {
        let table = [0u8; 1];
        let i = input[6] as usize;
        p.site(1);
        let _ = std::hint::black_box(table[std::hint::black_box(i)]);
    }
    server_decode(input, l, p)
}

/// A decoder that sizes a buffer from the declared length before checking the cap.
fn planted_over_alloc(input: &[u8], l: &WireLimits, p: &mut EdgeProbe) -> TargetOutcome {
    if input.len() >= FRAME_HEADER_LEN {
        let n = u32::from_le_bytes(input[12..16].try_into().unwrap()) as usize;
        let v: Vec<u8> = Vec::with_capacity(n.min(1 << 20));
        std::hint::black_box(v);
    }
    server_decode(input, l, p)
}

/// A decoder whose answer depends on the byte after the frame (reads one byte too far).
fn planted_read_past(input: &[u8], l: &WireLimits, p: &mut EdgeProbe) -> TargetOutcome {
    let out = server_decode(input, l, p);
    if let TargetOutcome::Accepted { consumed, .. } = &out {
        if let Some(&next) = input.get(*consumed) {
            p.touched(*consumed + 1);
            if next & 1 == 1 {
                return TargetOutcome::Refused(WireRefusal::TrailingBytes {
                    at: *consumed,
                    count: 1,
                });
            }
        }
    }
    out
}

/// A decoder that ignores the reserved byte, so two encodings of one frame decode.
fn planted_non_canonical(input: &[u8], l: &WireLimits, p: &mut EdgeProbe) -> TargetOutcome {
    let mut v = input.to_vec();
    if v.len() >= 8 {
        v[7] = 0;
    }
    server_decode(&v, l, p)
}

#[test]
fn negative_control_fuzzer_finds_planted_panic() {
    control(planted_panic, "panic");
}

#[test]
fn negative_control_fuzzer_finds_planted_allocation_over_cap() {
    control(planted_over_alloc, "alloc_over_cap");
}

#[test]
fn negative_control_fuzzer_finds_planted_read_past_frame() {
    control(planted_read_past, "read_past_frame");
}

#[test]
fn negative_control_fuzzer_finds_planted_non_canonical_accept() {
    control(planted_non_canonical, "non_canonical_accept");
}

/// Regression from the 300 s evidence run (`evidence/g1-wire-frames/fuzz/`): a `Submit`
/// whose scope lists many empty paths took 4 wire bytes per path but 24 bytes of memory per
/// decoded `String`, so one allocation passed the cap. The decoder now refuses a path count
/// whose decoded size would pass the cap.
#[test]
fn fuzz_regression_many_scope_paths_stay_under_allocation_cap() {
    use synapse_wire::frame::{decode_frame, encode_frame, Frame, FrameBody};
    use synapse_wire::fuzz::measured;
    use synapse_wire::testkit::{envelope, ChainFixture};
    let fx = ChainFixture::new(1, None);
    let (env, _) = envelope(&fx.agent, "many", &[], &["x"], 1);
    let mut req =
        synapse_wire::session::submit_request(&fx.agent, fx.chain.clone(), &env, [5; 32], 1)
            .unwrap();
    req.scope.paths = vec![String::new(); 400];
    let bytes = encode_frame(&Frame {
        request_id: 1,
        body: FrameBody::Submit(Box::new(req)),
    })
    .unwrap();
    let limits = WireLimits {
        max_frame_body: CAP,
    };
    assert!(bytes.len() - FRAME_HEADER_LEN <= CAP as usize);
    let (res, peak, _) = measured(|| decode_frame(&bytes, &limits));
    assert!(
        peak as u64 <= u64::from(CAP),
        "largest allocation {peak} over cap {CAP}"
    );
    assert!(
        matches!(res.unwrap(), Err(WireRefusal::LengthOverCap { .. })),
        "refused as over the cap"
    );
}
