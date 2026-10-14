//! Correctness tests for the A0 host bound probes. No test asserts a speed: every
//! figure checked here comes from synthetic integers or from counting work.

use super::*;
use std::sync::atomic::AtomicU64;

/// W1's sealed floor measurement (Phase 5), as listed in its SHA256SUMS.
const W1_FLOOR_PATH: &str = "evidence/phase5-group-commit/floor.json";
const W1_FLOOR_SHA256: &str = "9c30eddf2e278921b28df5ecd8f3b2e2b8f43771c73c5c540b8d9dc965f5ccef";

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn scratch(name: &str) -> PathBuf {
    static N: AtomicU64 = AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!(
        "synapse-a0-test-{}-{}-{name}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn small_protocol() -> Protocol {
    Protocol {
        schema: PROTOCOL_SCHEMA.into(),
        repetitions: 3,
        central_statistic: CentralStatistic::Median,
        spread_statistic: SpreadStatistic::Range,
        bound_statistic: BoundStatistic::MaxRate,
        threads: 2,
        idle_ms: 10,
        memory: MemoryParams {
            bytes_per_thread: 4096,
            passes: 2,
        },
        device: DeviceParams {
            file_bytes: 4 * 4096,
            chunk_bytes: 4096,
            threads: 2,
        },
        sha256: HashParams {
            block_bytes: 64,
            blocks_per_thread: 2,
        },
        ed25519: VerifyParams {
            message_bytes: 64,
            verifications_per_thread: 2,
        },
        energy_preflight: PreflightParams {
            observe_ms: 50,
            min_counter_changes: 1,
        },
        w1_flush: W1Source {
            path: W1_FLOOR_PATH.into(),
            sha256: W1_FLOOR_SHA256.into(),
            probes: vec!["overwrite_4k_fdatasync".into()],
        },
    }
}

/// A fake `aien_spbm` hwmon device under `root/hwmon7`.
fn fake_meter(root: &Path, pkg_uj: u64, overflow: u64) -> PathBuf {
    let dev = root.join("hwmon7");
    fs::create_dir_all(&dev).unwrap();
    fs::write(dev.join("name"), "aien_spbm\n").unwrap();
    for (n, label) in ENERGY_LABELS.iter().enumerate() {
        let n = n + 1;
        fs::write(dev.join(format!("energy{n}_label")), format!("{label}\n")).unwrap();
        fs::write(dev.join(format!("energy{n}_input")), format!("{pkg_uj}\n")).unwrap();
        fs::write(
            dev.join(format!("energy{n}_overflow_raw")),
            format!("{overflow}\n"),
        )
        .unwrap();
    }
    dev
}

fn preflight_params() -> PreflightParams {
    PreflightParams {
        observe_ms: 60,
        min_counter_changes: 2,
    }
}

// ----- protocol -----------------------------------------------------------------

#[test]
fn protocol_refuses_too_few_repetitions_and_unaligned_device_chunks() {
    assert_eq!(small_protocol().validate(), Ok(()));
    let mut p = small_protocol();
    p.repetitions = 2;
    assert!(p.validate().is_err(), "2 repetitions cannot give a range");
    let mut p = small_protocol();
    p.device.chunk_bytes = 1000;
    assert!(p.validate().is_err(), "O_DIRECT needs 4096-byte chunks");
    let mut p = small_protocol();
    p.w1_flush.sha256 = "not-a-digest".into();
    assert!(p.validate().is_err(), "W1 source must be pinned by digest");
    let text =
        serde_json::to_string(&small_protocol())
            .unwrap()
            .replacen('{', "{\"extra_knob\":1,", 1);
    assert!(
        Protocol::parse(text.as_bytes()).is_err(),
        "unknown protocol fields are refused"
    );
}

// ----- energy preflight ---------------------------------------------------------

#[test]
fn hidden_energy_device_refuses_with_instrument_unavailable_and_writes_nothing() {
    let evidence = scratch("hidden-evidence");
    let work = scratch("hidden-work");
    let empty_hwmon = scratch("hidden-hwmon");
    fs::write(
        evidence.join(PROTOCOL_FILE),
        serde_json::to_vec_pretty(&small_protocol()).unwrap(),
    )
    .unwrap();
    let cfg = BoundsConfig {
        evidence_dir: evidence.clone(),
        work_dir: work.clone(),
        repo_root: repo_root(),
        hwmon_root: empty_hwmon,
        source_rev: "test".into(),
    };
    let outcome = run_bounds(&cfg);
    let refusal = outcome
        .as_ref()
        .err()
        .unwrap_or_else(|| panic!("hidden meter must refuse, got a report: {outcome:?}"));
    assert_eq!(refusal.code(), INSTRUMENT_UNAVAILABLE, "{refusal}");
    assert!(!evidence.join(RAW_FILE).exists(), "no raw figures written");
    assert!(!evidence.join(REPORT_FILE).exists(), "no report written");
    assert_eq!(
        fs::read_dir(&work).unwrap().count(),
        0,
        "no probe touched the work directory"
    );
}

#[test]
fn frozen_overflowed_or_missing_counters_refuse_preflight() {
    let frozen = scratch("frozen");
    fake_meter(&frozen, 5_000_000, 0);
    let r = energy_preflight(&frozen, &preflight_params());
    assert!(
        matches!(r, Err(BoundsRefusal::InstrumentUnavailable(_))),
        "a counter that never advances is not a meter: {:?}",
        r.err()
    );

    let overflowed = scratch("overflow");
    fake_meter(&overflowed, 5_000_000, 1);
    let r = energy_preflight(&overflowed, &preflight_params());
    assert!(
        matches!(r, Err(BoundsRefusal::InstrumentUnavailable(_))),
        "overflow flag set: {:?}",
        r.err()
    );

    let missing_channel = scratch("missing");
    let dev = fake_meter(&missing_channel, 5_000_000, 0);
    fs::remove_file(dev.join("energy3_input")).unwrap();
    let r = energy_preflight(&missing_channel, &preflight_params());
    assert!(
        matches!(r, Err(BoundsRefusal::InstrumentUnavailable(_))),
        "cpu_p unreadable: {:?}",
        r.err()
    );
}

#[test]
fn advancing_counter_passes_preflight() {
    let root = scratch("advancing");
    let dev = fake_meter(&root, 1_000, 0);
    let stop = Arc::new(AtomicBool::new(false));
    let ticker = {
        let (stop, file) = (stop.clone(), dev.join("energy1_input"));
        std::thread::spawn(move || {
            let mut v = 1_000u64;
            while !stop.load(Ordering::Relaxed) {
                v += 1_000;
                let tmp = file.with_extension("tmp");
                fs::write(&tmp, format!("{v}\n")).unwrap();
                fs::rename(&tmp, &file).unwrap();
                std::thread::sleep(Duration::from_millis(5));
            }
        })
    };
    let r = energy_preflight(&root, &preflight_params());
    stop.store(true, Ordering::Relaxed);
    ticker.join().unwrap();
    assert!(r.is_ok(), "advancing counter refused: {:?}", r.err());
}

// ----- energy figures from raw counters -----------------------------------------

/// Samples every 100 ms for `n` periods; pkg advances `pkg_step_uj` per period, cpu_p
/// and cpu_e a quarter each.
fn samples(n: u64, pkg_step_uj: u64) -> Vec<RawEnergySample> {
    (0..=n)
        .map(|i| RawEnergySample {
            t_ns: i * 100_000_000,
            pkg_uj: Some(10_000_000 + i * pkg_step_uj),
            cpu_e_uj: Some(i * pkg_step_uj / 4),
            cpu_p_uj: Some(i * pkg_step_uj / 4),
        })
        .collect()
}

fn energy(samples: Vec<RawEnergySample>) -> RawEnergy {
    RawEnergy {
        overflow_at_start: false,
        overflow_at_end: false,
        samples,
    }
}

#[test]
fn energy_figures_come_from_counter_differences() {
    // 10 periods of 2 J each: 20 J over 1 s, 20 W; idle 5 W leaves 15 J above idle.
    let f = energy_figures(&energy(samples(10, 2_000_000)), 1_000, Some(5.0));
    assert!(f.valid, "{:?}", f.refusal);
    assert_eq!(f.pkg_j, Some(20.0));
    assert_eq!(f.cpu_p_j, Some(5.0));
    assert_eq!(f.cpu_e_j, Some(5.0));
    assert_eq!(f.window_s, Some(1.0));
    assert_eq!(f.pkg_mean_w, Some(20.0));
    assert_eq!(f.pkg_j_per_unit, Some(0.02));
    assert_eq!(f.pkg_j_per_unit_above_idle, Some(0.015));
}

#[test]
fn energy_figures_refuse_broken_windows() {
    let mut decreasing = samples(10, 2_000_000);
    decreasing[5].pkg_uj = Some(1);
    let mut gap = samples(10, 2_000_000);
    gap.remove(4);
    gap.remove(4);
    gap.remove(4);
    let mut overflow = energy(samples(10, 2_000_000));
    overflow.overflow_at_end = true;
    let mut unreadable = samples(10, 2_000_000);
    unreadable[3].cpu_e_uj = None;
    let cases = [
        ("decreasing counter", energy(decreasing)),
        ("400 ms gap", energy(gap)),
        ("overflow at an edge", overflow),
        ("unreadable counter", energy(unreadable)),
        ("one sample", energy(samples(0, 1))),
    ];
    for (what, raw) in cases {
        let f = energy_figures(&raw, 1_000, Some(5.0));
        assert!(!f.valid, "{what} accepted");
        assert!(f.refusal.is_some(), "{what} has no refusal reason");
        assert_eq!(f.pkg_j, None, "{what} reported joules");
        assert_eq!(f.pkg_j_per_unit, None, "{what} reported joules per unit");
    }
}

// ----- report and verification ---------------------------------------------------

fn synthetic_raw(p: &Protocol, protocol_bytes: &[u8]) -> RawEvidence {
    // Memory read takes 1, 2, then 4 ms in repetitions 0, 1, 2; every other probe 1 ms.
    let mut runs = Vec::new();
    for rep in 0..p.repetitions {
        for probe in PROBE_ORDER {
            let elapsed_ns = if probe == ProbeKind::MemoryRead {
                1_000_000 << rep
            } else {
                1_000_000
            };
            let step = if probe == ProbeKind::Idle {
                1_000_000
            } else {
                2_000_000
            };
            runs.push(RawRun {
                probe,
                rep,
                threads: p.expected_threads(probe),
                work_units: p.expected_units(probe),
                elapsed_ns,
                error: None,
                energy: energy(samples(10, step)),
                loadavg_start: None,
                loadavg_end: None,
            });
        }
    }
    RawEvidence {
        schema: RAW_SCHEMA.into(),
        protocol_sha256: sha256_hex(protocol_bytes),
        source_rev: "synthetic".into(),
        started_utc: "2026-10-14T00:00:00Z".into(),
        host: collect_host_info(&std::env::temp_dir()),
        instruments: Instruments {
            clock: "synthetic".into(),
            clock_resolution_ns: 1,
            energy_sensor: "synthetic".into(),
            energy_step_uj: 1000,
            energy_update_period_ms: 100,
            energy_sample_period_ms: 100,
        },
        w1_flush: load_w1_flush(&repo_root(), &p.w1_flush).unwrap(),
        runs,
    }
}

#[test]
fn report_figures_are_recomputed_from_integers() {
    let p = small_protocol();
    let pb = serde_json::to_vec_pretty(&p).unwrap();
    let raw = serde_json::to_vec_pretty(&synthetic_raw(&p, &pb)).unwrap();
    let r = compute_report(&pb, &raw).unwrap();
    let read = r
        .probes
        .iter()
        .find(|s| s.probe == ProbeKind::MemoryRead)
        .unwrap();
    // 2 threads x 4096 B x 2 passes = 16384 B in 1, 2, 4 ms.
    let rate = read.rate_per_s.as_ref().expect("memory read rate");
    assert_eq!(
        (rate.median, rate.min, rate.max, rate.n),
        (8_192_000.0, 4_096_000.0, 16_384_000.0, 3)
    );
    let bound = r
        .bound_inputs
        .iter()
        .find(|b| b.name == "memory_read_bandwidth")
        .expect("memory bound input");
    assert_eq!(bound.value, 16_384_000.0, "bound is the highest rate");
    assert_eq!(bound.statistic, BoundStatistic::MaxRate);
    // 20 J per run, idle 10 W over the same 1 s window.
    let jpu = read.pkg_j_per_unit.as_ref().expect("joules per byte");
    assert_eq!(jpu.median, 20.0 / 16_384.0);
    let above = read.pkg_j_per_unit_above_idle.as_ref().expect("above idle");
    assert_eq!(above.median, 10.0 / 16_384.0);
    assert_eq!(r.w1_flush.sha256, W1_FLOOR_SHA256);
    assert_eq!(r.w1_flush.probes[0].name, "overwrite_4k_fdatasync");
    assert_eq!(r.raw_sha256, sha256_hex(&raw));
}

fn sealed(p: &Protocol) -> PathBuf {
    let dir = scratch("sealed");
    let pb = serde_json::to_vec_pretty(p).unwrap();
    let raw = serde_json::to_vec_pretty(&synthetic_raw(p, &pb)).unwrap();
    let report = serde_json::to_vec_pretty(&compute_report(&pb, &raw).unwrap()).unwrap();
    fs::write(dir.join(PROTOCOL_FILE), &pb).unwrap();
    fs::write(dir.join(RAW_FILE), &raw).unwrap();
    fs::write(dir.join(REPORT_FILE), &report).unwrap();
    write_sums(&dir, &[PROTOCOL_FILE, RAW_FILE, REPORT_FILE]);
    dir
}

/// Writes `SHA256SUMS` in the `sha256sum` format over `names`.
fn write_sums(dir: &Path, names: &[&str]) {
    let text: String = names
        .iter()
        .map(|n| format!("{}  {n}\n", sha256_hex(&fs::read(dir.join(n)).unwrap())))
        .collect();
    fs::write(dir.join("SHA256SUMS"), text).unwrap();
}

/// Rewrites `report.json` so it is consistent with the (edited) raw data again.
fn reseal_report(dir: &Path) {
    let pb = fs::read(dir.join(PROTOCOL_FILE)).unwrap();
    let raw = fs::read(dir.join(RAW_FILE)).unwrap();
    let report = serde_json::to_vec_pretty(&compute_report(&pb, &raw).unwrap()).unwrap();
    fs::write(dir.join(REPORT_FILE), report).unwrap();
}

fn edit_raw(dir: &Path, f: impl FnOnce(&mut RawEvidence)) {
    let mut raw: RawEvidence =
        serde_json::from_slice(&fs::read(dir.join(RAW_FILE)).unwrap()).unwrap();
    f(&mut raw);
    fs::write(dir.join(RAW_FILE), serde_json::to_vec_pretty(&raw).unwrap()).unwrap();
}

#[test]
fn verify_accepts_sealed_evidence_as_written() {
    let dir = sealed(&small_protocol());
    let r = verify_evidence(&dir).expect("untouched evidence verifies");
    assert_eq!(r.probes.len(), PROBE_ORDER.len());
}

#[test]
fn verify_refuses_a_changed_raw_sample() {
    let dir = sealed(&small_protocol());
    edit_raw(&dir, |r| r.runs[1].elapsed_ns += 1);
    assert!(
        matches!(
            verify_evidence(&dir),
            Err(VerifyError::ReportMismatch { .. })
        ),
        "one nanosecond changed in raw.json must break the report: {:?}",
        verify_evidence(&dir)
    );
}

#[test]
fn verify_refuses_a_changed_report_figure() {
    let dir = sealed(&small_protocol());
    let text = fs::read_to_string(dir.join(REPORT_FILE)).unwrap();
    fs::write(
        dir.join(REPORT_FILE),
        text.replacen("16384000.0", "16384001.0", 1),
    )
    .unwrap();
    assert!(
        matches!(
            verify_evidence(&dir),
            Err(VerifyError::ReportMismatch { .. })
        ),
        "an edited figure must not verify: {:?}",
        verify_evidence(&dir)
    );
}

#[test]
fn verify_refuses_a_protocol_changed_after_the_run() {
    let dir = sealed(&small_protocol());
    let mut p = small_protocol();
    p.repetitions = 4;
    fs::write(
        dir.join(PROTOCOL_FILE),
        serde_json::to_vec_pretty(&p).unwrap(),
    )
    .unwrap();
    assert!(
        matches!(
            verify_evidence(&dir),
            Err(VerifyError::ProtocolDigestMismatch { .. })
        ),
        "{:?}",
        verify_evidence(&dir)
    );
}

#[test]
fn verify_refuses_dropped_extra_or_resized_repetitions() {
    let dir = sealed(&small_protocol());
    edit_raw(&dir, |r| {
        r.runs
            .retain(|x| !(x.probe == ProbeKind::MemoryRead && x.rep == 2));
    });
    assert!(
        matches!(
            verify_evidence(&dir),
            Err(VerifyError::RepetitionMismatch(_))
        ),
        "a dropped repetition (cherry-picking) must not verify: {:?}",
        verify_evidence(&dir)
    );

    let dir = sealed(&small_protocol());
    edit_raw(&dir, |r| {
        let mut extra = r.runs[1].clone();
        extra.rep = 0;
        r.runs.push(extra);
    });
    assert!(
        matches!(
            verify_evidence(&dir),
            Err(VerifyError::RepetitionMismatch(_))
        ),
        "an extra repetition must not verify: {:?}",
        verify_evidence(&dir)
    );

    let dir = sealed(&small_protocol());
    edit_raw(&dir, |r| r.runs[1].work_units /= 2);
    assert!(
        matches!(verify_evidence(&dir), Err(VerifyError::WorkMismatch(_))),
        "work other than the protocol's must not verify: {:?}",
        verify_evidence(&dir)
    );
}

#[test]
fn verify_checks_sha256sums_not_only_consistency() {
    // Edit raw.json and regenerate a consistent report.json: consistency alone would
    // verify, so the sealed checksums must catch it.
    let dir = sealed(&small_protocol());
    edit_raw(&dir, |r| r.runs[1].elapsed_ns += 1);
    reseal_report(&dir);
    let err = verify_evidence(&dir).map(|_| ()).unwrap_err().to_string();
    assert!(err.starts_with("CHECKSUM_MISMATCH"), "{err}");
    assert!(err.contains(RAW_FILE), "{err}");

    // No SHA256SUMS at all.
    let dir = sealed(&small_protocol());
    fs::remove_file(dir.join("SHA256SUMS")).unwrap();
    let err = verify_evidence(&dir).map(|_| ()).unwrap_err().to_string();
    assert!(err.starts_with("CHECKSUMS_MISSING"), "{err}");

    // SHA256SUMS that leaves out one of the three sealed files.
    let dir = sealed(&small_protocol());
    write_sums(&dir, &[PROTOCOL_FILE, RAW_FILE]);
    let err = verify_evidence(&dir).map(|_| ()).unwrap_err().to_string();
    assert!(err.starts_with("CHECKSUMS_MISSING"), "{err}");
    assert!(err.contains(REPORT_FILE), "{err}");

    // Every listed file is checked, not only the three sealed ones.
    let dir = sealed(&small_protocol());
    fs::write(dir.join("note.txt"), "log").unwrap();
    write_sums(&dir, &[PROTOCOL_FILE, RAW_FILE, REPORT_FILE, "note.txt"]);
    verify_evidence(&dir).expect("listed extra file matches");
    fs::write(dir.join("note.txt"), "edited log").unwrap();
    let err = verify_evidence(&dir).map(|_| ()).unwrap_err().to_string();
    assert!(err.starts_with("CHECKSUM_MISMATCH"), "{err}");
}

#[test]
fn errored_repetitions_are_counted_and_refused_beyond_the_protocol_allowance() {
    let p = small_protocol();
    let pb = serde_json::to_vec_pretty(&p).unwrap();
    let clean = serde_json::to_vec_pretty(&synthetic_raw(&p, &pb)).unwrap();
    let report = serde_json::to_value(compute_report(&pb, &clean).unwrap()).unwrap();
    assert_eq!(
        report["excluded_repetitions"], 0,
        "count is always reported"
    );

    // Protocol v1 allows no excluded repetitions: a run marked `error` (which skips
    // its work) must not quietly drop out of the statistics.
    let mut raw = synthetic_raw(&p, &pb);
    let i = raw
        .runs
        .iter()
        .position(|r| r.probe == ProbeKind::MemoryRead && r.rep == 2)
        .unwrap();
    raw.runs[i].error = Some("synthetic failure".into());
    raw.runs[i].work_units = 0;
    let raw = serde_json::to_vec_pretty(&raw).unwrap();
    let err = compute_report(&pb, &raw)
        .map(|_| ())
        .unwrap_err()
        .to_string();
    assert!(err.starts_with("EXCLUDED_REPETITIONS"), "{err}");
    assert!(err.contains("MemoryRead rep 2"), "{err}");
}

#[test]
fn measured_rates_are_labelled_achieved_never_bounds() {
    let p = small_protocol();
    let pb = serde_json::to_vec_pretty(&p).unwrap();
    let raw = serde_json::to_vec_pretty(&synthetic_raw(&p, &pb)).unwrap();
    let report = serde_json::to_value(compute_report(&pb, &raw).unwrap()).unwrap();
    let inputs = report["bound_inputs"].as_array().unwrap();
    let kind = |name: &str| {
        inputs
            .iter()
            .find(|b| b["name"] == name)
            .unwrap_or_else(|| panic!("{name}"))["kind"]
            .clone()
    };
    for name in [
        "memory_read_bandwidth",
        "memory_copy_bandwidth",
        "device_write_bandwidth",
        "device_read_bandwidth",
    ] {
        assert_eq!(kind(name), "achieved (lower bound on capability)", "{name}");
    }
    for name in [
        "sha256_all_core_throughput",
        "ed25519_verify_all_core_throughput",
    ] {
        assert_eq!(
            kind(name),
            "implementation reference (section 6.2 replacement rule)",
            "{name}"
        );
    }
    // Any other label, such as calling a measurement a hardware bound, is refused.
    let mut forged = report.clone();
    forged["bound_inputs"][0]["kind"] = "hardware measurement".into();
    assert!(serde_json::from_value::<Report>(forged).is_err());
}

#[test]
fn w1_source_with_a_different_digest_is_refused() {
    let mut src = small_protocol().w1_flush;
    src.sha256 = "0".repeat(64);
    assert!(matches!(
        load_w1_flush(&repo_root(), &src),
        Err(BoundsRefusal::W1SourceMismatch(_))
    ));
    let mut src = small_protocol().w1_flush;
    src.probes = vec!["no_such_probe".into()];
    assert!(matches!(
        load_w1_flush(&repo_root(), &src),
        Err(BoundsRefusal::W1SourceMismatch(_))
    ));
}

// ----- probes do the work they count ---------------------------------------------

#[test]
fn memory_read_touches_every_word_of_every_pass() {
    let mut st = memory_read_states(2, 4096);
    let t = memory_read(&mut st, 3).unwrap();
    assert_eq!(t.units, 2 * 4096 * 3);
    for (i, s) in st.iter().enumerate() {
        let one_pass = (0..512u64).fold(0u64, |a, j| a.wrapping_add(((i as u64) << 32) + j));
        assert_eq!(s.checksum, one_pass.wrapping_mul(3), "thread {i}");
    }
}

#[test]
fn memory_copy_copies_and_counts_both_directions() {
    let mut st = memory_copy_states(2, 4096);
    let t = memory_copy(&mut st, 2).unwrap();
    assert_eq!(t.units, 2 * 2 * 4096 * 2);
    for s in &st {
        assert_eq!(s.dst, s.src);
    }
}

#[test]
fn device_probes_write_then_read_back_the_pattern() {
    let dir = scratch("device");
    let path = dir.join("device.dat");
    let p = DeviceParams {
        file_bytes: 8 * 4096,
        chunk_bytes: 4096,
        threads: 2,
    };
    prepare_device_file(&path, p.file_bytes).unwrap();
    let w = device_write(&path, &p, 0x5a).unwrap();
    assert_eq!(w.units, p.file_bytes);
    let bytes = fs::read(&path).unwrap();
    assert_eq!(bytes.len() as u64, p.file_bytes);
    assert!(bytes.iter().all(|&b| b == 0x5a), "every byte overwritten");
    let r = device_read(&path, &p, 0x5a).unwrap();
    assert_eq!(r.units, p.file_bytes);
    assert!(
        device_read(&path, &p, 0x5b).is_err(),
        "a wrong pattern is detected on read-back"
    );
}

#[test]
fn arm_sha256_matches_the_sha2_crate() {
    if !cfg!(target_arch = "aarch64") {
        assert_eq!(sha256_arm(b"abc"), None);
        return;
    }
    let data: Vec<u8> = (0..20_000u32).map(|i| (i * 7 + 3) as u8).collect();
    for len in (0..=200).chain([1000, 16_384, 19_999]) {
        let want: [u8; 32] = Sha256::digest(&data[..len]).into();
        assert_eq!(sha256_arm(&data[..len]), Some(want), "length {len}");
    }
    let mut st = hash_states(2, 64);
    let t = sha256_arm_instructions(&mut st, 3).unwrap();
    assert_eq!(t.units, 2 * 64 * 3);
    for s in &st {
        let want: [u8; 32] = Sha256::digest(&s.block).into();
        assert_eq!(s.last, want);
    }
}

#[test]
fn sha2_crate_probe_counts_hashed_bytes() {
    let mut st = hash_states(3, 100);
    let t = sha256_sha2_crate(&mut st, 4).unwrap();
    assert_eq!(t.units, 3 * 100 * 4);
    for s in &st {
        let want: [u8; 32] = Sha256::digest(&s.block).into();
        assert_eq!(s.last, want);
    }
}

#[test]
fn ed25519_probe_verifies_and_refuses_a_bad_signature() {
    let mut st = verify_states(2, 64);
    let t = ed25519_verify(&mut st, 5).unwrap();
    assert_eq!(t.units, 10);
    st[1].items[0].1[0] ^= 1;
    assert!(
        ed25519_verify(&mut st, 5).is_err(),
        "a tampered message must fail verification"
    );
}
