//! Issue #64 acceptance tests. Portable: no test needs PMU access; the real-host test
//! accepts either valid counts or a typed refusal and fails on anything else.

use super::*;
use crate::fixture::test_support::{make_fixture_repo, temp_dir};
use crate::gitcmd::{git_line, git_ok};
use crate::pmu::{
    discover, event_attr, CounterReading, PerfBackend, PerfEventAttr, ATTR_FLAG_DISABLED,
    ATTR_FLAG_EXCLUDE_HV, ATTR_FLAG_EXCLUDE_KERNEL, ATTR_FLAG_INHERIT,
    PERF_FORMAT_TOTAL_TIME_ENABLED, PERF_FORMAT_TOTAL_TIME_RUNNING,
};
use std::cell::RefCell;
use std::collections::VecDeque;
use std::rc::Rc;

// ---------------------------------------------------------------- fake sysfs

/// One fake PMU: name, type, cpu list, MIDR, and `(event name, sysfs text)` overrides.
struct FakePmu<'a> {
    name: &'a str,
    perf_type: u32,
    cpus: &'a str,
    midr: &'a str,
    /// `None` removes the event file; `Some(text)` replaces the architected encoding.
    overrides: &'a [(&'a str, Option<&'a str>)],
}

const A725: FakePmu = FakePmu {
    name: "armv8_pmuv3_0",
    perf_type: 10,
    cpus: "0-4,10-14",
    midr: "0x00000000410fd871",
    overrides: &[],
};
const X925: FakePmu = FakePmu {
    name: "armv8_pmuv3_1",
    perf_type: 11,
    cpus: "5-9,15-19",
    midr: "0x00000000410fd851",
    overrides: &[],
};

fn fake_sysfs(label: &str, pmus: &[FakePmu], paranoid: &str) -> (PathBuf, Discovery) {
    let root = temp_dir(label);
    let sys = root.join("sys");
    let devs = sys.join("bus/event_source/devices");
    fs::create_dir_all(devs.join("software")).unwrap();
    fs::write(devs.join("software/type"), "1\n").unwrap();
    for p in pmus {
        let d = devs.join(p.name);
        fs::create_dir_all(d.join("events")).unwrap();
        fs::write(d.join("type"), format!("{}\n", p.perf_type)).unwrap();
        fs::write(d.join("cpus"), format!("{}\n", p.cpus)).unwrap();
        for spec in EVENTS {
            let text = match p.overrides.iter().find(|(n, _)| *n == spec.name) {
                Some((_, None)) => continue,
                Some((_, Some(t))) => t.to_string(),
                None => format!("event={:#06x}", spec.arm_event),
            };
            fs::write(d.join("events").join(spec.name), format!("{text}\n")).unwrap();
        }
        for c in crate::pmu::parse_cpu_list(p.cpus).unwrap() {
            let m = sys.join(format!("devices/system/cpu/cpu{c}/regs/identification"));
            fs::create_dir_all(&m).unwrap();
            fs::write(m.join("midr_el1"), format!("{}\n", p.midr)).unwrap();
        }
    }
    let paranoid_path = root.join("perf_event_paranoid");
    fs::write(&paranoid_path, format!("{paranoid}\n")).unwrap();
    let d = discover(&sys, &paranoid_path);
    (root, d)
}

// ---------------------------------------------------------------- fake backend

#[derive(Default)]
struct FakeLog {
    calls: Vec<String>,
    opened: Vec<PerfEventAttr>,
    open_fds: Vec<i32>,
}

/// Scripted `perf_event_open`: fails the `fail_at`-th open with `errno`, otherwise hands
/// out fds; reads pop from `reads` (or fail with EIO when empty).
struct FakePerf {
    log: Rc<RefCell<FakeLog>>,
    fail_at: Option<(usize, i32)>,
    reads: VecDeque<[u64; 3]>,
    next_fd: i32,
}

impl FakePerf {
    fn new(log: &Rc<RefCell<FakeLog>>) -> Self {
        Self {
            log: log.clone(),
            fail_at: None,
            reads: VecDeque::new(),
            next_fd: 100,
        }
    }
}

impl PerfBackend for FakePerf {
    fn open(&mut self, attr: &PerfEventAttr, group_fd: i32) -> Result<i32, i32> {
        let mut log = self.log.borrow_mut();
        let n = log.opened.len();
        log.calls.push(format!(
            "open type={} config={:#x} group={group_fd}",
            attr.type_, attr.config
        ));
        log.opened.push(*attr);
        if let Some((at, errno)) = self.fail_at {
            if n == at {
                return Err(errno);
            }
        }
        self.next_fd += 1;
        log.open_fds.push(self.next_fd);
        Ok(self.next_fd)
    }
    fn ioctl_group(&mut self, fd: i32, request: u64) -> Result<(), i32> {
        self.log
            .borrow_mut()
            .calls
            .push(format!("ioctl {fd} {request:#x}"));
        Ok(())
    }
    fn read3(&mut self, fd: i32) -> Result<[u64; 3], i32> {
        self.log.borrow_mut().calls.push(format!("read {fd}"));
        self.reads.pop_front().ok_or(libc::EIO)
    }
    fn close(&mut self, fd: i32) {
        let mut log = self.log.borrow_mut();
        log.calls.push(format!("close {fd}"));
        log.open_fds.retain(|f| *f != fd);
    }
}

fn session_with(
    discovery: &Discovery,
    affinity: AffinityPolicy,
    fail_at: Option<(usize, i32)>,
    reads: &[[u64; 3]],
) -> (PmuSample, Rc<RefCell<FakeLog>>) {
    let log = Rc::new(RefCell::new(FakeLog::default()));
    let mut fake = FakePerf::new(&log);
    fake.fail_at = fail_at;
    fake.reads = reads.iter().copied().collect();
    let mut s = PmuSession::open(fake, PmuMode::Enabled, discovery, affinity);
    s.start();
    let sample = s.stop();
    (sample, log)
}

// ---------------------------------------------------------------- acceptance 1

#[test]
fn acceptance1_discovery_verifies_encodings_and_core_classes() {
    let (_root, d) = fake_sysfs("disc", &[A725, X925], "2");
    assert_eq!(d.perf_event_paranoid, Some(2));
    assert_eq!(d.devices.len(), 2, "the software PMU is not a CPU PMU");
    assert_eq!(d.devices[0].core_class, CoreClass::CortexA725);
    assert_eq!(d.devices[1].core_class, CoreClass::CortexX925);
    assert_eq!(d.devices[0].cpus, vec![0, 1, 2, 3, 4, 10, 11, 12, 13, 14]);
    assert!(d.devices.iter().all(|x| x.all_events_verified()));
    assert_eq!(crate::pmu::parse_event_encoding("event=0x0010"), Some(0x10));
    assert_eq!(crate::pmu::parse_cpu_list("4-2"), None);
}

#[test]
fn acceptance1_event_attr_is_user_only_inherited_counting() {
    let a = event_attr(11, 0x10, true);
    assert_eq!(std::mem::size_of::<PerfEventAttr>(), 64);
    assert_eq!((a.type_, a.size, a.config), (11, 64, 0x10));
    assert_eq!(a.sample_period, 0, "counting, never sampling");
    assert_eq!(
        a.read_format,
        PERF_FORMAT_TOTAL_TIME_ENABLED | PERF_FORMAT_TOTAL_TIME_RUNNING
    );
    assert_eq!(
        a.flags,
        ATTR_FLAG_DISABLED | ATTR_FLAG_INHERIT | ATTR_FLAG_EXCLUDE_KERNEL | ATTR_FLAG_EXCLUDE_HV
    );
    assert_eq!(event_attr(11, 0x08, false).flags & ATTR_FLAG_DISABLED, 0);
}

#[test]
fn acceptance1_disabled_mode_makes_no_system_call() {
    let (_root, d) = fake_sysfs("disabled", &[A725, X925], "2");
    let log = Rc::new(RefCell::new(FakeLog::default()));
    let mut s = PmuSession::open(
        FakePerf::new(&log),
        PmuMode::Disabled,
        &d,
        AffinityPolicy::Unpinned,
    );
    s.start();
    assert_eq!(s.stop(), PmuSample::Disabled);
    assert!(
        log.borrow().calls.is_empty(),
        "calls: {:?}",
        log.borrow().calls
    );
}

#[test]
fn acceptance1_counted_reads_are_raw_and_attributed_per_core_class() {
    let (_root, d) = fake_sysfs("counted", &[A725, X925], "2");
    // A725 group ran the whole window; X925 group never ran (task pinned elsewhere).
    let reads = [
        [1000, 50, 50],
        [800, 50, 50],
        [90, 50, 50],
        [7, 50, 50],
        [0, 50, 0],
        [0, 50, 0],
        [0, 50, 0],
        [0, 50, 0],
    ];
    let (sample, log) = session_with(
        &d,
        AffinityPolicy::Pinned(CoreClass::CortexA725),
        None,
        &reads,
    );
    let PmuSample::Counted { readings } = sample else {
        panic!("expected counts, got {sample:?}")
    };
    assert_eq!(readings.len(), 8);
    assert_eq!(readings[0].core_class, CoreClass::CortexA725);
    assert_eq!(
        (readings[0].event.as_str(), readings[0].raw_count),
        ("cpu_cycles", 1000)
    );
    assert_eq!(readings[3].state, CounterState::Counted);
    assert_eq!(readings[4].core_class, CoreClass::CortexX925);
    assert_eq!(readings[4].state, CounterState::NotScheduled);
    let log = log.borrow();
    assert!(log.open_fds.is_empty(), "every fd closed");
    // Each PMU's events are opened by that PMU's own type, siblings in the leader's group.
    let types: Vec<u32> = log.opened.iter().map(|a| a.type_).collect();
    assert_eq!(types, vec![10, 10, 10, 10, 11, 11, 11, 11]);
    assert!(log.calls[1].ends_with("group=101"), "{}", log.calls[1]);
}

#[test]
fn acceptance1_multiplexed_and_partial_residency_are_labelled_not_scaled() {
    let (_root, d) = fake_sysfs("mux", &[A725], "2");
    let reads = [[600, 100, 40]; 4];
    let (pinned, _) = session_with(
        &d,
        AffinityPolicy::Pinned(CoreClass::CortexA725),
        None,
        &reads,
    );
    let PmuSample::Counted { readings } = pinned else {
        panic!("{pinned:?}")
    };
    assert!(readings
        .iter()
        .all(|r| r.state == CounterState::Multiplexed));
    assert!(
        readings.iter().all(|r| r.raw_count == 600),
        "never scaled to 1500"
    );
    let (unpinned, _) = session_with(&d, AffinityPolicy::Unpinned, None, &reads);
    let PmuSample::Counted { readings } = unpinned else {
        panic!("{unpinned:?}")
    };
    assert!(readings
        .iter()
        .all(|r| r.state == CounterState::PartialResidency));
}

#[test]
fn acceptance1_permission_denied_is_instrument_unavailable_without_counts() {
    let (_root, d) = fake_sysfs("eacces", &[A725, X925], "4");
    // Fails on the first event of the second PMU, after four fds were opened.
    let (sample, log) = session_with(&d, AffinityPolicy::Unpinned, Some((4, libc::EACCES)), &[]);
    match &sample {
        PmuSample::InstrumentUnavailable { reason, detail } => {
            assert_eq!(*reason, UnavailableReason::PermissionDenied);
            assert!(detail.contains("armv8_pmuv3_1"), "{detail}");
        }
        other => panic!("expected refusal, got {other:?}"),
    }
    assert!(
        log.borrow().open_fds.is_empty(),
        "fds opened before the refusal are closed"
    );
    assert!(
        !log.borrow().calls.iter().any(|c| c.starts_with("read")),
        "nothing read"
    );
    let json = serde_json::to_value(&sample).unwrap();
    assert_eq!(json["status"], "INSTRUMENT_UNAVAILABLE");
    assert_eq!(json["reason"], "PERMISSION_DENIED");
    assert!(
        json.get("readings").is_none(),
        "a refusal carries no counts: {json}"
    );
}

#[test]
fn acceptance1_unsupported_or_missing_pmu_refuses_before_any_open() {
    let wrong = FakePmu {
        overrides: &[("br_mis_pred", Some("event=0x0022"))],
        ..A725
    };
    let missing = FakePmu {
        overrides: &[("br_pred", None)],
        ..X925
    };
    for (label, pmus) in [("wrong-enc", vec![wrong]), ("missing-ev", vec![missing])] {
        let (_root, d) = fake_sysfs(label, &pmus, "2");
        let (sample, log) = session_with(&d, AffinityPolicy::Unpinned, None, &[]);
        assert!(
            matches!(
                sample,
                PmuSample::InstrumentUnavailable {
                    reason: UnavailableReason::UnsupportedEvent,
                    ..
                }
            ),
            "{label}: {sample:?}"
        );
        assert!(
            log.borrow().calls.is_empty(),
            "{label}: no open for an unverified event"
        );
    }
    let (_root, none) = fake_sysfs("no-pmu", &[], "2");
    let (sample, _) = session_with(&none, AffinityPolicy::Unpinned, None, &[]);
    assert!(matches!(
        sample,
        PmuSample::InstrumentUnavailable {
            reason: UnavailableReason::NoPmu,
            ..
        }
    ));
    let (_root, d) = fake_sysfs("enoent", &[A725], "2");
    let (sample, _) = session_with(&d, AffinityPolicy::Unpinned, Some((0, libc::ENOENT)), &[]);
    assert!(matches!(
        sample,
        PmuSample::InstrumentUnavailable {
            reason: UnavailableReason::UnsupportedEvent,
            ..
        }
    ));
    assert_eq!(
        UnavailableReason::from_open_errno(libc::ENOSYS),
        UnavailableReason::UnsupportedPlatform
    );
    assert_eq!(
        UnavailableReason::from_open_errno(libc::EBUSY),
        UnavailableReason::CounterUnavailable
    );
}

#[test]
fn acceptance1_malformed_reads_are_refused_never_repaired() {
    assert!(classify(5, 10, 11, true).is_err(), "running beyond enabled");
    assert!(
        classify(5, 10, 0, true).is_err(),
        "count with no running time"
    );
    let (_root, d) = fake_sysfs("malformed", &[A725], "2");
    for reads in [
        vec![[5, 10, 11]; 4],
        vec![[5, 10, 0]; 4],
        vec![[5, 10, 10]; 2],
    ] {
        let (sample, log) = session_with(&d, AffinityPolicy::Unpinned, None, &reads);
        assert!(
            matches!(
                sample,
                PmuSample::InstrumentUnavailable {
                    reason: UnavailableReason::CounterUnavailable,
                    ..
                }
            ),
            "{reads:?}: {sample:?}"
        );
        assert!(log.borrow().open_fds.is_empty());
    }
}

#[test]
fn acceptance1_real_host_sample_is_counted_or_typed_unavailable() {
    // Runs on any host: CI (no PMU or no permission) and the Spark alike.
    let d = crate::pmu::discover_host();
    let mut s = PmuSession::open(LinuxPerf, PmuMode::Enabled, &d, AffinityPolicy::Unpinned);
    s.start();
    let mut x = 0u64;
    for i in 0..100_000u64 {
        x = std::hint::black_box(x.wrapping_mul(31).wrapping_add(i));
    }
    let sample = s.stop();
    let w = Window {
        leg: "floor/sha256_content_12k".into(),
        affinity: AffinityPolicy::Unpinned,
        rep: 0,
        instrumented: true,
        ops: 1,
        wall_ns: 1,
        cpu_user_us: 0,
        cpu_sys_us: 0,
        error: None,
        pmu: sample.clone(),
    };
    validate_window(&w, &d).unwrap_or_else(|e| panic!("{e}: {sample:?}"));
    if let PmuSample::Counted { readings } = &sample {
        assert!(readings
            .iter()
            .any(|r| r.event == "inst_retired" && r.raw_count > 0));
    }
}

// ---------------------------------------------------------------- schema

fn floor_protocol() -> Protocol {
    Protocol {
        schema: PROTOCOL_SCHEMA.into(),
        purpose: "test".into(),
        seed: 7,
        fixture_rev: None,
        reps: 2,
        order: ORDER.into(),
        affinity: vec![AffinityPolicy::Unpinned],
        legs: vec![LegSpec::Floor {
            op: FloorOp::Sha256Content12k,
            iterations: 50,
        }],
        held_out: "nothing tuned".into(),
    }
}

#[test]
fn acceptance1_schema_protocol_refuses_bad_plans() {
    assert!(floor_protocol().validate().is_ok());
    let mut p = floor_protocol();
    p.schema = "synapse-bench/pmu-diag-protocol/v0".into();
    assert!(p.validate().is_err());
    let mut p = floor_protocol();
    p.order = "instrumented-then-control".into();
    assert!(p.validate().is_err());
    let mut p = floor_protocol();
    p.legs.push(p.legs[0].clone());
    assert!(p.validate().unwrap_err().contains("twice"));
    let mut p = floor_protocol();
    p.legs.push(LegSpec::Crumb { samples: 1 });
    assert!(p.validate().unwrap_err().contains("fixture_rev"));
    let mut p = floor_protocol();
    p.reps = 0;
    assert!(p.validate().is_err());
    let json = serde_json::to_string(&floor_protocol()).unwrap();
    let extra = json.replacen('{', "{\"tuned\":true,", 1);
    assert!(
        serde_json::from_str::<Protocol>(&extra).is_err(),
        "unknown fields refused"
    );
    let leg: LegSpec = serde_json::from_str(
        r#"{"kind":"write","arm":"group_commit","agents":8,"ops_per_agent":4}"#,
    )
    .unwrap();
    assert_eq!(leg.id(), "write/group_commit/agents=8");
}

/// Write a protocol and run `pmu-diag` against it with `discovery`.
fn run_in(
    label: &str,
    protocol: &Protocol,
    fixture_repo: Option<PathBuf>,
    discovery: Discovery,
) -> (PathBuf, Report) {
    let root = temp_dir(label);
    let ev = root.join("evidence");
    fs::create_dir_all(&ev).unwrap();
    fs::write(
        ev.join(PROTOCOL_FILE),
        serde_json::to_vec_pretty(protocol).unwrap(),
    )
    .unwrap();
    let cfg = DiagConfig {
        evidence_dir: ev.clone(),
        fixture_repo,
        work_dir: root.join("work"),
        source_rev: "0123abcd".into(),
        siblings: vec![SiblingRev {
            name: "omega".into(),
            rev: "feedface".into(),
        }],
        invocation: vec!["synapse-bench".into(), "pmu-diag".into()],
        discovery,
    };
    let report = run_diag(&cfg).unwrap();
    (ev, report)
}

fn read_raw(ev: &Path) -> Raw {
    serde_json::from_slice(&fs::read(ev.join(RAW_FILE)).unwrap()).unwrap()
}

/// Rewrite `raw.json` with `edit`, then regenerate report and sums so only the
/// semantic checks (not the digests) can catch the change.
fn tamper_consistently(ev: &Path, edit: impl FnOnce(&mut Raw)) -> VerifyError {
    let names = [PROTOCOL_FILE, RAW_FILE, REPORT_FILE, SUMS_FILE];
    let saved: Vec<Vec<u8>> = names
        .iter()
        .map(|n| fs::read(ev.join(n)).unwrap())
        .collect();
    let err = tamper_once(ev, edit);
    for (n, bytes) in names.iter().zip(saved) {
        fs::write(ev.join(n), bytes).unwrap();
    }
    err
}

fn tamper_once(ev: &Path, edit: impl FnOnce(&mut Raw)) -> VerifyError {
    let mut raw = read_raw(ev);
    edit(&mut raw);
    let raw_bytes = serde_json::to_vec_pretty(&raw).unwrap();
    fs::write(ev.join(RAW_FILE), &raw_bytes).unwrap();
    let protocol = fs::read(ev.join(PROTOCOL_FILE)).unwrap();
    match compute_report(&protocol, &raw_bytes) {
        Ok(r) => {
            fs::write(ev.join(REPORT_FILE), serde_json::to_vec_pretty(&r).unwrap()).unwrap();
            let sums = sha256sums(ev, &[PROTOCOL_FILE, RAW_FILE, REPORT_FILE]).unwrap();
            fs::write(ev.join(SUMS_FILE), sums).unwrap();
            verify_evidence(ev).expect_err("tampered evidence verified")
        }
        Err(e) => e,
    }
}

fn counted(class: CoreClass, pmu: &str, state: CounterState, t: [u64; 3]) -> Vec<CounterReading> {
    EVENTS
        .iter()
        .map(|spec| CounterReading {
            event: spec.name.into(),
            arm_event: spec.arm_event,
            pmu: pmu.into(),
            core_class: class,
            raw_count: t[0],
            time_enabled_ns: t[1],
            time_running_ns: t[2],
            state,
        })
        .collect()
}

#[test]
fn acceptance1_verify_refuses_mismatched_pmu_output() {
    let (_root, d) = fake_sysfs("mismatch-disc", &[A725], "2");
    let good = || PmuSample::Counted {
        readings: counted(
            CoreClass::CortexA725,
            "armv8_pmuv3_0",
            CounterState::Counted,
            [9, 5, 5],
        ),
    };
    // The run itself sees no PMU (no real counter is opened from a fake sysfs); the
    // edits below install the fake discovery and synthetic, contract-valid counts.
    let (_e, empty) = fake_sysfs("mismatch-empty", &[], "2");
    let (ev, _) = run_in("mismatch", &floor_protocol(), None, empty);
    let set_counts = |raw: &mut Raw, s: PmuSample| {
        for w in raw.windows.iter_mut().filter(|w| w.instrumented) {
            w.pmu = s.clone();
        }
    };
    // Baseline: synthetic valid counts verify (the control for every refusal below).
    let mut raw = read_raw(&ev);
    raw.discovery = d.clone();
    set_counts(&mut raw, good());
    let bytes = serde_json::to_vec_pretty(&raw).unwrap();
    let protocol = fs::read(ev.join(PROTOCOL_FILE)).unwrap();
    let report = compute_report(&protocol, &bytes).expect("valid counts verify");
    assert_eq!(report.legs[0].pmu.counted_windows, 2);
    assert_eq!(
        report.legs[0].pmu.ratios[0].instructions_per_kilocycle,
        Some(1000)
    );

    type Edit = Box<dyn Fn(&mut Vec<CounterReading>)>;
    let cases: Vec<(&str, Edit)> = vec![
        (
            "unknown pmu",
            Box::new(|r| r[0].pmu = "armv8_pmuv3_9".into()),
        ),
        (
            "wrong class",
            Box::new(|r| r[1].core_class = CoreClass::CortexX925),
        ),
        ("wrong event number", Box::new(|r| r[2].arm_event = 0x22)),
        (
            "state contradicts times",
            Box::new(|r| r[3].state = CounterState::Multiplexed),
        ),
        (
            "running beyond enabled",
            Box::new(|r| r[0].time_running_ns = 6),
        ),
        (
            "missing event",
            Box::new(|r| {
                r.pop();
            }),
        ),
        (
            "duplicate event",
            Box::new(|r| {
                let x = r[0].clone();
                r[1] = x;
            }),
        ),
    ];
    for (label, edit) in cases {
        let mut readings = counted(
            CoreClass::CortexA725,
            "armv8_pmuv3_0",
            CounterState::Counted,
            [9, 5, 5],
        );
        edit(&mut readings);
        let d2 = d.clone();
        let err = tamper_consistently(&ev, move |raw| {
            raw.discovery = d2;
            for w in raw.windows.iter_mut().filter(|w| w.instrumented) {
                w.pmu = PmuSample::Counted {
                    readings: readings.clone(),
                };
            }
        });
        assert!(matches!(err, VerifyError::Mismatch(_)), "{label}: {err}");
    }
    // Window-level contract.
    let err = tamper_consistently(&ev, |raw| raw.windows[0].pmu = good());
    assert!(
        matches!(err, VerifyError::Mismatch(ref m) if m.contains("control")),
        "{err}"
    );
    let err = tamper_consistently(&ev, |raw| {
        let i = raw.windows.iter().position(|w| w.instrumented).unwrap();
        raw.windows[i].pmu = PmuSample::Disabled;
    });
    assert!(matches!(err, VerifyError::Mismatch(_)), "{err}");
    let err = tamper_consistently(&ev, |raw| {
        raw.windows.pop();
    });
    assert!(
        matches!(err, VerifyError::Mismatch(ref m) if m.contains("missing")),
        "{err}"
    );
    let err = tamper_consistently(&ev, move |raw| {
        raw.discovery.devices.clear();
        set_counts(raw, good());
    });
    assert!(
        matches!(err, VerifyError::Mismatch(ref m) if m.contains("no PMU")),
        "{err}"
    );
}

// ---------------------------------------------------------------- acceptance 3

#[test]
fn acceptance3_report_recomputes_from_raw_and_digests_verify() {
    let (_root, d) = fake_sysfs("a3-disc", &[], "4");
    let (ev, report) = run_in("a3", &floor_protocol(), None, d);
    assert_eq!(report.status, "DIAGNOSTIC_ONLY");
    let again = verify_evidence(&ev).expect("fresh evidence verifies");
    assert_eq!(again, report);
    let leg = &report.legs[0];
    assert_eq!((leg.control.windows, leg.instrumented.windows), (2, 2));
    assert_eq!(leg.pmu.unavailable.get("NO_PMU"), Some(&2));
    assert!(
        leg.pmu.events.is_empty(),
        "no counts invented for refused windows"
    );
    assert!(leg.overhead_ppm_p50.is_some());
    assert!(run_diag(&DiagConfig {
        evidence_dir: ev.clone(),
        fixture_repo: None,
        work_dir: ev.join("w"),
        source_rev: String::new(),
        siblings: vec![],
        invocation: vec![],
        discovery: crate::pmu::discover(Path::new("/nonexistent"), Path::new("/nonexistent")),
    })
    .unwrap_err()
    .contains("never overwritten"));

    // Tampering: each sealed file is checked.
    let raw0 = fs::read(ev.join(RAW_FILE)).unwrap();
    let report0 = fs::read(ev.join(REPORT_FILE)).unwrap();
    let protocol0 = fs::read(ev.join(PROTOCOL_FILE)).unwrap();
    let sums0 = fs::read(ev.join(SUMS_FILE)).unwrap();
    let restore = || {
        fs::write(ev.join(RAW_FILE), &raw0).unwrap();
        fs::write(ev.join(REPORT_FILE), &report0).unwrap();
        fs::write(ev.join(PROTOCOL_FILE), &protocol0).unwrap();
        fs::write(ev.join(SUMS_FILE), &sums0).unwrap();
    };
    let mut raw = read_raw(&ev);
    raw.windows[0].wall_ns += 1;
    fs::write(ev.join(RAW_FILE), serde_json::to_vec_pretty(&raw).unwrap()).unwrap();
    assert!(matches!(
        verify_evidence(&ev),
        Err(VerifyError::ReportMismatch { .. })
    ));
    restore();
    let p = String::from_utf8(protocol0.clone())
        .unwrap()
        .replace("\"reps\": 2", "\"reps\": 1");
    fs::write(ev.join(PROTOCOL_FILE), p).unwrap();
    assert!(matches!(
        verify_evidence(&ev),
        Err(VerifyError::ProtocolDigest { .. })
    ));
    restore();
    let r = String::from_utf8(report0.clone())
        .unwrap()
        .replace("DIAGNOSTIC_ONLY", "QUALIFIED");
    fs::write(ev.join(REPORT_FILE), r).unwrap();
    assert!(matches!(
        verify_evidence(&ev),
        Err(VerifyError::ReportMismatch { .. })
    ));
    restore();
    fs::write(ev.join(SUMS_FILE), "").unwrap();
    assert!(matches!(
        verify_evidence(&ev),
        Err(VerifyError::ChecksumsMissing(_))
    ));
    restore();
    let mut raw = read_raw(&ev);
    raw.manifest.source_rev = "edited".into();
    let raw_bytes = serde_json::to_vec_pretty(&raw).unwrap();
    fs::write(ev.join(RAW_FILE), &raw_bytes).unwrap();
    let r = compute_report(&protocol0, &raw_bytes).unwrap();
    fs::write(ev.join(REPORT_FILE), serde_json::to_vec_pretty(&r).unwrap()).unwrap();
    assert!(matches!(
        verify_evidence(&ev),
        Err(VerifyError::ChecksumMismatch(_))
    ));
    restore();
    verify_evidence(&ev).unwrap();
}

// ---------------------------------------------------------------- manifest attribution and legs

const ROOT_CRUMB: &str =
    r#"{"schema_version":"1.0.0","name":"root","purpose":"Root.","invariants":["root rule"]}"#;

#[test]
fn acceptance1_manifest_attribution_and_every_leg_kind_runs() {
    let root = temp_dir("legs-fixture");
    make_fixture_repo(&root, 6, 40);
    let repo = root.join("fixture");
    fs::write(repo.join(".crumb"), ROOT_CRUMB).unwrap();
    git_ok(&repo, &[], &[], &["add", "-A"], None).unwrap();
    git_ok(&repo, &[], &[], &["commit", "-q", "-m", "crumb"], None).unwrap();
    let head = git_line(&repo, &["rev-parse", "HEAD"]).unwrap();
    let protocol = Protocol {
        schema: PROTOCOL_SCHEMA.into(),
        purpose: "test".into(),
        seed: 11,
        fixture_rev: Some("main".into()),
        reps: 1,
        order: ORDER.into(),
        affinity: vec![
            AffinityPolicy::Unpinned,
            AffinityPolicy::Pinned(CoreClass::CortexX925),
        ],
        legs: vec![
            LegSpec::Floor {
                op: FloorOp::EnvelopeValidate,
                iterations: 5,
            },
            LegSpec::Write {
                arm: WriteArm::EveryCommit,
                agents: 2,
                ops_per_agent: 1,
            },
            LegSpec::Write {
                arm: WriteArm::GroupCommit,
                agents: 2,
                ops_per_agent: 1,
            },
            LegSpec::Query {
                populate_agents: 2,
                populate_ops_per_agent: 2,
                samples: 2,
            },
            LegSpec::Crumb { samples: 2 },
        ],
        held_out: "nothing tuned".into(),
    };
    // No PMU in this discovery: pinned legs cannot resolve a core class -> NOT_RUN.
    let (_s, d) = fake_sysfs("legs-disc", &[], "4");
    let (ev, report) = run_in("legs", &protocol, Some(repo.clone()), d);
    let raw = read_raw(&ev);
    let m = &raw.manifest;
    assert_eq!(m.fixture_commit.as_deref(), Some(head.as_str()));
    assert_eq!(
        m.fixture_repo.as_deref(),
        Some(repo.display().to_string().as_str())
    );
    assert_eq!(m.source_rev, "0123abcd");
    assert_eq!(m.siblings[0].name, "omega");
    assert_eq!(m.invocation, vec!["synapse-bench", "pmu-diag"]);
    assert!(!m.host.rustc_version.is_empty() && !m.host.kernel_release.is_empty());
    assert!(m.energy.starts_with("NOT_MEASURED"));
    assert_eq!(raw.discovery.perf_event_paranoid, Some(4));
    assert_eq!(raw.not_run.len(), 5, "{:?}", raw.not_run);
    assert!(raw
        .not_run
        .iter()
        .all(|n| n.affinity == AffinityPolicy::Pinned(CoreClass::CortexX925)));
    assert_eq!(report.legs.len(), 5);
    for leg in &report.legs {
        assert_eq!(leg.control.errors + leg.instrumented.errors, 0, "{leg:?}");
        assert_eq!(leg.affinity, AffinityPolicy::Unpinned);
    }
    let ops = |id: &str| {
        raw.windows
            .iter()
            .find(|w| w.leg == id)
            .map(|w| w.ops)
            .unwrap()
    };
    assert_eq!(ops("floor/envelope_validate"), 5);
    assert_eq!(ops("write/every_commit/agents=2"), 2);
    assert_eq!(ops("write/group_commit/agents=2"), 2);
    assert_eq!(ops("query/read_tree_diff"), 6);
    assert_eq!(ops("crumb/context_advisory"), 4);
    for w in &raw.windows {
        assert_eq!(w.instrumented, w.pmu != PmuSample::Disabled, "{w:?}");
    }
    verify_evidence(&ev).unwrap();
}

#[test]
fn acceptance1_crumb_leg_without_crumb_fixture_is_not_run() {
    let root = temp_dir("nocrumb-fixture");
    make_fixture_repo(&root, 3, 20);
    let mut protocol = floor_protocol();
    protocol.fixture_rev = Some("main".into());
    protocol.reps = 1;
    protocol.legs = vec![LegSpec::Crumb { samples: 1 }];
    let (_s, d) = fake_sysfs("nocrumb-disc", &[], "2");
    let (ev, report) = run_in("nocrumb", &protocol, Some(root.join("fixture")), d);
    assert!(report.legs.is_empty());
    assert!(
        report.not_run[0].reason.contains("no .crumb"),
        "{:?}",
        report.not_run
    );
    verify_evidence(&ev).unwrap();
}
