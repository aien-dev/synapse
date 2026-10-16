//! `synapse-bench pmu-diag`: opt-in CPU PMU diagnostics beside the existing physical-bound
//! benchmarks (issue #64). Diagnostic only: hardware counts are supporting units, never a
//! performance claim and never a qualification result. Seconds per operation stay the
//! measured unit; energy is not measured here (the `run`, `floor` and `bounds` paths keep
//! their SI and joule reporting unchanged).
//!
//! Evidence follows the A0 shape (`docs/A0_HOST_BOUNDS.md`):
//! - `protocol.json` is written (and committed) before the run: legs, repetitions,
//!   affinity policies, seed, fixture revision. Nothing is tuned from these runs; any
//!   later tuning needs its own held-out runs.
//! - `raw.json` holds integers only: per window the wall nanoseconds, getrusage CPU
//!   microseconds, operation count, and the PMU sample exactly as read (or its refusal),
//!   plus the manifest (invocation, host, compiler, kernel, `perf_event_paranoid`,
//!   PMU discovery, fixture commit, source and sibling revisions).
//! - `report.json` is a pure function of the protocol and raw bytes; `pmu-verify`
//!   recomputes it byte for byte, re-validates every PMU reading against the discovery
//!   and the counter contract, and checks `SHA256SUMS`.
//!
//! Each repetition runs a control window (counters never opened) and then an
//! instrumented window on identical input, so instrumentation overhead is measured, not
//! assumed. Timing covers the measured work only: counters are opened before the clock
//! starts and read after it stops.

use crate::fixture::{self, BaseTree, EditableFile};
use crate::host::{collect_host_info, HostInfo};
use crate::pmu::{
    apply_affinity, classify, AffinityPolicy, CoreClass, CounterState, Discovery, LinuxPerf,
    PmuMode, PmuSample, PmuSession, UnavailableReason, EVENTS,
};
use crate::rng::SplitMix64;
use crate::rusage::sample_self;
use crate::stats::nearest_rank;
use crate::synapse_arm::{self, AgentIdentity, BenchIdentities};
use crate::workload::{generate_write_workload, EditOp, Proposal};
use crate::write_phase::synapse_submit;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Instant;
use synapse_api::{
    ChangesetAdvisoryPayload, CrumbContextQueryPayload, DiffQueryPayload, PageRequest,
    PageResponse, SynapseService, TreeQueryPayload, TreeTarget, DEFAULT_MAX_PAGE_SIZE,
};
use synapse_core::{ChangesetId, FileMode, GitOid, WalSeq};
use synapse_store::{FsyncPolicy, IngestOutcome, RecoveryPolicy, SharedStore, StoreLimits};

pub const PROTOCOL_FILE: &str = "protocol.json";
pub const RAW_FILE: &str = "raw.json";
pub const REPORT_FILE: &str = "report.json";
pub const SUMS_FILE: &str = "SHA256SUMS";
pub const PROTOCOL_SCHEMA: &str = "synapse-bench/pmu-diag-protocol/v1";
pub const RAW_SCHEMA: &str = "synapse-bench/pmu-diag-raw/v1";
pub const REPORT_SCHEMA: &str = "synapse-bench/pmu-diag-report/v1";
/// The only window order protocol v1 allows.
pub const ORDER: &str = "control-then-instrumented";

/// CPU-only floor operations (a subset of `floor.rs` CPU probes, same inputs).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FloorOp {
    #[serde(rename = "sha256_content_12k")]
    Sha256Content12k,
    Ed25519Verify,
    EnvelopeValidate,
    JsonDecodeSubmitRequest,
}

/// Store commit path for a write leg.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WriteArm {
    /// `FsyncPolicy::EveryCommit` (the S1 arm).
    EveryCommit,
    /// WAL v2 `FsyncPolicy::GROUP_COMMIT_DEFAULT` through `SharedStore` (the S3 arm).
    GroupCommit,
}

/// One pre-registered leg.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum LegSpec {
    Floor {
        op: FloorOp,
        iterations: u64,
    },
    Write {
        arm: WriteArm,
        agents: usize,
        ops_per_agent: usize,
    },
    /// read_file, tree (all pages) and diff (all pages) against a populated service.
    Query {
        populate_agents: usize,
        populate_ops_per_agent: usize,
        samples: usize,
    },
    /// crumb_context and changeset_advisory (no coordination plane) on the fixture base.
    Crumb {
        samples: usize,
    },
}

impl LegSpec {
    /// Stable identifier used in raw and report rows.
    pub fn id(&self) -> String {
        match self {
            Self::Floor { op, .. } => format!("floor/{}", enum_code(op)),
            Self::Write { arm, agents, .. } => format!("write/{}/agents={agents}", enum_code(arm)),
            Self::Query { .. } => "query/read_tree_diff".into(),
            Self::Crumb { .. } => "crumb/context_advisory".into(),
        }
    }

    fn needs_fixture(&self) -> bool {
        !matches!(self, Self::Floor { .. })
    }

    fn validate(&self) -> Result<(), String> {
        let ok = match self {
            Self::Floor { iterations, .. } => *iterations > 0,
            Self::Write {
                agents,
                ops_per_agent,
                ..
            } => *agents > 0 && *ops_per_agent > 0,
            Self::Query {
                populate_agents,
                populate_ops_per_agent,
                samples,
            } => *populate_agents > 0 && *populate_ops_per_agent > 0 && *samples > 0,
            Self::Crumb { samples } => *samples > 0,
        };
        if ok {
            Ok(())
        } else {
            Err(format!("leg {}: every count must be positive", self.id()))
        }
    }
}

fn enum_code<T: Serialize>(v: &T) -> String {
    serde_json::to_value(v)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_default()
}

/// Pre-registered plan (`protocol.json`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Protocol {
    pub schema: String,
    pub purpose: String,
    pub seed: u64,
    /// Required when any leg needs the fixture (write, query, crumb).
    pub fixture_rev: Option<String>,
    /// Repetitions per (leg, affinity); each is one control plus one instrumented window.
    pub reps: usize,
    pub order: String,
    pub affinity: Vec<AffinityPolicy>,
    pub legs: Vec<LegSpec>,
    /// Statement of what is held out (v1: nothing is tuned from these runs).
    pub held_out: String,
}

impl Protocol {
    pub fn validate(&self) -> Result<(), String> {
        if self.schema != PROTOCOL_SCHEMA {
            return Err(format!(
                "protocol schema {:?}, expected {PROTOCOL_SCHEMA:?}",
                self.schema
            ));
        }
        if self.order != ORDER {
            return Err(format!(
                "protocol order {:?}, expected {ORDER:?}",
                self.order
            ));
        }
        if self.reps == 0 || self.affinity.is_empty() || self.legs.is_empty() {
            return Err("protocol needs reps > 0, at least one affinity and one leg".into());
        }
        let mut ids = std::collections::BTreeSet::new();
        for leg in &self.legs {
            leg.validate()?;
            if !ids.insert(leg.id()) {
                return Err(format!("leg {} listed twice", leg.id()));
            }
        }
        let mut aff = std::collections::BTreeSet::new();
        if !self.affinity.iter().all(|a| aff.insert(*a)) {
            return Err("affinity policy listed twice".into());
        }
        if self.legs.iter().any(LegSpec::needs_fixture)
            && self.fixture_rev.as_deref().is_none_or(str::is_empty)
        {
            return Err("write, query and crumb legs need fixture_rev".into());
        }
        Ok(())
    }
}

/// A named sibling repository revision recorded for attribution (for example the
/// Omega PMU probe contract, issue omega#453).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SiblingRev {
    pub name: String,
    pub rev: String,
}

/// Who ran what, where, with which build.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub invocation: Vec<String>,
    pub started_at: String,
    pub host: HostInfo,
    /// `debug` or `release` (from `cfg!(debug_assertions)`).
    pub build_profile: String,
    pub target_arch: String,
    pub source_rev: String,
    pub fixture_repo: Option<String>,
    /// The fixture revision resolved to a commit.
    pub fixture_commit: Option<String>,
    pub siblings: Vec<SiblingRev>,
    pub clock: String,
    pub energy: String,
}

/// One measured window, as read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Window {
    pub leg: String,
    pub affinity: AffinityPolicy,
    pub rep: usize,
    pub instrumented: bool,
    pub ops: u64,
    pub wall_ns: u64,
    /// getrusage(RUSAGE_SELF) deltas over the window: every thread of this process.
    pub cpu_user_us: u64,
    pub cpu_sys_us: u64,
    pub error: Option<String>,
    pub pmu: PmuSample,
}

/// A (leg, affinity) pair that produced no windows, with the reason.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NotRun {
    pub leg: String,
    pub affinity: AffinityPolicy,
    pub reason: String,
}

/// `raw.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Raw {
    pub schema: String,
    pub protocol_sha256: String,
    pub manifest: Manifest,
    pub discovery: Discovery,
    pub windows: Vec<Window>,
    pub not_run: Vec<NotRun>,
}

/// Nearest-rank distribution of integer samples.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Dist {
    pub n: usize,
    pub min: u64,
    pub p50: u64,
    pub max: u64,
}

fn dist(values: &[u64]) -> Option<Dist> {
    let mut v = values.to_vec();
    v.sort_unstable();
    Some(Dist {
        n: v.len(),
        min: *v.first()?,
        p50: nearest_rank(&v, 0.5)?,
        max: *v.last()?,
    })
}

/// Timing over the successful windows of one side (control or instrumented).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimingSummary {
    pub windows: usize,
    pub errors: usize,
    pub wall_ns: Option<Dist>,
    /// `wall_ns / ops` per window (integer division).
    pub wall_ns_per_op: Option<Dist>,
    /// User plus system CPU microseconds per window (all threads).
    pub cpu_us: Option<Dist>,
}

/// Raw counts of one event on one core class over the windows that counted it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventSummary {
    pub core_class: CoreClass,
    pub event: String,
    /// Raw count per window (never scaled).
    pub raw_count: Dist,
    pub raw_count_per_op: Dist,
}

/// Ratios from counts summed over windows on one core class (same event group, so the
/// four counters share enable/run time). Integers: per mille.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClassRatios {
    pub core_class: CoreClass,
    pub windows: usize,
    /// `sum(INST_RETIRED) * 1000 / sum(CPU_CYCLES)`.
    pub instructions_per_kilocycle: Option<u64>,
    /// `sum(BR_MIS_PRED) * 1000 / sum(BR_PRED)`.
    pub mispredicts_per_kilo_predicted_branches: Option<u64>,
}

/// PMU outcome over the instrumented windows.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PmuSummary {
    pub windows: usize,
    pub counted_windows: usize,
    /// `INSTRUMENT_UNAVAILABLE` windows by reason code.
    pub unavailable: BTreeMap<String, usize>,
    /// Counter reads by state (`COUNTED`, `MULTIPLEXED`, ...).
    pub states: BTreeMap<String, usize>,
    pub events: Vec<EventSummary>,
    pub ratios: Vec<ClassRatios>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LegReport {
    pub leg: String,
    pub affinity: AffinityPolicy,
    pub control: TimingSummary,
    pub instrumented: TimingSummary,
    /// `(instrumented p50 - control p50) * 1e6 / control p50` of wall_ns, parts per million.
    pub overhead_ppm_p50: Option<i64>,
    pub pmu: PmuSummary,
}

/// `report.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Report {
    pub schema: String,
    pub status: String,
    pub protocol_sha256: String,
    pub raw_sha256: String,
    pub legs: Vec<LegReport>,
    pub not_run: Vec<NotRun>,
    pub notes: Vec<String>,
}

/// Why sealed evidence was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyError {
    Io(String),
    Parse(String),
    Protocol(String),
    ProtocolDigest {
        raw_says: String,
        actual: String,
    },
    /// A window or reading contradicts the protocol, the discovery, or the counter contract.
    Mismatch(String),
    ReportMismatch {
        first_difference_at: usize,
    },
    ChecksumsMissing(String),
    ChecksumMismatch(String),
}

impl std::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(m) => write!(f, "io: {m}"),
            Self::Parse(m) => write!(f, "parse: {m}"),
            Self::Protocol(m) => write!(f, "protocol: {m}"),
            Self::ProtocolDigest { raw_says, actual } => write!(
                f,
                "raw.json names protocol {raw_says}, protocol.json is {actual}"
            ),
            Self::Mismatch(m) => write!(f, "mismatch: {m}"),
            Self::ReportMismatch {
                first_difference_at,
            } => write!(
                f,
                "report.json differs from the recomputed report at byte {first_difference_at}"
            ),
            Self::ChecksumsMissing(m) => write!(f, "checksums missing: {m}"),
            Self::ChecksumMismatch(m) => write!(f, "checksum mismatch: {m}"),
        }
    }
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn parse<T: DeserializeOwned>(bytes: &[u8], what: &str) -> Result<T, VerifyError> {
    serde_json::from_slice(bytes).map_err(|e| VerifyError::Parse(format!("{what}: {e}")))
}

/// Check every window and reading in `raw` against `protocol`, the recorded discovery,
/// and the counter contract. Refuses, never repairs.
pub fn validate_raw(protocol: &Protocol, raw: &Raw) -> Result<(), VerifyError> {
    let mm = |m: String| Err(VerifyError::Mismatch(m));
    if raw.schema != RAW_SCHEMA {
        return mm(format!(
            "raw schema {:?}, expected {RAW_SCHEMA:?}",
            raw.schema
        ));
    }
    let legs: Vec<String> = protocol.legs.iter().map(LegSpec::id).collect();
    for n in &raw.not_run {
        if !legs.contains(&n.leg) || !protocol.affinity.contains(&n.affinity) {
            return mm(format!(
                "not_run names unknown leg {} / {:?}",
                n.leg, n.affinity
            ));
        }
    }
    // Exactly one control and one instrumented window per (leg, affinity, rep), unless
    // that (leg, affinity) is listed in not_run, in which case none.
    let mut seen = std::collections::BTreeSet::new();
    for w in &raw.windows {
        let key = (w.leg.clone(), w.affinity, w.rep, w.instrumented);
        if !legs.contains(&w.leg) || !protocol.affinity.contains(&w.affinity) {
            return mm(format!(
                "window for unknown leg {} / {:?}",
                w.leg, w.affinity
            ));
        }
        if w.rep >= protocol.reps {
            return mm(format!("{} rep {} beyond protocol reps", w.leg, w.rep));
        }
        if !seen.insert(key) {
            return mm(format!("duplicate window {} rep {}", w.leg, w.rep));
        }
        validate_window(w, &raw.discovery)?;
    }
    for leg in &legs {
        for aff in &protocol.affinity {
            let skipped = raw
                .not_run
                .iter()
                .any(|n| &n.leg == leg && n.affinity == *aff);
            for rep in 0..protocol.reps {
                for instrumented in [false, true] {
                    let present = seen.contains(&(leg.clone(), *aff, rep, instrumented));
                    if present == skipped {
                        return mm(format!(
                            "{leg} {aff:?} rep {rep} instrumented={instrumented}: {}",
                            if skipped {
                                "window present for a not_run leg"
                            } else {
                                "window missing"
                            }
                        ));
                    }
                }
            }
        }
    }
    Ok(())
}

fn validate_window(w: &Window, discovery: &Discovery) -> Result<(), VerifyError> {
    let at = format!("{} {:?} rep {}", w.leg, w.affinity, w.rep);
    let mm = |m: String| Err(VerifyError::Mismatch(format!("{at}: {m}")));
    match (&w.pmu, w.instrumented) {
        (PmuSample::Disabled, false) => return Ok(()),
        (PmuSample::Disabled, true) => return mm("instrumented window has no PMU sample".into()),
        (_, false) => return mm("control window carries a PMU sample".into()),
        (PmuSample::InstrumentUnavailable { .. }, true) => return Ok(()),
        (PmuSample::Counted { .. }, true) => {}
    }
    let PmuSample::Counted { readings } = &w.pmu else {
        unreachable!()
    };
    if discovery.devices.is_empty() {
        return mm("counts present but discovery found no PMU".into());
    }
    let mut expected = std::collections::BTreeSet::new();
    for d in &discovery.devices {
        for spec in EVENTS {
            expected.insert((d.name.clone(), spec.name.to_string()));
        }
    }
    let mut got = std::collections::BTreeSet::new();
    for r in readings {
        let Some(dev) = discovery.devices.iter().find(|d| d.name == r.pmu) else {
            return mm(format!("reading names PMU {} absent from discovery", r.pmu));
        };
        if dev.core_class != r.core_class {
            return mm(format!(
                "{} {}: core class {:?}, discovery says {:?}",
                r.pmu, r.event, r.core_class, dev.core_class
            ));
        }
        let Some(spec) = EVENTS.iter().find(|s| s.name == r.event) else {
            return mm(format!("unknown event {}", r.event));
        };
        if spec.arm_event != r.arm_event {
            return mm(format!(
                "{} event {:#06x}, architected number is {:#06x}",
                r.event, r.arm_event, spec.arm_event
            ));
        }
        if !dev
            .events
            .iter()
            .any(|e| e.name == r.event && e.verified && e.arm_event == r.arm_event)
        {
            return mm(format!("{} {} not verified by discovery", r.pmu, r.event));
        }
        let pinned = w.affinity == AffinityPolicy::Pinned(dev.core_class)
            && dev.core_class != CoreClass::Unknown;
        match classify(r.raw_count, r.time_enabled_ns, r.time_running_ns, pinned) {
            Ok(state) if state == r.state => {}
            Ok(state) => {
                return mm(format!(
                    "{} {}: state {:?} but times say {:?}",
                    r.pmu, r.event, r.state, state
                ))
            }
            Err(e) => return mm(format!("{} {}: {e}", r.pmu, r.event)),
        }
        if !got.insert((r.pmu.clone(), r.event.clone())) {
            return mm(format!("{} {} read twice", r.pmu, r.event));
        }
    }
    if got != expected {
        return mm("readings do not cover every discovered PMU and event exactly once".into());
    }
    Ok(())
}

fn timing(windows: &[&Window]) -> TimingSummary {
    let ok: Vec<&&Window> = windows.iter().filter(|w| w.error.is_none()).collect();
    let wall: Vec<u64> = ok.iter().map(|w| w.wall_ns).collect();
    let per_op: Vec<u64> = ok
        .iter()
        .filter(|w| w.ops > 0)
        .map(|w| w.wall_ns / w.ops)
        .collect();
    let cpu: Vec<u64> = ok.iter().map(|w| w.cpu_user_us + w.cpu_sys_us).collect();
    TimingSummary {
        windows: windows.len(),
        errors: windows.len() - ok.len(),
        wall_ns: dist(&wall),
        wall_ns_per_op: dist(&per_op),
        cpu_us: dist(&cpu),
    }
}

fn state_code(s: CounterState) -> String {
    enum_code(&s)
}

fn pmu_summary(windows: &[&Window], classes: &[CoreClass]) -> PmuSummary {
    let mut s = PmuSummary {
        windows: windows.len(),
        counted_windows: 0,
        unavailable: BTreeMap::new(),
        states: BTreeMap::new(),
        events: Vec::new(),
        ratios: Vec::new(),
    };
    let mut per: BTreeMap<(CoreClass, String), (Vec<u64>, Vec<u64>)> = BTreeMap::new();
    let mut sums: BTreeMap<CoreClass, (BTreeMap<String, u128>, usize)> = BTreeMap::new();
    for w in windows {
        match &w.pmu {
            PmuSample::InstrumentUnavailable { reason, .. } => {
                *s.unavailable.entry(enum_code(reason)).or_default() += 1;
            }
            PmuSample::Counted { readings } if w.error.is_none() => {
                s.counted_windows += 1;
                let mut classes_here = std::collections::BTreeSet::new();
                for r in readings {
                    *s.states.entry(state_code(r.state)).or_default() += 1;
                    if r.state == CounterState::NotScheduled {
                        continue;
                    }
                    let e = per.entry((r.core_class, r.event.clone())).or_default();
                    e.0.push(r.raw_count);
                    e.1.push(r.raw_count / w.ops.max(1));
                    let c = sums.entry(r.core_class).or_default();
                    *c.0.entry(r.event.clone()).or_default() += u128::from(r.raw_count);
                    classes_here.insert(r.core_class);
                }
                for c in classes_here {
                    sums.entry(c).or_default().1 += 1;
                }
            }
            _ => {}
        }
    }
    for class in classes {
        for spec in EVENTS {
            if let Some((counts, per_op)) = per.get(&(*class, spec.name.to_string())) {
                if let (Some(raw_count), Some(raw_count_per_op)) = (dist(counts), dist(per_op)) {
                    s.events.push(EventSummary {
                        core_class: *class,
                        event: spec.name.into(),
                        raw_count,
                        raw_count_per_op,
                    });
                }
            }
        }
        if let Some((m, n)) = sums.get(class) {
            let ratio = |num: &str, den: &str| {
                let (a, b) = (m.get(num).copied()?, m.get(den).copied()?);
                (b > 0).then(|| (a * 1000 / b) as u64)
            };
            s.ratios.push(ClassRatios {
                core_class: *class,
                windows: *n,
                instructions_per_kilocycle: ratio("inst_retired", "cpu_cycles"),
                mispredicts_per_kilo_predicted_branches: ratio("br_mis_pred", "br_pred"),
            });
        }
    }
    s
}

/// Pure function of the protocol and raw bytes; `pmu-verify` requires `report.json` to
/// equal its pretty JSON byte for byte.
pub fn compute_report(protocol_bytes: &[u8], raw_bytes: &[u8]) -> Result<Report, VerifyError> {
    let protocol: Protocol = parse(protocol_bytes, PROTOCOL_FILE)?;
    protocol.validate().map_err(VerifyError::Protocol)?;
    let raw: Raw = parse(raw_bytes, RAW_FILE)?;
    let actual = sha256_hex(protocol_bytes);
    if raw.protocol_sha256 != actual {
        return Err(VerifyError::ProtocolDigest {
            raw_says: raw.protocol_sha256,
            actual,
        });
    }
    validate_raw(&protocol, &raw)?;
    let mut classes: Vec<CoreClass> = raw.discovery.devices.iter().map(|d| d.core_class).collect();
    classes.sort();
    classes.dedup();
    let mut legs = Vec::new();
    for leg in &protocol.legs {
        let id = leg.id();
        for aff in &protocol.affinity {
            if raw
                .not_run
                .iter()
                .any(|n| n.leg == id && n.affinity == *aff)
            {
                continue;
            }
            let side = |instr: bool| -> Vec<&Window> {
                raw.windows
                    .iter()
                    .filter(|w| w.leg == id && w.affinity == *aff && w.instrumented == instr)
                    .collect()
            };
            let (control, instrumented) = (side(false), side(true));
            let (c, i) = (timing(&control), timing(&instrumented));
            let overhead_ppm_p50 = match (&c.wall_ns, &i.wall_ns) {
                (Some(c), Some(i)) if c.p50 > 0 => Some(
                    ((i128::from(i.p50) - i128::from(c.p50)) * 1_000_000 / i128::from(c.p50))
                        as i64,
                ),
                _ => None,
            };
            legs.push(LegReport {
                leg: id.clone(),
                affinity: *aff,
                pmu: pmu_summary(&instrumented, &classes),
                control: c,
                instrumented: i,
                overhead_ppm_p50,
            });
        }
    }
    Ok(Report {
        schema: REPORT_SCHEMA.into(),
        status: "DIAGNOSTIC_ONLY".into(),
        protocol_sha256: actual,
        raw_sha256: sha256_hex(raw_bytes),
        legs,
        not_run: raw.not_run.clone(),
        notes: vec![
            "Hardware counts are supporting diagnostics, not performance claims and not qualification. Seconds per operation are the measured unit.".into(),
            "Counts are user-space only (exclude_kernel, exclude_hv) and never scaled by time_enabled/time_running; a task blocked in fdatasync is off CPU and counts nothing.".into(),
            "INSTRUMENT_UNAVAILABLE windows carry no counts. Energy is not measured by pmu-diag.".into(),
        ],
    })
}

/// `SHA256SUMS` text over `names` in `dir` (sha256sum format).
pub fn sha256sums(dir: &Path, names: &[&str]) -> Result<String, String> {
    let mut out = String::new();
    for name in names {
        let bytes = fs::read(dir.join(name)).map_err(|e| format!("read {name}: {e}"))?;
        out.push_str(&format!("{}  {name}\n", sha256_hex(&bytes)));
    }
    Ok(out)
}

fn verify_sums(dir: &Path) -> Result<(), VerifyError> {
    let text = fs::read_to_string(dir.join(SUMS_FILE))
        .map_err(|e| VerifyError::ChecksumsMissing(format!("read {SUMS_FILE}: {e}")))?;
    let mut listed = Vec::new();
    for (i, line) in text.lines().enumerate() {
        let (digest, name) = line
            .split_once("  ")
            .filter(|(d, n)| d.len() == 64 && !n.is_empty())
            .ok_or_else(|| VerifyError::Parse(format!("{SUMS_FILE} line {}: {line:?}", i + 1)))?;
        let bytes = fs::read(dir.join(name)).map_err(|e| {
            VerifyError::ChecksumMismatch(format!("{name} listed but unreadable: {e}"))
        })?;
        let actual = sha256_hex(&bytes);
        if actual != digest {
            return Err(VerifyError::ChecksumMismatch(format!(
                "{name} is {actual}, {SUMS_FILE} lists {digest}"
            )));
        }
        listed.push(name.to_string());
    }
    let missing: Vec<&str> = [PROTOCOL_FILE, RAW_FILE, REPORT_FILE]
        .into_iter()
        .filter(|n| !listed.iter().any(|l| l == n))
        .collect();
    if missing.is_empty() {
        Ok(())
    } else {
        Err(VerifyError::ChecksumsMissing(format!(
            "{SUMS_FILE} does not list {}",
            missing.join(", ")
        )))
    }
}

/// Recompute `report.json` from `protocol.json` and `raw.json`, require a byte-for-byte
/// match, then check `SHA256SUMS`. Consistency only: authenticity comes from git history.
pub fn verify_evidence(dir: &Path) -> Result<Report, VerifyError> {
    let read =
        |name: &str| fs::read(dir.join(name)).map_err(|e| VerifyError::Io(format!("{name}: {e}")));
    let (protocol, raw, sealed) = (read(PROTOCOL_FILE)?, read(RAW_FILE)?, read(REPORT_FILE)?);
    let report = compute_report(&protocol, &raw)?;
    let again = serde_json::to_vec_pretty(&report)
        .map_err(|e| VerifyError::Parse(format!("serialize report: {e}")))?;
    if again != sealed {
        let first_difference_at = again
            .iter()
            .zip(&sealed)
            .position(|(a, b)| a != b)
            .unwrap_or(again.len().min(sealed.len()));
        return Err(VerifyError::ReportMismatch {
            first_difference_at,
        });
    }
    verify_sums(dir)?;
    Ok(report)
}

/// Host-side inputs for one `pmu-diag` run.
#[derive(Debug, Clone)]
pub struct DiagConfig {
    /// Holds `protocol.json`; `raw.json`, `report.json` and `SHA256SUMS` are written here.
    pub evidence_dir: PathBuf,
    pub fixture_repo: Option<PathBuf>,
    /// Scratch directory on the store filesystem (removed per window).
    pub work_dir: PathBuf,
    pub source_rev: String,
    pub siblings: Vec<SiblingRev>,
    pub invocation: Vec<String>,
    pub discovery: Discovery,
}

/// What a measured closure did.
struct Work {
    ops: u64,
    error: Option<String>,
}

/// Run one window: open counters (instrumented only), start the clock and the rusage
/// window, enable, run `work`, stop the clock, read the counters.
fn measure(
    discovery: &Discovery,
    affinity: AffinityPolicy,
    instrumented: bool,
    work: impl FnOnce() -> Work,
) -> (Work, u64, u64, u64, PmuSample) {
    let mode = if instrumented {
        PmuMode::Enabled
    } else {
        PmuMode::Disabled
    };
    let mut session = PmuSession::open(LinuxPerf, mode, discovery, affinity);
    let ru0 = sample_self().unwrap_or_default();
    session.start();
    let t = Instant::now();
    let done = work();
    let wall_ns = t.elapsed().as_nanos() as u64;
    let sample = session.stop();
    let ru1 = sample_self().unwrap_or_default();
    (
        done,
        wall_ns,
        ru1.user_us.saturating_sub(ru0.user_us),
        ru1.sys_us.saturating_sub(ru0.sys_us),
        sample,
    )
}

/// Loaded fixture shared by the write, query and crumb legs.
struct FixtureData {
    base: BaseTree,
    full: Vec<(String, FileMode, Vec<u8>)>,
    files: Vec<EditableFile>,
}

/// One Synapse service plus the identities that sign its requests.
struct Svc {
    svc: SynapseService,
    ids: BenchIdentities,
    base_oid: GitOid,
    counter: u64,
}

impl Svc {
    fn open(
        dir: &Path,
        seed: u64,
        agents: usize,
        fsync: FsyncPolicy,
        fx: &FixtureData,
    ) -> Result<Self, String> {
        let ids = synapse_arm::issue_identities(seed, agents, crate::unix_now_ms())?;
        let mut svc =
            synapse_arm::open_service(dir, &ids, fsync, RecoveryPolicy::StrictFailClosed)?;
        let base_oid = synapse_arm::register_base(&mut svc, &fx.base.commit_hex, fx.full.clone())?;
        Ok(Self {
            svc,
            ids,
            base_oid,
            counter: 0,
        })
    }

    /// Signed read request, JSON round trip both ways (as `query.rs` does).
    fn call<P, R>(
        &mut self,
        payload: P,
        api: impl FnOnce(
            &mut SynapseService,
            &synapse_auth::AuthenticatedRequest<P>,
            u64,
        ) -> synapse_core::SynapseResult<R>,
    ) -> Result<R, String>
    where
        P: Serialize + DeserializeOwned,
        R: Serialize + DeserializeOwned,
    {
        let resp = self.call_local(payload, api)?;
        Ok(synapse_arm::wire_roundtrip(&resp)?.0)
    }

    /// As [`Svc::call`] for responses without a JSON form (`CrumbContext`,
    /// `ChangesetAdvisory`): the request is signed and round-tripped, the response is not.
    fn call_local<P, R>(
        &mut self,
        payload: P,
        api: impl FnOnce(
            &mut SynapseService,
            &synapse_auth::AuthenticatedRequest<P>,
            u64,
        ) -> synapse_core::SynapseResult<R>,
    ) -> Result<R, String>
    where
        P: Serialize + DeserializeOwned,
    {
        self.counter += 1;
        let now = crate::unix_now_ms();
        let label = format!("pmu-diag/read/{}", self.counter);
        let req = synapse_arm::build_read_request(
            &self.ids.agents[0],
            &self.ids.repo_id,
            payload,
            &label,
            now,
        )?;
        let (decoded, _) = synapse_arm::wire_roundtrip(&req)?;
        api(&mut self.svc, &decoded, now).map_err(|e| e.to_string())
    }

    fn all_pages<T, P>(
        &mut self,
        make: impl Fn(PageRequest) -> P,
        api: fn(
            &mut SynapseService,
            &synapse_auth::AuthenticatedRequest<P>,
            u64,
        ) -> synapse_core::SynapseResult<PageResponse<T>>,
    ) -> Result<usize, String>
    where
        P: Serialize + DeserializeOwned,
        T: Serialize + DeserializeOwned,
    {
        let (mut cursor, mut snapshot): (Option<String>, Option<WalSeq>) = (None, None);
        let mut items = 0;
        loop {
            let page = PageRequest {
                cursor: cursor.clone(),
                limit: DEFAULT_MAX_PAGE_SIZE,
                min_visible_seq: None,
                snapshot_seq: snapshot,
            };
            let r = self.call(make(page), api)?;
            items += r.items.len();
            snapshot = Some(r.snapshot_seq);
            match r.next_cursor {
                Some(next) => cursor = Some(next),
                None => return Ok(items),
            }
        }
    }
}

fn floor_window(op: FloorOp, iterations: u64) -> impl FnOnce() -> Work {
    use ed25519_dalek::{Signer, SigningKey, Verifier};
    let req = crate::floor::typical_request();
    let wire = serde_json::to_vec(&req).unwrap_or_default();
    let content = vec![0x42u8; crate::floor::TYPICAL_CONTENT_BYTES];
    let key = SigningKey::from_bytes(&[5u8; 32]);
    let msg = vec![0x10u8; 256];
    let sig = key.sign(&msg);
    let vk = key.verifying_key();
    move || {
        for _ in 0..iterations {
            match op {
                FloorOp::Sha256Content12k => {
                    std::hint::black_box(Sha256::digest(std::hint::black_box(&content)));
                }
                FloorOp::Ed25519Verify => {
                    std::hint::black_box(vk.verify(std::hint::black_box(&msg), &sig).is_ok());
                }
                FloorOp::EnvelopeValidate => {
                    std::hint::black_box(req.payload.envelope.validate().ok());
                }
                FloorOp::JsonDecodeSubmitRequest => {
                    let r: Option<
                        synapse_auth::AuthenticatedRequest<synapse_api::SubmitChangesetPayload>,
                    > = serde_json::from_slice(std::hint::black_box(&wire)).ok();
                    std::hint::black_box(r);
                }
            }
        }
        Work {
            ops: iterations,
            error: None,
        }
    }
}

/// Prepared service and workload for one write window (setup is outside the clock).
struct WriteSetup {
    service: Mutex<SynapseService>,
    group: Option<SharedStore>,
    agents: Vec<AgentIdentity>,
    repo_id: synapse_core::RepoId,
    base_oid: GitOid,
    workload: Vec<Vec<Proposal>>,
}

fn write_setup(
    dir: &Path,
    seed: u64,
    rep: usize,
    arm: WriteArm,
    agents: usize,
    ops_per_agent: usize,
    fx: &FixtureData,
) -> Result<WriteSetup, String> {
    let store_dir = dir.join("synapse-store");
    let (svc_dir, svc_fsync) = match arm {
        WriteArm::EveryCommit => (store_dir.clone(), FsyncPolicy::EveryCommit),
        // As the S3 arm: the service does admission and indexing; the measured store is
        // the group-commit SharedStore.
        WriteArm::GroupCommit => (dir.join("service-admission"), FsyncPolicy::EveryCommit),
    };
    let s = Svc::open(&svc_dir, seed, agents, svc_fsync, fx)?;
    let group = match arm {
        WriteArm::EveryCommit => None,
        WriteArm::GroupCommit => Some(
            SharedStore::open(
                &store_dir,
                FsyncPolicy::GROUP_COMMIT_DEFAULT,
                RecoveryPolicy::StrictFailClosed,
                StoreLimits::default(),
            )
            .map_err(|e| e.to_string())?,
        ),
    };
    Ok(WriteSetup {
        workload: generate_write_workload(seed, rep, agents, ops_per_agent, &fx.files),
        service: Mutex::new(s.svc),
        group,
        agents: s.ids.agents.clone(),
        repo_id: s.ids.repo_id.clone(),
        base_oid: s.base_oid,
    })
}

fn write_window<'a>(setup: &'a WriteSetup, label: &'a str) -> impl FnOnce() -> Work + 'a {
    move || {
        let results: Vec<Result<u64, String>> = std::thread::scope(|scope| {
            let handles: Vec<_> = setup
                .workload
                .iter()
                .enumerate()
                .map(|(a, props)| {
                    scope.spawn(move || {
                        for p in props {
                            synapse_submit(
                                &setup.service,
                                setup.group.as_ref(),
                                &setup.agents[a],
                                &setup.repo_id,
                                setup.base_oid,
                                p,
                                &format!("{label}/a{a}/p{}", p.index),
                            )?;
                        }
                        Ok(props.len() as u64)
                    })
                })
                .collect();
            handles
                .into_iter()
                .map(|h| {
                    h.join()
                        .unwrap_or_else(|_| Err("agent thread panicked".into()))
                })
                .collect()
        });
        let mut ops = 0;
        let mut error = None;
        for r in results {
            match r {
                Ok(n) => ops += n,
                Err(e) => error = error.or(Some(e)),
            }
        }
        Work { ops, error }
    }
}

/// Populated query target: changesets and readable paths, chosen deterministically.
struct QueryPlan {
    reads: Vec<(ChangesetId, String)>,
    trees: Vec<ChangesetId>,
    diffs: Vec<ChangesetId>,
}

fn query_prepare(
    dir: &Path,
    seed: u64,
    leg: &LegSpec,
    fx: &FixtureData,
) -> Result<(Svc, QueryPlan), String> {
    let LegSpec::Query {
        populate_agents,
        populate_ops_per_agent,
        samples,
    } = *leg
    else {
        return Err("not a query leg".into());
    };
    let mut s = Svc::open(
        dir,
        seed,
        populate_agents,
        FsyncPolicy::BatchWindow { max_records: 1024 },
        fx,
    )?;
    let workload = generate_write_workload(
        seed,
        20_000,
        populate_agents,
        populate_ops_per_agent,
        &fx.files,
    );
    let mut readable = Vec::new();
    let mut changesets = Vec::new();
    for (a, props) in workload.iter().enumerate() {
        for p in props {
            let now = crate::unix_now_ms();
            let req = synapse_arm::build_submit_request(
                &s.ids.agents[a],
                &s.ids.repo_id,
                s.base_oid,
                p,
                &format!("pmu-diag/query-pop/a{a}/p{}", p.index),
                now,
            )?;
            let (decoded, _) = synapse_arm::wire_roundtrip(&req)?;
            let cs = match s.svc.submit(&decoded, now).map_err(|e| e.to_string())? {
                IngestOutcome::Committed { changeset_id, .. }
                | IngestOutcome::IdempotentDuplicate { changeset_id, .. } => changeset_id,
            };
            changesets.push(cs);
            for e in &p.edits {
                if let EditOp::Upsert { .. } = e.op {
                    readable.push((cs, e.path.clone()));
                }
            }
        }
    }
    s.svc.store_mut().sync_wal().map_err(|e| e.to_string())?;
    if readable.is_empty() || changesets.is_empty() {
        return Err("query population has no upserted files".into());
    }
    let mut rng = SplitMix64::derive(seed, &[0x0E_E7, 64]);
    let plan = QueryPlan {
        reads: (0..samples)
            .map(|_| readable[rng.below(readable.len())].clone())
            .collect(),
        trees: (0..samples)
            .map(|_| changesets[rng.below(changesets.len())])
            .collect(),
        diffs: (0..samples)
            .map(|_| changesets[rng.below(changesets.len())])
            .collect(),
    };
    Ok((s, plan))
}

fn query_window<'a>(s: &'a mut Svc, plan: &'a QueryPlan) -> impl FnOnce() -> Work + 'a {
    move || {
        let mut ops = 0;
        let base = TreeTarget::BaseGitCommit(s.base_oid);
        let run = |s: &mut Svc, ops: &mut u64| -> Result<(), String> {
            for (cs, path) in &plan.reads {
                s.call(
                    (TreeTarget::Changeset(*cs), path.clone(), None::<WalSeq>),
                    |svc, req, now| svc.read_file(req, now),
                )?;
                *ops += 1;
            }
            for cs in &plan.trees {
                let target = TreeTarget::Changeset(*cs);
                s.all_pages(
                    |page| TreeQueryPayload {
                        target,
                        path_prefix: None,
                        page,
                    },
                    SynapseService::tree,
                )?;
                *ops += 1;
            }
            for cs in &plan.diffs {
                let target = TreeTarget::Changeset(*cs);
                s.all_pages(
                    |page| DiffQueryPayload { base, target, page },
                    SynapseService::diff,
                )?;
                *ops += 1;
            }
            Ok(())
        };
        let error = run(s, &mut ops).err();
        Work { ops, error }
    }
}

/// Paths for crumb queries, or `None` when the fixture base has no `.crumb` file.
fn crumb_paths(fx: &FixtureData, seed: u64, samples: usize) -> Option<Vec<String>> {
    if !fx
        .base
        .entries
        .iter()
        .any(|e| e.path == ".crumb" || e.path.ends_with("/.crumb"))
    {
        return None;
    }
    let paths: Vec<&str> = fx.base.entries.iter().map(|e| e.path.as_str()).collect();
    let mut rng = SplitMix64::derive(seed, &[0xC2_0B, 64]);
    Some(
        (0..samples)
            .map(|_| paths[rng.below(paths.len())].to_string())
            .collect(),
    )
}

fn crumb_window<'a>(s: &'a mut Svc, paths: &'a [String]) -> impl FnOnce() -> Work + 'a {
    move || {
        let base = TreeTarget::BaseGitCommit(s.base_oid);
        let mut ops = 0;
        let mut run = || -> Result<(), String> {
            for p in paths {
                s.call_local(
                    CrumbContextQueryPayload {
                        target: base,
                        path: p.clone(),
                        snapshot_seq: None,
                    },
                    |svc, req, now| svc.crumb_context(req, now),
                )?;
                ops += 1;
                s.call_local(
                    ChangesetAdvisoryPayload {
                        base,
                        latest: None,
                        paths: vec![p.clone()],
                        agent: "pmu-diag".into(),
                        snapshot_seq: None,
                    },
                    |svc, req, now| svc.changeset_advisory(req, None, now),
                )?;
                ops += 1;
            }
            Ok(())
        };
        let error = run().err();
        Work { ops, error }
    }
}

fn record(
    windows: &mut Vec<Window>,
    leg: &str,
    affinity: AffinityPolicy,
    rep: usize,
    instrumented: bool,
    m: (Work, u64, u64, u64, PmuSample),
) {
    let (work, wall_ns, cpu_user_us, cpu_sys_us, pmu) = m;
    windows.push(Window {
        leg: leg.into(),
        affinity,
        rep,
        instrumented,
        ops: work.ops,
        wall_ns,
        cpu_user_us,
        cpu_sys_us,
        error: work.error,
        pmu,
    });
}

/// Run every leg of `protocol.json` in `cfg.evidence_dir`; write raw, report, sums.
/// Refuses to overwrite an existing `raw.json`.
pub fn run_diag(cfg: &DiagConfig) -> Result<Report, String> {
    let protocol_bytes = fs::read(cfg.evidence_dir.join(PROTOCOL_FILE))
        .map_err(|e| format!("read {PROTOCOL_FILE}: {e}"))?;
    let protocol: Protocol =
        serde_json::from_slice(&protocol_bytes).map_err(|e| format!("{PROTOCOL_FILE}: {e}"))?;
    protocol.validate()?;
    let raw_path = cfg.evidence_dir.join(RAW_FILE);
    if raw_path.exists() {
        return Err(format!(
            "{} exists; evidence is never overwritten",
            raw_path.display()
        ));
    }
    fs::create_dir_all(&cfg.work_dir).map_err(|e| format!("mkdir work dir: {e}"))?;
    let needs_fixture = protocol.legs.iter().any(LegSpec::needs_fixture);
    let fx = if needs_fixture {
        let repo = cfg
            .fixture_repo
            .as_deref()
            .ok_or("write, query and crumb legs need --fixture-repo")?;
        let rev = protocol.fixture_rev.as_deref().unwrap_or_default();
        let base = fixture::list_base_tree(repo, rev)?;
        let full = fixture::load_full_base(repo, &base)?;
        let files = fixture::editable_from_full_base(&base, &full);
        Some(FixtureData { base, full, files })
    } else {
        None
    };
    let manifest = Manifest {
        invocation: cfg.invocation.clone(),
        started_at: crate::utc_timestamp(),
        host: collect_host_info(&cfg.work_dir),
        build_profile: if cfg!(debug_assertions) {
            "debug"
        } else {
            "release"
        }
        .into(),
        target_arch: std::env::consts::ARCH.into(),
        source_rev: cfg.source_rev.clone(),
        fixture_repo: cfg.fixture_repo.as_ref().map(|p| p.display().to_string()),
        fixture_commit: fx.as_ref().map(|f| f.base.commit_hex.clone()),
        siblings: cfg.siblings.clone(),
        clock: "std::time::Instant (CLOCK_MONOTONIC), wall nanoseconds per window".into(),
        energy: "NOT_MEASURED by pmu-diag (energy stays with run, floor and bounds)".into(),
    };
    let mut windows = Vec::new();
    let mut not_run = Vec::new();
    let seed = protocol.seed;
    let scratch = cfg.work_dir.join("pmu-diag");
    for leg in &protocol.legs {
        let id = leg.id();
        for &aff in &protocol.affinity {
            let _pin = match apply_affinity(aff, &cfg.discovery) {
                Ok(g) => g,
                Err(reason) => {
                    not_run.push(NotRun {
                        leg: id.clone(),
                        affinity: aff,
                        reason,
                    });
                    continue;
                }
            };
            let leg_dir = scratch.join(id.replace(['/', '='], "_")).join(aff.code());
            let _ = fs::remove_dir_all(&leg_dir);
            let outcome = run_leg(
                cfg,
                &protocol,
                leg,
                &id,
                aff,
                seed,
                fx.as_ref(),
                &leg_dir,
                &mut windows,
            );
            let _ = fs::remove_dir_all(&leg_dir);
            if let Err(reason) = outcome {
                windows.retain(|w| !(w.leg == id && w.affinity == aff));
                not_run.push(NotRun {
                    leg: id.clone(),
                    affinity: aff,
                    reason,
                });
            }
        }
    }
    let raw = Raw {
        schema: RAW_SCHEMA.into(),
        protocol_sha256: sha256_hex(&protocol_bytes),
        manifest,
        discovery: cfg.discovery.clone(),
        windows,
        not_run,
    };
    let raw_bytes = serde_json::to_vec_pretty(&raw).map_err(|e| e.to_string())?;
    let report = compute_report(&protocol_bytes, &raw_bytes).map_err(|e| e.to_string())?;
    let report_bytes = serde_json::to_vec_pretty(&report).map_err(|e| e.to_string())?;
    fs::write(&raw_path, &raw_bytes).map_err(|e| format!("write {RAW_FILE}: {e}"))?;
    fs::write(cfg.evidence_dir.join(REPORT_FILE), &report_bytes)
        .map_err(|e| format!("write {REPORT_FILE}: {e}"))?;
    let sums = sha256sums(&cfg.evidence_dir, &[PROTOCOL_FILE, RAW_FILE, REPORT_FILE])?;
    fs::write(cfg.evidence_dir.join(SUMS_FILE), sums)
        .map_err(|e| format!("write {SUMS_FILE}: {e}"))?;
    Ok(report)
}

/// Run every repetition of one (leg, affinity). A setup failure (not a window error)
/// returns `Err` and the caller records the pair as not run.
#[allow(clippy::too_many_arguments)]
fn run_leg(
    cfg: &DiagConfig,
    protocol: &Protocol,
    leg: &LegSpec,
    id: &str,
    aff: AffinityPolicy,
    seed: u64,
    fx: Option<&FixtureData>,
    leg_dir: &Path,
    windows: &mut Vec<Window>,
) -> Result<(), String> {
    let d = &cfg.discovery;
    let fixture = || fx.ok_or_else(|| "fixture not loaded".to_string());
    match leg {
        LegSpec::Floor { op, iterations } => {
            // One untimed warm-up pass so the first control window is not cold.
            floor_window(*op, (*iterations / 10).max(1))();
            for rep in 0..protocol.reps {
                for instrumented in [false, true] {
                    let m = measure(d, aff, instrumented, floor_window(*op, *iterations));
                    record(windows, id, aff, rep, instrumented, m);
                }
            }
        }
        LegSpec::Write {
            arm,
            agents,
            ops_per_agent,
        } => {
            let fx = fixture()?;
            for rep in 0..protocol.reps {
                for instrumented in [false, true] {
                    let dir =
                        leg_dir.join(format!("r{rep}-{}", if instrumented { "i" } else { "c" }));
                    let setup = write_setup(&dir, seed, rep, *arm, *agents, *ops_per_agent, fx)?;
                    let label = format!("pmu-diag/{id}/{}/r{rep}/{instrumented}", aff.code());
                    let m = measure(d, aff, instrumented, write_window(&setup, &label));
                    drop(setup);
                    let _ = fs::remove_dir_all(&dir);
                    record(windows, id, aff, rep, instrumented, m);
                }
            }
        }
        LegSpec::Query { .. } => {
            let fx = fixture()?;
            let (mut s, plan) = query_prepare(leg_dir, seed, leg, fx)?;
            // Untimed warm-up: materialize every virtual tree the windows will read.
            let warm = query_window(&mut s, &plan)();
            if let Some(e) = warm.error {
                return Err(format!("query warm-up: {e}"));
            }
            for rep in 0..protocol.reps {
                for instrumented in [false, true] {
                    let m = measure(d, aff, instrumented, query_window(&mut s, &plan));
                    record(windows, id, aff, rep, instrumented, m);
                }
            }
        }
        LegSpec::Crumb { samples } => {
            let fx = fixture()?;
            let paths = crumb_paths(fx, seed, *samples).ok_or(
                "fixture base has no .crumb file: no representative Crumb fixture (NOT_RUN)",
            )?;
            let mut s = Svc::open(leg_dir, seed, 1, FsyncPolicy::EveryCommit, fx)?;
            let warm = crumb_window(&mut s, &paths)();
            if let Some(e) = warm.error {
                return Err(format!("crumb warm-up: {e}"));
            }
            for rep in 0..protocol.reps {
                for instrumented in [false, true] {
                    let m = measure(d, aff, instrumented, crumb_window(&mut s, &paths));
                    record(windows, id, aff, rep, instrumented, m);
                }
            }
        }
    }
    Ok(())
}

/// `UnavailableReason` codes as they appear in reports.
pub fn reason_code(r: UnavailableReason) -> String {
    enum_code(&r)
}

#[cfg(test)]
mod tests;
