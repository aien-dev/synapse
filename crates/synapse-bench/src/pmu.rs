//! Opt-in ARM CPU PMU counters for diagnostics (issue #64). Never on by default.
//!
//! Nothing in the store, the service, or the default `run`/`floor`/`bounds` paths uses
//! this module. Only `synapse-bench pmu-diag` ([`crate::pmu_diag`]) opens counters, and
//! its controls run with [`PmuMode::Disabled`], which makes no system call at all.
//!
//! Backend: Linux `perf_event_open(2)` called through `libc::syscall`, one counting (not
//! sampling) event group per CPU PMU. Sources, quoted in `docs/BENCH_PMU_DIAGNOSTICS.md`:
//! - `perf_event_open(2)` (man-pages): attribute layout (`PERF_ATTR_SIZE_VER0` = 64
//!   bytes), `read_format` with `PERF_FORMAT_TOTAL_TIME_ENABLED | _RUNNING`, the
//!   `inherit` bit (counts threads created after the open; not usable with
//!   `PERF_FORMAT_GROUP`, so each counter is read on its own fd), the `ioctl` enable,
//!   disable and reset requests, the `EACCES`/`EPERM` permission errors and
//!   `/proc/sys/kernel/perf_event_paranoid`.
//! - Arm common architectural PMU event numbers, as the kernel defines them in
//!   `include/linux/perf/arm_pmuv3.h`: `INST_RETIRED` 0x0008, `BR_MIS_PRED` 0x0010,
//!   `CPU_CYCLES` 0x0011, `BR_PRED` 0x0012. They are only used after the PMU's own
//!   sysfs event description (`events/<name>` = `event=0x....`) confirms the same
//!   number; an absent or different description is `UNSUPPORTED_EVENT`.
//!
//! Attribution: GB10 has two CPU PMUs, one per core class (Cortex-A725, MIDR part
//! 0xD87, and Cortex-X925, MIDR part 0xD85). Each event is opened on each PMU by that
//! PMU's dynamic `type`, so a count belongs to exactly one core class and only grows
//! while the measured task runs on that class. Counts are never scaled by
//! `time_enabled / time_running`. `exclude_kernel` and `exclude_hv` are set: counters
//! measure user-space execution only, and a task blocked in `fdatasync` is off CPU and
//! counts nothing, so storage wait is never attributed to branch prediction.
//!
//! Refusal: any open failure refuses the whole sample with `INSTRUMENT_UNAVAILABLE` and
//! a reason code (`PERMISSION_DENIED`, `UNSUPPORTED_EVENT`, `COUNTER_UNAVAILABLE`,
//! `NO_PMU`, `UNSUPPORTED_PLATFORM`, the vocabulary of Omega issue #453). A refused
//! sample carries no counts, never zeros.

use serde::{Deserialize, Serialize};
use std::path::Path;

/// One architected event this module counts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EventSpec {
    /// Lower-case sysfs name (`/sys/bus/event_source/devices/<pmu>/events/<name>`).
    pub name: &'static str,
    /// Arm common architectural event number (`arm_pmuv3.h`).
    pub arm_event: u16,
}

/// The counted events, in group order (the first is the group leader).
pub const EVENTS: [EventSpec; 4] = [
    EventSpec {
        name: "cpu_cycles",
        arm_event: 0x0011,
    },
    EventSpec {
        name: "inst_retired",
        arm_event: 0x0008,
    },
    EventSpec {
        name: "br_pred",
        arm_event: 0x0012,
    },
    EventSpec {
        name: "br_mis_pred",
        arm_event: 0x0010,
    },
];

/// Where the kernel exposes sysfs on a real host.
pub const SYSFS_ROOT: &str = "/sys";

/// CPU core class behind one PMU.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum CoreClass {
    CortexA725,
    CortexX925,
    /// The MIDR was unreadable or names another part.
    Unknown,
}

impl CoreClass {
    /// Class from a `midr_el1` value (implementer 0x41 Arm; part number bits 15:4).
    pub fn from_midr(midr: u64) -> Self {
        let implementer = (midr >> 24) & 0xff;
        let part = (midr >> 4) & 0xfff;
        match (implementer, part) {
            (0x41, 0xd87) => Self::CortexA725,
            (0x41, 0xd85) => Self::CortexX925,
            _ => Self::Unknown,
        }
    }

    pub fn code(self) -> &'static str {
        match self {
            Self::CortexA725 => "a725",
            Self::CortexX925 => "x925",
            Self::Unknown => "unknown",
        }
    }
}

/// What the PMU's sysfs description says about one event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventDiscovery {
    pub name: String,
    pub arm_event: u16,
    /// Raw contents of `events/<name>`, `None` when absent.
    pub sysfs_encoding: Option<String>,
    /// True only when the sysfs encoding parses to exactly `arm_event`.
    pub verified: bool,
}

/// One CPU PMU found in sysfs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PmuDevice {
    pub name: String,
    /// Dynamic `perf_event_attr.type` from `<pmu>/type`.
    pub perf_type: u32,
    pub cpus: Vec<usize>,
    pub core_class: CoreClass,
    /// `midr_el1` of the first listed CPU, as read.
    pub midr: Option<String>,
    pub events: Vec<EventDiscovery>,
}

impl PmuDevice {
    pub fn all_events_verified(&self) -> bool {
        EVENTS.iter().all(|spec| {
            self.events
                .iter()
                .any(|e| e.name == spec.name && e.arm_event == spec.arm_event && e.verified)
        })
    }
}

/// Everything discovered about the host's PMU access, recorded in `raw.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Discovery {
    pub sysfs_root: String,
    /// `/proc/sys/kernel/perf_event_paranoid` (`None` when unreadable).
    pub perf_event_paranoid: Option<i64>,
    pub devices: Vec<PmuDevice>,
}

/// Parse a kernel CPU list such as `0-4,10-14`.
pub fn parse_cpu_list(s: &str) -> Option<Vec<usize>> {
    let mut out = Vec::new();
    for part in s.trim().split(',').filter(|p| !p.is_empty()) {
        match part.split_once('-') {
            Some((a, b)) => {
                let (a, b): (usize, usize) = (a.parse().ok()?, b.parse().ok()?);
                if a > b {
                    return None;
                }
                out.extend(a..=b);
            }
            None => out.push(part.parse().ok()?),
        }
    }
    Some(out)
}

/// Parse a sysfs event description `event=0x0011[,...]` to its event number.
pub fn parse_event_encoding(s: &str) -> Option<u64> {
    s.trim()
        .split(',')
        .find_map(|kv| kv.trim().strip_prefix("event="))
        .and_then(|v| match v.strip_prefix("0x") {
            Some(h) => u64::from_str_radix(h, 16).ok(),
            None => v.parse().ok(),
        })
}

fn read_trim(path: &Path) -> Option<String> {
    std::fs::read_to_string(path)
        .ok()
        .map(|s| s.trim().to_string())
}

/// Discover CPU PMUs under `sysfs_root` (`/sys` on a host; a temporary tree in tests).
/// A device counts as a CPU PMU when it has `type`, `cpus` and `events/cpu_cycles`.
pub fn discover(sysfs_root: &Path, paranoid_path: &Path) -> Discovery {
    let mut devices = Vec::new();
    let dir = sysfs_root.join("bus/event_source/devices");
    let mut names: Vec<String> = std::fs::read_dir(&dir)
        .map(|rd| {
            rd.filter_map(|e| e.ok())
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .collect()
        })
        .unwrap_or_default();
    names.sort();
    for name in names {
        let d = dir.join(&name);
        if !d.join("events/cpu_cycles").exists() {
            continue;
        }
        let (Some(perf_type), Some(cpus)) = (
            read_trim(&d.join("type")).and_then(|t| t.parse::<u32>().ok()),
            read_trim(&d.join("cpus")).and_then(|c| parse_cpu_list(&c)),
        ) else {
            continue;
        };
        let midr = cpus.first().and_then(|c| {
            read_trim(&sysfs_root.join(format!(
                "devices/system/cpu/cpu{c}/regs/identification/midr_el1"
            )))
        });
        let core_class = midr
            .as_deref()
            .and_then(|m| u64::from_str_radix(m.trim_start_matches("0x"), 16).ok())
            .map(CoreClass::from_midr)
            .unwrap_or(CoreClass::Unknown);
        let events = EVENTS
            .iter()
            .map(|spec| {
                let enc = read_trim(&d.join("events").join(spec.name));
                let verified = enc
                    .as_deref()
                    .and_then(parse_event_encoding)
                    .is_some_and(|v| v == u64::from(spec.arm_event));
                EventDiscovery {
                    name: spec.name.into(),
                    arm_event: spec.arm_event,
                    sysfs_encoding: enc,
                    verified,
                }
            })
            .collect();
        devices.push(PmuDevice {
            name,
            perf_type,
            cpus,
            core_class,
            midr,
            events,
        });
    }
    Discovery {
        sysfs_root: sysfs_root.display().to_string(),
        perf_event_paranoid: read_trim(paranoid_path).and_then(|s| s.parse().ok()),
        devices,
    }
}

/// Discovery on the running host.
pub fn discover_host() -> Discovery {
    discover(
        Path::new(SYSFS_ROOT),
        Path::new("/proc/sys/kernel/perf_event_paranoid"),
    )
}

/// Whether counters are opened at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PmuMode {
    /// No system call, no counter, no file descriptor (default and every control run).
    Disabled,
    Enabled,
}

/// Affinity of the measured thread (and every thread it creates) during a window.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum AffinityPolicy {
    /// Scheduler's choice; a counter that ran part of the window cannot tell migration
    /// from multiplexing and is reported as `PartialResidency`.
    Unpinned,
    /// Pinned to every CPU of one core class.
    Pinned(CoreClass),
}

impl AffinityPolicy {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "unpinned" => Some(Self::Unpinned),
            "a725" => Some(Self::Pinned(CoreClass::CortexA725)),
            "x925" => Some(Self::Pinned(CoreClass::CortexX925)),
            _ => None,
        }
    }

    pub fn code(self) -> &'static str {
        match self {
            Self::Unpinned => "unpinned",
            Self::Pinned(c) => c.code(),
        }
    }
}

/// Why a sample has no counts. Serialized next to `status: INSTRUMENT_UNAVAILABLE`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum UnavailableReason {
    /// `EACCES` or `EPERM` (CAP_PERFMON missing or `perf_event_paranoid` too high).
    PermissionDenied,
    /// The PMU's sysfs description lacks the event or gives another number, or the
    /// kernel refuses the type or config (`ENOENT`, `ENODEV`, `EOPNOTSUPP`).
    UnsupportedEvent,
    /// Any other open, enable, disable, or read failure (`EINVAL`, `EBUSY`, `EMFILE`...).
    CounterUnavailable,
    /// No CPU PMU in sysfs.
    NoPmu,
    /// Not Linux, or the kernel has no `perf_event_open` (`ENOSYS`).
    UnsupportedPlatform,
}

impl UnavailableReason {
    /// Classify an errno from `perf_event_open`.
    pub fn from_open_errno(errno: i32) -> Self {
        match errno {
            libc::EACCES | libc::EPERM => Self::PermissionDenied,
            libc::ENOENT | libc::ENODEV | libc::EOPNOTSUPP => Self::UnsupportedEvent,
            libc::ENOSYS => Self::UnsupportedPlatform,
            _ => Self::CounterUnavailable,
        }
    }
}

/// How a counter that was read relates to the window.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CounterState {
    /// `time_running == time_enabled > 0`: counted for the whole time the task ran.
    Counted,
    /// Pinned to this PMU's class and `0 < time_running < time_enabled`: the kernel
    /// time-shared the hardware counter. The raw count covers only `time_running`.
    Multiplexed,
    /// Unpinned and `0 < time_running < time_enabled`: the task migrated between core
    /// classes and/or the counter was multiplexed; the two cannot be told apart.
    PartialResidency,
    /// `time_running == 0` and count 0: the task never ran on this class.
    NotScheduled,
}

/// A read that contradicts the counter contract (refused, never repaired).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MalformedRead {
    RunningExceedsEnabled { running: u64, enabled: u64 },
    CountWithoutRunningTime { value: u64 },
}

impl std::fmt::Display for MalformedRead {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RunningExceedsEnabled { running, enabled } => {
                write!(
                    f,
                    "time_running {running} ns exceeds time_enabled {enabled} ns"
                )
            }
            Self::CountWithoutRunningTime { value } => {
                write!(f, "count {value} with zero time_running")
            }
        }
    }
}

/// Classify one `(value, time_enabled, time_running)` read. Pure: used both when
/// sampling and when verifying sealed evidence.
pub fn classify(
    value: u64,
    enabled_ns: u64,
    running_ns: u64,
    pinned_to_this_class: bool,
) -> Result<CounterState, MalformedRead> {
    if running_ns > enabled_ns {
        return Err(MalformedRead::RunningExceedsEnabled {
            running: running_ns,
            enabled: enabled_ns,
        });
    }
    if running_ns == 0 {
        return if value == 0 {
            Ok(CounterState::NotScheduled)
        } else {
            Err(MalformedRead::CountWithoutRunningTime { value })
        };
    }
    Ok(if running_ns == enabled_ns {
        CounterState::Counted
    } else if pinned_to_this_class {
        CounterState::Multiplexed
    } else {
        CounterState::PartialResidency
    })
}

/// One counter read. `raw_count` is exactly what the kernel returned, never scaled.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CounterReading {
    pub event: String,
    pub arm_event: u16,
    pub pmu: String,
    pub core_class: CoreClass,
    pub raw_count: u64,
    pub time_enabled_ns: u64,
    pub time_running_ns: u64,
    pub state: CounterState,
}

/// Outcome of one instrumented window.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PmuSample {
    /// Control run: no counters were opened.
    Disabled,
    /// Counters could not be used. No counts exist for this window.
    InstrumentUnavailable {
        reason: UnavailableReason,
        detail: String,
    },
    Counted {
        readings: Vec<CounterReading>,
    },
}

/// `perf_event_attr` truncated to `PERF_ATTR_SIZE_VER0` (64 bytes), which every kernel
/// since 2.6.31 accepts (`perf_event_open(2)`, `size` field). Field order and widths
/// follow `include/uapi/linux/perf_event.h`.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PerfEventAttr {
    pub type_: u32,
    pub size: u32,
    pub config: u64,
    pub sample_period: u64,
    pub sample_type: u64,
    pub read_format: u64,
    /// Bit field: bit 0 `disabled`, 1 `inherit`, 5 `exclude_kernel`, 6 `exclude_hv`.
    pub flags: u64,
    pub wakeup_events: u32,
    pub bp_type: u32,
    pub config1: u64,
}

pub const PERF_ATTR_SIZE_VER0: u32 = 64;
const _: () = assert!(std::mem::size_of::<PerfEventAttr>() == PERF_ATTR_SIZE_VER0 as usize);

pub const PERF_FORMAT_TOTAL_TIME_ENABLED: u64 = 1 << 0;
pub const PERF_FORMAT_TOTAL_TIME_RUNNING: u64 = 1 << 1;
pub const ATTR_FLAG_DISABLED: u64 = 1 << 0;
pub const ATTR_FLAG_INHERIT: u64 = 1 << 1;
pub const ATTR_FLAG_EXCLUDE_KERNEL: u64 = 1 << 5;
pub const ATTR_FLAG_EXCLUDE_HV: u64 = 1 << 6;
/// `_IO('$', 0)`, `_IO('$', 1)`, `_IO('$', 3)`.
pub const PERF_EVENT_IOC_ENABLE: u64 = 0x2400;
pub const PERF_EVENT_IOC_DISABLE: u64 = 0x2401;
pub const PERF_EVENT_IOC_RESET: u64 = 0x2403;
pub const PERF_IOC_FLAG_GROUP: u64 = 1;
pub const PERF_FLAG_FD_CLOEXEC: u64 = 1 << 3;

/// Attribute for one counting event on `pmu`: user space only, inherited by threads
/// created after the open; the group leader starts disabled.
pub fn event_attr(perf_type: u32, arm_event: u16, leader: bool) -> PerfEventAttr {
    let mut flags = ATTR_FLAG_INHERIT | ATTR_FLAG_EXCLUDE_KERNEL | ATTR_FLAG_EXCLUDE_HV;
    if leader {
        flags |= ATTR_FLAG_DISABLED;
    }
    PerfEventAttr {
        type_: perf_type,
        size: PERF_ATTR_SIZE_VER0,
        config: u64::from(arm_event),
        read_format: PERF_FORMAT_TOTAL_TIME_ENABLED | PERF_FORMAT_TOTAL_TIME_RUNNING,
        flags,
        ..Default::default()
    }
}

/// The system calls a session makes. [`LinuxPerf`] is the real one; tests script a
/// fake to exercise refusals and multiplexing on any host.
pub trait PerfBackend {
    /// `perf_event_open(attr, pid = 0, cpu = -1, group_fd, PERF_FLAG_FD_CLOEXEC)`.
    fn open(&mut self, attr: &PerfEventAttr, group_fd: i32) -> Result<i32, i32>;
    fn ioctl_group(&mut self, fd: i32, request: u64) -> Result<(), i32>;
    /// `[value, time_enabled, time_running]`.
    fn read3(&mut self, fd: i32) -> Result<[u64; 3], i32>;
    fn close(&mut self, fd: i32);
}

/// Real backend: `libc::syscall(SYS_perf_event_open, ...)`.
#[derive(Debug, Default)]
pub struct LinuxPerf;

fn last_errno() -> i32 {
    std::io::Error::last_os_error()
        .raw_os_error()
        .unwrap_or(libc::EIO)
}

impl PerfBackend for LinuxPerf {
    #[cfg(target_os = "linux")]
    fn open(&mut self, attr: &PerfEventAttr, group_fd: i32) -> Result<i32, i32> {
        // SAFETY: `attr` points to a live, initialized 64-byte `perf_event_attr` whose
        // `size` field says 64; the kernel only reads it (or writes `size` on E2BIG,
        // which cannot happen for VER0). pid 0 = calling thread, cpu -1 = any CPU.
        let fd = unsafe {
            libc::syscall(
                libc::SYS_perf_event_open,
                attr as *const PerfEventAttr,
                0 as libc::pid_t,
                -1 as libc::c_int,
                group_fd as libc::c_int,
                PERF_FLAG_FD_CLOEXEC as libc::c_ulong,
            )
        };
        if fd < 0 {
            Err(last_errno())
        } else {
            Ok(fd as i32)
        }
    }

    #[cfg(not(target_os = "linux"))]
    fn open(&mut self, _attr: &PerfEventAttr, _group_fd: i32) -> Result<i32, i32> {
        Err(libc::ENOSYS)
    }

    fn ioctl_group(&mut self, fd: i32, request: u64) -> Result<(), i32> {
        // SAFETY: `fd` is a perf event fd this session opened and still owns; the
        // enable/disable/reset requests take an integer flag argument, no pointer.
        let rc = unsafe { libc::ioctl(fd, request as _, PERF_IOC_FLAG_GROUP) };
        if rc < 0 {
            Err(last_errno())
        } else {
            Ok(())
        }
    }

    fn read3(&mut self, fd: i32) -> Result<[u64; 3], i32> {
        let mut buf = [0u64; 3];
        // SAFETY: `buf` is 24 writable bytes owned by this frame; `fd` is owned.
        let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), std::mem::size_of_val(&buf)) };
        if n < 0 {
            Err(last_errno())
        } else if n as usize != std::mem::size_of_val(&buf) {
            Err(libc::EIO)
        } else {
            Ok(buf)
        }
    }

    fn close(&mut self, fd: i32) {
        // SAFETY: closes an fd this session opened exactly once.
        unsafe { libc::close(fd) };
    }
}

struct OpenEvent {
    fd: i32,
    spec: EventSpec,
}

struct OpenGroup {
    device: PmuDevice,
    events: Vec<OpenEvent>,
}

/// Counters for one measured window. Open before the window (and before the window
/// creates threads, so `inherit` covers them), then [`PmuSession::start`] and
/// [`PmuSession::stop`] around the measured work.
pub struct PmuSession<B: PerfBackend> {
    backend: B,
    groups: Vec<OpenGroup>,
    refusal: Option<(UnavailableReason, String)>,
    mode: PmuMode,
    affinity: AffinityPolicy,
}

impl<B: PerfBackend> PmuSession<B> {
    /// Open one group per discovered device. Fails closed: any refusal closes every
    /// fd already opened and the session yields only `InstrumentUnavailable`.
    /// `PmuMode::Disabled` touches nothing.
    pub fn open(
        backend: B,
        mode: PmuMode,
        discovery: &Discovery,
        affinity: AffinityPolicy,
    ) -> Self {
        let mut s = Self {
            groups: Vec::new(),
            refusal: None,
            mode,
            affinity,
            backend,
        };
        if mode == PmuMode::Disabled {
            return s;
        }
        if discovery.devices.is_empty() {
            s.refusal = Some((
                UnavailableReason::NoPmu,
                format!(
                    "no CPU PMU under {}/bus/event_source/devices",
                    discovery.sysfs_root
                ),
            ));
            return s;
        }
        if let Some(d) = discovery.devices.iter().find(|d| !d.all_events_verified()) {
            let missing: Vec<String> = d
                .events
                .iter()
                .filter(|e| !e.verified)
                .map(|e| format!("{} (sysfs {:?})", e.name, e.sysfs_encoding))
                .collect();
            s.refusal = Some((
                UnavailableReason::UnsupportedEvent,
                format!(
                    "{}: event description absent or not the architected number: {}",
                    d.name,
                    missing.join(", ")
                ),
            ));
            return s;
        }
        for d in &discovery.devices {
            let mut group = OpenGroup {
                device: d.clone(),
                events: Vec::new(),
            };
            let mut leader_fd = -1;
            for (i, spec) in EVENTS.iter().enumerate() {
                let attr = event_attr(d.perf_type, spec.arm_event, i == 0);
                match s.backend.open(&attr, leader_fd) {
                    Ok(fd) => {
                        if i == 0 {
                            leader_fd = fd;
                        }
                        group.events.push(OpenEvent { fd, spec: *spec });
                    }
                    Err(errno) => {
                        s.groups.push(group);
                        s.close_all();
                        s.refusal = Some((
                            UnavailableReason::from_open_errno(errno),
                            format!(
                                "perf_event_open({} type {} event {:#06x} {}): {}",
                                d.name,
                                d.perf_type,
                                spec.arm_event,
                                spec.name,
                                std::io::Error::from_raw_os_error(errno)
                            ),
                        ));
                        return s;
                    }
                }
            }
            s.groups.push(group);
        }
        s
    }

    fn close_all(&mut self) {
        for g in self.groups.drain(..) {
            for e in g.events.iter().rev() {
                self.backend.close(e.fd);
            }
        }
    }

    fn group_ioctl(&mut self, request: u64, what: &str) {
        if self.refusal.is_some() {
            return;
        }
        let leaders: Vec<(String, i32)> = self
            .groups
            .iter()
            .filter_map(|g| g.events.first().map(|e| (g.device.name.clone(), e.fd)))
            .collect();
        for (name, fd) in leaders {
            if let Err(errno) = self.backend.ioctl_group(fd, request) {
                self.refusal = Some((
                    UnavailableReason::CounterUnavailable,
                    format!(
                        "{what} {name}: {}",
                        std::io::Error::from_raw_os_error(errno)
                    ),
                ));
                return;
            }
        }
    }

    /// Reset and enable every group (no-op when disabled or refused).
    pub fn start(&mut self) {
        if self.mode == PmuMode::Disabled {
            return;
        }
        self.group_ioctl(PERF_EVENT_IOC_RESET, "reset");
        self.group_ioctl(PERF_EVENT_IOC_ENABLE, "enable");
    }

    /// Disable, read, classify, and close every counter.
    pub fn stop(mut self) -> PmuSample {
        if self.mode == PmuMode::Disabled {
            return PmuSample::Disabled;
        }
        self.group_ioctl(PERF_EVENT_IOC_DISABLE, "disable");
        let mut readings = Vec::new();
        if self.refusal.is_none() {
            'outer: for gi in 0..self.groups.len() {
                let dev = self.groups[gi].device.clone();
                let pinned_here = self.affinity == AffinityPolicy::Pinned(dev.core_class)
                    && dev.core_class != CoreClass::Unknown;
                for ei in 0..self.groups[gi].events.len() {
                    let (fd, spec) = {
                        let e = &self.groups[gi].events[ei];
                        (e.fd, e.spec)
                    };
                    let raw = match self.backend.read3(fd) {
                        Ok(v) => v,
                        Err(errno) => {
                            self.refusal = Some((
                                UnavailableReason::CounterUnavailable,
                                format!(
                                    "read {} {}: {}",
                                    dev.name,
                                    spec.name,
                                    std::io::Error::from_raw_os_error(errno)
                                ),
                            ));
                            break 'outer;
                        }
                    };
                    match classify(raw[0], raw[1], raw[2], pinned_here) {
                        Ok(state) => readings.push(CounterReading {
                            event: spec.name.into(),
                            arm_event: spec.arm_event,
                            pmu: dev.name.clone(),
                            core_class: dev.core_class,
                            raw_count: raw[0],
                            time_enabled_ns: raw[1],
                            time_running_ns: raw[2],
                            state,
                        }),
                        Err(m) => {
                            self.refusal = Some((
                                UnavailableReason::CounterUnavailable,
                                format!("{} {}: malformed read: {m}", dev.name, spec.name),
                            ));
                            break 'outer;
                        }
                    }
                }
            }
        }
        self.close_all();
        match self.refusal.take() {
            Some((reason, detail)) => PmuSample::InstrumentUnavailable { reason, detail },
            None => PmuSample::Counted { readings },
        }
    }
}

impl<B: PerfBackend> Drop for PmuSession<B> {
    fn drop(&mut self) {
        self.close_all();
    }
}

/// The calling thread's CPU affinity, so a pinned window can restore it afterwards.
pub struct AffinityGuard {
    #[cfg(target_os = "linux")]
    saved: Option<libc::cpu_set_t>,
}

/// Pin the calling thread (threads it creates inherit the mask) to `cpus`.
/// `AffinityPolicy::Unpinned` changes nothing.
pub fn apply_affinity(
    policy: AffinityPolicy,
    discovery: &Discovery,
) -> Result<AffinityGuard, String> {
    let cpus: Vec<usize> = match policy {
        AffinityPolicy::Unpinned => {
            return Ok(AffinityGuard {
                #[cfg(target_os = "linux")]
                saved: None,
            })
        }
        AffinityPolicy::Pinned(class) => discovery
            .devices
            .iter()
            .filter(|d| d.core_class == class)
            .flat_map(|d| d.cpus.iter().copied())
            .collect(),
    };
    if cpus.is_empty() {
        return Err(format!(
            "affinity {}: no PMU in sysfs names that core class",
            policy.code()
        ));
    }
    pin_to(&cpus)
}

#[cfg(target_os = "linux")]
fn pin_to(cpus: &[usize]) -> Result<AffinityGuard, String> {
    // SAFETY: `cpu_set_t` is a plain bit array; all-zero is the empty set.
    let mut saved: libc::cpu_set_t = unsafe { std::mem::zeroed() };
    // SAFETY: `saved` is a valid, exclusively borrowed cpu_set_t of the given size.
    let rc =
        unsafe { libc::sched_getaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &mut saved) };
    if rc != 0 {
        return Err(format!(
            "sched_getaffinity: {}",
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: as above.
    let mut set: libc::cpu_set_t = unsafe { std::mem::zeroed() };
    for &c in cpus {
        if c >= libc::CPU_SETSIZE as usize {
            return Err(format!("cpu {c} outside cpu_set_t"));
        }
        // SAFETY: `c` is checked against CPU_SETSIZE above.
        unsafe { libc::CPU_SET(c, &mut set) };
    }
    // SAFETY: `set` is a valid cpu_set_t; pid 0 is the calling thread.
    let rc = unsafe { libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &set) };
    if rc != 0 {
        return Err(format!(
            "sched_setaffinity: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(AffinityGuard { saved: Some(saved) })
}

#[cfg(not(target_os = "linux"))]
fn pin_to(_cpus: &[usize]) -> Result<AffinityGuard, String> {
    Err("CPU affinity is only implemented on Linux".into())
}

impl Drop for AffinityGuard {
    fn drop(&mut self) {
        #[cfg(target_os = "linux")]
        if let Some(saved) = self.saved.take() {
            // SAFETY: restores the mask read by `pin_to` on the same thread.
            unsafe { libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &saved) };
        }
    }
}
