//! On-board CPU energy readings for measurement windows (read-only).
//!
//! Meter: the `aien_spbm` hwmon device (read-only reader of the GB10 SPBM firmware
//! block; `omega-r15/research/m15/spbm/README.md`). Energy channels are 32-bit
//! millijoule counters exposed as microjoules; power channels are milliwatts exposed
//! as microwatts. The firmware publishes no accuracy specification and the readings
//! were never compared with an external meter, so absolute accuracy is not claimed.
//! `pkg` is the SoC package (CPU clusters plus uncore and memory side); the NVMe drive
//! and the rest of the system are outside it and stay UNMEASURED. The boundary of the
//! `sys_total` power channel is not documented (UNVERIFIED) and is kept as supporting
//! data only.
//!
//! Method: the Omega TY-4/TY-5 energy protocol
//! (`omega/docs/turing/TURING_YIELD_ENERGY_PROTOCOL_V0.md` sections 7 to 9), adapted to
//! this harness: a 10 Hz sampler pinned to CPU 0 (an A725 core) records pkg, cpu_e and
//! cpu_p; a window is refused, never repaired, when the meter is missing, an overflow
//! flag is set at either edge, a counter decreased, the counter is within one window of
//! the 32-bit wrap, two consecutive samples are more than 300 ms apart, or fewer than
//! 90% of the expected samples arrived. Each edge is uncertain by up to one sensor
//! period (about 0.1 s) of power; the analytic edge bound is reported. The idle share is
//! subtracted from a separate IDLE window measured the same way (a COUNTERFACTUAL
//! estimate, not a direct reading). Other processes on the host are a confounder: the
//! window records `/proc/loadavg` and whole-machine busy CPU time at both edges.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Sampler period (10 Hz, as in the TY protocol).
pub const SAMPLE_PERIOD: Duration = Duration::from_millis(100);
/// Sensor update period assumed for the analytic edge bound (TY protocol section 7).
pub const SENSOR_PERIOD_S: f64 = 0.1;
/// 32-bit millijoule counter wrap, in microjoules.
pub const COUNTER_WRAP_UJ: u64 = (u32::MAX as u64 + 1) * 1000;
/// Refuse a window when two consecutive samples are further apart than this.
pub const MAX_SAMPLE_GAP: Duration = Duration::from_millis(300);

/// A located hwmon device with labelled channels.
#[derive(Debug, Clone)]
pub struct Spbm {
    dir: PathBuf,
}

fn read_trim(path: &Path) -> Option<String> {
    std::fs::read_to_string(path)
        .ok()
        .map(|s| s.trim().to_string())
}

impl Spbm {
    /// Find the hwmon device named `aien_spbm`.
    pub fn find() -> Option<Self> {
        let entries = std::fs::read_dir("/sys/class/hwmon").ok()?;
        for e in entries.flatten() {
            let dir = e.path();
            if read_trim(&dir.join("name")).as_deref() == Some("aien_spbm") {
                return Some(Self { dir });
            }
        }
        None
    }

    fn channel_index(&self, kind: &str, label: &str) -> Option<usize> {
        (1..=16).find(|n| {
            read_trim(&self.dir.join(format!("{kind}{n}_label"))).as_deref() == Some(label)
        })
    }

    /// Energy counter in microjoules (`pkg`, `cpu_e`, `cpu_p`, `gpm`). `None` when the
    /// read fails (the reader returns `EOVERFLOW` when an overflow flag is set).
    pub fn energy_uj(&self, label: &str) -> Option<u64> {
        let n = self.channel_index("energy", label)?;
        read_trim(&self.dir.join(format!("energy{n}_input")))?
            .parse()
            .ok()
    }

    /// Raw overflow indicator of an energy channel (0 means no overflow).
    pub fn overflow_raw(&self, label: &str) -> Option<u64> {
        let n = self.channel_index("energy", label)?;
        read_trim(&self.dir.join(format!("energy{n}_overflow_raw")))?
            .parse()
            .ok()
    }

    /// Instantaneous power in microwatts (`sys_total`, `soc_pkg`, `cpu_e`, `cpu_p`, `gpu`).
    pub fn power_uw(&self, label: &str) -> Option<u64> {
        let n = self.channel_index("power", label)?;
        read_trim(&self.dir.join(format!("power{n}_input")))?
            .parse()
            .ok()
    }
}

/// NVMe composite temperature in kelvin from the `nvme` hwmon device, if present.
pub fn nvme_temperature_k() -> Option<f64> {
    let entries = std::fs::read_dir("/sys/class/hwmon").ok()?;
    for e in entries.flatten() {
        let dir = e.path();
        if read_trim(&dir.join("name")).as_deref() == Some("nvme") {
            let milli_c: f64 = read_trim(&dir.join("temp1_input"))?.parse().ok()?;
            return Some(milli_c / 1000.0 + 273.15);
        }
    }
    None
}

/// `/proc/loadavg` first three fields.
pub fn loadavg() -> Option<[f64; 3]> {
    let s = read_trim(Path::new("/proc/loadavg"))?;
    let mut it = s.split_whitespace().map(|v| v.parse::<f64>().ok());
    Some([it.next()??, it.next()??, it.next()??])
}

/// Whole-machine busy CPU time (all CPUs, user + nice + system + irq + softirq + steal), seconds.
pub fn machine_busy_cpu_s() -> Option<f64> {
    let s = std::fs::read_to_string("/proc/stat").ok()?;
    let line = s.lines().find(|l| l.starts_with("cpu "))?;
    let v: Vec<u64> = line
        .split_whitespace()
        .skip(1)
        .filter_map(|x| x.parse().ok())
        .collect();
    // user nice system idle iowait irq softirq steal
    let busy = v.first()? + v.get(1)? + v.get(2)? + v.get(5)? + v.get(6)? + v.get(7)?;
    // SAFETY: sysconf has no preconditions.
    let hz = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    (hz > 0).then(|| busy as f64 / hz as f64)
}

#[derive(Debug, Clone, Copy)]
struct Sample {
    t: Instant,
    pkg: Option<u64>,
    cpu_e: Option<u64>,
    cpu_p: Option<u64>,
    sys_total_uw: Option<u64>,
}

fn take_sample(s: &Spbm) -> Sample {
    Sample {
        t: Instant::now(),
        pkg: s.energy_uj("pkg"),
        cpu_e: s.energy_uj("cpu_e"),
        cpu_p: s.energy_uj("cpu_p"),
        sys_total_uw: s.power_uw("sys_total"),
    }
}

/// Energy over one measurement window. Joule fields are `None` when the window was
/// refused (`refusal` says why) or the meter is absent.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EnergyReading {
    /// Meter description, or `UNMEASURED: <reason>`.
    pub sensor: String,
    pub window_s: f64,
    pub valid: bool,
    pub refusal: Option<String>,
    pub samples: usize,
    pub largest_gap_ms: Option<f64>,
    /// SoC package energy, joules (DIRECT reading for this interval).
    pub pkg_j: Option<f64>,
    pub cpu_p_j: Option<f64>,
    pub cpu_e_j: Option<f64>,
    /// pkg - cpu_p - cpu_e (uncore and memory side).
    pub rest_j: Option<f64>,
    /// Mean pkg power over the window, watts.
    pub pkg_mean_w: Option<f64>,
    /// Analytic sd of the pkg energy from both edges: `P * 0.1 s * sqrt(2/3)`, joules.
    pub pkg_edge_sd_j: Option<f64>,
    /// Mean of the `sys_total` power samples, watts (boundary UNVERIFIED; supporting only).
    pub sys_total_mean_w: Option<f64>,
    pub nvme_temp_k: Option<f64>,
    pub loadavg_start: Option<[f64; 3]>,
    pub loadavg_end: Option<[f64; 3]>,
    /// Busy CPU seconds of the whole machine over the window (all processes).
    pub machine_busy_cpu_s: Option<f64>,
}

impl EnergyReading {
    /// Package joules above an idle baseline power for this window's length
    /// (idle share is a COUNTERFACTUAL estimate from a separate IDLE window).
    pub fn pkg_above_idle_j(&self, idle: &EnergyReading) -> Option<f64> {
        let p_idle = idle.pkg_mean_w?;
        Some(self.pkg_j? - p_idle * self.window_s)
    }
}

/// An open measurement window; call [`EnergyWindow::finish`] to close it.
pub struct EnergyWindow {
    spbm: Option<Spbm>,
    start: Instant,
    first: Option<Sample>,
    overflow_start: bool,
    stop: Arc<AtomicBool>,
    samples: Arc<Mutex<Vec<Sample>>>,
    sampler: Option<std::thread::JoinHandle<()>>,
    loadavg_start: Option<[f64; 3]>,
    busy_start: Option<f64>,
}

fn pin_current_thread_to_cpu0() {
    // SAFETY: `set` is a zeroed cpu_set_t; CPU_SET and sched_setaffinity(0, ...) only
    // touch it and the calling thread's affinity. Failure is harmless (sampler unpinned).
    unsafe {
        let mut set: libc::cpu_set_t = std::mem::zeroed();
        libc::CPU_SET(0, &mut set);
        let _ = libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &set);
    }
}

fn any_overflow(s: &Spbm) -> bool {
    ["pkg", "cpu_e", "cpu_p"]
        .iter()
        .any(|l| s.overflow_raw(l).is_none_or(|v| v != 0))
}

impl EnergyWindow {
    /// Start a window: check overflow flags, take the first sample, start the 10 Hz sampler.
    pub fn start() -> Self {
        let spbm = Spbm::find();
        let stop = Arc::new(AtomicBool::new(false));
        let samples = Arc::new(Mutex::new(Vec::new()));
        let loadavg_start = loadavg();
        let busy_start = machine_busy_cpu_s();
        let overflow_start = spbm.as_ref().is_some_and(any_overflow);
        let first = spbm.as_ref().map(take_sample);
        let sampler = spbm.clone().map(|s| {
            let (stop, samples) = (stop.clone(), samples.clone());
            std::thread::spawn(move || {
                pin_current_thread_to_cpu0();
                let mut next = Instant::now() + SAMPLE_PERIOD;
                while !stop.load(Ordering::Relaxed) {
                    let now = Instant::now();
                    if now < next {
                        std::thread::sleep((next - now).min(Duration::from_millis(5)));
                        continue;
                    }
                    let sm = take_sample(&s);
                    if let Ok(mut v) = samples.lock() {
                        v.push(sm);
                    }
                    next += SAMPLE_PERIOD;
                }
            })
        });
        Self {
            spbm,
            start: Instant::now(),
            first,
            overflow_start,
            stop,
            samples,
            sampler,
            loadavg_start,
            busy_start,
        }
    }

    /// Close the window, apply the refusal rules, and return the reading.
    pub fn finish(mut self) -> EnergyReading {
        let last = self.spbm.as_ref().map(take_sample);
        let window_s = self.start.elapsed().as_secs_f64();
        self.stop.store(true, Ordering::Relaxed);
        if let Some(h) = self.sampler.take() {
            let _ = h.join();
        }
        let overflow_end = self.spbm.as_ref().is_some_and(any_overflow);
        let mut all: Vec<Sample> = Vec::new();
        all.extend(self.first);
        all.extend(self.samples.lock().map(|v| v.clone()).unwrap_or_default());
        all.extend(last);
        let mut r = EnergyReading {
            sensor: "UNMEASURED: no aien_spbm hwmon device on this host".into(),
            window_s,
            samples: all.len(),
            nvme_temp_k: nvme_temperature_k(),
            loadavg_start: self.loadavg_start,
            loadavg_end: loadavg(),
            machine_busy_cpu_s: match (self.busy_start, machine_busy_cpu_s()) {
                (Some(a), Some(b)) => Some(b - a),
                _ => None,
            },
            ..Default::default()
        };
        if self.spbm.is_none() {
            r.refusal = Some("meter unavailable".into());
            return r;
        }
        r.sensor = "aien_spbm hwmon, SoC package only (GB10 SPBM firmware counters: energy 1 mJ \
                    step, update about 0.1 s, sampled at 10 Hz; no published accuracy; not \
                    compared with an external meter)"
            .into();
        let gaps: Vec<Duration> = all.windows(2).map(|w| w[1].t - w[0].t).collect();
        r.largest_gap_ms = gaps
            .iter()
            .max()
            .map(|g| (g.as_secs_f64() * 1e6).round() / 1e3);
        let sys: Vec<u64> = all.iter().filter_map(|s| s.sys_total_uw).collect();
        if !sys.is_empty() {
            r.sys_total_mean_w = Some(sys.iter().sum::<u64>() as f64 / sys.len() as f64 / 1e6);
        }
        let expected = (window_s / SAMPLE_PERIOD.as_secs_f64()).floor() as usize;
        let delta = |f: fn(&Sample) -> Option<u64>| -> Result<u64, String> {
            let mut prev: Option<u64> = None;
            for s in &all {
                let v = f(s).ok_or("counter read failed (overflow or missing)")?;
                if prev.is_some_and(|p| v < p) {
                    return Err("energy counter decreased".into());
                }
                prev = Some(v);
            }
            let (a, b) = (
                f(all.first().ok_or("no samples")?),
                f(all.last().ok_or("no samples")?),
            );
            let (a, b) = (a.ok_or("no start reading")?, b.ok_or("no end reading")?);
            if COUNTER_WRAP_UJ.saturating_sub(b) <= b - a {
                return Err("counter within one window of the 32-bit wrap".into());
            }
            Ok(b - a)
        };
        let refusal = if self.overflow_start || overflow_end {
            Some("overflow flag set at a window edge".to_string())
        } else if gaps.iter().any(|g| *g > MAX_SAMPLE_GAP) {
            Some("gap between consecutive samples above 300 ms".into())
        } else if all.len().saturating_sub(2) * 10 < expected * 9 {
            Some(format!(
                "fewer than 90% of expected samples ({} of {expected})",
                all.len().saturating_sub(2)
            ))
        } else {
            None
        };
        let deltas = (delta(|s| s.pkg), delta(|s| s.cpu_p), delta(|s| s.cpu_e));
        match (refusal, deltas) {
            (Some(why), _) => r.refusal = Some(why),
            (None, (Ok(pkg), Ok(cpu_p), Ok(cpu_e))) => {
                let j = |uj: u64| uj as f64 / 1e6;
                r.valid = true;
                r.pkg_j = Some(j(pkg));
                r.cpu_p_j = Some(j(cpu_p));
                r.cpu_e_j = Some(j(cpu_e));
                r.rest_j = Some(j(pkg) - j(cpu_p) - j(cpu_e));
                if window_s > 0.0 {
                    let p = j(pkg) / window_s;
                    r.pkg_mean_w = Some(p);
                    r.pkg_edge_sd_j = Some(p * SENSOR_PERIOD_S * (2.0f64 / 3.0).sqrt());
                }
            }
            (None, (a, b, c)) => {
                r.refusal = [a.err(), b.err(), c.err()].into_iter().flatten().next();
            }
        }
        r
    }
}

/// Measure an IDLE window of `length` (the harness sleeps; other tenants keep running).
pub fn idle_window(length: Duration) -> EnergyReading {
    let w = EnergyWindow::start();
    std::thread::sleep(length);
    w.finish()
}
