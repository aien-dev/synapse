//! CPU time and peak RSS attribution via `getrusage(2)`.
//!
//! `RUSAGE_SELF` covers every thread of the arm process. `RUSAGE_CHILDREN` covers
//! only children that have terminated and been waited for (every `git` spawn in
//! this harness is waited for). CPU times are deltas over the measured window and
//! can be summed. `ru_maxrss` is a lifetime high-water mark: for `RUSAGE_CHILDREN`
//! it is the RSS of the single largest waited-for child, never a sum, so self and
//! child peaks are reported separately and never added or subtracted.

use serde::{Deserialize, Serialize};

/// One `getrusage` reading.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RusageSample {
    pub user_us: u64,
    pub sys_us: u64,
    /// Linux reports `ru_maxrss` in kibibytes.
    pub maxrss_kib: u64,
}

fn sample(who: libc::c_int) -> Result<RusageSample, String> {
    // SAFETY: `rusage` is a plain C struct; an all-zero bit pattern is valid.
    let mut ru: libc::rusage = unsafe { std::mem::zeroed() };
    // SAFETY: `ru` is a valid, exclusively borrowed `rusage` for the kernel to fill.
    let rc = unsafe { libc::getrusage(who, &mut ru) };
    if rc != 0 {
        return Err(format!(
            "getrusage failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    let tv = |t: libc::timeval| (t.tv_sec as u64) * 1_000_000 + t.tv_usec as u64;
    Ok(RusageSample {
        user_us: tv(ru.ru_utime),
        sys_us: tv(ru.ru_stime),
        maxrss_kib: ru.ru_maxrss as u64,
    })
}

pub fn sample_self() -> Result<RusageSample, String> {
    sample(libc::RUSAGE_SELF)
}

pub fn sample_children() -> Result<RusageSample, String> {
    sample(libc::RUSAGE_CHILDREN)
}

/// CPU and memory attribution for one measured window of an arm process.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CpuUsage {
    pub self_user_ms: f64,
    pub self_sys_ms: f64,
    pub children_user_ms: f64,
    pub children_sys_ms: f64,
    /// Self plus waited-children CPU time (user + system) inside the window.
    pub total_cpu_ms: f64,
    /// Lifetime peak RSS of the arm process (includes setup, for example the
    /// in-memory base tree held by the Synapse service).
    pub peak_rss_self_kib: u64,
    /// Peak RSS of the largest single waited-for child process (not a sum).
    pub peak_rss_largest_child_kib: u64,
}

/// Start/finish pair for a measured window.
#[derive(Debug, Clone, Copy)]
pub struct RusageWindow {
    self_start: RusageSample,
    children_start: RusageSample,
}

impl RusageWindow {
    pub fn start() -> Result<Self, String> {
        Ok(Self {
            self_start: sample_self()?,
            children_start: sample_children()?,
        })
    }

    pub fn finish(&self) -> Result<CpuUsage, String> {
        let s = sample_self()?;
        let c = sample_children()?;
        let ms = |a: u64, b: u64| crate::stats::round3(a.saturating_sub(b) as f64 / 1000.0);
        let self_user_ms = ms(s.user_us, self.self_start.user_us);
        let self_sys_ms = ms(s.sys_us, self.self_start.sys_us);
        let children_user_ms = ms(c.user_us, self.children_start.user_us);
        let children_sys_ms = ms(c.sys_us, self.children_start.sys_us);
        Ok(CpuUsage {
            self_user_ms,
            self_sys_ms,
            children_user_ms,
            children_sys_ms,
            total_cpu_ms: crate::stats::round3(
                self_user_ms + self_sys_ms + children_user_ms + children_sys_ms,
            ),
            peak_rss_self_kib: s.maxrss_kib,
            peak_rss_largest_child_kib: c.maxrss_kib,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn window_counts_waited_child_cpu() {
        let w = RusageWindow::start().unwrap();
        let status = std::process::Command::new("git")
            .arg("--version")
            .output()
            .unwrap();
        assert!(status.status.success());
        let usage = w.finish().unwrap();
        assert!(usage.peak_rss_self_kib > 0);
        assert!(usage.peak_rss_largest_child_kib > 0);
        assert!(usage.total_cpu_ms >= 0.0);
    }
}
