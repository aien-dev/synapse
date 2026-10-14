//! Host, toolchain, filesystem, and Git configuration manifest collection.
//!
//! Every field is read from the running system. When a value cannot be read it is
//! recorded as `"unknown"` (never a guessed or invented fallback).

use crate::gitcmd::run_git;
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::process::Command;

pub const UNKNOWN: &str = "unknown";

/// Host and toolchain facts recorded in `manifest.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostInfo {
    pub hostname: String,
    pub kernel_release: String,
    pub arch: String,
    /// Distinct CPU model names as reported by the source below.
    pub cpu_models: Vec<String>,
    /// `lscpu`, `/proc/cpuinfo`, or `unknown`.
    pub cpu_model_source: String,
    pub logical_cpus: Option<usize>,
    pub mem_total_kib: Option<u64>,
    pub git_version: String,
    pub rustc_version: String,
    pub cargo_version: String,
    pub work_dir: String,
    pub work_dir_fs_type: String,
    pub work_dir_source: String,
    pub work_dir_free_bytes_at_start: Option<u64>,
}

fn command_line(program: &str, args: &[&str]) -> Option<String> {
    let out = Command::new(program).args(args).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if text.is_empty() {
        None
    } else {
        Some(text)
    }
}

fn read_trimmed(path: &str) -> Option<String> {
    std::fs::read_to_string(path)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// CPU model names from `lscpu` ("Model name:" lines), else `/proc/cpuinfo`
/// ("model name" lines), else `["unknown"]`.
pub fn cpu_models() -> (Vec<String>, String) {
    let mut models: Vec<String> = Vec::new();
    if let Some(text) = command_line("lscpu", &[]) {
        for line in text.lines() {
            if let Some(rest) = line.trim().strip_prefix("Model name:") {
                let name = rest.trim().to_string();
                if !name.is_empty() && !models.contains(&name) {
                    models.push(name);
                }
            }
        }
        if !models.is_empty() {
            return (models, "lscpu".to_string());
        }
    }
    if let Some(text) = read_trimmed("/proc/cpuinfo") {
        for line in text.lines() {
            let lower = line.to_ascii_lowercase();
            if lower.starts_with("model name") {
                if let Some((_, v)) = line.split_once(':') {
                    let name = v.trim().to_string();
                    if !name.is_empty() && !models.contains(&name) {
                        models.push(name);
                    }
                }
            }
        }
        if !models.is_empty() {
            return (models, "/proc/cpuinfo".to_string());
        }
    }
    (vec![UNKNOWN.to_string()], UNKNOWN.to_string())
}

fn mem_total_kib() -> Option<u64> {
    let text = std::fs::read_to_string("/proc/meminfo").ok()?;
    let line = text.lines().find(|l| l.starts_with("MemTotal:"))?;
    line.split_whitespace().nth(1)?.parse().ok()
}

/// Free bytes available to unprivileged users on the filesystem holding `dir`.
pub fn free_bytes(dir: &Path) -> Option<u64> {
    let c_path = std::ffi::CString::new(dir.to_str()?).ok()?;
    // SAFETY: `statvfs` is a plain C struct; an all-zero bit pattern is valid.
    let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
    // SAFETY: `c_path` is a valid NUL-terminated string and `st` is exclusively borrowed.
    let rc = unsafe { libc::statvfs(c_path.as_ptr(), &mut st) };
    if rc != 0 {
        return None;
    }
    Some((st.f_bavail as u64).saturating_mul(st.f_frsize as u64))
}

/// Collect host facts; `work_dir` must exist.
pub fn collect_host_info(work_dir: &Path) -> HostInfo {
    let (cpu_models, cpu_model_source) = cpu_models();
    let dir_str = work_dir.to_string_lossy().to_string();
    let findmnt = command_line("findmnt", &["-n", "-o", "FSTYPE,SOURCE", "-T", &dir_str]);
    let (fs_type, source) = match findmnt {
        Some(line) => {
            let mut parts = line.split_whitespace();
            (
                parts.next().unwrap_or(UNKNOWN).to_string(),
                parts.next().unwrap_or(UNKNOWN).to_string(),
            )
        }
        None => (UNKNOWN.to_string(), UNKNOWN.to_string()),
    };
    HostInfo {
        hostname: read_trimmed("/proc/sys/kernel/hostname").unwrap_or_else(|| UNKNOWN.into()),
        kernel_release: read_trimmed("/proc/sys/kernel/osrelease")
            .unwrap_or_else(|| UNKNOWN.into()),
        arch: std::env::consts::ARCH.to_string(),
        cpu_models,
        cpu_model_source,
        logical_cpus: std::thread::available_parallelism().ok().map(|n| n.get()),
        mem_total_kib: mem_total_kib(),
        git_version: command_line("git", &["--version"]).unwrap_or_else(|| UNKNOWN.into()),
        rustc_version: command_line("rustc", &["--version"]).unwrap_or_else(|| UNKNOWN.into()),
        cargo_version: command_line("cargo", &["--version"]).unwrap_or_else(|| UNKNOWN.into()),
        work_dir: dir_str,
        work_dir_fs_type: fs_type,
        work_dir_source: source,
        work_dir_free_bytes_at_start: free_bytes(work_dir),
    }
}

/// Effective value and origin of one Git config key as seen from `repo`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitConfigValue {
    pub key: String,
    /// `git config --show-origin --get-all` lines, or empty when unset.
    pub values_with_origin: Vec<String>,
    pub set: bool,
}

/// Read `key` with `git config --show-origin --get-all` (exit 1 means unset).
pub fn git_config_value(repo: &Path, key: &str) -> Result<GitConfigValue, String> {
    let run = run_git(
        repo,
        &[],
        &[],
        &["config", "--show-origin", "--get-all", key],
        None,
    )?;
    match run.code {
        Some(0) => Ok(GitConfigValue {
            key: key.to_string(),
            values_with_origin: String::from_utf8_lossy(&run.stdout)
                .lines()
                .map(|l| l.replace('\t', " "))
                .collect(),
            set: true,
        }),
        Some(1) => Ok(GitConfigValue {
            key: key.to_string(),
            values_with_origin: Vec::new(),
            set: false,
        }),
        other => Err(format!(
            "git config --get-all {key} failed (exit {other:?}): {}",
            run.stderr_tail()
        )),
    }
}

/// Full `git config --list --show-origin` for `repo`, excluding `credential.*` keys.
pub fn git_config_listing(repo: &Path) -> Result<Vec<String>, String> {
    let out = crate::gitcmd::git_ok(repo, &[], &[], &["config", "--list", "--show-origin"], None)?;
    Ok(String::from_utf8_lossy(&out)
        .lines()
        .filter(|l| !l.contains("credential."))
        .map(|l| l.replace('\t', " "))
        .collect())
}

/// Result of counting fsync-family syscalls issued by one small `git hash-object -w`
/// under `strace`, with and without `core.fsync=all` (verifies that the G3F arm
/// really hardens writes instead of trusting the documentation).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FsyncProbe {
    pub tool: String,
    pub default_config_fsync_calls: Option<u64>,
    pub fsync_all_config_fsync_calls: Option<u64>,
    pub note: String,
}

fn strace_fsync_count(repo: &Path, config: &[&str]) -> Result<u64, String> {
    let trace_file = repo.join(format!("strace-{}.txt", config.len()));
    let mut cmd = Command::new("strace");
    cmd.arg("-f")
        .arg("-c")
        .arg("-o")
        .arg(&trace_file)
        .arg("-e")
        .arg("trace=fsync,fdatasync,sync_file_range,syncfs")
        .arg("git")
        .arg("-C")
        .arg(repo);
    for c in config {
        cmd.arg("-c").arg(c);
    }
    cmd.args(["hash-object", "-w", "--stdin"]);
    cmd.stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let mut child = cmd.spawn().map_err(|e| format!("spawn strace: {e}"))?;
    {
        use std::io::Write;
        let mut stdin = child.stdin.take().ok_or("strace stdin unavailable")?;
        stdin
            .write_all(format!("fsync probe {}\n", config.join(",")).as_bytes())
            .map_err(|e| format!("write strace stdin: {e}"))?;
    }
    let out = child
        .wait_with_output()
        .map_err(|e| format!("wait strace: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "strace git hash-object failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    let text = std::fs::read_to_string(&trace_file)
        .map_err(|e| format!("read {}: {e}", trace_file.display()))?;
    let _ = std::fs::remove_file(&trace_file);
    // `strace -c` table rows: "% time seconds usecs/call calls errors syscall".
    let mut total = 0u64;
    for line in text.lines() {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if let Some(name) = cols.last() {
            if matches!(*name, "fsync" | "fdatasync" | "sync_file_range" | "syncfs")
                && cols.len() >= 5
            {
                if let Ok(calls) = cols[3].parse::<u64>() {
                    total += calls;
                }
            }
        }
    }
    Ok(total)
}

/// Probe fsync behaviour in a scratch repository under `scratch_dir`.
pub fn probe_git_fsync(scratch_dir: &Path) -> FsyncProbe {
    let repo = scratch_dir.join("fsync-probe-repo");
    let _ = std::fs::remove_dir_all(&repo);
    if let Err(e) = std::fs::create_dir_all(&repo) {
        return FsyncProbe {
            tool: "strace".into(),
            default_config_fsync_calls: None,
            fsync_all_config_fsync_calls: None,
            note: format!("could not create probe repo: {e}"),
        };
    }
    let init = crate::gitcmd::git_ok(&repo, &[], &[], &["init", "-q"], None);
    if let Err(e) = init {
        return FsyncProbe {
            tool: "strace".into(),
            default_config_fsync_calls: None,
            fsync_all_config_fsync_calls: None,
            note: format!("git init failed: {e}"),
        };
    }
    let default_calls = strace_fsync_count(&repo, &[]);
    let all_calls = strace_fsync_count(&repo, &["core.fsync=all", "core.fsyncMethod=fsync"]);
    let _ = std::fs::remove_dir_all(&repo);
    let note = match (&default_calls, &all_calls) {
        (Ok(_), Ok(_)) => "counts of fsync, fdatasync, sync_file_range, and syncfs calls made by \
                           one `git hash-object -w --stdin` (strace -f -c)"
            .to_string(),
        (d, a) => format!(
            "probe incomplete: default={:?} all={:?}",
            d.as_ref().err(),
            a.as_ref().err()
        ),
    };
    FsyncProbe {
        tool: "strace".into(),
        default_config_fsync_calls: default_calls.ok(),
        fsync_all_config_fsync_calls: all_calls.ok(),
        note,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cpu_models_never_empty_and_free_bytes_readable() {
        let (models, source) = cpu_models();
        assert!(!models.is_empty());
        assert!(!source.is_empty());
        assert!(free_bytes(&std::env::temp_dir()).is_some());
    }
}
