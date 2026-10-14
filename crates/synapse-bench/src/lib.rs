//! Gate 4 comparative qualification harness for Synapse ([aien-sovereign-core#515]).
//!
//! The harness measures Synapse changeset ingest and checkout-free queries against
//! conventional Git workflows on a pinned, real repository fixture, runs neutral
//! conformance suites (WAL recovery, Git materialization, Radicle canonicality), and
//! records raw per-operation traces plus a host and toolchain manifest.
//!
//! It reports measurements only. No module contains an adoption verdict, and no test
//! asserts that one arm is faster than another: tests assert correctness only.
//!
//! Process model: the `run` orchestrator ([`orchestrator::run_qualification`]) spawns
//! one child process per measurement cell (`synapse-bench child ...`) so that CPU time
//! (`getrusage` self plus waited children) and peak RSS are attributed per arm.
//!
//! [aien-sovereign-core#515]: https://github.com/aien-spark/aien-sovereign-core/issues/515

pub mod bounds;
pub mod conflict;
pub mod conformance;
pub mod crypto_vectors;
pub mod energy;
pub mod fixture;
pub mod floor;
pub mod git_arm;
pub mod gitcmd;
pub mod host;
pub mod orchestrator;
pub mod query;
pub mod recovery;
pub mod rng;
pub mod rusage;
pub mod stats;
pub mod synapse_arm;
pub mod workload;
pub mod write_phase;

use std::path::Path;

/// Write `value` as pretty JSON to `path`, creating parent directories.
pub fn write_json<T: serde::Serialize>(path: &Path, value: &T) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("create {}: {e}", parent.display()))?;
    }
    let bytes = serde_json::to_vec_pretty(value)
        .map_err(|e| format!("serialize {}: {e}", path.display()))?;
    std::fs::write(path, bytes).map_err(|e| format!("write {}: {e}", path.display()))
}

/// Read and deserialize a JSON file.
pub fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    serde_json::from_slice(&bytes).map_err(|e| format!("parse {}: {e}", path.display()))
}

/// Write one JSON object per line (JSONL) to `path`, creating parent directories.
pub fn write_jsonl<T: serde::Serialize>(path: &Path, rows: &[T]) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("create {}: {e}", parent.display()))?;
    }
    let mut out = Vec::with_capacity(rows.len() * 160);
    for row in rows {
        serde_json::to_writer(&mut out, row)
            .map_err(|e| format!("serialize trace row for {}: {e}", path.display()))?;
        out.push(b'\n');
    }
    std::fs::write(path, out).map_err(|e| format!("write {}: {e}", path.display()))
}

/// Convert a path to UTF-8 for use as a command-line argument.
pub fn path_str(path: &Path) -> Result<&str, String> {
    path.to_str()
        .ok_or_else(|| format!("path is not valid UTF-8: {}", path.display()))
}

/// Current wall-clock time in Unix milliseconds.
pub fn unix_now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Current UTC timestamp formatted as `YYYY-MM-DDTHH:MM:SSZ` (civil-from-days, no external crate).
pub fn utc_timestamp() -> String {
    let secs = unix_now_ms() / 1000;
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let (h, m, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    // Howard Hinnant's days-to-civil algorithm.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let mo = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if mo <= 2 { y + 1 } else { y };
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{m:02}:{s:02}Z")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utc_timestamp_has_iso_shape() {
        let ts = utc_timestamp();
        assert_eq!(ts.len(), 20);
        assert!(ts.ends_with('Z'));
        assert_eq!(&ts[4..5], "-");
        assert_eq!(&ts[10..11], "T");
    }
}
