//! `synapse-bench`: Gate 4 comparative qualification runner.
//!
//! ```text
//! synapse-bench run --fixture-repo <path> --fixture-rev <rev> --out <dir> --work-dir <dir>
//!     [--reps N] [--tiers 1,4,8,32] [--arms S1,S2,G1,G2,G3,G3F] [--seed N]
//!     [--radicle-repo <path>] [--source-rev R] [--source-dirty D] [--source-digest H] [--smoke]
//!     [--write-only] [--idle-window-s S] [--ops-floor N]
//! synapse-bench child --kind <write|query|conflict|conformance|recovery|import-probe>
//!     --spec <file> --result <file>
//! synapse-bench floor --dir <dir on the store filesystem> --out <file.json> [--iterations N]
//! synapse-bench bounds --evidence <dir with protocol.json> --work-dir <dir on the store filesystem>
//!     [--repo-root <path>] [--source-rev R] [--hwmon-root <path>]
//! synapse-bench bounds-verify --evidence <dir>
//! synapse-bench bounds-report --evidence <dir>   (prints report.json recomputed from protocol.json and raw.json)
//! ```

use std::path::PathBuf;
use std::process::ExitCode;
use synapse_bench::orchestrator::{child_main, run_qualification, RunConfig};
use synapse_bench::write_phase::ArmKind;

fn parse_list<T>(s: &str, f: impl Fn(&str) -> Option<T>) -> Result<Vec<T>, String> {
    s.split(',')
        .filter(|x| !x.is_empty())
        .map(|x| f(x.trim()).ok_or_else(|| format!("invalid list item {x:?}")))
        .collect()
}

fn parse_u64(s: &str) -> Option<u64> {
    match s.strip_prefix("0x") {
        Some(h) => u64::from_str_radix(h, 16).ok(),
        None => s.parse().ok(),
    }
}

const KNOWN_RUN_OPTIONS: &[&str] = &[
    "--fixture-repo",
    "--fixture-rev",
    "--out",
    "--work-dir",
    "--reps",
    "--tiers",
    "--arms",
    "--seed",
    "--radicle-repo",
    "--source-rev",
    "--source-dirty",
    "--source-digest",
    "--smoke",
    "--write-only",
    "--idle-window-s",
    "--ops-floor",
];

fn run(args: &[String]) -> Result<(), String> {
    let mut opts: Vec<(String, Option<String>)> = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let key = args[i].clone();
        if !key.starts_with("--") {
            return Err(format!("unexpected argument {key}"));
        }
        if key == "--smoke" || key == "--write-only" {
            opts.push((key, None));
            i += 1;
        } else {
            let v = args.get(i + 1).ok_or(format!("{key} needs a value"))?;
            opts.push((key, Some(v.clone())));
            i += 2;
        }
    }
    let get = |k: &str| {
        opts.iter()
            .rev()
            .find(|(key, _)| key == k)
            .and_then(|(_, v)| v.clone())
    };
    let need = |k: &str| get(k).ok_or(format!("missing {k}"));
    let mut cfg = RunConfig::new(
        PathBuf::from(need("--fixture-repo")?),
        need("--fixture-rev")?,
        PathBuf::from(need("--out")?),
        PathBuf::from(need("--work-dir")?),
    );
    if opts.iter().any(|(k, _)| k == "--smoke") {
        cfg.apply_smoke();
    }
    cfg.write_only = opts.iter().any(|(k, _)| k == "--write-only");
    if let Some(v) = get("--ops-floor") {
        cfg.ops_floor = v.parse().map_err(|_| "invalid --ops-floor")?;
    }
    if let Some(v) = get("--idle-window-s") {
        cfg.idle_window_s = v.parse().map_err(|_| "invalid --idle-window-s")?;
    }
    if let Some(v) = get("--reps") {
        cfg.reps = v.parse().map_err(|_| "invalid --reps")?;
    }
    if let Some(v) = get("--tiers") {
        cfg.tiers = parse_list(&v, |x| x.parse().ok().filter(|n: &usize| *n > 0))?;
    }
    if let Some(v) = get("--arms") {
        cfg.arms = parse_list(&v, ArmKind::parse)?;
    }
    if let Some(v) = get("--seed") {
        cfg.seed = parse_u64(&v).ok_or("invalid --seed")?;
    }
    cfg.radicle_repo = get("--radicle-repo")
        .filter(|s| !s.is_empty())
        .map(PathBuf::from);
    if let Some(v) = get("--source-rev") {
        cfg.source_rev = v;
    }
    if let Some(v) = get("--source-dirty") {
        cfg.source_dirty = v;
    }
    if let Some(v) = get("--source-digest") {
        cfg.source_digest = v;
    }
    if let Some((k, _)) = opts
        .iter()
        .find(|(k, _)| !KNOWN_RUN_OPTIONS.contains(&k.as_str()))
    {
        return Err(format!("unknown option {k}"));
    }
    if cfg.reps == 0 || cfg.tiers.is_empty() || cfg.arms.is_empty() {
        return Err("reps, tiers, and arms must be non-empty".into());
    }
    cfg.command_line = std::env::args().collect();
    run_qualification(&cfg)
}

fn child(args: &[String]) -> Result<(), String> {
    let mut kind = None;
    let mut spec = None;
    let mut result = None;
    let mut i = 0;
    while i < args.len() {
        let v = args
            .get(i + 1)
            .cloned()
            .ok_or(format!("{} needs a value", args[i]))?;
        match args[i].as_str() {
            "--kind" => kind = Some(v),
            "--spec" => spec = Some(PathBuf::from(v)),
            "--result" => result = Some(PathBuf::from(v)),
            other => return Err(format!("unknown option {other}")),
        }
        i += 2;
    }
    child_main(
        &kind.ok_or("missing --kind")?,
        &spec.ok_or("missing --spec")?,
        &result.ok_or("missing --result")?,
    )
}

fn floor(args: &[String]) -> Result<(), String> {
    let mut dir = None;
    let mut out = None;
    let mut iterations = 300usize;
    let mut i = 0;
    while i < args.len() {
        let v = args
            .get(i + 1)
            .cloned()
            .ok_or(format!("{} needs a value", args[i]))?;
        match args[i].as_str() {
            "--dir" => dir = Some(PathBuf::from(v)),
            "--out" => out = Some(PathBuf::from(v)),
            "--iterations" => iterations = v.parse().map_err(|_| "invalid --iterations")?,
            other => return Err(format!("unknown option {other}")),
        }
        i += 2;
    }
    let report = synapse_bench::floor::run_floor(&dir.ok_or("missing --dir")?, iterations)?;
    synapse_bench::write_json(&out.ok_or("missing --out")?, &report)
}

fn parse_pairs(args: &[String], known: &[&str]) -> Result<Vec<(String, String)>, String> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let key = args[i].as_str();
        if !known.contains(&key) {
            return Err(format!("unknown option {key}"));
        }
        let v = args.get(i + 1).ok_or(format!("{key} needs a value"))?;
        out.push((key.to_string(), v.clone()));
        i += 2;
    }
    Ok(out)
}

fn bounds(args: &[String]) -> Result<(), String> {
    let opts = parse_pairs(
        args,
        &[
            "--evidence",
            "--work-dir",
            "--repo-root",
            "--source-rev",
            "--hwmon-root",
        ],
    )?;
    let get = |k: &str| {
        opts.iter()
            .rev()
            .find(|(key, _)| key == k)
            .map(|(_, v)| v.clone())
    };
    let cfg = synapse_bench::bounds::BoundsConfig {
        evidence_dir: PathBuf::from(get("--evidence").ok_or("missing --evidence")?),
        work_dir: PathBuf::from(get("--work-dir").ok_or("missing --work-dir")?),
        repo_root: PathBuf::from(get("--repo-root").unwrap_or_else(|| ".".into())),
        hwmon_root: PathBuf::from(
            get("--hwmon-root").unwrap_or_else(|| synapse_bench::energy::HWMON_ROOT.into()),
        ),
        source_rev: get("--source-rev").unwrap_or_else(|| "unknown".into()),
    };
    let report = synapse_bench::bounds::run_bounds(&cfg).map_err(|r| r.to_string())?;
    for b in &report.bound_inputs {
        println!(
            "{} = {} {} ({}, {:?})",
            b.name, b.value, b.unit, b.kind, b.probe
        );
    }
    Ok(())
}

/// Print the report recomputed from `protocol.json` and `raw.json` (exactly the bytes
/// `bounds` writes as `report.json`). Used to reissue a report after a report-schema
/// change without touching the raw data; `bounds-verify` then checks the result.
fn bounds_report(args: &[String]) -> Result<(), String> {
    use std::io::Write;
    let opts = parse_pairs(args, &["--evidence"])?;
    let dir = opts
        .last()
        .map(|(_, v)| PathBuf::from(v))
        .ok_or("missing --evidence")?;
    let read = |name: &str| std::fs::read(dir.join(name)).map_err(|e| format!("read {name}: {e}"));
    let report = synapse_bench::bounds::compute_report(
        &read(synapse_bench::bounds::PROTOCOL_FILE)?,
        &read(synapse_bench::bounds::RAW_FILE)?,
    )
    .map_err(|e| e.to_string())?;
    let bytes = serde_json::to_vec_pretty(&report).map_err(|e| e.to_string())?;
    std::io::stdout()
        .write_all(&bytes)
        .map_err(|e| format!("write stdout: {e}"))
}

fn bounds_verify(args: &[String]) -> Result<(), String> {
    let opts = parse_pairs(args, &["--evidence"])?;
    let dir = opts
        .last()
        .map(|(_, v)| PathBuf::from(v))
        .ok_or("missing --evidence")?;
    let report = synapse_bench::bounds::verify_evidence(&dir).map_err(|e| e.to_string())?;
    println!(
        "verified: report.json recomputed byte for byte from protocol.json ({}) and raw.json ({}); every file in SHA256SUMS matches; {} excluded repetition(s). Consistency only: authenticity comes from git history and review.",
        report.protocol_sha256, report.raw_sha256, report.excluded_repetitions
    );
    Ok(())
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let outcome = match args.first().map(String::as_str) {
        Some("run") => run(&args[1..]),
        Some("child") => child(&args[1..]),
        Some("floor") => floor(&args[1..]),
        Some("bounds") => bounds(&args[1..]),
        Some("bounds-verify") => bounds_verify(&args[1..]),
        Some("bounds-report") => bounds_report(&args[1..]),
        _ => Err("usage: synapse-bench run ... | synapse-bench child ... (see crate docs)".into()),
    };
    match outcome {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("synapse-bench: {e}");
            ExitCode::FAILURE
        }
    }
}
