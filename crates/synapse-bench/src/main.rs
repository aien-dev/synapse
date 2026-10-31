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
//! synapse-bench pmu-diag --evidence <dir with protocol.json> --work-dir <dir> [--fixture-repo <path>]
//!     [--source-rev R] [--sibling name=rev]...   (opt-in CPU PMU diagnostics; see docs/BENCH_PMU_DIAGNOSTICS.md)
//! synapse-bench pmu-verify --evidence <dir>
//! synapse-bench segments --dir <dir on the store filesystem> --out <raw.json> [--agents 1,4,8,32]
//!     [--changes N] [--reps N] [--blob-bytes N] [--segment-mib N] [--checkpoint-every N] [--idle-window-s S]
//!     [--block-device <absolute path that does not exist> [--block-device-mib N] [--block-meta-mib N]]
//! synapse-bench segments-report --raw <raw.json> --floor <floor.json>   (prints the A2 report)
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

/// Opt-in CPU PMU diagnostics (issue #64). Separate from `run`, `floor` and `bounds`,
/// whose behaviour and output this subcommand never changes.
fn pmu_diag(args: &[String]) -> Result<(), String> {
    use synapse_bench::pmu_diag::{run_diag, DiagConfig, SiblingRev};
    let opts = parse_pairs(
        args,
        &[
            "--evidence",
            "--work-dir",
            "--fixture-repo",
            "--source-rev",
            "--sibling",
        ],
    )?;
    let get = |k: &str| {
        opts.iter()
            .rev()
            .find(|(key, _)| key == k)
            .map(|(_, v)| v.clone())
    };
    let siblings = opts
        .iter()
        .filter(|(k, _)| k == "--sibling")
        .map(|(_, v)| {
            v.split_once('=')
                .filter(|(n, r)| !n.is_empty() && !r.is_empty())
                .map(|(n, r)| SiblingRev {
                    name: n.into(),
                    rev: r.into(),
                })
                .ok_or(format!("--sibling needs name=rev, got {v:?}"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let cfg = DiagConfig {
        evidence_dir: PathBuf::from(get("--evidence").ok_or("missing --evidence")?),
        work_dir: PathBuf::from(get("--work-dir").ok_or("missing --work-dir")?),
        fixture_repo: get("--fixture-repo").map(PathBuf::from),
        source_rev: get("--source-rev").unwrap_or_else(|| "unknown".into()),
        siblings,
        invocation: std::env::args().collect(),
        discovery: synapse_bench::pmu::discover_host(),
    };
    let report = run_diag(&cfg)?;
    for leg in &report.legs {
        let p50 = |t: &synapse_bench::pmu_diag::TimingSummary| {
            t.wall_ns_per_op
                .as_ref()
                .map_or("-".to_string(), |d| d.p50.to_string())
        };
        println!(
            "{} [{}]: ns/op p50 control {} instrumented {}; PMU counted {}/{} windows, unavailable {:?}",
            leg.leg,
            leg.affinity.code(),
            p50(&leg.control),
            p50(&leg.instrumented),
            leg.pmu.counted_windows,
            leg.pmu.windows,
            leg.pmu.unavailable
        );
    }
    for n in &report.not_run {
        println!("{} [{}]: NOT_RUN: {}", n.leg, n.affinity.code(), n.reason);
    }
    Ok(())
}

fn pmu_verify(args: &[String]) -> Result<(), String> {
    let opts = parse_pairs(args, &["--evidence"])?;
    let dir = opts
        .last()
        .map(|(_, v)| PathBuf::from(v))
        .ok_or("missing --evidence")?;
    let report = synapse_bench::pmu_diag::verify_evidence(&dir).map_err(|e| e.to_string())?;
    println!(
        "verified: report.json recomputed byte for byte from protocol.json ({}) and raw.json ({}); every PMU reading matches the recorded discovery and counter contract; every file in SHA256SUMS matches. Consistency only: authenticity comes from git history and review.",
        report.protocol_sha256, report.raw_sha256
    );
    Ok(())
}

/// Write the J3 vector corpus from the Rust crates; refuses to overwrite.
fn crypto_vectors_write(args: &[String]) -> Result<(), String> {
    use std::io::Write;
    use synapse_bench::crypto_vectors as cv;
    let opts = parse_pairs(args, &["--out"])?;
    let out = opts
        .last()
        .map(|(_, v)| PathBuf::from(v))
        .ok_or("missing --out")?;
    let vectors = cv::rust_corpus();
    let bytes = cv::encode(&vectors);
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&out)
        .map_err(|e| format!("create {} (never overwritten): {e}", out.display()))?;
    f.write_all(&bytes)
        .and_then(|_| f.sync_all())
        .map_err(|e| format!("write {}: {e}", out.display()))?;
    println!("{} records, {} bytes", vectors.len(), bytes.len());
    Ok(())
}

/// Decode a J3 corpus and recompute every record with the Rust crates.
fn crypto_vectors_verify(args: &[String]) -> Result<(), String> {
    use synapse_bench::crypto_vectors as cv;
    let opts = parse_pairs(args, &["--corpus"])?;
    let path = opts
        .last()
        .map(|(_, v)| PathBuf::from(v))
        .ok_or("missing --corpus")?;
    let bytes = std::fs::read(&path).map_err(|e| format!("read {}: {e}", path.display()))?;
    let vectors = cv::decode(&bytes).map_err(|e| format!("refused: {e}"))?;
    cv::check_against_rust_crates(&vectors)
        .map_err(|m| format!("record {}: {}", m.index, m.detail))?;
    println!(
        "verified: {} records decode and every digest and verdict equals the Rust crates' answer",
        vectors.len()
    );
    Ok(())
}

/// C1 (ADR 0003 step 4): shared Merkle tree parity, cold build and warm paging times, and the
/// cache bound on the Gate 4 query population (see `synapse_bench::c1`).
fn c1(args: &[String]) -> Result<(), String> {
    let opts = parse_pairs(
        args,
        &[
            "--clone",
            "--base",
            "--work-dir",
            "--out",
            "--seed",
            "--rep",
            "--agents",
            "--ops-per-agent",
            "--samples",
            "--cache-bytes",
            "--skip-parity",
        ],
    )?;
    let get = |k: &str| {
        opts.iter()
            .rev()
            .find(|(key, _)| key == k)
            .map(|(_, v)| v.clone())
    };
    let num = |k: &str, d: u64| -> Result<u64, String> {
        get(k).map_or(Ok(d), |v| parse_u64(&v).ok_or(format!("invalid {k}")))
    };
    let spec = synapse_bench::c1::C1Spec {
        clone_dir: PathBuf::from(get("--clone").ok_or("missing --clone")?),
        base_commit: get("--base").ok_or("missing --base")?,
        seed: num("--seed", synapse_bench::orchestrator::DEFAULT_SEED)?,
        rep: num("--rep", 0)? as usize,
        agents: num("--agents", 8)? as usize,
        ops_per_agent: num("--ops-per-agent", 50)? as usize,
        samples: num("--samples", 400)? as usize,
        cache_bytes: num(
            "--cache-bytes",
            synapse_api::DEFAULT_TREE_CACHE_BYTES as u64,
        )? as usize,
        work_dir: PathBuf::from(get("--work-dir").ok_or("missing --work-dir")?),
        out_dir: PathBuf::from(get("--out").ok_or("missing --out")?),
        skip_parity: get("--skip-parity").is_some_and(|v| v == "1" || v == "true"),
    };
    let r = synapse_bench::c1::run_c1(&spec)?;
    for p in &r.parity {
        println!(
            "parity: {} trees, {} entries, {} mismatched: {}",
            p.compared_trees, p.compared_entries, p.mismatched_trees, p.check
        );
    }
    for ph in &r.phases {
        println!(
            "{}: n={} built={} p50={:?} ms bound_p50={:?} ms fraction_p50={:?}",
            ph.phase,
            ph.samples,
            ph.samples_that_built,
            ph.latency.as_ref().map(|l| l.p50_ms),
            ph.bound_ms_p50,
            ph.fraction_of_bound_p50
        );
    }
    println!(
        "cache: bound {} B, high water {} B, held {}; peak RSS {} KiB",
        r.cache_after.max_bytes,
        r.cache_after.high_water_bytes,
        r.cache_bound_held,
        r.peak_rss_self_kib
    );
    Ok(())
}

/// `segments`: ADR 0003 A2 segment store measurement (raw samples to `--out`).
fn segments(args: &[String]) -> Result<(), String> {
    let opts = parse_pairs(
        args,
        &[
            "--dir",
            "--out",
            "--agents",
            "--changes",
            "--reps",
            "--blob-bytes",
            "--segment-mib",
            "--checkpoint-every",
            "--idle-window-s",
            "--block-device",
            "--block-device-mib",
            "--block-meta-mib",
        ],
    )?;
    let get = |k: &str| {
        opts.iter()
            .rev()
            .find(|(key, _)| key == k)
            .map(|(_, v)| v.clone())
    };
    let num = |k: &str, d: u64| -> Result<u64, String> {
        get(k).map_or(Ok(d), |v| v.parse().map_err(|_| format!("invalid {k}")))
    };
    let cfg = synapse_bench::segments::SegmentsConfig {
        agents: parse_list(&get("--agents").unwrap_or_else(|| "1,4,8,32".into()), |x| {
            x.parse().ok().filter(|n| *n > 0)
        })?,
        changes: num("--changes", 4000)? as usize,
        reps: num("--reps", 3)? as usize,
        blob_bytes: num("--blob-bytes", 11_949)? as usize,
        segment_bytes: num("--segment-mib", 16)? * 1024 * 1024,
        checkpoint_every: num("--checkpoint-every", 1000)? as usize,
        idle_window_s: num("--idle-window-s", 30)?,
        block_device: get("--block-device"),
        block_device_bytes: num(
            "--block-device-mib",
            synapse_bench::segments::DEFAULT_BLOCK_DEVICE_BYTES >> 20,
        )? << 20,
        block_meta_bytes: num(
            "--block-meta-mib",
            synapse_bench::segments::DEFAULT_BLOCK_META_BYTES >> 20,
        )? << 20,
    };
    let dir = PathBuf::from(get("--dir").ok_or("missing --dir")?);
    let out = PathBuf::from(get("--out").ok_or("missing --out")?);
    let raw = synapse_bench::segments::run_segments(&dir, &cfg)?;
    synapse_bench::write_json(&out, &raw)
}

/// R1 store repair (issue #105). Without an action flag it only reports (read-only open)
/// and never writes. A write needs exactly one of `--roll-forward` or
/// `--adopt-older-checkpoint`, plus `--operator-key <file>` (64 hex characters: the
/// Ed25519 seed that signs the repair entry) and `--backup <new file>` (every byte range
/// the repair overwrites is saved there first). Prints the signed receipt.
fn store_repair(args: &[String]) -> Result<(), String> {
    use synapse_store::blockdev::repair::{diagnose_path, repair_path, RepairAction};
    let flags = [
        ("--roll-forward", RepairAction::RollForward),
        (
            "--adopt-older-checkpoint",
            RepairAction::AdoptOlderCheckpoint,
        ),
    ];
    let actions: Vec<RepairAction> = flags
        .iter()
        .filter(|(f, _)| args.iter().any(|a| a == f))
        .map(|(_, a)| *a)
        .collect();
    let rest: Vec<String> = args
        .iter()
        .filter(|a| !flags.iter().any(|(f, _)| f == a))
        .cloned()
        .collect();
    let opts = parse_pairs(&rest, &["--device", "--backup", "--operator-key"])?;
    let get = |k: &str| {
        opts.iter()
            .rev()
            .find(|(key, _)| key == k)
            .map(|(_, v)| PathBuf::from(v))
    };
    let device = get("--device").ok_or("missing --device (absolute path)")?;
    let action = match actions[..] {
        [] => {
            print!("{}", diagnose_path(&device).map_err(|e| e.to_string())?);
            return Ok(());
        }
        [a] => a,
        _ => return Err("give one action: --roll-forward or --adopt-older-checkpoint".into()),
    };
    let backup = get("--backup").ok_or("a repair needs --backup <new file>")?;
    let key_path = get("--operator-key").ok_or("a repair needs --operator-key <file>")?;
    let key_hex = std::fs::read_to_string(&key_path)
        .map_err(|e| format!("operator key {}: {e}", key_path.display()))?;
    let seed: [u8; 32] = hex::decode(key_hex.trim())
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or("the operator key file must hold 64 hex characters (an Ed25519 seed)")?;
    let operator = ed25519_dalek::SigningKey::from_bytes(&seed);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let receipt =
        repair_path(&device, action, &operator, &backup, now).map_err(|e| e.to_string())?;
    print!("{}", receipt.report);
    println!("{receipt}");
    if receipt.wrote {
        println!("backup at {}", backup.display());
    }
    Ok(())
}

/// `segments-report`: recompute the A2 report from `--raw` and a `--floor` report.
fn segments_report(args: &[String]) -> Result<(), String> {
    use std::io::Write;
    let opts = parse_pairs(args, &["--raw", "--floor"])?;
    let get = |k: &str| {
        opts.iter()
            .rev()
            .find(|(key, _)| key == k)
            .map(|(_, v)| PathBuf::from(v))
            .ok_or(format!("missing {k}"))
    };
    let raw: synapse_bench::segments::SegmentsRaw = synapse_bench::read_json(&get("--raw")?)?;
    let floor: synapse_bench::floor::FloorReport = synapse_bench::read_json(&get("--floor")?)?;
    let report = synapse_bench::segments::segments_report(&raw, &floor)?;
    let bytes = serde_json::to_vec_pretty(&report).map_err(|e| e.to_string())?;
    std::io::stdout()
        .write_all(&bytes)
        .map_err(|e| format!("write stdout: {e}"))
}

/// ADR 0003 X6 (G2): `x6 --corpus <dir of bare clones> --out <raw.json> [--dir <scratch>]
/// [--reps 3] [--idle-window-s 10] [--only K1,C0]`. Progress goes to stderr.
fn x6(args: &[String]) -> Result<(), String> {
    let opts = parse_pairs(
        args,
        &[
            "--corpus",
            "--out",
            "--dir",
            "--reps",
            "--idle-window-s",
            "--only",
        ],
    )?;
    let get = |k: &str| {
        opts.iter()
            .rev()
            .find(|(key, _)| key == k)
            .map(|(_, v)| v.clone())
    };
    let corpus = PathBuf::from(get("--corpus").ok_or("missing --corpus")?);
    let out = PathBuf::from(get("--out").ok_or("missing --out")?);
    let scratch = get("--dir")
        .map(PathBuf::from)
        .unwrap_or_else(synapse_bench::x6::default_scratch);
    let reps: usize = get("--reps")
        .map_or(Ok(3), |v| v.parse())
        .map_err(|_| "invalid --reps")?;
    let idle: u64 = get("--idle-window-s")
        .map_or(Ok(10), |v| v.parse())
        .map_err(|_| "invalid --idle-window-s")?;
    let only: Option<Vec<String>> = get("--only").map(|v| v.split(',').map(String::from).collect());
    std::fs::create_dir_all(&scratch).map_err(|e| format!("create {}: {e}", scratch.display()))?;
    let raw =
        synapse_bench::x6::run_x6(&corpus, &scratch, reps, idle, only.as_deref(), &mut |m| {
            eprintln!("{m}")
        })?;
    let bytes = serde_json::to_vec(&raw).map_err(|e| e.to_string())?;
    std::fs::write(&out, bytes).map_err(|e| format!("write {}: {e}", out.display()))
}

/// `x6-report --raw <raw.json>`: the RULE.md section 6 decision as JSON on stdout.
fn x6_report(args: &[String]) -> Result<(), String> {
    use std::io::Write;
    let opts = parse_pairs(args, &["--raw"])?;
    let raw_path = opts
        .iter()
        .rev()
        .find(|(k, _)| k == "--raw")
        .map(|(_, v)| PathBuf::from(v))
        .ok_or("missing --raw")?;
    let raw: synapse_bench::x6::X6Raw = synapse_bench::read_json(&raw_path)?;
    let report = synapse_bench::x6::decide(&raw);
    let bytes = serde_json::to_vec_pretty(&report).map_err(|e| e.to_string())?;
    std::io::stdout()
        .write_all(&bytes)
        .map_err(|e| format!("write stdout: {e}"))
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let outcome = match args.first().map(String::as_str) {
        Some("run") => run(&args[1..]),
        Some("child") => child(&args[1..]),
        Some("floor") => floor(&args[1..]),
        Some("c1") => c1(&args[1..]),
        Some("bounds") => bounds(&args[1..]),
        Some("bounds-verify") => bounds_verify(&args[1..]),
        Some("bounds-report") => bounds_report(&args[1..]),
        Some("pmu-diag") => pmu_diag(&args[1..]),
        Some("pmu-verify") => pmu_verify(&args[1..]),
        Some("crypto-vectors-write") => crypto_vectors_write(&args[1..]),
        Some("crypto-vectors-verify") => crypto_vectors_verify(&args[1..]),
        Some("segments") => segments(&args[1..]),
        Some("segments-report") => segments_report(&args[1..]),
        Some("x6") => x6(&args[1..]),
        Some("x6-report") => x6_report(&args[1..]),
        Some("store-repair") => store_repair(&args[1..]),
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
