//! Run the in-repository coverage-guided fuzzer on the wire frame decoder.
//!
//! ```text
//! synapse-wire-fuzz --out DIR [--seconds N | --execs N] [--seed S] [--cap BYTES]
//! ```
//!
//! Writes `DIR/spec.json` (budget, seed, cap, revision) before the first execution, then
//! `DIR/result.json` and `DIR/corpus.bin` (every input that reached new coverage, replayed
//! afterwards without instrumentation: each must be a canonical frame or a typed refusal).
//! Exits non-zero on any violation.

use std::path::PathBuf;
use std::process::ExitCode;
use synapse_wire::frame::WireLimits;
use synapse_wire::fuzz::{
    corpus_to_bytes, malformed_seed_corpus, replay_corpus, run, seed_corpus, Budget, CountingAlloc,
    FuzzConfig,
};

#[global_allocator]
static ALLOC: CountingAlloc = CountingAlloc;

fn usage() -> ExitCode {
    eprintln!(
        "usage: synapse-wire-fuzz --out DIR [--seconds N | --execs N] [--seed S] [--cap BYTES]"
    );
    ExitCode::from(2)
}

fn git_rev() -> String {
    std::process::Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|| "unknown".into())
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut out: Option<PathBuf> = None;
    let mut budget = Budget::Seconds(60.0);
    let mut seed = 0x5EED_6100_u64;
    let mut cap = 8192u32;
    let mut i = 0;
    while i < args.len() {
        let val = args.get(i + 1);
        match (args[i].as_str(), val) {
            ("--out", Some(v)) => out = Some(PathBuf::from(v)),
            ("--seconds", Some(v)) => match v.parse() {
                Ok(s) => budget = Budget::Seconds(s),
                Err(_) => return usage(),
            },
            ("--execs", Some(v)) => match v.parse() {
                Ok(n) => budget = Budget::Execs(n),
                Err(_) => return usage(),
            },
            ("--seed", Some(v)) => match v.parse() {
                Ok(s) => seed = s,
                Err(_) => return usage(),
            },
            ("--cap", Some(v)) => match v.parse() {
                Ok(c) => cap = c,
                Err(_) => return usage(),
            },
            _ => return usage(),
        }
        i += 2;
    }
    let Some(out) = out else { return usage() };
    if let Err(e) = std::fs::create_dir_all(&out) {
        eprintln!("cannot create {}: {e}", out.display());
        return ExitCode::from(2);
    }
    let limits = WireLimits {
        max_frame_body: cap,
    };
    let mut seeds = seed_corpus(&limits);
    let valid_seeds = seeds.len();
    seeds.extend(malformed_seed_corpus(&limits));
    let (budget_kind, budget_value) = match budget {
        Budget::Execs(n) => ("execs", n as f64),
        Budget::Seconds(s) => ("seconds", s),
    };
    let spec = serde_json::json!({
        "tool": "synapse-wire-fuzz",
        "kind": "in-repository coverage-guided mutation fuzzer (edge feedback from instrumented frame-decoder states)",
        "target": "synapse_wire::frame::decode_frame, then synapse_store::codec::decode_envelope on Submit payloads",
        "budget_kind": budget_kind,
        "budget_value": budget_value,
        "seed": seed,
        "max_frame_body": cap,
        "seed_inputs": seeds.len(),
        "valid_seed_inputs": valid_seeds,
        "git_rev": git_rev(),
        "declared_before_run": true,
    });
    let write = |name: &str, bytes: &[u8]| -> Result<(), ExitCode> {
        std::fs::write(out.join(name), bytes).map_err(|e| {
            eprintln!("cannot write {name}: {e}");
            ExitCode::from(2)
        })
    };
    let spec_text = serde_json::to_string_pretty(&spec).expect("json") + "\n";
    if let Err(c) = write("spec.json", spec_text.as_bytes()) {
        return c;
    }
    eprintln!("spec written; fuzzing ({budget_kind} {budget_value}, seed {seed}, cap {cap})");

    let report = run(
        FuzzConfig {
            seed,
            budget,
            limits,
            max_corpus: 50_000,
        },
        &seeds,
    );
    let replay = replay_corpus(&report.corpus, &limits);
    let result = serde_json::json!({
        "execs": report.execs,
        "elapsed_s": report.elapsed_s,
        "execs_per_s": report.execs as f64 / report.elapsed_s.max(1e-9),
        "edges": report.edges,
        "instrumented_sites": report.sites_total,
        "sites_unreached_lines": report.sites_unreached,
        "corpus_entries": report.corpus.len(),
        "corpus_found_at_execs": report.corpus_found_at,
        "largest_input_bytes": report.largest_input,
        "alloc_tracking_installed": report.alloc_tracking,
        "peak_single_alloc_bytes": report.peak_alloc,
        "peak_total_alloc_per_decode_bytes": report.peak_alloc_total,
        "outcomes": report.outcomes,
        "violation_total": report.violation_total(),
        "violation_counts": report.violation_counts,
        "violations": report.violations.iter().map(|v| serde_json::json!({
            "kind": v.kind, "detail": v.detail, "input_hex": hex(&v.input),
        })).collect::<Vec<_>>(),
        "corpus_replay": {
            "entries": replay.entries,
            "accepted_canonical": replay.accepted_canonical,
            "refused_by_kind": replay.refused,
            "violations": replay.violations,
            "peak_single_alloc_bytes": replay.peak_alloc,
        },
    });
    let result_text = serde_json::to_string_pretty(&result).expect("json") + "\n";
    if let Err(c) = write("result.json", result_text.as_bytes()) {
        return c;
    }
    if let Err(c) = write("corpus.bin", &corpus_to_bytes(&report.corpus)) {
        return c;
    }
    eprintln!(
        "execs {} in {:.1} s, edges {}, sites {}/{}, corpus {}, violations {}, replay violations {}",
        report.execs,
        report.elapsed_s,
        report.edges,
        report.sites_total - report.sites_unreached.len(),
        report.sites_total,
        report.corpus.len(),
        report.violation_total(),
        replay.violations.len()
    );
    if report.violation_total() == 0 && replay.violations.is_empty() && report.alloc_tracking {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
