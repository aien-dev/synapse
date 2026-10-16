//! G1 transport measurement: seconds and joules per accepted change across the wire
//! transport (Unix socket, binary frames, have-want negotiation), against the ADR 0003
//! section 6 bound for one durable change (`docs/PHASE5_GROUP_COMMIT.md` section 5).
//!
//! ```text
//! wire-transport --out DIR [--changes N] [--reps R] [--idle-s S] [--store-root DIR]
//! ```
//!
//! Three arms per repetition, order rotated, each on a fresh store directory with
//! `GROUP_COMMIT_DEFAULT` and one agent submitting one change at a time:
//! * `wire`: client and server threads joined by a Unix socket; per change Have, Want,
//!   Chunk (only the blobs the server lacks), Submit, Accepted after durable commit.
//! * `direct_auth`: the same chain authorisation and store admission in process, no
//!   transport (isolates framing and socket cost).
//! * `direct`: store admission only (no chain check).
//!
//! Every change upserts one new 3,967-byte blob (the Gate 4 median new content per change)
//! and one blob shared by every change (sent once, then skipped by negotiation).
//! Envelopes and requests are signed before timing starts. `spec.json` is written before
//! the first change; `result.json` holds every per-change latency in nanoseconds.

use serde_json::json;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::{Duration, Instant};
use synapse_auth::{BoundaryKind, Capability, ChainedRequest, PolicyEnforcer};
use synapse_bench::energy::{idle_window, EnergyReading, EnergyWindow};
use synapse_core::{BlobDigest, ChangesetEnvelope, WalSeq};
use synapse_store::{FsyncPolicy, RecoveryPolicy, SharedStore, StoreLimits};
use synapse_wire::session::submit_request;
use synapse_wire::testkit::{envelope, repo, server, ChainFixture, FIXTURE_NOW_MS};
use synapse_wire::{WireClient, WireLimits};

/// Bound inputs, `docs/PHASE5_GROUP_COMMIT.md` section 5 (W1 floor, one agent).
const FLUSH_FLOOR_S: f64 = 0.805e-3;
const SEQ_WRITE_S_PER_GIB: f64 = 0.138;
const FLOOR_BYTES_PER_CHANGE: f64 = 11_500.0;
const IDLE_W_FLOOR: f64 = 22.731;
const ESSENTIAL_CPU_J: f64 = 0.2766e-3;
/// Gate 4 median new content per change, bytes.
const NEW_BLOB_BYTES: usize = 3_967;

struct Change {
    env: ChangesetEnvelope,
    req: ChainedRequest,
    blobs: Vec<(BlobDigest, Vec<u8>)>,
}

fn blob(seed: u64, len: usize) -> Vec<u8> {
    let mut x = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x >> 24) as u8
        })
        .collect()
}

fn build_changes(fx: &ChainFixture, rep: usize, n: usize, shared: &[u8]) -> Vec<Change> {
    (0..n)
        .map(|i| {
            let new = blob((rep as u64) << 32 | i as u64, NEW_BLOB_BYTES);
            let path = format!("src/r{rep}/c{i:05}.rs");
            let shared_path = format!("src/r{rep}/shared{i:05}.rs");
            let (env, blobs) = envelope(
                &fx.agent,
                &format!("wire-{rep}-{i}"),
                &[(&path, new), (&shared_path, shared.to_vec())],
                &[],
                1_000 + i as u64,
            );
            let mut nonce = [0u8; 32];
            nonce[..8].copy_from_slice(&(rep as u64).to_le_bytes());
            nonce[8..16].copy_from_slice(&(i as u64).to_le_bytes());
            let req = submit_request(&fx.agent, fx.chain.clone(), &env, nonce, 1_000 + i as u64)
                .expect("request");
            Change { env, req, blobs }
        })
        .collect()
}

fn open(dir: &Path) -> Arc<SharedStore> {
    let _ = std::fs::remove_dir_all(dir);
    std::fs::create_dir_all(dir).expect("store dir");
    Arc::new(
        SharedStore::open(
            dir,
            FsyncPolicy::GROUP_COMMIT_DEFAULT,
            RecoveryPolicy::StrictFailClosed,
            StoreLimits::default(),
        )
        .expect("open store"),
    )
}

/// Per repetition: seconds per change, package joules per change, above-idle joules.
type RepFigures = (f64, Option<f64>, f64);

struct ArmRun {
    latencies_ns: Vec<u64>,
    elapsed_s: f64,
    energy: EnergyReading,
    wire_bytes_sent: u64,
    wire_bytes_received: u64,
    chunks_sent: u64,
    chunk_bytes_sent: u64,
}

fn run_wire(fx: &ChainFixture, dir: &Path, changes: &[Change]) -> ArmRun {
    let store = open(dir);
    let srv = server(fx, store.clone());
    let (a, b) = UnixStream::pair().expect("socket pair");
    let s = srv.clone();
    let t = std::thread::spawn(move || s.serve(b));
    let mut client = WireClient::connect(a, WireLimits::default()).expect("connect");
    let (s0, r0) = client.bytes();
    let mut lat = Vec::with_capacity(changes.len());
    let (mut chunks, mut chunk_bytes) = (0u64, 0u64);
    let w = EnergyWindow::start();
    let start = Instant::now();
    for c in changes {
        let t0 = Instant::now();
        let rep = client.submit(&c.req, &c.blobs).expect("accepted");
        lat.push(t0.elapsed().as_nanos() as u64);
        assert!(!rep.accepted.duplicate);
        chunks += rep.wanted as u64;
        chunk_bytes += rep.chunk_bytes_sent;
    }
    let elapsed_s = start.elapsed().as_secs_f64();
    let energy = w.finish();
    let (s1, r1) = client.bytes();
    drop(client);
    t.join().expect("server thread").expect("server");
    ArmRun {
        latencies_ns: lat,
        elapsed_s,
        energy,
        wire_bytes_sent: s1 - s0,
        wire_bytes_received: r1 - r0,
        chunks_sent: chunks,
        chunk_bytes_sent: chunk_bytes,
    }
}

fn run_direct(fx: &ChainFixture, dir: &Path, changes: &[Change], auth: bool) -> ArmRun {
    let store = open(dir);
    let mut enforcer: PolicyEnforcer = fx.enforcer();
    let mut lat = Vec::with_capacity(changes.len());
    let w = EnergyWindow::start();
    let start = Instant::now();
    for c in changes {
        let t0 = Instant::now();
        if auth {
            let seq = WalSeq(store.read().committed_seq().0 + 1);
            enforcer
                .authorize_chain(
                    BoundaryKind::Api,
                    "wire_submit",
                    &repo(),
                    Capability::Propose,
                    &c.req,
                    seq,
                    FIXTURE_NOW_MS,
                )
                .expect("authorized");
        }
        store.submit(c.env.clone(), &c.blobs).expect("committed");
        lat.push(t0.elapsed().as_nanos() as u64);
    }
    let elapsed_s = start.elapsed().as_secs_f64();
    let energy = w.finish();
    ArmRun {
        latencies_ns: lat,
        elapsed_s,
        energy,
        wire_bytes_sent: 0,
        wire_bytes_received: 0,
        chunks_sent: 0,
        chunk_bytes_sent: 0,
    }
}

fn nearest_rank(sorted: &[u64], q: f64) -> u64 {
    let rank = (q * sorted.len() as f64).ceil() as usize;
    sorted[rank.clamp(1, sorted.len()) - 1]
}

fn median(v: &mut [f64]) -> f64 {
    v.sort_by(|a, b| a.total_cmp(b));
    v[v.len() / 2]
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

fn usage() -> ExitCode {
    eprintln!(
        "usage: wire-transport --out DIR [--changes N] [--reps R] [--idle-s S] [--store-root DIR]"
    );
    ExitCode::from(2)
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (mut out, mut changes_n, mut reps, mut idle_s) = (None, 2000usize, 3usize, 30u64);
    let mut store_root = PathBuf::from("target/wire-transport-stores");
    let mut i = 0;
    while i < args.len() {
        let Some(v) = args.get(i + 1) else {
            return usage();
        };
        match args[i].as_str() {
            "--out" => out = Some(PathBuf::from(v)),
            "--changes" => match v.parse() {
                Ok(n) => changes_n = n,
                Err(_) => return usage(),
            },
            "--reps" => match v.parse() {
                Ok(n) => reps = n,
                Err(_) => return usage(),
            },
            "--idle-s" => match v.parse() {
                Ok(n) => idle_s = n,
                Err(_) => return usage(),
            },
            "--store-root" => store_root = PathBuf::from(v),
            _ => return usage(),
        }
        i += 2;
    }
    let Some(out) = out else { return usage() };
    if changes_n == 0 || reps == 0 {
        return usage();
    }
    std::fs::create_dir_all(&out).expect("out dir");
    std::fs::create_dir_all(&store_root).expect("store root");
    let t_floor =
        FLUSH_FLOOR_S + FLOOR_BYTES_PER_CHANGE * SEQ_WRITE_S_PER_GIB / (1u64 << 30) as f64;
    let e_floor = IDLE_W_FLOOR * t_floor + ESSENTIAL_CPU_J;
    let arms = ["wire", "direct_auth", "direct"];
    let spec = json!({
        "tool": "wire-transport",
        "step": "G1",
        "git_rev": git_rev(),
        "changes_per_arm": changes_n,
        "reps": reps,
        "arms": arms,
        "order": "rotated per repetition",
        "agents": 1,
        "fsync_policy": "GROUP_COMMIT_DEFAULT",
        "chain_depth": 2,
        "per_change": {"new_blob_bytes": NEW_BLOB_BYTES, "shared_blob_bytes": NEW_BLOB_BYTES, "paths": 2},
        "transport": "std::os::unix::net::UnixStream pair, client and server threads in one process",
        "store_root": store_root.display().to_string(),
        "idle_window_s": idle_s,
        "bound": {
            "source": "docs/PHASE5_GROUP_COMMIT.md section 5 (ADR 0003 section 6 durable latency for one change)",
            "t_floor_s": t_floor,
            "t_floor_formula": "0.805 ms + 11500 B x 0.138 s/GiB",
            "e_floor_j": e_floor,
            "e_floor_formula": "22.731 W x t_floor + 0.2766 mJ",
            "fraction": "floor / measured (1.0 = at the floor)",
        },
        "energy_sensor": "aien_spbm hwmon: SoC package only, uncalibrated; NVMe UNMEASURED",
        "declared_before_run": true,
    });
    std::fs::write(
        out.join("spec.json"),
        serde_json::to_string_pretty(&spec).expect("json") + "\n",
    )
    .expect("write spec");
    eprintln!("spec written; idle window {idle_s} s");
    let idle = idle_window(Duration::from_secs(idle_s));

    let fx = ChainFixture::new(2, None);
    let shared = blob(0xFEED, NEW_BLOB_BYTES);
    let mut runs: Vec<serde_json::Value> = Vec::new();
    let mut per_arm: std::collections::BTreeMap<&str, Vec<RepFigures>> = Default::default();
    for rep in 0..reps {
        for k in 0..arms.len() {
            let arm = arms[(k + rep) % arms.len()];
            let changes = build_changes(&fx, rep, changes_n, &shared);
            let dir = store_root.join(format!("{arm}-{rep}"));
            let r = match arm {
                "wire" => run_wire(&fx, &dir, &changes),
                "direct_auth" => run_direct(&fx, &dir, &changes, true),
                _ => run_direct(&fx, &dir, &changes, false),
            };
            let _ = std::fs::remove_dir_all(&dir);
            let mut s = r.latencies_ns.clone();
            s.sort_unstable();
            let n = s.len() as f64;
            let s_per_change = r.elapsed_s / n;
            let j_per_change = r.energy.pkg_j.map(|j| j / n);
            let above_idle = r.energy.pkg_above_idle_j(&idle).map(|j| j / n);
            per_arm.entry(arm).or_default().push((
                s_per_change,
                j_per_change,
                above_idle.unwrap_or(f64::NAN),
            ));
            eprintln!(
                "rep {rep} {arm}: {:.3} ms/change, p50 {:.3} ms, {:?} J/change",
                s_per_change * 1e3,
                nearest_rank(&s, 0.5) as f64 / 1e6,
                j_per_change
            );
            runs.push(json!({
                "rep": rep,
                "arm": arm,
                "changes": s.len(),
                "elapsed_s": r.elapsed_s,
                "s_per_change": s_per_change,
                "p50_s": nearest_rank(&s, 0.50) as f64 / 1e9,
                "p99_s": nearest_rank(&s, 0.99) as f64 / 1e9,
                "max_s": s[s.len() - 1] as f64 / 1e9,
                "pkg_j_per_change": j_per_change,
                "pkg_above_idle_j_per_change": above_idle,
                "wire_bytes_sent_per_change": r.wire_bytes_sent as f64 / n,
                "wire_bytes_received_per_change": r.wire_bytes_received as f64 / n,
                "chunks_sent": r.chunks_sent,
                "chunk_bytes_sent": r.chunk_bytes_sent,
                "energy": r.energy,
                "latencies_ns": r.latencies_ns,
            }));
        }
    }
    let mut summary = serde_json::Map::new();
    for (arm, v) in &per_arm {
        let mut s: Vec<f64> = v.iter().map(|x| x.0).collect();
        let mut j: Vec<f64> = v.iter().filter_map(|x| x.1).collect();
        let mut a: Vec<f64> = v.iter().map(|x| x.2).filter(|x| x.is_finite()).collect();
        let s_med = median(&mut s);
        let j_med = (!j.is_empty()).then(|| median(&mut j));
        summary.insert(
            arm.to_string(),
            json!({
                "s_per_change_median": s_med,
                "s_per_change_reps": v.iter().map(|x| x.0).collect::<Vec<_>>(),
                "fraction_of_time_floor": t_floor / s_med,
                "pkg_j_per_change_median": j_med,
                "fraction_of_energy_floor": j_med.map(|j| e_floor / j),
                "pkg_above_idle_j_per_change_median": (!a.is_empty()).then(|| median(&mut a)),
            }),
        );
    }
    let result = json!({
        "spec": spec,
        "idle": idle,
        "summary": summary,
        "runs": runs,
    });
    std::fs::write(
        out.join("result.json"),
        serde_json::to_string_pretty(&result).expect("json") + "\n",
    )
    .expect("write result");
    eprintln!("{}", serde_json::to_string_pretty(&summary).expect("json"));
    ExitCode::SUCCESS
}
