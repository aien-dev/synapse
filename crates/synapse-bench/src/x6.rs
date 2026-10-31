//! ADR 0003 experiment X6 (step G2, issue #45): content-defined chunking threshold and
//! chunk sizes on real AIEN repository histories.
//!
//! Everything this module does is fixed in `evidence/g2-content-defined-chunking/x6/
//! RULE.md`, committed before the runs: the eight configurations, the corpus (one
//! accepted change per first-parent commit that adds or modifies a regular file, bytes
//! provided the first time a blob appears), the measurements (ingest phase: per-change
//! latency, wall time, one energy window, log bytes; read phase: every distinct blob once
//! with a byte comparison, per-read time, one energy window), three repetitions with the
//! configuration order rotated by one per repetition, and the decision criterion
//! ([`decide`]). Joules come only from the `aien_spbm` package meter; a refused window
//! leaves them `None` with the reason (`INSTRUMENT_UNAVAILABLE`), never a substitute.

use crate::energy::{idle_window, EnergyReading, EnergyWindow};
use crate::stats::{summarize_us, LatencySummary};
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use synapse_core::{
    BlobDigest, ChangesetEnvelope, FileMode, GitOid, IdempotencyKey, MutationOp, PathMutation,
    RepoId, SYNAPSE_ENVELOPE_VERSION,
};
use synapse_store::{
    ChunkParams, FsyncPolicy, IngestOutcome, RecoveryPolicy, SharedStore, StoreLimits,
};

/// A2 flush bound, seconds: `evidence/a2-segment-store/measurement/floor.json`, cheapest
/// `overwrite_*_fdatasync` p50 (`overwrite_64k_fdatasync`), as fixed in RULE.md section 4.
pub const A2_FLUSH_BOUND_S: f64 = 1.006e-3;
/// Memory bandwidth, bytes per second (NVIDIA DGX Spark specification, A0).
pub const MEMORY_BW_BPS: f64 = 273e9;

/// The corpus repositories and commits of RULE.md section 3, in order.
pub const CORPUS: [(&str, &str); 4] = [
    (
        "aien-architecture",
        "d2768e9b8730af5f13c0fbbdfbfa4ba788f7605a",
    ),
    ("aienos", "b7ebf7cde234e1ddcc91eb8fcaf378d060cfb3a2"),
    ("omega", "43d8d20da2f64319bcf6196ac7204021c3f280eb"),
    ("synapse", "b9f46b16aa74301f0b330cfb5fa2e06f07d60b43"),
];

/// The eight configurations of RULE.md section 2.
pub fn configurations() -> Vec<(&'static str, ChunkParams)> {
    const K: u64 = 1024;
    vec![
        ("C0", ChunkParams::OFF),
        ("K1", ChunkParams::candidate(16 * K, 4 * 1024)),
        ("K2", ChunkParams::candidate(16 * K, 8 * 1024)),
        ("K3", ChunkParams::candidate(64 * K, 8 * 1024)),
        ("K4", ChunkParams::candidate(64 * K, 16 * 1024)),
        ("K5", ChunkParams::candidate(64 * K, 32 * 1024)),
        ("K6", ChunkParams::candidate(256 * K, 16 * 1024)),
        ("K7", ChunkParams::candidate(256 * K, 64 * 1024)),
    ]
}

/// A signed changeset and the blob bytes it provides.
pub type SignedChange = (ChangesetEnvelope, Vec<(BlobDigest, Vec<u8>)>);

/// One file revision of a change: synthetic path, blob index, executable bit.
#[derive(Debug, Clone)]
pub struct FileRev {
    pub path: String,
    pub blob: usize,
    pub exec: bool,
}

/// The corpus in memory: changes in order and the distinct blobs they name.
#[derive(Debug)]
pub struct Corpus {
    pub changes: Vec<(String, String, Vec<FileRev>)>,
    pub blobs: Vec<Vec<u8>>,
    pub digests: Vec<BlobDigest>,
    pub revisions: usize,
    pub revision_bytes: u64,
}

fn git(dir: &Path, args: &[&str]) -> Result<Vec<u8>, String> {
    let out = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .output()
        .map_err(|e| format!("git: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "git {args:?} in {}: {}",
            dir.display(),
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    Ok(out.stdout)
}

/// Read the corpus from bare clones `<root>/<name>.git` (RULE.md section 3).
pub fn load_corpus(root: &Path) -> Result<Corpus, String> {
    let mut changes = Vec::new();
    let mut oid_index: HashMap<String, usize> = HashMap::new();
    let mut oids: Vec<String> = Vec::new();
    let mut paths: HashMap<(usize, String), usize> = HashMap::new();
    let mut revisions = 0usize;
    for (r, (name, commit)) in CORPUS.iter().enumerate() {
        let dir = root.join(format!("{name}.git"));
        let head = git(&dir, &["rev-parse", &format!("{commit}^{{commit}}")])?;
        if String::from_utf8_lossy(&head).trim() != *commit {
            return Err(format!("{name}: commit {commit} not found"));
        }
        let log = git(
            &dir,
            &[
                "log",
                "--reverse",
                "--first-parent",
                "--raw",
                "--no-renames",
                "--no-abbrev",
                "--format=commit %H",
                commit,
            ],
        )?;
        let mut current: Option<(String, Vec<FileRev>)> = None;
        let flush = |cur: Option<(String, Vec<FileRev>)>, changes: &mut Vec<_>| {
            if let Some((h, files)) = cur {
                if !files.is_empty() {
                    changes.push((name.to_string(), h, files));
                }
            }
        };
        for line in String::from_utf8_lossy(&log).lines() {
            if let Some(h) = line.strip_prefix("commit ") {
                flush(current.take(), &mut changes);
                current = Some((h.to_string(), Vec::new()));
                continue;
            }
            let Some(rest) = line.strip_prefix(':') else {
                continue;
            };
            let (meta, path) = rest.split_once('\t').ok_or("raw line without path")?;
            let f: Vec<&str> = meta.split(' ').collect();
            if f.len() != 5 {
                return Err(format!("unexpected raw line {line}"));
            }
            let (mode, oid, status) = (f[1], f[3], f[4]);
            if !(status.starts_with('A') || status.starts_with('M')) {
                continue;
            }
            if mode != "100644" && mode != "100755" {
                continue;
            }
            let next = paths.len();
            let pid = *paths.entry((r, path.to_string())).or_insert(next);
            let next = oids.len();
            let blob = *oid_index.entry(oid.to_string()).or_insert_with(|| {
                oids.push(oid.to_string());
                next
            });
            let files = &mut current.as_mut().ok_or("raw line before commit")?.1;
            files.push(FileRev {
                path: format!("p{pid}"),
                blob,
                exec: mode == "100755",
            });
            revisions += 1;
        }
        flush(current.take(), &mut changes);
    }
    // Blob contents through one `git cat-file --batch` per repository.
    let mut blobs: Vec<Option<Vec<u8>>> = vec![None; oids.len()];
    for (name, _) in CORPUS.iter() {
        let dir = root.join(format!("{name}.git"));
        let wanted: Vec<usize> = changes
            .iter()
            .filter(|(n, _, _)| n == name)
            .flat_map(|(_, _, f)| f.iter().map(|x| x.blob))
            .filter(|&b| blobs[b].is_none())
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect();
        let mut child = Command::new("git")
            .arg("-C")
            .arg(&dir)
            .args(["cat-file", "--batch"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .map_err(|e| format!("git cat-file: {e}"))?;
        let mut stdin = child.stdin.take().expect("piped");
        let list: String = wanted.iter().map(|&b| format!("{}\n", oids[b])).collect();
        let writer = std::thread::spawn(move || stdin.write_all(list.as_bytes()));
        let mut out = BufReader::new(child.stdout.take().expect("piped"));
        for &b in &wanted {
            let mut header = String::new();
            out.read_line(&mut header).map_err(|e| e.to_string())?;
            let h: Vec<&str> = header.trim_end().split(' ').collect();
            if h.len() != 3 || h[0] != oids[b] || h[1] != "blob" {
                return Err(format!("cat-file header {header:?} for {}", oids[b]));
            }
            let len: usize = h[2].parse().map_err(|_| "cat-file size")?;
            let mut bytes = vec![0u8; len + 1];
            out.read_exact(&mut bytes).map_err(|e| e.to_string())?;
            if bytes.pop() != Some(b'\n') {
                return Err("cat-file record without newline".into());
            }
            if GitOid::compute_blob(&bytes).to_hex() != oids[b] {
                return Err(format!("blob {} does not hash to its oid", oids[b]));
            }
            blobs[b] = Some(bytes);
        }
        writer.join().expect("writer").map_err(|e| e.to_string())?;
        child.wait().map_err(|e| e.to_string())?;
    }
    let blobs: Vec<Vec<u8>> = blobs
        .into_iter()
        .map(|b| b.ok_or("blob not read"))
        .collect::<Result<_, _>>()?;
    let revision_bytes = changes
        .iter()
        .flat_map(|(_, _, f)| f.iter().map(|x| blobs[x.blob].len() as u64))
        .sum();
    let digests = blobs.iter().map(|b| BlobDigest::compute(b)).collect();
    Ok(Corpus {
        changes,
        blobs,
        digests,
        revisions,
        revision_bytes,
    })
}

/// Signed changesets of the corpus, with the bytes of each blob attached only the first
/// time its `BlobDigest` appears (RULE.md section 3). Built once, outside every timed phase.
pub fn build_changesets(c: &Corpus) -> Vec<SignedChange> {
    let key = SigningKey::from_bytes(&[0x56; 32]);
    let mut seen = std::collections::HashSet::new();
    c.changes
        .iter()
        .map(|(repo, hash, files)| {
            let mut provided = Vec::new();
            // Envelopes require mutations in path order.
            let mut files: Vec<&FileRev> = files.iter().collect();
            files.sort_by(|a, b| a.path.cmp(&b.path));
            let mutations = files
                .into_iter()
                .map(|f| {
                    let d = c.digests[f.blob];
                    if seen.insert(d) {
                        provided.push((d, c.blobs[f.blob].clone()));
                    }
                    PathMutation {
                        path: f.path.clone(),
                        op: MutationOp::Upsert {
                            mode: if f.exec {
                                FileMode::Executable755
                            } else {
                                FileMode::Regular644
                            },
                            blob_digest: d,
                            size_bytes: c.blobs[f.blob].len() as u64,
                        },
                    }
                })
                .collect();
            let mut env = ChangesetEnvelope {
                version: SYNAPSE_ENVELOPE_VERSION,
                repo_id: RepoId::new(format!("aien-spark/{repo}")).expect("repo id"),
                base_git_oid: GitOid::compute_blob(hash.as_bytes()),
                parent_changesets: vec![],
                author_did: String::new(),
                idempotency_key: IdempotencyKey::from_label(&format!("x6-{repo}-{hash}")),
                created_at_ms: 1000,
                intent_summary: format!("{repo} {hash}"),
                mutations,
                evidence_receipts: vec![],
                signature: vec![],
            };
            env.sign(&key);
            (env, provided)
        })
        .collect()
}

/// Raw samples of one configuration in one repetition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunRaw {
    pub config: String,
    pub params: ChunkParams,
    pub rep: usize,
    pub position_in_rep: usize,
    pub accepted: usize,
    pub ingest_elapsed_ns: u64,
    pub ingest_latency_ns: Vec<u64>,
    pub ingest_energy: EnergyReading,
    /// Bytes appended to the segments during the ingest phase.
    pub log_bytes: u64,
    /// Whole blobs stored inline plus distinct chunks.
    pub content_bytes: u64,
    pub inline_blob_bytes: u64,
    pub chunks: usize,
    pub chunk_bytes: u64,
    pub chunked_blobs: usize,
    pub batches: u64,
    pub reads: usize,
    pub read_bytes: u64,
    pub read_elapsed_ns: u64,
    pub read_ns: Vec<u64>,
    pub read_energy: EnergyReading,
}

/// Raw output of an X6 run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct X6Raw {
    pub corpus: Vec<(String, String)>,
    pub changes: usize,
    pub revisions: usize,
    pub revision_bytes: u64,
    pub distinct_blobs: usize,
    pub distinct_blob_bytes: u64,
    /// Limits raised so that no commit is refused (the largest commit decides).
    pub max_paths_per_changeset: usize,
    pub max_total_changeset_bytes: u64,
    pub idle: EnergyReading,
    pub runs: Vec<RunRaw>,
}

fn run_one(
    dir: &Path,
    corpus: &Corpus,
    sets: &[SignedChange],
    limits: &StoreLimits,
    order: &[usize],
) -> Result<RunRaw, String> {
    let _ = std::fs::remove_dir_all(dir);
    let shared = SharedStore::open(
        dir,
        FsyncPolicy::GROUP_COMMIT_DEFAULT,
        RecoveryPolicy::StrictFailClosed,
        limits.clone(),
    )
    .map_err(|e| format!("open: {e:?}"))?;
    let mut latency = Vec::with_capacity(sets.len());
    let window = EnergyWindow::start();
    let t0 = Instant::now();
    for (env, blobs) in sets {
        let s = Instant::now();
        match shared.submit(env.clone(), blobs) {
            Ok(IngestOutcome::Committed { .. }) => {}
            other => return Err(format!("change not committed: {other:?}")),
        }
        latency.push(s.elapsed().as_nanos() as u64);
    }
    let ingest_elapsed_ns = t0.elapsed().as_nanos() as u64;
    let ingest_energy = window.finish();
    let stats = shared.stats();
    let st = shared.read();
    let log_bytes = st.log_bytes_written();
    let (chunks, chunk_bytes) = st.chunk_storage();
    let inline_blob_bytes = st.inline_blob_bytes();
    let chunked_blobs = corpus
        .digests
        .iter()
        .filter(|d| st.blob_manifest(d).is_some())
        .count();
    // Read phase: every distinct committed blob once, in commit order.
    let mut read_ns = Vec::with_capacity(order.len());
    let mut read_bytes = 0u64;
    let window = EnergyWindow::start();
    let t0 = Instant::now();
    for &b in order {
        let s = Instant::now();
        let got = st
            .get_blob_visible(corpus.digests[b], None, None)
            .map_err(|e| format!("read: {e:?}"))?;
        read_ns.push(s.elapsed().as_nanos() as u64);
        if got != corpus.blobs[b] {
            return Err(format!(
                "blob {} read back different bytes",
                corpus.digests[b]
            ));
        }
        read_bytes += got.len() as u64;
    }
    let read_elapsed_ns = t0.elapsed().as_nanos() as u64;
    let read_energy = window.finish();
    drop(st);
    drop(shared);
    let _ = std::fs::remove_dir_all(dir);
    Ok(RunRaw {
        config: String::new(),
        params: limits.chunking,
        rep: 0,
        position_in_rep: 0,
        accepted: sets.len(),
        ingest_elapsed_ns,
        ingest_latency_ns: latency,
        ingest_energy,
        log_bytes,
        content_bytes: inline_blob_bytes + chunk_bytes,
        inline_blob_bytes,
        chunks,
        chunk_bytes,
        chunked_blobs,
        batches: stats.batches,
        reads: order.len(),
        read_bytes,
        read_elapsed_ns,
        read_ns,
        read_energy,
    })
}

/// Run X6: `reps` repetitions of every configuration (order rotated by one per
/// repetition) on stores under `scratch`. `only` restricts the configurations (smoke runs).
pub fn run_x6(
    corpus_root: &Path,
    scratch: &Path,
    reps: usize,
    idle_s: u64,
    only: Option<&[String]>,
    log: &mut dyn FnMut(&str),
) -> Result<X6Raw, String> {
    let corpus = load_corpus(corpus_root)?;
    log(&format!(
        "corpus: {} changes, {} revisions, {} bytes, {} distinct blobs",
        corpus.changes.len(),
        corpus.revisions,
        corpus.revision_bytes,
        corpus.blobs.len()
    ));
    let sets = build_changesets(&corpus);
    let max_paths = sets
        .iter()
        .map(|(e, _)| e.mutations.len())
        .max()
        .unwrap_or(1);
    let max_total = sets
        .iter()
        .map(|(_, b)| b.iter().map(|(_, x)| x.len() as u64).sum::<u64>())
        .max()
        .unwrap_or(0);
    let mut order = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for (_, _, files) in &corpus.changes {
        for f in files {
            if seen.insert(f.blob) {
                order.push(f.blob);
            }
        }
    }
    let base = StoreLimits {
        max_paths_per_changeset: max_paths.max(StoreLimits::default().max_paths_per_changeset),
        max_total_changeset_bytes: max_total.max(StoreLimits::default().max_total_changeset_bytes),
        ..Default::default()
    };
    let configs: Vec<_> = configurations()
        .into_iter()
        .filter(|(id, _)| only.is_none_or(|o| o.iter().any(|x| x == id)))
        .collect();
    let idle = idle_window(Duration::from_secs(idle_s));
    let mut runs = Vec::new();
    for rep in 0..reps {
        for pos in 0..configs.len() {
            let (id, params) = configs[(pos + rep) % configs.len()];
            let limits = StoreLimits {
                chunking: params,
                ..base.clone()
            };
            let dir = scratch.join(format!("x6-{id}-rep{rep}"));
            let mut r = run_one(&dir, &corpus, &sets, &limits, &order)?;
            r.config = id.to_string();
            r.rep = rep;
            r.position_in_rep = pos;
            log(&format!(
                "rep {rep} {id}: ingest {:.3} s, log {} B, content {} B, read {:.3} s",
                r.ingest_elapsed_ns as f64 / 1e9,
                r.log_bytes,
                r.content_bytes,
                r.read_elapsed_ns as f64 / 1e9
            ));
            runs.push(r);
        }
    }
    Ok(X6Raw {
        corpus: CORPUS
            .iter()
            .map(|(n, c)| (n.to_string(), c.to_string()))
            .collect(),
        changes: corpus.changes.len(),
        revisions: corpus.revisions,
        revision_bytes: corpus.revision_bytes,
        distinct_blobs: corpus.blobs.len(),
        distinct_blob_bytes: corpus.blobs.iter().map(|b| b.len() as u64).sum(),
        max_paths_per_changeset: base.max_paths_per_changeset,
        max_total_changeset_bytes: base.max_total_changeset_bytes,
        idle,
        runs,
    })
}

/// Figures of one configuration (medians over the repetitions).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigReport {
    pub config: String,
    pub params: ChunkParams,
    pub reps: usize,
    /// `W_k`: median over repetitions of ingest wall time / accepted changes, seconds.
    pub w_s_per_change: f64,
    /// `R_k`: median of read wall time / reads, seconds.
    pub r_s_per_read: f64,
    /// `S_k`: log bytes of the ingest phase (equal in every repetition, else invalid).
    pub s_log_bytes: u64,
    pub content_bytes: u64,
    pub chunks: usize,
    pub chunked_blobs: usize,
    pub deterministic: bool,
    pub latency: Option<LatencySummary>,
    pub read_latency: Option<LatencySummary>,
    /// A2 flush bound / `W_k` (fraction of the bound reached, at most 1).
    pub flush_bound_fraction: f64,
    /// Mean read bytes / 273 GB/s per read, seconds (the index lookup term is not
    /// modelled, so this bound is lower than the RULE's), and bound / `R_k`.
    pub read_bound_s: f64,
    pub read_bound_fraction: f64,
    pub ingest_j_per_change: Option<f64>,
    pub ingest_j_per_change_above_idle: Option<f64>,
    pub read_j_per_read: Option<f64>,
    pub read_j_per_read_above_idle: Option<f64>,
    pub energy_refusals: Vec<String>,
    pub w_ratio: f64,
    pub r_ratio: f64,
    pub s_ratio: f64,
    pub eligible: bool,
}

/// The decision of RULE.md section 6.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct X6Report {
    pub configs: Vec<ConfigReport>,
    pub valid: bool,
    pub invalid_reasons: Vec<String>,
    pub eligible: Vec<String>,
    /// Winner id, or `None` (chunking off by default).
    pub winner: Option<String>,
    pub winner_params: ChunkParams,
    pub flush_bound_s: f64,
}

fn median(mut v: Vec<f64>) -> f64 {
    v.sort_by(|a, b| a.total_cmp(b));
    let n = v.len();
    if n % 2 == 1 {
        v[n / 2]
    } else {
        (v[n / 2 - 1] + v[n / 2]) / 2.0
    }
}

fn median_opt(v: Vec<Option<f64>>) -> Option<f64> {
    let v: Option<Vec<f64>> = v.into_iter().collect();
    v.filter(|v| !v.is_empty()).map(median)
}

/// Apply the decision criterion of RULE.md section 6 to the raw runs.
pub fn decide(raw: &X6Raw) -> X6Report {
    let mut by: BTreeMap<String, Vec<&RunRaw>> = BTreeMap::new();
    for r in &raw.runs {
        by.entry(r.config.clone()).or_default().push(r);
    }
    let mut invalid = Vec::new();
    let mut configs = Vec::new();
    for (id, params) in configurations() {
        let Some(runs) = by.get(id) else { continue };
        let det = runs
            .iter()
            .all(|r| (r.log_bytes, r.content_bytes) == (runs[0].log_bytes, runs[0].content_bytes));
        if !det {
            invalid.push(format!(
                "{id}: log or content bytes differ between repetitions"
            ));
        }
        let w = median(
            runs.iter()
                .map(|r| r.ingest_elapsed_ns as f64 / 1e9 / r.accepted as f64)
                .collect(),
        );
        let rr = median(
            runs.iter()
                .map(|r| r.read_elapsed_ns as f64 / 1e9 / r.reads as f64)
                .collect(),
        );
        let lat: Vec<u64> = runs
            .iter()
            .flat_map(|r| r.ingest_latency_ns.iter().map(|n| n / 1000))
            .collect();
        let rlat: Vec<u64> = runs
            .iter()
            .flat_map(|r| r.read_ns.iter().map(|n| n / 1000))
            .collect();
        let read_bound_s = runs[0].read_bytes as f64 / runs[0].reads as f64 / MEMORY_BW_BPS;
        let mut refusals = Vec::new();
        for r in runs {
            for e in [&r.ingest_energy, &r.read_energy] {
                if let Some(x) = &e.refusal {
                    refusals.push(format!("rep {}: {x}", r.rep));
                }
            }
        }
        configs.push(ConfigReport {
            config: id.to_string(),
            params,
            reps: runs.len(),
            w_s_per_change: w,
            r_s_per_read: rr,
            s_log_bytes: runs[0].log_bytes,
            content_bytes: runs[0].content_bytes,
            chunks: runs[0].chunks,
            chunked_blobs: runs[0].chunked_blobs,
            deterministic: det,
            latency: summarize_us(&lat),
            read_latency: summarize_us(&rlat),
            flush_bound_fraction: (A2_FLUSH_BOUND_S / w).min(1.0),
            read_bound_s,
            read_bound_fraction: (read_bound_s / rr).min(1.0),
            ingest_j_per_change: median_opt(
                runs.iter()
                    .map(|r| r.ingest_energy.pkg_j.map(|j| j / r.accepted as f64))
                    .collect(),
            ),
            ingest_j_per_change_above_idle: median_opt(
                runs.iter()
                    .map(|r| {
                        r.ingest_energy
                            .pkg_above_idle_j(&raw.idle)
                            .map(|j| j / r.accepted as f64)
                    })
                    .collect(),
            ),
            read_j_per_read: median_opt(
                runs.iter()
                    .map(|r| r.read_energy.pkg_j.map(|j| j / r.reads as f64))
                    .collect(),
            ),
            read_j_per_read_above_idle: median_opt(
                runs.iter()
                    .map(|r| {
                        r.read_energy
                            .pkg_above_idle_j(&raw.idle)
                            .map(|j| j / r.reads as f64)
                    })
                    .collect(),
            ),
            energy_refusals: refusals,
            w_ratio: 0.0,
            r_ratio: 0.0,
            s_ratio: 0.0,
            eligible: false,
        });
    }
    let c0 = configs.iter().find(|c| c.config == "C0").cloned();
    if c0.is_none() {
        invalid.push("control C0 missing".into());
    }
    if let Some(c0) = &c0 {
        for c in configs.iter_mut() {
            c.w_ratio = c.w_s_per_change / c0.w_s_per_change;
            c.r_ratio = c.r_s_per_read / c0.r_s_per_read;
            c.s_ratio = c.s_log_bytes as f64 / c0.s_log_bytes as f64;
            c.eligible = c.config != "C0"
                && c.w_s_per_change <= 1.10 * c0.w_s_per_change
                && c.r_s_per_read <= 1.25 * c0.r_s_per_read
                && (c.s_log_bytes as f64) <= 0.95 * c0.s_log_bytes as f64;
        }
    }
    let valid = invalid.is_empty();
    let eligible: Vec<&ConfigReport> = configs.iter().filter(|c| c.eligible).collect();
    let winner = if valid {
        eligible
            .iter()
            .map(|c| c.s_log_bytes)
            .min()
            .and_then(|best| {
                eligible
                    .iter()
                    .filter(|c| (c.s_log_bytes as f64) <= best as f64 * 1.01)
                    .max_by_key(|c| (c.params.avg_bytes, c.params.threshold_bytes))
                    .map(|c| (*c).clone())
            })
    } else {
        None
    };
    X6Report {
        eligible: eligible.iter().map(|c| c.config.clone()).collect(),
        winner_params: winner.as_ref().map_or(ChunkParams::OFF, |c| c.params),
        winner: winner.map(|c| c.config),
        configs,
        valid,
        invalid_reasons: invalid,
        flush_bound_s: A2_FLUSH_BOUND_S,
    }
}

/// Default scratch directory for the stores of a run.
pub fn default_scratch() -> PathBuf {
    std::env::temp_dir().join("synapse-x6")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(config: &str, rep: usize, w_ns: u64, r_ns: u64, s: u64) -> RunRaw {
        RunRaw {
            config: config.into(),
            params: configurations()
                .into_iter()
                .find(|(i, _)| *i == config)
                .unwrap()
                .1,
            rep,
            position_in_rep: 0,
            accepted: 1000,
            ingest_elapsed_ns: w_ns * 1000,
            ingest_latency_ns: vec![w_ns; 4],
            ingest_energy: EnergyReading::default(),
            log_bytes: s,
            content_bytes: s / 2,
            inline_blob_bytes: 0,
            chunks: 0,
            chunk_bytes: 0,
            chunked_blobs: 0,
            batches: 1000,
            reads: 100,
            read_bytes: 100 * 4096,
            read_elapsed_ns: r_ns * 100,
            read_ns: vec![r_ns; 4],
            read_energy: EnergyReading::default(),
        }
    }

    fn raw(runs: Vec<RunRaw>) -> X6Raw {
        X6Raw {
            corpus: vec![],
            changes: 1000,
            revisions: 0,
            revision_bytes: 0,
            distinct_blobs: 100,
            distinct_blob_bytes: 0,
            max_paths_per_changeset: 1,
            max_total_changeset_bytes: 1,
            idle: EnergyReading::default(),
            runs,
        }
    }

    #[test]
    fn x6_decision_follows_the_rule() {
        let mut runs = Vec::new();
        for rep in 0..3 {
            runs.push(run("C0", rep, 1_000_000, 10_000, 1000));
            // Eligible, smallest S.
            runs.push(run("K1", rep, 1_050_000, 11_000, 800));
            // Within 1 % of K1 with a larger avg: wins the tie.
            runs.push(run("K4", rep, 1_090_000, 12_000, 805));
            // Too slow to ingest.
            runs.push(run("K2", rep, 1_200_000, 10_000, 700));
            // Too slow to read.
            runs.push(run("K3", rep, 1_000_000, 13_000, 700));
            // Saves under 5 %.
            runs.push(run("K7", rep, 1_000_000, 10_000, 960));
        }
        let r = decide(&raw(runs.clone()));
        assert!(r.valid);
        assert_eq!(r.eligible, vec!["K1".to_string(), "K4".to_string()]);
        assert_eq!(r.winner.as_deref(), Some("K4"));
        assert_eq!(
            r.winner_params,
            ChunkParams::candidate(64 * 1024, 16 * 1024)
        );

        // Repetitions that disagree on log bytes make the run invalid: no winner.
        let mut bad = runs.clone();
        bad[1].log_bytes += 1;
        let r = decide(&raw(bad));
        assert!(!r.valid && r.winner.is_none());

        // Nothing eligible: chunking stays off.
        let only: Vec<RunRaw> = runs
            .into_iter()
            .filter(|r| r.config == "C0" || r.config == "K7")
            .collect();
        let r = decide(&raw(only));
        assert!(r.valid && r.winner.is_none());
        assert_eq!(r.winner_params, ChunkParams::OFF);
    }
}
