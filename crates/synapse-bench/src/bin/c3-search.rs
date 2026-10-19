//! C3 measurement: trigram index size and search time on a real corpus, this repository's own
//! Git history, against the ADR 0003 section 6 bound for a read of n bytes (n divided by memory
//! bandwidth, plus one index lookup).
//!
//! ```text
//! c3-search --git-dir DIR --commit HEX --out DIR [--reps R] [--idle-s S] [--store-root DIR]
//! ```
//!
//! Every commit reachable from `--commit` is read with the native Git reader (`synapse-git`)
//! and registered as a base tree. Parity: for every commit, every query of the fixed set, and
//! two reader scopes (whole repository; `crates/synapse-api`), the paged search equals an
//! independent full scan (the same regular expression run over the Git blobs, outside
//! Synapse), once before indexing and once after. Timing: on the `--commit` tree, `R`
//! repetitions per query and scope with the index, then `R` with an empty index (every
//! in-scope file read). Each sample is the `SynapseService::search` calls of one complete
//! paged search (chain authorisation included); signing happens outside the timer. Blobs are
//! held in memory, so device reads are not part of any sample. `result.json` holds every raw
//! sample in nanoseconds.

use ed25519_dalek::SigningKey;
use regex::bytes::Regex;
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, Instant};
use synapse_api::{
    SearchIndexConfig, SearchMatch, SearchQueryPayload, SearchTarget, SynapseService,
    TreeCacheConfig, TreeTarget, MAX_SEARCH_RESULTS, MAX_SPANS_PER_FILE,
};
use synapse_auth::{
    Capability, CapabilityChain, CapabilityLink, ChainQuotas, ChainedRequest, ChangeScope,
    LinkCaveats, OperationSet, PathScope, ReferenceKind, ReferenceScope, RequestScope, ROOT_PARENT,
};
use synapse_bench::energy::{idle_window, EnergyReading, EnergyWindow};
use synapse_core::{encode_did_key_ed25519, BlobDigest, FileMode, GitOid, RepoId, WalSeq};
use synapse_git::object::{parse_commit_links, parse_tree};
use synapse_git::{GitRepository, ObjectKind};
use synapse_store::{FsyncPolicy, RecoveryPolicy, StoreLimits};

/// Physical memory bandwidth, `docs/A0_HOST_BOUNDS.md` (NVIDIA DGX Spark specification).
const MEMORY_BYTES_PER_S: f64 = 273e9;
const NOW: u64 = 2_000;
/// The scoped reader's `Read` path scope.
const SCOPED_PREFIX: &str = "crates/synapse-api";

/// The fixed query set for this corpus: literals, case folding, classes, alternation,
/// repetition, anchors, Unicode, a NUL byte, a pattern no trigram can narrow, and a negative
/// control that matches no file.
const QUERIES: &[&str] = &[
    "SynapseError",
    "RefusalCode::[A-Z][A-Za-z]+",
    "(?i)trigram",
    "fn [a-z_]+\\(&mut self",
    "unsafe|transmute",
    "TODO|FIXME",
    "[0-9]{4}-[0-9]{2}-[0-9]{2}",
    "(?m)^use synapse_[a-z]+::",
    "\\bEd25519\\b",
    "calc:[0-9a-f]{8}",
    "Co-Authored-By",
    "\u{e9}",
    "\\x00",
    "(?s)fn main\\(\\).*ExitCode",
    ".",
    "zzz_never_present_q7",
];

type Files = Vec<(String, FileMode, GitOid)>;

/// Every commit reachable from the start commit, each with its file list, and the bytes of
/// every distinct blob.
struct Corpus {
    commits: Vec<GitOid>,
    trees: BTreeMap<GitOid, Files>,
    blobs: BTreeMap<GitOid, Vec<u8>>,
    /// Entries left out: gitlinks, non-UTF-8 names.
    skipped_entries: u64,
}

fn read(repo: &mut GitRepository, oid: GitOid, kind: ObjectKind) -> Result<Vec<u8>, String> {
    let obj = repo
        .read_object(oid)
        .map_err(|e| format!("{oid}: {}", e.message))?
        .ok_or_else(|| format!("object {oid} missing"))?;
    if obj.kind != kind {
        return Err(format!("object {oid} is a {}", obj.kind.name()));
    }
    Ok(obj.payload)
}

fn walk_tree(
    repo: &mut GitRepository,
    corpus: &mut Corpus,
    tree: GitOid,
    prefix: &str,
    out: &mut Files,
) -> Result<(), String> {
    let payload = read(repo, tree, ObjectKind::Tree)?;
    for e in parse_tree(&payload).map_err(|e| e.message)? {
        let Ok(name) = std::str::from_utf8(&e.name) else {
            corpus.skipped_entries += 1;
            continue;
        };
        let path = if prefix.is_empty() {
            name.to_string()
        } else {
            format!("{prefix}/{name}")
        };
        let mode = match e.mode.as_slice() {
            b"40000" | b"040000" => {
                walk_tree(repo, corpus, e.oid, &path, out)?;
                continue;
            }
            b"100644" => FileMode::Regular644,
            b"100755" => FileMode::Executable755,
            b"120000" => FileMode::Symlink120000,
            _ => {
                corpus.skipped_entries += 1;
                continue;
            }
        };
        if let std::collections::btree_map::Entry::Vacant(v) = corpus.blobs.entry(e.oid) {
            v.insert(read(repo, e.oid, ObjectKind::Blob)?);
        }
        out.push((path, mode, e.oid));
    }
    Ok(())
}

fn load(git_dir: &Path, start: GitOid) -> Result<Corpus, String> {
    let mut repo = GitRepository::open(git_dir).map_err(|e| e.message)?;
    let mut corpus = Corpus {
        commits: Vec::new(),
        trees: BTreeMap::new(),
        blobs: BTreeMap::new(),
        skipped_entries: 0,
    };
    let mut seen = BTreeSet::from([start]);
    let mut queue = VecDeque::from([start]);
    while let Some(c) = queue.pop_front() {
        let links =
            parse_commit_links(&read(&mut repo, c, ObjectKind::Commit)?).map_err(|e| e.message)?;
        let mut files = Vec::new();
        walk_tree(&mut repo, &mut corpus, links.tree, "", &mut files)?;
        corpus.commits.push(c);
        corpus.trees.insert(c, files);
        for p in links.parents {
            if seen.insert(p) {
                queue.push_back(p);
            }
        }
    }
    Ok(corpus)
}

fn caveats(paths: PathScope, share: u64) -> LinkCaveats {
    LinkCaveats {
        operations: OperationSet::from_capabilities(&[Capability::Read]),
        paths,
        references: ReferenceScope::from_kinds(&[ReferenceKind::OwnDrafts]),
        changes: ChangeScope::any(),
        quotas: ChainQuotas {
            max_ops_per_window: (1_000_000 / share) as u32,
            window_duration_ms: 60_000,
            storage_bytes: (1 << 30) / share,
            footprint_paths: (1 << 20) / share,
            max_bytes_per_op: 1 << 20,
        },
        issued_at_ms: 1_000,
        expires_at_ms: 100_000,
    }
}

struct Reader {
    name: &'static str,
    key: SigningKey,
    chain: CapabilityChain,
    scope: PathScope,
}

struct Bench {
    svc: SynapseService,
    repo: RepoId,
    nonce: u64,
}

impl Bench {
    /// One complete paged search; returns the matches and the seconds spent inside
    /// `SynapseService::search` (signing excluded).
    fn search_all(
        &mut self,
        who: &Reader,
        commit: GitOid,
        pattern: &str,
    ) -> Result<(Vec<SearchMatch>, Duration), String> {
        let mut out = Vec::new();
        let mut after = None;
        let mut spent = Duration::ZERO;
        loop {
            self.nonce += 1;
            let mut n = [0u8; 32];
            n[..8].copy_from_slice(&self.nonce.to_le_bytes());
            let payload = SearchQueryPayload {
                target: SearchTarget::Tree(TreeTarget::BaseGitCommit(commit)),
                pattern: pattern.into(),
                after_path: after,
                limit: MAX_SEARCH_RESULTS as u32,
            }
            .encode();
            let req = ChainedRequest::sign_new(
                &who.key,
                who.chain.clone(),
                self.repo.clone(),
                Capability::Read,
                RequestScope::default(),
                n,
                NOW,
                payload,
            );
            let t = Instant::now();
            let page = self.svc.search(&req, NOW);
            spent += t.elapsed();
            let page = page.map_err(|e| format!("search {pattern:?}: {}", e.message))?;
            out.extend(page.matches);
            match page.next_after {
                Some(a) => after = Some(a),
                None => return Ok((out, spent)),
            }
        }
    }
}

/// The reference: the same expression over every in-scope file of the commit, read from the
/// Git blobs, outside Synapse.
fn full_scan(corpus: &Corpus, commit: GitOid, scope: &PathScope, re: &Regex) -> Vec<SearchMatch> {
    let mut out = BTreeMap::new();
    for (path, _, oid) in &corpus.trees[&commit] {
        if !scope.covers_path(path) {
            continue;
        }
        let bytes = &corpus.blobs[oid];
        let all: Vec<(u64, u64)> = re
            .find_iter(bytes)
            .take(MAX_SPANS_PER_FILE + 1)
            .map(|m| (m.start() as u64, m.end() as u64))
            .collect();
        if all.is_empty() {
            continue;
        }
        out.insert(
            path.clone(),
            SearchMatch {
                path: path.clone(),
                blob_digest: BlobDigest::compute(bytes),
                more_spans: all.len() > MAX_SPANS_PER_FILE,
                spans: all.into_iter().take(MAX_SPANS_PER_FILE).collect(),
            },
        );
    }
    out.into_values().collect()
}

/// Parity over every commit, query, and reader; returns the number of comparisons.
fn parity(
    bench: &mut Bench,
    corpus: &Corpus,
    readers: &[Reader],
    regexes: &[Regex],
) -> Result<u64, String> {
    let mut checked = 0;
    let t = Instant::now();
    for (i, &commit) in corpus.commits.iter().enumerate() {
        if i % 20 == 0 {
            eprintln!(
                "parity: commit {i}/{} at {:.1} s",
                corpus.commits.len(),
                t.elapsed().as_secs_f64()
            );
        }
        for (q, re) in QUERIES.iter().zip(regexes) {
            for r in readers {
                let (got, _) = bench.search_all(r, commit, q)?;
                if got != full_scan(corpus, commit, &r.scope, re) {
                    return Err(format!(
                        "PARITY FAIL: commit {commit}, reader {}, query {q:?}",
                        r.name
                    ));
                }
                checked += 1;
            }
        }
    }
    Ok(checked)
}

fn median(v: &[f64]) -> f64 {
    let mut s = v.to_vec();
    s.sort_by(f64::total_cmp);
    let n = s.len();
    if n % 2 == 1 {
        s[n / 2]
    } else {
        (s[n / 2 - 1] + s[n / 2]) / 2.0
    }
}

/// `R` samples per query and reader on `commit`, after one untimed warm-up each.
fn time_block(
    bench: &mut Bench,
    corpus: &Corpus,
    readers: &[Reader],
    commit: GitOid,
    reps: usize,
) -> Result<(Vec<serde_json::Value>, EnergyReading, Duration), String> {
    let mut rows = Vec::new();
    let mut busy = Duration::ZERO;
    let window = EnergyWindow::start();
    for r in readers {
        eprintln!("timing: reader {}", r.name);
        for q in QUERIES {
            let (matches, _) = bench.search_all(r, commit, q)?;
            let stats0 = bench.svc.search_index().stats();
            let mut samples_ns = Vec::with_capacity(reps);
            for _ in 0..reps {
                let (_, spent) = bench.search_all(r, commit, q)?;
                busy += spent;
                samples_ns.push(spent.as_nanos() as u64);
            }
            let stats1 = bench.svc.search_index().stats();
            let files = &corpus.trees[&commit];
            let size = |oid: &GitOid| corpus.blobs[oid].len() as u64;
            let in_scope: Vec<&(String, FileMode, GitOid)> =
                files.iter().filter(|f| r.scope.covers_path(&f.0)).collect();
            let scope_bytes: u64 = in_scope.iter().map(|f| size(&f.2)).sum();
            let matched: BTreeSet<&str> = matches.iter().map(|m| m.path.as_str()).collect();
            let match_bytes: u64 = in_scope
                .iter()
                .filter(|f| matched.contains(f.0.as_str()))
                .map(|f| size(&f.2))
                .sum();
            let secs: Vec<f64> = samples_ns.iter().map(|&n| n as f64 * 1e-9).collect();
            let med = median(&secs);
            let bound_s = match_bytes as f64 / MEMORY_BYTES_PER_S;
            rows.push(json!({
                "reader": r.name,
                "query": q,
                "files_in_scope": in_scope.len(),
                "bytes_in_scope": scope_bytes,
                "files_matched": matches.len(),
                "bytes_of_matched_files": match_bytes,
                "files_read_per_search": (stats1.files_read - stats0.files_read) / reps as u64,
                "files_pruned_per_search": (stats1.files_pruned - stats0.files_pruned) / reps as u64,
                "median_s": med,
                "min_s": secs.iter().copied().fold(f64::INFINITY, f64::min),
                "max_s": secs.iter().copied().fold(0.0, f64::max),
                "bound_s": if match_bytes > 0 { json!(bound_s) } else { json!(null) },
                "fraction_of_bound": if match_bytes > 0 { json!(bound_s / med) } else { json!(null) },
                "full_scan_bound_s": scope_bytes as f64 / MEMORY_BYTES_PER_S,
                "samples_ns": samples_ns,
            }));
        }
    }
    Ok((rows, window.finish(), busy))
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
        "usage: c3-search --git-dir DIR --commit HEX --out DIR [--reps R] [--idle-s S] [--store-root DIR]"
    );
    ExitCode::from(2)
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (mut git_dir, mut commit, mut out) = (None, None, None);
    let (mut reps, mut idle_s) = (30usize, 10u64);
    let mut store_root = PathBuf::from("target/c3-search-stores");
    let mut i = 0;
    while i < args.len() {
        let Some(v) = args.get(i + 1) else {
            return usage();
        };
        match args[i].as_str() {
            "--git-dir" => git_dir = Some(PathBuf::from(v)),
            "--commit" => match GitOid::from_hex(v) {
                Ok(c) => commit = Some(c),
                Err(_) => return usage(),
            },
            "--out" => out = Some(PathBuf::from(v)),
            "--reps" => match v.parse() {
                Ok(n) if n > 0 => reps = n,
                _ => return usage(),
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
    let (Some(git_dir), Some(commit), Some(out)) = (git_dir, commit, out) else {
        return usage();
    };
    match run(&git_dir, commit, &out, reps, idle_s, &store_root) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("c3-search: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run(
    git_dir: &Path,
    start: GitOid,
    out: &Path,
    reps: usize,
    idle_s: u64,
    store_root: &Path,
) -> Result<(), String> {
    std::fs::create_dir_all(out).map_err(|e| e.to_string())?;
    let t = Instant::now();
    let corpus = load(git_dir, start)?;
    let load_s = t.elapsed().as_secs_f64();
    let corpus_bytes: u64 = corpus.blobs.values().map(|b| b.len() as u64).sum();
    let file_versions: usize = corpus.trees.values().map(Vec::len).sum();
    println!(
        "corpus: {} commits, {} file entries over all commits, {} distinct blobs, {} bytes of distinct blobs (read in {:.3} s)",
        corpus.commits.len(),
        file_versions,
        corpus.blobs.len(),
        corpus_bytes,
        load_s
    );

    let dir = store_root.join(format!("c3-{}", std::process::id()));
    let repo = RepoId::new("aien-spark/synapse").map_err(|e| e.message)?;
    let mut svc = SynapseService::open(
        &dir,
        repo.clone(),
        FsyncPolicy::EveryCommit,
        RecoveryPolicy::StrictFailClosed,
        StoreLimits {
            wal_prealloc_bytes: 64 * 1024,
            ..Default::default()
        },
    )
    .map_err(|e| e.message)?;
    svc.set_tree_cache_config(TreeCacheConfig { max_bytes: 1 << 30 })
        .map_err(|e| e.message)?;
    let key = |n: u8| SigningKey::from_bytes(&[n; 32]);
    let pk = |k: &SigningKey| k.verifying_key().to_bytes();
    let (a, o) = (key(1), key(2));
    svc.auth_mut()
        .register_repo_authority(repo.clone(), encode_did_key_ed25519(&pk(&a)));
    let nonce = |n: u8| [n; 32];
    let root = CapabilityLink::issue(
        &a,
        ROOT_PARENT,
        nonce(1),
        repo.clone(),
        pk(&o),
        caveats(PathScope::whole_repository(), 1),
    );
    let chain_o = CapabilityChain::new(vec![root.clone()]);
    svc.auth_mut()
        .grant_link(&chain_o, WalSeq(0), NOW)
        .map_err(|e| e.message)?;
    let mut readers = Vec::new();
    for (name, n, scope) in [
        ("whole_repository", 3u8, PathScope::whole_repository()),
        (
            "crates/synapse-api",
            4u8,
            PathScope::new(vec![SCOPED_PREFIX.into()]).map_err(|e| e.message)?,
        ),
    ] {
        let k = key(n);
        let link = CapabilityLink::issue(
            &o,
            root.digest(),
            nonce(n),
            repo.clone(),
            pk(&k),
            caveats(scope.clone(), 2),
        );
        let chain = chain_o.extended(link);
        svc.auth_mut()
            .grant_link(&chain, WalSeq(0), NOW)
            .map_err(|e| e.message)?;
        readers.push(Reader {
            name,
            key: k,
            chain,
            scope,
        });
    }
    let t = Instant::now();
    for c in &corpus.commits {
        let files = corpus.trees[c]
            .iter()
            .map(|(p, m, oid)| (p.clone(), *m, corpus.blobs[oid].clone()))
            .collect();
        svc.register_base_tree(*c, files).map_err(|e| e.message)?;
    }
    let register_s = t.elapsed().as_secs_f64();
    let mut bench = Bench {
        svc,
        repo,
        nonce: 0,
    };
    let regexes: Vec<Regex> = QUERIES
        .iter()
        .map(|q| Regex::new(q).map_err(|e| e.to_string()))
        .collect::<Result<_, _>>()?;

    let checked_before = parity(&mut bench, &corpus, &readers, &regexes)?;
    println!("parity before indexing: {checked_before} searches equal a full scan");

    let t = Instant::now();
    let (mut indexed, mut already, mut skipped) = (0, 0, 0);
    for c in &corpus.commits {
        let r = bench
            .svc
            .index_search_content(SearchTarget::Tree(TreeTarget::BaseGitCommit(*c)))
            .map_err(|e| e.message)?;
        indexed += r.indexed;
        already += r.already;
        skipped += r.skipped;
    }
    let index_s = t.elapsed().as_secs_f64();
    let index = bench.svc.search_index();
    let index_bytes = index.bytes();
    let config = index.config();
    let indexed_blob_bytes: u64 = corpus
        .blobs
        .values()
        .filter(|b| index.contains(&BlobDigest::compute(b)))
        .map(|b| b.len() as u64)
        .sum();
    println!(
        "index: {index_bytes} bytes for {indexed} blobs holding {indexed_blob_bytes} bytes ({:.4} bytes of index per byte indexed), {skipped} blobs left out, built in {index_s:.3} s",
        index_bytes as f64 / indexed_blob_bytes as f64
    );

    let checked_after = parity(&mut bench, &corpus, &readers, &regexes)?;
    println!("parity after indexing: {checked_after} searches equal a full scan");

    let (indexed_rows, indexed_energy, indexed_busy) =
        time_block(&mut bench, &corpus, &readers, start, reps)?;
    bench
        .svc
        .set_search_index_config(SearchIndexConfig::default());
    let (scan_rows, scan_energy, scan_busy) =
        time_block(&mut bench, &corpus, &readers, start, reps)?;
    let idle = if idle_s > 0 {
        Some(idle_window(Duration::from_secs(idle_s)))
    } else {
        None
    };

    println!("\nreader             query                            matched  read/pruned   indexed median s   no-index median s   bound s      fraction");
    for (a, b) in indexed_rows.iter().zip(&scan_rows) {
        println!(
            "{:<18} {:<32} {:>7}  {:>5}/{:<5}  {:>16.6e}  {:>18.6e}  {:>10}  {}",
            a["reader"].as_str().unwrap_or(""),
            a["query"].as_str().unwrap_or(""),
            a["files_matched"],
            a["files_read_per_search"],
            a["files_pruned_per_search"],
            a["median_s"].as_f64().unwrap_or(f64::NAN),
            b["median_s"].as_f64().unwrap_or(f64::NAN),
            a["bound_s"]
                .as_f64()
                .map_or("n/a".into(), |v| format!("{v:.3e}")),
            a["fraction_of_bound"]
                .as_f64()
                .map_or("n/a".into(), |v| format!("{v:.3e}")),
        );
    }
    println!(
        "energy: indexed block {}, no-index block {}",
        indexed_energy.pkg_j.map_or(
            format!("NOT MEASURED ({})", indexed_energy.sensor),
            |j| format!("{j:.3} J")
        ),
        scan_energy.pkg_j.map_or(
            format!("NOT MEASURED ({})", scan_energy.sensor),
            |j| format!("{j:.3} J")
        ),
    );

    let result = json!({
        "tool": "c3-search",
        "step": "C3",
        "tool_git_rev": git_rev(),
        "corpus": {
            "git_dir": git_dir.display().to_string(),
            "start_commit": start.to_string(),
            "commits": corpus.commits.len(),
            "file_entries_over_all_commits": file_versions,
            "distinct_blobs": corpus.blobs.len(),
            "distinct_blob_bytes": corpus_bytes,
            "skipped_entries": corpus.skipped_entries,
            "load_s": load_s,
            "register_base_trees_s": register_s,
        },
        "queries": QUERIES,
        "readers": readers.iter().map(|r| json!({"name": r.name, "scope": r.scope.prefixes()})).collect::<Vec<_>>(),
        "parity": {
            "before_indexing_searches": checked_before,
            "after_indexing_searches": checked_after,
            "verdict": "PASS",
        },
        "index": {
            "config_max_bytes": config.max_bytes,
            "config_max_blob_bytes": config.max_blob_bytes,
            "bytes": index_bytes,
            "blobs_indexed": indexed,
            "blobs_already": already,
            "blobs_left_out": skipped,
            "indexed_blob_bytes": indexed_blob_bytes,
            "index_bytes_per_indexed_byte": index_bytes as f64 / indexed_blob_bytes as f64,
            "build_s": index_s,
            "build_read_bound_s": indexed_blob_bytes as f64 / MEMORY_BYTES_PER_S,
            "build_fraction_of_read_bound": indexed_blob_bytes as f64 / MEMORY_BYTES_PER_S / index_s,
        },
        "timing": {
            "commit": start.to_string(),
            "reps": reps,
            "sample": "SynapseService::search calls of one complete paged search, signing excluded, blobs in memory",
            "bound": "ADR 0003 section 6.2 read of n bytes: n / 273 GB/s; n = bytes of the matched files (they must be read to report spans); the one index lookup term is not quantified, so the bound is understated and the fraction is a lower estimate",
            "indexed": indexed_rows,
            "no_index": scan_rows,
            "indexed_busy_s": indexed_busy.as_secs_f64(),
            "no_index_busy_s": scan_busy.as_secs_f64(),
        },
        "energy": {
            "sensor_note": "aien_spbm hwmon: SoC package only, uncalibrated; NVMe UNMEASURED",
            "indexed_block": indexed_energy,
            "no_index_block": scan_energy,
            "idle": idle,
        },
    });
    let path = out.join("result.json");
    std::fs::write(
        &path,
        serde_json::to_vec_pretty(&result).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    let _ = std::fs::remove_dir_all(&dir);
    println!("wrote {}", path.display());
    Ok(())
}
