//! Read-phase measurement: checkout-free queries against a populated Synapse service and
//! equivalent `git` CLI queries against a repository holding the same proposals as
//! commits, plus the per-proposal transfer-size estimate.
//!
//! Queries run from one client thread with no concurrent writers (separate from the write
//! phase; no mixed-load claim). Synapse timings include request signing, JSON request
//! encode/decode, the API call, and JSON response encode/decode for every page; `api_us`
//! records the API call alone. Git timings include process spawn unless the method is the
//! persistent `git cat-file --batch` process.

use crate::fixture::{self, CatFileBatch};
use crate::git_arm;
use crate::gitcmd::{git_ok, run_git};
use crate::rng::SplitMix64;
use crate::rusage::sample_self;
use crate::stats::{round3, summarize_us, LatencySummary};
use crate::synapse_arm::{self, AgentIdentity};
use crate::workload::{generate_write_workload, EditOp, Proposal};
use crate::write_jsonl;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::Instant;
use synapse_api::{
    ConflictQueryPayload, DiffQueryPayload, PageRequest, PageResponse, SynapseService,
    TreeQueryPayload, TreeTarget, DEFAULT_MAX_PAGE_SIZE,
};
use synapse_core::{ChangesetId, GitOid, RepoId, WalSeq};
use synapse_store::{FsyncPolicy, IngestOutcome, RecoveryPolicy};

/// Input for one query cell.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuerySpec {
    pub rep: usize,
    pub seed: u64,
    pub agents: usize,
    pub ops_per_agent: usize,
    pub samples: usize,
    pub clone_dir: PathBuf,
    pub base_commit: String,
    pub cell_dir: PathBuf,
    pub trace_path: PathBuf,
}

/// One timed query.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryTrace {
    pub rep: usize,
    pub query: String,
    pub sample: usize,
    pub latency_us: u64,
    pub api_us: Option<u64>,
    pub request_bytes: Option<u64>,
    pub response_bytes: Option<u64>,
    pub pages: Option<usize>,
    /// Synapse only: the call built at least one changeset tree (not answered from the memo).
    pub cold: Option<bool>,
    pub result_items: Option<usize>,
    pub ok: bool,
    pub error: Option<String>,
}

/// Summary of one query method.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryKindResult {
    pub query: String,
    pub system: String,
    pub method: String,
    pub latency: Option<LatencySummary>,
    pub api_only: Option<LatencySummary>,
    pub failures: usize,
    pub cold_samples: Option<usize>,
    pub mean_pages: Option<f64>,
    pub mean_response_bytes: Option<f64>,
}

/// Byte-size distribution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ByteSummary {
    pub n: usize,
    pub min: u64,
    pub p50: u64,
    pub max: u64,
    pub mean: f64,
    pub total: u64,
}

pub fn byte_summary(values: &[u64]) -> Option<ByteSummary> {
    if values.is_empty() {
        return None;
    }
    let mut v = values.to_vec();
    v.sort_unstable();
    let total: u64 = v.iter().sum();
    Some(ByteSummary {
        n: v.len(),
        min: v[0],
        p50: crate::stats::nearest_rank(&v, 0.5)?,
        max: v[v.len() - 1],
        mean: round3(total as f64 / v.len() as f64),
        total,
    })
}

/// Per-proposal transfer-size estimate (labelled ESTIMATE in the report).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferEstimate {
    pub label: String,
    pub proposals: usize,
    /// JSON-encoded `AuthenticatedRequest<SubmitChangesetPayload>` as built by this harness.
    pub synapse_json_request_bytes: Option<ByteSummary>,
    /// Sum of upserted file content bytes (lower bound for any encoding of the content).
    pub raw_content_bytes: Option<ByteSummary>,
    /// `git pack-objects --thin --stdout --revs` for `<commit> ^<base>`.
    pub git_thin_pack_bytes: Option<ByteSummary>,
    pub notes: Vec<String>,
}

/// Cross-check between Synapse and Git answers for the same samples.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParityCheck {
    pub check: String,
    pub compared: usize,
    pub mismatches: usize,
}

/// Result of one query cell.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryCellResult {
    pub rep: usize,
    pub population_changesets: usize,
    pub samples_per_query: usize,
    pub synapse_populate_ms: f64,
    pub git_populate_ms: f64,
    pub queries: Vec<QueryKindResult>,
    pub parity: Vec<ParityCheck>,
    pub transfer: TransferEstimate,
    pub synapse_cached_virtual_trees_after: usize,
    pub peak_rss_self_kib: u64,
}

struct Populated {
    proposal: Proposal,
    changeset: ChangesetId,
    commit: String,
    wire_bytes: u64,
}

struct SynapseClient<'a> {
    svc: &'a mut SynapseService,
    agent: &'a AgentIdentity,
    repo_id: &'a RepoId,
    counter: u64,
}

struct CallTiming<R> {
    value: R,
    api_us: u64,
    request_bytes: u64,
    response_bytes: u64,
}

impl SynapseClient<'_> {
    /// Sign, wire-encode, decode, call, and wire-encode/decode the response.
    fn call<P, R>(
        &mut self,
        payload: P,
        api: impl FnOnce(
            &mut SynapseService,
            &synapse_auth::AuthenticatedRequest<P>,
            u64,
        ) -> synapse_core::SynapseResult<R>,
    ) -> Result<CallTiming<R>, String>
    where
        P: Serialize + DeserializeOwned,
        R: Serialize + DeserializeOwned,
    {
        self.counter += 1;
        let now = crate::unix_now_ms();
        let label = format!("gate4/query/{}", self.counter);
        let req = synapse_arm::build_read_request(self.agent, self.repo_id, payload, &label, now)?;
        let (decoded, request_bytes) = synapse_arm::wire_roundtrip(&req)?;
        let t = Instant::now();
        let resp = api(self.svc, &decoded, now).map_err(|e| e.to_string())?;
        let api_us = t.elapsed().as_micros() as u64;
        let (value, response_bytes) = synapse_arm::wire_roundtrip(&resp)?;
        Ok(CallTiming {
            value,
            api_us,
            request_bytes: request_bytes as u64,
            response_bytes: response_bytes as u64,
        })
    }

    /// Fetch every page of a paginated query. Returns (items, pages, api_us, req, resp bytes).
    fn all_pages<T, P>(
        &mut self,
        make: impl Fn(PageRequest) -> P,
        api: fn(
            &mut SynapseService,
            &synapse_auth::AuthenticatedRequest<P>,
            u64,
        ) -> synapse_core::SynapseResult<PageResponse<T>>,
    ) -> Result<(usize, usize, u64, u64, u64), String>
    where
        P: Serialize + DeserializeOwned,
        T: Serialize + DeserializeOwned,
    {
        let mut cursor: Option<String> = None;
        let mut snapshot: Option<WalSeq> = None;
        let (mut items, mut pages, mut api_us, mut req_b, mut resp_b) = (0usize, 0, 0, 0, 0);
        loop {
            let page = PageRequest {
                cursor: cursor.clone(),
                limit: DEFAULT_MAX_PAGE_SIZE,
                min_visible_seq: None,
                snapshot_seq: snapshot,
            };
            let r = self.call(make(page), api)?;
            pages += 1;
            items += r.value.items.len();
            api_us += r.api_us;
            req_b += r.request_bytes;
            resp_b += r.response_bytes;
            snapshot = Some(r.value.snapshot_seq);
            match r.value.next_cursor {
                Some(next) => cursor = Some(next),
                None => break,
            }
        }
        Ok((items, pages, api_us, req_b, resp_b))
    }
}

fn trace(rep: usize, query: &str, sample: usize) -> QueryTrace {
    QueryTrace {
        rep,
        query: query.to_string(),
        sample,
        latency_us: 0,
        api_us: None,
        request_bytes: None,
        response_bytes: None,
        pages: None,
        cold: None,
        result_items: None,
        ok: false,
        error: None,
    }
}

fn summarize_kind(query: &str, system: &str, method: &str, rows: &[QueryTrace]) -> QueryKindResult {
    let ok: Vec<&QueryTrace> = rows.iter().filter(|r| r.ok).collect();
    let lat: Vec<u64> = ok.iter().map(|r| r.latency_us).collect();
    let api: Vec<u64> = ok.iter().filter_map(|r| r.api_us).collect();
    let pages: Vec<usize> = ok.iter().filter_map(|r| r.pages).collect();
    let resp: Vec<u64> = ok.iter().filter_map(|r| r.response_bytes).collect();
    let cold = ok.iter().filter(|r| r.cold == Some(true)).count();
    QueryKindResult {
        query: query.to_string(),
        system: system.to_string(),
        method: method.to_string(),
        latency: summarize_us(&lat),
        api_only: summarize_us(&api),
        failures: rows.len() - ok.len(),
        cold_samples: if system == "synapse" {
            Some(cold)
        } else {
            None
        },
        mean_pages: if pages.is_empty() {
            None
        } else {
            Some(round3(
                pages.iter().sum::<usize>() as f64 / pages.len() as f64,
            ))
        },
        mean_response_bytes: if resp.is_empty() {
            None
        } else {
            Some(round3(resp.iter().sum::<u64>() as f64 / resp.len() as f64))
        },
    }
}

fn line_count(bytes: &[u8]) -> usize {
    bytes
        .split(|&b| b == b'\n')
        .filter(|l| !l.is_empty())
        .count()
}

/// Run one query cell.
pub fn run_query_cell(spec: &QuerySpec) -> Result<QueryCellResult, String> {
    std::fs::create_dir_all(&spec.cell_dir)
        .map_err(|e| format!("mkdir {}: {e}", spec.cell_dir.display()))?;
    let clone = spec.clone_dir.as_path();
    let base = fixture::list_base_tree(clone, &spec.base_commit)?;
    let full = fixture::load_full_base(clone, &base)?;
    let files = fixture::editable_from_full_base(&base, &full);
    let workload = generate_write_workload(
        spec.seed,
        10_000 + spec.rep,
        spec.agents,
        spec.ops_per_agent,
        &files,
    );
    drop(files);

    // Populate Synapse (untimed for query purposes; recorded as populate time).
    let ids = synapse_arm::issue_identities(spec.seed, spec.agents, crate::unix_now_ms())?;
    let t = Instant::now();
    let mut svc = synapse_arm::open_service(
        &spec.cell_dir.join("synapse-store"),
        &ids,
        FsyncPolicy::BatchWindow { max_records: 1024 },
        RecoveryPolicy::StrictFailClosed,
    )?;
    let base_oid: GitOid = synapse_arm::register_base(&mut svc, &spec.base_commit, full)?;
    let mut populated: Vec<Populated> = Vec::new();
    for (a, props) in workload.iter().enumerate() {
        for p in props {
            let label = format!("gate4/query-pop/r{}/a{}/p{}", spec.rep, a, p.index);
            let now = crate::unix_now_ms();
            let req = synapse_arm::build_submit_request(
                &ids.agents[a],
                &ids.repo_id,
                base_oid,
                p,
                &label,
                now,
            )?;
            let (decoded, wire) = synapse_arm::wire_roundtrip(&req)?;
            let cs = match svc.submit(&decoded, now).map_err(|e| e.to_string())? {
                IngestOutcome::Committed { changeset_id, .. }
                | IngestOutcome::IdempotentDuplicate { changeset_id, .. } => changeset_id,
            };
            populated.push(Populated {
                proposal: p.clone(),
                changeset: cs,
                commit: String::new(),
                wire_bytes: wire as u64,
            });
        }
    }
    svc.store_mut().sync_wal().map_err(|e| e.to_string())?;
    let synapse_populate_ms = round3(t.elapsed().as_secs_f64() * 1000.0);

    // Populate Git with the same proposals through the plumbing path.
    let t = Instant::now();
    let plumbing = git_arm::g3_setup_agent(
        clone,
        &spec.base_commit,
        &spec.cell_dir.join("plumbing"),
        0,
        &[],
    )?;
    for pop in populated.iter_mut() {
        pop.commit = git_arm::g3_op(clone, &spec.base_commit, &plumbing, &pop.proposal, &[])?;
    }
    let git_populate_ms = round3(t.elapsed().as_secs_f64() * 1000.0);

    // Transfer estimate (outside any timing).
    let mut thin_pack = Vec::with_capacity(populated.len());
    for pop in &populated {
        let out = git_ok(
            clone,
            &[],
            &[],
            &["pack-objects", "--thin", "--stdout", "--revs", "-q"],
            Some(format!("{}\n^{}\n", pop.commit, spec.base_commit).into_bytes()),
        )?;
        thin_pack.push(out.len() as u64);
    }
    let wire: Vec<u64> = populated.iter().map(|p| p.wire_bytes).collect();
    let raw: Vec<u64> = populated
        .iter()
        .map(|p| p.proposal.content_bytes())
        .collect();
    let transfer = TransferEstimate {
        label: "ESTIMATE".into(),
        proposals: populated.len(),
        synapse_json_request_bytes: byte_summary(&wire),
        raw_content_bytes: byte_summary(&raw),
        git_thin_pack_bytes: byte_summary(&thin_pack),
        notes: vec![
            "No Synapse network protocol exists yet; the JSON request is this harness's wire approximation and serde_json encodes blob bytes as decimal arrays.".into(),
            "The Git figure is the thin pack a receiver that already has the base commit would need; protocol negotiation overhead is excluded on both sides.".into(),
        ],
    };

    // Sample selection.
    let mut rng = SplitMix64::derive(spec.seed, &[spec.rep as u64, 0x0E_E7]);
    let n = populated.len();
    let readable: Vec<(usize, String, std::sync::Arc<Vec<u8>>)> = populated
        .iter()
        .enumerate()
        .flat_map(|(i, p)| {
            p.proposal.edits.iter().filter_map(move |e| match &e.op {
                EditOp::Upsert { content, .. } => Some((i, e.path.clone(), content.clone())),
                EditOp::Delete => None,
            })
        })
        .collect();
    if readable.is_empty() || n < 2 {
        return Err("query population has no upserted files".into());
    }
    let reads: Vec<usize> = (0..spec.samples)
        .map(|_| rng.below(readable.len()))
        .collect();
    let trees: Vec<usize> = (0..spec.samples).map(|_| rng.below(n)).collect();
    let diffs: Vec<usize> = (0..spec.samples).map(|_| rng.below(n)).collect();
    let confl: Vec<usize> = (0..spec.samples).map(|_| rng.below(n)).collect();
    let pairs: Vec<(usize, usize)> = (0..spec.samples)
        .map(|_| {
            let i = rng.below(n);
            let mut j = rng.below(n - 1);
            if j >= i {
                j += 1;
            }
            (i, j)
        })
        .collect();

    let reader = &ids.agents[0];
    let mut client = SynapseClient {
        svc: &mut svc,
        agent: reader,
        repo_id: &ids.repo_id,
        counter: 0,
    };
    let mut rows: Vec<QueryTrace> = Vec::new();
    let mut kinds: Vec<QueryKindResult> = Vec::new();
    let rep = spec.rep;

    // read_file (Synapse) vs cat-file --batch (persistent) vs cat-file blob (spawn).
    let mut chunk = Vec::new();
    for (s, &ri) in reads.iter().enumerate() {
        let (pi, path, expected) = &readable[ri];
        let cs = populated[*pi].changeset;
        let mut t = trace(rep, "read_file/synapse", s);
        let before = client.svc.tree_store().stats().root_builds;
        let start = Instant::now();
        let r = client.call(
            (TreeTarget::Changeset(cs), path.clone(), None),
            |svc, req, now| svc.read_file(req, now),
        );
        t.latency_us = start.elapsed().as_micros() as u64;
        t.cold = Some(client.svc.tree_store().stats().root_builds > before);
        match r {
            Ok(c) if c.value.as_slice() == expected.as_slice() => {
                t.ok = true;
                t.api_us = Some(c.api_us);
                t.request_bytes = Some(c.request_bytes);
                t.response_bytes = Some(c.response_bytes);
                t.result_items = Some(1);
            }
            Ok(_) => t.error = Some("read_file returned unexpected bytes".into()),
            Err(e) => t.error = Some(e),
        }
        chunk.push(t);
    }
    kinds.push(summarize_kind(
        "read_file",
        "synapse",
        "SynapseService::read_file (signed request, JSON wire round trip both ways)",
        &chunk,
    ));
    rows.append(&mut chunk);

    let mut batch = CatFileBatch::spawn(clone)?;
    for (s, &ri) in reads.iter().enumerate() {
        let (pi, path, expected) = &readable[ri];
        let spec_str = format!("{}:{}", populated[*pi].commit, path);
        let mut t = trace(rep, "read_file/git-cat-file-batch", s);
        let start = Instant::now();
        let r = batch.read(&spec_str);
        t.latency_us = start.elapsed().as_micros() as u64;
        match r {
            Ok(bytes) if bytes.as_slice() == expected.as_slice() => {
                t.ok = true;
                t.response_bytes = Some(bytes.len() as u64);
            }
            Ok(_) => t.error = Some("cat-file --batch returned unexpected bytes".into()),
            Err(e) => t.error = Some(e),
        }
        chunk.push(t);
    }
    batch.finish()?;
    kinds.push(summarize_kind(
        "read_file",
        "git",
        "git cat-file --batch (one persistent process, request/response per read)",
        &chunk,
    ));
    rows.append(&mut chunk);

    for (s, &ri) in reads.iter().enumerate() {
        let (pi, path, expected) = &readable[ri];
        let spec_str = format!("{}:{}", populated[*pi].commit, path);
        let mut t = trace(rep, "read_file/git-cat-file-spawn", s);
        let start = Instant::now();
        let r = git_ok(clone, &[], &[], &["cat-file", "blob", &spec_str], None);
        t.latency_us = start.elapsed().as_micros() as u64;
        match r {
            Ok(bytes) if bytes.as_slice() == expected.as_slice() => {
                t.ok = true;
                t.response_bytes = Some(bytes.len() as u64);
            }
            Ok(_) => t.error = Some("cat-file blob returned unexpected bytes".into()),
            Err(e) => t.error = Some(e),
        }
        chunk.push(t);
    }
    kinds.push(summarize_kind(
        "read_file",
        "git",
        "git cat-file blob <commit>:<path> (process spawn per read)",
        &chunk,
    ));
    rows.append(&mut chunk);

    // tree (all pages) vs git ls-tree -r.
    let mut syn_tree_counts = Vec::new();
    for (s, &i) in trees.iter().enumerate() {
        let target = TreeTarget::Changeset(populated[i].changeset);
        let mut t = trace(rep, "tree/synapse", s);
        let before = client.svc.tree_store().stats().root_builds;
        let start = Instant::now();
        let r = client.all_pages(
            |page| TreeQueryPayload {
                target,
                path_prefix: None,
                page,
            },
            SynapseService::tree,
        );
        t.latency_us = start.elapsed().as_micros() as u64;
        t.cold = Some(client.svc.tree_store().stats().root_builds > before);
        match r {
            Ok((items, pages, api, rq, rs)) => {
                t.ok = true;
                t.result_items = Some(items);
                t.pages = Some(pages);
                t.api_us = Some(api);
                t.request_bytes = Some(rq);
                t.response_bytes = Some(rs);
                syn_tree_counts.push(Some(items));
            }
            Err(e) => {
                t.error = Some(e);
                syn_tree_counts.push(None);
            }
        }
        chunk.push(t);
    }
    kinds.push(summarize_kind(
        "tree",
        "synapse",
        "SynapseService::tree, every page (limit 256), signed and JSON round-tripped",
        &chunk,
    ));
    rows.append(&mut chunk);

    let mut tree_mismatch = 0usize;
    for (s, &i) in trees.iter().enumerate() {
        let mut t = trace(rep, "tree/git-ls-tree", s);
        let start = Instant::now();
        let r = git_ok(
            clone,
            &[],
            &[],
            &["ls-tree", "-r", &populated[i].commit],
            None,
        );
        t.latency_us = start.elapsed().as_micros() as u64;
        match r {
            Ok(out) => {
                t.ok = true;
                let items = line_count(&out);
                t.result_items = Some(items);
                t.response_bytes = Some(out.len() as u64);
                if syn_tree_counts[s] != Some(items) {
                    tree_mismatch += 1;
                }
            }
            Err(e) => t.error = Some(e),
        }
        chunk.push(t);
    }
    kinds.push(summarize_kind(
        "tree",
        "git",
        "git ls-tree -r <commit> (process spawn, full output read)",
        &chunk,
    ));
    rows.append(&mut chunk);

    // diff (all pages) vs git diff-tree -r --name-status.
    let mut syn_diff_counts = Vec::new();
    for (s, &i) in diffs.iter().enumerate() {
        let target = TreeTarget::Changeset(populated[i].changeset);
        let mut t = trace(rep, "diff/synapse", s);
        let before = client.svc.tree_store().stats().root_builds;
        let start = Instant::now();
        let r = client.all_pages(
            |page| DiffQueryPayload {
                base: TreeTarget::BaseGitCommit(base_oid),
                target,
                page,
            },
            SynapseService::diff,
        );
        t.latency_us = start.elapsed().as_micros() as u64;
        t.cold = Some(client.svc.tree_store().stats().root_builds > before);
        match r {
            Ok((items, pages, api, rq, rs)) => {
                t.ok = true;
                t.result_items = Some(items);
                t.pages = Some(pages);
                t.api_us = Some(api);
                t.request_bytes = Some(rq);
                t.response_bytes = Some(rs);
                syn_diff_counts.push(Some(items));
            }
            Err(e) => {
                t.error = Some(e);
                syn_diff_counts.push(None);
            }
        }
        chunk.push(t);
    }
    kinds.push(summarize_kind(
        "diff",
        "synapse",
        "SynapseService::diff base..changeset, every page, signed and JSON round-tripped",
        &chunk,
    ));
    rows.append(&mut chunk);

    let mut diff_mismatch = 0usize;
    for (s, &i) in diffs.iter().enumerate() {
        let mut t = trace(rep, "diff/git-diff-tree", s);
        let start = Instant::now();
        let r = git_ok(
            clone,
            &[],
            &[],
            &[
                "diff-tree",
                "-r",
                "--name-status",
                &spec.base_commit,
                &populated[i].commit,
            ],
            None,
        );
        t.latency_us = start.elapsed().as_micros() as u64;
        match r {
            Ok(out) => {
                t.ok = true;
                let items = line_count(&out);
                t.result_items = Some(items);
                t.response_bytes = Some(out.len() as u64);
                if syn_diff_counts[s] != Some(items) {
                    diff_mismatch += 1;
                }
            }
            Err(e) => t.error = Some(e),
        }
        chunk.push(t);
    }
    kinds.push(summarize_kind(
        "diff",
        "git",
        "git diff-tree -r --name-status <base> <commit> (process spawn)",
        &chunk,
    ));
    rows.append(&mut chunk);

    // conflicts (Synapse, against every same-base peer) and merge-tree (Git, one pair):
    // different work, reported separately and never as a head-to-head.
    for (s, &i) in confl.iter().enumerate() {
        let candidate = populated[i].changeset;
        let mut t = trace(rep, "conflicts/synapse", s);
        let start = Instant::now();
        let r = client.all_pages(
            |page| ConflictQueryPayload {
                candidate,
                against: None,
                page,
            },
            SynapseService::conflicts,
        );
        t.latency_us = start.elapsed().as_micros() as u64;
        match r {
            Ok((items, pages, api, rq, rs)) => {
                t.ok = true;
                t.result_items = Some(items);
                t.pages = Some(pages);
                t.api_us = Some(api);
                t.request_bytes = Some(rq);
                t.response_bytes = Some(rs);
            }
            Err(e) => t.error = Some(e),
        }
        chunk.push(t);
    }
    kinds.push(summarize_kind(
        "conflicts",
        "synapse",
        "SynapseService::conflicts candidate vs every same-base peer in the population (path level)",
        &chunk,
    ));
    rows.append(&mut chunk);

    for (s, &(i, j)) in pairs.iter().enumerate() {
        let mut t = trace(rep, "merge-tree/git", s);
        let start = Instant::now();
        let r = run_git(
            clone,
            &[],
            &[],
            &[
                "merge-tree",
                "--write-tree",
                &populated[i].commit,
                &populated[j].commit,
            ],
            None,
        );
        t.latency_us = start.elapsed().as_micros() as u64;
        match r {
            Ok(run) if matches!(run.code, Some(0) | Some(1)) => {
                t.ok = true;
                t.result_items = Some(usize::from(run.code == Some(1)));
            }
            Ok(run) => t.error = Some(format!("merge-tree exit {:?}", run.code)),
            Err(e) => t.error = Some(e),
        }
        chunk.push(t);
    }
    kinds.push(summarize_kind(
        "merge-tree",
        "git",
        "git merge-tree --write-tree <commitA> <commitB> for one pair (content-level three-way merge)",
        &chunk,
    ));
    rows.append(&mut chunk);

    let cached_after = client.svc.tree_store().memoized_roots();
    write_jsonl(&spec.trace_path, &rows)?;
    Ok(QueryCellResult {
        rep,
        population_changesets: n,
        samples_per_query: spec.samples,
        synapse_populate_ms,
        git_populate_ms,
        queries: kinds,
        parity: vec![
            ParityCheck {
                check: "tree entry count: Synapse tree == git ls-tree -r".into(),
                compared: trees.len(),
                mismatches: tree_mismatch,
            },
            ParityCheck {
                check: "diff entry count: Synapse diff == git diff-tree -r --name-status".into(),
                compared: diffs.len(),
                mismatches: diff_mismatch,
            },
        ],
        transfer,
        synapse_cached_virtual_trees_after: cached_after,
        peak_rss_self_kib: sample_self()?.maxrss_kib,
    })
}
