//! Trigram content search with the scope filter (ADR 0003 step C3, section 5.7, source [S25]).
//!
//! A query is a regular expression over raw file bytes (`regex::bytes`, linear time, no
//! backtracking). Its syntax tree is reduced to a boolean query over trigrams that every match
//! must contain (Russ Cox, "Regular Expression Matching with a Trigram Index"). Each indexed
//! blob keeps its sorted set of trigrams, so a file whose blob cannot contain a match is passed
//! over without reading a byte; every other file is read and matched in full, so the result is
//! exactly the result of a full scan. A blob the bounded index does not hold is always read.
//!
//! The scope filter runs before any content is touched: the walk enters only the subtrees the
//! caller's `Read` path scope covers, a revision target is resolved through the step B4
//! visibility rule, and the query is evaluated per in-scope file against that file's own
//! trigram set (never by intersecting global posting lists), so no result, count, or amount of
//! work depends on a file outside the caller's scope.

use crate::tree::{TreeEdit, TreeFile};
use crate::{admission_authority, SynapseService, TreeTarget};
use regex::bytes::{Regex, RegexBuilder};
use regex_syntax::hir::{Class, Hir, HirKind};
use std::collections::{BTreeMap, BTreeSet};
use synapse_auth::{BoundaryKind, Capability, ChainedRequest};
use synapse_core::{
    BlobDigest, ChangesetId, GitOid, MutationOp, RefusalCode, SynapseError, SynapseResult,
    TreeDigest,
};

/// Most matching files one search returns.
pub const MAX_SEARCH_RESULTS: usize = 256;
/// Longest accepted pattern, in bytes.
pub const MAX_SEARCH_PATTERN_BYTES: usize = 4096;
/// Most match spans reported per file (`more_spans` says when there were more).
pub const MAX_SPANS_PER_FILE: usize = 16;
/// Compiled program bound for one pattern, in bytes (a larger one is refused, typed).
pub const MAX_REGEX_PROGRAM_BYTES: usize = 1 << 20;
/// Default memory bound of the trigram index.
pub const DEFAULT_SEARCH_INDEX_BYTES: usize = 64 << 20;
/// Default largest blob the index holds; a larger blob is always read and matched.
pub const DEFAULT_MAX_INDEXED_BLOB_BYTES: usize = 4 << 20;

/// Files fetched from the tree per walk step: bounds the memory of one search.
const WALK_PAGE: usize = 1024;
/// Largest literal set kept while planning a query before it is folded into trigrams.
const MAX_EXACT_SET: usize = 64;
/// Largest character class expanded into literals while planning.
const MAX_CLASS_EXPANSION: usize = 32;
/// Most trigrams taken from one literal (a subset is still a necessary condition).
const MAX_TRIGRAMS_PER_LITERAL: usize = 64;
/// Most nodes in a planned query; a larger plan becomes "read every file" (still exact).
const MAX_QUERY_NODES: usize = 4096;
/// Bookkeeping charged per indexed blob on top of its trigrams.
const INDEX_ENTRY_OVERHEAD: usize = 96;

/// What a search runs over.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SearchTarget {
    /// A base Git tree or an envelope v1 changeset tree.
    Tree(TreeTarget),
    /// An envelope v2 revision (step B4): its base tree with its mutations applied. Another
    /// owner's `Private` revision, or one with a mutation outside the caller's path scope, is
    /// `ChangesetNotFound`, exactly like an unknown one (the `read_revision` rule).
    Revision(ChangesetId),
}

/// A search request, carried as the payload of a `ChainedRequest` granting `Read`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchQueryPayload {
    pub target: SearchTarget,
    /// Regular expression over raw bytes (`regex` crate syntax).
    pub pattern: String,
    /// Return only paths strictly after this one (the previous response's `next_after`).
    pub after_path: Option<String>,
    /// 1..=`MAX_SEARCH_RESULTS` files.
    pub limit: u32,
}

const PAYLOAD_TAG: &[u8] = b"SYNAPSE_SEARCH_V1\0";

impl SearchQueryPayload {
    /// Canonical bytes: tag, target kind and id, limit, optional after path, pattern.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = PAYLOAD_TAG.to_vec();
        match self.target {
            SearchTarget::Tree(TreeTarget::BaseGitCommit(oid)) => {
                out.push(0);
                out.extend_from_slice(&oid.0);
            }
            SearchTarget::Tree(TreeTarget::Changeset(id)) => {
                out.push(1);
                out.extend_from_slice(&id.0);
            }
            SearchTarget::Revision(id) => {
                out.push(2);
                out.extend_from_slice(&id.0);
            }
        }
        out.extend_from_slice(&self.limit.to_le_bytes());
        match &self.after_path {
            None => out.push(0),
            Some(p) => {
                out.push(1);
                put_bytes(&mut out, p.as_bytes());
            }
        }
        put_bytes(&mut out, self.pattern.as_bytes());
        out
    }

    /// Strict decode: any truncation, unknown kind, non-UTF-8 text, or trailing byte is
    /// `EnvelopeMalformed`.
    pub fn decode(bytes: &[u8]) -> SynapseResult<Self> {
        let mut r = Reader(bytes);
        if r.take(PAYLOAD_TAG.len())? != PAYLOAD_TAG {
            return Err(malformed("search payload tag"));
        }
        let target = match r.take(1)?[0] {
            0 => SearchTarget::Tree(TreeTarget::BaseGitCommit(GitOid(r.array()?))),
            1 => SearchTarget::Tree(TreeTarget::Changeset(ChangesetId(r.array()?))),
            2 => SearchTarget::Revision(ChangesetId(r.array()?)),
            _ => return Err(malformed("search target kind")),
        };
        let limit = u32::from_le_bytes(r.array()?);
        let after_path = match r.take(1)?[0] {
            0 => None,
            1 => Some(r.text()?),
            _ => return Err(malformed("search after_path flag")),
        };
        let pattern = r.text()?;
        if !r.0.is_empty() {
            return Err(malformed("search payload has trailing bytes"));
        }
        Ok(Self {
            target,
            pattern,
            after_path,
            limit,
        })
    }
}

fn put_bytes(out: &mut Vec<u8>, b: &[u8]) {
    out.extend_from_slice(&(b.len() as u32).to_le_bytes());
    out.extend_from_slice(b);
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> SynapseResult<&'a [u8]> {
        if self.0.len() < n {
            return Err(malformed("search payload truncated"));
        }
        let (head, tail) = self.0.split_at(n);
        self.0 = tail;
        Ok(head)
    }

    fn array<const N: usize>(&mut self) -> SynapseResult<[u8; N]> {
        let mut a = [0u8; N];
        a.copy_from_slice(self.take(N)?);
        Ok(a)
    }

    fn text(&mut self) -> SynapseResult<String> {
        let n = u32::from_le_bytes(self.array()?) as usize;
        let b = self.take(n)?;
        String::from_utf8(b.to_vec()).map_err(|_| malformed("search text is not UTF-8"))
    }
}

fn malformed(what: &str) -> SynapseError {
    SynapseError::new(RefusalCode::EnvelopeMalformed, what.to_string())
}

/// One matching file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchMatch {
    pub path: String,
    pub blob_digest: BlobDigest,
    /// Byte ranges `[start, end)` of the first `MAX_SPANS_PER_FILE` non-overlapping matches,
    /// leftmost first.
    pub spans: Vec<(u64, u64)>,
    /// True when the file has more matches than `spans` lists.
    pub more_spans: bool,
}

/// One page of results, in path byte order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchResponse {
    pub matches: Vec<SearchMatch>,
    /// Set when more matching files follow: pass it as `after_path` for the next page.
    pub next_after: Option<String>,
}

/// Memory bounds of the trigram index.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SearchIndexConfig {
    pub max_bytes: usize,
    pub max_blob_bytes: usize,
}

impl Default for SearchIndexConfig {
    fn default() -> Self {
        Self {
            max_bytes: DEFAULT_SEARCH_INDEX_BYTES,
            max_blob_bytes: DEFAULT_MAX_INDEXED_BLOB_BYTES,
        }
    }
}

/// Result of indexing one tree.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct IndexReport {
    /// Distinct blobs newly indexed.
    pub indexed: u64,
    /// Blobs already in the index.
    pub already: u64,
    /// Blobs left out (too large, or the memory bound is reached); always read when searched.
    pub skipped: u64,
}

/// Server-side counters (never returned to a caller).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SearchStats {
    /// In-scope files passed over by the trigram query without reading their bytes.
    pub files_pruned: u64,
    /// In-scope files read and matched.
    pub files_read: u64,
}

/// Bounded per-blob trigram index. Content addressed, so one entry serves every tree that
/// holds the blob. Trigrams are packed into the low 24 bits of a `u32`.
#[derive(Debug, Default)]
pub struct SearchIndex {
    config: SearchIndexConfig,
    blobs: BTreeMap<BlobDigest, Box<[u32]>>,
    bytes: usize,
    stats: SearchStats,
}

impl SearchIndex {
    pub fn new(config: SearchIndexConfig) -> Self {
        Self {
            config,
            ..Default::default()
        }
    }

    pub fn config(&self) -> SearchIndexConfig {
        self.config
    }

    /// Bytes charged against `max_bytes`.
    pub fn bytes(&self) -> usize {
        self.bytes
    }

    pub fn indexed_blobs(&self) -> usize {
        self.blobs.len()
    }

    pub fn contains(&self, digest: &BlobDigest) -> bool {
        self.blobs.contains_key(digest)
    }

    pub fn stats(&self) -> SearchStats {
        self.stats
    }

    /// Index `content` under `digest`. `Some(true)` when newly indexed, `Some(false)` when
    /// already present, `None` when left out by a bound.
    pub fn insert(&mut self, digest: BlobDigest, content: &[u8]) -> Option<bool> {
        if self.blobs.contains_key(&digest) {
            return Some(false);
        }
        if content.len() > self.config.max_blob_bytes {
            return None;
        }
        let tris = trigrams_of(content);
        let cost = tris.len() * 4 + INDEX_ENTRY_OVERHEAD;
        if self.bytes.saturating_add(cost) > self.config.max_bytes {
            return None;
        }
        self.bytes += cost;
        self.blobs.insert(digest, tris.into_boxed_slice());
        Some(true)
    }

    /// Whether the blob may hold a match of `query`: true for a blob the index does not hold.
    fn may_match(&self, digest: &BlobDigest, query: &Query) -> bool {
        match self.blobs.get(digest) {
            Some(tris) => query.eval(tris),
            None => true,
        }
    }
}

fn pack(t: &[u8]) -> u32 {
    (u32::from(t[0]) << 16) | (u32::from(t[1]) << 8) | u32::from(t[2])
}

/// Sorted distinct trigrams of `content`.
fn trigrams_of(content: &[u8]) -> Vec<u32> {
    let mut v: Vec<u32> = content.windows(3).map(pack).collect();
    v.sort_unstable();
    v.dedup();
    v.shrink_to_fit();
    v
}

/// A necessary condition on a file's trigram set for a match to exist.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Query {
    /// No condition: every file is a candidate.
    All,
    /// No file can match.
    Nothing,
    Tri(u32),
    And(Vec<Query>),
    Or(Vec<Query>),
}

impl Query {
    fn and(a: Query, b: Query) -> Query {
        match (a, b) {
            (Query::All, x) | (x, Query::All) => x,
            (Query::Nothing, _) | (_, Query::Nothing) => Query::Nothing,
            (Query::And(mut x), Query::And(y)) => {
                x.extend(y);
                Query::And(x)
            }
            (Query::And(mut x), y) | (y, Query::And(mut x)) => {
                x.push(y);
                Query::And(x)
            }
            (x, y) => Query::And(vec![x, y]),
        }
    }

    fn or(a: Query, b: Query) -> Query {
        match (a, b) {
            (Query::Nothing, x) | (x, Query::Nothing) => x,
            (Query::All, _) | (_, Query::All) => Query::All,
            (Query::Or(mut x), Query::Or(y)) => {
                x.extend(y);
                Query::Or(x)
            }
            (Query::Or(mut x), y) | (y, Query::Or(mut x)) => {
                x.push(y);
                Query::Or(x)
            }
            (x, y) => Query::Or(vec![x, y]),
        }
    }

    fn nodes(&self) -> usize {
        match self {
            Query::And(v) | Query::Or(v) => 1 + v.iter().map(Query::nodes).sum::<usize>(),
            _ => 1,
        }
    }

    fn eval(&self, tris: &[u32]) -> bool {
        match self {
            Query::All => true,
            Query::Nothing => false,
            Query::Tri(t) => tris.binary_search(t).is_ok(),
            Query::And(v) => v.iter().all(|q| q.eval(tris)),
            Query::Or(v) => v.iter().any(|q| q.eval(tris)),
        }
    }
}

/// Planning facts of one syntax node: `exact` is the full set of byte strings the node can
/// match, when small enough to keep; `query` is a condition every match satisfies. Invariant:
/// when `exact` is set, `query` is `All`.
struct Info {
    exact: Option<BTreeSet<Vec<u8>>>,
    query: Query,
}

fn empty_string() -> Info {
    Info {
        exact: Some(BTreeSet::from([Vec::new()])),
        query: Query::All,
    }
}

fn anything() -> Info {
    Info {
        exact: None,
        query: Query::All,
    }
}

/// Condition that a match contains one of the strings of `set`.
fn trigrams_of_set(set: &BTreeSet<Vec<u8>>) -> Query {
    let mut q = Query::Nothing;
    for s in set {
        if s.len() < 3 {
            return Query::All;
        }
        let mut tris: Vec<u32> = s.windows(3).map(pack).collect();
        tris.sort_unstable();
        tris.dedup();
        tris.truncate(MAX_TRIGRAMS_PER_LITERAL);
        let all = tris
            .into_iter()
            .fold(Query::All, |acc, t| Query::and(acc, Query::Tri(t)));
        q = Query::or(q, all);
    }
    q
}

fn info_query(i: Info) -> Query {
    match i.exact {
        Some(set) => Query::and(i.query, trigrams_of_set(&set)),
        None => i.query,
    }
}

fn plan(hir: &Hir) -> Info {
    match hir.kind() {
        HirKind::Empty | HirKind::Look(_) => empty_string(),
        HirKind::Literal(lit) => Info {
            exact: Some(BTreeSet::from([lit.0.to_vec()])),
            query: Query::All,
        },
        HirKind::Class(class) => match expand_class(class) {
            Some(set) => Info {
                exact: Some(set),
                query: Query::All,
            },
            None => anything(),
        },
        HirKind::Capture(c) => plan(&c.sub),
        HirKind::Repetition(r) => {
            if r.max == Some(0) {
                empty_string()
            } else if r.min == 0 {
                anything()
            } else if r.min == 1 && r.max == Some(1) {
                plan(&r.sub)
            } else {
                Info {
                    exact: None,
                    query: info_query(plan(&r.sub)),
                }
            }
        }
        HirKind::Concat(subs) => {
            let mut query = Query::All;
            let mut run: Option<BTreeSet<Vec<u8>>> = Some(BTreeSet::from([Vec::new()]));
            let mut whole_exact = true;
            for sub in subs {
                let i = plan(sub);
                match (run.take(), i.exact) {
                    (Some(a), Some(b)) => {
                        if a.len().saturating_mul(b.len()) <= MAX_EXACT_SET {
                            let mut prod = BTreeSet::new();
                            for x in &a {
                                for y in &b {
                                    let mut s = x.clone();
                                    s.extend_from_slice(y);
                                    prod.insert(s);
                                }
                            }
                            run = Some(prod);
                        } else {
                            whole_exact = false;
                            query = Query::and(query, trigrams_of_set(&a));
                            run = Some(b);
                        }
                    }
                    (Some(a), None) => {
                        whole_exact = false;
                        query = Query::and(query, trigrams_of_set(&a));
                        query = Query::and(query, i.query);
                    }
                    (None, Some(b)) => run = Some(b),
                    (None, None) => query = Query::and(query, i.query),
                }
            }
            if whole_exact {
                Info {
                    exact: run,
                    query: Query::All,
                }
            } else {
                if let Some(a) = run {
                    query = Query::and(query, trigrams_of_set(&a));
                }
                Info { exact: None, query }
            }
        }
        HirKind::Alternation(subs) => {
            let infos: Vec<Info> = subs.iter().map(plan).collect();
            let union_len: usize = infos
                .iter()
                .map(|i| i.exact.as_ref().map_or(usize::MAX, BTreeSet::len))
                .fold(0usize, usize::saturating_add);
            if union_len <= MAX_EXACT_SET {
                let mut set = BTreeSet::new();
                for i in infos {
                    set.extend(i.exact.unwrap_or_default());
                }
                Info {
                    exact: Some(set),
                    query: Query::All,
                }
            } else {
                let query = infos
                    .into_iter()
                    .fold(Query::Nothing, |acc, i| Query::or(acc, info_query(i)));
                Info { exact: None, query }
            }
        }
    }
}

/// The byte strings a small class matches (UTF-8 encodings for a Unicode class).
fn expand_class(class: &Class) -> Option<BTreeSet<Vec<u8>>> {
    let mut out = BTreeSet::new();
    match class {
        Class::Unicode(c) => {
            for r in c.ranges() {
                for ch in r.start()..=r.end() {
                    if out.len() >= MAX_CLASS_EXPANSION {
                        return None;
                    }
                    let mut buf = [0u8; 4];
                    out.insert(ch.encode_utf8(&mut buf).as_bytes().to_vec());
                }
            }
        }
        Class::Bytes(c) => {
            for r in c.ranges() {
                for b in r.start()..=r.end() {
                    if out.len() >= MAX_CLASS_EXPANSION {
                        return None;
                    }
                    out.insert(vec![b]);
                }
            }
        }
    }
    Some(out)
}

/// A compiled pattern and its trigram query.
struct Compiled {
    regex: Regex,
    query: Query,
}

/// Compile `pattern` the way `regex::bytes` does (Unicode on, UTF-8 matching off) and plan
/// its trigram query from the same syntax tree.
fn compile(pattern: &str) -> SynapseResult<Compiled> {
    if pattern.len() > MAX_SEARCH_PATTERN_BYTES {
        return Err(SynapseError::new(
            RefusalCode::QuotaPayloadTooLarge,
            format!("search pattern exceeds {MAX_SEARCH_PATTERN_BYTES} bytes"),
        ));
    }
    let regex = RegexBuilder::new(pattern)
        .size_limit(MAX_REGEX_PROGRAM_BYTES)
        .dfa_size_limit(MAX_REGEX_PROGRAM_BYTES)
        .build()
        .map_err(|e| malformed(&format!("search pattern: {e}")))?;
    let hir = regex_syntax::ParserBuilder::new()
        .utf8(false)
        .build()
        .parse(pattern)
        .map_err(|e| malformed(&format!("search pattern: {e}")))?;
    let mut query = info_query(plan(&hir));
    if query.nodes() > MAX_QUERY_NODES {
        query = Query::All;
    }
    Ok(Compiled { regex, query })
}

/// Match spans of `regex` in `content`.
fn spans_of(regex: &Regex, content: &[u8]) -> (Vec<(u64, u64)>, bool) {
    let mut spans = Vec::new();
    for m in regex.find_iter(content) {
        if spans.len() == MAX_SPANS_PER_FILE {
            return (spans, true);
        }
        spans.push((m.start() as u64, m.end() as u64));
    }
    (spans, false)
}

impl SynapseService {
    /// The trigram index (read-only view, for bounds and statistics).
    pub fn search_index(&self) -> &SearchIndex {
        &self.search_index
    }

    /// Replace the trigram index with an empty one bounded by `config`.
    pub fn set_search_index_config(&mut self, config: SearchIndexConfig) {
        self.search_index = SearchIndex::new(config);
    }

    /// Server-side step: add every blob of `target` to the trigram index, within its bounds.
    /// Not on behalf of a key (no visibility filter), and never run by a search, so the
    /// index's contents never depend on what any caller searched.
    pub fn index_search_content(&mut self, target: SearchTarget) -> SynapseResult<IndexReport> {
        let mut report = IndexReport::default();
        let mut offset = 0u64;
        loop {
            let page = self.search_page(target, None, "", offset)?;
            let n = page.len();
            for (_, file) in page {
                if self.search_index.contains(&file.blob_digest) {
                    report.already += 1;
                    continue;
                }
                let bytes = self.read_blob_bytes(file.blob_digest, None)?;
                match self.search_index.insert(file.blob_digest, &bytes) {
                    Some(true) => report.indexed += 1,
                    Some(false) => report.already += 1,
                    None => report.skipped += 1,
                }
            }
            if n < WALK_PAGE {
                return Ok(report);
            }
            offset += n as u64;
        }
    }

    /// Content search (ADR 0003 step C3) under an F1 delegation chain granting `Read`.
    /// `req.payload` is a [`SearchQueryPayload`]. Only files the chain's leaf path scope
    /// covers are walked, pruned, read, matched, or returned; a revision target the chain may
    /// not see is `ChangesetNotFound`. Results are in path byte order, at most `limit` files.
    pub fn search(&mut self, req: &ChainedRequest, now_ms: u64) -> SynapseResult<SearchResponse> {
        let q = SearchQueryPayload::decode(&req.payload)?;
        if q.limit == 0 || q.limit as usize > MAX_SEARCH_RESULTS {
            return Err(SynapseError::new(
                RefusalCode::PaginationLimitExceeded,
                format!("search limit must be 1..={MAX_SEARCH_RESULTS}"),
            ));
        }
        let compiled = compile(&q.pattern)?;
        self.auth.authorize_chain(
            BoundaryKind::Api,
            "search",
            &self.repo_id,
            Capability::Read,
            req,
            self.store.committed_seq().next(),
            now_ms,
        )?;
        let scope = req
            .chain
            .leaf()
            .map(|leaf| leaf.caveats.paths.clone())
            .ok_or_else(|| {
                SynapseError::new(RefusalCode::AuthChainBroken, "search: empty chain")
            })?;
        let revision_root = match q.target {
            SearchTarget::Tree(_) => None,
            SearchTarget::Revision(id) => {
                let viewer = admission_authority(req)?.chain;
                let rev = self
                    .store
                    .get_revision_visible_to(&self.repo_id, id, &viewer)?;
                if !rev
                    .content
                    .mutations
                    .iter()
                    .all(|m| scope.covers_path(&m.path))
                {
                    return Err(SynapseError::new(
                        RefusalCode::ChangesetNotFound,
                        format!("revision {id} not found"),
                    ));
                }
                Some(self.revision_root(id)?)
            }
        };
        let limit = q.limit as usize;
        let mut found: BTreeMap<String, SearchMatch> = BTreeMap::new();
        let mut consider = |svc: &mut Self, path: String, file: TreeFile| -> SynapseResult<()> {
            if q.after_path.as_deref().is_some_and(|a| path.as_str() <= a) {
                return Ok(());
            }
            if found.len() > limit && found.last_key_value().is_some_and(|(k, _)| path > *k) {
                return Ok(());
            }
            if !svc
                .search_index
                .may_match(&file.blob_digest, &compiled.query)
            {
                svc.search_index.stats.files_pruned += 1;
                return Ok(());
            }
            svc.search_index.stats.files_read += 1;
            let bytes = svc.read_blob_bytes(file.blob_digest, None)?;
            let (spans, more_spans) = spans_of(&compiled.regex, &bytes);
            if !spans.is_empty() {
                found.insert(
                    path.clone(),
                    SearchMatch {
                        path,
                        blob_digest: file.blob_digest,
                        spans,
                        more_spans,
                    },
                );
                if found.len() > limit + 1 {
                    found.pop_last();
                }
            }
            Ok(())
        };
        for prefix in scope.prefixes() {
            // A scope prefix covers the file at that exact path and everything under `prefix/`.
            let walk_prefix = if prefix.is_empty() {
                String::new()
            } else {
                if let Some(file) = self.search_lookup(q.target, revision_root, prefix)? {
                    consider(self, prefix.clone(), file)?;
                }
                format!("{prefix}/")
            };
            let mut offset = 0u64;
            loop {
                let page = self.search_page(q.target, revision_root, &walk_prefix, offset)?;
                let n = page.len();
                for (path, file) in page {
                    consider(self, path, file)?;
                }
                if n < WALK_PAGE {
                    break;
                }
                offset += n as u64;
            }
        }
        let next_after = if found.len() > limit {
            found.pop_last();
            found.last_key_value().map(|(k, _)| k.clone())
        } else {
            None
        };
        Ok(SearchResponse {
            matches: found.into_values().collect(),
            next_after,
        })
    }

    /// The tree of a v2 revision: its base tree with its mutations applied (server side).
    fn revision_root(&mut self, id: ChangesetId) -> SynapseResult<TreeDigest> {
        let rev = self.store.get_revision(&self.repo_id, id)?;
        let mut edit = TreeEdit::new(&mut self.trees, rev.content.base_tree)?;
        for m in &rev.content.mutations {
            match &m.op {
                MutationOp::Upsert {
                    mode,
                    blob_digest,
                    size_bytes,
                } => {
                    let raw = self.read_blob_bytes(*blob_digest, None)?;
                    let file = TreeFile {
                        mode: *mode,
                        blob_digest: *blob_digest,
                        size_bytes: *size_bytes,
                        git_blob_oid: GitOid::compute_blob(&raw),
                    };
                    edit.upsert(&mut self.trees, &m.path, file)?;
                }
                MutationOp::Delete => edit.delete(&mut self.trees, &m.path)?,
            }
        }
        edit.finish(&mut self.trees)
    }

    /// One walk page of `target` under `prefix`. `revision_root` is the root already built
    /// for a revision target (built here when absent); it is rebuilt once if the bounded tree
    /// store evicted part of it.
    fn search_page(
        &mut self,
        target: SearchTarget,
        revision_root: Option<TreeDigest>,
        prefix: &str,
        offset: u64,
    ) -> SynapseResult<Vec<(String, TreeFile)>> {
        match target {
            SearchTarget::Tree(t) => self.with_tree(t, None, |trees, root| {
                trees.page_files(root, prefix, offset, WALK_PAGE)
            }),
            SearchTarget::Revision(id) => {
                let root = match revision_root {
                    Some(r) => r,
                    None => self.revision_root(id)?,
                };
                match self.trees.page_files(root, prefix, offset, WALK_PAGE) {
                    Err(e) if e.code == RefusalCode::TreeNodeNotFound => {
                        let root = self.revision_root(id)?;
                        self.trees.page_files(root, prefix, offset, WALK_PAGE)
                    }
                    other => other,
                }
            }
        }
    }

    fn search_lookup(
        &mut self,
        target: SearchTarget,
        revision_root: Option<TreeDigest>,
        path: &str,
    ) -> SynapseResult<Option<TreeFile>> {
        match (target, revision_root) {
            (SearchTarget::Tree(t), _) => {
                self.with_tree(t, None, |trees, root| trees.lookup(root, path))
            }
            (SearchTarget::Revision(id), root) => {
                let root = match root {
                    Some(r) => r,
                    None => self.revision_root(id)?,
                };
                match self.trees.lookup(root, path) {
                    Err(e) if e.code == RefusalCode::TreeNodeNotFound => {
                        let root = self.revision_root(id)?;
                        self.trees.lookup(root, path)
                    }
                    other => other,
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn candidates(pattern: &str, content: &[u8]) -> bool {
        compile(pattern).unwrap().query.eval(&trigrams_of(content))
    }

    /// The planned query never prunes a file the pattern matches, and does prune files that
    /// lack a required literal.
    #[test]
    fn planned_query_is_necessary_and_prunes() {
        let cases: &[(&str, &[u8])] = &[
            ("hello", b"say hello world"),
            ("(?i)hello", b"say HeLLo world"),
            ("foo|barbaz", b"xx barbaz"),
            ("ab+c", b"abbbbc"),
            ("a.c", b"axc"),
            ("serve\\(\\)", b"pub fn serve() {}"),
            ("[0-9]{3}-wal", b"seg 042-wal"),
            ("\u{e9}t\u{e9}", "caf\u{e9} \u{e9}t\u{e9}".as_bytes()),
            ("(?-u)\\xFF\\xFEabc", b"\xff\xfeabc"),
            ("^$", b""),
            ("x*", b""),
        ];
        for (p, c) in cases {
            let re = compile(p).unwrap();
            assert!(re.regex.is_match(c), "{p} should match");
            assert!(re.query.eval(&trigrams_of(c)), "{p} pruned a match");
        }
        assert!(!candidates("hello", b"help low"));
        assert!(!candidates("foo|barbaz", b"bar baz fo"));
        assert!(!candidates("[0-9]{3}-wal", b"no digits"));
        assert!(candidates(".*", b"anything"));
    }

    #[test]
    fn index_bounds_are_enforced() {
        let mut idx = SearchIndex::new(SearchIndexConfig {
            max_bytes: 200,
            max_blob_bytes: 64,
        });
        let small = b"abcdef";
        let d = BlobDigest::compute(small);
        assert_eq!(idx.insert(d, small), Some(true));
        assert_eq!(idx.insert(d, small), Some(false));
        let big = [b'a'; 65];
        assert_eq!(idx.insert(BlobDigest::compute(&big), &big), None);
        let many: Vec<u8> = (0u8..=60).collect();
        assert_eq!(idx.insert(BlobDigest::compute(&many), &many), None);
        assert!(idx.bytes() <= 200);
        assert!(!idx.contains(&BlobDigest::compute(&big)));
    }

    #[test]
    fn payload_round_trips_and_malformed_payloads_are_refused() {
        let p = SearchQueryPayload {
            target: SearchTarget::Revision(ChangesetId([7; 32])),
            pattern: "fn \\w+".into(),
            after_path: Some("src/a.rs".into()),
            limit: 10,
        };
        let bytes = p.encode();
        assert_eq!(SearchQueryPayload::decode(&bytes).unwrap(), p);
        for cut in 0..bytes.len() {
            assert!(SearchQueryPayload::decode(&bytes[..cut]).is_err());
        }
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(SearchQueryPayload::decode(&trailing).is_err());
        let mut bad_kind = bytes;
        bad_kind[PAYLOAD_TAG.len()] = 9;
        assert!(SearchQueryPayload::decode(&bad_kind).is_err());
    }

    #[test]
    fn malformed_and_oversized_patterns_are_refused_typed() {
        assert_eq!(
            compile("(unclosed").err().unwrap().code,
            RefusalCode::EnvelopeMalformed
        );
        let long = "a".repeat(MAX_SEARCH_PATTERN_BYTES + 1);
        assert_eq!(
            compile(&long).err().unwrap().code,
            RefusalCode::QuotaPayloadTooLarge
        );
        assert!(compile("\\w{1000}\\w{1000}\\w{1000}").is_err());
    }
}
