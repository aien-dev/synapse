//! ADR 0003 step C3 through the API with real signed F1 capability chains: authority `A`
//! grants orchestrator `O` and outsider `X` (whole repository); `O` delegates worker `W`
//! (scoped to `src`), worker `V` (whole repository), and reader `D` (scoped to `docs`).
//!
//! Acceptance: every regular expression of a fixed query set returns exactly the matches of a
//! full scan of the same trees (before and after indexing); no result, count, or amount of
//! work reveals a file outside the caller's `Read` scope or another owner's `Private` revision.

use ed25519_dalek::SigningKey;
use regex::bytes::Regex;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use synapse_api::{
    RevisionStateMovePayload, SearchMatch, SearchQueryPayload, SearchResponse, SearchTarget,
    SynapseService, TreeTarget, MAX_SPANS_PER_FILE,
};
use synapse_auth::{
    Capability, CapabilityChain, CapabilityLink, ChainQuotas, ChainedRequest, ChangeScope,
    LinkCaveats, OperationSet, PathScope, ReferenceKind, ReferenceScope, RequestScope, ROOT_PARENT,
};
use synapse_core::{
    encode_did_key_ed25519, BlobDigest, ChangeId, ChangesetEnvelopeV2, ChangesetId, FileMode,
    GitOid, IdempotencyKey, MutationOp, PathMutation, RefusalCode, RepoId, RevisionContent,
    RevisionState, TreeDigest, WalSeq,
};
use synapse_store::{FsyncPolicy, RecoveryPolicy, RevisionOutcome, StoreLimits};

const NOW: u64 = 2_000;
const C: ChangeId = ChangeId([0xC3; 16]);
const BASE: GitOid = GitOid([0x0C; 20]);

type Agent = (SigningKey, CapabilityChain);

/// The fixed query set: literals, case folding, classes, alternation, repetition, anchors,
/// Unicode, raw non-UTF-8 bytes, and patterns no trigram can narrow.
const QUERIES: &[&str] = &[
    "secret",
    "SECRET_KEY",
    "(?i)secret_key",
    "fn [a-z_]+\\(",
    "serve|parse_frame",
    "wal_[0-9]{2}",
    "(?m)^pub ",
    "caf\u{e9}",
    "(?-u)\\xFF\\xFE",
    "(?-u)\\xFFnul",
    "TODO.*later",
    "\\bmod\\b",
    "[a-c]{3}x",
    "zzz_never_present",
    ".",
    "x?",
];

fn link_nonces(dir: &Path) -> impl FnMut() -> [u8; 32] {
    let seed = dir.to_string_lossy().into_owned();
    let mut issued = 0u32;
    move || {
        issued += 1;
        let mut h = Sha256::new();
        h.update(seed.as_bytes());
        h.update(issued.to_le_bytes());
        h.finalize().into()
    }
}

fn repo() -> RepoId {
    RepoId::new("aien-spark/synapse").unwrap()
}

fn pk(k: &SigningKey) -> [u8; 32] {
    k.verifying_key().to_bytes()
}

fn caveats(paths: PathScope, share: u64) -> LinkCaveats {
    LinkCaveats {
        operations: OperationSet::from_capabilities(&[Capability::Read, Capability::Propose]),
        paths,
        references: ReferenceScope::from_kinds(&[ReferenceKind::OwnDrafts]),
        changes: ChangeScope::any(),
        quotas: ChainQuotas {
            max_ops_per_window: (100_000 / share) as u32,
            window_duration_ms: 60_000,
            storage_bytes: (1 << 30) / share,
            footprint_paths: (1 << 20) / share,
            max_bytes_per_op: 1 << 20,
        },
        issued_at_ms: 1_000,
        expires_at_ms: 100_000,
    }
}

fn base_files() -> Vec<(String, FileMode, Vec<u8>)> {
    let f = |p: &str, b: &[u8]| (p.to_string(), FileMode::Regular644, b.to_vec());
    let mut v = vec![
        f("README.md", b"Synapse: TODO explain later\nabcx\n"),
        f(
            "src/lib.rs",
            b"pub mod wal;\npub fn serve() {}\n// TODO tidy later\n",
        ),
        f(
            "src/wal.rs",
            b"pub fn parse_frame(b: &[u8]) {}\nconst WAL: &str = \"wal_07\";\n",
        ),
        f(
            "src/bin/\u{e9}t\u{e9}.rs",
            "fn main() { println!(\"caf\u{e9}\"); }\n".as_bytes(),
        ),
        f(
            "src/raw.bin",
            b"\xff\xfe\x00\xffnul binary \xc3 not utf8 secret",
        ),
        f(
            "src-other/leak.rs",
            b"SECRET_KEY = \"src-other must not leak to src\"\n",
        ),
        f(
            "docs/guide.md",
            b"# Guide\nThe secret is in the wal_42 chapter. bbcx\n",
        ),
        f(
            "docs/caf\u{e9}.md",
            "caf\u{e9} au lait, fn brew(\n".as_bytes(),
        ),
        f(
            "private/keys.env",
            b"SECRET_KEY=hunter2\nsecret_key=lower\n",
        ),
        f(
            "private/notes.txt",
            b"pub fn serve_secretly() {}\nTODO do it later\n",
        ),
    ];
    // Enough files to need several walk pages and to give the index something to prune.
    for i in 0..1500 {
        v.push(f(
            &format!("src/gen/m{i:04}.rs"),
            format!("pub fn generated_{i}() -> u32 {{ {i} }}\n").as_bytes(),
        ));
    }
    v.push(f(
        "src/gen/m0777.rs",
        b"pub fn generated_777() { /* secret */ }\n",
    ));
    v.sort_by(|a, b| a.0.cmp(&b.0));
    v.dedup_by(|a, b| a.0 == b.0);
    v
}

struct Fx {
    svc: SynapseService,
    base: TreeDigest,
    o: Agent,
    w: Agent,
    v: Agent,
    d: Agent,
    x: Agent,
    nonce: u32,
}

impl Fx {
    fn new(name: &str, files: Vec<(String, FileMode, Vec<u8>)>) -> Self {
        let dir: PathBuf = std::env::temp_dir().join(format!(
            "synapse-c3-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let mut svc = SynapseService::open(
            &dir,
            repo(),
            FsyncPolicy::EveryCommit,
            RecoveryPolicy::StrictFailClosed,
            StoreLimits {
                wal_prealloc_bytes: 64 * 1024,
                ..Default::default()
            },
        )
        .unwrap();
        let a = SigningKey::from_bytes(&[1; 32]);
        let key = |n: u8| SigningKey::from_bytes(&[n; 32]);
        let (o, w, v, d, x) = (key(2), key(3), key(4), key(5), key(9));
        svc.auth_mut()
            .register_repo_authority(repo(), encode_did_key_ed25519(&pk(&a)));
        let whole = PathScope::whole_repository;
        let mut nonce = link_nonces(&dir);
        let root = |nonce: [u8; 32], to: &SigningKey| {
            CapabilityLink::issue(&a, ROOT_PARENT, nonce, repo(), pk(to), caveats(whole(), 1))
        };
        let root_o = root(nonce(), &o);
        let root_x = root(nonce(), &x);
        let child = |nonce: [u8; 32], to: &SigningKey, paths: PathScope| {
            CapabilityLink::issue(
                &o,
                root_o.digest(),
                nonce,
                repo(),
                pk(to),
                caveats(paths, 4),
            )
        };
        let link_w = child(nonce(), &w, PathScope::new(vec!["src".into()]).unwrap());
        let link_v = child(nonce(), &v, whole());
        let link_d = child(nonce(), &d, PathScope::new(vec!["docs".into()]).unwrap());
        let co = CapabilityChain::new(vec![root_o]);
        let cx = CapabilityChain::new(vec![root_x]);
        let (cw, cv, cd) = (
            co.extended(link_w),
            co.extended(link_v),
            co.extended(link_d),
        );
        for c in [&co, &cx, &cw, &cv, &cd] {
            svc.auth_mut().grant_link(c, WalSeq(0), NOW).unwrap();
        }
        svc.register_base_tree(BASE, files).unwrap();
        let base = svc
            .tree_digest(TreeTarget::BaseGitCommit(BASE), None)
            .unwrap();
        Self {
            svc,
            base,
            o: (o, co),
            w: (w, cw),
            v: (v, cv),
            d: (d, cd),
            x: (x, cx),
            nonce: 0,
        }
    }

    fn request(
        &mut self,
        who: &Agent,
        cap: Capability,
        scope: RequestScope,
        payload: Vec<u8>,
    ) -> ChainedRequest {
        self.nonce += 1;
        let mut n = [0u8; 32];
        n[..4].copy_from_slice(&self.nonce.to_le_bytes());
        ChainedRequest::sign_new(&who.0, who.1.clone(), repo(), cap, scope, n, NOW, payload)
    }

    fn search_page(
        &mut self,
        who: &Agent,
        target: SearchTarget,
        pattern: &str,
        after: Option<String>,
        limit: u32,
    ) -> Result<SearchResponse, (RefusalCode, String)> {
        let payload = SearchQueryPayload {
            target,
            pattern: pattern.into(),
            after_path: after,
            limit,
        }
        .encode();
        let req = self.request(who, Capability::Read, RequestScope::default(), payload);
        self.svc.search(&req, NOW).map_err(|e| (e.code, e.message))
    }

    /// Every match, following `next_after` across pages of `limit`.
    fn search_all(
        &mut self,
        who: &Agent,
        target: SearchTarget,
        pattern: &str,
        limit: u32,
    ) -> Result<Vec<SearchMatch>, (RefusalCode, String)> {
        let mut out = Vec::new();
        let mut after = None;
        loop {
            let page = self.search_page(who, target, pattern, after, limit)?;
            assert!(page.matches.len() <= limit as usize);
            out.extend(page.matches);
            match page.next_after {
                Some(a) => after = Some(a),
                None => return Ok(out),
            }
        }
    }

    /// The reference: read every file of the tree and match it, keeping the files `scope`
    /// covers.
    fn full_scan(
        &mut self,
        target: TreeTarget,
        scope: &PathScope,
        pattern: &str,
    ) -> Vec<SearchMatch> {
        let re = Regex::new(pattern).unwrap();
        let files = self.svc.materialize_virtual_tree(target, None).unwrap();
        let mut out = Vec::new();
        for (path, entry) in files {
            if !scope.covers_path(&path) {
                continue;
            }
            let bytes = self.svc.read_blob_bytes(entry.blob_digest, None).unwrap();
            let all: Vec<(u64, u64)> = re
                .find_iter(&bytes)
                .map(|m| (m.start() as u64, m.end() as u64))
                .collect();
            if all.is_empty() {
                continue;
            }
            out.push(SearchMatch {
                path,
                blob_digest: entry.blob_digest,
                more_spans: all.len() > MAX_SPANS_PER_FILE,
                spans: all.into_iter().take(MAX_SPANS_PER_FILE).collect(),
            });
        }
        out
    }

    /// `who` submits a `Private` revision of change `C` writing `body` to `path`.
    fn submit(&mut self, who: &Agent, path: &str, body: &[u8], idem: u8) -> ChangesetId {
        let content = RevisionContent {
            change_id: C,
            base_tree: self.base,
            parents: vec![],
            mutations: vec![PathMutation {
                path: path.into(),
                op: MutationOp::Upsert {
                    mode: FileMode::Regular644,
                    blob_digest: BlobDigest::compute(body),
                    size_bytes: body.len() as u64,
                },
            }],
            intent_summary: "c3 search fixture".into(),
        };
        let env =
            ChangesetEnvelopeV2::sign_new(&who.0, repo(), content, IdempotencyKey([idem; 32]), NOW);
        let scope = RequestScope {
            paths: vec![path.into()],
            reference: None,
            join_change: Some(C),
        };
        let req = self.request(who, Capability::Propose, scope, env.encode());
        let blobs = vec![(BlobDigest::compute(body), body.to_vec())];
        match self.svc.submit_revision(&req, &blobs, NOW).unwrap() {
            RevisionOutcome::Admitted { changeset_id, .. } => changeset_id,
            other => panic!("expected an admission, got {other:?}"),
        }
    }

    fn mv(&mut self, who: &Agent, id: ChangesetId, to: RevisionState) {
        let payload = RevisionStateMovePayload::sign_new(&who.0, &repo(), &who.1, id, to, NOW)
            .unwrap()
            .encode();
        let req = self.request(who, Capability::Propose, RequestScope::default(), payload);
        self.svc.advance_revision_state(&req, NOW).unwrap();
    }
}

fn scope_of(prefixes: &[&str]) -> PathScope {
    PathScope::new(prefixes.iter().map(|p| p.to_string()).collect()).unwrap()
}

/// Acceptance 1: indexed search equals a full scan of the same tree, for every query of the
/// fixed set and every reader scope, before indexing (no pruning), after indexing (pruning),
/// and across pages.
#[test]
fn c3_search_equals_a_full_scan_for_the_fixed_query_set() {
    let mut fx = Fx::new("parity", base_files());
    let target = TreeTarget::BaseGitCommit(BASE);
    let readers = [
        (fx.v.clone(), scope_of(&[""])),
        (fx.w.clone(), scope_of(&["src"])),
        (fx.d.clone(), scope_of(&["docs"])),
    ];
    for indexed in [false, true] {
        if indexed {
            let report = fx
                .svc
                .index_search_content(SearchTarget::Tree(target))
                .unwrap();
            assert!(report.indexed > 1000, "{report:?}");
            assert_eq!(report.skipped, 0);
        }
        for (who, scope) in &readers {
            for q in QUERIES {
                let want = fx.full_scan(target, scope, q);
                let got = fx
                    .search_all(who, SearchTarget::Tree(target), q, 256)
                    .unwrap();
                assert_eq!(got, want, "query {q:?} indexed={indexed} scope={scope:?}");
            }
        }
    }
    // Small pages give the same answer as one large one.
    for q in ["secret", "fn [a-z_]+\\(", "."] {
        let want = fx.full_scan(target, &scope_of(&[""]), q);
        let v = fx.v.clone();
        assert_eq!(
            fx.search_all(&v, SearchTarget::Tree(target), q, 3).unwrap(),
            want
        );
    }
    // The index pruned files without reading them, and the results did not change.
    let stats = fx.svc.search_index().stats();
    assert!(stats.files_pruned > 10_000, "{stats:?}");
    assert!(fx.svc.search_index().bytes() <= fx.svc.search_index().config().max_bytes);
}

/// A tiny index bound leaves most blobs unindexed; those are read, so results stay exact.
#[test]
fn c3_bounded_index_keeps_results_exact() {
    let mut fx = Fx::new("bounded", base_files());
    fx.svc
        .set_search_index_config(synapse_api::SearchIndexConfig {
            max_bytes: 4096,
            max_blob_bytes: 64,
        });
    let target = TreeTarget::BaseGitCommit(BASE);
    let report = fx
        .svc
        .index_search_content(SearchTarget::Tree(target))
        .unwrap();
    assert!(report.skipped > 0 && report.indexed > 0, "{report:?}");
    assert!(fx.svc.search_index().bytes() <= 4096);
    let v = fx.v.clone();
    for q in QUERIES {
        let want = fx.full_scan(target, &scope_of(&[""]), q);
        assert_eq!(
            fx.search_all(&v, SearchTarget::Tree(target), q, 256)
                .unwrap(),
            want
        );
    }
}

/// Acceptance 2 (path scope): a `src` reader never sees `docs`, `private`, the root, or the
/// sibling prefix `src-other`, by result or by count; and the work done for a scoped search
/// (files pruned plus files read) does not change when out-of-scope files are added.
#[test]
fn c3_cross_scope_search_reveals_nothing_outside_the_read_scope() {
    let mut fx = Fx::new("scope", base_files());
    let target = SearchTarget::Tree(TreeTarget::BaseGitCommit(BASE));
    fx.svc.index_search_content(target).unwrap();
    let (w, d) = (fx.w.clone(), fx.d.clone());
    // Matches exist only outside `src`: nothing comes back, no cursor, no count.
    for q in [
        "SECRET_KEY",
        "hunter2",
        "Guide",
        "explain",
        "serve_secretly",
    ] {
        let page = fx.search_page(&w, target, q, None, 10).unwrap();
        assert!(
            page.matches.is_empty() && page.next_after.is_none(),
            "{q}: {page:?}"
        );
    }
    // A pattern matching everywhere returns only `src` files to W and only `docs` files to D.
    for m in fx.search_all(&w, target, "secret|e", 256).unwrap() {
        assert!(m.path.starts_with("src/"), "{}", m.path);
    }
    for m in fx.search_all(&d, target, "secret|e", 256).unwrap() {
        assert!(m.path.starts_with("docs/"), "{}", m.path);
    }
    // A cursor before the scope does not pull in out-of-scope paths either.
    let page = fx
        .search_page(&w, target, "SECRET", Some(String::new()), 10)
        .unwrap();
    assert!(page.matches.iter().all(|m| m.path.starts_with("src/")));

    // Work is independent of out-of-scope content: same responses, same work, with 2000
    // extra matching files outside `docs`.
    let mut more = base_files();
    for i in 0..2000 {
        more.push((
            format!("private/extra/{i}.txt"),
            FileMode::Regular644,
            b"secret wal_99 caf\xc3\xa9".to_vec(),
        ));
    }
    let mut big = Fx::new("scope-big", more);
    big.svc.index_search_content(target).unwrap();
    let d_big = big.d.clone();
    for q in QUERIES {
        let s0 = fx.svc.search_index().stats();
        let small = fx.search_all(&d, target, q, 256).unwrap();
        let s1 = fx.svc.search_index().stats();
        let b0 = big.svc.search_index().stats();
        let large = big.search_all(&d_big, target, q, 256).unwrap();
        let b1 = big.svc.search_index().stats();
        assert_eq!(small, large, "{q}");
        assert_eq!(
            s1.files_read - s0.files_read,
            b1.files_read - b0.files_read,
            "{q}"
        );
        assert_eq!(
            s1.files_pruned - s0.files_pruned,
            b1.files_pruned - b0.files_pruned,
            "{q}"
        );
    }
}

/// Acceptance 2 (`Private`): W's `Private` revision is searchable by W and by O (whose grant
/// W's descends from) and by nobody else, each refused exactly like an unknown revision; the
/// base tree never shows its content. After `Draft` it is searchable within `Read` scope, and
/// still refused to D, whose scope does not cover its mutation.
#[test]
fn c3_private_revision_content_is_invisible_outside_its_owner_chain() {
    let mut fx = Fx::new("private", base_files());
    let (o, w, v, d, x) = (
        fx.o.clone(),
        fx.w.clone(),
        fx.v.clone(),
        fx.d.clone(),
        fx.x.clone(),
    );
    let rev = fx.submit(&w, "src/lib.rs", b"pub fn private_token_c3() {}\n", 1);
    let target = SearchTarget::Revision(rev);
    fx.svc.index_search_content(target).unwrap();
    for owner in [&w, &o] {
        let hits = fx
            .search_all(owner, target, "private_token_c3", 10)
            .unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].path, "src/lib.rs");
    }
    let unknown = SearchTarget::Revision(ChangesetId([0xEE; 32]));
    let (code, msg) = fx.search_page(&o, unknown, "x", None, 1).unwrap_err();
    assert_eq!(code, RefusalCode::ChangesetNotFound);
    for outsider in [&v, &d, &x] {
        for q in ["private_token_c3", "zzz_never_present", "."] {
            let (c, m) = fx.search_page(outsider, target, q, None, 10).unwrap_err();
            assert_eq!(c, code);
            assert_eq!(
                m,
                msg.replace(&ChangesetId([0xEE; 32]).to_string(), &rev.to_string())
            );
        }
    }
    // The base tree never carries the revision's content, for anyone.
    let base = SearchTarget::Tree(TreeTarget::BaseGitCommit(BASE));
    for who in [&o, &w, &v, &x] {
        assert!(fx
            .search_all(who, base, "private_token_c3", 10)
            .unwrap()
            .is_empty());
    }
    fx.mv(&w, rev, RevisionState::Draft);
    for reader in [&o, &w, &v, &x] {
        assert_eq!(
            fx.search_all(reader, target, "private_token_c3", 10)
                .unwrap()
                .len(),
            1
        );
    }
    assert_eq!(
        fx.search_page(&d, target, "private_token_c3", None, 10)
            .unwrap_err()
            .0,
        RefusalCode::ChangesetNotFound
    );
    // Parity with a full scan holds on the revision tree too.
    let v_scope = scope_of(&[""]);
    let rev_files = fx
        .svc
        .materialize_virtual_tree(TreeTarget::BaseGitCommit(BASE), None)
        .unwrap();
    assert!(rev_files.contains_key("src/lib.rs"));
    for q in QUERIES {
        let mut want = fx.full_scan(TreeTarget::BaseGitCommit(BASE), &v_scope, q);
        want.retain(|m| m.path != "src/lib.rs");
        let body: &[u8] = b"pub fn private_token_c3() {}\n";
        let re = Regex::new(q).unwrap();
        let spans: Vec<(u64, u64)> = re
            .find_iter(body)
            .map(|m| (m.start() as u64, m.end() as u64))
            .collect();
        if !spans.is_empty() {
            want.push(SearchMatch {
                path: "src/lib.rs".into(),
                blob_digest: BlobDigest::compute(body),
                more_spans: spans.len() > MAX_SPANS_PER_FILE,
                spans: spans.into_iter().take(MAX_SPANS_PER_FILE).collect(),
            });
            want.sort_by(|a, b| a.path.cmp(&b.path));
        }
        assert_eq!(fx.search_all(&v, target, q, 256).unwrap(), want, "{q}");
    }
}

/// Malformed requests are refused typed, never by a panic.
#[test]
fn c3_malformed_requests_are_refused_typed() {
    let mut fx = Fx::new("malformed", base_files());
    let v = fx.v.clone();
    let target = SearchTarget::Tree(TreeTarget::BaseGitCommit(BASE));
    assert_eq!(
        fx.search_page(&v, target, "(", None, 1).unwrap_err().0,
        RefusalCode::EnvelopeMalformed
    );
    assert_eq!(
        fx.search_page(&v, target, "a", None, 0).unwrap_err().0,
        RefusalCode::PaginationLimitExceeded
    );
    assert_eq!(
        fx.search_page(&v, target, "a", None, 257).unwrap_err().0,
        RefusalCode::PaginationLimitExceeded
    );
    for junk in [vec![], vec![0xff; 7], b"SYNAPSE_SEARCH_V1\0\x07".to_vec()] {
        let req = fx.request(&v, Capability::Read, RequestScope::default(), junk);
        assert_eq!(
            fx.svc.search(&req, NOW).unwrap_err().code,
            RefusalCode::EnvelopeMalformed
        );
    }
}
