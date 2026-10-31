//! ADR 0003 section 9 step F1: attenuated capability chains with path, reference, and change
//! scope, `Undo`, and partitioned rate, storage, and footprint quotas.
//!
//! Acceptance (each item names the test that proves it):
//! * no derived grant exceeds its parent in operations, paths, references, change scope, quotas,
//!   or expiry: `f1_property_no_derived_grant_exceeds_its_parent`
//! * child quotas never sum above the parent's: `f1_property_child_quotas_never_sum_above_the_parent`
//! * forged chains refused: `f1_forged_chains_are_refused`
//! * stripped chains refused: `f1_stripped_chains_are_refused`
//! * reordered chains refused: `f1_reordered_chains_are_refused`
//! * a link bound to another repository refused: `f1_link_bound_to_another_repository_is_refused`
//! * a link bound to another audience refused: `f1_link_bound_to_another_audience_is_refused`
//! * out-of-scope path refused: `f1_out_of_scope_path_is_refused`
//! * a chain with an ancestor revoked at the request's `WalSeq` refused:
//!   `f1_chain_with_an_ancestor_revoked_at_the_request_walseq_is_refused`
//!
//! The property tests use a seeded SplitMix64 generator (no new dependency); the seed and case
//! count are constants below and every failure message prints the seed, case, and caveats.

use ed25519_dalek::SigningKey;
use synapse_auth::{
    AuditOutcome, BoundaryKind, Capability, CapabilityChain, CapabilityLink, ChainQuotas,
    ChainedRequest, ChangeScope, LinkCaveats, LinkDigest, OperationSet, PathScope, PolicyEnforcer,
    ReferenceKind, ReferenceScope, RequestScope, MAX_CHAIN_DEPTH, ROOT_PARENT,
};
use synapse_core::{encode_did_key_ed25519, ChangeId, RefusalCode, RepoId, WalSeq};

const PROPERTY_SEED: u64 = 0xF1F1_0003_0025_5EED;
const NARROWING_CASES: u64 = 256;
const PARTITION_CASES: u64 = 256;

const ALL_CAPS: [Capability; 6] = [
    Capability::Read,
    Capability::Propose,
    Capability::Evaluate,
    Capability::Review,
    Capability::Publish,
    Capability::Undo,
];
const ALL_OPS_BITS: u8 = 0b0011_1111;
const ALL_REF_BITS: u8 = 0b0000_0011;

struct SplitMix64(u64);

impl SplitMix64 {
    fn new(seed: u64) -> Self {
        Self(seed)
    }
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    /// Uniform in `0..=max`.
    fn upto(&mut self, max: u64) -> u64 {
        if max == u64::MAX {
            self.next()
        } else {
            self.next() % (max + 1)
        }
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
    fn chance(&mut self, num: u64, den: u64) -> bool {
        self.below(den) < num
    }
    fn bytes32(&mut self) -> [u8; 32] {
        let mut out = [0u8; 32];
        for chunk in out.chunks_mut(8) {
            chunk.copy_from_slice(&self.next().to_le_bytes());
        }
        out
    }
    fn key(&mut self) -> SigningKey {
        SigningKey::from_bytes(&self.bytes32())
    }
}

fn repo() -> RepoId {
    RepoId::new("aien-spark/synapse").unwrap()
}

fn pubkey(k: &SigningKey) -> [u8; 32] {
    k.verifying_key().to_bytes()
}

fn change_id(n: u8) -> ChangeId {
    ChangeId([n; 16])
}

fn wide_caveats() -> LinkCaveats {
    LinkCaveats {
        operations: OperationSet::from_capabilities(&ALL_CAPS),
        paths: PathScope::whole_repository(),
        references: ReferenceScope::from_kinds(&[
            ReferenceKind::OwnDrafts,
            ReferenceKind::CanonicalViaPromotionQueue,
        ]),
        changes: ChangeScope::any(),
        quotas: ChainQuotas {
            max_ops_per_window: 1_000,
            window_duration_ms: 60_000,
            storage_bytes: 1 << 30,
            footprint_paths: 1 << 20,
            max_bytes_per_op: 1 << 20,
        },
        issued_at_ms: 1_000,
        expires_at_ms: 100_000,
    }
}

const NOW: u64 = 2_000;

/// Authority A issues root to orchestrator O; O delegates `mid` to worker W; W delegates `leaf`
/// to sub-worker S. Granted at `WalSeq` 1, 2, 3.
struct Fx {
    enforcer: PolicyEnforcer,
    authority: SigningKey,
    o: SigningKey,
    w: SigningKey,
    s: SigningKey,
    root: CapabilityLink,
    mid: CapabilityLink,
    leaf: CapabilityLink,
}

impl Fx {
    fn new() -> Self {
        let authority = SigningKey::from_bytes(&[1u8; 32]);
        let o = SigningKey::from_bytes(&[2u8; 32]);
        let w = SigningKey::from_bytes(&[3u8; 32]);
        let s = SigningKey::from_bytes(&[4u8; 32]);
        let mut enforcer = PolicyEnforcer::new();
        enforcer.register_repo_authority(repo(), encode_did_key_ed25519(&pubkey(&authority)));

        let root = CapabilityLink::issue(
            &authority,
            ROOT_PARENT,
            [0xA0; 32],
            repo(),
            pubkey(&o),
            wide_caveats(),
        );
        let mut mid_cav = wide_caveats();
        mid_cav.paths = PathScope::new(vec!["crates/synapse-auth".into(), "docs".into()]).unwrap();
        mid_cav.quotas.max_ops_per_window = 500;
        mid_cav.quotas.storage_bytes = 1 << 29;
        mid_cav.quotas.footprint_paths = 1 << 19;
        let mid = CapabilityLink::issue(&o, root.digest(), [0xA1; 32], repo(), pubkey(&w), mid_cav);
        let mut leaf_cav = mid.caveats.clone();
        leaf_cav.operations =
            OperationSet::from_capabilities(&[Capability::Read, Capability::Propose]);
        leaf_cav.paths = PathScope::new(vec!["crates/synapse-auth".into()]).unwrap();
        leaf_cav.references = ReferenceScope::from_kinds(&[ReferenceKind::OwnDrafts]);
        leaf_cav.changes = ChangeScope::only(vec![change_id(1)]).unwrap();
        leaf_cav.quotas.max_ops_per_window = 250;
        leaf_cav.quotas.storage_bytes = 1 << 28;
        leaf_cav.quotas.footprint_paths = 1 << 18;
        let leaf =
            CapabilityLink::issue(&w, mid.digest(), [0xA2; 32], repo(), pubkey(&s), leaf_cav);

        let mut fx = Self {
            enforcer,
            authority,
            o,
            w,
            s,
            root,
            mid,
            leaf,
        };
        let c1 = fx.chain(&[&fx.root.clone()]);
        let c2 = fx.chain(&[&fx.root.clone(), &fx.mid.clone()]);
        let c3 = fx.full_chain();
        fx.enforcer.grant_link(&c1, WalSeq(1), NOW).unwrap();
        fx.enforcer.grant_link(&c2, WalSeq(2), NOW).unwrap();
        fx.enforcer.grant_link(&c3, WalSeq(3), NOW).unwrap();
        fx
    }

    fn chain(&self, links: &[&CapabilityLink]) -> CapabilityChain {
        CapabilityChain::new(links.iter().map(|l| (*l).clone()).collect())
    }

    fn full_chain(&self) -> CapabilityChain {
        self.chain(&[&self.root, &self.mid, &self.leaf])
    }

    fn request(
        &self,
        signer: &SigningKey,
        chain: CapabilityChain,
        cap: Capability,
        scope: RequestScope,
        nonce: u8,
    ) -> ChainedRequest {
        ChainedRequest::sign_new(
            signer,
            chain,
            repo(),
            cap,
            scope,
            [nonce; 32],
            NOW,
            b"payload".to_vec(),
        )
    }

    fn authorize(&mut self, req: &ChainedRequest, seq: u64) -> Result<(), RefusalCode> {
        self.enforcer
            .authorize_chain(
                BoundaryKind::Api,
                "submit",
                &repo(),
                req.required_capability,
                req,
                WalSeq(seq),
                NOW,
            )
            .map_err(|e| e.code)
    }
}

fn paths(p: &[&str]) -> RequestScope {
    RequestScope {
        paths: p.iter().map(|s| s.to_string()).collect(),
        ..RequestScope::default()
    }
}

fn in_scope() -> RequestScope {
    paths(&["crates/synapse-auth/src/lib.rs"])
}
#[test]
fn chained_authorization_backpressures_before_evaluating_request() {
    use synapse_auth::{AuditOutcome, MAX_AUDIT_ENTRIES};
    let mut fx = Fx::new();
    let req = fx.request(&fx.s, fx.full_chain(), Capability::Propose, in_scope(), 42);
    for _ in 0..MAX_AUDIT_ENTRIES {
        fx.enforcer
            .audit_log_mut()
            .record(
                NOW,
                BoundaryKind::Api,
                repo(),
                "untrusted".into(),
                Capability::Propose,
                "wire_submit",
                AuditOutcome::Refused {
                    code: RefusalCode::AuthChainBroken,
                    reason: "invalid".into(),
                },
            )
            .unwrap();
    }
    let head = fx.enforcer.audit_log().verify_chain().unwrap();
    assert_eq!(
        fx.authorize(&req, 4),
        Err(RefusalCode::BackpressureOverCapacity)
    );
    assert_eq!(fx.enforcer.audit_log().verify_chain().unwrap(), head);
}

// ---------------------------------------------------------------------------------------------
// Property: no derived grant exceeds its parent.
// ---------------------------------------------------------------------------------------------

/// Independent model of prefix coverage at segment boundaries (not the crate's code).
fn oracle_covers(prefixes: &[String], path: &str) -> bool {
    prefixes.iter().any(|p| {
        if p.is_empty() {
            return true;
        }
        if path.is_empty() {
            return false;
        }
        let ps: Vec<&str> = p.split('/').collect();
        let xs: Vec<&str> = path.split('/').collect();
        xs.len() >= ps.len() && xs[..ps.len()] == ps[..]
    })
}

/// The first dimension in which `child` exceeds `parent` under the independent model.
fn oracle_exceeds(child: &LinkCaveats, parent: &LinkCaveats) -> Option<&'static str> {
    if child.operations.bits() & !parent.operations.bits() != 0 {
        return Some("operations");
    }
    let parent_prefixes = parent.paths.prefixes();
    for c in child.paths.prefixes() {
        let probes = [c.clone(), format!("{c}/probe"), format!("{c}/probe/deeper")];
        for probe in probes.iter() {
            let probe = probe.trim_start_matches('/');
            if oracle_covers(child.paths.prefixes(), probe)
                && !oracle_covers(parent_prefixes, probe)
            {
                return Some("paths");
            }
        }
    }
    if child.references.bits() & !parent.references.bits() != 0 {
        return Some("references");
    }
    match (child.changes.ids(), parent.changes.ids()) {
        (_, None) => {}
        (None, Some(_)) => return Some("change scope"),
        (Some(c), Some(p)) => {
            if c.iter().any(|id| !p.contains(id)) {
                return Some("change scope");
            }
        }
    }
    let (c, p) = (&child.quotas, &parent.quotas);
    if c.window_duration_ms != p.window_duration_ms
        || c.max_ops_per_window > p.max_ops_per_window
        || c.storage_bytes > p.storage_bytes
        || c.footprint_paths > p.footprint_paths
        || c.max_bytes_per_op > p.max_bytes_per_op
    {
        return Some("quotas");
    }
    if child.issued_at_ms < parent.issued_at_ms || child.expires_at_ms > parent.expires_at_ms {
        return Some("expiry");
    }
    None
}

const SEGMENTS: [&str; 8] = ["src", "docs", "crates", "tests", "a", "b", "ab", "a-b"];

fn random_prefix(rng: &mut SplitMix64) -> String {
    let depth = 1 + rng.below(2) as usize;
    (0..depth)
        .map(|_| SEGMENTS[rng.below(SEGMENTS.len() as u64) as usize])
        .collect::<Vec<_>>()
        .join("/")
}

fn random_change_ids(rng: &mut SplitMix64, pool: u8, max: u64) -> Vec<ChangeId> {
    (0..rng.upto(max))
        .map(|_| change_id(1 + rng.below(pool as u64) as u8))
        .collect()
}

fn random_root_caveats(rng: &mut SplitMix64) -> LinkCaveats {
    let paths = if rng.chance(1, 10) {
        PathScope::whole_repository()
    } else {
        PathScope::new((0..1 + rng.below(3)).map(|_| random_prefix(rng)).collect()).unwrap()
    };
    let changes = if rng.chance(1, 5) {
        ChangeScope::any()
    } else {
        ChangeScope::only(random_change_ids(rng, 8, 4)).unwrap()
    };
    let issued = 1_000 + rng.below(500);
    LinkCaveats {
        operations: OperationSet::from_bits(rng.upto(ALL_OPS_BITS as u64) as u8).unwrap(),
        paths,
        references: ReferenceScope::from_bits(rng.upto(ALL_REF_BITS as u64) as u8).unwrap(),
        changes,
        quotas: ChainQuotas {
            max_ops_per_window: 1 + rng.below(1_000) as u32,
            window_duration_ms: if rng.chance(1, 2) { 1_000 } else { 60_000 },
            storage_bytes: 1 + rng.below(1 << 30),
            footprint_paths: 1 + rng.below(1 << 20),
            max_bytes_per_op: 1 + rng.below(1 << 20),
        },
        issued_at_ms: issued,
        expires_at_ms: NOW + 1 + rng.below(1_000_000),
    }
}

/// A child that narrows `parent` in every dimension; partitioned quotas take at most a quarter
/// so up to three siblings always fit.
fn narrowed(rng: &mut SplitMix64, parent: &LinkCaveats) -> LinkCaveats {
    let paths = if parent.paths.prefixes().iter().any(String::is_empty) {
        if rng.chance(1, 4) {
            PathScope::whole_repository()
        } else {
            PathScope::new((0..1 + rng.below(2)).map(|_| random_prefix(rng)).collect()).unwrap()
        }
    } else {
        let mut picked = Vec::new();
        for p in parent.paths.prefixes() {
            match rng.below(3) {
                0 => {}
                1 => picked.push(p.clone()),
                _ => picked.push(format!("{p}/{}", random_prefix(rng))),
            }
        }
        PathScope::new(picked).unwrap()
    };
    let changes = match parent.changes.ids() {
        None if rng.chance(1, 2) => ChangeScope::any(),
        None => ChangeScope::only(random_change_ids(rng, 8, 3)).unwrap(),
        Some(ids) => {
            ChangeScope::only(ids.iter().copied().filter(|_| rng.chance(1, 2)).collect()).unwrap()
        }
    };
    let q = &parent.quotas;
    LinkCaveats {
        operations: OperationSet::from_bits(parent.operations.bits() & rng.next() as u8).unwrap(),
        paths,
        references: ReferenceScope::from_bits(parent.references.bits() & rng.next() as u8).unwrap(),
        changes,
        quotas: ChainQuotas {
            max_ops_per_window: rng.upto(u64::from(q.max_ops_per_window / 4)) as u32,
            window_duration_ms: q.window_duration_ms,
            storage_bytes: rng.upto(q.storage_bytes / 4),
            footprint_paths: rng.upto(q.footprint_paths / 4),
            max_bytes_per_op: rng.upto(q.max_bytes_per_op),
        },
        issued_at_ms: parent.issued_at_ms + rng.upto(NOW - parent.issued_at_ms),
        expires_at_ms: NOW + rng.upto(parent.expires_at_ms - NOW),
    }
}

const DIMENSIONS: [&str; 6] = [
    "operations",
    "paths",
    "references",
    "change scope",
    "quotas",
    "expiry",
];

/// A child that is `narrowed` except wider than `parent` in dimension `dim`; `None` when the
/// parent is already maximal in that dimension.
fn widened(rng: &mut SplitMix64, parent: &LinkCaveats, dim: usize) -> Option<LinkCaveats> {
    let mut c = narrowed(rng, parent);
    match DIMENSIONS[dim] {
        "operations" => {
            let missing = ALL_OPS_BITS & !parent.operations.bits();
            if missing == 0 {
                return None;
            }
            let bit = 1u8 << missing.trailing_zeros();
            c.operations = OperationSet::from_bits(c.operations.bits() | bit).unwrap();
        }
        "paths" => {
            if parent.paths.prefixes().iter().any(String::is_empty) {
                return None;
            }
            c.paths = if rng.chance(1, 3) {
                PathScope::whole_repository()
            } else {
                let mut p = c.paths.prefixes().to_vec();
                p.push(format!("zz{}", rng.below(1_000)));
                PathScope::new(p).unwrap()
            };
        }
        "references" => {
            let missing = ALL_REF_BITS & !parent.references.bits();
            if missing == 0 {
                return None;
            }
            let bit = 1u8 << missing.trailing_zeros();
            c.references = ReferenceScope::from_bits(c.references.bits() | bit).unwrap();
        }
        "change scope" => {
            let ids = parent.changes.ids()?;
            c.changes = if rng.chance(1, 3) {
                ChangeScope::any()
            } else {
                let mut v = c.changes.ids().unwrap_or(&[]).to_vec();
                v.push(change_id(100 + rng.below(100) as u8));
                debug_assert!(!ids.contains(v.last().unwrap()));
                ChangeScope::only(v).unwrap()
            };
        }
        "quotas" => {
            let q = &parent.quotas;
            match rng.below(5) {
                0 => c.quotas.max_ops_per_window = q.max_ops_per_window.checked_add(1)?,
                1 => c.quotas.storage_bytes = q.storage_bytes.checked_add(1)?,
                2 => c.quotas.footprint_paths = q.footprint_paths.checked_add(1)?,
                3 => c.quotas.max_bytes_per_op = q.max_bytes_per_op.checked_add(1)?,
                _ => c.quotas.window_duration_ms = q.window_duration_ms + 1,
            }
        }
        "expiry" => {
            if rng.chance(1, 2) {
                c.expires_at_ms = parent.expires_at_ms + 1 + rng.below(1_000);
            } else {
                c.issued_at_ms = parent.issued_at_ms - 1;
            }
        }
        _ => unreachable!(),
    }
    Some(c)
}

struct Node {
    chain: CapabilityChain,
    holder: SigningKey,
}

#[test]
fn f1_property_no_derived_grant_exceeds_its_parent() {
    let mut accepted_narrowed = 0u64;
    let mut refused_by_dim = [0u64; 6];
    for case in 0..NARROWING_CASES {
        let mut rng = SplitMix64::new(PROPERTY_SEED ^ case.wrapping_mul(0x2545_F491_4F6C_DD1D));
        let authority = rng.key();
        let mut enforcer = PolicyEnforcer::new();
        enforcer.register_repo_authority(repo(), encode_did_key_ed25519(&pubkey(&authority)));
        let root_holder = rng.key();
        let root = CapabilityLink::issue(
            &authority,
            ROOT_PARENT,
            rng.bytes32(),
            repo(),
            pubkey(&root_holder),
            random_root_caveats(&mut rng),
        );
        let root_chain = CapabilityChain::new(vec![root]);
        let mut seq = 1u64;
        enforcer
            .grant_link(&root_chain, WalSeq(seq), NOW)
            .unwrap_or_else(|e| panic!("seed {PROPERTY_SEED:#x} case {case}: root refused {e}"));
        let mut frontier = vec![Node {
            chain: root_chain,
            holder: root_holder,
        }];
        while let Some(node) = frontier.pop() {
            if node.chain.links.len() >= 4 {
                continue;
            }
            let parent = node.chain.leaf().unwrap().clone();
            for _ in 0..1 + rng.below(3) {
                let audience = rng.key();
                let wide_dim = if rng.chance(1, 2) {
                    None
                } else {
                    Some(rng.below(6) as usize)
                };
                let caveats = match wide_dim {
                    None => narrowed(&mut rng, &parent.caveats),
                    Some(d) => match widened(&mut rng, &parent.caveats, d) {
                        Some(c) => c,
                        None => continue,
                    },
                };
                let child = CapabilityLink::issue(
                    &node.holder,
                    parent.digest(),
                    rng.bytes32(),
                    repo(),
                    pubkey(&audience),
                    caveats.clone(),
                );
                let chain = node.chain.extended(child);
                seq += 1;
                let granted = enforcer
                    .grant_link(&chain, WalSeq(seq), NOW)
                    .map_err(|e| e.code);

                // The property: every link the server accepts lies inside its parent and inside
                // every ancestor, under the independent model.
                if granted.is_ok() {
                    for (i, ancestor) in chain.links[..chain.links.len() - 1].iter().enumerate() {
                        if let Some(dim) = oracle_exceeds(&caveats, &ancestor.caveats) {
                            panic!(
                                "seed {PROPERTY_SEED:#x} case {case}: accepted link exceeds \
                                 ancestor {i} in {dim}\n child {caveats:#?}\n ancestor {:#?}",
                                ancestor.caveats
                            );
                        }
                    }
                }
                match wide_dim {
                    None => {
                        assert_eq!(
                            granted.map(|_| ()),
                            Ok(()),
                            "seed {PROPERTY_SEED:#x} case {case}: narrowed link refused\n \
                             child {caveats:#?}\n parent {:#?}",
                            parent.caveats
                        );
                        accepted_narrowed += 1;
                        frontier.push(Node {
                            chain,
                            holder: audience,
                        });
                    }
                    Some(d) => {
                        assert_eq!(
                            granted.map(|_| ()),
                            Err(RefusalCode::AuthScopeEscalation),
                            "seed {PROPERTY_SEED:#x} case {case}: link wider in {} not refused",
                            DIMENSIONS[d]
                        );
                        // The same widened chain presented on a request is refused too.
                        let req = ChainedRequest::sign_new(
                            &audience,
                            chain,
                            repo(),
                            Capability::Read,
                            RequestScope::default(),
                            rng.bytes32(),
                            NOW,
                            Vec::new(),
                        );
                        let got = enforcer
                            .authorize_chain(
                                BoundaryKind::Api,
                                "read",
                                &repo(),
                                Capability::Read,
                                &req,
                                WalSeq(seq),
                                NOW,
                            )
                            .map_err(|e| e.code);
                        assert_eq!(
                            got,
                            Err(RefusalCode::AuthScopeEscalation),
                            "seed {PROPERTY_SEED:#x} case {case}: request through a link wider \
                             in {} not refused",
                            DIMENSIONS[d]
                        );
                        refused_by_dim[d] += 1;
                    }
                }
            }
        }
    }
    println!(
        "seed {PROPERTY_SEED:#x}, {NARROWING_CASES} cases: {accepted_narrowed} narrowed links \
         accepted; widened links refused per dimension {DIMENSIONS:?} = {refused_by_dim:?}"
    );
    assert!(accepted_narrowed > 0, "no narrowed link was generated");
    for (d, n) in refused_by_dim.iter().enumerate() {
        assert!(*n > 0, "no widened link generated in {}", DIMENSIONS[d]);
    }
}

// ---------------------------------------------------------------------------------------------
// Property: child quotas never sum above the parent's.
// ---------------------------------------------------------------------------------------------

#[derive(Clone, Copy, Default, Debug, PartialEq)]
struct Sum {
    ops: u64,
    storage: u64,
    footprint: u64,
}

#[test]
fn f1_property_child_quotas_never_sum_above_the_parent() {
    let (mut accepted, mut refused) = (0u64, 0u64);
    for case in 0..PARTITION_CASES {
        let mut rng = SplitMix64::new(PROPERTY_SEED ^ 0xC0FF_EE00 ^ case.wrapping_mul(0x9E37));
        let authority = rng.key();
        let mut enforcer = PolicyEnforcer::new();
        enforcer.register_repo_authority(repo(), encode_did_key_ed25519(&pubkey(&authority)));
        let mut root_cav = wide_caveats();
        root_cav.quotas = ChainQuotas {
            max_ops_per_window: rng.upto(200) as u32,
            window_duration_ms: 60_000,
            storage_bytes: rng.upto(10_000),
            footprint_paths: rng.upto(1_000),
            max_bytes_per_op: 1 << 20,
        };
        let holder = rng.key();
        let root = CapabilityLink::issue(
            &authority,
            ROOT_PARENT,
            rng.bytes32(),
            repo(),
            pubkey(&holder),
            root_cav,
        );
        let mut nodes = vec![(CapabilityChain::new(vec![root]), holder)];
        let mut seq = 1u64;
        enforcer.grant_link(&nodes[0].0, WalSeq(seq), NOW).unwrap();
        let mut children_sum = vec![Sum::default()];
        for _ in 0..16 {
            let pi = rng.below(nodes.len() as u64) as usize;
            if nodes[pi].0.links.len() >= MAX_CHAIN_DEPTH {
                continue;
            }
            let parent = nodes[pi].0.leaf().unwrap().clone();
            let pq = parent.caveats.quotas;
            let mut cav = parent.caveats.clone();
            cav.quotas.max_ops_per_window = rng.upto(u64::from(pq.max_ops_per_window)) as u32;
            cav.quotas.storage_bytes = rng.upto(pq.storage_bytes);
            cav.quotas.footprint_paths = rng.upto(pq.footprint_paths);
            let audience = rng.key();
            let child = CapabilityLink::issue(
                &nodes[pi].1,
                parent.digest(),
                rng.bytes32(),
                repo(),
                pubkey(&audience),
                cav.clone(),
            );
            let chain = nodes[pi].0.extended(child);
            let s = children_sum[pi];
            let next = Sum {
                ops: s.ops + u64::from(cav.quotas.max_ops_per_window),
                storage: s.storage + cav.quotas.storage_bytes,
                footprint: s.footprint + cav.quotas.footprint_paths,
            };
            let fits = next.ops <= u64::from(pq.max_ops_per_window)
                && next.storage <= pq.storage_bytes
                && next.footprint <= pq.footprint_paths;
            seq += 1;
            let got = enforcer
                .grant_link(&chain, WalSeq(seq), NOW)
                .map_err(|e| e.code);
            match got {
                Ok(_) => {
                    // The property: what the server accepted keeps the children's sum within
                    // the parent's rate, storage, and footprint quotas.
                    assert!(
                        fits,
                        "seed {PROPERTY_SEED:#x} case {case}: accepted child makes children sum \
                         {next:?} above parent quotas {pq:?}"
                    );
                    children_sum[pi] = next;
                    children_sum.push(Sum::default());
                    nodes.push((chain, audience));
                    accepted += 1;
                }
                Err(code) => {
                    assert!(
                        !fits,
                        "seed {PROPERTY_SEED:#x} case {case}: child that fits refused with \
                         {code:?} (sum {next:?}, parent {pq:?})"
                    );
                    assert_eq!(
                        code,
                        RefusalCode::QuotaPartitionExceeded,
                        "seed {PROPERTY_SEED:#x} case {case}"
                    );
                    refused += 1;
                }
            }
        }
        // What each granted link keeps for itself is its quota minus what it handed down.
        for (i, (chain, _)) in nodes.iter().enumerate() {
            let leaf = chain.leaf().unwrap();
            let q = leaf.caveats.quotas;
            let own = enforcer.unallocated_quota(&leaf.digest());
            let expect = ChainQuotas {
                max_ops_per_window: q.max_ops_per_window - children_sum[i].ops as u32,
                storage_bytes: q.storage_bytes - children_sum[i].storage,
                footprint_paths: q.footprint_paths - children_sum[i].footprint,
                ..q
            };
            assert_eq!(
                own,
                Some(expect),
                "seed {PROPERTY_SEED:#x} case {case} node {i}"
            );
        }
    }
    println!(
        "seed {PROPERTY_SEED:#x}, {PARTITION_CASES} cases: {accepted} children accepted, \
         {refused} refused with QuotaPartitionExceeded"
    );
    assert!(accepted > 0 && refused > 0);
}

#[test]
fn f1_partitioned_rate_parent_keeps_only_what_it_has_not_handed_down() {
    let mut fx = Fx::new();
    // mid (500 ops) handed 250 to leaf; a second child asking 251 does not fit.
    let mut cav = fx.mid.caveats.clone();
    cav.quotas.max_ops_per_window = 251;
    cav.quotas.storage_bytes = 0;
    cav.quotas.footprint_paths = 0;
    let extra = CapabilityLink::issue(&fx.w, fx.mid.digest(), [0xB0; 32], repo(), [9u8; 32], cav);
    let chain = fx.chain(&[&fx.root, &fx.mid, &extra]);
    assert_eq!(
        fx.enforcer
            .grant_link(&chain, WalSeq(4), NOW)
            .map_err(|e| e.code),
        Err(RefusalCode::QuotaPartitionExceeded)
    );
    let own = fx.enforcer.unallocated_quota(&fx.mid.digest()).unwrap();
    assert_eq!(own.max_ops_per_window, 250);

    // A link whose rate is fully handed down cannot make requests itself.
    let mut cav = fx.leaf.caveats.clone();
    cav.quotas.max_ops_per_window = 1;
    cav.quotas.storage_bytes = 0;
    cav.quotas.footprint_paths = 0;
    let sub_key = SigningKey::from_bytes(&[5u8; 32]);
    let sub = CapabilityLink::issue(
        &fx.s,
        fx.leaf.digest(),
        [0xB1; 32],
        repo(),
        pubkey(&sub_key),
        cav,
    );
    // Shrink the leaf's own allowance to zero by handing all 250 to children.
    let mut big = fx.leaf.caveats.clone();
    big.quotas.max_ops_per_window = 249;
    big.quotas.storage_bytes = 0;
    big.quotas.footprint_paths = 0;
    let other = CapabilityLink::issue(&fx.s, fx.leaf.digest(), [0xB2; 32], repo(), [8u8; 32], big);
    let full = fx.full_chain();
    fx.enforcer
        .grant_link(&full.extended(sub.clone()), WalSeq(5), NOW)
        .unwrap();
    fx.enforcer
        .grant_link(&full.extended(other), WalSeq(6), NOW)
        .unwrap();
    assert_eq!(
        fx.enforcer
            .unallocated_quota(&fx.leaf.digest())
            .unwrap()
            .max_ops_per_window,
        0
    );
    let req = fx.request(&fx.s.clone(), full.clone(), Capability::Read, in_scope(), 1);
    assert_eq!(
        fx.authorize(&req, 7),
        Err(RefusalCode::QuotaRateLimitExceeded)
    );

    // The child with one op gets exactly one request in the window.
    let sub_chain = full.extended(sub);
    let r1 = fx.request(&sub_key, sub_chain.clone(), Capability::Read, in_scope(), 2);
    assert_eq!(fx.authorize(&r1, 8), Ok(()));
    let r2 = fx.request(&sub_key, sub_chain, Capability::Read, in_scope(), 3);
    assert_eq!(
        fx.authorize(&r2, 9),
        Err(RefusalCode::QuotaRateLimitExceeded)
    );
}

// ---------------------------------------------------------------------------------------------
// Forged, stripped, and reordered chains; links bound to another repository or audience.
// ---------------------------------------------------------------------------------------------

#[test]
fn f1_forged_chains_are_refused() {
    let mut fx = Fx::new();
    // Positive control: the genuine chain is admitted and audited.
    let ok = fx.request(
        &fx.s.clone(),
        fx.full_chain(),
        Capability::Propose,
        in_scope(),
        1,
    );
    assert_eq!(fx.authorize(&ok, 4), Ok(()));
    let last = fx.enforcer.audit_log().entries().last().cloned();
    assert_eq!(last.map(|e| e.outcome), Some(AuditOutcome::Admitted));

    // A link whose caveats were widened after signing.
    let mut mid_forged = fx.mid.clone();
    mid_forged.caveats.paths = PathScope::whole_repository();
    let chain = fx.chain(&[&fx.root, &mid_forged, &fx.leaf]);
    let req = fx.request(
        &fx.s.clone(),
        chain.clone(),
        Capability::Propose,
        in_scope(),
        2,
    );
    assert_eq!(
        fx.authorize(&req, 4),
        Err(RefusalCode::AuthGrantSignatureInvalid)
    );
    assert_eq!(
        fx.enforcer
            .grant_link(&fx.chain(&[&fx.root, &mid_forged]), WalSeq(4), NOW)
            .map_err(|e| e.code),
        Err(RefusalCode::AuthGrantSignatureInvalid)
    );

    // A link with signature bytes that were never produced by its issuer.
    let mut leaf_forged = fx.leaf.clone();
    leaf_forged.signature = [0x5A; 64];
    let chain = fx.chain(&[&fx.root, &fx.mid, &leaf_forged]);
    let req = fx.request(&fx.s.clone(), chain, Capability::Propose, in_scope(), 3);
    assert_eq!(
        fx.authorize(&req, 4),
        Err(RefusalCode::AuthGrantSignatureInvalid)
    );

    // A leaf whose audience was swapped to the attacker, presented by the attacker.
    let attacker = SigningKey::from_bytes(&[66u8; 32]);
    let mut leaf_stolen = fx.leaf.clone();
    leaf_stolen.audience_key = pubkey(&attacker);
    let chain = fx.chain(&[&fx.root, &fx.mid, &leaf_stolen]);
    let req = fx.request(&attacker, chain, Capability::Propose, in_scope(), 4);
    assert_eq!(
        fx.authorize(&req, 4),
        Err(RefusalCode::AuthGrantSignatureInvalid)
    );

    // A root the attacker signed for itself (not a trusted repository authority).
    let fake_root = CapabilityLink::issue(
        &attacker,
        ROOT_PARENT,
        [0xEE; 32],
        repo(),
        pubkey(&attacker),
        wide_caveats(),
    );
    let chain = CapabilityChain::new(vec![fake_root]);
    let req = fx.request(&attacker, chain.clone(), Capability::Propose, in_scope(), 5);
    assert_eq!(
        fx.authorize(&req, 4),
        Err(RefusalCode::AuthGrantSignatureInvalid)
    );
    assert_eq!(
        fx.enforcer
            .grant_link(&chain, WalSeq(4), NOW)
            .map_err(|e| e.code),
        Err(RefusalCode::AuthGrantSignatureInvalid)
    );
}

#[test]
fn f1_stripped_chains_are_refused() {
    let mut fx = Fx::new();
    let ok = fx.request(
        &fx.s.clone(),
        fx.full_chain(),
        Capability::Read,
        in_scope(),
        1,
    );
    assert_eq!(fx.authorize(&ok, 4), Ok(()));
    let cases: Vec<(&str, CapabilityChain)> = vec![
        ("middle link dropped", fx.chain(&[&fx.root, &fx.leaf])),
        ("root dropped", fx.chain(&[&fx.mid, &fx.leaf])),
        ("only the leaf", fx.chain(&[&fx.leaf])),
        ("empty chain", CapabilityChain::new(Vec::new())),
    ];
    for (i, (what, chain)) in cases.into_iter().enumerate() {
        let req = fx.request(
            &fx.s.clone(),
            chain,
            Capability::Read,
            in_scope(),
            10 + i as u8,
        );
        assert_eq!(
            fx.authorize(&req, 4),
            Err(RefusalCode::AuthChainBroken),
            "{what}"
        );
    }
}

#[test]
fn f1_reordered_chains_are_refused() {
    let mut fx = Fx::new();
    let links = [fx.root.clone(), fx.mid.clone(), fx.leaf.clone()];
    let orders = [[0, 2, 1], [1, 0, 2], [1, 2, 0], [2, 0, 1], [2, 1, 0]];
    let ok = fx.request(
        &fx.s.clone(),
        fx.full_chain(),
        Capability::Read,
        in_scope(),
        1,
    );
    assert_eq!(fx.authorize(&ok, 4), Ok(()));
    for (i, order) in orders.iter().enumerate() {
        let chain = CapabilityChain::new(order.iter().map(|&j| links[j].clone()).collect());
        let req = fx.request(
            &fx.s.clone(),
            chain,
            Capability::Read,
            in_scope(),
            10 + i as u8,
        );
        assert_eq!(
            fx.authorize(&req, 4),
            Err(RefusalCode::AuthChainBroken),
            "order {order:?}"
        );
    }
}

#[test]
fn f1_link_bound_to_another_repository_is_refused() {
    let mut fx = Fx::new();
    let other = RepoId::new("aien-spark/aien-sovereign-core").unwrap();
    fx.enforcer.register_repo_authority(
        other.clone(),
        encode_did_key_ed25519(&pubkey(&fx.authority)),
    );

    // A properly signed leaf bound to another repository, spliced under this repository's chain.
    let leaf_other = CapabilityLink::issue(
        &fx.w,
        fx.mid.digest(),
        [0xC0; 32],
        other.clone(),
        pubkey(&fx.s),
        fx.leaf.caveats.clone(),
    );
    let chain = fx.chain(&[&fx.root, &fx.mid, &leaf_other]);
    assert_eq!(
        fx.enforcer
            .grant_link(&chain, WalSeq(4), NOW)
            .map_err(|e| e.code),
        Err(RefusalCode::AuthCrossRepoDenied)
    );
    let req = fx.request(&fx.s.clone(), chain, Capability::Read, in_scope(), 1);
    assert_eq!(fx.authorize(&req, 4), Err(RefusalCode::AuthCrossRepoDenied));

    // This repository's whole chain presented to another repository.
    let req = ChainedRequest::sign_new(
        &fx.s,
        fx.full_chain(),
        other.clone(),
        Capability::Read,
        in_scope(),
        [2u8; 32],
        NOW,
        Vec::new(),
    );
    let got = fx
        .enforcer
        .authorize_chain(
            BoundaryKind::Api,
            "read",
            &other,
            Capability::Read,
            &req,
            WalSeq(4),
            NOW,
        )
        .map_err(|e| e.code);
    assert_eq!(got, Err(RefusalCode::AuthCrossRepoDenied));
}

#[test]
fn f1_link_bound_to_another_audience_is_refused() {
    let mut fx = Fx::new();
    let x = SigningKey::from_bytes(&[77u8; 32]);

    // The chain names S as its audience; X presents it with X's own valid signature.
    let req = fx.request(&x, fx.full_chain(), Capability::Read, in_scope(), 1);
    assert_eq!(
        fx.authorize(&req, 4),
        Err(RefusalCode::AuthAudienceMismatch)
    );

    // X signs a child under mid, but mid is bound to audience W, so X cannot extend it.
    let rogue = CapabilityLink::issue(
        &x,
        fx.mid.digest(),
        [0xD0; 32],
        repo(),
        pubkey(&x),
        fx.leaf.caveats.clone(),
    );
    let chain = fx.chain(&[&fx.root, &fx.mid, &rogue]);
    assert_eq!(
        fx.enforcer
            .grant_link(&chain, WalSeq(4), NOW)
            .map_err(|e| e.code),
        Err(RefusalCode::AuthAudienceMismatch)
    );
    let req = fx.request(&x, chain, Capability::Read, in_scope(), 2);
    assert_eq!(
        fx.authorize(&req, 4),
        Err(RefusalCode::AuthAudienceMismatch)
    );

    // A request that claims S as presenter but was signed by X.
    let mut req = fx.request(&x, fx.full_chain(), Capability::Read, in_scope(), 3);
    req.agent_key = pubkey(&fx.s);
    assert_eq!(
        fx.authorize(&req, 4),
        Err(RefusalCode::AuthSignatureInvalid)
    );

    // An ancestor's holder (W) cannot present the leaf bound to S.
    let req = fx.request(
        &fx.w.clone(),
        fx.full_chain(),
        Capability::Read,
        in_scope(),
        4,
    );
    assert_eq!(
        fx.authorize(&req, 4),
        Err(RefusalCode::AuthAudienceMismatch)
    );

    let ok = fx.request(
        &fx.s.clone(),
        fx.full_chain(),
        Capability::Read,
        in_scope(),
        5,
    );
    assert_eq!(fx.authorize(&ok, 4), Ok(()));
}

// ---------------------------------------------------------------------------------------------
// Scope at request time and revocation at the request's WalSeq.
// ---------------------------------------------------------------------------------------------

#[test]
fn f1_out_of_scope_path_is_refused() {
    let mut fx = Fx::new();
    let s = fx.s.clone();
    let chain = fx.full_chain();
    let mut nonce = 0u8;
    let mut run = |fx: &mut Fx, scope: RequestScope| {
        nonce += 1;
        let req = fx.request(&s, chain.clone(), Capability::Propose, scope, nonce);
        fx.authorize(&req, 4)
    };
    assert_eq!(run(&mut fx, in_scope()), Ok(()));
    assert_eq!(
        run(&mut fx, paths(&["crates/synapse-core/src/lib.rs"])),
        Err(RefusalCode::AuthPathOutOfScope)
    );
    // Prefixes match whole segments: `crates/synapse-auth` does not cover `crates/synapse-authz`.
    assert_eq!(
        run(&mut fx, paths(&["crates/synapse-authz/src/lib.rs"])),
        Err(RefusalCode::AuthPathOutOfScope)
    );
    // `docs` is in the parent's scope but not the leaf's.
    assert_eq!(
        run(
            &mut fx,
            paths(&["crates/synapse-auth/src/lib.rs", "docs/F1.md"])
        ),
        Err(RefusalCode::AuthPathOutOfScope)
    );
    assert_eq!(
        run(
            &mut fx,
            paths(&["crates/synapse-auth/../synapse-core/src/lib.rs"])
        ),
        Err(RefusalCode::PathInvalid)
    );
    let with_ref = |k| RequestScope {
        reference: Some(k),
        ..in_scope()
    };
    assert_eq!(run(&mut fx, with_ref(ReferenceKind::OwnDrafts)), Ok(()));
    assert_eq!(
        run(&mut fx, with_ref(ReferenceKind::CanonicalViaPromotionQueue)),
        Err(RefusalCode::AuthReferenceOutOfScope)
    );
    let with_change = |id| RequestScope {
        join_change: Some(id),
        ..in_scope()
    };
    assert_eq!(run(&mut fx, with_change(change_id(1))), Ok(()));
    assert_eq!(
        run(&mut fx, with_change(change_id(2))),
        Err(RefusalCode::AuthChangeOutOfScope)
    );
}

#[test]
fn f1_chain_with_an_ancestor_revoked_at_the_request_walseq_is_refused() {
    let mut fx = Fx::new();
    let s = fx.s.clone();
    let chain = fx.full_chain();
    let mut nonce = 0u8;
    let mut at = |fx: &mut Fx, seq: u64| {
        nonce += 1;
        let req = fx.request(&s, chain.clone(), Capability::Propose, in_scope(), nonce);
        fx.authorize(&req, seq)
    };
    assert_eq!(at(&mut fx, 9), Ok(()));

    fx.enforcer
        .revoke_link(fx.mid.digest(), WalSeq(10))
        .unwrap();
    // Revocation applies from its own WalSeq on, not before.
    assert_eq!(at(&mut fx, 9), Ok(()));
    assert_eq!(at(&mut fx, 10), Err(RefusalCode::AuthGrantRevoked));
    assert_eq!(at(&mut fx, 11), Err(RefusalCode::AuthGrantRevoked));

    // A later revocation never moves the first one, so revocation cannot be undone that way.
    fx.enforcer
        .revoke_link(fx.mid.digest(), WalSeq(20))
        .unwrap();
    assert_eq!(at(&mut fx, 15), Err(RefusalCode::AuthGrantRevoked));

    // No new child can be granted under the revoked ancestor.
    let mut cav = fx.leaf.caveats.clone();
    cav.quotas.max_ops_per_window = 0;
    cav.quotas.storage_bytes = 0;
    cav.quotas.footprint_paths = 0;
    let late = CapabilityLink::issue(&fx.w, fx.mid.digest(), [0xF0; 32], repo(), [7u8; 32], cav);
    assert_eq!(
        fx.enforcer
            .grant_link(&fx.chain(&[&fx.root, &fx.mid, &late]), WalSeq(12), NOW)
            .map_err(|e| e.code),
        Err(RefusalCode::AuthGrantRevoked)
    );

    // Revoking the root refuses even a chain of the root alone held by O.
    fx.enforcer
        .revoke_link(fx.root.digest(), WalSeq(30))
        .unwrap();
    let req = fx.request(
        &fx.o.clone(),
        fx.chain(&[&fx.root]),
        Capability::Read,
        in_scope(),
        200,
    );
    assert_eq!(fx.authorize(&req, 30), Err(RefusalCode::AuthGrantRevoked));

    // The leaf is granted at WalSeq 3: a request at WalSeq 2 predates it (no link is revoked
    // at WalSeq 2, so this refusal is about the grant, not the revocations above).
    assert_eq!(at(&mut fx, 2), Err(RefusalCode::AuthChainBroken));
}

// ---------------------------------------------------------------------------------------------
// Binary encoding (ADR 0003 principle P5).
// ---------------------------------------------------------------------------------------------

#[test]
fn f1_link_and_chain_binary_encoding_is_canonical_and_malformed_bytes_are_refused() {
    let fx = Fx::new();
    let leaf = fx.leaf.clone();
    let bytes = leaf.encode();
    // Documented layout: version u16 LE, nonce, parent digest, repo (u32 LE length + bytes).
    assert_eq!(&bytes[0..2], &1u16.to_le_bytes());
    assert_eq!(&bytes[2..34], &leaf.nonce);
    assert_eq!(&bytes[34..66], &fx.mid.digest().0);
    let repo_len = repo().as_str().len();
    assert_eq!(&bytes[66..70], &(repo_len as u32).to_le_bytes());
    assert_eq!(&bytes[bytes.len() - 64..], &leaf.signature);

    let back = CapabilityLink::decode(&bytes).map_err(|e| e.code);
    assert_eq!(back.as_ref(), Ok(&leaf));
    assert_eq!(back.unwrap().encode(), bytes);

    let chain = fx.full_chain();
    let chain_bytes = chain.encode();
    let chain_back = CapabilityChain::decode(&chain_bytes).map_err(|e| e.code);
    assert_eq!(chain_back.as_ref(), Ok(&chain));
    assert_eq!(chain_back.unwrap().encode(), chain_bytes);
    assert_eq!(
        chain.link_digests(),
        vec![fx.root.digest(), fx.mid.digest(), leaf.digest()]
    );

    let malformed = |b: &[u8]| CapabilityChain::decode(b).map_err(|e| e.code);
    for cut in 0..chain_bytes.len() {
        assert_eq!(
            malformed(&chain_bytes[..cut]),
            Err(RefusalCode::AuthChainMalformed),
            "truncated at {cut}"
        );
    }
    let mut trailing = chain_bytes.clone();
    trailing.push(0);
    assert_eq!(malformed(&trailing), Err(RefusalCode::AuthChainMalformed));
    let mut v2 = chain_bytes.clone();
    v2[0] = 2;
    assert_eq!(malformed(&v2), Err(RefusalCode::AuthChainMalformed));
    for count in [0u8, (MAX_CHAIN_DEPTH + 1) as u8] {
        let mut c = chain_bytes.clone();
        c[2] = count;
        assert_eq!(malformed(&c), Err(RefusalCode::AuthChainMalformed));
    }

    let link_err = |b: &[u8]| CapabilityLink::decode(b).map_err(|e| e.code);
    let ops_at = 2 + 32 + 32 + 4 + repo_len + 32 + 32;
    let mut bad_ops = bytes.clone();
    bad_ops[ops_at] |= 0x40;
    assert_eq!(link_err(&bad_ops), Err(RefusalCode::AuthChainMalformed));
    let mut bad_refs = bytes.clone();
    bad_refs[ops_at + 1] |= 0x04;
    assert_eq!(link_err(&bad_refs), Err(RefusalCode::AuthChainMalformed));
    let mut huge_paths = bytes.clone();
    huge_paths[ops_at + 2..ops_at + 6].copy_from_slice(&u32::MAX.to_le_bytes());
    assert_eq!(link_err(&huge_paths), Err(RefusalCode::AuthChainMalformed));

    // Path prefixes out of order are not the canonical form.
    let mut cav = wide_caveats();
    cav.paths = PathScope::new(vec!["a".into(), "b".into()]).unwrap();
    let two = CapabilityLink::issue(&fx.authority, ROOT_PARENT, [1; 32], repo(), [2; 32], cav);
    let mut swapped = two.encode();
    let first = ops_at + 2 + 4 + 4;
    let second = first + 1 + 4;
    assert_eq!((swapped[first], swapped[second]), (b'a', b'b'));
    swapped.swap(first, second);
    assert_eq!(link_err(&swapped), Err(RefusalCode::AuthChainMalformed));
    // Unknown change-scope tag.
    let mut bad_change = two.encode();
    bad_change[second + 1] = 2;
    assert_eq!(link_err(&bad_change), Err(RefusalCode::AuthChainMalformed));

    // Every link digest differs once any signed byte differs.
    let d: LinkDigest = fx.leaf.digest();
    let mut other = fx.leaf.clone();
    other.caveats.expires_at_ms -= 1;
    assert_ne!(other.digest(), d);
}
