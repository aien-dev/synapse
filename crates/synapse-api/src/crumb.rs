//! Read-only Directory Crumb context over `VirtualTree` snapshots (ADR 0004, deliverable D1).
//!
//! Reads go through `materialize_virtual_tree` and `read_blob_bytes`, the same path
//! `read_file` uses, after one `Capability::Read` authorization. Nothing is written and no
//! new capability exists: a Crumb context grants nothing.

use crate::{SynapseService, TreeTarget, VirtualTreeEntry};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use synapse_auth::{AuthenticatedRequest, BoundaryKind, Capability};
use synapse_core::{
    validate_repo_relative_path, FileMode, RefusalCode, SynapseError, SynapseResult, WalSeq,
};
use synapse_crumb::{CrumbContext, CrumbFile, MAX_CRUMB_BYTES, ROOT_DIR};

/// Request payload for [`SynapseService::crumb_context`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrumbContextQueryPayload {
    pub target: TreeTarget,
    /// `"."` for the repository root, else a repository-relative file or directory.
    pub path: String,
    pub snapshot_seq: Option<WalSeq>,
}

impl SynapseService {
    /// Directory Crumb context for `path` in the `target` snapshot (`Capability::Read`).
    ///
    /// A file path resolves to its parent directory. A path absent from the snapshot is
    /// refused with `BlobNotFound`, as `read_file` does.
    pub fn crumb_context(
        &mut self,
        req: &AuthenticatedRequest<CrumbContextQueryPayload>,
        now_ms: u64,
    ) -> SynapseResult<CrumbContext> {
        self.auth.authorize(
            BoundaryKind::Api,
            "crumb_context",
            &self.repo_id,
            Capability::Read,
            req,
            now_ms,
        )?;
        let payload = &req.payload;
        let tree = self.materialize_virtual_tree(payload.target, payload.snapshot_seq)?;
        let dir = target_dir(&tree, &payload.path)?;
        self.resolve_crumb_context(&tree, &dir, payload.snapshot_seq)
    }

    /// Resolve the context chain for `dir` in an already materialized `tree`. No
    /// authorization: callers authorize once before materializing.
    pub(crate) fn resolve_crumb_context(
        &self,
        tree: &BTreeMap<String, VirtualTreeEntry>,
        dir: &str,
        snapshot_seq: Option<WalSeq>,
    ) -> SynapseResult<CrumbContext> {
        CrumbContext::resolve(dir, |crumb_path| match tree.get(crumb_path) {
            None => Ok(CrumbFile::Missing),
            Some(e) if e.mode == FileMode::Symlink120000 => Ok(CrumbFile::NotRegularFile {
                blob_digest: e.blob_digest,
            }),
            Some(e) if e.size_bytes > MAX_CRUMB_BYTES => Ok(CrumbFile::Oversized {
                blob_digest: e.blob_digest,
                size: e.size_bytes,
            }),
            Some(e) => self
                .read_blob_bytes(e.blob_digest, snapshot_seq)
                .map(CrumbFile::Bytes),
        })
    }
}

/// Directory whose context is wanted: the path itself if it is a directory in `tree`,
/// its parent if it is a file.
fn target_dir(tree: &BTreeMap<String, VirtualTreeEntry>, path: &str) -> SynapseResult<String> {
    if path == ROOT_DIR {
        return Ok(ROOT_DIR.to_string());
    }
    validate_repo_relative_path(path)?;
    if tree.contains_key(path) {
        return Ok(path
            .rsplit_once('/')
            .map_or(ROOT_DIR.to_string(), |(parent, _)| parent.to_string()));
    }
    let prefix = format!("{path}/");
    if tree
        .range(prefix.clone()..)
        .next()
        .is_some_and(|(k, _)| k.starts_with(&prefix))
    {
        return Ok(path.to_string());
    }
    Err(SynapseError::new(
        RefusalCode::BlobNotFound,
        format!("path {path} not found in virtual tree"),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::FsyncPolicy;
    use crate::RecoveryPolicy;
    use crate::StoreLimits;
    use ed25519_dalek::SigningKey;
    use std::fs;
    use synapse_auth::AgentCapabilityGrant;
    use synapse_core::{encode_did_key_ed25519, BlobDigest, GitOid, RepoId};
    use synapse_crumb::{Dialect, DirectoryCrumb, EntryStatus, InvalidReason};

    const ROOT: &[u8] =
        br#"{"schema_version":"1.0.0","name":"root","purpose":"Root.","invariants":["root rule"]}"#;
    const SRC: &[u8] = br#"{"schema_version":"1.0.0","name":"src","purpose":"Sources."}"#;

    struct Fixture {
        svc: SynapseService,
        agent: SigningKey,
        auth: SigningKey,
        repo: RepoId,
        nonce: u8,
        dir: std::path::PathBuf,
    }

    impl Fixture {
        fn new(label: &str) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "synapse-api-crumb-{label}-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            let repo = RepoId::new("aien-spark/synapse").unwrap();
            let mut svc = SynapseService::open(
                &dir,
                repo.clone(),
                FsyncPolicy::EveryCommit,
                RecoveryPolicy::StrictFailClosed,
                StoreLimits::default(),
            )
            .unwrap();
            let auth = SigningKey::from_bytes(&[10u8; 32]);
            svc.register_authority(encode_did_key_ed25519(&auth.verifying_key().to_bytes()));
            Self {
                svc,
                agent: SigningKey::from_bytes(&[20u8; 32]),
                auth,
                repo,
                nonce: 0,
                dir,
            }
        }

        fn query(
            &mut self,
            caps: Vec<Capability>,
            target: TreeTarget,
            path: &str,
        ) -> SynapseResult<CrumbContext> {
            self.nonce += 1;
            let grant = AgentCapabilityGrant::issue(
                &self.auth,
                [self.nonce; 32],
                self.repo.clone(),
                encode_did_key_ed25519(&self.agent.verifying_key().to_bytes()),
                caps,
                1024 * 1024,
                100,
                60_000,
                10,
                100_000,
            );
            let req = AuthenticatedRequest::sign_new(
                &self.agent,
                grant,
                self.repo.clone(),
                Capability::Read,
                [self.nonce; 32],
                1000 + u64::from(self.nonce),
                0,
                CrumbContextQueryPayload {
                    target,
                    path: path.to_string(),
                    snapshot_seq: None,
                },
            )?;
            self.svc.crumb_context(&req, 1000 + u64::from(self.nonce))
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.dir);
        }
    }

    fn base(fx: &mut Fixture, seed: u8, files: Vec<(&str, FileMode, Vec<u8>)>) -> TreeTarget {
        let oid = GitOid([seed; 20]);
        fx.svc
            .register_base_tree(
                oid,
                files
                    .into_iter()
                    .map(|(p, m, b)| (p.to_string(), m, b))
                    .collect(),
            )
            .unwrap();
        TreeTarget::BaseGitCommit(oid)
    }

    #[test]
    fn reads_chain_from_snapshot_for_files_and_directories() {
        let mut fx = Fixture::new("chain");
        let t = base(
            &mut fx,
            1,
            vec![
                (".crumb", FileMode::Regular644, ROOT.to_vec()),
                ("src/.crumb", FileMode::Regular644, SRC.to_vec()),
                (
                    "src/net/http.rs",
                    FileMode::Regular644,
                    b"fn x() {}\n".to_vec(),
                ),
            ],
        );
        let by_file = fx
            .query(vec![Capability::Read], t, "src/net/http.rs")
            .unwrap();
        assert_eq!(by_file.target_dir(), "src/net");
        let dirs: Vec<&str> = by_file.entries().iter().map(|e| e.dir.as_str()).collect();
        assert_eq!(dirs, [".", "src", "src/net"]);
        assert_eq!(by_file.leaf().status, EntryStatus::Missing);
        assert_eq!(by_file.nearest().unwrap().dir, "src");
        assert_eq!(by_file.inherited_invariants(), vec![(".", "root rule")]);
        assert_eq!(
            by_file.entries()[1].blob_digest,
            Some(BlobDigest::compute(SRC))
        );

        let by_dir = fx.query(vec![Capability::Read], t, "src/net").unwrap();
        assert_eq!(by_dir.digest(), by_file.digest());

        let root = fx.query(vec![Capability::Read], t, ".").unwrap();
        assert_eq!(root.entries().len(), 1);
        assert!(matches!(
            root.leaf().crumb(),
            Some(DirectoryCrumb::Rfc0001(c)) if c.name == "root"
        ));
    }

    #[test]
    fn different_snapshots_give_different_digests() {
        let mut fx = Fixture::new("snapshots");
        let a = base(
            &mut fx,
            1,
            vec![(".crumb", FileMode::Regular644, ROOT.to_vec())],
        );
        let b = base(
            &mut fx,
            2,
            vec![(".crumb", FileMode::Regular644, b"{not json".to_vec())],
        );
        let ca = fx.query(vec![Capability::Read], a, ".").unwrap();
        let cb = fx.query(vec![Capability::Read], b, ".").unwrap();
        assert!(matches!(
            cb.leaf().status,
            EntryStatus::Invalid(InvalidReason::Json(_))
        ));
        assert_ne!(ca.digest(), cb.digest());
    }

    #[test]
    fn oversized_and_symlink_crumbs_are_invalid_without_parsing() {
        let mut fx = Fixture::new("bounds");
        let big = vec![b' '; MAX_CRUMB_BYTES as usize + 1];
        let t = base(
            &mut fx,
            3,
            vec![
                (".crumb", FileMode::Regular644, big.clone()),
                ("a/.crumb", FileMode::Symlink120000, b"../.crumb".to_vec()),
                ("a/f", FileMode::Regular644, b"x".to_vec()),
            ],
        );
        let c = fx.query(vec![Capability::Read], t, "a").unwrap();
        assert_eq!(
            c.entries()[0].status,
            EntryStatus::Invalid(InvalidReason::TooLarge {
                size: MAX_CRUMB_BYTES + 1
            })
        );
        assert_eq!(c.entries()[0].blob_digest, Some(BlobDigest::compute(&big)));
        assert_eq!(
            c.leaf().status,
            EntryStatus::Invalid(InvalidReason::NotRegularFile)
        );
        assert!(c.nearest().is_none());
        assert_eq!(c.leaf().dialect(), None::<Dialect>);
    }

    #[test]
    fn refuses_without_read_capability_and_for_unknown_paths() {
        let mut fx = Fixture::new("refuse");
        let t = base(
            &mut fx,
            4,
            vec![("a/f", FileMode::Regular644, b"x".to_vec())],
        );
        let denied = fx.query(vec![Capability::Propose], t, "a").unwrap_err();
        assert_eq!(denied.code, RefusalCode::AuthCapabilityDenied);
        let missing = fx.query(vec![Capability::Read], t, "nope").unwrap_err();
        assert_eq!(missing.code, RefusalCode::BlobNotFound);
        // "a/f" exists as a file, so "a/f/g" is not a directory in the tree.
        let under_file = fx.query(vec![Capability::Read], t, "a/f/g").unwrap_err();
        assert_eq!(under_file.code, RefusalCode::BlobNotFound);
        let bad = fx.query(vec![Capability::Read], t, "../a").unwrap_err();
        assert_eq!(bad.code, RefusalCode::PathInvalid);
    }
}
