//! Radicle `refs/rad/id` identity document and `refs/namespaces/<nid>/refs/rad/sigrefs`
//! Ed25519 delegate threshold verifier, canonical promotion gate, and split-brain
//! reconciliation state machine (`synapse-radicle`, Gate 3).

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;
use std::process::Command;
use synapse_core::{
    decode_did_key_ed25519, encode_did_key_ed25519, ChangesetId, GitOid, RadicleCanonicalHead,
    RefusalCode, RepoId, SynapseError, SynapseResult,
};

/// Radicle project payload inside `embeds/radicle.json` (`payload["xyz.radicle.project"]`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RadicleProjectPayload {
    pub default_branch: String,
    #[serde(default)]
    pub description: String,
    pub name: String,
}

/// Top-level payload map in `embeds/radicle.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RadiclePayloadMap {
    #[serde(rename = "xyz.radicle.project")]
    pub project: RadicleProjectPayload,
}

/// Wire format of Radicle's `refs/rad/id:embeds/radicle.json` identity document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RadicleIdentityDoc {
    pub delegates: Vec<String>,
    pub payload: RadiclePayloadMap,
    pub threshold: usize,
}

impl RadicleIdentityDoc {
    /// Validate delegate `did:key:z6Mk...` encodings and threshold bounds.
    pub fn validate(&self) -> SynapseResult<()> {
        if self.delegates.is_empty() {
            return Err(SynapseError::new(
                RefusalCode::RadicleIdentityInvalid,
                "Radicle identity document must have at least one delegate",
            ));
        }
        if self.threshold == 0 || self.threshold > self.delegates.len() {
            return Err(SynapseError::new(
                RefusalCode::RadicleIdentityInvalid,
                format!(
                    "invalid Radicle threshold {} for {} delegates",
                    self.threshold,
                    self.delegates.len()
                ),
            ));
        }
        if self.payload.project.default_branch.trim().is_empty() {
            return Err(SynapseError::new(
                RefusalCode::RadicleIdentityInvalid,
                "Radicle project defaultBranch cannot be empty",
            ));
        }
        for delegate_did in &self.delegates {
            let _ = decode_did_key_ed25519(delegate_did)?;
        }
        Ok(())
    }

    pub fn default_branch_ref(&self) -> String {
        format!("refs/heads/{}", self.payload.project.default_branch)
    }

    pub fn compute_doc_oid_hint(&self) -> GitOid {
        let json = serde_json::to_vec(self).unwrap_or_default();
        GitOid::compute_blob(&json)
    }
}

/// Wire bundle for a single delegate's `refs/namespaces/<nid>/refs/rad/sigrefs`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DelegateSigrefs {
    /// Delegate node identity (`did:key:z6Mk...` or bare `z6Mk...`).
    pub delegate_did: String,
    /// Exact contents of the `refs` blob inside `refs/rad/sigrefs` (sorted `<oid> <refname>\n` lines).
    pub refs_blob: Vec<u8>,
    /// Raw 64-byte Ed25519 `signature` blob inside `refs/rad/sigrefs` over `refs_blob`.
    pub signature_blob: Vec<u8>,
}

impl DelegateSigrefs {
    /// Helper to sign a sorted `refs` map with a delegate's Ed25519 `SigningKey`.
    pub fn sign_refs(delegate_key: &SigningKey, refs: &BTreeMap<String, GitOid>) -> Self {
        let delegate_did = encode_did_key_ed25519(&delegate_key.verifying_key().to_bytes());
        let mut refs_text = String::new();
        for (refname, oid) in refs {
            refs_text.push_str(&format!("{} {}\n", oid.to_hex(), refname));
        }
        let refs_blob = refs_text.into_bytes();
        let signature_blob = delegate_key.sign(&refs_blob).to_bytes().to_vec();
        Self {
            delegate_did,
            refs_blob,
            signature_blob,
        }
    }

    /// Cryptographically verify the delegate's Ed25519 signature over `refs_blob`
    /// and parse the signed `refname -> GitOid` table.
    pub fn verify_and_parse(&self) -> SynapseResult<(String, BTreeMap<String, GitOid>)> {
        let normalized_did = if self.delegate_did.starts_with("did:key:") {
            self.delegate_did.clone()
        } else {
            format!("did:key:{}", self.delegate_did)
        };
        let pubkey_bytes = decode_did_key_ed25519(&normalized_did)?;
        let verifying_key = VerifyingKey::from_bytes(&pubkey_bytes).map_err(|_| {
            SynapseError::new(
                RefusalCode::RadicleIdentityInvalid,
                "invalid delegate Ed25519 public key",
            )
        })?;
        let sig_arr: [u8; 64] = self.signature_blob.as_slice().try_into().map_err(|_| {
            SynapseError::new(
                RefusalCode::RadicleSignatureInvalid,
                "Radicle sigrefs signature must be 64 bytes",
            )
        })?;
        let sig = Signature::from_bytes(&sig_arr);
        verifying_key.verify(&self.refs_blob, &sig).map_err(|_| {
            SynapseError::new(
                RefusalCode::RadicleSignatureInvalid,
                format!("Ed25519 signature verification failed for delegate {normalized_did}"),
            )
        })?;

        let text = std::str::from_utf8(&self.refs_blob).map_err(|_| {
            SynapseError::new(
                RefusalCode::RadicleSignatureInvalid,
                "sigrefs refs blob is not valid UTF-8",
            )
        })?;

        let mut parsed = BTreeMap::new();
        for line in text.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            let (oid_hex, refname) = trimmed.split_once(' ').ok_or_else(|| {
                SynapseError::new(
                    RefusalCode::RadicleSignatureInvalid,
                    format!("malformed sigrefs line: {trimmed}"),
                )
            })?;
            let oid = GitOid::from_hex(oid_hex)?;
            parsed.insert(refname.to_string(), oid);
        }

        Ok((normalized_did, parsed))
    }
}

/// Classification of repository canonical reconciliation state across Radicle and GitHub.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReconciliationState {
    /// Radicle delegate threshold is satisfied for `canonical_oid`.
    CanonicalQuorumSatisfied {
        canonical_oid: GitOid,
        verified_delegates: Vec<String>,
    },
    /// Split-brain Case 1: A GitHub PR was marked merged, but Radicle delegate threshold is absent.
    /// Canonical promotion is refused until Radicle delegate threshold is satisfied.
    SplitBrainGithubMergedWithoutRadicleQuorum {
        candidate_oid: GitOid,
        verified_count: usize,
        required_threshold: usize,
    },
    /// Split-brain Case 2: Radicle delegate quorum points to `radicle_canonical_oid`,
    /// which diverges from the candidate `candidate_oid`.
    SplitBrainRadicleCanonicalDiverged {
        radicle_canonical_oid: GitOid,
        candidate_oid: GitOid,
    },
    /// Network partition Case 4: Fewer than `threshold` delegate `sigrefs` are reachable.
    PartitionedAwaitingDelegates {
        reachable_verified: usize,
        required_threshold: usize,
    },
}

/// Input bundle for evaluating canonical promotion of a candidate commit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PromotionCandidate {
    pub repo_id: RepoId,
    pub changeset_id: Option<ChangesetId>,
    pub proposal_base_git_oid: GitOid,
    pub candidate_git_oid: GitOid,
    pub github_pr_merged: bool,
    pub verified_at_ms: u64,
}

/// Radicle canonical promotion and split-brain reconciliation verifier.
pub struct CanonicalPromotionEngine {
    identity_doc: RadicleIdentityDoc,
    identity_doc_oid: GitOid,
    current_canonical: Option<RadicleCanonicalHead>,
}

impl CanonicalPromotionEngine {
    pub fn new(
        identity_doc: RadicleIdentityDoc,
        identity_doc_oid: Option<GitOid>,
        current_canonical: Option<RadicleCanonicalHead>,
    ) -> SynapseResult<Self> {
        identity_doc.validate()?;
        let doc_oid = identity_doc_oid.unwrap_or_else(|| identity_doc.compute_doc_oid_hint());
        Ok(Self {
            identity_doc,
            identity_doc_oid: doc_oid,
            current_canonical,
        })
    }

    pub fn current_canonical(&self) -> Option<&RadicleCanonicalHead> {
        self.current_canonical.as_ref()
    }

    /// Inspect the reconciliation state between `candidate` and the available `delegate_sigrefs`
    /// without mutating canonical state.
    pub fn classify_reconciliation(
        &self,
        candidate: &PromotionCandidate,
        delegate_sigrefs: &[DelegateSigrefs],
    ) -> SynapseResult<ReconciliationState> {
        let default_ref = self.identity_doc.default_branch_ref();
        let mut votes_by_oid: BTreeMap<GitOid, Vec<String>> = BTreeMap::new();
        let mut verified_for_candidate = Vec::new();

        for sigref in delegate_sigrefs {
            let (norm_did, refs_map) = sigref.verify_and_parse()?;
            if !self.identity_doc.delegates.contains(&norm_did) {
                return Err(SynapseError::new(
                    RefusalCode::RadicleIdentityInvalid,
                    format!("signer {norm_did} is not an authorized delegate in refs/rad/id"),
                ));
            }
            if let Some(&signed_oid) = refs_map.get(&default_ref) {
                let voters = votes_by_oid.entry(signed_oid).or_default();
                if !voters.contains(&norm_did) {
                    voters.push(norm_did.clone());
                }
                if signed_oid == candidate.candidate_git_oid
                    && !verified_for_candidate.contains(&norm_did)
                {
                    verified_for_candidate.push(norm_did);
                }
            }
        }

        // Check if Radicle delegate threshold already converged on a DIFFERENT commit OID
        for (oid, voters) in &votes_by_oid {
            if voters.len() >= self.identity_doc.threshold && *oid != candidate.candidate_git_oid {
                return Ok(ReconciliationState::SplitBrainRadicleCanonicalDiverged {
                    radicle_canonical_oid: *oid,
                    candidate_oid: candidate.candidate_git_oid,
                });
            }
        }

        if verified_for_candidate.len() >= self.identity_doc.threshold {
            return Ok(ReconciliationState::CanonicalQuorumSatisfied {
                canonical_oid: candidate.candidate_git_oid,
                verified_delegates: verified_for_candidate,
            });
        }

        if candidate.github_pr_merged {
            Ok(
                ReconciliationState::SplitBrainGithubMergedWithoutRadicleQuorum {
                    candidate_oid: candidate.candidate_git_oid,
                    verified_count: verified_for_candidate.len(),
                    required_threshold: self.identity_doc.threshold,
                },
            )
        } else {
            Ok(ReconciliationState::PartitionedAwaitingDelegates {
                reachable_verified: verified_for_candidate.len(),
                required_threshold: self.identity_doc.threshold,
            })
        }
    }

    /// Verify Radicle identity, signed refs, base freshness, and delegate threshold,
    /// promoting `candidate` to `RadicleCanonicalHead` only when all invariants hold.
    pub fn verify_and_promote(
        &mut self,
        candidate: &PromotionCandidate,
        delegate_sigrefs: &[DelegateSigrefs],
    ) -> SynapseResult<RadicleCanonicalHead> {
        // 1. Stale-base refusal: if a canonical head is already established, the proposal's
        //    base must match the current canonical head OID.
        if let Some(ref curr) = self.current_canonical {
            if candidate.proposal_base_git_oid != curr.canonical_git_oid {
                return Err(SynapseError::new(
                    RefusalCode::StaleBaseHead,
                    format!(
                        "stale proposal base {} != current Radicle canonical head {}",
                        candidate.proposal_base_git_oid, curr.canonical_git_oid
                    ),
                ));
            }
        }

        // 2. Classify reconciliation state and verify all delegate Ed25519 signatures
        match self.classify_reconciliation(candidate, delegate_sigrefs)? {
            ReconciliationState::CanonicalQuorumSatisfied {
                canonical_oid,
                verified_delegates,
            } => {
                let head = RadicleCanonicalHead {
                    repo_id: candidate.repo_id.clone(),
                    default_branch: self.identity_doc.payload.project.default_branch.clone(),
                    canonical_git_oid: canonical_oid,
                    promoted_changeset_id: candidate.changeset_id,
                    rad_id_commit_oid: self.identity_doc_oid,
                    verified_delegates,
                    threshold: self.identity_doc.threshold,
                    verified_at_ms: candidate.verified_at_ms,
                };
                self.current_canonical = Some(head.clone());
                Ok(head)
            }
            ReconciliationState::SplitBrainRadicleCanonicalDiverged {
                radicle_canonical_oid,
                candidate_oid,
            } => Err(SynapseError::new(
                RefusalCode::SplitBrainDivergence,
                format!(
                    "Radicle canonical quorum points to {radicle_canonical_oid}, diverging from candidate {candidate_oid}"
                ),
            )),
            ReconciliationState::SplitBrainGithubMergedWithoutRadicleQuorum {
                candidate_oid,
                verified_count,
                required_threshold,
            } => Err(SynapseError::new(
                RefusalCode::RadicleQuorumInsufficient,
                format!(
                    "GitHub PR merged for {candidate_oid}, but Radicle delegate quorum is {verified_count}/{required_threshold}; refusing canonical promotion"
                ),
            )),
            ReconciliationState::PartitionedAwaitingDelegates {
                reachable_verified,
                required_threshold,
            } => Err(SynapseError::new(
                RefusalCode::RadicleQuorumInsufficient,
                format!(
                    "Radicle delegate quorum insufficient ({reachable_verified}/{required_threshold} reachable); failing closed"
                ),
            )),
        }
    }
}

/// Load `RadicleIdentityDoc` (`refs/rad/id:embeds/radicle.json`) and all delegate
/// `DelegateSigrefs` (`refs/namespaces/<nid>/refs/rad/sigrefs:{refs,signature}`)
/// directly from a real bare Radicle Git repository on disk.
pub fn load_radicle_state_from_bare_repo(
    bare_repo_dir: &Path,
) -> SynapseResult<(RadicleIdentityDoc, GitOid, Vec<DelegateSigrefs>)> {
    let id_rev_out = Command::new("git")
        .arg("--git-dir")
        .arg(bare_repo_dir)
        .args(["rev-parse", "refs/rad/id"])
        .output()
        .map_err(|e| SynapseError::new(RefusalCode::IoFailure, e.to_string()))?;
    if !id_rev_out.status.success() {
        return Err(SynapseError::new(
            RefusalCode::RadicleIdentityInvalid,
            "refs/rad/id not found in bare Radicle repository",
        ));
    }
    let id_oid = GitOid::from_hex(String::from_utf8_lossy(&id_rev_out.stdout).trim())?;

    let doc_out = Command::new("git")
        .arg("--git-dir")
        .arg(bare_repo_dir)
        .args(["cat-file", "blob", "refs/rad/id:embeds/radicle.json"])
        .output()
        .map_err(|e| SynapseError::new(RefusalCode::IoFailure, e.to_string()))?;
    if !doc_out.status.success() {
        return Err(SynapseError::new(
            RefusalCode::RadicleIdentityInvalid,
            "refs/rad/id:embeds/radicle.json not found",
        ));
    }
    let doc: RadicleIdentityDoc = serde_json::from_slice(&doc_out.stdout).map_err(|e| {
        SynapseError::new(
            RefusalCode::RadicleIdentityInvalid,
            format!("parse embeds/radicle.json: {e}"),
        )
    })?;
    doc.validate()?;

    let mut sigrefs_list = Vec::new();
    for delegate_did in &doc.delegates {
        let nid = delegate_did
            .strip_prefix("did:key:")
            .unwrap_or(delegate_did);
        let sigref_base = format!("refs/namespaces/{nid}/refs/rad/sigrefs");

        let refs_out = Command::new("git")
            .arg("--git-dir")
            .arg(bare_repo_dir)
            .args(["cat-file", "blob", &format!("{sigref_base}:refs")])
            .output()
            .map_err(|e| SynapseError::new(RefusalCode::IoFailure, e.to_string()))?;
        let sig_out = Command::new("git")
            .arg("--git-dir")
            .arg(bare_repo_dir)
            .args(["cat-file", "blob", &format!("{sigref_base}:signature")])
            .output()
            .map_err(|e| SynapseError::new(RefusalCode::IoFailure, e.to_string()))?;

        if refs_out.status.success() && sig_out.status.success() {
            sigrefs_list.push(DelegateSigrefs {
                delegate_did: delegate_did.clone(),
                refs_blob: refs_out.stdout,
                signature_blob: sig_out.stdout,
            });
        }
    }

    Ok((doc, id_oid, sigrefs_list))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_radicle_quorum_and_all_five_split_brain_cases() {
        let del1_key = SigningKey::from_bytes(&[51u8; 32]);
        let del1_did = encode_did_key_ed25519(&del1_key.verifying_key().to_bytes());
        let del2_key = SigningKey::from_bytes(&[52u8; 32]);
        let del2_did = encode_did_key_ed25519(&del2_key.verifying_key().to_bytes());
        let del3_key = SigningKey::from_bytes(&[53u8; 32]);
        let del3_did = encode_did_key_ed25519(&del3_key.verifying_key().to_bytes());

        let doc = RadicleIdentityDoc {
            delegates: vec![del1_did, del2_did, del3_did],
            payload: RadiclePayloadMap {
                project: RadicleProjectPayload {
                    default_branch: "main".to_string(),
                    description: "Sovereign changeset engine".to_string(),
                    name: "synapse".to_string(),
                },
            },
            threshold: 2, // 2-of-3 delegate quorum required!
        };

        let repo_id = RepoId::new("aien-spark/synapse").unwrap();
        let genesis_oid = GitOid::compute_blob(b"genesis-commit");
        let commit_v1 = GitOid::compute_blob(b"commit-v1");
        let commit_diverged = GitOid::compute_blob(b"commit-diverged");
        let commit_v2 = GitOid::compute_blob(b"commit-v2");

        let mut engine = CanonicalPromotionEngine::new(doc, None, None).unwrap();

        let cand_v1_gh_merged = PromotionCandidate {
            repo_id: repo_id.clone(),
            changeset_id: Some(ChangesetId([0x11; 32])),
            proposal_base_git_oid: genesis_oid,
            candidate_git_oid: commit_v1,
            github_pr_merged: true,
            verified_at_ms: 1_000,
        };

        // Only 1 delegate (`del1`) has signed `commit_v1` so far
        let mut refs_v1 = BTreeMap::new();
        refs_v1.insert("refs/heads/main".to_string(), commit_v1);
        let sig1_v1 = DelegateSigrefs::sign_refs(&del1_key, &refs_v1);

        // SPLIT-BRAIN CASE 1: GitHub PR is merged (`github_pr_merged: true`),
        // while Radicle 2-of-3 threshold is absent (only 1/2 signed).
        let state_case1 = engine
            .classify_reconciliation(&cand_v1_gh_merged, std::slice::from_ref(&sig1_v1))
            .unwrap();
        assert_eq!(
            state_case1,
            ReconciliationState::SplitBrainGithubMergedWithoutRadicleQuorum {
                candidate_oid: commit_v1,
                verified_count: 1,
                required_threshold: 2,
            }
        );
        let err_case1 = engine
            .verify_and_promote(&cand_v1_gh_merged, std::slice::from_ref(&sig1_v1))
            .unwrap_err();
        assert_eq!(err_case1.code, RefusalCode::RadicleQuorumInsufficient);
        assert!(engine.current_canonical().is_none());

        // SPLIT-BRAIN CASE 2: Radicle 2-of-3 delegate quorum points elsewhere (`commit_diverged`)
        let mut refs_div = BTreeMap::new();
        refs_div.insert("refs/heads/main".to_string(), commit_diverged);
        let sig2_div = DelegateSigrefs::sign_refs(&del2_key, &refs_div);
        let sig3_div = DelegateSigrefs::sign_refs(&del3_key, &refs_div);

        let err_case2 = engine
            .verify_and_promote(&cand_v1_gh_merged, &[sig1_v1.clone(), sig2_div, sig3_div])
            .unwrap_err();
        assert_eq!(err_case2.code, RefusalCode::SplitBrainDivergence);

        // SPLIT-BRAIN CASE 4 (Network Partition): `github_pr_merged: false`, only 1/2 delegates reachable
        let mut cand_v1_partitioned = cand_v1_gh_merged.clone();
        cand_v1_partitioned.github_pr_merged = false;
        let state_case4 = engine
            .classify_reconciliation(&cand_v1_partitioned, std::slice::from_ref(&sig1_v1))
            .unwrap();
        assert_eq!(
            state_case4,
            ReconciliationState::PartitionedAwaitingDelegates {
                reachable_verified: 1,
                required_threshold: 2,
            }
        );
        let err_case4 = engine
            .verify_and_promote(&cand_v1_partitioned, std::slice::from_ref(&sig1_v1))
            .unwrap_err();
        assert_eq!(err_case4.code, RefusalCode::RadicleQuorumInsufficient);

        // Tampered signature refusal check
        let mut bad_sig = sig1_v1.clone();
        bad_sig.signature_blob[0] ^= 0xff;
        let bad_err = engine
            .verify_and_promote(&cand_v1_partitioned, &[bad_sig])
            .unwrap_err();
        assert_eq!(bad_err.code, RefusalCode::RadicleSignatureInvalid);

        // SPLIT-BRAIN CASE 5 (Restored Peer): Partition heals, `del2` signs `commit_v1` -> 2-of-3 quorum satisfied!
        let sig2_v1 = DelegateSigrefs::sign_refs(&del2_key, &refs_v1);
        let promoted_v1 = engine
            .verify_and_promote(&cand_v1_partitioned, &[sig1_v1, sig2_v1])
            .unwrap();
        assert_eq!(promoted_v1.canonical_git_oid, commit_v1);
        assert_eq!(promoted_v1.verified_delegates.len(), 2);

        // SPLIT-BRAIN CASE 3 (Stale Agent Proposal): Now that canonical head is `commit_v1`,
        // an agent proposal still based on `genesis_oid` is refused with `StaleBaseHead`!
        let mut refs_v2 = BTreeMap::new();
        refs_v2.insert("refs/heads/main".to_string(), commit_v2);
        let sig1_v2 = DelegateSigrefs::sign_refs(&del1_key, &refs_v2);
        let sig2_v2 = DelegateSigrefs::sign_refs(&del2_key, &refs_v2);

        let stale_cand = PromotionCandidate {
            repo_id,
            changeset_id: Some(ChangesetId([0x22; 32])),
            proposal_base_git_oid: genesis_oid, // Stale! Current canonical is `commit_v1`
            candidate_git_oid: commit_v2,
            github_pr_merged: false,
            verified_at_ms: 2_000,
        };
        let stale_err = engine
            .verify_and_promote(&stale_cand, &[sig1_v2, sig2_v2])
            .unwrap_err();
        assert_eq!(stale_err.code, RefusalCode::StaleBaseHead);
    }

    #[test]
    fn test_real_host_radicle_storage_sigrefs_verification() {
        // If `/home/drakestapleton/.radicle/storage/z21SQF1DVwRmpxbTMnSiYxXveiRp1` exists on this host,
        // verify our parser and Ed25519 `sigrefs` verifier against the live Radicle storage!
        let real_repo =
            Path::new("/home/drakestapleton/.radicle/storage/z21SQF1DVwRmpxbTMnSiYxXveiRp1");
        if !real_repo.exists() {
            return;
        }
        let (doc, id_oid, sigrefs) = load_radicle_state_from_bare_repo(real_repo).unwrap();
        assert_eq!(doc.threshold, 1);
        assert_eq!(doc.delegates.len(), 1);
        assert_eq!(sigrefs.len(), 1);

        let (verified_did, parsed_refs) = sigrefs[0].verify_and_parse().unwrap();
        assert_eq!(verified_did, doc.delegates[0]);
        let main_oid = *parsed_refs.get("refs/heads/main").unwrap();

        let mut engine = CanonicalPromotionEngine::new(doc, Some(id_oid), None).unwrap();
        let cand = PromotionCandidate {
            repo_id: RepoId::new("aien-spark/aien-sovereign-core").unwrap(),
            changeset_id: None,
            proposal_base_git_oid: GitOid::ZERO,
            candidate_git_oid: main_oid,
            github_pr_merged: false,
            verified_at_ms: 1_700_000_000_000,
        };
        let head = engine.verify_and_promote(&cand, &sigrefs).unwrap();
        assert_eq!(head.canonical_git_oid, main_oid);
        assert_eq!(head.rad_id_commit_oid, id_oid);
    }
}
