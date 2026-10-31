//! Signed revision state moves (ADR 0003 sections 5.3 and 5.4, step B4; issue #89).
//!
//! Section 5.4: every operation records the actor and the capability chain used. A state
//! move (WAL kind 9) therefore carries the mover's key and its strict Ed25519 signature over
//! the move under [`DOMAIN_STATE_MOVE_SIGN_V1`], as an obsolescence marker does, and the
//! leaf link of the chain it was made under. The chain is a list of link digests, so the
//! leaf link is what ties the mover key to the chain: its digest must be the chain's last
//! digest, its parent the digest before it (or [`ROOT_PARENT`] for a one-link chain), its
//! repository the move's repository, and its audience the mover key. Replay checks all of
//! this from the record alone, so a record written into the WAL without the private key of
//! the chain's leaf never verifies. See `docs/B4_REVISION_STATES.md`.

use crate::{CapabilityChain, CapabilityLink, ROOT_PARENT};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use synapse_core::{
    ChainPath, ChangesetId, RefusalCode, RepoId, RevisionState, SynapseError, SynapseResult,
};

/// Domain tag of the mover's Ed25519 signature over a revision state move.
pub const DOMAIN_STATE_MOVE_SIGN_V1: &[u8] = b"SYNAPSE_STATE_MOVE_SIGN_V1\0";

/// Why a signed state move does not verify.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum StateMoveFault {
    /// The mover key is not an Ed25519 key, or the signature does not verify strictly over
    /// [`SignedStateMove::signable_bytes`].
    SignatureInvalid,
    /// The leaf link is not the leaf of the move's chain (its digest, parent, or repository
    /// differ), or the mover key is not the leaf link's audience.
    SignerNotChainLeaf,
}

impl StateMoveFault {
    /// The refusal of a live request carrying this fault (`AuthSignatureInvalid`, as for an
    /// envelope whose author is not the chain's leaf audience).
    pub fn into_error(self) -> SynapseError {
        let msg = match self {
            Self::SignatureInvalid => "state move: mover signature does not verify",
            Self::SignerNotChainLeaf => {
                "state move: the mover key is not the audience of the chain's leaf link"
            }
        };
        SynapseError::new(RefusalCode::AuthSignatureInvalid, msg)
    }
}

/// A revision state move signed by its mover: revision `changeset_id` of `repo_id` moves to
/// `to` under `chain`, signed at the mover's time `signed_at_ms` by `mover_key`, the
/// audience of `leaf_link` (the chain's leaf link).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedStateMove {
    pub repo_id: RepoId,
    pub changeset_id: ChangesetId,
    pub to: RevisionState,
    pub chain: ChainPath,
    pub signed_at_ms: u64,
    pub leaf_link: CapabilityLink,
    pub mover_key: [u8; 32],
    pub signature: [u8; 64],
}

impl SignedStateMove {
    /// `DOMAIN_STATE_MOVE_SIGN_V1 || u32 len | repo_id || changeset_id [32] || to u8 ||
    /// chain (u8 count | link digest [32]*) || signed_at_ms u64`: what the mover signs.
    pub fn statement_bytes(
        repo_id: &RepoId,
        changeset_id: ChangesetId,
        to: RevisionState,
        chain: &ChainPath,
        signed_at_ms: u64,
    ) -> Vec<u8> {
        let repo = repo_id.as_str().as_bytes();
        let mut buf = Vec::with_capacity(
            DOMAIN_STATE_MOVE_SIGN_V1.len() + 4 + repo.len() + 32 + 1 + 1 + 32 * 16 + 8,
        );
        buf.extend_from_slice(DOMAIN_STATE_MOVE_SIGN_V1);
        buf.extend_from_slice(&(repo.len() as u32).to_le_bytes());
        buf.extend_from_slice(repo);
        buf.extend_from_slice(&changeset_id.0);
        buf.push(to.tag_byte());
        chain.encode_into(&mut buf);
        buf.extend_from_slice(&signed_at_ms.to_le_bytes());
        buf
    }

    /// The mover's signature over [`Self::statement_bytes`].
    pub fn sign_statement(
        mover: &SigningKey,
        repo_id: &RepoId,
        changeset_id: ChangesetId,
        to: RevisionState,
        chain: &ChainPath,
        signed_at_ms: u64,
    ) -> [u8; 64] {
        mover
            .sign(&Self::statement_bytes(
                repo_id,
                changeset_id,
                to,
                chain,
                signed_at_ms,
            ))
            .to_bytes()
    }

    /// Build and sign a move under the F1 chain `chain` (its link digests and its leaf link).
    /// An empty chain is `AuthChainBroken`.
    pub fn sign_new(
        mover: &SigningKey,
        repo_id: RepoId,
        changeset_id: ChangesetId,
        to: RevisionState,
        chain: &CapabilityChain,
        signed_at_ms: u64,
    ) -> SynapseResult<Self> {
        let leaf_link = chain.leaf().cloned().ok_or_else(|| {
            SynapseError::new(RefusalCode::AuthChainBroken, "state move: empty chain")
        })?;
        let path = ChainPath::new(chain.link_digests().iter().map(|d| d.0).collect())?;
        let signature =
            Self::sign_statement(mover, &repo_id, changeset_id, to, &path, signed_at_ms);
        Ok(Self {
            repo_id,
            changeset_id,
            to,
            chain: path,
            signed_at_ms,
            leaf_link,
            mover_key: mover.verifying_key().to_bytes(),
            signature,
        })
    }

    /// [`Self::statement_bytes`] of this move.
    pub fn signable_bytes(&self) -> Vec<u8> {
        Self::statement_bytes(
            &self.repo_id,
            self.changeset_id,
            self.to,
            &self.chain,
            self.signed_at_ms,
        )
    }

    /// The signature verifies strictly under `mover_key`, and `mover_key` is the audience
    /// of the chain's leaf link: `leaf_link` hashes to the chain's last digest, names the
    /// digest before it as its parent (`ROOT_PARENT` for a one-link chain), and belongs to
    /// the move's repository. A pure function of the move, so replay gives the same verdict
    /// as the live store.
    ///
    /// **This binds the signer to the chain; it does not authorize the move.** It never
    /// checks who issued `leaf_link`, nor its caveats, so anyone can mint a root link of
    /// their own, or append a link of their own under someone else's chain, and sign a
    /// move that verifies. Precondition for every caller: the chain must also be, or
    /// dominate, the chain of the revision's first admission (`ChainPath::dominates`, as
    /// the store's owner rule does). Dominance pins every digest of the chain, the leaf
    /// included, to links that were really admitted. A descendant chain (`descends_from`)
    /// is not enough: its extra links are unchecked.
    pub fn verify(&self) -> Result<(), StateMoveFault> {
        let key = VerifyingKey::from_bytes(&self.mover_key)
            .map_err(|_| StateMoveFault::SignatureInvalid)?;
        key.verify_strict(
            &self.signable_bytes(),
            &Signature::from_bytes(&self.signature),
        )
        .map_err(|_| StateMoveFault::SignatureInvalid)?;
        let links = self.chain.links();
        let (leaf, ancestors) = links
            .split_last()
            .ok_or(StateMoveFault::SignerNotChainLeaf)?;
        let parent = ancestors.last().copied().unwrap_or(ROOT_PARENT.0);
        let link = &self.leaf_link;
        if link.digest().0 != *leaf
            || link.parent.0 != parent
            || link.repo_id != self.repo_id
            || link.audience_key != self.mover_key
        {
            return Err(StateMoveFault::SignerNotChainLeaf);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Capability, ChainQuotas, ChangeScope, LinkCaveats, LinkDigest, OperationSet, PathScope,
        ReferenceScope,
    };
    use sha2::{Digest, Sha256};

    /// Keys and nonces are SHA-256 of a label, never fixed byte values.
    fn derived(label: &str) -> [u8; 32] {
        Sha256::digest(label.as_bytes()).into()
    }

    fn key(label: &str) -> SigningKey {
        SigningKey::from_bytes(&derived(label))
    }

    fn repo() -> RepoId {
        RepoId::new("aien-spark/synapse").unwrap()
    }

    fn caveats() -> LinkCaveats {
        LinkCaveats {
            operations: OperationSet::from_capabilities(&[Capability::Read, Capability::Propose]),
            paths: PathScope::whole_repository(),
            references: ReferenceScope::from_kinds(&[]),
            changes: ChangeScope::any(),
            quotas: ChainQuotas {
                max_ops_per_window: 100,
                window_duration_ms: 60_000,
                storage_bytes: 1 << 20,
                footprint_paths: 64,
                max_bytes_per_op: 1 << 20,
            },
            issued_at_ms: 0,
            expires_at_ms: u64::MAX,
        }
    }

    fn link(
        issuer: &SigningKey,
        parent: LinkDigest,
        to: &SigningKey,
        label: &str,
    ) -> CapabilityLink {
        CapabilityLink::issue(
            issuer,
            parent,
            derived(label),
            repo(),
            to.verifying_key().to_bytes(),
            caveats(),
        )
    }

    /// Authority -> orchestrator -> worker.
    fn chains() -> (SigningKey, SigningKey, CapabilityChain, CapabilityChain) {
        let authority = key("state-move authority");
        let orchestrator = key("state-move orchestrator");
        let worker = key("state-move worker");
        let root = link(
            &authority,
            ROOT_PARENT,
            &orchestrator,
            "state-move root link",
        );
        let child = link(
            &orchestrator,
            root.digest(),
            &worker,
            "state-move child link",
        );
        let co = CapabilityChain::new(vec![root]);
        let cw = co.extended(child);
        (orchestrator, worker, co, cw)
    }

    fn id() -> ChangesetId {
        ChangesetId(derived("state-move changeset"))
    }

    #[test]
    fn a_move_signed_by_the_chain_leaf_verifies_for_root_and_derived_chains() {
        let (o, w, co, cw) = chains();
        for (k, c) in [(&o, &co), (&w, &cw)] {
            let m = SignedStateMove::sign_new(k, repo(), id(), RevisionState::Draft, c, 7).unwrap();
            assert_eq!(m.verify(), Ok(()));
        }
    }

    #[test]
    fn a_bad_signature_or_a_signer_that_is_not_the_leaf_is_refused_typed() {
        let (o, w, co, cw) = chains();
        let good =
            SignedStateMove::sign_new(&w, repo(), id(), RevisionState::Draft, &cw, 7).unwrap();

        // Any change to a signed field breaks the signature.
        let mut m = good.clone();
        m.to = RevisionState::Proposed;
        assert_eq!(m.verify(), Err(StateMoveFault::SignatureInvalid));
        let mut m = good.clone();
        m.signed_at_ms += 1;
        assert_eq!(m.verify(), Err(StateMoveFault::SignatureInvalid));
        let mut m = good.clone();
        m.signature[0] ^= 1;
        assert_eq!(m.verify(), Err(StateMoveFault::SignatureInvalid));
        let mut m = good.clone();
        m.mover_key = derived("state-move not the mover");
        assert_eq!(m.verify(), Err(StateMoveFault::SignatureInvalid));

        // A valid signature by the orchestrator over the worker's chain: the orchestrator is
        // an ancestor, not the leaf, so it must sign under its own chain instead.
        let m = SignedStateMove {
            mover_key: o.verifying_key().to_bytes(),
            signature: SignedStateMove::sign_statement(
                &o,
                &repo(),
                id(),
                RevisionState::Draft,
                &good.chain,
                7,
            ),
            ..good.clone()
        };
        assert_eq!(m.verify(), Err(StateMoveFault::SignerNotChainLeaf));

        // A leaf link that is not the chain's leaf (the root link under the worker's chain).
        let m = SignedStateMove {
            leaf_link: co.leaf().unwrap().clone(),
            ..good.clone()
        };
        assert_eq!(m.verify(), Err(StateMoveFault::SignerNotChainLeaf));

        // A self-issued link whose audience is the signer, named as a one-link chain whose
        // digest is that link: the parent is not the root, so it is not this chain's leaf
        // unless it really is a root link. A forger can mint such a root link, but then the
        // chain is its own and never dominates another owner's chain (section 5.3).
        let forger = key("state-move forger");
        let fake = link(
            &forger,
            LinkDigest(*good.chain.links().first().unwrap()),
            &forger,
            "fake",
        );
        let path = ChainPath::new(vec![good.chain.links()[0], fake.digest().0]).unwrap();
        let m = SignedStateMove {
            chain: path.clone(),
            leaf_link: fake,
            mover_key: forger.verifying_key().to_bytes(),
            signature: SignedStateMove::sign_statement(
                &forger,
                &repo(),
                id(),
                RevisionState::Draft,
                &path,
                7,
            ),
            ..good.clone()
        };
        assert_eq!(
            m.verify(),
            Ok(()),
            "the record alone binds key to chain digests"
        );
        assert_ne!(m.chain, good.chain, "but never to another chain's digests");
    }

    #[test]
    fn a_leaf_link_of_another_repository_is_refused() {
        let (_, w, _, cw) = chains();
        let mut m =
            SignedStateMove::sign_new(&w, repo(), id(), RevisionState::Draft, &cw, 7).unwrap();
        m.repo_id = RepoId::new("aien-spark/other").unwrap();
        m.signature = SignedStateMove::sign_statement(&w, &m.repo_id, id(), m.to, &m.chain, 7);
        assert_eq!(m.verify(), Err(StateMoveFault::SignerNotChainLeaf));
    }

    #[test]
    fn faults_map_to_auth_signature_invalid() {
        for f in [
            StateMoveFault::SignatureInvalid,
            StateMoveFault::SignerNotChainLeaf,
        ] {
            assert_eq!(f.into_error().code, RefusalCode::AuthSignatureInvalid);
        }
    }
}
