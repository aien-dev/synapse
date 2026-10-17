//! Revision state machine (ADR 0003 section 5.3, section 9 step B4).
//!
//! A revision is `Private` (visible only to its owner's delegation chain) or `Draft` (visible
//! within `Read` scope), then `Proposed`, then `Verified` (every claim and required action
//! discharged on its exact tree), then `Canonical` (promoted by quorum, immutable). States
//! never move backwards: replacing a revision creates a new revision and an obsolescence
//! marker, never an earlier state. See `docs/B4_REVISION_STATES.md`.
//!
//! The only moves are the five forward edges of [`RevisionState::may_move_to`]. Which of them
//! a caller may take depends on who asks: the owner chain may move a revision to `Draft` or
//! `Proposed` ([`RevisionState::check_owner_move`]); `Verified` needs claims (step B3) and
//! required-action receipts (step E1) discharged on the exact tree; `Canonical` is reached
//! only through the promotion queue (step E2), so every other move to it is refused with
//! `CanonicalOutsidePromotionQueue`.

use crate::{RefusalCode, SynapseError, SynapseResult};

/// Where a revision stands. The declaration order is the one forward order, so `Ord`
/// compares states by [`RevisionState::rank`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RevisionState {
    /// Visible only to its owner's delegation chain: the keys that submitted it and the keys
    /// their grants descend from (need N14).
    Private,
    /// Visible within `Read` scope.
    Draft,
    /// Put forward for verification and promotion.
    Proposed,
    /// Every claim and required action discharged on its exact tree.
    Verified,
    /// Promoted by quorum through the promotion queue; immutable.
    Canonical,
}

impl RevisionState {
    /// Every state, in forward order.
    pub const ALL: [Self; 5] = [
        Self::Private,
        Self::Draft,
        Self::Proposed,
        Self::Verified,
        Self::Canonical,
    ];

    /// Position in the forward order (`Private` = 0 .. `Canonical` = 4).
    pub fn rank(self) -> u8 {
        match self {
            Self::Private => 0,
            Self::Draft => 1,
            Self::Proposed => 2,
            Self::Verified => 3,
            Self::Canonical => 4,
        }
    }

    /// Binary tag of the state (1..=5); 0 and anything above 5 are not states.
    pub fn tag_byte(self) -> u8 {
        self.rank() + 1
    }

    /// The state with binary tag `tag`, if any.
    pub fn from_tag_byte(tag: u8) -> Option<Self> {
        Self::ALL.get(usize::from(tag.checked_sub(1)?)).copied()
    }

    /// True for the five edges of the state machine: `Private -> Draft`,
    /// `Private -> Proposed`, `Draft -> Proposed`, `Proposed -> Verified`, and
    /// `Verified -> Canonical`. Every edge strictly raises the rank; nothing else is a move.
    pub fn may_move_to(self, to: Self) -> bool {
        matches!(
            (self, to),
            (Self::Private, Self::Draft)
                | (Self::Private, Self::Proposed)
                | (Self::Draft, Self::Proposed)
                | (Self::Proposed, Self::Verified)
                | (Self::Verified, Self::Canonical)
        )
    }

    /// The order rule: `RevisionStateMoveInvalid` for any move that is not an edge
    /// (backwards, in place, or skipping a state).
    pub fn check_move(self, to: Self) -> SynapseResult<()> {
        if self.may_move_to(to) {
            return Ok(());
        }
        let why = if to < self {
            "backwards"
        } else if to == self {
            "in place"
        } else {
            "skipping a state"
        };
        Err(SynapseError::new(
            RefusalCode::RevisionStateMoveInvalid,
            format!("revision state move {self:?} -> {to:?} is {why}"),
        ))
    }

    /// A move asked for by the revision's owner chain. A move to `Canonical` is refused
    /// with `CanonicalOutsidePromotionQueue` whatever the current state; a move to
    /// `Verified` is refused with `RevisionStateMoveInvalid` (it is recorded only when the
    /// claims and required actions are discharged, steps B3 and E1); otherwise the order
    /// rule of [`RevisionState::check_move`] applies.
    pub fn check_owner_move(self, to: Self) -> SynapseResult<()> {
        match to {
            Self::Canonical => Err(SynapseError::new(
                RefusalCode::CanonicalOutsidePromotionQueue,
                format!(
                    "revision state move {self:?} -> Canonical: canonical moves only through the promotion queue"
                ),
            )),
            Self::Verified => Err(SynapseError::new(
                RefusalCode::RevisionStateMoveInvalid,
                format!(
                    "revision state move {self:?} -> Verified: needs every claim and required action discharged on the exact tree, which the owner chain cannot assert"
                ),
            )),
            _ => self.check_move(to),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Seeded SplitMix64 (no new dependency), as in the F1 property tests.
    struct SplitMix64(u64);

    impl SplitMix64 {
        fn next(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        }

        fn state(&mut self) -> RevisionState {
            RevisionState::ALL[(self.next() % 5) as usize]
        }
    }

    #[test]
    fn b4_state_tags_round_trip_and_unknown_tags_are_not_states() {
        for s in RevisionState::ALL {
            assert_eq!(RevisionState::from_tag_byte(s.tag_byte()), Some(s));
        }
        assert_eq!(RevisionState::from_tag_byte(0), None);
        for tag in 6..=u8::MAX {
            assert_eq!(RevisionState::from_tag_byte(tag), None);
        }
    }

    #[test]
    fn b4_every_allowed_move_raises_the_rank_and_every_other_pair_is_refused() {
        let mut allowed = 0;
        for from in RevisionState::ALL {
            for to in RevisionState::ALL {
                match from.check_move(to) {
                    Ok(()) => {
                        allowed += 1;
                        assert!(to.rank() > from.rank(), "{from:?} -> {to:?}");
                    }
                    Err(e) => assert_eq!(e.code, RefusalCode::RevisionStateMoveInvalid),
                }
                if to.rank() <= from.rank() {
                    assert!(from.check_move(to).is_err(), "{from:?} -> {to:?}");
                    assert!(from.check_owner_move(to).is_err(), "{from:?} -> {to:?}");
                }
            }
        }
        assert_eq!(allowed, 5, "exactly the five edges of section 5.3");
    }

    #[test]
    fn b4_owner_moves_never_reach_verified_or_canonical() {
        for from in RevisionState::ALL {
            assert_eq!(
                from.check_owner_move(RevisionState::Canonical)
                    .unwrap_err()
                    .code,
                RefusalCode::CanonicalOutsidePromotionQueue
            );
            assert_eq!(
                from.check_owner_move(RevisionState::Verified)
                    .unwrap_err()
                    .code,
                RefusalCode::RevisionStateMoveInvalid
            );
        }
        RevisionState::Private
            .check_owner_move(RevisionState::Draft)
            .unwrap();
        RevisionState::Private
            .check_owner_move(RevisionState::Proposed)
            .unwrap();
        RevisionState::Draft
            .check_owner_move(RevisionState::Proposed)
            .unwrap();
    }

    /// Property: over random sequences of attempted moves (any target, owner or order rule),
    /// applying only the accepted ones, the rank never decreases and owner moves never reach
    /// `Verified` or `Canonical`.
    #[test]
    fn b4_property_random_move_sequences_never_move_backwards() {
        let mut rng = SplitMix64(0xB4_5EED);
        for _case in 0..2_000 {
            let mut owner_only = rng.next().is_multiple_of(2);
            let mut state = if rng.next().is_multiple_of(2) {
                RevisionState::Private
            } else {
                RevisionState::Draft
            };
            for _ in 0..32 {
                let to = rng.state();
                let before = state;
                let result = if owner_only {
                    state.check_owner_move(to)
                } else {
                    state.check_move(to)
                };
                if result.is_ok() {
                    state = to;
                }
                assert!(state.rank() >= before.rank(), "{before:?} -> {state:?}");
                if owner_only {
                    assert!(state <= RevisionState::Proposed, "owner reached {state:?}");
                }
                if rng.next().is_multiple_of(8) {
                    owner_only = !owner_only && state <= RevisionState::Proposed;
                }
            }
        }
    }
}
