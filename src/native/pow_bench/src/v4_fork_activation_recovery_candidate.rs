//! CP-0226 isolated fork-activation recovery and reorg-boundary guard.
//!
//! This is a deterministic recovery classifier, not a durable store or block fork-choice
//! engine. It requires a separately verified FAT1 record and an external monotonic floor.
//! All persisted-state/failure inputs in tests are synthetic. No production migration,
//! restart recovery, or consensus callsite is added by this candidate.
use crate::v4_fat1_trust_candidate::{Fat1Record, TrustedFat1Floor, VerifiedFat1};
use sha2::{Digest, Sha256};

const ACTIVATION_ID_DOMAIN: &[u8] = b"AIN1-V4-FORK-ACTIVATION-ID-V1\0";

fn hash_parts(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for part in parts {
        h.update(part);
    }
    h.finalize().into()
}
fn is_zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActivationTrust {
    pub record: Fat1Record,
    pub record_id: [u8; 32],
    pub envelope_id: [u8; 32],
    pub predecessor_record_id: [u8; 32],
}
impl ActivationTrust {
    pub fn from_verified(verified: &VerifiedFat1) -> Self {
        Self {
            record: verified.record.clone(),
            record_id: verified.record_id,
            envelope_id: verified.envelope_id,
            predecessor_record_id: verified.predecessor_record_id,
        }
    }
    pub fn activation_block_id(&self) -> [u8; 32] {
        hash_parts(&[
            ACTIVATION_ID_DOMAIN,
            &self.record.network_id,
            &self.record.manifest_id,
            &self.record.migration_plan_id,
            &self.record.trust_epoch.to_be_bytes(),
            &self.record_id,
            &self.record.activation_height.to_be_bytes(),
            &self.record.parent_block_id,
            &self.record.expected_post_stv4_root,
        ])
    }
    pub fn matches_target_floor(&self, floor: &TrustedFat1Floor) -> bool {
        floor.network_id == self.record.network_id
            && floor.trust_epoch == self.record.trust_epoch
            && floor.record_id == self.record_id
            && floor.envelope_id == self.envelope_id
    }
    pub fn matches_predecessor_floor(&self, floor: &TrustedFat1Floor) -> bool {
        floor.network_id == self.record.network_id
            && self.record.trust_epoch.checked_sub(1) == Some(floor.trust_epoch)
            && floor.record_id == self.predecessor_record_id
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MigrationBoundaryArtifact {
    pub network_id: [u8; 32],
    pub manifest_id: [u8; 32],
    pub migration_plan_id: [u8; 32],
    pub trust_record_id: [u8; 32],
    pub activation_height: u64,
    pub parent_block_id: [u8; 32],
    pub pre_stv3_root: [u8; 32],
    pub post_stv4_root: [u8; 32],
}
impl MigrationBoundaryArtifact {
    pub fn matches(&self, trust: &ActivationTrust) -> bool {
        let r = &trust.record;
        self.network_id == r.network_id
            && self.manifest_id == r.manifest_id
            && self.migration_plan_id == r.migration_plan_id
            && self.trust_record_id == trust.record_id
            && self.activation_height == r.activation_height
            && self.parent_block_id == r.parent_block_id
            && self.pre_stv3_root == r.pre_stv3_root
            && self.post_stv4_root == r.expected_post_stv4_root
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MigrationCommitIntent {
    pub from_height: u64,
    pub from_root: [u8; 32],
    pub to_height: u64,
    pub to_root: [u8; 32],
    pub target_trust_epoch: u64,
    pub target_trust_record_id: [u8; 32],
    /// Represents strict schema/checksum/semantic validation of the durable intent envelope.
    pub envelope_valid: bool,
}
impl MigrationCommitIntent {
    pub fn for_trust(trust: &ActivationTrust) -> Self {
        Self {
            from_height: trust.record.activation_height - 1,
            from_root: trust.record.pre_stv3_root,
            to_height: trust.record.activation_height,
            to_root: trust.record.expected_post_stv4_root,
            target_trust_epoch: trust.record.trust_epoch,
            target_trust_record_id: trust.record_id,
            envelope_valid: true,
        }
    }
    pub fn matches(&self, trust: &ActivationTrust) -> bool {
        self.envelope_valid
            && self.from_height.checked_add(1) == Some(self.to_height)
            && self.from_height.checked_add(1) == Some(trust.record.activation_height)
            && self.from_root == trust.record.pre_stv3_root
            && self.to_height == trust.record.activation_height
            && self.to_root == trust.record.expected_post_stv4_root
            && self.target_trust_epoch == trust.record.trust_epoch
            && self.target_trust_record_id == trust.record_id
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LocalActivationState {
    LegacyParent {
        height: u64,
        block_id: [u8; 32],
        state_root: [u8; 32],
    },
    Boundary {
        network_id: [u8; 32],
        manifest_id: [u8; 32],
        trust_record_id: [u8; 32],
        height: u64,
        activation_block_id: [u8; 32],
        state_root: [u8; 32],
    },
    Descendant {
        network_id: [u8; 32],
        manifest_id: [u8; 32],
        trust_record_id: [u8; 32],
        activation_height: u64,
        activation_ancestor_id: [u8; 32],
        activation_state_root: [u8; 32],
        tip_height: u64,
        tip_block_id: [u8; 32],
        tip_state_root: [u8; 32],
    },
    Conflict {
        height: u64,
        state_root: [u8; 32],
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecoveryDecision {
    ContinueLegacyBeforeActivation,
    DiscardUncommittedPrepareAndKeepLegacy,
    ClearUnanchoredIntentAndKeepLegacy,
    RollForwardPreparedBoundaryAfterAnchorAdvance,
    AcceptCommittedBoundary,
    AcceptCommittedBoundaryAndClearIntent,
    AcceptAnchoredDescendant,
    AcceptAnchoredDescendantAndClearIntent,
    QuarantineTrustFloorUnavailable,
    QuarantineFloorNetworkMismatch,
    QuarantineFloorDoesNotMatchCurrentOrPredecessor,
    QuarantineLegacyParentMismatch,
    QuarantinePreparedBoundaryMismatch,
    QuarantineIntentMismatch,
    QuarantineAnchorAdvancedWithoutPreparedBoundary,
    QuarantineLocalStateAheadOfTrustFloor,
    QuarantineBoundaryStateMismatch,
    QuarantineDescendantCrossesActivationFence,
    QuarantineConflictingLocalState,
}

fn local_is_exact_legacy(local: &LocalActivationState, trust: &ActivationTrust) -> bool {
    matches!(local, LocalActivationState::LegacyParent { height, block_id, state_root }
        if *height == trust.record.activation_height - 1
        && *block_id == trust.record.parent_block_id
        && *state_root == trust.record.pre_stv3_root)
}
fn local_is_exact_boundary(local: &LocalActivationState, trust: &ActivationTrust) -> bool {
    matches!(local, LocalActivationState::Boundary {
        network_id, manifest_id, trust_record_id, height, activation_block_id, state_root
    } if *network_id == trust.record.network_id
      && *manifest_id == trust.record.manifest_id
      && *trust_record_id == trust.record_id
      && *height == trust.record.activation_height
      && *activation_block_id == trust.activation_block_id()
      && *state_root == trust.record.expected_post_stv4_root)
}
fn local_is_exact_descendant(local: &LocalActivationState, trust: &ActivationTrust) -> bool {
    matches!(local, LocalActivationState::Descendant {
        network_id, manifest_id, trust_record_id, activation_height,
        activation_ancestor_id, activation_state_root, tip_height, tip_block_id, tip_state_root
    } if *network_id == trust.record.network_id
      && *manifest_id == trust.record.manifest_id
      && *trust_record_id == trust.record_id
      && *activation_height == trust.record.activation_height
      && *activation_ancestor_id == trust.activation_block_id()
      && *activation_state_root == trust.record.expected_post_stv4_root
      && *tip_height > trust.record.activation_height
      && !is_zero(tip_block_id)
      && !is_zero(tip_state_root))
}

/// Reconcile crash windows around the order: prepared boundary durable -> intent durable ->
/// external trust-floor CAS -> local state install -> clear intent. No local checksum can
/// substitute for the external monotonic trust floor. Unknown evidence quarantines.
pub fn recover_activation(
    trust: &ActivationTrust,
    floor: Option<&TrustedFat1Floor>,
    local: &LocalActivationState,
    prepared: Option<&MigrationBoundaryArtifact>,
    intent: Option<&MigrationCommitIntent>,
) -> RecoveryDecision {
    let Some(floor) = floor else {
        return RecoveryDecision::QuarantineTrustFloorUnavailable;
    };
    if floor.network_id != trust.record.network_id {
        return RecoveryDecision::QuarantineFloorNetworkMismatch;
    }

    let at_target = trust.matches_target_floor(floor);
    let at_predecessor = trust.matches_predecessor_floor(floor);
    if !at_target && !at_predecessor {
        return RecoveryDecision::QuarantineFloorDoesNotMatchCurrentOrPredecessor;
    }

    let prepared_matches = match prepared {
        Some(item) if item.matches(trust) => true,
        Some(_) => return RecoveryDecision::QuarantinePreparedBoundaryMismatch,
        None => false,
    };
    let intent_matches = match intent {
        Some(item) if item.matches(trust) => true,
        Some(_) => return RecoveryDecision::QuarantineIntentMismatch,
        None => false,
    };

    if local_is_exact_legacy(local, trust) {
        if at_target {
            if prepared_matches && intent_matches {
                return RecoveryDecision::RollForwardPreparedBoundaryAfterAnchorAdvance;
            }
            return RecoveryDecision::QuarantineAnchorAdvancedWithoutPreparedBoundary;
        }
        return match (prepared_matches, intent_matches) {
            (false, false) => RecoveryDecision::ContinueLegacyBeforeActivation,
            (true, false) => RecoveryDecision::DiscardUncommittedPrepareAndKeepLegacy,
            (false, true) | (true, true) => RecoveryDecision::ClearUnanchoredIntentAndKeepLegacy,
        };
    }
    if local_is_exact_boundary(local, trust) {
        if !at_target {
            return RecoveryDecision::QuarantineLocalStateAheadOfTrustFloor;
        }
        return if intent_matches {
            RecoveryDecision::AcceptCommittedBoundaryAndClearIntent
        } else if intent.is_none() && prepared_matches {
            RecoveryDecision::AcceptCommittedBoundary
        } else if intent.is_none() && prepared.is_none() {
            RecoveryDecision::AcceptCommittedBoundary
        } else {
            RecoveryDecision::QuarantineIntentMismatch
        };
    }
    if local_is_exact_descendant(local, trust) {
        if !at_target {
            return RecoveryDecision::QuarantineLocalStateAheadOfTrustFloor;
        }
        return if intent_matches {
            RecoveryDecision::AcceptAnchoredDescendantAndClearIntent
        } else if intent.is_none() && (prepared.is_none() || prepared_matches) {
            RecoveryDecision::AcceptAnchoredDescendant
        } else {
            RecoveryDecision::QuarantineIntentMismatch
        };
    }
    match local {
        LocalActivationState::Conflict { .. } => RecoveryDecision::QuarantineConflictingLocalState,
        LocalActivationState::Boundary { .. } => RecoveryDecision::QuarantineBoundaryStateMismatch,
        LocalActivationState::Descendant { tip_height, .. }
            if *tip_height < trust.record.activation_height =>
        {
            RecoveryDecision::QuarantineDescendantCrossesActivationFence
        }
        LocalActivationState::Descendant { .. } => {
            RecoveryDecision::QuarantineBoundaryStateMismatch
        }
        LocalActivationState::LegacyParent { .. } => {
            RecoveryDecision::QuarantineLegacyParentMismatch
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BranchEvidence {
    pub network_id: [u8; 32],
    pub manifest_id: [u8; 32],
    pub trust_record_id: [u8; 32],
    pub activation_height: u64,
    pub activation_ancestor_id: [u8; 32],
    pub activation_state_root: [u8; 32],
    pub tip_height: u64,
    pub tip_block_id: [u8; 32],
    pub tip_state_root: [u8; 32],
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReorgBoundaryError {
    CrossesBelowActivationHeight,
    WrongNetworkOrManifest,
    WrongTrustRecord,
    WrongActivationAncestor,
    WrongActivationStateRoot,
    InvalidTip,
    NoncanonicalBoundaryBlock,
}

/// Checks only migration/activation continuity, not cumulative work, PoW or branch selection.
/// A reorg above H is allowed only when its height-H ancestor remains the exact trusted boundary.
pub fn validate_reorg_boundary(
    trust: &ActivationTrust,
    candidate: &BranchEvidence,
) -> Result<(), ReorgBoundaryError> {
    if candidate.tip_height < trust.record.activation_height {
        return Err(ReorgBoundaryError::CrossesBelowActivationHeight);
    }
    if candidate.network_id != trust.record.network_id
        || candidate.manifest_id != trust.record.manifest_id
    {
        return Err(ReorgBoundaryError::WrongNetworkOrManifest);
    }
    if candidate.trust_record_id != trust.record_id {
        return Err(ReorgBoundaryError::WrongTrustRecord);
    }
    if candidate.activation_height != trust.record.activation_height
        || candidate.activation_ancestor_id != trust.activation_block_id()
    {
        return Err(ReorgBoundaryError::WrongActivationAncestor);
    }
    if candidate.activation_state_root != trust.record.expected_post_stv4_root {
        return Err(ReorgBoundaryError::WrongActivationStateRoot);
    }
    if is_zero(&candidate.tip_block_id) || is_zero(&candidate.tip_state_root) {
        return Err(ReorgBoundaryError::InvalidTip);
    }
    if candidate.tip_height == trust.record.activation_height
        && (candidate.tip_block_id != trust.activation_block_id()
            || candidate.tip_state_root != trust.record.expected_post_stv4_root)
    {
        return Err(ReorgBoundaryError::NoncanonicalBoundaryBlock);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v4_fat1_trust_candidate::{
        verify_fat1, Fat1SignedEnvelope, MlDsa65Verifier, PinnedFat1Authority, FAS1_BYTES,
        ML_DSA_65_PUBLIC_KEY_BYTES, ML_DSA_65_SIGNATURE_BYTES,
    };
    use ed25519_dalek::{Signer, SigningKey};

    const FAT1_FIXTURE: &[u8] = include_bytes!("../../../../simulations/cp0224_fat1_record.bin");

    struct TestPq {
        key: [u8; ML_DSA_65_PUBLIC_KEY_BYTES],
        sig: [u8; ML_DSA_65_SIGNATURE_BYTES],
        digest: [u8; 32],
    }
    impl MlDsa65Verifier for TestPq {
        fn verify(
            &self,
            key: &[u8; ML_DSA_65_PUBLIC_KEY_BYTES],
            digest: &[u8; 32],
            sig: &[u8; ML_DSA_65_SIGNATURE_BYTES],
        ) -> bool {
            *key == self.key && *digest == self.digest && *sig == self.sig
        }
    }
    fn trusted() -> (
        ActivationTrust,
        TrustedFat1Floor,
        Vec<u8>,
        PinnedFat1Authority,
        TestPq,
    ) {
        let rec = Fat1Record::decode(FAT1_FIXTURE).unwrap();
        let ed = SigningKey::from_bytes(&[0x61; 32]);
        let authority = PinnedFat1Authority {
            ed25519_public_key: ed.verifying_key().to_bytes(),
            mldsa65_public_key: [0x62; ML_DSA_65_PUBLIC_KEY_BYTES],
        };
        let keyset = authority.keyset_id().unwrap();
        let predecessor = [0; 32];
        let digest = rec.signing_digest(&predecessor, &keyset).unwrap();
        let pq_sig = [0x63; ML_DSA_65_SIGNATURE_BYTES];
        let pq = TestPq {
            key: authority.mldsa65_public_key,
            sig: pq_sig,
            digest,
        };
        let env = Fat1SignedEnvelope {
            record: rec.clone(),
            predecessor_record_id: predecessor,
            authority_keyset_id: keyset,
            ed25519_signature: ed.sign(&digest).to_bytes(),
            mldsa65_signature: pq_sig,
        };
        let bytes = env.encode().unwrap();
        assert_eq!(bytes.len(), FAS1_BYTES);
        let floor0 = TrustedFat1Floor::initial(rec.network_id).unwrap();
        let expected = crate::v4_fat1_trust_candidate::ExpectedForkContext {
            network_id: rec.network_id,
            manifest_id: rec.manifest_id,
            migration_plan_id: rec.migration_plan_id,
            activation_height: rec.activation_height,
            parent_block_id: rec.parent_block_id,
            pre_stv3_root: rec.pre_stv3_root,
            migration_algorithm_id: rec.migration_algorithm_id,
            migration_policy_hash: rec.migration_policy_hash,
            expected_post_stv4_root: rec.expected_post_stv4_root,
        };
        let verified = verify_fat1(&env, &authority, &pq, &expected, &floor0).unwrap();
        let trust = ActivationTrust::from_verified(&verified);
        (trust, floor0, bytes, authority, pq)
    }
    fn prepared(trust: &ActivationTrust) -> MigrationBoundaryArtifact {
        MigrationBoundaryArtifact {
            network_id: trust.record.network_id,
            manifest_id: trust.record.manifest_id,
            migration_plan_id: trust.record.migration_plan_id,
            trust_record_id: trust.record_id,
            activation_height: trust.record.activation_height,
            parent_block_id: trust.record.parent_block_id,
            pre_stv3_root: trust.record.pre_stv3_root,
            post_stv4_root: trust.record.expected_post_stv4_root,
        }
    }
    fn intent(trust: &ActivationTrust) -> MigrationCommitIntent {
        MigrationCommitIntent::for_trust(trust)
    }
    fn legacy(trust: &ActivationTrust) -> LocalActivationState {
        LocalActivationState::LegacyParent {
            height: trust.record.activation_height - 1,
            block_id: trust.record.parent_block_id,
            state_root: trust.record.pre_stv3_root,
        }
    }
    fn boundary(trust: &ActivationTrust) -> LocalActivationState {
        LocalActivationState::Boundary {
            network_id: trust.record.network_id,
            manifest_id: trust.record.manifest_id,
            trust_record_id: trust.record_id,
            height: trust.record.activation_height,
            activation_block_id: trust.activation_block_id(),
            state_root: trust.record.expected_post_stv4_root,
        }
    }
    fn descendant(trust: &ActivationTrust, height: u64, tip: u8, root: u8) -> LocalActivationState {
        LocalActivationState::Descendant {
            network_id: trust.record.network_id,
            manifest_id: trust.record.manifest_id,
            trust_record_id: trust.record_id,
            activation_height: trust.record.activation_height,
            activation_ancestor_id: trust.activation_block_id(),
            activation_state_root: trust.record.expected_post_stv4_root,
            tip_height: height,
            tip_block_id: [tip; 32],
            tip_state_root: [root; 32],
        }
    }
    fn advanced_floor(trust: &ActivationTrust) -> TrustedFat1Floor {
        let envelope_id = hash_parts(&[b"AIN1-FAS1-ENVELOPE-ID-V1\0", &trusted().2]);
        TrustedFat1Floor {
            network_id: trust.record.network_id,
            trust_epoch: trust.record.trust_epoch,
            record_id: trust.record_id,
            envelope_id,
        }
    }
    fn old_floor(trust: &ActivationTrust) -> TrustedFat1Floor {
        TrustedFat1Floor {
            network_id: trust.record.network_id,
            trust_epoch: trust.record.trust_epoch - 1,
            record_id: trust.predecessor_record_id,
            envelope_id: [0; 32],
        }
    }

    #[test]
    fn crash_matrix_reconciles_only_old_or_new_anchored_state() {
        let (t, _, _, _, _) = trusted();
        let old = old_floor(&t);
        let new = advanced_floor(&t);
        let p = prepared(&t);
        let i = intent(&t);
        let l = legacy(&t);
        let b = boundary(&t);

        assert_eq!(
            recover_activation(&t, Some(&old), &l, None, None),
            RecoveryDecision::ContinueLegacyBeforeActivation
        );
        assert_eq!(
            recover_activation(&t, Some(&old), &l, Some(&p), None),
            RecoveryDecision::DiscardUncommittedPrepareAndKeepLegacy
        );
        assert_eq!(
            recover_activation(&t, Some(&old), &l, Some(&p), Some(&i)),
            RecoveryDecision::ClearUnanchoredIntentAndKeepLegacy
        );
        assert_eq!(
            recover_activation(&t, Some(&new), &l, Some(&p), Some(&i)),
            RecoveryDecision::RollForwardPreparedBoundaryAfterAnchorAdvance
        );
        assert_eq!(
            recover_activation(&t, Some(&new), &b, Some(&p), Some(&i)),
            RecoveryDecision::AcceptCommittedBoundaryAndClearIntent
        );
        assert_eq!(
            recover_activation(&t, Some(&new), &b, None, None),
            RecoveryDecision::AcceptCommittedBoundary
        );
        assert_eq!(
            recover_activation(&t, None, &l, None, None),
            RecoveryDecision::QuarantineTrustFloorUnavailable
        );
        assert_eq!(
            recover_activation(&t, Some(&old), &b, None, None),
            RecoveryDecision::QuarantineLocalStateAheadOfTrustFloor
        );
        assert_eq!(
            recover_activation(&t, Some(&new), &l, None, None),
            RecoveryDecision::QuarantineAnchorAdvancedWithoutPreparedBoundary
        );
    }

    #[test]
    fn reorg_above_activation_is_allowed_only_with_exact_boundary_ancestor() {
        let (t, _, _, _, _) = trusted();
        let activation_id = t.activation_block_id();
        let current = BranchEvidence {
            network_id: t.record.network_id,
            manifest_id: t.record.manifest_id,
            trust_record_id: t.record_id,
            activation_height: t.record.activation_height,
            activation_ancestor_id: activation_id,
            activation_state_root: t.record.expected_post_stv4_root,
            tip_height: t.record.activation_height + 20,
            tip_block_id: [0x71; 32],
            tip_state_root: [0x72; 32],
        };
        let mut alternate = current.clone();
        alternate.tip_block_id = [0x81; 32];
        alternate.tip_state_root = [0x82; 32];
        assert!(validate_reorg_boundary(&t, &current).is_ok());
        assert!(validate_reorg_boundary(&t, &alternate).is_ok());

        let mut bad = alternate.clone();
        bad.tip_height = t.record.activation_height - 1;
        assert_eq!(
            validate_reorg_boundary(&t, &bad),
            Err(ReorgBoundaryError::CrossesBelowActivationHeight)
        );
        let mut bad = alternate.clone();
        bad.activation_ancestor_id[0] ^= 1;
        assert_eq!(
            validate_reorg_boundary(&t, &bad),
            Err(ReorgBoundaryError::WrongActivationAncestor)
        );
        let mut bad = alternate.clone();
        bad.activation_state_root[0] ^= 1;
        assert_eq!(
            validate_reorg_boundary(&t, &bad),
            Err(ReorgBoundaryError::WrongActivationStateRoot)
        );
        let mut bad = alternate.clone();
        bad.trust_record_id[0] ^= 1;
        assert_eq!(
            validate_reorg_boundary(&t, &bad),
            Err(ReorgBoundaryError::WrongTrustRecord)
        );
        let mut bad = alternate;
        bad.network_id[0] ^= 1;
        assert_eq!(
            validate_reorg_boundary(&t, &bad),
            Err(ReorgBoundaryError::WrongNetworkOrManifest)
        );
    }

    #[test]
    fn wrong_prepare_intent_and_conflicting_local_state_quarantine() {
        let (t, _, _, _, _) = trusted();
        let new = advanced_floor(&t);
        let l = legacy(&t);
        let mut p = prepared(&t);
        p.post_stv4_root[0] ^= 1;
        assert_eq!(
            recover_activation(&t, Some(&new), &l, Some(&p), Some(&intent(&t))),
            RecoveryDecision::QuarantinePreparedBoundaryMismatch
        );
        let mut i = intent(&t);
        i.envelope_valid = false;
        assert_eq!(
            recover_activation(&t, Some(&old_floor(&t)), &l, Some(&prepared(&t)), Some(&i)),
            RecoveryDecision::QuarantineIntentMismatch
        );
        let conflict = LocalActivationState::Conflict {
            height: t.record.activation_height,
            state_root: [0x99; 32],
        };
        assert_eq!(
            recover_activation(&t, Some(&new), &conflict, None, None),
            RecoveryDecision::QuarantineConflictingLocalState
        );
        let wrong = TrustedFat1Floor {
            network_id: t.record.network_id,
            trust_epoch: t.record.trust_epoch + 1,
            record_id: [0x91; 32],
            envelope_id: [0x92; 32],
        };
        assert_eq!(
            recover_activation(&t, Some(&wrong), &l, Some(&prepared(&t)), Some(&intent(&t))),
            RecoveryDecision::QuarantineFloorDoesNotMatchCurrentOrPredecessor
        );
    }

    #[test]
    fn post_activation_descendants_restart_and_clear_intent_without_weakening_floor() {
        let (t, _, _, _, _) = trusted();
        let new = advanced_floor(&t);
        let i = intent(&t);
        assert_eq!(
            recover_activation(
                &t,
                Some(&new),
                &descendant(&t, t.record.activation_height + 10, 0x91, 0x92),
                None,
                None
            ),
            RecoveryDecision::AcceptAnchoredDescendant
        );
        assert_eq!(
            recover_activation(
                &t,
                Some(&new),
                &descendant(&t, t.record.activation_height + 10, 0x91, 0x92),
                Some(&prepared(&t)),
                Some(&i)
            ),
            RecoveryDecision::AcceptAnchoredDescendantAndClearIntent
        );
        assert_eq!(
            recover_activation(
                &t,
                Some(&old_floor(&t)),
                &descendant(&t, t.record.activation_height + 10, 0x91, 0x92),
                None,
                None
            ),
            RecoveryDecision::QuarantineLocalStateAheadOfTrustFloor
        );
    }

    // CP-0236: finite durable-lifecycle event explorer. This is test-only state modeling;
    // it does not perform file I/O, contact an anchor, or claim power-loss durability.
    use std::collections::{HashSet, VecDeque};

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    enum LifecycleLocal {
        LegacyParent,
        Boundary,
        Descendant,
        Conflict,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Hash)]
    struct LifecycleModel {
        // The model can only monotonically advance Old -> Target. There is deliberately
        // no event that rolls an external provider backwards.
        target_floor: bool,
        provider_available: bool,
        local: LifecycleLocal,
        prepared: bool,
        prepared_corrupt: bool,
        intent: bool,
        intent_corrupt: bool,
        cas_response_lost: bool,
        alternate_tip: bool,
        quarantined: bool,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum LifecycleEvent {
        PrepareDurable,
        IntentDurable,
        AnchorCasCommit,
        LoseCasResponse,
        InstallBoundary,
        ClearIntent,
        CrashRestart,
        RestoreOldLocalSnapshot,
        EnterDescendant,
        ValidReorgAboveH,
        InvalidReorgAcrossH,
        ProviderUnavailable,
        ProviderRestored,
        CorruptPreparedArtifact,
        CorruptIntent,
        ConflictingCas,
        ConflictingLocalState,
    }

    fn lifecycle_floor<'a>(
        trust: &ActivationTrust,
        state: &LifecycleModel,
    ) -> Option<TrustedFat1Floor> {
        if !state.provider_available {
            None
        } else if state.target_floor {
            Some(advanced_floor(trust))
        } else {
            Some(old_floor(trust))
        }
    }

    fn lifecycle_local(trust: &ActivationTrust, state: &LifecycleModel) -> LocalActivationState {
        match state.local {
            LifecycleLocal::LegacyParent => legacy(trust),
            LifecycleLocal::Boundary => boundary(trust),
            LifecycleLocal::Descendant => descendant(
                trust,
                trust.record.activation_height + 10,
                if state.alternate_tip { 0x81 } else { 0x71 },
                if state.alternate_tip { 0x82 } else { 0x72 },
            ),
            LifecycleLocal::Conflict => LocalActivationState::Conflict {
                height: trust.record.activation_height,
                state_root: [0x99; 32],
            },
        }
    }

    fn lifecycle_recovery(trust: &ActivationTrust, state: &LifecycleModel) -> RecoveryDecision {
        if state.quarantined {
            return RecoveryDecision::QuarantineConflictingLocalState;
        }
        let floor = lifecycle_floor(trust, state);
        let local = lifecycle_local(trust, state);
        let mut p = state.prepared.then(|| prepared(trust));
        let mut i = state.intent.then(|| intent(trust));
        if state.prepared_corrupt {
            if let Some(value) = p.as_mut() {
                value.post_stv4_root[0] ^= 1;
            }
        }
        if state.intent_corrupt {
            if let Some(value) = i.as_mut() {
                value.envelope_valid = false;
            }
        }
        recover_activation(trust, floor.as_ref(), &local, p.as_ref(), i.as_ref())
    }

    fn is_quarantine_decision(decision: &RecoveryDecision) -> bool {
        matches!(
            decision,
            RecoveryDecision::QuarantineTrustFloorUnavailable
                | RecoveryDecision::QuarantineFloorNetworkMismatch
                | RecoveryDecision::QuarantineFloorDoesNotMatchCurrentOrPredecessor
                | RecoveryDecision::QuarantineLegacyParentMismatch
                | RecoveryDecision::QuarantinePreparedBoundaryMismatch
                | RecoveryDecision::QuarantineIntentMismatch
                | RecoveryDecision::QuarantineAnchorAdvancedWithoutPreparedBoundary
                | RecoveryDecision::QuarantineLocalStateAheadOfTrustFloor
                | RecoveryDecision::QuarantineBoundaryStateMismatch
                | RecoveryDecision::QuarantineDescendantCrossesActivationFence
                | RecoveryDecision::QuarantineConflictingLocalState
        )
    }

    fn lifecycle_step(
        trust: &ActivationTrust,
        state: &LifecycleModel,
        event: LifecycleEvent,
    ) -> LifecycleModel {
        let mut next = state.clone();
        // Once recovery quarantines, ordinary actions cannot resume trust automatically.
        // ProviderRestored records availability only; it cannot clear the quarantine flag.
        if state.quarantined && event != LifecycleEvent::ProviderRestored {
            return next;
        }
        match event {
            LifecycleEvent::PrepareDurable => {
                if next.local == LifecycleLocal::LegacyParent
                    && !next.target_floor
                    && !next.quarantined
                {
                    if !next.prepared {
                        next.prepared = true;
                        next.prepared_corrupt = false;
                    }
                }
            }
            LifecycleEvent::IntentDurable => {
                if next.local == LifecycleLocal::LegacyParent
                    && !next.target_floor
                    && next.prepared
                    && !next.prepared_corrupt
                {
                    next.intent = true;
                    next.intent_corrupt = false;
                }
            }
            LifecycleEvent::AnchorCasCommit => {
                if next.provider_available
                    && next.local == LifecycleLocal::LegacyParent
                    && next.prepared
                    && !next.prepared_corrupt
                    && next.intent
                    && !next.intent_corrupt
                    && !next.target_floor
                {
                    // Represents a successful exact CAS. The response is a separate event.
                    next.target_floor = true;
                    next.cas_response_lost = false;
                }
            }
            LifecycleEvent::LoseCasResponse => {
                if next.target_floor {
                    next.cas_response_lost = true;
                }
            }
            LifecycleEvent::InstallBoundary => {
                if next.provider_available
                    && next.target_floor
                    && next.local == LifecycleLocal::LegacyParent
                    && next.prepared
                    && !next.prepared_corrupt
                    && next.intent
                    && !next.intent_corrupt
                {
                    next.local = LifecycleLocal::Boundary;
                    next.cas_response_lost = false;
                }
            }
            LifecycleEvent::ClearIntent => {
                if next.provider_available
                    && next.target_floor
                    && matches!(
                        next.local,
                        LifecycleLocal::Boundary | LifecycleLocal::Descendant
                    )
                    && next.intent
                    && !next.intent_corrupt
                {
                    next.intent = false;
                    next.intent_corrupt = false;
                    next.prepared = false;
                    next.prepared_corrupt = false;
                    next.cas_response_lost = false;
                }
            }
            LifecycleEvent::CrashRestart => {
                let decision = lifecycle_recovery(trust, state);
                match decision {
                    RecoveryDecision::ContinueLegacyBeforeActivation => {
                        next.cas_response_lost = false;
                    }
                    RecoveryDecision::DiscardUncommittedPrepareAndKeepLegacy => {
                        next.prepared = false;
                        next.prepared_corrupt = false;
                    }
                    RecoveryDecision::ClearUnanchoredIntentAndKeepLegacy => {
                        next.intent = false;
                        next.intent_corrupt = false;
                        next.cas_response_lost = false;
                    }
                    RecoveryDecision::RollForwardPreparedBoundaryAfterAnchorAdvance => {
                        next.local = LifecycleLocal::Boundary;
                        next.cas_response_lost = false;
                    }
                    RecoveryDecision::AcceptCommittedBoundary
                    | RecoveryDecision::AcceptCommittedBoundaryAndClearIntent => {
                        next.prepared = false;
                        next.prepared_corrupt = false;
                        next.intent = false;
                        next.intent_corrupt = false;
                        next.cas_response_lost = false;
                    }
                    RecoveryDecision::AcceptAnchoredDescendant => {
                        next.cas_response_lost = false;
                    }
                    RecoveryDecision::AcceptAnchoredDescendantAndClearIntent => {
                        next.prepared = false;
                        next.prepared_corrupt = false;
                        next.intent = false;
                        next.intent_corrupt = false;
                        next.cas_response_lost = false;
                    }
                    _ => next.quarantined = true,
                }
            }
            LifecycleEvent::RestoreOldLocalSnapshot => {
                // Model restoring the ordinary local volume only; the external floor
                // is intentionally outside that restored failure domain.
                next.local = LifecycleLocal::LegacyParent;
                next.prepared = false;
                next.prepared_corrupt = false;
                next.intent = false;
                next.intent_corrupt = false;
                next.cas_response_lost = false;
                next.alternate_tip = false;
            }
            LifecycleEvent::EnterDescendant => {
                if next.target_floor && next.local == LifecycleLocal::Boundary {
                    next.local = LifecycleLocal::Descendant;
                }
            }
            LifecycleEvent::ValidReorgAboveH => {
                if next.local == LifecycleLocal::Descendant && next.target_floor {
                    let branch = BranchEvidence {
                        network_id: trust.record.network_id,
                        manifest_id: trust.record.manifest_id,
                        trust_record_id: trust.record_id,
                        activation_height: trust.record.activation_height,
                        activation_ancestor_id: trust.activation_block_id(),
                        activation_state_root: trust.record.expected_post_stv4_root,
                        tip_height: trust.record.activation_height + 11,
                        tip_block_id: [0x83; 32],
                        tip_state_root: [0x84; 32],
                    };
                    if validate_reorg_boundary(trust, &branch).is_ok() {
                        next.alternate_tip = !next.alternate_tip;
                    } else {
                        next.quarantined = true;
                    }
                }
            }
            LifecycleEvent::InvalidReorgAcrossH => {
                if next.local == LifecycleLocal::Descendant {
                    let mut branch = BranchEvidence {
                        network_id: trust.record.network_id,
                        manifest_id: trust.record.manifest_id,
                        trust_record_id: trust.record_id,
                        activation_height: trust.record.activation_height,
                        activation_ancestor_id: trust.activation_block_id(),
                        activation_state_root: trust.record.expected_post_stv4_root,
                        tip_height: trust.record.activation_height + 11,
                        tip_block_id: [0x85; 32],
                        tip_state_root: [0x86; 32],
                    };
                    branch.activation_ancestor_id[0] ^= 1;
                    // A losing/invalid reorg is rejected without changing the active state.
                    assert_eq!(
                        validate_reorg_boundary(trust, &branch),
                        Err(ReorgBoundaryError::WrongActivationAncestor)
                    );
                }
            }
            LifecycleEvent::ProviderUnavailable => next.provider_available = false,
            LifecycleEvent::ProviderRestored => next.provider_available = true,
            LifecycleEvent::CorruptPreparedArtifact => {
                if next.prepared {
                    next.prepared_corrupt = true;
                }
            }
            LifecycleEvent::CorruptIntent => {
                if next.intent {
                    next.intent_corrupt = true;
                }
            }
            LifecycleEvent::ConflictingCas => {
                // A CAS against the wrong expected floor or with a different target/ID
                // must have no state effect; it cannot reverse or overwrite the winner.
            }
            LifecycleEvent::ConflictingLocalState => {
                if next.local != LifecycleLocal::Conflict {
                    next.local = LifecycleLocal::Conflict;
                }
            }
        }
        next
    }

    #[test]
    fn cp0236_restore_after_anchor_commit_quarantines_without_floor_regression() {
        let (t, _, _, _, _) = trusted();
        let mut state = LifecycleModel {
            target_floor: false,
            provider_available: true,
            local: LifecycleLocal::LegacyParent,
            prepared: false,
            prepared_corrupt: false,
            intent: false,
            intent_corrupt: false,
            cas_response_lost: false,
            alternate_tip: false,
            quarantined: false,
        };
        state = lifecycle_step(&t, &state, LifecycleEvent::PrepareDurable);
        state = lifecycle_step(&t, &state, LifecycleEvent::IntentDurable);
        state = lifecycle_step(&t, &state, LifecycleEvent::AnchorCasCommit);
        assert!(state.target_floor);
        state = lifecycle_step(&t, &state, LifecycleEvent::LoseCasResponse);
        state = lifecycle_step(&t, &state, LifecycleEvent::RestoreOldLocalSnapshot);
        assert!(
            state.target_floor,
            "local snapshot restore must not roll back external floor"
        );
        assert_eq!(
            lifecycle_recovery(&t, &state),
            RecoveryDecision::QuarantineAnchorAdvancedWithoutPreparedBoundary
        );
        state = lifecycle_step(&t, &state, LifecycleEvent::CrashRestart);
        assert!(state.quarantined);
        assert!(state.target_floor);
    }

    #[test]
    fn cp0236_anchor_outage_and_corrupt_recovery_evidence_fail_closed() {
        let (t, _, _, _, _) = trusted();
        let mut state = LifecycleModel {
            target_floor: false,
            provider_available: true,
            local: LifecycleLocal::LegacyParent,
            prepared: false,
            prepared_corrupt: false,
            intent: false,
            intent_corrupt: false,
            cas_response_lost: false,
            alternate_tip: false,
            quarantined: false,
        };
        state = lifecycle_step(&t, &state, LifecycleEvent::PrepareDurable);
        state = lifecycle_step(&t, &state, LifecycleEvent::IntentDurable);
        state = lifecycle_step(&t, &state, LifecycleEvent::AnchorCasCommit);
        state = lifecycle_step(&t, &state, LifecycleEvent::InstallBoundary);
        state = lifecycle_step(&t, &state, LifecycleEvent::ProviderUnavailable);
        assert_eq!(
            lifecycle_recovery(&t, &state),
            RecoveryDecision::QuarantineTrustFloorUnavailable
        );
        state = lifecycle_step(&t, &state, LifecycleEvent::CrashRestart);
        assert!(state.quarantined);
        state = lifecycle_step(&t, &state, LifecycleEvent::ProviderRestored);
        state = lifecycle_step(&t, &state, LifecycleEvent::CrashRestart);
        assert!(
            state.quarantined,
            "provider restoration must not auto-clear quarantine"
        );

        let mut corrupt = LifecycleModel {
            target_floor: false,
            provider_available: true,
            local: LifecycleLocal::LegacyParent,
            prepared: true,
            prepared_corrupt: false,
            intent: true,
            intent_corrupt: false,
            cas_response_lost: false,
            alternate_tip: false,
            quarantined: false,
        };
        corrupt = lifecycle_step(&t, &corrupt, LifecycleEvent::CorruptIntent);
        assert_eq!(
            lifecycle_recovery(&t, &corrupt),
            RecoveryDecision::QuarantineIntentMismatch
        );
        corrupt = lifecycle_step(&t, &corrupt, LifecycleEvent::CrashRestart);
        assert!(corrupt.quarantined);
    }

    #[test]
    fn cp0236_valid_descendant_reorg_preserves_h_boundary_and_conflict_cas_is_noop() {
        let (t, _, _, _, _) = trusted();
        let mut state = LifecycleModel {
            target_floor: false,
            provider_available: true,
            local: LifecycleLocal::LegacyParent,
            prepared: false,
            prepared_corrupt: false,
            intent: false,
            intent_corrupt: false,
            cas_response_lost: false,
            alternate_tip: false,
            quarantined: false,
        };
        for event in [
            LifecycleEvent::PrepareDurable,
            LifecycleEvent::IntentDurable,
            LifecycleEvent::AnchorCasCommit,
            LifecycleEvent::InstallBoundary,
            LifecycleEvent::ClearIntent,
            LifecycleEvent::EnterDescendant,
        ] {
            state = lifecycle_step(&t, &state, event);
        }
        assert_eq!(state.local, LifecycleLocal::Descendant);
        let prior = state.clone();
        state = lifecycle_step(&t, &state, LifecycleEvent::InvalidReorgAcrossH);
        assert_eq!(
            state, prior,
            "invalid branch must not mutate the active branch"
        );
        state = lifecycle_step(&t, &state, LifecycleEvent::ValidReorgAboveH);
        assert_eq!(state.local, LifecycleLocal::Descendant);
        assert!(state.target_floor);
        assert!(!state.quarantined);
        let before_conflict = state.clone();
        state = lifecycle_step(&t, &state, LifecycleEvent::ConflictingCas);
        assert_eq!(
            state, before_conflict,
            "conflicting CAS cannot alter the winning floor"
        );
    }

    #[test]
    fn cp0236_bounded_event_explorer_preserves_floor_and_quarantines_inconsistent_states() {
        let (t, _, _, _, _) = trusted();
        let initial = LifecycleModel {
            target_floor: false,
            provider_available: true,
            local: LifecycleLocal::LegacyParent,
            prepared: false,
            prepared_corrupt: false,
            intent: false,
            intent_corrupt: false,
            cas_response_lost: false,
            alternate_tip: false,
            quarantined: false,
        };
        let events = [
            LifecycleEvent::PrepareDurable,
            LifecycleEvent::IntentDurable,
            LifecycleEvent::AnchorCasCommit,
            LifecycleEvent::LoseCasResponse,
            LifecycleEvent::InstallBoundary,
            LifecycleEvent::ClearIntent,
            LifecycleEvent::CrashRestart,
            LifecycleEvent::RestoreOldLocalSnapshot,
            LifecycleEvent::EnterDescendant,
            LifecycleEvent::ValidReorgAboveH,
            LifecycleEvent::InvalidReorgAcrossH,
            LifecycleEvent::ProviderUnavailable,
            LifecycleEvent::ProviderRestored,
            LifecycleEvent::CorruptPreparedArtifact,
            LifecycleEvent::CorruptIntent,
            LifecycleEvent::ConflictingCas,
            LifecycleEvent::ConflictingLocalState,
        ];
        let mut queue = VecDeque::from([initial.clone()]);
        let mut visited = HashSet::from([initial]);
        let mut transitions = 0usize;
        while let Some(state) = queue.pop_front() {
            let decision = lifecycle_recovery(&t, &state);
            if !state.provider_available {
                assert!(is_quarantine_decision(&decision));
                if !state.quarantined {
                    assert_eq!(decision, RecoveryDecision::QuarantineTrustFloorUnavailable);
                }
            }
            if !state.target_floor
                && matches!(
                    state.local,
                    LifecycleLocal::Boundary | LifecycleLocal::Descendant
                )
            {
                assert!(
                    is_quarantine_decision(&decision),
                    "local state ahead of old floor must quarantine: {state:?} => {decision:?}"
                );
            }
            if state.target_floor
                && state.local == LifecycleLocal::LegacyParent
                && (!state.prepared || !state.intent)
            {
                assert!(
                    is_quarantine_decision(&decision),
                    "advanced anchor without a recoverable intent must quarantine: {state:?} => {decision:?}"
                );
            }
            if state.quarantined {
                assert!(is_quarantine_decision(&decision));
            }
            for event in events {
                let next = lifecycle_step(&t, &state, event);
                assert!(
                    !state.target_floor || next.target_floor,
                    "model violated external floor monotonicity at {event:?}: {state:?} => {next:?}"
                );
                transitions += 1;
                if visited.insert(next.clone()) {
                    queue.push_back(next);
                }
            }
        }
        assert!(
            visited.len() >= 100,
            "exploration unexpectedly small: {}",
            visited.len()
        );
        assert!(transitions >= visited.len() * events.len());
        eprintln!(
            "CP-0236_EVENT_EXPLORER=PASS states={} transitions={} alphabet={}",
            visited.len(),
            transitions,
            events.len()
        );
    }

    #[path = "../../v4_migration_persistence_fault_harness.rs"]
    mod cp0237_migration_persistence_fault_harness;
}
