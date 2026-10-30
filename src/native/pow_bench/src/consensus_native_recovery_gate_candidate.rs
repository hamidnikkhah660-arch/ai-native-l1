//! CP-0428 candidate: fail-closed readiness gate for consensus-native recovery.
//!
//! This pure policy model is wired into the QZBE candidate node for point-in-time startup recovery
//! classification and the loopback read-only status RPC. It is not a continuously refreshed or
//! production Mainnet gate. A node may report recovery READY only after its canonical profile and
//! Genesis are pinned, retained history is replayed and validated, and pinned-peer reconciliation
//! plus state-root and cumulative-work agreement have completed. A stale local snapshot is not
//! freshness evidence. Operator independence and production transport must be established outside
//! this module; READY here never implies public-launch approval.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvidenceStatus {
    Pending,
    Valid,
    Invalid,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryCheck {
    NetworkProfile,
    GenesisManifest,
    FullHistoryReplay,
    PeerReconciliation,
    StateRootAgreement,
    CumulativeChainworkAgreement,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryFault {
    NetworkProfileMismatch,
    GenesisManifestMismatch,
    InvalidHistoricalBlockOrReplay,
    ConflictingPeerHistory,
    CanonicalStateRootMismatch,
    CumulativeChainworkMismatch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryReadiness {
    /// The node must not claim canonical freshness, mine on a supposedly-current tip, or confirm
    /// value-bearing transactions until the missing checks have completed.
    Syncing(RecoveryCheck),
    Ready,
    /// A permanent mismatch or observed conflict requires quarantine/recovery, not a fallback.
    Quarantined(RecoveryFault),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecoveryEvidence {
    pub network_profile: EvidenceStatus,
    pub genesis_manifest: EvidenceStatus,
    pub full_history_replay: EvidenceStatus,
    pub peer_reconciliation: EvidenceStatus,
    pub state_root_agreement: EvidenceStatus,
    pub cumulative_chainwork_agreement: EvidenceStatus,
    pub conflicting_peer_history: bool,
}

impl Default for RecoveryEvidence {
    fn default() -> Self {
        Self {
            network_profile: EvidenceStatus::Pending,
            genesis_manifest: EvidenceStatus::Pending,
            full_history_replay: EvidenceStatus::Pending,
            peer_reconciliation: EvidenceStatus::Pending,
            state_root_agreement: EvidenceStatus::Pending,
            cumulative_chainwork_agreement: EvidenceStatus::Pending,
            conflicting_peer_history: false,
        }
    }
}

impl RecoveryEvidence {
    /// Return the only safe readiness classification supported by the supplied evidence.
    ///
    /// Invalid evidence and explicit peer conflicts take precedence over pending work, so a node
    /// cannot report merely SYNCING when it already knows its history/profile is inconsistent.
    pub fn evaluate(&self) -> RecoveryReadiness {
        if self.conflicting_peer_history {
            return RecoveryReadiness::Quarantined(RecoveryFault::ConflictingPeerHistory);
        }

        for (status, fault) in [
            (self.network_profile, RecoveryFault::NetworkProfileMismatch),
            (
                self.genesis_manifest,
                RecoveryFault::GenesisManifestMismatch,
            ),
            (
                self.full_history_replay,
                RecoveryFault::InvalidHistoricalBlockOrReplay,
            ),
            (
                self.peer_reconciliation,
                RecoveryFault::ConflictingPeerHistory,
            ),
            (
                self.state_root_agreement,
                RecoveryFault::CanonicalStateRootMismatch,
            ),
            (
                self.cumulative_chainwork_agreement,
                RecoveryFault::CumulativeChainworkMismatch,
            ),
        ] {
            if status == EvidenceStatus::Invalid {
                return RecoveryReadiness::Quarantined(fault);
            }
        }

        for (status, check) in [
            (self.network_profile, RecoveryCheck::NetworkProfile),
            (self.genesis_manifest, RecoveryCheck::GenesisManifest),
            (self.full_history_replay, RecoveryCheck::FullHistoryReplay),
            (self.peer_reconciliation, RecoveryCheck::PeerReconciliation),
            (self.state_root_agreement, RecoveryCheck::StateRootAgreement),
            (
                self.cumulative_chainwork_agreement,
                RecoveryCheck::CumulativeChainworkAgreement,
            ),
        ] {
            if status == EvidenceStatus::Pending {
                return RecoveryReadiness::Syncing(check);
            }
        }

        RecoveryReadiness::Ready
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fully_valid() -> RecoveryEvidence {
        RecoveryEvidence {
            network_profile: EvidenceStatus::Valid,
            genesis_manifest: EvidenceStatus::Valid,
            full_history_replay: EvidenceStatus::Valid,
            peer_reconciliation: EvidenceStatus::Valid,
            state_root_agreement: EvidenceStatus::Valid,
            cumulative_chainwork_agreement: EvidenceStatus::Valid,
            conflicting_peer_history: false,
        }
    }

    #[test]
    fn empty_or_restored_local_state_never_implies_ready() {
        assert_eq!(
            RecoveryEvidence::default().evaluate(),
            RecoveryReadiness::Syncing(RecoveryCheck::NetworkProfile)
        );
    }

    #[test]
    fn profile_mismatch_quarantines_even_if_other_evidence_is_pending() {
        let mut evidence = RecoveryEvidence::default();
        evidence.network_profile = EvidenceStatus::Invalid;
        assert_eq!(
            evidence.evaluate(),
            RecoveryReadiness::Quarantined(RecoveryFault::NetworkProfileMismatch)
        );
    }

    #[test]
    fn genesis_mismatch_quarantines() {
        let mut evidence = fully_valid();
        evidence.genesis_manifest = EvidenceStatus::Invalid;
        assert_eq!(
            evidence.evaluate(),
            RecoveryReadiness::Quarantined(RecoveryFault::GenesisManifestMismatch)
        );
    }

    #[test]
    fn invalid_history_takes_precedence_over_pending_peer_work() {
        let mut evidence = RecoveryEvidence::default();
        evidence.full_history_replay = EvidenceStatus::Invalid;
        assert_eq!(
            evidence.evaluate(),
            RecoveryReadiness::Quarantined(RecoveryFault::InvalidHistoricalBlockOrReplay)
        );
    }

    #[test]
    fn locally_replayed_history_is_not_ready_before_peer_reconciliation() {
        let mut evidence = fully_valid();
        evidence.peer_reconciliation = EvidenceStatus::Pending;
        assert_eq!(
            evidence.evaluate(),
            RecoveryReadiness::Syncing(RecoveryCheck::PeerReconciliation)
        );
    }

    #[test]
    fn local_replay_without_state_root_agreement_is_not_ready() {
        let mut evidence = fully_valid();
        evidence.state_root_agreement = EvidenceStatus::Pending;
        assert_eq!(
            evidence.evaluate(),
            RecoveryReadiness::Syncing(RecoveryCheck::StateRootAgreement)
        );
    }

    #[test]
    fn local_replay_without_chainwork_agreement_is_not_ready() {
        let mut evidence = fully_valid();
        evidence.cumulative_chainwork_agreement = EvidenceStatus::Pending;
        assert_eq!(
            evidence.evaluate(),
            RecoveryReadiness::Syncing(RecoveryCheck::CumulativeChainworkAgreement)
        );
    }

    #[test]
    fn explicit_peer_conflict_quarantines_even_if_every_check_was_otherwise_valid() {
        let mut evidence = fully_valid();
        evidence.conflicting_peer_history = true;
        assert_eq!(
            evidence.evaluate(),
            RecoveryReadiness::Quarantined(RecoveryFault::ConflictingPeerHistory)
        );
    }

    #[test]
    fn state_root_mismatch_quarantines() {
        let mut evidence = fully_valid();
        evidence.state_root_agreement = EvidenceStatus::Invalid;
        assert_eq!(
            evidence.evaluate(),
            RecoveryReadiness::Quarantined(RecoveryFault::CanonicalStateRootMismatch)
        );
    }

    #[test]
    fn chainwork_mismatch_quarantines() {
        let mut evidence = fully_valid();
        evidence.cumulative_chainwork_agreement = EvidenceStatus::Invalid;
        assert_eq!(
            evidence.evaluate(),
            RecoveryReadiness::Quarantined(RecoveryFault::CumulativeChainworkMismatch)
        );
    }

    #[test]
    fn ready_requires_every_independent_check_to_be_valid() {
        assert_eq!(fully_valid().evaluate(), RecoveryReadiness::Ready);
    }
}
