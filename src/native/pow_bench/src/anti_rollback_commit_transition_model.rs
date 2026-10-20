//! Test-only transition model for ambiguous cross-store snapshot commits.
//!
//! This is an abstract state machine, not a storage protocol or recovery implementation.
//! It performs no I/O, chooses no trust anchor, authenticates no remote response, and is
//! compiled only for tests. A "prepared" payload means the candidate was durably written,
//! independently reopened, and fully validated by an external hypothetical caller.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SnapshotRef {
    generation: u64,
    digest: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AnchorView {
    Unavailable,
    Uninitialized,
    Current(SnapshotRef),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PendingCommit {
    id: u64,
    prior_anchor: SnapshotRef,
    target: SnapshotRef,
    prepared_and_reopened: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    Idle,
    Prepared,
    AnchorAdvanced,
    LocalInstalled,
    Quarantined,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ClientOutcome {
    NoResponseYet,
    ResponseLost,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TransitionResult {
    Applied,
    Idempotent,
    RejectNoPendingCommit,
    RejectDifferentCommitId,
    RejectConflictingReuseOfCommitId,
    RejectPayloadNotIndependentlyValidated,
    RejectNonMonotonicGeneration,
    RejectAnchorNotAtTarget,
    FailClosedAnchorUnavailable,
    RejectAnchorUninitialized,
    RejectStaleAnchorObservation,
    RetrySameCommitIdOnly,
    ConfirmedAlreadyCommitted,
    ContinueLocalInstallRecovery,
    QuarantineUnexpectedAnchorState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CommitModel {
    local: SnapshotRef,
    anchor: AnchorView,
    pending: Option<PendingCommit>,
    phase: Phase,
    client_outcome: ClientOutcome,
    next_query_id: u64,
    latest_query_id: Option<u64>,
}

impl CommitModel {
    fn blocked_if_quarantined(&self) -> Option<TransitionResult> {
        (self.phase == Phase::Quarantined)
            .then_some(TransitionResult::QuarantineUnexpectedAnchorState)
    }

    fn new(initial: SnapshotRef) -> Self {
        Self {
            local: initial,
            anchor: AnchorView::Current(initial),
            pending: None,
            phase: Phase::Idle,
            client_outcome: ClientOutcome::NoResponseYet,
            next_query_id: 1,
            latest_query_id: None,
        }
    }

    /// Record a hypothetical payload that has already been durably prepared, reopened,
    /// and validated. This records evidence only; it does not write or sync any file.
    fn prepare(
        &mut self,
        id: u64,
        target: SnapshotRef,
        prepared_and_reopened: bool,
    ) -> TransitionResult {
        if let Some(result) = self.blocked_if_quarantined() {
            return result;
        }
        if let Some(pending) = self.pending {
            if pending.id == id && pending.target == target {
                return if pending.prepared_and_reopened == prepared_and_reopened
                    && prepared_and_reopened
                {
                    TransitionResult::Idempotent
                } else {
                    TransitionResult::RejectConflictingReuseOfCommitId
                };
            }
            if pending.id == id {
                self.phase = Phase::Quarantined;
                return TransitionResult::RejectConflictingReuseOfCommitId;
            }
            return TransitionResult::RejectDifferentCommitId;
        }

        if !prepared_and_reopened {
            return TransitionResult::RejectPayloadNotIndependentlyValidated;
        }
        let AnchorView::Current(prior_anchor) = self.anchor else {
            return match self.anchor {
                AnchorView::Unavailable => TransitionResult::FailClosedAnchorUnavailable,
                AnchorView::Uninitialized => TransitionResult::RejectAnchorUninitialized,
                AnchorView::Current(_) => unreachable!(),
            };
        };
        if self.local != prior_anchor {
            self.phase = Phase::Quarantined;
            return TransitionResult::QuarantineUnexpectedAnchorState;
        }
        if target.generation <= prior_anchor.generation {
            return TransitionResult::RejectNonMonotonicGeneration;
        }

        self.pending = Some(PendingCommit {
            id,
            prior_anchor,
            target,
            prepared_and_reopened,
        });
        self.phase = Phase::Prepared;
        self.client_outcome = ClientOutcome::NoResponseYet;
        TransitionResult::Applied
    }

    /// Model an authenticated, fresh anchor acknowledgement for this exact commit ID and
    /// target. The authentication/freshness assumptions are preconditions, not implemented.
    fn acknowledge_anchor(&mut self, id: u64, target: SnapshotRef) -> TransitionResult {
        if let Some(result) = self.blocked_if_quarantined() {
            return result;
        }
        let Some(pending) = self.pending else {
            return TransitionResult::RejectNoPendingCommit;
        };
        if pending.id != id {
            return TransitionResult::RejectDifferentCommitId;
        }
        if pending.target != target || !pending.prepared_and_reopened {
            self.phase = Phase::Quarantined;
            return TransitionResult::RejectConflictingReuseOfCommitId;
        }
        match self.anchor {
            AnchorView::Unavailable => TransitionResult::FailClosedAnchorUnavailable,
            AnchorView::Uninitialized => TransitionResult::RejectAnchorUninitialized,
            AnchorView::Current(current) if current == target => {
                if self.local == target {
                    self.phase = Phase::LocalInstalled;
                    TransitionResult::Idempotent
                } else if self.local == pending.prior_anchor
                    || self.local.generation < pending.prior_anchor.generation
                {
                    self.phase = Phase::AnchorAdvanced;
                    TransitionResult::Idempotent
                } else {
                    self.phase = Phase::Quarantined;
                    TransitionResult::QuarantineUnexpectedAnchorState
                }
            }
            AnchorView::Current(current) if current == pending.prior_anchor => {
                if self.local != pending.prior_anchor {
                    self.phase = Phase::Quarantined;
                    TransitionResult::QuarantineUnexpectedAnchorState
                } else {
                    self.anchor = AnchorView::Current(target);
                    self.phase = Phase::AnchorAdvanced;
                    TransitionResult::Applied
                }
            }
            AnchorView::Current(_) => {
                self.phase = Phase::Quarantined;
                TransitionResult::QuarantineUnexpectedAnchorState
            }
        }
    }

    /// Model a successful local replacement acknowledgement. No replacement occurs here.
    fn acknowledge_local_install(&mut self, id: u64, target: SnapshotRef) -> TransitionResult {
        if let Some(result) = self.blocked_if_quarantined() {
            return result;
        }
        let Some(pending) = self.pending else {
            return TransitionResult::RejectNoPendingCommit;
        };
        if pending.id != id {
            return TransitionResult::RejectDifferentCommitId;
        }
        if pending.target != target || !pending.prepared_and_reopened {
            self.phase = Phase::Quarantined;
            return TransitionResult::RejectConflictingReuseOfCommitId;
        }
        if self.anchor != AnchorView::Current(target) {
            return TransitionResult::RejectAnchorNotAtTarget;
        }
        if self.local == target {
            self.phase = Phase::LocalInstalled;
            return TransitionResult::Idempotent;
        }
        // The only non-target local bytes that are safe to replace are the exact
        // prior-anchor snapshot or an older generation eligible for recovery. A
        // same-generation digest conflict or an intermediate generation is not
        // made trustworthy merely because it is below the target generation.
        if self.local != pending.prior_anchor
            && self.local.generation >= pending.prior_anchor.generation
        {
            self.phase = Phase::Quarantined;
            return TransitionResult::QuarantineUnexpectedAnchorState;
        }
        self.local = target;
        self.phase = Phase::LocalInstalled;
        TransitionResult::Applied
    }

    /// Model only a lost client response. It deliberately does not imply abort or rollback.
    fn lose_response(&mut self, id: u64) -> TransitionResult {
        let Some(pending) = self.pending else {
            return TransitionResult::RejectNoPendingCommit;
        };
        if pending.id != id {
            return TransitionResult::RejectDifferentCommitId;
        }
        self.client_outcome = ClientOutcome::ResponseLost;
        TransitionResult::Applied
    }

    /// Start a new abstract anchor read. A response to an earlier query is stale once a
    /// later query has been issued; this sequence number is test bookkeeping, not a nonce.
    fn begin_anchor_query(&mut self) -> u64 {
        let id = self.next_query_id;
        self.next_query_id = self.next_query_id.saturating_add(1);
        self.latest_query_id = Some(id);
        id
    }

    /// Classify a recovery read. A fresh observation of the intended target allows recovery
    /// to continue; an observation of the prior anchor allows only retry with the same ID.
    /// No RPC is issued and no snapshot is installed by this method.
    fn classify_recovery_observation(
        &mut self,
        commit_id: u64,
        query_id: u64,
        observed: AnchorView,
    ) -> TransitionResult {
        if let Some(result) = self.blocked_if_quarantined() {
            return result;
        }
        if self.latest_query_id != Some(query_id) {
            return TransitionResult::RejectStaleAnchorObservation;
        }
        let Some(pending) = self.pending else {
            return TransitionResult::RejectNoPendingCommit;
        };
        if pending.id != commit_id {
            return TransitionResult::RejectDifferentCommitId;
        }
        if !pending.prepared_and_reopened {
            return TransitionResult::RejectPayloadNotIndependentlyValidated;
        }

        match observed {
            AnchorView::Unavailable => TransitionResult::FailClosedAnchorUnavailable,
            AnchorView::Uninitialized => TransitionResult::RejectAnchorUninitialized,
            AnchorView::Current(current) if current == pending.target => {
                self.anchor = AnchorView::Current(current);
                if self.local == pending.target {
                    self.phase = Phase::LocalInstalled;
                    TransitionResult::ConfirmedAlreadyCommitted
                } else if self.local == pending.prior_anchor
                    || self.local.generation < pending.prior_anchor.generation
                {
                    self.phase = Phase::AnchorAdvanced;
                    TransitionResult::ContinueLocalInstallRecovery
                } else {
                    // Conflicting local bytes at/after the prior generation must never be
                    // overwritten merely because the anchor observation matches the target.
                    self.phase = Phase::Quarantined;
                    TransitionResult::QuarantineUnexpectedAnchorState
                }
            }
            AnchorView::Current(current) if current == pending.prior_anchor => {
                // Do not roll back a target already observed/acknowledged. Also retry only
                // while local bytes still equal the prior anchored snapshot.
                if self.anchor != AnchorView::Current(pending.prior_anchor)
                    || self.local != pending.prior_anchor
                {
                    self.phase = Phase::Quarantined;
                    TransitionResult::QuarantineUnexpectedAnchorState
                } else {
                    self.phase = Phase::Prepared;
                    TransitionResult::RetrySameCommitIdOnly
                }
            }
            AnchorView::Current(_) => {
                self.phase = Phase::Quarantined;
                TransitionResult::QuarantineUnexpectedAnchorState
            }
        }
    }

    /// Check the model's internal safety invariants after each abstract event. Quarantine is
    /// an explicit terminal classification for automated transitions, not a state to accept.
    fn modeled_invariants_hold(&self) -> bool {
        if self.phase == Phase::Quarantined {
            return true;
        }

        let AnchorView::Current(anchor) = self.anchor else {
            return false;
        };
        if self.local.generation > anchor.generation
            || (self.local.generation == anchor.generation && self.local.digest != anchor.digest)
        {
            return false;
        }

        match (self.phase, self.pending) {
            (Phase::Idle, None) => self.local == anchor,
            (Phase::Prepared, Some(pending)) => {
                pending.prepared_and_reopened
                    && anchor == pending.prior_anchor
                    && self.local == pending.prior_anchor
            }
            (Phase::AnchorAdvanced, Some(pending)) => {
                pending.prepared_and_reopened
                    && anchor == pending.target
                    && (self.local == pending.prior_anchor
                        || self.local.generation < pending.prior_anchor.generation)
            }
            (Phase::LocalInstalled, Some(pending)) => {
                pending.prepared_and_reopened
                    && anchor == pending.target
                    && self.local == pending.target
            }
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snap(generation: u64, byte: u8) -> SnapshotRef {
        SnapshotRef {
            generation,
            digest: [byte; 32],
        }
    }

    #[test]
    fn commit_order_requires_prepared_payload_anchor_then_local_install() {
        let old = snap(10, 0x10);
        let next = snap(11, 0x11);
        let mut model = CommitModel::new(old);

        assert_eq!(
            model.prepare(7, next, false),
            TransitionResult::RejectPayloadNotIndependentlyValidated
        );
        assert_eq!(model.local, old);
        assert_eq!(model.anchor, AnchorView::Current(old));

        assert_eq!(model.prepare(7, next, true), TransitionResult::Applied);
        assert_eq!(
            model.acknowledge_local_install(7, next),
            TransitionResult::RejectAnchorNotAtTarget
        );
        assert_eq!(model.local, old);
        assert_eq!(model.acknowledge_anchor(7, next), TransitionResult::Applied);
        assert_eq!(model.local, old);
        assert_eq!(
            model.acknowledge_local_install(7, next),
            TransitionResult::Applied
        );
        assert_eq!(model.local, next);
        assert_eq!(model.anchor, AnchorView::Current(next));
        assert!(model.modeled_invariants_hold());
    }

    #[test]
    fn same_commit_id_and_same_target_are_idempotent_but_conflicting_reuse_quarantines() {
        let old = snap(3, 0x30);
        let next = snap(4, 0x40);
        let other = snap(4, 0x41);
        let mut model = CommitModel::new(old);
        assert_eq!(model.prepare(44, next, true), TransitionResult::Applied);
        assert_eq!(model.prepare(44, next, true), TransitionResult::Idempotent);
        assert_eq!(
            model.prepare(44, other, true),
            TransitionResult::RejectConflictingReuseOfCommitId
        );
        assert_eq!(model.phase, Phase::Quarantined);
    }

    #[test]
    fn lost_response_requires_fresh_observation_and_never_means_abort() {
        let old = snap(20, 0x20);
        let next = snap(21, 0x21);
        let mut model = CommitModel::new(old);
        assert_eq!(model.prepare(5, next, true), TransitionResult::Applied);
        assert_eq!(model.lose_response(5), TransitionResult::Applied);
        assert_eq!(model.client_outcome, ClientOutcome::ResponseLost);

        let stale_query = model.begin_anchor_query();
        let current_query = model.begin_anchor_query();
        assert_eq!(
            model.classify_recovery_observation(5, stale_query, AnchorView::Current(old)),
            TransitionResult::RejectStaleAnchorObservation
        );
        assert_eq!(
            model.classify_recovery_observation(5, current_query, AnchorView::Current(old)),
            TransitionResult::RetrySameCommitIdOnly
        );
        assert_eq!(model.local, old);
        assert_eq!(model.client_outcome, ClientOutcome::ResponseLost);
    }

    #[test]
    fn matching_anchor_observation_allows_only_recovery_classification() {
        let old = snap(50, 0x50);
        let next = snap(51, 0x51);
        let mut model = CommitModel::new(old);
        assert_eq!(model.prepare(9, next, true), TransitionResult::Applied);
        let query = model.begin_anchor_query();
        assert_eq!(
            model.classify_recovery_observation(9, query, AnchorView::Current(next)),
            TransitionResult::ContinueLocalInstallRecovery
        );
        assert_eq!(model.anchor, AnchorView::Current(next));
        assert_eq!(model.local, old); // Classification never installs bytes.
        assert_eq!(
            model.acknowledge_local_install(9, next),
            TransitionResult::Applied
        );
        assert_eq!(model.local, next);
        assert!(model.modeled_invariants_hold());
    }

    #[test]
    fn unavailable_uninitialized_and_conflicting_anchor_observations_fail_closed() {
        let old = snap(80, 0x80);
        let next = snap(81, 0x81);
        let mut model = CommitModel::new(old);
        assert_eq!(model.prepare(12, next, true), TransitionResult::Applied);

        let q = model.begin_anchor_query();
        assert_eq!(
            model.classify_recovery_observation(12, q, AnchorView::Unavailable),
            TransitionResult::FailClosedAnchorUnavailable
        );
        let q = model.begin_anchor_query();
        assert_eq!(
            model.classify_recovery_observation(12, q, AnchorView::Uninitialized),
            TransitionResult::RejectAnchorUninitialized
        );
        let q = model.begin_anchor_query();
        assert_eq!(
            model.classify_recovery_observation(12, q, AnchorView::Current(snap(80, 0xFE))),
            TransitionResult::QuarantineUnexpectedAnchorState
        );
        assert_eq!(model.phase, Phase::Quarantined);
    }

    #[test]
    fn anchor_acknowledgement_is_bound_to_id_and_exact_target() {
        let old = snap(1, 0x01);
        let next = snap(2, 0x02);
        let wrong = snap(2, 0x03);
        let mut model = CommitModel::new(old);
        assert_eq!(model.prepare(2, next, true), TransitionResult::Applied);
        assert_eq!(
            model.acknowledge_anchor(3, next),
            TransitionResult::RejectDifferentCommitId
        );
        assert_eq!(
            model.acknowledge_anchor(2, wrong),
            TransitionResult::RejectConflictingReuseOfCommitId
        );
        assert_eq!(model.phase, Phase::Quarantined);
    }

    #[test]
    fn previously_advanced_anchor_cannot_be_rolled_back_by_recovery_observation() {
        let old = snap(4, 0x04);
        let next = snap(5, 0x05);
        let mut model = CommitModel::new(old);
        assert_eq!(model.prepare(17, next, true), TransitionResult::Applied);
        assert_eq!(
            model.acknowledge_anchor(17, next),
            TransitionResult::Applied
        );
        assert_eq!(
            model.acknowledge_local_install(17, next),
            TransitionResult::Applied
        );

        let query = model.begin_anchor_query();
        assert_eq!(
            model.classify_recovery_observation(17, query, AnchorView::Current(old)),
            TransitionResult::QuarantineUnexpectedAnchorState
        );
        assert_eq!(model.phase, Phase::Quarantined);
        assert_eq!(model.local, next);
        assert_eq!(model.anchor, AnchorView::Current(next));
        assert_eq!(
            model.acknowledge_local_install(17, next),
            TransitionResult::QuarantineUnexpectedAnchorState
        );
        assert_eq!(
            model.acknowledge_anchor(17, next),
            TransitionResult::QuarantineUnexpectedAnchorState
        );
        assert!(model.modeled_invariants_hold());
    }

    #[test]
    fn prepare_and_anchor_ack_fail_closed_when_local_does_not_match_prior_anchor() {
        let prior = snap(30, 0x30);
        let target = snap(31, 0x31);
        let conflicting_local = snap(30, 0xEE);

        let mut prepare_model = CommitModel::new(prior);
        prepare_model.local = conflicting_local;
        assert_eq!(
            prepare_model.prepare(32, target, true),
            TransitionResult::QuarantineUnexpectedAnchorState
        );
        assert_eq!(prepare_model.anchor, AnchorView::Current(prior));
        assert_eq!(prepare_model.pending, None);
        assert_eq!(prepare_model.phase, Phase::Quarantined);

        let mut ack_model = CommitModel::new(prior);
        assert_eq!(
            ack_model.prepare(32, target, true),
            TransitionResult::Applied
        );
        ack_model.local = conflicting_local;
        assert_eq!(
            ack_model.acknowledge_anchor(32, target),
            TransitionResult::QuarantineUnexpectedAnchorState
        );
        assert_eq!(ack_model.anchor, AnchorView::Current(prior));
        assert_eq!(ack_model.local, conflicting_local);
        assert_eq!(ack_model.phase, Phase::Quarantined);
    }

    #[test]
    fn duplicate_anchor_ack_after_local_install_is_idempotent_without_phase_regression() {
        let old = snap(31, 0x31);
        let target = snap(32, 0x32);
        let mut model = CommitModel::new(old);
        assert_eq!(model.prepare(33, target, true), TransitionResult::Applied);
        assert_eq!(
            model.acknowledge_anchor(33, target),
            TransitionResult::Applied
        );
        assert_eq!(
            model.acknowledge_local_install(33, target),
            TransitionResult::Applied
        );
        assert_eq!(model.phase, Phase::LocalInstalled);
        assert_eq!(
            model.acknowledge_anchor(33, target),
            TransitionResult::Idempotent
        );
        assert_eq!(model.phase, Phase::LocalInstalled);
        assert!(model.modeled_invariants_hold());
    }

    #[test]
    fn anchor_ack_with_target_but_conflicting_same_generation_local_is_quarantined() {
        let prior = snap(40, 0x40);
        let target = snap(41, 0x41);
        let conflicting_local = snap(41, 0xFE);
        let mut model = CommitModel::new(prior);
        assert_eq!(model.prepare(42, target, true), TransitionResult::Applied);
        model.anchor = AnchorView::Current(target);
        model.local = conflicting_local;
        assert_eq!(
            model.acknowledge_anchor(42, target),
            TransitionResult::QuarantineUnexpectedAnchorState
        );
        assert_eq!(model.phase, Phase::Quarantined);
    }

    #[test]
    fn local_install_quarantines_prior_digest_conflict_and_intermediate_generation() {
        let prior = snap(40, 0x40);
        let target = snap(42, 0x42);
        for inconsistent_local in [snap(40, 0xFE), snap(41, 0x41)] {
            let mut model = CommitModel::new(prior);
            assert_eq!(model.prepare(43, target, true), TransitionResult::Applied);
            assert_eq!(
                model.acknowledge_anchor(43, target),
                TransitionResult::Applied
            );
            model.local = inconsistent_local;
            assert!(!model.modeled_invariants_hold());
            assert_eq!(
                model.acknowledge_local_install(43, target),
                TransitionResult::QuarantineUnexpectedAnchorState
            );
            assert_eq!(model.phase, Phase::Quarantined);
        }
    }

    #[test]
    fn matching_anchor_does_not_override_same_generation_local_digest_conflict() {
        let old = snap(9, 0x09);
        let target = snap(10, 0x10);
        let conflicting_local = snap(10, 0xEE);
        let mut model = CommitModel::new(old);
        assert_eq!(model.prepare(21, target, true), TransitionResult::Applied);
        // Simulate an inconsistent local file observation that the abstract model did not
        // itself install. A matching remote digest cannot legitimize those local bytes.
        model.local = conflicting_local;
        let query = model.begin_anchor_query();
        assert_eq!(
            model.classify_recovery_observation(21, query, AnchorView::Current(target)),
            TransitionResult::QuarantineUnexpectedAnchorState
        );
        assert_eq!(model.phase, Phase::Quarantined);
    }

    #[derive(Debug, Clone, Copy)]
    enum Event {
        PrepareGood,
        PrepareUnvalidated,
        PrepareSameIdConflict,
        PrepareOtherId,
        AckAnchor,
        AckWrongId,
        AckWrongTarget,
        InstallLocal,
        InstallWrongId,
        LoseResponse,
        RecoverPrior,
        RecoverTarget,
        RecoverUnexpected,
        RecoverUnavailable,
        RecoverUninitialized,
        RecoverStale,
    }

    const EVENTS: [Event; 16] = [
        Event::PrepareGood,
        Event::PrepareUnvalidated,
        Event::PrepareSameIdConflict,
        Event::PrepareOtherId,
        Event::AckAnchor,
        Event::AckWrongId,
        Event::AckWrongTarget,
        Event::InstallLocal,
        Event::InstallWrongId,
        Event::LoseResponse,
        Event::RecoverPrior,
        Event::RecoverTarget,
        Event::RecoverUnexpected,
        Event::RecoverUnavailable,
        Event::RecoverUninitialized,
        Event::RecoverStale,
    ];

    fn apply_event(model: &mut CommitModel, event: Event) -> TransitionResult {
        let prior = snap(1, 0x11);
        let target = snap(2, 0x22);
        let conflict = snap(2, 0x33);
        match event {
            Event::PrepareGood => model.prepare(7, target, true),
            Event::PrepareUnvalidated => model.prepare(7, target, false),
            Event::PrepareSameIdConflict => model.prepare(7, conflict, true),
            Event::PrepareOtherId => model.prepare(8, target, true),
            Event::AckAnchor => model.acknowledge_anchor(7, target),
            Event::AckWrongId => model.acknowledge_anchor(8, target),
            Event::AckWrongTarget => model.acknowledge_anchor(7, conflict),
            Event::InstallLocal => model.acknowledge_local_install(7, target),
            Event::InstallWrongId => model.acknowledge_local_install(8, target),
            Event::LoseResponse => model.lose_response(7),
            Event::RecoverPrior => {
                let query = model.begin_anchor_query();
                model.classify_recovery_observation(7, query, AnchorView::Current(prior))
            }
            Event::RecoverTarget => {
                let query = model.begin_anchor_query();
                model.classify_recovery_observation(7, query, AnchorView::Current(target))
            }
            Event::RecoverUnexpected => {
                let query = model.begin_anchor_query();
                model.classify_recovery_observation(7, query, AnchorView::Current(snap(9, 0x99)))
            }
            Event::RecoverUnavailable => {
                let query = model.begin_anchor_query();
                model.classify_recovery_observation(7, query, AnchorView::Unavailable)
            }
            Event::RecoverUninitialized => {
                let query = model.begin_anchor_query();
                model.classify_recovery_observation(7, query, AnchorView::Uninitialized)
            }
            Event::RecoverStale => {
                let stale_query = model.begin_anchor_query();
                let _latest_query = model.begin_anchor_query();
                model.classify_recovery_observation(7, stale_query, AnchorView::Current(target))
            }
        }
    }

    fn explore_event_sequences(
        model: CommitModel,
        remaining: usize,
        path: &mut Vec<Event>,
        visited: &mut usize,
    ) {
        assert!(
            model.modeled_invariants_hold(),
            "invariant failed before events: path={path:?}, model={model:?}"
        );
        *visited += 1;
        if remaining == 0 {
            return;
        }
        for event in EVENTS {
            let mut next = model;
            let quarantined_before = model.phase == Phase::Quarantined;
            let result = apply_event(&mut next, event);
            path.push(event);
            if quarantined_before {
                assert_eq!(
                    next.phase,
                    Phase::Quarantined,
                    "quarantine phase escaped: path={path:?}, result={result:?}"
                );
                assert_eq!(
                    next.local, model.local,
                    "local state changed after quarantine"
                );
                assert_eq!(
                    next.anchor, model.anchor,
                    "anchor state changed after quarantine"
                );
                assert_eq!(
                    next.pending, model.pending,
                    "pending commit changed after quarantine"
                );
            }
            assert!(
                next.modeled_invariants_hold(),
                "invariant failed after result={result:?}: path={path:?}, model={next:?}"
            );
            explore_event_sequences(next, remaining - 1, path, visited);
            path.pop();
        }
    }

    #[test]
    fn bounded_event_sequence_exploration_preserves_model_invariants() {
        let initial = CommitModel::new(snap(1, 0x11));
        let mut path = Vec::new();
        let mut visited = 0;
        explore_event_sequences(initial, 5, &mut path, &mut visited);
        assert_eq!(
            visited,
            1 + 16 + 16usize.pow(2) + 16usize.pow(3) + 16usize.pow(4) + 16usize.pow(5)
        );
    }
}
