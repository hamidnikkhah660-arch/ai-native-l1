//! CP-0547 QFP6 node-admission coordinator candidate.
//!
//! Joins the QFP6 durable fork store to the independently administered Q6EA/ECR1 anchor.
//! This is a runtime seam, not a socket listener, miner, RPC server, mempool, or production
//! node binary. Only Acknowledged admissions may be translated into network/application ACKs.
//! A local manifest with an unresolved external anchor remains pending and MUST NOT be ACKed.

use crate::{
    external_cas_anchor_candidate::ExternalCasProviderTransport,
    qrun_v06_external_anchor_candidate::{
        QRunV06ExternalAnchorCoordinator, QRunV06ExternalAnchorError, QRunV06ExternalAnchorState,
    },
    qrun_v06_pow_fork_choice_candidate::{
        QRunV06PowForkChoice, QRunV06QuoteAssetAuthorizationProvider,
    },
    qrun_v06_pow_fork_store_candidate::{
        QRunV06DurableCommit, QRunV06DurableForkStore, QRunV06ForkStoreError,
    },
    qrun_v06_qap1_coordinator_candidate::{
        QRunV06Qap1AnchorTransport, QRunV06Qap1ExternalCoordinator,
    },
    state_machine::TransactionAuthenticator,
    v4_fat1_trust_candidate::MlDsa65Verifier,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QRunV06NodeRuntimeError {
    ForkStore(String),
    ExternalAnchor(String),
    ExternalAnchorStateMismatch,
    InvalidAnchorTransition(String),
    PendingAnchorMustBeReconciled,
    RecoveryRequired,
    NoPendingAnchorCommit,
    Qap1(String),
}

impl std::fmt::Display for QRunV06NodeRuntimeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ForkStore(error) => write!(f, "QFP6 node durable admission failed: {error}"),
            Self::ExternalAnchor(error) => write!(f, "QFP6 node external anchor failed: {error}"),
            Self::ExternalAnchorStateMismatch => f.write_str(
                "QFP6 local durable state differs from the independently provisioned external anchor state",
            ),
            Self::InvalidAnchorTransition(error) => {
                write!(f, "QFP6 node rejected its durable anchor transition: {error}")
            }
            Self::PendingAnchorMustBeReconciled => f.write_str(
                "QFP6 node has a locally committed block whose external anchor is unresolved; reconcile before admitting another block",
            ),
            Self::RecoveryRequired => f.write_str(
                "QFP6 node requires a fresh externally anchored store reopen before admission can continue",
            ),
            Self::NoPendingAnchorCommit => {
                f.write_str("QFP6 node has no pending external-anchor commit to reconcile")
            }
            Self::Qap1(error) => write!(f, "QFP6 QAP1 durable admission failed: {error}"),
        }
    }
}
impl std::error::Error for QRunV06NodeRuntimeError {}

impl From<QRunV06ForkStoreError> for QRunV06NodeRuntimeError {
    fn from(value: QRunV06ForkStoreError) -> Self {
        Self::ForkStore(value.to_string())
    }
}
impl From<QRunV06ExternalAnchorError> for QRunV06NodeRuntimeError {
    fn from(value: QRunV06ExternalAnchorError) -> Self {
        Self::ExternalAnchor(value.to_string())
    }
}

/// Minimal anchor contract consumed by the node admission coordinator.
pub trait QRunV06NodeAnchorGate {
    fn verify_current(&mut self, state: &QRunV06ExternalAnchorState) -> Result<(), String>;
    fn advance_after_local_commit(
        &mut self,
        current: &QRunV06ExternalAnchorState,
        next: &QRunV06ExternalAnchorState,
    ) -> Result<(), String>;

    /// Recover after process restart from an independently provisioned predecessor. The
    /// implementation must first reconcile an already-applied exact successor, and only
    /// issue the same bounded successor CAS when the provider still reports the predecessor.
    fn recover_durable_successor(
        &mut self,
        current: &QRunV06ExternalAnchorState,
        next: &QRunV06ExternalAnchorState,
    ) -> Result<(), String> {
        self.advance_after_local_commit(current, next)
    }
}

impl<P, V> QRunV06NodeAnchorGate for QRunV06ExternalAnchorCoordinator<P, V>
where
    P: ExternalCasProviderTransport,
    V: MlDsa65Verifier,
{
    fn verify_current(&mut self, state: &QRunV06ExternalAnchorState) -> Result<(), String> {
        self.verify_state(state)
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    fn advance_after_local_commit(
        &mut self,
        current: &QRunV06ExternalAnchorState,
        next: &QRunV06ExternalAnchorState,
    ) -> Result<(), String> {
        self.advance_after_durable_commit(current, next)
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    fn recover_durable_successor(
        &mut self,
        current: &QRunV06ExternalAnchorState,
        next: &QRunV06ExternalAnchorState,
    ) -> Result<(), String> {
        match self.reconcile_committed_state(next) {
            Ok(_) => Ok(()),
            Err(QRunV06ExternalAnchorError::StateMismatch) => self
                .advance_after_durable_commit(current, next)
                .map(|_| ())
                .map_err(|error| error.to_string()),
            Err(error) => Err(error.to_string()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QRunV06NodeAdmission {
    /// The local manifest and independent signed high-water state both advanced.
    /// This is the sole result that may be translated into a network/application ACK.
    Acknowledged(QRunV06DurableCommit),
    /// The local manifest is durable, but the independent anchor did not confirm its
    /// successor. Do not ACK; call reconcile_pending before admitting another block.
    ExternalAnchorPending(QRunV06DurableCommit),
}

impl QRunV06NodeAdmission {
    pub fn is_acknowledged(&self) -> bool {
        matches!(self, Self::Acknowledged(_))
    }

    pub fn durable_commit(&self) -> QRunV06DurableCommit {
        match self {
            Self::Acknowledged(commit) | Self::ExternalAnchorPending(commit) => *commit,
        }
    }
}

#[derive(Debug, Clone)]
struct PendingAnchorCommit {
    before: QRunV06ExternalAnchorState,
    after: QRunV06ExternalAnchorState,
    commit: QRunV06DurableCommit,
}

/// Node-side admission seam. Store creation/reopen remains explicit: callers must supply
/// a store opened with the manifest anchor from an independent provisioning channel, plus
/// the full expected Q6EA state from that channel.
pub struct QRunV06NodeRuntime<A: QRunV06NodeAnchorGate> {
    store: QRunV06DurableForkStore,
    anchor_gate: A,
    genesis_digest: [u8; 32],
    committed_anchor_state: QRunV06ExternalAnchorState,
    pending_anchor_commit: Option<PendingAnchorCommit>,
    recovery_required: bool,
    qap1_required: bool,
    qap1_recovered: bool,
}

impl<A: QRunV06NodeAnchorGate> QRunV06NodeRuntime<A> {
    /// Refuse startup unless the local store reproduces the exact independently provisioned
    /// Q6EA state and the external provider confirms that state as its current signed tip.
    pub fn new(
        store: QRunV06DurableForkStore,
        mut anchor_gate: A,
        genesis_digest: [u8; 32],
        independently_provisioned_state: QRunV06ExternalAnchorState,
    ) -> Result<Self, QRunV06NodeRuntimeError> {
        independently_provisioned_state.validate()?;
        if store.has_qap1_intent()? {
            return Err(QRunV06NodeRuntimeError::Qap1(
                "unresolved QAP1 intent exists; use the QAP1 recovery constructor".into(),
            ));
        }
        let actual = QRunV06ExternalAnchorState::from_store(&store, genesis_digest)?;
        if actual != independently_provisioned_state {
            return Err(QRunV06NodeRuntimeError::ExternalAnchorStateMismatch);
        }
        anchor_gate
            .verify_current(&actual)
            .map_err(QRunV06NodeRuntimeError::ExternalAnchor)?;
        Ok(Self {
            store,
            anchor_gate,
            genesis_digest,
            committed_anchor_state: actual,
            pending_anchor_commit: None,
            recovery_required: false,
            qap1_required: false,
            qap1_recovered: false,
        })
    }

    /// Restart recovery for a store whose local manifest may have committed immediately
    /// before the previous process stopped. The predecessor must come from the independent
    /// provisioning/anchor channel, never from the local manifest being recovered.
    ///
    /// The provider first reconciles whether the exact successor was already applied. If it
    /// was not, the coordinator retries only current -> this exact local successor. A stale,
    /// divergent or unverifiable provider state keeps startup closed.
    pub fn recover_after_process_restart(
        store: QRunV06DurableForkStore,
        mut anchor_gate: A,
        genesis_digest: [u8; 32],
        independently_provisioned_predecessor: QRunV06ExternalAnchorState,
    ) -> Result<Self, QRunV06NodeRuntimeError> {
        independently_provisioned_predecessor.validate()?;
        if store.has_qap1_intent()? {
            return Err(QRunV06NodeRuntimeError::Qap1(
                "unresolved QAP1 intent exists; use the QAP1 recovery constructor".into(),
            ));
        }
        let actual = QRunV06ExternalAnchorState::from_store(&store, genesis_digest)?;
        independently_provisioned_predecessor.validate_successor(&actual)?;
        anchor_gate
            .recover_durable_successor(&independently_provisioned_predecessor, &actual)
            .map_err(QRunV06NodeRuntimeError::ExternalAnchor)?;
        anchor_gate
            .verify_current(&actual)
            .map_err(QRunV06NodeRuntimeError::ExternalAnchor)?;
        Ok(Self {
            store,
            anchor_gate,
            genesis_digest,
            committed_anchor_state: actual,
            pending_anchor_commit: None,
            recovery_required: false,
            qap1_required: false,
            qap1_recovered: false,
        })
    }

    /// Restart constructor for the QAP1-only admission path. Any unresolved intent is
    /// resumed from its exact saved Provider request and Q6EA receipts before the Runtime is
    /// exposed. The legacy anchor gate is retained only for type compatibility; QAP1's separately
    /// pinned Provider and Anchor verifiers are the admission authority for this Runtime.
    pub fn recover_qap1_after_process_restart<P, PV, AV, Q>(
        mut store: QRunV06DurableForkStore,
        anchor_gate: A,
        mut coordinator: QRunV06Qap1ExternalCoordinator<P, PV, AV, Q>,
        genesis_digest: [u8; 32],
        authenticator: &impl TransactionAuthenticator,
        quote_authorizer: &mut QRunV06QuoteAssetAuthorizationProvider<'_>,
    ) -> Result<Self, QRunV06NodeRuntimeError>
    where
        P: ExternalCasProviderTransport,
        PV: MlDsa65Verifier + Clone,
        AV: MlDsa65Verifier,
        Q: QRunV06Qap1AnchorTransport,
    {
        let directory = store.qap1_directory()?;
        let has_intent = store.has_qap1_intent()?;
        let actual = QRunV06ExternalAnchorState::from_store(&store, genesis_digest)?;

        if !has_intent {
            coordinator
                .verify_current(&actual)
                .map_err(|error| QRunV06NodeRuntimeError::Qap1(error.to_string()))?;
            return Ok(Self {
                store,
                anchor_gate,
                genesis_digest,
                committed_anchor_state: actual,
                pending_anchor_commit: None,
                recovery_required: false,
                qap1_required: true,
                qap1_recovered: true,
            });
        }

        let mut journal = coordinator
            .load_latest_journal(&directory)
            .map_err(|error| QRunV06NodeRuntimeError::Qap1(error.to_string()))?
            .ok_or_else(|| {
                QRunV06NodeRuntimeError::Qap1(
                    "QAP1 directory has an unresolved/partial intent but no valid phase snapshot"
                        .into(),
                )
            })?;

        let local_is_predecessor = actual == *journal.predecessor();
        let local_is_successor = actual == *journal.successor();
        if !local_is_predecessor && !local_is_successor {
            return Err(QRunV06NodeRuntimeError::ExternalAnchorStateMismatch);
        }

        if journal.phase()
            < crate::qrun_v06_qap1_journal_candidate::QRunV06Qap1Phase::LocalManifestCommitted
        {
            if journal.phase()
                != crate::qrun_v06_qap1_journal_candidate::QRunV06Qap1Phase::AnchorConfirmed
            {
                if !local_is_predecessor {
                    return Err(QRunV06NodeRuntimeError::Qap1(
                        "local Manifest advanced before QAP1 AnchorConfirmed".into(),
                    ));
                }
                journal = coordinator
                    .advance_to_anchor_confirmed(&directory, journal)
                    .map_err(|error| QRunV06NodeRuntimeError::Qap1(error.to_string()))?;
            } else {
                journal
                    .verify_saved_evidence(
                        coordinator.provider_pin(),
                        coordinator.anchor_pin(),
                        coordinator.provider_verifier(),
                        coordinator.anchor_verifier(),
                    )
                    .map_err(|error| QRunV06NodeRuntimeError::Qap1(error.to_string()))?;
            }
            coordinator
                .verify_current(journal.successor())
                .map_err(|error| QRunV06NodeRuntimeError::Qap1(error.to_string()))?;

            if local_is_predecessor {
                let prepared = store
                    .prepare_with_quote_asset_authorization(
                        journal.candidate_envelope(),
                        authenticator,
                        quote_authorizer,
                    )?
                    .ok_or_else(|| {
                        QRunV06NodeRuntimeError::Qap1(
                            "saved QAP1 candidate did not reproduce a new prepared transition"
                                .into(),
                        )
                    })?;
                let recomputed_successor =
                    store.external_anchor_state_for_prepared(&prepared, genesis_digest)?;
                if prepared.candidate_envelope() != journal.candidate_envelope()
                    || prepared.manifest_bytes() != journal.next_manifest_bytes()
                    || recomputed_successor != *journal.successor()
                {
                    return Err(QRunV06NodeRuntimeError::Qap1(
                        "replayed QFP6 candidate differs from immutable QAP1 intent".into(),
                    ));
                }
                store.publish_prepared_with_qap1(
                    prepared,
                    &journal,
                    coordinator.provider_pin(),
                    coordinator.anchor_pin(),
                    coordinator.provider_verifier(),
                    coordinator.anchor_verifier(),
                )?;
            }
        } else if !local_is_successor {
            return Err(QRunV06NodeRuntimeError::Qap1(
                "QAP1 says local Manifest was committed but QFP6 still exposes predecessor".into(),
            ));
        }

        store.verify_published_successor_with_qap1(
            &journal,
            coordinator.provider_pin(),
            coordinator.anchor_pin(),
            coordinator.provider_verifier(),
            coordinator.anchor_verifier(),
        )?;
        let local_successor = QRunV06ExternalAnchorState::from_store(&store, genesis_digest)?;
        if local_successor != *journal.successor() {
            return Err(QRunV06NodeRuntimeError::ExternalAnchorStateMismatch);
        }

        if journal.phase()
            == crate::qrun_v06_qap1_journal_candidate::QRunV06Qap1Phase::AnchorConfirmed
        {
            let local_committed = journal
                .mark_local_manifest_committed(&local_successor, coordinator.provider_pin())
                .map_err(|error| QRunV06NodeRuntimeError::Qap1(error.to_string()))?;
            local_committed
                .persist_transition(
                    &directory,
                    &journal,
                    coordinator.provider_pin(),
                    coordinator.anchor_pin(),
                    coordinator.provider_verifier(),
                    coordinator.anchor_verifier(),
                )
                .map_err(|error| QRunV06NodeRuntimeError::Qap1(error.to_string()))?;
            journal = local_committed;
        }

        match journal.phase() {
            crate::qrun_v06_qap1_journal_candidate::QRunV06Qap1Phase::LocalManifestCommitted => {
                journal
                    .finalize_and_clear(
                        &directory,
                        &local_successor,
                        coordinator.provider_pin(),
                        coordinator.anchor_pin(),
                        coordinator.provider_verifier(),
                        coordinator.anchor_verifier(),
                    )
                    .map_err(|error| QRunV06NodeRuntimeError::Qap1(error.to_string()))?;
            }
            crate::qrun_v06_qap1_journal_candidate::QRunV06Qap1Phase::Finalized => {
                journal
                    .cleanup_finalized(
                        &directory,
                        &local_successor,
                        coordinator.provider_pin(),
                        coordinator.anchor_pin(),
                        coordinator.provider_verifier(),
                        coordinator.anchor_verifier(),
                    )
                    .map_err(|error| QRunV06NodeRuntimeError::Qap1(error.to_string()))?;
            }
            _ => {
                return Err(QRunV06NodeRuntimeError::Qap1(
                    "QAP1 recovery stopped at an unsupported phase".into(),
                ));
            }
        }

        coordinator
            .verify_current(&local_successor)
            .map_err(|error| QRunV06NodeRuntimeError::Qap1(error.to_string()))?;

        Ok(Self {
            store,
            anchor_gate,
            genesis_digest,
            committed_anchor_state: local_successor,
            pending_anchor_commit: None,
            recovery_required: false,
            qap1_required: true,
            qap1_recovered: true,
        })
    }

    /// Validate, execute, persist and externally anchor one QFP6 envelope.
    /// Q6TS/Q6QA authorization is requested by fork choice for every non-native quote block.
    /// Only a return value for which is_acknowledged() is true may be propagated as an ACK.
    pub fn submit_envelope<T: TransactionAuthenticator>(
        &mut self,
        envelope: &[u8],
        authenticator: &T,
        quote_authorizer: &mut QRunV06QuoteAssetAuthorizationProvider<'_>,
    ) -> Result<QRunV06NodeAdmission, QRunV06NodeRuntimeError> {
        if self.qap1_required {
            return Err(QRunV06NodeRuntimeError::Qap1(
                "legacy admission is disabled for a QAP1-required runtime".into(),
            ));
        }
        if self.recovery_required {
            return Err(QRunV06NodeRuntimeError::RecoveryRequired);
        }
        if self.pending_anchor_commit.is_some() {
            return Err(QRunV06NodeRuntimeError::PendingAnchorMustBeReconciled);
        }
        if self.store.has_qap1_intent()? {
            self.recovery_required = true;
            return Err(QRunV06NodeRuntimeError::Qap1(
                "durable QAP1 intent blocks legacy admission".into(),
            ));
        }

        let before = self.committed_anchor_state.clone();
        let commit = self.store.submit_with_quote_asset_authorization(
            envelope,
            authenticator,
            quote_authorizer,
        )?;

        // Re-submitting an already archived envelope is idempotent and creates no new
        // manifest generation. The current independently anchored tip remains unchanged.
        if commit.generation == before.manifest_generation
            && commit.manifest_anchor == before.manifest_anchor
        {
            return Ok(QRunV06NodeAdmission::Acknowledged(commit));
        }

        let after = match QRunV06ExternalAnchorState::from_store(&self.store, self.genesis_digest) {
            Ok(state) => state,
            Err(error) => {
                self.recovery_required = true;
                return Err(QRunV06NodeRuntimeError::ExternalAnchor(error.to_string()));
            }
        };
        if let Err(error) = before.validate_successor(&after) {
            self.recovery_required = true;
            return Err(QRunV06NodeRuntimeError::InvalidAnchorTransition(
                error.to_string(),
            ));
        }

        match self.anchor_gate.advance_after_local_commit(&before, &after) {
            Ok(()) => {
                self.committed_anchor_state = after;
                Ok(QRunV06NodeAdmission::Acknowledged(commit))
            }
            Err(_) => {
                self.pending_anchor_commit = Some(PendingAnchorCommit {
                    before,
                    after,
                    commit,
                });
                Ok(QRunV06NodeAdmission::ExternalAnchorPending(commit))
            }
        }
    }

    /// QAP1-protected admission path. The active QFP6 manifest is not published until the
    /// signed Provider CAS, signed Q6EA CAS and a fresh signed Q6EA Read have all been verified.
    /// On any failure after the intent is persisted, this runtime instance is poisoned and must
    /// be reopened/recovered; it must not admit another block through the legacy path.
    pub fn submit_envelope_with_qap1<P, PV, AV, Q>(
        &mut self,
        envelope: &[u8],
        authenticator: &impl TransactionAuthenticator,
        quote_authorizer: &mut QRunV06QuoteAssetAuthorizationProvider<'_>,
        coordinator: &mut QRunV06Qap1ExternalCoordinator<P, PV, AV, Q>,
    ) -> Result<QRunV06NodeAdmission, QRunV06NodeRuntimeError>
    where
        P: ExternalCasProviderTransport,
        PV: MlDsa65Verifier + Clone,
        AV: MlDsa65Verifier,
        Q: QRunV06Qap1AnchorTransport,
    {
        self.qap1_required = true;
        if self.recovery_required {
            return Err(QRunV06NodeRuntimeError::RecoveryRequired);
        }
        if self.pending_anchor_commit.is_some() {
            return Err(QRunV06NodeRuntimeError::PendingAnchorMustBeReconciled);
        }
        if self.store.has_qap1_intent()? {
            self.recovery_required = true;
            return Err(QRunV06NodeRuntimeError::Qap1(
                "an unresolved QAP1 journal already exists; recover it before preparing another block".into(),
            ));
        }

        let prepared = self.store.prepare_with_quote_asset_authorization(
            envelope,
            authenticator,
            quote_authorizer,
        )?;
        let Some(prepared) = prepared else {
            // An already archived envelope is idempotent. The legacy submit call performs no
            // new manifest generation for this case and preserves the historical outcome shape.
            let commit = self.store.submit_with_quote_asset_authorization(
                envelope,
                authenticator,
                quote_authorizer,
            )?;
            return Ok(QRunV06NodeAdmission::Acknowledged(commit));
        };

        let before = self.committed_anchor_state.clone();
        let result = (|| {
            let successor = self
                .store
                .external_anchor_state_for_prepared(&prepared, self.genesis_digest)?;
            let journal_directory = self.store.qap1_directory()?;
            let journal = coordinator
                .prepare_intent(&self.store, &prepared, &before, &successor)
                .map_err(|error| QRunV06NodeRuntimeError::Qap1(error.to_string()))?;
            let confirmed = coordinator
                .advance_to_anchor_confirmed(&journal_directory, journal)
                .map_err(|error| QRunV06NodeRuntimeError::Qap1(error.to_string()))?;
            coordinator
                .verify_current(&successor)
                .map_err(|error| QRunV06NodeRuntimeError::Qap1(error.to_string()))?;

            let commit = self.store.publish_prepared_with_qap1(
                prepared,
                &confirmed,
                coordinator.provider_pin(),
                coordinator.anchor_pin(),
                coordinator.provider_verifier(),
                coordinator.anchor_verifier(),
            )?;
            self.store.verify_published_successor_with_qap1(
                &confirmed,
                coordinator.provider_pin(),
                coordinator.anchor_pin(),
                coordinator.provider_verifier(),
                coordinator.anchor_verifier(),
            )?;
            let local_successor =
                QRunV06ExternalAnchorState::from_store(&self.store, self.genesis_digest)?;
            let local_committed = confirmed
                .mark_local_manifest_committed(&local_successor, coordinator.provider_pin())
                .map_err(|error| QRunV06NodeRuntimeError::Qap1(error.to_string()))?;
            local_committed
                .persist_transition(
                    &journal_directory,
                    &confirmed,
                    coordinator.provider_pin(),
                    coordinator.anchor_pin(),
                    coordinator.provider_verifier(),
                    coordinator.anchor_verifier(),
                )
                .map_err(|error| QRunV06NodeRuntimeError::Qap1(error.to_string()))?;
            local_committed
                .finalize_and_clear(
                    &journal_directory,
                    &local_successor,
                    coordinator.provider_pin(),
                    coordinator.anchor_pin(),
                    coordinator.provider_verifier(),
                    coordinator.anchor_verifier(),
                )
                .map_err(|error| QRunV06NodeRuntimeError::Qap1(error.to_string()))?;
            Ok::<_, QRunV06NodeRuntimeError>((commit, local_successor))
        })();

        match result {
            Ok((commit, successor)) => {
                self.committed_anchor_state = successor;
                Ok(QRunV06NodeAdmission::Acknowledged(commit))
            }
            Err(error) => {
                self.recovery_required = true;
                Err(error)
            }
        }
    }

    /// Resolve an unacknowledged local commit. The concrete CAS coordinator retries the
    /// same exact transition and first reconciles a potentially-lost successful CAS result.
    /// Only success clears the pending record and returns an ACK-safe admission result.
    pub fn reconcile_pending(&mut self) -> Result<QRunV06NodeAdmission, QRunV06NodeRuntimeError> {
        if self.recovery_required {
            return Err(QRunV06NodeRuntimeError::RecoveryRequired);
        }
        let pending = self
            .pending_anchor_commit
            .as_ref()
            .ok_or(QRunV06NodeRuntimeError::NoPendingAnchorCommit)?;

        self.anchor_gate
            .advance_after_local_commit(&pending.before, &pending.after)
            .map_err(QRunV06NodeRuntimeError::ExternalAnchor)?;

        let pending = self
            .pending_anchor_commit
            .take()
            .ok_or(QRunV06NodeRuntimeError::NoPendingAnchorCommit)?;
        self.committed_anchor_state = pending.after;
        Ok(QRunV06NodeAdmission::Acknowledged(pending.commit))
    }

    pub fn canonical_height(&self) -> Result<u64, QRunV06NodeRuntimeError> {
        self.store.canonical_height().map_err(Into::into)
    }

    pub fn canonical_tip(&self) -> Result<[u8; 32], QRunV06NodeRuntimeError> {
        self.store.canonical_tip().map_err(Into::into)
    }

    pub fn manifest_generation(&self) -> Result<u64, QRunV06NodeRuntimeError> {
        self.store.generation().map_err(Into::into)
    }

    pub fn committed_anchor_state(&self) -> &QRunV06ExternalAnchorState {
        &self.committed_anchor_state
    }

    /// Return a fresh in-memory fork-choice view rebuilt from this Runtime's durable store.
    /// Supervisors must call this after peer QAP1 admission before the local miner chooses a tip.
    pub fn fork_choice_snapshot(&self) -> Result<QRunV06PowForkChoice, QRunV06NodeRuntimeError> {
        self.store
            .graph()
            .cloned()
            .map_err(|error| QRunV06NodeRuntimeError::ForkStore(format!("{error:?}")))
    }

    pub fn has_pending_external_anchor(&self) -> bool {
        self.pending_anchor_commit.is_some()
    }

    pub fn requires_reopen(&self) -> bool {
        self.recovery_required
    }

    /// Whether this runtime was recovered/configured to require the QAP1 admission path.
    /// A network-facing supervisor must require this to be true before binding its listener.
    pub fn requires_qap1(&self) -> bool {
        self.qap1_required
    }

    /// True only after the QAP1 restart constructor verified the Provider and Q6EA state.
    pub fn qap1_recovery_verified(&self) -> bool {
        self.qap1_recovered
    }
}

/// Minimal bounded QFP6 peer block frame. This codec is intentionally separate from the
/// QFP5 QRB5/QRA5 transport and is not wired into the v0.5 executable.
pub const QRUN_V06_PEER_BLOCK_MAGIC: [u8; 4] = *b"Q6PB";
pub const QRUN_V06_PEER_ADMISSION_MAGIC: [u8; 4] = *b"Q6PA";
pub const QRUN_V06_PEER_FRAME_VERSION: u16 = 1;
pub const QRUN_V06_PEER_BLOCK_HEADER_BYTES: usize = 20;
pub const QRUN_V06_PEER_ADMISSION_RESPONSE_BYTES: usize = 128;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QRunV06PeerIngressError {
    Incomplete,
    BadMagic,
    UnsupportedVersion(u16),
    WrongMessageType,
    Oversize,
    LengthMismatch,
    Io(String),
}

impl std::fmt::Display for QRunV06PeerIngressError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for QRunV06PeerIngressError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QRunV06PeerBlockRequest {
    pub request_id: u64,
    pub envelope: Vec<u8>,
}

pub fn encode_qrun_v06_peer_block_request(
    request_id: u64,
    envelope: &[u8],
) -> Result<Vec<u8>, QRunV06PeerIngressError> {
    if envelope.is_empty()
        || envelope.len() > crate::qrun_v06_pow_wire_candidate::MAX_QRUN_V06_POW_ENVELOPE_BYTES
    {
        return Err(QRunV06PeerIngressError::Oversize);
    }
    let length = u32::try_from(envelope.len()).map_err(|_| QRunV06PeerIngressError::Oversize)?;
    let mut frame = Vec::with_capacity(QRUN_V06_PEER_BLOCK_HEADER_BYTES + envelope.len());
    frame.extend_from_slice(&QRUN_V06_PEER_BLOCK_MAGIC);
    frame.extend_from_slice(&QRUN_V06_PEER_FRAME_VERSION.to_be_bytes());
    frame.extend_from_slice(&1u16.to_be_bytes());
    frame.extend_from_slice(&request_id.to_be_bytes());
    frame.extend_from_slice(&length.to_be_bytes());
    frame.extend_from_slice(envelope);
    Ok(frame)
}

pub fn decode_qrun_v06_peer_block_request(
    frame: &[u8],
) -> Result<QRunV06PeerBlockRequest, QRunV06PeerIngressError> {
    if frame.len() < QRUN_V06_PEER_BLOCK_HEADER_BYTES {
        return Err(QRunV06PeerIngressError::Incomplete);
    }
    if frame[..4] != QRUN_V06_PEER_BLOCK_MAGIC {
        return Err(QRunV06PeerIngressError::BadMagic);
    }
    let version = u16::from_be_bytes([frame[4], frame[5]]);
    if version != QRUN_V06_PEER_FRAME_VERSION {
        return Err(QRunV06PeerIngressError::UnsupportedVersion(version));
    }
    if frame[6..8] != 1u16.to_be_bytes() {
        return Err(QRunV06PeerIngressError::WrongMessageType);
    }
    let request_id = u64::from_be_bytes(frame[8..16].try_into().unwrap());
    let declared = u32::from_be_bytes(frame[16..20].try_into().unwrap()) as usize;
    if declared == 0
        || declared > crate::qrun_v06_pow_wire_candidate::MAX_QRUN_V06_POW_ENVELOPE_BYTES
    {
        return Err(QRunV06PeerIngressError::Oversize);
    }
    if frame.len() != QRUN_V06_PEER_BLOCK_HEADER_BYTES + declared {
        return Err(QRunV06PeerIngressError::LengthMismatch);
    }
    Ok(QRunV06PeerBlockRequest {
        request_id,
        envelope: frame[QRUN_V06_PEER_BLOCK_HEADER_BYTES..].to_vec(),
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum QRunV06PeerAdmissionStatus {
    /// This is the only positive peer acknowledgement status.
    Accepted = 1,
    /// Local storage committed, but the independent Q6EA anchor is not yet confirmed.
    /// A peer must not interpret this status as an acknowledgement.
    Deferred = 2,
    /// The envelope or its admission was rejected. No positive acknowledgement is implied.
    Rejected = 3,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QRunV06PeerAdmissionResponse {
    request_id: u64,
    status: QRunV06PeerAdmissionStatus,
    commit: Option<QRunV06DurableCommit>,
}

impl QRunV06PeerAdmissionResponse {
    pub fn request_id(&self) -> u64 {
        self.request_id
    }

    pub fn status(&self) -> QRunV06PeerAdmissionStatus {
        self.status
    }

    pub fn durable_commit(&self) -> Option<QRunV06DurableCommit> {
        self.commit
    }

    pub fn is_positive_ack(&self) -> bool {
        self.status == QRunV06PeerAdmissionStatus::Accepted && self.commit.is_some()
    }

    /// Fixed 128-byte Q6PA response. Commit fields are zeroed unless status is Accepted.
    pub fn encode(&self) -> [u8; QRUN_V06_PEER_ADMISSION_RESPONSE_BYTES] {
        let mut bytes = [0u8; QRUN_V06_PEER_ADMISSION_RESPONSE_BYTES];
        bytes[..4].copy_from_slice(&QRUN_V06_PEER_ADMISSION_MAGIC);
        bytes[4..6].copy_from_slice(&QRUN_V06_PEER_FRAME_VERSION.to_be_bytes());
        bytes[6..8].copy_from_slice(&(self.status as u16).to_be_bytes());
        bytes[8..16].copy_from_slice(&self.request_id.to_be_bytes());
        if self.status == QRunV06PeerAdmissionStatus::Accepted {
            if let Some(commit) = self.commit {
                bytes[16..48].copy_from_slice(&commit.outcome.block_digest);
                bytes[48..80].copy_from_slice(&commit.outcome.canonical_tip);
                bytes[80..88].copy_from_slice(&commit.outcome.canonical_height.to_be_bytes());
                bytes[88..96].copy_from_slice(&commit.generation.to_be_bytes());
                bytes[96..128].copy_from_slice(&commit.manifest_anchor);
            }
        }
        bytes
    }
}

/// Session-local replay protection for Q6PB request identifiers.
/// Create one guard per already-authenticated peer session, retain it for the entire
/// session, and never share it across peers. This guard does not authenticate a peer,
/// persist replay state across reconnects, or replace the required Noise identity binding.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct QRunV06PeerReplayGuard {
    last_request_id: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QRunV06PeerReplayError {
    ZeroRequestId,
    NonMonotonic { received: u64, last_accepted: u64 },
}

impl QRunV06PeerReplayGuard {
    pub const fn new() -> Self {
        Self {
            last_request_id: None,
        }
    }

    pub fn last_request_id(&self) -> Option<u64> {
        self.last_request_id
    }

    /// Accepts a strictly increasing, non-zero request ID.
    /// IDs are consumed before block validation so rejected requests cannot be replayed.
    pub fn accept(&mut self, request_id: u64) -> Result<(), QRunV06PeerReplayError> {
        if request_id == 0 {
            return Err(QRunV06PeerReplayError::ZeroRequestId);
        }
        if let Some(last_accepted) = self.last_request_id {
            if request_id <= last_accepted {
                return Err(QRunV06PeerReplayError::NonMonotonic {
                    received: request_id,
                    last_accepted,
                });
            }
        }
        self.last_request_id = Some(request_id);
        Ok(())
    }
}

/// Process one bounded Q6PB frame through the QAP1-protected admission path.
/// Request IDs are consumed before execution. A positive Accepted response is emitted only
/// after Provider CAS, Q6EA CAS, fresh signed Q6EA Read, local Manifest publication,
/// read-back verification and journal finalization have all succeeded. Any failure is fail-closed.
pub fn process_qrun_v06_peer_block_frame_with_qap1<A, T, P, PV, AV, Q>(
    runtime: &mut QRunV06NodeRuntime<A>,
    replay_guard: &mut QRunV06PeerReplayGuard,
    frame: &[u8],
    authenticator: &T,
    quote_authorizer: &mut QRunV06QuoteAssetAuthorizationProvider<'_>,
    coordinator: &mut QRunV06Qap1ExternalCoordinator<P, PV, AV, Q>,
) -> Result<QRunV06PeerAdmissionResponse, QRunV06PeerIngressError>
where
    A: QRunV06NodeAnchorGate,
    T: TransactionAuthenticator,
    P: ExternalCasProviderTransport,
    PV: MlDsa65Verifier + Clone,
    AV: MlDsa65Verifier,
    Q: QRunV06Qap1AnchorTransport,
{
    let request = decode_qrun_v06_peer_block_request(frame)?;
    let (status, commit) = if replay_guard.accept(request.request_id).is_err() {
        (QRunV06PeerAdmissionStatus::Rejected, None)
    } else {
        match runtime.submit_envelope_with_qap1(
            &request.envelope,
            authenticator,
            quote_authorizer,
            coordinator,
        ) {
            Ok(QRunV06NodeAdmission::Acknowledged(commit)) => {
                (QRunV06PeerAdmissionStatus::Accepted, Some(commit))
            }
            Ok(QRunV06NodeAdmission::ExternalAnchorPending(_)) => {
                (QRunV06PeerAdmissionStatus::Deferred, None)
            }
            Err(_) => (QRunV06PeerAdmissionStatus::Rejected, None),
        }
    };
    Ok(QRunV06PeerAdmissionResponse {
        request_id: request.request_id,
        status,
        commit,
    })
}

/// Process one bounded Q6PB peer frame through the QFP6 node admission coordinator.
/// The caller must supply the guard belonging to this peer's authenticated session.
/// Runtime errors or replayed IDs become a Rejected response. Only the coordinator's
/// Acknowledged state becomes Accepted; ExternalAnchorPending is Deferred and carries no
/// commit/ACK fields. This remains a transport seam, not a socket listener or production node.
pub fn process_qrun_v06_peer_block_frame<A, T>(
    runtime: &mut QRunV06NodeRuntime<A>,
    replay_guard: &mut QRunV06PeerReplayGuard,
    frame: &[u8],
    authenticator: &T,
    quote_authorizer: &mut QRunV06QuoteAssetAuthorizationProvider<'_>,
) -> Result<QRunV06PeerAdmissionResponse, QRunV06PeerIngressError>
where
    A: QRunV06NodeAnchorGate,
    T: TransactionAuthenticator,
{
    let request = decode_qrun_v06_peer_block_request(frame)?;
    let (status, commit) = if replay_guard.accept(request.request_id).is_err() {
        (QRunV06PeerAdmissionStatus::Rejected, None)
    } else {
        match runtime.submit_envelope(&request.envelope, authenticator, quote_authorizer) {
            Ok(QRunV06NodeAdmission::Acknowledged(commit)) => {
                (QRunV06PeerAdmissionStatus::Accepted, Some(commit))
            }
            Ok(QRunV06NodeAdmission::ExternalAnchorPending(_)) => {
                (QRunV06PeerAdmissionStatus::Deferred, None)
            }
            Err(_) => (QRunV06PeerAdmissionStatus::Rejected, None),
        }
    };
    Ok(QRunV06PeerAdmissionResponse {
        request_id: request.request_id,
        status,
        commit,
    })
}

/// Read exactly one bounded Q6PB frame from a byte stream.
///
/// The fixed header is validated before payload allocation. An oversized peer-controlled
/// length is rejected without allocating based on that length. A successful call consumes
/// exactly one frame and leaves following frame bytes on the stream.
pub fn read_qrun_v06_peer_block_frame<R: std::io::Read>(
    reader: &mut R,
) -> Result<Vec<u8>, QRunV06PeerIngressError> {
    let mut header = [0u8; QRUN_V06_PEER_BLOCK_HEADER_BYTES];
    reader.read_exact(&mut header).map_err(|error| {
        if error.kind() == std::io::ErrorKind::UnexpectedEof {
            QRunV06PeerIngressError::Incomplete
        } else {
            QRunV06PeerIngressError::Io(error.to_string())
        }
    })?;

    if header[..4] != QRUN_V06_PEER_BLOCK_MAGIC {
        return Err(QRunV06PeerIngressError::BadMagic);
    }
    let version = u16::from_be_bytes([header[4], header[5]]);
    if version != QRUN_V06_PEER_FRAME_VERSION {
        return Err(QRunV06PeerIngressError::UnsupportedVersion(version));
    }
    if header[6..8] != 1u16.to_be_bytes() {
        return Err(QRunV06PeerIngressError::WrongMessageType);
    }

    let declared = u32::from_be_bytes(header[16..20].try_into().unwrap()) as usize;
    if declared == 0
        || declared > crate::qrun_v06_pow_wire_candidate::MAX_QRUN_V06_POW_ENVELOPE_BYTES
    {
        return Err(QRunV06PeerIngressError::Oversize);
    }

    let total = QRUN_V06_PEER_BLOCK_HEADER_BYTES
        .checked_add(declared)
        .ok_or(QRunV06PeerIngressError::Oversize)?;
    let mut frame = Vec::with_capacity(total);
    frame.extend_from_slice(&header);
    frame.resize(total, 0);
    reader
        .read_exact(&mut frame[QRUN_V06_PEER_BLOCK_HEADER_BYTES..])
        .map_err(|error| {
            if error.kind() == std::io::ErrorKind::UnexpectedEof {
                QRunV06PeerIngressError::Incomplete
            } else {
                QRunV06PeerIngressError::Io(error.to_string())
            }
        })?;
    decode_qrun_v06_peer_block_request(&frame)?;
    Ok(frame)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QRunV06PeerTransportError {
    InvalidFrame(QRunV06PeerIngressError),
    Noise(String),
    Io(String),
}

/// Handle exactly one Q6PB request and write one fixed Q6PA response on a Read+Write stream.
/// The replay guard must belong exclusively to this already-authenticated peer session and
/// must remain alive across every request on that session. This function does not open a
/// socket, authenticate a peer, set I/O deadlines, or enforce connection quotas.
pub fn handle_qrun_v06_peer_stream<S, A, T>(
    stream: &mut S,
    runtime: &mut QRunV06NodeRuntime<A>,
    replay_guard: &mut QRunV06PeerReplayGuard,
    authenticator: &T,
    quote_authorizer: &mut QRunV06QuoteAssetAuthorizationProvider<'_>,
) -> Result<QRunV06PeerAdmissionResponse, QRunV06PeerTransportError>
where
    S: std::io::Read + std::io::Write,
    A: QRunV06NodeAnchorGate,
    T: TransactionAuthenticator,
{
    let frame =
        read_qrun_v06_peer_block_frame(stream).map_err(QRunV06PeerTransportError::InvalidFrame)?;
    let response = process_qrun_v06_peer_block_frame(
        runtime,
        replay_guard,
        &frame,
        authenticator,
        quote_authorizer,
    )
    .map_err(QRunV06PeerTransportError::InvalidFrame)?;
    stream
        .write_all(&response.encode())
        .map_err(|error| QRunV06PeerTransportError::Io(error.to_string()))?;
    stream
        .flush()
        .map_err(|error| QRunV06PeerTransportError::Io(error.to_string()))?;
    Ok(response)
}

/// Handle one encrypted QFP6 peer request inside an already authenticated, two-sided pinned
/// Noise XX session. The replay guard is session-owned and must outlive every request on the
/// connection. The TCP stream itself is supplied by the caller: this function does not bind,
/// accept, discover peers, or manage listener lifecycle/connection quotas.
pub fn handle_qrun_v06_noise_peer_request<A, T>(
    stream: &mut std::net::TcpStream,
    noise: &mut crate::qrun_v06_noise_transport_candidate::QRunV06NoiseSession,
    runtime: &mut QRunV06NodeRuntime<A>,
    replay_guard: &mut QRunV06PeerReplayGuard,
    authenticator: &T,
    quote_authorizer: &mut QRunV06QuoteAssetAuthorizationProvider<'_>,
) -> Result<QRunV06PeerAdmissionResponse, QRunV06PeerTransportError>
where
    A: QRunV06NodeAnchorGate,
    T: TransactionAuthenticator,
{
    let frame = noise
        .read_record(stream)
        .map_err(|error| QRunV06PeerTransportError::Noise(error.to_string()))?;
    let response = process_qrun_v06_peer_block_frame(
        runtime,
        replay_guard,
        &frame,
        authenticator,
        quote_authorizer,
    )
    .map_err(QRunV06PeerTransportError::InvalidFrame)?;
    noise
        .write_record(stream, &response.encode())
        .map_err(|error| QRunV06PeerTransportError::Noise(error.to_string()))?;
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        consensus::{pow_digest, ConsensusParameters, PowAlgorithm, PowHeader, Uint256},
        external_cas_anchor_candidate::{
            ExternalCasPin, ExternalCasProviderTransport, ExternalCasReadRequest,
            ExternalCasReceipt, ExternalCasReceiptKind, ExternalCasReceiptOutcome,
            ExternalCasRecord, ExternalCasWriteRequest,
        },
        external_cas_floor_store_candidate::ExternalCasFloorStore,
        external_cas_offhost_anchor_candidate::ExternalCasOffhostAnchorState,
        external_cas_offhost_anchor_protocol_candidate::{
            ExternalCasOffhostAnchorCasRequest, ExternalCasOffhostAnchorMemoryModel,
            ExternalCasOffhostAnchorPin, ExternalCasOffhostAnchorReadRequest,
            ExternalCasOffhostAnchorReceipt, OffhostAnchorReceiptSigner,
        },
        qrun_v06_canonical_execution_candidate::{
            QRunV06Block, QRunV06BlockOperation, QRunV06CanonicalExecutionState,
        },
        qrun_v06_external_anchor_candidate::QRunV06ExternalAnchorPin,
        qrun_v06_hybrid_auth_candidate::{
            QRunV06HybridTransactionAuthenticator, QRunV06HybridTransactionSigner,
        },
        qrun_v06_node_supervisor_candidate::process_qfp6_application_frame_with_qap1,
        qrun_v06_noise_transport_candidate::QRunV06NoiseSession,
        qrun_v06_peer_listener_candidate::{serve_qfp6_noise_listener, QRunV06PeerListenerConfig},
        qrun_v06_pow_wire_candidate::{encode_qrun_v06_pow_block, qrun_v06_pow_state_commitment},
        qrun_v06_profile_trust_candidate::QRunV06TrustAuthorizedQuoteAsset,
        qrun_v06_qap1_coordinator_candidate::{
            QRunV06Qap1AnchorTransport, QRunV06Qap1ExternalCoordinator,
        },
        qrun_v06_tokenomics_candidate::{QRunV06MiningScheduleCandidate, QRunV06TokenomicsState},
        qrun_v06_transaction_ingress_candidate::{
            decode_q6ta_response, encode_q6ti_transaction_request, QRunV06TransactionSubmitStatus,
        },
        qrun_v06_transaction_journal_candidate::QRunV06TransactionJournal,
        qrun_v06_transaction_mempool_candidate::{
            QRunV06MempoolLimits, QRunV06NativeTransactionMempool,
        },
        state_machine::{
            transaction_id_with_signature_limit, AccountId, Transaction, TransactionAuthenticator,
            QRUN_V06_MAX_NATIVE_TX_SIGNATURE_BYTES,
        },
        v4_fat1_mldsa65_candidate::LibcruxMlDsa65VerifierCandidate,
        v4_fat1_trust_candidate::{ML_DSA_65_PUBLIC_KEY_BYTES, ML_DSA_65_SIGNATURE_BYTES},
    };
    use libcrux_ml_dsa::ml_dsa_65::{portable, MLDSA65SigningKey};
    use std::{
        env, fs,
        net::{SocketAddr, TcpListener, TcpStream},
        path::Path,
        process::{Command, Stdio},
        sync::{atomic::AtomicBool, Arc, Mutex},
        thread,
        time::{Duration, Instant, SystemTime, UNIX_EPOCH},
    };

    const NETWORK: [u8; 32] = [0x71; 32];
    const PROFILE: [u8; 32] = [0x72; 32];
    const OWNER: [u8; 32] = [0x73; 32];
    const PRODUCER: [u8; 32] = [0x74; 32];
    const GENESIS_DIGEST: [u8; 32] = [0x75; 32];

    struct EmptyAuthenticator;
    impl TransactionAuthenticator for EmptyAuthenticator {
        fn verify(&self, _: &AccountId, _: &[u8; 32], _: &[u8]) -> Result<(), ()> {
            Err(())
        }
    }

    struct TestPeerStream {
        input: std::io::Cursor<Vec<u8>>,
        output: Vec<u8>,
    }

    impl TestPeerStream {
        fn new(input: Vec<u8>) -> Self {
            Self {
                input: std::io::Cursor::new(input),
                output: Vec::new(),
            }
        }
    }

    impl std::io::Read for TestPeerStream {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            std::io::Read::read(&mut self.input, buf)
        }
    }

    impl std::io::Write for TestPeerStream {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.output.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    struct TestDir(std::path::PathBuf);
    impl TestDir {
        fn new() -> Self {
            let tick = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let path =
                env::temp_dir().join(format!("qfp6_node_runtime_{}_{}", std::process::id(), tick));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
            let _ = fs::remove_dir_all(self.0.with_extension("qap1-floor"));
        }
    }

    fn params() -> ConsensusParameters {
        let mut params = ConsensusParameters::candidate_testnet().unwrap();
        params.protocol_version = 6;
        params.target_block_time_secs = 30;
        params.difficulty_window_blocks = 2;
        params.difficulty_min_ratio_divisor = 4;
        params.difficulty_max_ratio = 4;
        params.initial_target = Uint256::from_be_bytes([0x7F; 32]);
        params.pow_limit = Uint256::MAX;
        params.pow = crate::consensus::PowParameters {
            algorithm: PowAlgorithm::Argon2id,
            memory_kib: 8,
            iterations: 1,
            lanes: 1,
            output_bytes: 32,
        };
        params.validate().unwrap();
        params
    }

    fn genesis_state() -> QRunV06CanonicalExecutionState {
        genesis_state_with_owner(OWNER)
    }

    fn genesis_state_with_owner(owner: AccountId) -> QRunV06CanonicalExecutionState {
        let params = params();
        let schedule = QRunV06MiningScheduleCandidate::cp0422_research_candidate();
        let tokenomics = QRunV06TokenomicsState::genesis(NETWORK, owner, schedule).unwrap();
        let descriptor =
            crate::qrun_v06_genesis_descriptor_candidate::QRunV06GenesisDescriptor::new(
                NETWORK,
                PROFILE,
                owner,
                1,
                crate::qrun_v06_checkpoint_candidate::qrun_v06_consensus_fingerprint(&params)
                    .unwrap(),
                tokenomics.policy_fingerprint(),
            )
            .unwrap();
        QRunV06CanonicalExecutionState::cp0528_genesis_candidate_with_descriptor(
            descriptor, schedule,
        )
        .unwrap()
    }

    // Deterministic test-only Q6HA identity. These seeds are test fixtures, never wallet material.
    fn q6ti_test_signer() -> QRunV06HybridTransactionSigner {
        QRunV06HybridTransactionSigner::from_seeds([0xA1; 32], [0xA2; 32]).unwrap()
    }

    fn q6ti_test_genesis_state() -> QRunV06CanonicalExecutionState {
        genesis_state_with_owner(q6ti_test_signer().account_id())
    }

    fn q6ti_test_transaction() -> Transaction {
        let signer = q6ti_test_signer();
        let mut transaction = Transaction {
            network_id: NETWORK,
            sender: signer.account_id(),
            recipient: [0xD2; 32],
            nonce: 1,
            amount: 10_000,
            fee: 10,
            expires_at: 10_000,
            signature: Vec::new(),
        };
        signer.sign_transaction(&mut transaction).unwrap();
        transaction
    }

    #[derive(Clone)]
    struct MockAnchorGate {
        current: QRunV06ExternalAnchorState,
        fail_next_advance: bool,
        advance_calls: usize,
    }
    impl QRunV06NodeAnchorGate for MockAnchorGate {
        fn verify_current(&mut self, state: &QRunV06ExternalAnchorState) -> Result<(), String> {
            if &self.current != state {
                return Err("mock independent anchor does not match local state".into());
            }
            Ok(())
        }

        fn advance_after_local_commit(
            &mut self,
            current: &QRunV06ExternalAnchorState,
            next: &QRunV06ExternalAnchorState,
        ) -> Result<(), String> {
            self.advance_calls += 1;
            if &self.current != current {
                return Err("mock anchor predecessor mismatch".into());
            }
            current
                .validate_successor(next)
                .map_err(|error| error.to_string())?;
            if self.fail_next_advance {
                self.fail_next_advance = false;
                return Err("injected ambiguous external CAS result".into());
            }
            self.current = next.clone();
            Ok(())
        }

        fn recover_durable_successor(
            &mut self,
            current: &QRunV06ExternalAnchorState,
            next: &QRunV06ExternalAnchorState,
        ) -> Result<(), String> {
            if &self.current == next {
                return Ok(());
            }
            self.advance_after_local_commit(current, next)
        }
    }

    fn open_store() -> (TestDir, QRunV06DurableForkStore) {
        open_store_with_genesis(genesis_state())
    }

    fn open_store_with_genesis(
        genesis: QRunV06CanonicalExecutionState,
    ) -> (TestDir, QRunV06DurableForkStore) {
        let dir = TestDir::new();
        let descriptor = genesis.genesis_descriptor_commitment().unwrap();
        let store = QRunV06DurableForkStore::open_with_expected_genesis_descriptor_commitment(
            &dir.0,
            genesis,
            params(),
            &EmptyAuthenticator,
            None,
            descriptor,
        )
        .unwrap();
        (dir, store)
    }

    fn open_store_at(
        directory: &Path,
        trusted_manifest_anchor: Option<[u8; 32]>,
    ) -> QRunV06DurableForkStore {
        open_store_at_with_genesis(directory, trusted_manifest_anchor, genesis_state())
    }

    fn open_store_at_with_genesis(
        directory: &Path,
        trusted_manifest_anchor: Option<[u8; 32]>,
        genesis: QRunV06CanonicalExecutionState,
    ) -> QRunV06DurableForkStore {
        let descriptor = genesis.genesis_descriptor_commitment().unwrap();
        QRunV06DurableForkStore::open_with_expected_genesis_descriptor_commitment(
            directory,
            genesis,
            params(),
            &EmptyAuthenticator,
            trusted_manifest_anchor,
            descriptor,
        )
        .unwrap()
    }

    fn first_block(store: &QRunV06DurableForkStore) -> Vec<u8> {
        let params = params();
        let graph = store.graph().unwrap();
        let parent = graph.canonical_state().clone();
        let parent_tip = graph.canonical_tip().tip_hash;
        let target = graph.expected_next_target(&parent_tip).unwrap();
        let mut block = QRunV06Block {
            network_id: NETWORK,
            profile_id: PROFILE,
            height: parent.height() + 1,
            timestamp: parent.last_timestamp() + 60,
            parent_hash: parent.tip_hash(),
            state_root: [0; 32],
            producer: PRODUCER,
            operations: Vec::<QRunV06BlockOperation>::new(),
        };
        block.state_root = parent
            .preview_state_root_after(&block, &EmptyAuthenticator)
            .unwrap();
        let mut header = PowHeader {
            protocol_version: 6,
            network_id: NETWORK,
            height: block.height,
            timestamp: block.timestamp,
            parent_hash: block.parent_hash,
            previous_consensus_hash: parent_tip,
            state_root: qrun_v06_pow_state_commitment(&block).unwrap(),
            target,
            nonce: 0,
        };
        for nonce in 0..4_096u64 {
            header.nonce = nonce;
            if Uint256::from_be_bytes(pow_digest(&header, params.pow).unwrap()) <= target {
                return encode_qrun_v06_pow_block(&header, &block).unwrap();
            }
        }
        panic!("test PoW nonce search exhausted");
    }

    fn quote_provider() -> impl FnMut(
        &QRunV06CanonicalExecutionState,
        &QRunV06Block,
        [u8; 32],
    ) -> Result<QRunV06TrustAuthorizedQuoteAsset, String> {
        |_, _, _| Err("unexpected quote-authorization request in native-only test".into())
    }

    #[derive(Clone)]
    struct Qap1TestSigner {
        key: Arc<MLDSA65SigningKey>,
    }

    impl Qap1TestSigner {
        fn sign(&self, digest: &[u8; 32]) -> [u8; ML_DSA_65_SIGNATURE_BYTES] {
            let signature = portable::sign(self.key.as_ref(), digest, &[], [0xC1; 32]).unwrap();
            *signature.as_ref()
        }
    }

    impl OffhostAnchorReceiptSigner for Qap1TestSigner {
        fn sign_digest(
            &self,
            digest: &[u8; 32],
        ) -> Result<[u8; ML_DSA_65_SIGNATURE_BYTES], String> {
            Ok(self.sign(digest))
        }
    }

    struct Qap1TestProviderState {
        current: ExternalCasRecord,
        object_generation: u64,
    }

    struct Qap1TestProvider {
        pin: ExternalCasPin,
        state: Arc<Mutex<Qap1TestProviderState>>,
        signer: Qap1TestSigner,
    }

    impl Qap1TestProvider {
        fn signed_receipt(
            &self,
            request_nonce: [u8; 32],
            operation_id: [u8; 32],
            request_digest: [u8; 32],
            kind: ExternalCasReceiptKind,
            outcome: ExternalCasReceiptOutcome,
            record: &ExternalCasRecord,
            object_generation: u64,
        ) -> ExternalCasReceipt {
            let mut receipt = ExternalCasReceipt {
                kind,
                outcome,
                generation: record.generation,
                object_generation,
                provider_id: self.pin.provider_id,
                network_id: self.pin.network_id,
                genesis_digest: self.pin.genesis_digest,
                receipt_key_id: self.pin.receipt_key_id,
                request_nonce,
                record_digest: record.digest().unwrap(),
                previous_record_digest: record.previous_record_digest,
                previous_state_digest: record.previous_state_digest,
                state_digest: record.next_state_digest,
                operation_id,
                request_digest,
                signature: [0; ML_DSA_65_SIGNATURE_BYTES],
            };
            let digest = receipt.signing_digest().unwrap();
            receipt.signature = self.signer.sign(&digest);
            receipt
        }
    }

    impl ExternalCasProviderTransport for Qap1TestProvider {
        type Error = String;

        fn read_current(
            &mut self,
            request: &ExternalCasReadRequest,
        ) -> Result<(ExternalCasRecord, ExternalCasReceipt), Self::Error> {
            let state = self
                .state
                .lock()
                .map_err(|_| "provider mutex poisoned".to_string())?;
            let record = state.current.clone();
            let receipt = self.signed_receipt(
                request.request_nonce,
                request.operation_id,
                request.request_digest,
                ExternalCasReceiptKind::Read,
                ExternalCasReceiptOutcome::Observed,
                &record,
                state.object_generation,
            );
            Ok((record, receipt))
        }

        fn compare_and_swap(
            &mut self,
            request: &ExternalCasWriteRequest,
        ) -> Result<ExternalCasReceipt, Self::Error> {
            request
                .validate(&self.pin)
                .map_err(|error| error.to_string())?;
            let mut state = self
                .state
                .lock()
                .map_err(|_| "provider mutex poisoned".to_string())?;
            let already_applied = state.current == request.next_record
                && state.current.operation_id == request.operation_id
                && state.current.request_digest == request.request_digest;
            let can_apply = state.current.generation == request.expected_generation
                && state.object_generation == request.expected_object_generation
                && state.current.digest().map_err(|error| error.to_string())?
                    == request.expected_record_digest
                && state.current.next_state_digest == request.expected_state_digest;
            let outcome = if already_applied {
                ExternalCasReceiptOutcome::AlreadyApplied
            } else if can_apply {
                state.current = request.next_record.clone();
                state.object_generation = state
                    .object_generation
                    .checked_add(1)
                    .ok_or_else(|| "provider object generation overflow".to_string())?;
                ExternalCasReceiptOutcome::Applied
            } else {
                return Err("provider conditional CAS conflict".into());
            };
            Ok(self.signed_receipt(
                request.request_nonce,
                request.operation_id,
                request.request_digest,
                ExternalCasReceiptKind::Commit,
                outcome,
                &state.current,
                state.object_generation,
            ))
        }
    }

    struct Qap1TestAnchorTransport {
        anchor_pin: ExternalCasOffhostAnchorPin,
        provider_pin: ExternalCasPin,
        model: Arc<ExternalCasOffhostAnchorMemoryModel>,
        signer: Qap1TestSigner,
        fail_after_cas_response: Arc<Mutex<bool>>,
    }

    impl QRunV06Qap1AnchorTransport for Qap1TestAnchorTransport {
        fn is_pinned_to(
            &self,
            anchor_pin: &ExternalCasOffhostAnchorPin,
            provider_pin: &ExternalCasPin,
        ) -> bool {
            &self.anchor_pin == anchor_pin && &self.provider_pin == provider_pin
        }

        fn read(
            &mut self,
            request: &ExternalCasOffhostAnchorReadRequest,
        ) -> Result<ExternalCasOffhostAnchorReceipt, String> {
            self.model
                .read(request, &self.signer)
                .map_err(|error| error.to_string())
        }

        fn compare_and_swap(
            &mut self,
            request: &ExternalCasOffhostAnchorCasRequest,
            next_record_bytes: &[u8],
            provider_receipt_bytes: &[u8],
        ) -> Result<ExternalCasOffhostAnchorReceipt, String> {
            let receipt = self
                .model
                .compare_and_swap(
                    request,
                    next_record_bytes,
                    provider_receipt_bytes,
                    &LibcruxMlDsa65VerifierCandidate,
                    &self.signer,
                )
                .map_err(|error| error.to_string())?;
            let mut fail = self
                .fail_after_cas_response
                .lock()
                .map_err(|_| "anchor fault-injection mutex poisoned".to_string())?;
            if *fail {
                *fail = false;
                return Err("injected lost Q6EA CAS response after remote apply".into());
            }
            Ok(receipt)
        }
    }

    type TestQap1Coordinator = QRunV06Qap1ExternalCoordinator<
        Qap1TestProvider,
        LibcruxMlDsa65VerifierCandidate,
        LibcruxMlDsa65VerifierCandidate,
        Qap1TestAnchorTransport,
    >;

    struct Qap1CoordinatorFixture {
        floor_directory: std::path::PathBuf,
        provider_pin: ExternalCasPin,
        anchor_pin: ExternalCasOffhostAnchorPin,
        qfp6_pin: QRunV06ExternalAnchorPin,
        provider_state: Arc<Mutex<Qap1TestProviderState>>,
        model: Arc<ExternalCasOffhostAnchorMemoryModel>,
        provider_signer: Qap1TestSigner,
        anchor_signer: Qap1TestSigner,
        fail_after_cas_response: Arc<Mutex<bool>>,
    }

    impl Qap1CoordinatorFixture {
        fn coordinator(&self) -> TestQap1Coordinator {
            let floor =
                ExternalCasFloorStore::open(&self.floor_directory, self.provider_pin.clone())
                    .unwrap();
            let provider = Qap1TestProvider {
                pin: self.provider_pin.clone(),
                state: self.provider_state.clone(),
                signer: self.provider_signer.clone(),
            };
            let anchor = Qap1TestAnchorTransport {
                anchor_pin: self.anchor_pin.clone(),
                provider_pin: self.provider_pin.clone(),
                model: self.model.clone(),
                signer: self.anchor_signer.clone(),
                fail_after_cas_response: self.fail_after_cas_response.clone(),
            };
            QRunV06Qap1ExternalCoordinator::new(
                provider,
                floor,
                anchor,
                self.qfp6_pin.clone(),
                self.anchor_pin.clone(),
                LibcruxMlDsa65VerifierCandidate,
                LibcruxMlDsa65VerifierCandidate,
            )
            .unwrap()
        }
    }

    fn qap1_coordinator(
        dir: &TestDir,
        initial: &QRunV06ExternalAnchorState,
    ) -> Qap1CoordinatorFixture {
        let provider_keys = portable::generate_key_pair([0xA1; 32]);
        let anchor_keys = portable::generate_key_pair([0xA2; 32]);
        let provider_public: [u8; ML_DSA_65_PUBLIC_KEY_BYTES] =
            *provider_keys.verification_key.as_ref();
        let anchor_public: [u8; ML_DSA_65_PUBLIC_KEY_BYTES] =
            *anchor_keys.verification_key.as_ref();
        let provider_pin = ExternalCasPin {
            provider_id: [0xB1; 32],
            network_id: NETWORK,
            genesis_digest: GENESIS_DIGEST,
            receipt_key_id: [0xB2; 32],
            receipt_public_key: provider_public,
        };
        let anchor_pin = ExternalCasOffhostAnchorPin {
            anchor_id: [0xB3; 32],
            provider_id: provider_pin.provider_id,
            network_id: provider_pin.network_id,
            genesis_digest: provider_pin.genesis_digest,
            receipt_key_id: [0xB4; 32],
            receipt_public_key: anchor_public,
        };
        let bootstrap_record = ExternalCasRecord {
            generation: 0,
            provider_id: provider_pin.provider_id,
            network_id: provider_pin.network_id,
            genesis_digest: provider_pin.genesis_digest,
            previous_record_digest: [0; 32],
            previous_state_digest: [0; 32],
            next_state_digest: initial.digest().unwrap(),
            operation_id: [0xB5; 32],
            request_digest: [0xB6; 32],
        };
        // Keep the monotonic Provider floor outside the QFP6 archive root.
        let floor_directory = dir.0.with_extension("qap1-floor");
        ExternalCasFloorStore::initialize(
            &floor_directory,
            provider_pin.clone(),
            bootstrap_record.clone(),
            1,
        )
        .unwrap();
        let bootstrap_anchor = ExternalCasOffhostAnchorState::provision_bootstrap(
            &provider_pin,
            bootstrap_record.clone(),
            1,
        )
        .unwrap();
        let model = Arc::new(
            ExternalCasOffhostAnchorMemoryModel::new(
                anchor_pin.clone(),
                provider_pin.clone(),
                bootstrap_anchor,
            )
            .unwrap(),
        );
        let provider_state = Arc::new(Mutex::new(Qap1TestProviderState {
            current: bootstrap_record,
            object_generation: 1,
        }));
        let provider_signer = Qap1TestSigner {
            key: Arc::new(provider_keys.signing_key),
        };
        let anchor_signer = Qap1TestSigner {
            key: Arc::new(anchor_keys.signing_key),
        };
        let qfp6_pin = QRunV06ExternalAnchorPin::new(
            provider_pin.clone(),
            initial.genesis_descriptor_commitment,
        )
        .unwrap();
        Qap1CoordinatorFixture {
            floor_directory,
            provider_pin,
            anchor_pin,
            qfp6_pin,
            provider_state,
            model,
            provider_signer,
            anchor_signer,
            fail_after_cas_response: Arc::new(Mutex::new(false)),
        }
    }

    #[test]
    fn qap1_runtime_ack_waits_for_signed_provider_q6ea_and_manifest_finalize() {
        let (dir, store) = open_store();
        let initial = QRunV06ExternalAnchorState::from_store(&store, GENESIS_DIGEST).unwrap();
        let gate = MockAnchorGate {
            current: initial.clone(),
            fail_next_advance: false,
            advance_calls: 0,
        };
        let mut runtime =
            QRunV06NodeRuntime::new(store, gate, GENESIS_DIGEST, initial.clone()).unwrap();
        let envelope = first_block(&runtime.store);
        let mut quote = quote_provider();
        let fixture = qap1_coordinator(&dir, &initial);
        let mut coordinator = fixture.coordinator();

        let admission = runtime
            .submit_envelope_with_qap1(&envelope, &EmptyAuthenticator, &mut quote, &mut coordinator)
            .unwrap();
        assert!(matches!(admission, QRunV06NodeAdmission::Acknowledged(_)));
        assert!(admission.is_acknowledged());
        assert_eq!(runtime.canonical_height().unwrap(), 1);
        assert_eq!(runtime.manifest_generation().unwrap(), 1);
        assert!(runtime.qap1_required);
        assert!(!runtime.store.has_qap1_intent().unwrap());
        assert!(matches!(
            runtime.submit_envelope(&envelope, &EmptyAuthenticator, &mut quote),
            Err(QRunV06NodeRuntimeError::Qap1(_))
        ));
        coordinator
            .verify_current(runtime.committed_anchor_state())
            .unwrap();
    }

    fn qap1_noise_keypair() -> ([u8; 32], [u8; 32]) {
        let mut pair = snow::Builder::new(
            "Noise_XX_25519_ChaChaPoly_SHA256"
                .parse::<snow::params::NoiseParams>()
                .unwrap(),
        )
        .generate_keypair()
        .unwrap();
        let private = pair.private.as_slice().try_into().unwrap();
        let public = pair.public.as_slice().try_into().unwrap();
        pair.private.fill(0);
        pair.public.fill(0);
        (private, public)
    }

    struct DurableProviderNoiseServer {
        address: SocketAddr,
        server_public: [u8; 32],
        client_private: [u8; 32],
        shutdown: Arc<AtomicBool>,
        join: thread::JoinHandle<Result<(), String>>,
    }

    impl DurableProviderNoiseServer {
        fn shutdown_and_join(self) {
            self.shutdown
                .store(true, std::sync::atomic::Ordering::Release);
            self.join.join().unwrap().unwrap();
        }
    }

    fn assert_qap1_test_bind_address(address: std::net::SocketAddr) {
        let ip = address.ip();
        let allowed = ip.is_loopback() || is_qap1_netbird_overlay_ip(ip);
        assert!(
            allowed,
            "QAP1 test service bind must be loopback or an explicit NetBird overlay IPv4 address"
        );
    }

    fn is_qap1_netbird_overlay_ip(ip: std::net::IpAddr) -> bool {
        match ip {
            std::net::IpAddr::V4(value) => {
                let octets = value.octets();
                octets[0] == 100 && (64..=127).contains(&octets[1])
            }
            std::net::IpAddr::V6(_) => false,
        }
    }

    fn assert_qap1_netbird_overlay_ip(ip: std::net::IpAddr) {
        assert!(
            is_qap1_netbird_overlay_ip(ip),
            "QAP1 cross-host role requires a NetBird overlay IPv4 address in 100.64.0.0/10"
        );
    }

    fn qap1_callback_fields(line: &str) -> Vec<&str> {
        line.trim_start_matches('\u{feff}')
            .trim_end()
            .split('|')
            .collect()
    }

    fn qap1_test_service_bind_address(value: Option<&str>) -> std::net::SocketAddr {
        let address = match value {
            None => "127.0.0.1:0".parse().unwrap(),
            Some(value) => value
                .parse::<std::net::SocketAddr>()
                .expect("QAP1 test service bind address must be a valid SocketAddr"),
        };
        assert_qap1_test_bind_address(address);
        address
    }

    #[test]
    fn qap1_service_bind_policy_accepts_only_loopback_or_netbird_overlay() {
        assert_eq!(
            qap1_test_service_bind_address(None),
            "127.0.0.1:0".parse().unwrap()
        );
        assert_eq!(
            qap1_test_service_bind_address(Some("100.64.0.10:49551")),
            "100.64.0.10:49551".parse().unwrap()
        );
        for address in [
            "127.0.0.1:0",
            "[::1]:0",
            "100.64.0.1:0",
            "100.127.255.254:0",
        ] {
            assert_qap1_test_bind_address(address.parse().unwrap());
        }

        for address in [
            "0.0.0.0:0",
            "192.168.1.10:0",
            "8.8.8.8:0",
            "100.63.255.255:0",
            "100.128.0.1:0",
        ] {
            let parsed = address.parse().unwrap();
            assert!(
                std::panic::catch_unwind(|| assert_qap1_test_bind_address(parsed)).is_err(),
                "unexpectedly accepted disallowed service bind {address}"
            );
        }
    }

    #[test]
    fn qap1_cross_host_overlay_policy_requires_netbird_ipv4() {
        for address in ["100.64.0.1", "100.64.0.10", "100.127.255.254"] {
            let parsed = address.parse().unwrap();
            assert!(
                is_qap1_netbird_overlay_ip(parsed),
                "expected NetBird overlay address to be accepted: {address}"
            );
        }

        for address in [
            "127.0.0.1",
            "::1",
            "100.63.255.255",
            "100.128.0.1",
            "192.168.1.10",
            "0.0.0.0",
        ] {
            let parsed = address.parse().unwrap();
            assert!(
                !is_qap1_netbird_overlay_ip(parsed),
                "unexpectedly accepted non-overlay address: {address}"
            );
        }
    }

    #[test]
    fn qap1_callback_parser_accepts_bomless_and_bom_prefixed_ready_done() {
        let ready_bomless = "READY|nonce|100.64.0.2:48664|listener-key\n";
        let ready_bom = "\u{feff}READY|nonce|100.64.0.2:48664|listener-key\r\n";
        assert_eq!(
            qap1_callback_fields(ready_bomless),
            vec!["READY", "nonce", "100.64.0.2:48664", "listener-key"]
        );
        assert_eq!(
            qap1_callback_fields(ready_bom),
            vec!["READY", "nonce", "100.64.0.2:48664", "listener-key"]
        );

        let done_bomless = "DONE|nonce|anchor|state-root|1|1|PASS\n";
        let done_bom = "\u{feff}DONE|nonce|anchor|state-root|1|1|PASS\r\n";
        assert_eq!(
            qap1_callback_fields(done_bomless),
            vec!["DONE", "nonce", "anchor", "state-root", "1", "1", "PASS"]
        );
        assert_eq!(
            qap1_callback_fields(done_bom),
            vec!["DONE", "nonce", "anchor", "state-root", "1", "1", "PASS"]
        );
    }

    fn start_durable_provider_noise_server(
        directory: &Path,
        pin: ExternalCasPin,
        signing_key: Arc<MLDSA65SigningKey>,
    ) -> DurableProviderNoiseServer {
        start_durable_provider_noise_server_at(
            directory,
            pin,
            signing_key,
            "127.0.0.1:0".parse().unwrap(),
        )
    }

    fn start_durable_provider_noise_server_at(
        directory: &Path,
        pin: ExternalCasPin,
        signing_key: Arc<MLDSA65SigningKey>,
        bind_address: std::net::SocketAddr,
    ) -> DurableProviderNoiseServer {
        use crate::external_cas_disk_provider_candidate::DurableExternalCasProvider;
        use crate::external_cas_noise_transport_candidate::serve_external_cas_noise_connection;

        assert_qap1_test_bind_address(bind_address);
        let (server_private, server_public) = qap1_noise_keypair();
        let (client_private, client_public) = qap1_noise_keypair();
        let listener = TcpListener::bind(bind_address).unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let shutdown = Arc::new(AtomicBool::new(false));
        let worker_shutdown = Arc::clone(&shutdown);
        let server_pin = pin.clone();
        let provider_directory = directory.to_path_buf();
        let join = thread::spawn(move || {
            let signer_key = signing_key;
            let signer = move |digest: &[u8; 32]| {
                let signature = portable::sign(&signer_key, digest, &[], [0xC1; 32])
                    .map_err(|error| format!("{error:?}"))?;
                Ok(*signature.as_ref())
            };
            let mut backend =
                DurableExternalCasProvider::open(&provider_directory, server_pin.clone(), signer)
                    .map_err(|error| error.to_string())?;
            while !worker_shutdown.load(std::sync::atomic::Ordering::Acquire) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        serve_external_cas_noise_connection(
                            &mut stream,
                            &server_private,
                            &[client_public],
                            &server_pin,
                            &mut backend,
                        )
                        .map_err(|error| error.to_string())?;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) => return Err(error.to_string()),
                }
            }
            Ok(())
        });
        DurableProviderNoiseServer {
            address,
            server_public,
            client_private,
            shutdown,
            join,
        }
    }

    struct DurableAnchorNoiseServer {
        address: SocketAddr,
        server_public: [u8; 32],
        client_private: [u8; 32],
        task:
            crate::external_cas_offhost_anchor_noise_daemon_candidate::OffhostAnchorNoiseDaemonTask,
    }

    impl DurableAnchorNoiseServer {
        fn shutdown_and_join(
            self,
        ) -> crate::external_cas_offhost_anchor_noise_daemon_candidate::OffhostAnchorNoiseDaemonStats
        {
            self.task.shutdown_and_join().unwrap()
        }
    }

    fn start_durable_anchor_noise_server(
        directory: &Path,
        provider_pin: ExternalCasPin,
        anchor_pin: ExternalCasOffhostAnchorPin,
        bootstrap: ExternalCasOffhostAnchorState,
        signer: Qap1TestSigner,
    ) -> DurableAnchorNoiseServer {
        start_durable_anchor_noise_server_at(
            directory,
            provider_pin,
            anchor_pin,
            bootstrap,
            signer,
            "127.0.0.1:0".parse().unwrap(),
        )
    }

    fn start_durable_anchor_noise_server_at(
        directory: &Path,
        provider_pin: ExternalCasPin,
        anchor_pin: ExternalCasOffhostAnchorPin,
        bootstrap: ExternalCasOffhostAnchorState,
        signer: Qap1TestSigner,
        bind_address: std::net::SocketAddr,
    ) -> DurableAnchorNoiseServer {
        use crate::external_cas_offhost_anchor_file_store_candidate::ExternalCasOffhostAnchorFileStore;
        use crate::external_cas_offhost_anchor_noise_daemon_candidate::{
            OffhostAnchorNoiseDaemon, OffhostAnchorNoiseDaemonConfig,
        };
        use crate::external_cas_offhost_anchor_protocol_candidate::ExternalCasOffhostAnchorMemoryModel;

        let (provisioned, outcome) = ExternalCasOffhostAnchorFileStore::provision(
            directory,
            anchor_pin.clone(),
            provider_pin.clone(),
            bootstrap,
        )
        .unwrap();
        // Bootstrap is create-once; restart accepts the existing durable state.
        let _ = outcome;
        drop(provisioned);

        let store = Arc::new(
            ExternalCasOffhostAnchorFileStore::open(
                directory,
                anchor_pin.clone(),
                provider_pin.clone(),
            )
            .unwrap(),
        );
        let model = Arc::new(
            ExternalCasOffhostAnchorMemoryModel::with_store(
                anchor_pin.clone(),
                provider_pin.clone(),
                store,
            )
            .unwrap(),
        );
        assert_qap1_test_bind_address(bind_address);
        let (server_private, server_public) = qap1_noise_keypair();
        let (client_private, client_public) = qap1_noise_keypair();
        let daemon = OffhostAnchorNoiseDaemon::bind(
            OffhostAnchorNoiseDaemonConfig {
                bind_address,
                local_static_private_key: server_private,
                trusted_client_static_public_keys: vec![client_public],
                anchor_pin,
                provider_pin,
                max_workers: 2,
                queue_capacity: 8,
            },
            model,
            Arc::new(LibcruxMlDsa65VerifierCandidate),
            Arc::new(signer),
        )
        .unwrap();
        let address = daemon.local_addr().unwrap();
        let task = daemon.spawn().unwrap();
        DurableAnchorNoiseServer {
            address,
            server_public,
            client_private,
            task,
        }
    }

    type DurableNoiseQap1Coordinator = QRunV06Qap1ExternalCoordinator<
        crate::external_cas_noise_transport_candidate::NoiseTcpExternalCasProviderTransport,
        LibcruxMlDsa65VerifierCandidate,
        LibcruxMlDsa65VerifierCandidate,
        crate::external_cas_offhost_anchor_noise_transport_candidate::NoiseTcpOffhostAnchorTransport,
    >;

    fn durable_noise_qap1_coordinator(
        provider_server: &DurableProviderNoiseServer,
        anchor_server: &DurableAnchorNoiseServer,
        provider_pin: ExternalCasPin,
        anchor_pin: ExternalCasOffhostAnchorPin,
        initial: &QRunV06ExternalAnchorState,
        floor_directory: &Path,
    ) -> DurableNoiseQap1Coordinator {
        let provider_transport =
            crate::external_cas_noise_transport_candidate::NoiseTcpExternalCasProviderTransport::new(
                provider_server.address,
                provider_server.client_private,
                provider_server.server_public,
                provider_pin.clone(),
            )
            .unwrap();
        let anchor_transport =
            crate::external_cas_offhost_anchor_noise_transport_candidate::NoiseTcpOffhostAnchorTransport::new(
                anchor_server.address,
                anchor_server.client_private,
                anchor_server.server_public,
                anchor_pin.clone(),
                provider_pin.clone(),
            )
            .unwrap();
        let floor = ExternalCasFloorStore::open(floor_directory, provider_pin.clone()).unwrap();
        QRunV06Qap1ExternalCoordinator::new(
            provider_transport,
            floor,
            anchor_transport,
            QRunV06ExternalAnchorPin::new(provider_pin, initial.genesis_descriptor_commitment)
                .unwrap(),
            anchor_pin,
            LibcruxMlDsa65VerifierCandidate,
            LibcruxMlDsa65VerifierCandidate,
        )
        .unwrap()
    }

    #[test]
    fn qap1_runtime_uses_durable_provider_and_q6ea_noise_services_across_restart() {
        use crate::external_cas_anchor_candidate::ExternalCasPin;
        use crate::external_cas_disk_provider_candidate::DurableExternalCasProvider;
        use crate::external_cas_floor_store_candidate::ExternalCasFloorStore;
        use crate::external_cas_offhost_anchor_candidate::ExternalCasOffhostAnchorState;

        let (dir, store) = open_store();
        let initial = QRunV06ExternalAnchorState::from_store(&store, GENESIS_DIGEST).unwrap();
        let service_root = dir.0.with_extension("cp0563-services");
        fs::create_dir_all(&service_root).unwrap();
        let provider_dir = service_root.join("durable-provider");
        let anchor_dir = service_root.join("durable-q6ea");
        let floor_dir = service_root.join("durable-provider-floor");

        let provider_keys = portable::generate_key_pair([0xD1; 32]);
        let anchor_keys = portable::generate_key_pair([0xD2; 32]);
        let provider_pin = ExternalCasPin {
            provider_id: [0xD3; 32],
            network_id: NETWORK,
            genesis_digest: GENESIS_DIGEST,
            receipt_key_id: [0xD4; 32],
            receipt_public_key: *provider_keys.verification_key.as_ref(),
        };
        let anchor_pin = ExternalCasOffhostAnchorPin {
            anchor_id: [0xD5; 32],
            provider_id: provider_pin.provider_id,
            network_id: provider_pin.network_id,
            genesis_digest: provider_pin.genesis_digest,
            receipt_key_id: [0xD6; 32],
            receipt_public_key: *anchor_keys.verification_key.as_ref(),
        };
        let bootstrap_record = ExternalCasRecord {
            generation: 0,
            provider_id: provider_pin.provider_id,
            network_id: provider_pin.network_id,
            genesis_digest: provider_pin.genesis_digest,
            previous_record_digest: [0; 32],
            previous_state_digest: [0; 32],
            next_state_digest: initial.digest().unwrap(),
            operation_id: [0xD7; 32],
            request_digest: [0xD8; 32],
        };
        let bootstrap_anchor = ExternalCasOffhostAnchorState::provision_bootstrap(
            &provider_pin,
            bootstrap_record.clone(),
            1,
        )
        .unwrap();
        let bootstrap_anchor_for_restart = bootstrap_anchor.clone();

        let provider_signing_key = Arc::new(provider_keys.signing_key);
        let provider_init_signer_key = Arc::clone(&provider_signing_key);
        let provider = DurableExternalCasProvider::initialize(
            &provider_dir,
            provider_pin.clone(),
            bootstrap_record.clone(),
            move |digest| {
                let signature = portable::sign(&provider_init_signer_key, digest, &[], [0xC1; 32])
                    .map_err(|error| format!("{error:?}"))?;
                Ok(*signature.as_ref())
            },
        )
        .unwrap();
        drop(provider);
        ExternalCasFloorStore::initialize(&floor_dir, provider_pin.clone(), bootstrap_record, 1)
            .unwrap();

        let anchor_signer = Qap1TestSigner {
            key: Arc::new(anchor_keys.signing_key),
        };
        let mut anchor_server = start_durable_anchor_noise_server(
            &anchor_dir,
            provider_pin.clone(),
            anchor_pin.clone(),
            bootstrap_anchor,
            anchor_signer.clone(),
        );
        let mut provider_server = start_durable_provider_noise_server(
            &provider_dir,
            provider_pin.clone(),
            Arc::clone(&provider_signing_key),
        );

        let gate = MockAnchorGate {
            current: initial.clone(),
            fail_next_advance: false,
            advance_calls: 0,
        };
        let mut recovery_quote = quote_provider();
        let recovery_coordinator = durable_noise_qap1_coordinator(
            &provider_server,
            &anchor_server,
            provider_pin.clone(),
            anchor_pin.clone(),
            &initial,
            &floor_dir,
        );
        let mut runtime = QRunV06NodeRuntime::recover_qap1_after_process_restart(
            store,
            gate,
            recovery_coordinator,
            GENESIS_DIGEST,
            &EmptyAuthenticator,
            &mut recovery_quote,
        )
        .unwrap();
        assert!(runtime.qap1_recovery_verified());

        let mut fork_choice = runtime.store.graph().unwrap().clone();
        let mut quote = quote_provider();
        let mut coordinator = durable_noise_qap1_coordinator(
            &provider_server,
            &anchor_server,
            provider_pin.clone(),
            anchor_pin.clone(),
            &initial,
            &floor_dir,
        );
        let shutdown = AtomicBool::new(false);
        let mining_report = crate::qrun_v06_qap1_mining_loop_candidate::run_qfp6_qap1_mining_loop(
            &mut runtime,
            &mut fork_choice,
            PRODUCER,
            &EmptyAuthenticator,
            &mut quote,
            &mut coordinator,
            crate::qrun_v06_qap1_mining_loop_candidate::QRunV06Qap1MiningLoopConfig {
                max_blocks_per_run: 2,
                max_nonce_attempts_per_block: 100_000,
            },
            &shutdown,
            |parent| Ok((parent.last_timestamp() + 60, Vec::new())),
        )
        .unwrap();

        assert_eq!(mining_report.blocks_acknowledged, 2);
        assert_eq!(mining_report.starting_height, 0);
        assert_eq!(mining_report.ending_height, 2);
        assert_eq!(runtime.canonical_height().unwrap(), 2);
        assert_eq!(runtime.manifest_generation().unwrap(), 2);
        assert_eq!(fork_choice.canonical_tip().height, 2);
        assert_eq!(
            fork_choice.canonical_tip().tip_hash,
            mining_report.ending_tip
        );
        assert!(!runtime.store.has_qap1_intent().unwrap());
        coordinator
            .verify_current(runtime.committed_anchor_state())
            .unwrap();

        let expected_anchor = runtime.committed_anchor_state().clone();
        let expected_root = runtime.store.canonical_state_root().unwrap();
        let expected_generation = runtime.manifest_generation().unwrap();
        drop(coordinator);
        drop(runtime);
        anchor_server.shutdown_and_join();
        provider_server.shutdown_and_join();

        // Restart both independently bound local services from their durable stores.
        anchor_server = start_durable_anchor_noise_server(
            &anchor_dir,
            provider_pin.clone(),
            anchor_pin.clone(),
            bootstrap_anchor_for_restart,
            anchor_signer.clone(),
        );
        provider_server = start_durable_provider_noise_server(
            &provider_dir,
            provider_pin.clone(),
            Arc::clone(&provider_signing_key),
        );

        let reopened_genesis = genesis_state();
        let reopened_descriptor = reopened_genesis.genesis_descriptor_commitment().unwrap();
        let reopened_store =
            QRunV06DurableForkStore::open_with_expected_genesis_descriptor_commitment(
                &dir.0,
                reopened_genesis,
                params(),
                &EmptyAuthenticator,
                Some(expected_anchor.manifest_anchor),
                reopened_descriptor,
            )
            .unwrap();
        let recovery_gate = MockAnchorGate {
            current: expected_anchor.clone(),
            fail_next_advance: false,
            advance_calls: 0,
        };
        let mut recovered_quote = quote_provider();
        let recovered_coordinator = durable_noise_qap1_coordinator(
            &provider_server,
            &anchor_server,
            provider_pin.clone(),
            anchor_pin.clone(),
            &expected_anchor,
            &floor_dir,
        );
        let mut recovered = QRunV06NodeRuntime::recover_qap1_after_process_restart(
            reopened_store,
            recovery_gate,
            recovered_coordinator,
            GENESIS_DIGEST,
            &EmptyAuthenticator,
            &mut recovered_quote,
        )
        .unwrap();
        assert!(recovered.qap1_required);
        assert!(recovered.qap1_recovery_verified());
        assert_eq!(recovered.canonical_height().unwrap(), 2);
        assert_eq!(
            recovered.manifest_generation().unwrap(),
            expected_generation
        );
        assert_eq!(
            recovered.store.canonical_state_root().unwrap(),
            expected_root
        );

        let mut recovered_fork_choice = recovered.store.graph().unwrap().clone();
        let mut resumed_quote = quote_provider();
        let mut resumed_coordinator = durable_noise_qap1_coordinator(
            &provider_server,
            &anchor_server,
            provider_pin.clone(),
            anchor_pin.clone(),
            &expected_anchor,
            &floor_dir,
        );
        let resumed_report = crate::qrun_v06_qap1_mining_loop_candidate::run_qfp6_qap1_mining_loop(
            &mut recovered,
            &mut recovered_fork_choice,
            PRODUCER,
            &EmptyAuthenticator,
            &mut resumed_quote,
            &mut resumed_coordinator,
            crate::qrun_v06_qap1_mining_loop_candidate::QRunV06Qap1MiningLoopConfig {
                max_blocks_per_run: 1,
                max_nonce_attempts_per_block: 100_000,
            },
            &shutdown,
            |parent| Ok((parent.last_timestamp() + 60, Vec::new())),
        )
        .unwrap();
        assert_eq!(resumed_report.blocks_acknowledged, 1);
        assert_eq!(resumed_report.starting_height, 2);
        assert_eq!(resumed_report.ending_height, 3);
        assert_eq!(recovered.canonical_height().unwrap(), 3);
        assert_eq!(
            recovered.manifest_generation().unwrap(),
            expected_generation + 1
        );
        assert_eq!(recovered_fork_choice.canonical_tip().height, 3);
        resumed_coordinator
            .verify_current(recovered.committed_anchor_state())
            .unwrap();

        drop(resumed_coordinator);
        drop(recovered);
        anchor_server.shutdown_and_join();
        provider_server.shutdown_and_join();
        fs::remove_dir_all(&service_root).unwrap();
    }

    #[test]
    fn qfp6_mining_supervisor_admits_real_noise_peer_then_mines_locally_via_durable_qap1() {
        use crate::external_cas_anchor_candidate::ExternalCasPin;
        use crate::external_cas_disk_provider_candidate::DurableExternalCasProvider;
        use crate::external_cas_floor_store_candidate::ExternalCasFloorStore;
        use crate::external_cas_offhost_anchor_candidate::ExternalCasOffhostAnchorState;
        use crate::{
            qrun_v06_node_supervisor_candidate::{
                run_qfp6_mining_supervisor, QRunV06MiningSupervisorConfig,
                QRunV06NodeSupervisorStopReason,
            },
            qrun_v06_transaction_journal_candidate::QRunV06TransactionJournal,
            qrun_v06_transaction_mempool_candidate::QRunV06MempoolLimits,
        };

        // Build independently persisted Provider and Q6EA services with real Noise endpoints
        // and pinned ML-DSA-65 receipt keys.
        let (dir, store) = open_store();
        let initial = QRunV06ExternalAnchorState::from_store(&store, GENESIS_DIGEST).unwrap();
        let service_root = dir.0.with_extension("cp0572-supervisor-services");
        fs::create_dir_all(&service_root).unwrap();
        let provider_dir = service_root.join("durable-provider");
        let anchor_dir = service_root.join("durable-q6ea");
        let floor_dir = service_root.join("durable-provider-floor");

        let provider_keys = portable::generate_key_pair([0xE1; 32]);
        let anchor_keys = portable::generate_key_pair([0xE2; 32]);
        let provider_pin = ExternalCasPin {
            provider_id: [0xE3; 32],
            network_id: NETWORK,
            genesis_digest: GENESIS_DIGEST,
            receipt_key_id: [0xE4; 32],
            receipt_public_key: *provider_keys.verification_key.as_ref(),
        };
        let anchor_pin = ExternalCasOffhostAnchorPin {
            anchor_id: [0xE5; 32],
            provider_id: provider_pin.provider_id,
            network_id: provider_pin.network_id,
            genesis_digest: provider_pin.genesis_digest,
            receipt_key_id: [0xE6; 32],
            receipt_public_key: *anchor_keys.verification_key.as_ref(),
        };
        let bootstrap_record = ExternalCasRecord {
            generation: 0,
            provider_id: provider_pin.provider_id,
            network_id: provider_pin.network_id,
            genesis_digest: provider_pin.genesis_digest,
            previous_record_digest: [0; 32],
            previous_state_digest: [0; 32],
            next_state_digest: initial.digest().unwrap(),
            operation_id: [0xE7; 32],
            request_digest: [0xE8; 32],
        };
        let bootstrap_anchor = ExternalCasOffhostAnchorState::provision_bootstrap(
            &provider_pin,
            bootstrap_record.clone(),
            1,
        )
        .unwrap();

        let provider_signing_key = Arc::new(provider_keys.signing_key);
        let provider_init_signer_key = Arc::clone(&provider_signing_key);
        let provider = DurableExternalCasProvider::initialize(
            &provider_dir,
            provider_pin.clone(),
            bootstrap_record.clone(),
            move |digest| {
                let signature = portable::sign(&provider_init_signer_key, digest, &[], [0xC1; 32])
                    .map_err(|error| format!("{error:?}"))?;
                Ok(*signature.as_ref())
            },
        )
        .unwrap();
        drop(provider);
        ExternalCasFloorStore::initialize(&floor_dir, provider_pin.clone(), bootstrap_record, 1)
            .unwrap();

        let anchor_signer = Qap1TestSigner {
            key: Arc::new(anchor_keys.signing_key),
        };
        let anchor_server = start_durable_anchor_noise_server(
            &anchor_dir,
            provider_pin.clone(),
            anchor_pin.clone(),
            bootstrap_anchor,
            anchor_signer,
        );
        let provider_server = start_durable_provider_noise_server(
            &provider_dir,
            provider_pin.clone(),
            Arc::clone(&provider_signing_key),
        );

        // The Runtime is recovered and QAP1-required before the Supervisor can serve.
        let gate = MockAnchorGate {
            current: initial.clone(),
            fail_next_advance: false,
            advance_calls: 0,
        };
        let mut recovery_quote = quote_provider();
        let recovery_coordinator = durable_noise_qap1_coordinator(
            &provider_server,
            &anchor_server,
            provider_pin.clone(),
            anchor_pin.clone(),
            &initial,
            &floor_dir,
        );
        let mut runtime = QRunV06NodeRuntime::recover_qap1_after_process_restart(
            store,
            gate,
            recovery_coordinator,
            GENESIS_DIGEST,
            &EmptyAuthenticator,
            &mut recovery_quote,
        )
        .unwrap();
        assert!(runtime.qap1_recovery_verified());

        let mut quote = quote_provider();
        let mut coordinator = durable_noise_qap1_coordinator(
            &provider_server,
            &anchor_server,
            provider_pin.clone(),
            anchor_pin.clone(),
            &initial,
            &floor_dir,
        );

        // A distinct pinned Noise peer submits a valid Genesis-child block. The Supervisor
        // must QAP1-commit it, refresh ForkChoice from the durable store, then mine height 2.
        let (node_private, node_public) = qap1_noise_keypair();
        let (peer_private, peer_public) = qap1_noise_keypair();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let listener_address = listener.local_addr().unwrap();
        let peer_envelope = first_block(&runtime.store);
        let peer_frame = encode_qrun_v06_peer_block_request(1, &peer_envelope).unwrap();

        let peer = thread::spawn(move || {
            let mut stream = TcpStream::connect(listener_address).unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(15)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(15)))
                .unwrap();
            let mut noise = QRunV06NoiseSession::connect(
                &mut stream,
                &peer_private,
                &node_public,
                &NETWORK,
                &PROFILE,
            )
            .unwrap();
            noise.write_q6pb_request(&mut stream, &peer_frame).unwrap();
            let response = noise.read_q6pa_response(&mut stream, 1).unwrap();
            u16::from_be_bytes([response[6], response[7]])
        });

        let shutdown = AtomicBool::new(false);
        let mut template_calls = 0usize;
        let mut config = QRunV06MiningSupervisorConfig::default();
        config.peer.install_os_signal_handler = false;
        config.peer.max_total_sessions = 1;
        config.peer.listener.max_requests_per_session = 1;
        config.peer.listener.accept_poll_interval = Duration::from_millis(10);
        config.listener_round_timeout = Duration::from_millis(250);
        config.mining.max_blocks_per_run = 2;
        config.mining.max_nonce_attempts_per_block = 100_000;
        let mut transaction_journal = QRunV06TransactionJournal::open(
            dir.0.join("q6ti-pending-journal"),
            QRunV06MempoolLimits::default(),
        )
        .unwrap();

        let report = run_qfp6_mining_supervisor(
            &listener,
            config,
            &node_private,
            &[peer_public],
            &NETWORK,
            &PROFILE,
            &shutdown,
            &mut runtime,
            &EmptyAuthenticator,
            &mut quote,
            &mut coordinator,
            PRODUCER,
            &mut transaction_journal,
            |parent| {
                template_calls += 1;
                if template_calls == 2 {
                    // Stop only after the first local mining attempt was ACKed.
                    shutdown.store(true, std::sync::atomic::Ordering::Release);
                }
                Ok((parent.last_timestamp() + 60, Vec::new()))
            },
        )
        .unwrap();

        let peer_status = peer.join().unwrap();
        assert_eq!(peer_status, QRunV06PeerAdmissionStatus::Accepted as u16);
        assert_eq!(report.listener_rounds, 1);
        assert_eq!(report.mining_rounds, 1);
        assert_eq!(report.stats.accepted_connections, 1);
        assert_eq!(report.stats.authenticated_sessions, 1);
        assert_eq!(report.stats.requests_received, 1);
        assert_eq!(report.stats.responses_written, 1);
        assert_eq!(report.blocks_acknowledged, 1);
        assert_eq!(report.ending_height, 2);
        assert_eq!(
            report.stop_reason,
            QRunV06NodeSupervisorStopReason::ShutdownRequested
        );
        assert_eq!(runtime.canonical_height().unwrap(), 2);
        assert_eq!(runtime.manifest_generation().unwrap(), 2);
        assert!(!runtime.store.has_qap1_intent().unwrap());
        coordinator
            .verify_current(runtime.committed_anchor_state())
            .unwrap();

        drop(coordinator);
        drop(runtime);
        anchor_server.shutdown_and_join();
        provider_server.shutdown_and_join();
        fs::remove_dir_all(&service_root).unwrap();
    }

    struct DigestAuthenticator;
    impl TransactionAuthenticator for DigestAuthenticator {
        fn verify(
            &self,
            _: &AccountId,
            signing_digest: &[u8; 32],
            signature: &[u8],
        ) -> Result<(), ()> {
            if signature == signing_digest {
                Ok(())
            } else {
                Err(())
            }
        }
    }

    #[test]
    fn qap1_peer_ingress_executes_qzxb_qusdt_test_trade() {
        use crate::qrun_v06_asset_registry_candidate::{
            AssetRegistration, AssetSupplyPolicy, AssetTrustPolicy,
        };
        use crate::qrun_v06_orderbook_candidate::{
            OrderBook, QRunV06OrderBookOperation as OrderOp,
            QRunV06SignedOrderBookOperation as SignedOrderOp, Side, Tif,
        };
        use crate::state_machine::{transaction_signing_digest, Transaction};

        const BUYER: [u8; 32] = [0x76; 32];
        const Q6QA_COMMITMENT: [u8; 32] = [0xD7; 32];
        const Q6PN_COMMITMENT: [u8; 32] = [0xD8; 32];

        let (dir, store) = open_store();
        let initial = QRunV06ExternalAnchorState::from_store(&store, GENESIS_DIGEST).unwrap();
        let gate = MockAnchorGate {
            current: initial.clone(),
            fail_next_advance: false,
            advance_calls: 0,
        };
        let mut runtime =
            QRunV06NodeRuntime::new(store, gate, GENESIS_DIGEST, initial.clone()).unwrap();
        let params = params();
        let graph = runtime.store.graph().unwrap();
        let parent = graph.canonical_state().clone();
        let parent_tip = graph.canonical_tip().tip_hash;
        let target = graph.expected_next_target(&parent_tip).unwrap();
        let height = parent.height() + 1;
        let timestamp = parent.last_timestamp() + 60;
        let native_asset = crate::qzxb_amm_candidate::qzxb_native_asset_id(NETWORK).unwrap();

        // Worthless local test quote; not Tether USDT, not redeemable, and not backed.
        let mut quote_registration = AssetRegistration {
            network_id: NETWORK,
            issuer: OWNER,
            issuer_nonce: 1,
            salt: [0xD9; 32],
            name: "QUSDT Test Quote (Zero Value)".to_string(),
            symbol: "QUSDT-TST".to_string(),
            decimals: 6,
            supply_policy: AssetSupplyPolicy::Fixed {
                total_supply: 1_000,
            },
            initial_supply: 1_000,
            initial_recipient: BUYER,
            trust_policy: AssetTrustPolicy::Unverified,
            expires_at: 10_000,
            signature: Vec::new(),
        };
        quote_registration.signature = quote_registration.signing_digest().unwrap().to_vec();
        let quote_asset = quote_registration.asset_id();
        let pair_id = OrderBook::pair_id(NETWORK, native_asset, quote_asset).unwrap();

        let mut trader_funding = Transaction {
            network_id: NETWORK,
            sender: OWNER,
            recipient: BUYER,
            nonce: 1,
            amount: 10,
            fee: 1,
            expires_at: 10_000,
            signature: Vec::new(),
        };
        trader_funding.signature = transaction_signing_digest(&trader_funding)
            .unwrap()
            .to_vec();

        let signed_orderbook = |sender: AccountId, nonce: u64, operation: OrderOp| {
            let mut signed = SignedOrderOp {
                network_id: NETWORK,
                sender,
                nonce,
                expires_at: 10_000,
                operation,
                signature: Vec::new(),
            };
            signed.signature = signed.signing_digest().unwrap().to_vec();
            signed
        };

        let operations = vec![
            QRunV06BlockOperation::NativeTransfer(trader_funding),
            QRunV06BlockOperation::AssetRegistration(quote_registration),
            QRunV06BlockOperation::OrderBook(signed_orderbook(
                OWNER,
                2,
                OrderOp::CreatePair {
                    base: native_asset,
                    quote: quote_asset,
                    base_lot_atoms: 1,
                    quote_tick_atoms: 1,
                    max_price_ticks: 10,
                    max_quantity_lots: 20,
                    min_notional: 1,
                    maker_fee_bps: 0,
                    taker_fee_bps: 0,
                    fee_collector: PRODUCER,
                },
            )),
            QRunV06BlockOperation::OrderBook(signed_orderbook(
                OWNER,
                3,
                OrderOp::Deposit {
                    asset: native_asset,
                    amount: 20,
                },
            )),
            QRunV06BlockOperation::OrderBook(signed_orderbook(
                BUYER,
                1,
                OrderOp::Deposit {
                    asset: quote_asset,
                    amount: 40,
                },
            )),
            QRunV06BlockOperation::OrderBook(signed_orderbook(
                OWNER,
                4,
                OrderOp::PlaceLimit {
                    pair: pair_id,
                    side: Side::Sell,
                    price_ticks: 2,
                    quantity_lots: 20,
                    tif: Tif::Gtc,
                    expires_at_height: 100,
                },
            )),
            QRunV06BlockOperation::OrderBook(signed_orderbook(
                BUYER,
                2,
                OrderOp::PlaceLimit {
                    pair: pair_id,
                    side: Side::Buy,
                    price_ticks: 2,
                    quantity_lots: 20,
                    tif: Tif::Ioc,
                    expires_at_height: 100,
                },
            )),
        ];
        let mut block = QRunV06Block {
            network_id: NETWORK,
            profile_id: PROFILE,
            height,
            timestamp,
            parent_hash: parent.tip_hash(),
            state_root: [0; 32],
            producer: PRODUCER,
            operations,
        };
        let quote_authorization =
            crate::qrun_v06_profile_trust_candidate::test_trust_authorized_quote_asset_candidate(
                NETWORK,
                PROFILE,
                quote_asset,
                Q6QA_COMMITMENT,
                Q6PN_COMMITMENT,
                3,
                1,
                100,
                1,
                height,
            );
        block.state_root = parent
            .preview_state_root_after_with_quote_asset_authorization(
                &block,
                &DigestAuthenticator,
                Some(&quote_authorization),
            )
            .unwrap();

        let mut header = PowHeader {
            protocol_version: 6,
            network_id: NETWORK,
            height,
            timestamp,
            parent_hash: block.parent_hash,
            previous_consensus_hash: parent_tip,
            state_root: qrun_v06_pow_state_commitment(&block).unwrap(),
            target,
            nonce: 0,
        };
        let mut envelope = None;
        for nonce in 0..4_096u64 {
            header.nonce = nonce;
            if Uint256::from_be_bytes(pow_digest(&header, params.pow).unwrap()) <= target {
                envelope = Some(encode_qrun_v06_pow_block(&header, &block).unwrap());
                break;
            }
        }
        let envelope = envelope.expect("test PoW nonce search exhausted");
        let frame = encode_qrun_v06_peer_block_request(602, &envelope).unwrap();
        let mut replay_guard = QRunV06PeerReplayGuard::new();
        let mut quote_authorizer = |_: &QRunV06CanonicalExecutionState,
                                    block: &QRunV06Block,
                                    asset: [u8; 32]| {
            Ok(crate::qrun_v06_profile_trust_candidate::test_trust_authorized_quote_asset_candidate(
                NETWORK, PROFILE, asset, Q6QA_COMMITMENT, Q6PN_COMMITMENT, 3, 1, 100, 1, block.height,
            ))
        };
        let fixture = qap1_coordinator(&dir, &initial);
        let mut coordinator = fixture.coordinator();

        let accepted = process_qrun_v06_peer_block_frame_with_qap1(
            &mut runtime,
            &mut replay_guard,
            &frame,
            &DigestAuthenticator,
            &mut quote_authorizer,
            &mut coordinator,
        )
        .unwrap();
        assert_eq!(accepted.request_id(), 602);
        assert_eq!(accepted.status(), QRunV06PeerAdmissionStatus::Accepted);
        assert!(accepted.is_positive_ack());
        assert_eq!(runtime.canonical_height().unwrap(), 1);
        assert_eq!(runtime.manifest_generation().unwrap(), 1);
        assert!(!runtime.store.has_qap1_intent().unwrap());

        let committed = runtime.store.graph().unwrap().canonical_state().clone();
        assert_eq!(
            committed.quote_asset_authorization_commitment(),
            Some(Q6QA_COMMITMENT)
        );
        assert_eq!(committed.orderbook().fills().len(), 1);
        let fill = &committed.orderbook().fills()[0];
        assert_eq!(fill.buyer, BUYER);
        assert_eq!(fill.seller, OWNER);
        assert_eq!(fill.base_atoms, 20);
        assert_eq!(fill.quote_atoms, 40);
        assert_eq!(committed.orderbook().balance(&native_asset, &BUYER), 20);
        assert_eq!(committed.orderbook().balance(&quote_asset, &OWNER), 40);
        committed.verify_invariants().unwrap();

        let generation = runtime.manifest_generation().unwrap();
        let replayed = process_qrun_v06_peer_block_frame_with_qap1(
            &mut runtime,
            &mut replay_guard,
            &frame,
            &DigestAuthenticator,
            &mut quote_authorizer,
            &mut coordinator,
        )
        .unwrap();
        assert_eq!(replayed.status(), QRunV06PeerAdmissionStatus::Rejected);
        assert!(!replayed.is_positive_ack());
        assert_eq!(runtime.canonical_height().unwrap(), 1);
        assert_eq!(runtime.manifest_generation().unwrap(), generation);
        assert_eq!(
            runtime
                .store
                .graph()
                .unwrap()
                .canonical_state()
                .orderbook()
                .fills()
                .len(),
            1
        );
        coordinator
            .verify_current(runtime.committed_anchor_state())
            .unwrap();
        // Reopen the durable QFP6 archive with exact-height quote evidence, then recover
        // a QAP1-required runtime from the independently advanced Q6EA state.
        let expected_anchor_state = runtime.committed_anchor_state().clone();
        let expected_state_root = runtime.store.canonical_state_root().unwrap();
        let expected_generation = runtime.manifest_generation().unwrap();
        drop(coordinator);
        drop(runtime);

        let reopened_genesis = genesis_state();
        let reopened_descriptor = reopened_genesis.genesis_descriptor_commitment().unwrap();
        let mut restart_quote_authorizer =
            |_: &QRunV06CanonicalExecutionState, block: &QRunV06Block, asset: [u8; 32]| {
                Ok(crate::qrun_v06_profile_trust_candidate::test_trust_authorized_quote_asset_candidate(
                    NETWORK, PROFILE, asset, Q6QA_COMMITMENT, Q6PN_COMMITMENT,
                    3, 1, 100, 1, block.height,
                ))
            };
        let reopened_store =
            crate::qrun_v06_pow_fork_store_candidate::QRunV06DurableForkStore::open_for_test_with_quote_asset_authorization(
                &dir.0,
                reopened_genesis,
                params.clone(),
                &DigestAuthenticator,
                Some(expected_anchor_state.manifest_anchor),
                reopened_descriptor,
                &mut restart_quote_authorizer,
            ).unwrap();
        let recovery_gate = MockAnchorGate {
            current: expected_anchor_state.clone(),
            fail_next_advance: false,
            advance_calls: 0,
        };
        let recovered = QRunV06NodeRuntime::recover_qap1_after_process_restart(
            reopened_store,
            recovery_gate,
            fixture.coordinator(),
            GENESIS_DIGEST,
            &DigestAuthenticator,
            &mut restart_quote_authorizer,
        )
        .unwrap();
        assert!(recovered.qap1_required);
        assert_eq!(recovered.canonical_height().unwrap(), 1);
        assert_eq!(
            recovered.manifest_generation().unwrap(),
            expected_generation
        );
        assert_eq!(
            recovered.store.canonical_state_root().unwrap(),
            expected_state_root
        );
        let recovered_market = recovered.store.graph().unwrap().canonical_state().clone();
        assert_eq!(recovered_market.orderbook().fills().len(), 1);
        assert_eq!(recovered_market.orderbook().fills()[0].base_atoms, 20);
        assert_eq!(recovered_market.orderbook().fills()[0].quote_atoms, 40);
        assert_eq!(
            recovered_market.quote_asset_authorization_commitment(),
            Some(Q6QA_COMMITMENT)
        );
        recovered_market.verify_invariants().unwrap();
    }
    #[test]
    fn qap1_peer_ingress_executes_qzxb_qusdt_amm_swap_and_restarts() {
        use crate::external_cas_anchor_candidate::ExternalCasPin;
        use crate::external_cas_disk_provider_candidate::DurableExternalCasProvider;
        use crate::external_cas_floor_store_candidate::ExternalCasFloorStore;
        use crate::external_cas_offhost_anchor_candidate::ExternalCasOffhostAnchorState;
        use crate::qrun_v06_asset_registry_candidate::{
            AssetRegistration, AssetSupplyPolicy, AssetTrustPolicy,
        };
        use crate::qzxb_amm_candidate::{
            qzxb_native_asset_id, AmmOperation, AmmSignedOperation, QzxbAmmStateCandidate,
        };

        const Q6QA_COMMITMENT: [u8; 32] = [0xE1; 32];
        const Q6PN_COMMITMENT: [u8; 32] = [0xE2; 32];

        let (dir, store) = open_store();
        let initial = QRunV06ExternalAnchorState::from_store(&store, GENESIS_DIGEST).unwrap();

        // Keep the market's Provider, Q6EA and monotonic floor outside the QFP6 archive root.
        let service_root = dir.0.with_extension("cp0565-amm-services");
        fs::create_dir_all(&service_root).unwrap();
        let provider_dir = service_root.join("provider");
        let anchor_dir = service_root.join("q6ea");
        let floor_dir = service_root.join("provider-floor");

        let provider_keys = portable::generate_key_pair([0xE5; 32]);
        let anchor_keys = portable::generate_key_pair([0xE6; 32]);
        let provider_pin = ExternalCasPin {
            provider_id: [0xE7; 32],
            network_id: NETWORK,
            genesis_digest: GENESIS_DIGEST,
            receipt_key_id: [0xE8; 32],
            receipt_public_key: *provider_keys.verification_key.as_ref(),
        };
        let anchor_pin = ExternalCasOffhostAnchorPin {
            anchor_id: [0xE9; 32],
            provider_id: provider_pin.provider_id,
            network_id: provider_pin.network_id,
            genesis_digest: provider_pin.genesis_digest,
            receipt_key_id: [0xEA; 32],
            receipt_public_key: *anchor_keys.verification_key.as_ref(),
        };
        let bootstrap_record = ExternalCasRecord {
            generation: 0,
            provider_id: provider_pin.provider_id,
            network_id: provider_pin.network_id,
            genesis_digest: provider_pin.genesis_digest,
            previous_record_digest: [0; 32],
            previous_state_digest: [0; 32],
            next_state_digest: initial.digest().unwrap(),
            operation_id: [0xEB; 32],
            request_digest: [0xEC; 32],
        };
        let bootstrap_anchor = ExternalCasOffhostAnchorState::provision_bootstrap(
            &provider_pin,
            bootstrap_record.clone(),
            1,
        )
        .unwrap();
        let bootstrap_anchor_for_restart = bootstrap_anchor.clone();

        let provider_signing_key = Arc::new(provider_keys.signing_key);
        let provider_init_signer_key = Arc::clone(&provider_signing_key);
        let provider = DurableExternalCasProvider::initialize(
            &provider_dir,
            provider_pin.clone(),
            bootstrap_record.clone(),
            move |digest| {
                let signature = portable::sign(&provider_init_signer_key, digest, &[], [0xED; 32])
                    .map_err(|error| format!("{error:?}"))?;
                Ok(*signature.as_ref())
            },
        )
        .unwrap();
        drop(provider);
        ExternalCasFloorStore::initialize(&floor_dir, provider_pin.clone(), bootstrap_record, 1)
            .unwrap();

        let anchor_signer = Qap1TestSigner {
            key: Arc::new(anchor_keys.signing_key),
        };
        let mut anchor_server = start_durable_anchor_noise_server(
            &anchor_dir,
            provider_pin.clone(),
            anchor_pin.clone(),
            bootstrap_anchor,
            anchor_signer.clone(),
        );
        let mut provider_server = start_durable_provider_noise_server(
            &provider_dir,
            provider_pin.clone(),
            Arc::clone(&provider_signing_key),
        );

        let gate = MockAnchorGate {
            current: initial.clone(),
            fail_next_advance: false,
            advance_calls: 0,
        };
        let mut runtime =
            QRunV06NodeRuntime::new(store, gate, GENESIS_DIGEST, initial.clone()).unwrap();
        let params = params();
        let graph = runtime.store.graph().unwrap();
        let parent = graph.canonical_state().clone();
        let parent_tip = graph.canonical_tip().tip_hash;
        let target = graph.expected_next_target(&parent_tip).unwrap();
        let height = parent.height() + 1;
        let timestamp = parent.last_timestamp() + 60;
        let native_asset = qzxb_native_asset_id(NETWORK).unwrap();

        // Local zero-value QUSDT-TST only: it is not Tether USDT and has no redemption.
        let mut quote_registration = AssetRegistration {
            network_id: NETWORK,
            issuer: OWNER,
            issuer_nonce: 1,
            salt: [0xE3; 32],
            name: "QUSDT Test Quote (Zero Value)".to_string(),
            symbol: "QUSDT-TST".to_string(),
            decimals: 6,
            supply_policy: AssetSupplyPolicy::Fixed {
                total_supply: 1_000,
            },
            initial_supply: 1_000,
            initial_recipient: OWNER,
            trust_policy: AssetTrustPolicy::Unverified,
            expires_at: 10_000,
            signature: Vec::new(),
        };
        quote_registration.signature = quote_registration.signing_digest().unwrap().to_vec();
        let quote_asset = quote_registration.asset_id();
        let pair_id = QzxbAmmStateCandidate::pair_id_for_assets(native_asset, quote_asset).unwrap();

        let signed_amm = |nonce: u64, operation: AmmOperation| {
            let mut signed = AmmSignedOperation {
                network_id: NETWORK,
                sender: OWNER,
                nonce,
                expires_at: 10_000,
                operation,
                signature: Vec::new(),
            };
            signed.signature = signed.signing_digest().unwrap().to_vec();
            signed
        };

        let operations = vec![
            QRunV06BlockOperation::AssetRegistration(quote_registration),
            QRunV06BlockOperation::Amm(signed_amm(
                1,
                AmmOperation::CreatePair {
                    token_a: native_asset,
                    token_b: quote_asset,
                },
            )),
            QRunV06BlockOperation::Amm(signed_amm(
                2,
                AmmOperation::AddLiquidity {
                    pair_id,
                    amount0_desired: 100,
                    amount1_desired: 100,
                    min_lp_shares: 1,
                },
            )),
            QRunV06BlockOperation::Amm(signed_amm(
                3,
                AmmOperation::SwapExactIn {
                    token_in: native_asset,
                    token_out: quote_asset,
                    amount_in: 10,
                    min_amount_out: 1,
                },
            )),
        ];
        let mut block = QRunV06Block {
            network_id: NETWORK,
            profile_id: PROFILE,
            height,
            timestamp,
            parent_hash: parent.tip_hash(),
            state_root: [0; 32],
            producer: PRODUCER,
            operations,
        };
        let quote_authorization =
            crate::qrun_v06_profile_trust_candidate::test_trust_authorized_quote_asset_candidate(
                NETWORK,
                PROFILE,
                quote_asset,
                Q6QA_COMMITMENT,
                Q6PN_COMMITMENT,
                3,
                1,
                100,
                1,
                height,
            );
        block.state_root = parent
            .preview_state_root_after_with_quote_asset_authorization(
                &block,
                &DigestAuthenticator,
                Some(&quote_authorization),
            )
            .unwrap();

        let mut header = PowHeader {
            protocol_version: 6,
            network_id: NETWORK,
            height,
            timestamp,
            parent_hash: block.parent_hash,
            previous_consensus_hash: parent_tip,
            state_root: qrun_v06_pow_state_commitment(&block).unwrap(),
            target,
            nonce: 0,
        };
        let mut envelope = None;
        for nonce in 0..4_096u64 {
            header.nonce = nonce;
            if Uint256::from_be_bytes(pow_digest(&header, params.pow).unwrap()) <= target {
                envelope = Some(encode_qrun_v06_pow_block(&header, &block).unwrap());
                break;
            }
        }
        let envelope = envelope.expect("test PoW nonce search exhausted");
        let frame = encode_qrun_v06_peer_block_request(603, &envelope).unwrap();
        let mut quote_authorizer = |_: &QRunV06CanonicalExecutionState,
                                    block: &QRunV06Block,
                                    asset: [u8; 32]| {
            Ok(crate::qrun_v06_profile_trust_candidate::test_trust_authorized_quote_asset_candidate(
                    NETWORK,
                    PROFILE,
                    asset,
                    Q6QA_COMMITMENT,
                    Q6PN_COMMITMENT,
                    3,
                    1,
                    100,
                    1,
                    block.height,
                ))
        };
        let mut coordinator = durable_noise_qap1_coordinator(
            &provider_server,
            &anchor_server,
            provider_pin.clone(),
            anchor_pin.clone(),
            &initial,
            &floor_dir,
        );

        // CP-0566A: exercise the complete QFP6 Noise listener -> QAP1 -> durable
        // Provider/Q6EA path over a real TCP session, not a direct in-process handler call.
        let peer_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let peer_listener_address = peer_listener.local_addr().unwrap();
        let (listener_private, listener_public) = qap1_noise_keypair();
        let (peer_private, peer_public) = qap1_noise_keypair();
        let listener_shutdown = AtomicBool::new(false);

        let (accepted, replayed, listener_report) = thread::scope(|scope| {
            let server = scope.spawn(|| {
                let mut handler = |guard: &mut QRunV06PeerReplayGuard, peer_frame: &[u8]| {
                    crate::qrun_v06_peer_listener_candidate::process_qfp6_peer_frame_with_qap1(
                        &mut runtime,
                        guard,
                        peer_frame,
                        &DigestAuthenticator,
                        &mut quote_authorizer,
                        &mut coordinator,
                    )
                };
                serve_qfp6_noise_listener(
                    &peer_listener,
                    QRunV06PeerListenerConfig {
                        max_sessions: 1,
                        max_requests_per_session: 2,
                        max_failed_handshakes: 2,
                        accept_poll_interval: Duration::from_millis(10),
                    },
                    &listener_private,
                    &[peer_public],
                    &NETWORK,
                    &PROFILE,
                    &listener_shutdown,
                    &mut handler,
                )
                .map_err(|error| error.to_string())
            });

            let mut stream = TcpStream::connect(peer_listener_address).unwrap();
            let mut noise = QRunV06NoiseSession::connect(
                &mut stream,
                &peer_private,
                &listener_public,
                &NETWORK,
                &PROFILE,
            )
            .unwrap();
            noise.write_q6pb_request(&mut stream, &frame).unwrap();
            let accepted = noise.read_q6pa_response(&mut stream, 603).unwrap();

            // Same request ID and payload on the same authenticated session must be rejected.
            noise.write_q6pb_request(&mut stream, &frame).unwrap();
            let replayed = noise.read_q6pa_response(&mut stream, 603).unwrap();
            drop(noise);
            drop(stream);

            let report = server.join().unwrap().unwrap();
            (accepted, replayed, report)
        });

        assert_eq!(
            u16::from_be_bytes([accepted[6], accepted[7]]),
            QRunV06PeerAdmissionStatus::Accepted as u16
        );
        assert_eq!(
            u16::from_be_bytes([replayed[6], replayed[7]]),
            QRunV06PeerAdmissionStatus::Rejected as u16
        );
        assert_eq!(listener_report.stats.authenticated_sessions, 1);
        assert_eq!(listener_report.stats.requests_received, 2);
        assert_eq!(listener_report.stats.responses_written, 2);
        assert_eq!(listener_report.stats.sessions_closed, 1);
        assert_eq!(runtime.canonical_height().unwrap(), 1);
        assert_eq!(runtime.manifest_generation().unwrap(), 1);
        assert!(!runtime.store.has_qap1_intent().unwrap());

        let committed = runtime.store.graph().unwrap().canonical_state().clone();
        assert_eq!(
            committed.quote_asset_authorization_commitment(),
            Some(Q6QA_COMMITMENT)
        );
        let amm = committed.unified().amm();
        assert_eq!(amm.pair_count(), 1);
        let assets = amm.pair_assets(&pair_id).unwrap();
        assert!(assets == (native_asset, quote_asset) || assets == (quote_asset, native_asset));
        assert_eq!(amm.balance_of(&native_asset, &pair_id), 110);
        assert!(
            amm.balance_of(&quote_asset, &pair_id) > 0
                && amm.balance_of(&quote_asset, &pair_id) < 100
        );
        assert!(amm.balance_of(&quote_asset, &OWNER) > 900);
        let expected_native_reserve = amm.balance_of(&native_asset, &pair_id);
        let expected_quote_reserve = amm.balance_of(&quote_asset, &pair_id);
        let expected_owner_quote_balance = amm.balance_of(&quote_asset, &OWNER);
        committed.verify_invariants().unwrap();

        // The replay was already rejected through the same authenticated Noise session above.
        assert_eq!(runtime.canonical_height().unwrap(), 1);
        assert_eq!(runtime.manifest_generation().unwrap(), 1);

        let expected_anchor_state = runtime.committed_anchor_state().clone();
        let expected_state_root = runtime.store.canonical_state_root().unwrap();
        let expected_generation = runtime.manifest_generation().unwrap();
        drop(coordinator);
        drop(runtime);

        // Stop both old services and restart them from their independently durable local stores.
        anchor_server.shutdown_and_join();
        provider_server.shutdown_and_join();
        anchor_server = start_durable_anchor_noise_server(
            &anchor_dir,
            provider_pin.clone(),
            anchor_pin.clone(),
            bootstrap_anchor_for_restart,
            anchor_signer.clone(),
        );
        provider_server = start_durable_provider_noise_server(
            &provider_dir,
            provider_pin.clone(),
            Arc::clone(&provider_signing_key),
        );

        let reopened_genesis = genesis_state();
        let reopened_descriptor = reopened_genesis.genesis_descriptor_commitment().unwrap();
        let mut restart_quote_authorizer =
            |_: &QRunV06CanonicalExecutionState, block: &QRunV06Block, asset: [u8; 32]| {
                Ok(crate::qrun_v06_profile_trust_candidate::test_trust_authorized_quote_asset_candidate(
                    NETWORK,
                    PROFILE,
                    asset,
                    Q6QA_COMMITMENT,
                    Q6PN_COMMITMENT,
                    3,
                    1,
                    100,
                    1,
                    block.height,
                ))
            };
        let reopened_store =
            crate::qrun_v06_pow_fork_store_candidate::QRunV06DurableForkStore::open_for_test_with_quote_asset_authorization(
                &dir.0,
                reopened_genesis,
                params.clone(),
                &DigestAuthenticator,
                Some(expected_anchor_state.manifest_anchor),
                reopened_descriptor,
                &mut restart_quote_authorizer,
            )
            .unwrap();
        let recovery_gate = MockAnchorGate {
            current: expected_anchor_state.clone(),
            fail_next_advance: false,
            advance_calls: 0,
        };
        let recovered_coordinator = durable_noise_qap1_coordinator(
            &provider_server,
            &anchor_server,
            provider_pin.clone(),
            anchor_pin.clone(),
            &expected_anchor_state,
            &floor_dir,
        );
        let recovered = QRunV06NodeRuntime::recover_qap1_after_process_restart(
            reopened_store,
            recovery_gate,
            recovered_coordinator,
            GENESIS_DIGEST,
            &DigestAuthenticator,
            &mut restart_quote_authorizer,
        )
        .unwrap();
        assert!(recovered.qap1_required);
        assert_eq!(recovered.canonical_height().unwrap(), 1);
        assert_eq!(
            recovered.manifest_generation().unwrap(),
            expected_generation
        );
        assert_eq!(
            recovered.store.canonical_state_root().unwrap(),
            expected_state_root
        );
        let recovered_state = recovered.store.graph().unwrap().canonical_state().clone();
        assert_eq!(recovered_state.unified().amm().pair_count(), 1);
        let recovered_amm = recovered_state.unified().amm();
        assert_eq!(
            recovered_amm.balance_of(&native_asset, &pair_id),
            expected_native_reserve
        );
        assert_eq!(
            recovered_amm.balance_of(&quote_asset, &pair_id),
            expected_quote_reserve
        );
        assert_eq!(
            recovered_amm.balance_of(&quote_asset, &OWNER),
            expected_owner_quote_balance
        );
        assert_eq!(
            recovered_state.quote_asset_authorization_commitment(),
            Some(Q6QA_COMMITMENT)
        );
        recovered_state.verify_invariants().unwrap();

        drop(recovered);
        anchor_server.shutdown_and_join();
        provider_server.shutdown_and_join();
        fs::remove_dir_all(&service_root).unwrap();
    }

    #[test]
    fn qap1_peer_ingress_emits_positive_ack_only_after_qap1_finalization() {
        let (dir, store) = open_store();
        let initial = QRunV06ExternalAnchorState::from_store(&store, GENESIS_DIGEST).unwrap();
        let gate = MockAnchorGate {
            current: initial.clone(),
            fail_next_advance: false,
            advance_calls: 0,
        };
        let mut runtime =
            QRunV06NodeRuntime::new(store, gate, GENESIS_DIGEST, initial.clone()).unwrap();
        let envelope = first_block(&runtime.store);
        let frame = encode_qrun_v06_peer_block_request(601, &envelope).unwrap();
        let mut replay_guard = QRunV06PeerReplayGuard::new();
        let mut quote = quote_provider();
        let fixture = qap1_coordinator(&dir, &initial);
        let mut coordinator = fixture.coordinator();

        let accepted = process_qrun_v06_peer_block_frame_with_qap1(
            &mut runtime,
            &mut replay_guard,
            &frame,
            &EmptyAuthenticator,
            &mut quote,
            &mut coordinator,
        )
        .unwrap();
        assert_eq!(accepted.request_id(), 601);
        assert_eq!(accepted.status(), QRunV06PeerAdmissionStatus::Accepted);
        assert!(accepted.is_positive_ack());
        assert_eq!(runtime.canonical_height().unwrap(), 1);
        assert_eq!(runtime.manifest_generation().unwrap(), 1);
        assert!(!runtime.store.has_qap1_intent().unwrap());

        let replayed = process_qrun_v06_peer_block_frame_with_qap1(
            &mut runtime,
            &mut replay_guard,
            &frame,
            &EmptyAuthenticator,
            &mut quote,
            &mut coordinator,
        )
        .unwrap();
        assert_eq!(replayed.status(), QRunV06PeerAdmissionStatus::Rejected);
        assert!(!replayed.is_positive_ack());
        assert_eq!(replayed.durable_commit(), None);
        assert_eq!(runtime.canonical_height().unwrap(), 1);
        coordinator
            .verify_current(runtime.committed_anchor_state())
            .unwrap();
    }

    #[test]
    fn qap1_q6ha_hybrid_transfer_is_admitted_and_acknowledged_only_after_anchor_finalize() {
        use crate::{
            qrun_v06_genesis_descriptor_candidate::QRunV06GenesisDescriptor,
            qrun_v06_hybrid_auth_candidate::{
                QRunV06HybridTransactionAuthenticator, QRunV06HybridTransactionSigner,
            },
            qrun_v06_tokenomics_candidate::QRunV06MiningScheduleCandidate,
            qrun_v06_tokenomics_candidate::QRunV06TokenomicsState,
            qrun_v06_transaction_ingress_candidate::{
                decode_q6ta_response, encode_q6ti_transaction_request,
                process_q6ti_transaction_frame, QRunV06TransactionSubmitStatus,
            },
            qrun_v06_transaction_mempool_candidate::{
                QRunV06MempoolLimits, QRunV06NativeTransactionMempool,
            },
            state_machine::{
                transaction_id_with_signature_limit, transaction_signing_digest, Transaction,
                QRUN_V06_MAX_NATIVE_TX_SIGNATURE_BYTES,
            },
            v4_fat1_mldsa65_candidate::LibcruxMlDsa65VerifierCandidate,
        };

        const RECIPIENT: [u8; 32] = [0x7C; 32];
        let signer = QRunV06HybridTransactionSigner::from_seeds([0x81; 32], [0x82; 32]).unwrap();
        let founder = signer.account_id();
        let authenticator =
            QRunV06HybridTransactionAuthenticator::new(LibcruxMlDsa65VerifierCandidate);

        // Fund the exact hybrid Q6HA account in this disposable Genesis fixture. No legacy
        // Ed25519 account is aliased to it.
        let params = params();
        let schedule = QRunV06MiningScheduleCandidate::cp0422_research_candidate();
        let tokenomics = QRunV06TokenomicsState::genesis(NETWORK, founder, schedule).unwrap();
        let descriptor = QRunV06GenesisDescriptor::new(
            NETWORK,
            PROFILE,
            founder,
            1,
            crate::qrun_v06_checkpoint_candidate::qrun_v06_consensus_fingerprint(&params).unwrap(),
            tokenomics.policy_fingerprint(),
        )
        .unwrap();
        let genesis = QRunV06CanonicalExecutionState::cp0528_genesis_candidate_with_descriptor(
            descriptor, schedule,
        )
        .unwrap();

        let dir = TestDir::new();
        let descriptor_commitment = genesis.genesis_descriptor_commitment().unwrap();
        let store = QRunV06DurableForkStore::open_with_expected_genesis_descriptor_commitment(
            &dir.0,
            genesis,
            params.clone(),
            &authenticator,
            None,
            descriptor_commitment,
        )
        .unwrap();
        let initial = QRunV06ExternalAnchorState::from_store(&store, GENESIS_DIGEST).unwrap();
        let gate = MockAnchorGate {
            current: initial.clone(),
            fail_next_advance: false,
            advance_calls: 0,
        };
        let mut runtime =
            QRunV06NodeRuntime::new(store, gate, GENESIS_DIGEST, initial.clone()).unwrap();

        let graph = runtime.store.graph().unwrap();
        let parent = graph.canonical_state().clone();
        let parent_tip = graph.canonical_tip().tip_hash;
        let target = graph.expected_next_target(&parent_tip).unwrap();
        let mut transaction = Transaction {
            network_id: NETWORK,
            sender: founder,
            recipient: RECIPIENT,
            nonce: 1,
            amount: 5_000,
            fee: 10,
            expires_at: parent.last_timestamp() + 10_000,
            signature: Vec::new(),
        };
        signer.sign_transaction(&mut transaction).unwrap();
        let signing_digest = transaction_signing_digest(&transaction).unwrap();
        assert_eq!(
            authenticator.verify(&transaction.sender, &signing_digest, &transaction.signature,),
            Ok(())
        );
        let legacy_ed25519 = ed25519_dalek::SigningKey::from_bytes(&[0x83; 32]);
        let legacy_signature =
            ed25519_dalek::Signer::sign(&legacy_ed25519, &signing_digest).to_bytes();
        assert_eq!(
            authenticator.verify(&founder, &signing_digest, &legacy_signature),
            Err(()),
            "QFP6 hybrid auth must not accept a legacy Ed25519-only signature",
        );
        // Route the signed transfer through Q6TI and the bounded mempool before block production.
        let candidate_timestamp = parent.last_timestamp() + 60;
        let mut mempool =
            QRunV06NativeTransactionMempool::new(QRunV06MempoolLimits::default()).unwrap();
        let mut transaction_replay_guard = QRunV06PeerReplayGuard::new();
        let txid = transaction_id_with_signature_limit(
            &transaction,
            QRUN_V06_MAX_NATIVE_TX_SIGNATURE_BYTES,
        )
        .unwrap();
        let submit_frame = encode_q6ti_transaction_request(6_580, &transaction).unwrap();
        let submit_ack = process_q6ti_transaction_frame(
            &submit_frame,
            &mut transaction_replay_guard,
            &mut mempool,
            &parent,
            &authenticator,
            PRODUCER,
            candidate_timestamp,
        )
        .unwrap();
        let accepted_submit = decode_q6ta_response(&submit_ack, 6_580).unwrap();
        assert_eq!(
            accepted_submit.status,
            QRunV06TransactionSubmitStatus::Accepted
        );
        assert_eq!(accepted_submit.transaction_id, txid);
        assert_eq!(accepted_submit.mempool_count, 1);
        assert!(accepted_submit.mempool_bytes > 4 * 1024);
        assert_eq!(accepted_submit.canonical_height, parent.height());

        let duplicate_frame = encode_q6ti_transaction_request(6_581, &transaction).unwrap();
        let duplicate_ack = process_q6ti_transaction_frame(
            &duplicate_frame,
            &mut transaction_replay_guard,
            &mut mempool,
            &parent,
            &authenticator,
            PRODUCER,
            candidate_timestamp,
        )
        .unwrap();
        let duplicate = decode_q6ta_response(&duplicate_ack, 6_581).unwrap();
        assert_eq!(duplicate.status, QRunV06TransactionSubmitStatus::Duplicate);
        assert_eq!(duplicate.transaction_id, txid);
        assert_eq!(duplicate.mempool_count, 1);

        let block = mempool
            .build_block(&parent, &authenticator, PRODUCER, candidate_timestamp)
            .unwrap();
        assert_eq!(block.height, parent.height() + 1);
        assert_eq!(block.parent_hash, parent.tip_hash());
        assert_eq!(block.operations.len(), 1);
        assert_eq!(
            block.state_root,
            parent
                .preview_state_root_after(&block, &authenticator)
                .unwrap()
        );

        let mut header = PowHeader {
            protocol_version: 6,
            network_id: NETWORK,
            height: block.height,
            timestamp: block.timestamp,
            parent_hash: block.parent_hash,
            previous_consensus_hash: parent_tip,
            state_root: qrun_v06_pow_state_commitment(&block).unwrap(),
            target,
            nonce: 0,
        };
        let mut envelope = None;
        for nonce in 0..4_096u64 {
            header.nonce = nonce;
            if Uint256::from_be_bytes(pow_digest(&header, params.pow).unwrap()) <= target {
                envelope = Some(encode_qrun_v06_pow_block(&header, &block).unwrap());
                break;
            }
        }
        let envelope = envelope.expect("Q6HA integration test PoW search exhausted");
        let frame = encode_qrun_v06_peer_block_request(6_582, &envelope).unwrap();
        let mut replay_guard = QRunV06PeerReplayGuard::new();
        let mut quote = quote_provider();
        let fixture = qap1_coordinator(&dir, &initial);
        let mut coordinator = fixture.coordinator();

        let accepted = process_qrun_v06_peer_block_frame_with_qap1(
            &mut runtime,
            &mut replay_guard,
            &frame,
            &authenticator,
            &mut quote,
            &mut coordinator,
        )
        .unwrap();
        assert_eq!(accepted.request_id(), 6_582);
        assert_eq!(accepted.status(), QRunV06PeerAdmissionStatus::Accepted);
        assert!(accepted.is_positive_ack());
        assert_eq!(runtime.canonical_height().unwrap(), 1);
        assert_eq!(runtime.manifest_generation().unwrap(), 1);
        assert!(!runtime.store.has_qap1_intent().unwrap());
        assert_eq!(mempool.remove_included(&[transaction.clone()]), 1);
        assert!(mempool.is_empty());
        coordinator
            .verify_current(runtime.committed_anchor_state())
            .unwrap();

        let committed = runtime.store.graph().unwrap().canonical_state().clone();
        let recipient = committed
            .unified()
            .ledger()
            .account(&RECIPIENT)
            .expect("Q6HA recipient ledger account should be created");
        assert_eq!(recipient.balance, 5_000);
        assert_eq!(recipient.nonce, 0);
        let founder_account = committed
            .unified()
            .ledger()
            .account(&founder)
            .expect("Q6HA founder ledger account must remain present");
        assert_eq!(founder_account.nonce, 1);

        let generation = runtime.manifest_generation().unwrap();
        let replayed = process_qrun_v06_peer_block_frame_with_qap1(
            &mut runtime,
            &mut replay_guard,
            &frame,
            &authenticator,
            &mut quote,
            &mut coordinator,
        )
        .unwrap();
        assert_eq!(replayed.status(), QRunV06PeerAdmissionStatus::Rejected);
        assert!(!replayed.is_positive_ack());
        assert_eq!(runtime.canonical_height().unwrap(), 1);
        assert_eq!(runtime.manifest_generation().unwrap(), generation);
        coordinator
            .verify_current(runtime.committed_anchor_state())
            .unwrap();
    }

    #[test]
    fn qap1_runtime_recovers_exact_anchor_cas_after_lost_response_and_restart() {
        let (dir, store) = open_store();
        let initial = QRunV06ExternalAnchorState::from_store(&store, GENESIS_DIGEST).unwrap();
        let fixture = qap1_coordinator(&dir, &initial);
        *fixture.fail_after_cas_response.lock().unwrap() = true;

        let gate = MockAnchorGate {
            current: initial.clone(),
            fail_next_advance: false,
            advance_calls: 0,
        };
        let mut runtime =
            QRunV06NodeRuntime::new(store, gate, GENESIS_DIGEST, initial.clone()).unwrap();
        let envelope = first_block(&runtime.store);
        let mut quote = quote_provider();
        let mut coordinator = fixture.coordinator();

        let first = runtime.submit_envelope_with_qap1(
            &envelope,
            &EmptyAuthenticator,
            &mut quote,
            &mut coordinator,
        );
        assert!(matches!(first, Err(QRunV06NodeRuntimeError::Qap1(_))));
        assert_eq!(runtime.canonical_height().unwrap(), 0);
        assert_eq!(runtime.manifest_generation().unwrap(), 0);
        assert!(runtime.requires_reopen());
        assert!(runtime.qap1_required);
        assert!(runtime.store.has_qap1_intent().unwrap());
        drop(coordinator);
        drop(runtime);

        // Q6EA applied the first CAS even though its response was lost. The local store is
        // still at the predecessor. Reopen from that independently provisioned predecessor,
        // then resume the byte-exact persisted CAS request rather than creating a new operation.
        let genesis = genesis_state();
        let descriptor = genesis.genesis_descriptor_commitment().unwrap();
        let reopened_store =
            QRunV06DurableForkStore::open_with_expected_genesis_descriptor_commitment(
                &dir.0,
                genesis,
                params(),
                &EmptyAuthenticator,
                Some(initial.manifest_anchor),
                descriptor,
            )
            .unwrap();
        assert!(reopened_store.has_qap1_intent().unwrap());

        let recovery_gate = MockAnchorGate {
            current: initial.clone(),
            fail_next_advance: false,
            advance_calls: 0,
        };
        let mut recovery_quote = quote_provider();
        let mut recovered = QRunV06NodeRuntime::recover_qap1_after_process_restart(
            reopened_store,
            recovery_gate,
            fixture.coordinator(),
            GENESIS_DIGEST,
            &EmptyAuthenticator,
            &mut recovery_quote,
        )
        .unwrap();

        assert_eq!(recovered.canonical_height().unwrap(), 1);
        assert_eq!(recovered.manifest_generation().unwrap(), 1);
        assert!(recovered.qap1_required);
        assert!(!recovered.requires_reopen());
        assert!(!recovered.store.has_qap1_intent().unwrap());
        assert!(matches!(
            recovered.submit_envelope(&envelope, &EmptyAuthenticator, &mut recovery_quote,),
            Err(QRunV06NodeRuntimeError::Qap1(_))
        ));
    }

    #[test]
    fn legacy_runtime_startup_refuses_any_durable_qap1_intent() {
        let (_dir, store) = open_store();
        let initial = QRunV06ExternalAnchorState::from_store(&store, GENESIS_DIGEST).unwrap();
        let journal_directory = store.qap1_directory().unwrap();
        fs::create_dir(&journal_directory).unwrap();
        fs::write(
            journal_directory.join("qfp6-anchor-qap1-01.qap1"),
            b"deliberately corrupt incomplete QAP1 marker",
        )
        .unwrap();
        assert!(store.has_qap1_intent().unwrap());

        let gate = MockAnchorGate {
            current: initial.clone(),
            fail_next_advance: false,
            advance_calls: 0,
        };
        assert!(matches!(
            QRunV06NodeRuntime::new(store, gate, GENESIS_DIGEST, initial),
            Err(QRunV06NodeRuntimeError::Qap1(_))
        ));
    }

    #[test]
    fn startup_requires_exact_external_anchor_state_and_provider_confirmation() {
        let (_dir, store) = open_store();
        let expected = QRunV06ExternalAnchorState::from_store(&store, GENESIS_DIGEST).unwrap();
        let gate = MockAnchorGate {
            current: expected.clone(),
            fail_next_advance: false,
            advance_calls: 0,
        };
        let runtime = QRunV06NodeRuntime::new(store, gate, GENESIS_DIGEST, expected).unwrap();
        assert_eq!(runtime.canonical_height().unwrap(), 0);

        let (_dir, wrong_store) = open_store();
        let actual = QRunV06ExternalAnchorState::from_store(&wrong_store, GENESIS_DIGEST).unwrap();
        let mut wrong_expected = actual.clone();
        wrong_expected.genesis_digest = [0x76; 32];
        let gate = MockAnchorGate {
            current: wrong_expected.clone(),
            fail_next_advance: false,
            advance_calls: 0,
        };
        assert!(matches!(
            QRunV06NodeRuntime::new(wrong_store, gate, GENESIS_DIGEST, wrong_expected),
            Err(QRunV06NodeRuntimeError::ExternalAnchorStateMismatch)
        ));
    }

    #[test]
    fn local_commit_is_not_ackable_until_external_anchor_reconciles() {
        let (_dir, store) = open_store();
        let initial = QRunV06ExternalAnchorState::from_store(&store, GENESIS_DIGEST).unwrap();
        let gate = MockAnchorGate {
            current: initial.clone(),
            fail_next_advance: true,
            advance_calls: 0,
        };
        let mut runtime = QRunV06NodeRuntime::new(store, gate, GENESIS_DIGEST, initial).unwrap();
        let envelope = first_block(&runtime.store);
        let mut provider = quote_provider();

        let first = runtime
            .submit_envelope(&envelope, &EmptyAuthenticator, &mut provider)
            .unwrap();
        assert!(matches!(
            first,
            QRunV06NodeAdmission::ExternalAnchorPending(_)
        ));
        assert!(!first.is_acknowledged());
        assert_eq!(runtime.canonical_height().unwrap(), 1);
        assert!(runtime.has_pending_external_anchor());
        assert!(matches!(
            runtime.submit_envelope(&envelope, &EmptyAuthenticator, &mut provider),
            Err(QRunV06NodeRuntimeError::PendingAnchorMustBeReconciled)
        ));

        let reconciled = runtime.reconcile_pending().unwrap();
        assert!(matches!(reconciled, QRunV06NodeAdmission::Acknowledged(_)));
        assert!(reconciled.is_acknowledged());
        assert!(!runtime.has_pending_external_anchor());
        assert_eq!(runtime.manifest_generation().unwrap(), 1);
    }

    #[test]
    fn restart_recovers_a_local_manifest_commit_from_its_independent_predecessor() {
        let (_dir, mut store) = open_store();
        let predecessor = QRunV06ExternalAnchorState::from_store(&store, GENESIS_DIGEST).unwrap();
        let envelope = first_block(&store);
        let mut provider = quote_provider();

        // Simulate the old process stopping after the QFP6 store committed but before it
        // could advance the external anchor or return a peer/application ACK.
        store
            .submit_with_quote_asset_authorization(&envelope, &EmptyAuthenticator, &mut provider)
            .unwrap();
        let local_successor =
            QRunV06ExternalAnchorState::from_store(&store, GENESIS_DIGEST).unwrap();
        assert_eq!(local_successor.canonical_height, 1);

        let gate = MockAnchorGate {
            current: predecessor.clone(),
            fail_next_advance: false,
            advance_calls: 0,
        };
        let recovered = QRunV06NodeRuntime::recover_after_process_restart(
            store,
            gate,
            GENESIS_DIGEST,
            predecessor,
        )
        .unwrap();
        assert_eq!(recovered.canonical_height().unwrap(), 1);
        assert_eq!(recovered.committed_anchor_state(), &local_successor);
        assert!(!recovered.has_pending_external_anchor());
        assert!(!recovered.requires_reopen());
    }

    #[test]
    fn q6pb_stream_reader_is_bounded_and_consumes_exactly_one_frame() {
        let first = encode_qrun_v06_peer_block_request(11, &[1, 2, 3]).unwrap();
        let second = encode_qrun_v06_peer_block_request(12, &[4, 5]).unwrap();
        let mut bytes = first.clone();
        bytes.extend_from_slice(&second);
        let mut stream = std::io::Cursor::new(bytes);

        assert_eq!(read_qrun_v06_peer_block_frame(&mut stream), Ok(first));
        assert_eq!(read_qrun_v06_peer_block_frame(&mut stream), Ok(second));

        let mut oversized_header = [0u8; QRUN_V06_PEER_BLOCK_HEADER_BYTES];
        oversized_header[..4].copy_from_slice(&QRUN_V06_PEER_BLOCK_MAGIC);
        oversized_header[4..6].copy_from_slice(&QRUN_V06_PEER_FRAME_VERSION.to_be_bytes());
        oversized_header[6..8].copy_from_slice(&1u16.to_be_bytes());
        let oversized =
            u32::try_from(crate::qrun_v06_pow_wire_candidate::MAX_QRUN_V06_POW_ENVELOPE_BYTES)
                .unwrap()
                .checked_add(1)
                .unwrap();
        oversized_header[16..20].copy_from_slice(&oversized.to_be_bytes());
        let mut oversized_stream = std::io::Cursor::new(oversized_header.to_vec());
        assert_eq!(
            read_qrun_v06_peer_block_frame(&mut oversized_stream),
            Err(QRunV06PeerIngressError::Oversize)
        );
        assert_eq!(
            oversized_stream.position(),
            QRUN_V06_PEER_BLOCK_HEADER_BYTES as u64,
            "oversized peer length must be rejected before reading/allocating a payload"
        );

        let mut truncated = encode_qrun_v06_peer_block_request(13, &[9, 8, 7]).unwrap();
        truncated.pop();
        assert_eq!(
            read_qrun_v06_peer_block_frame(&mut std::io::Cursor::new(truncated)),
            Err(QRunV06PeerIngressError::Incomplete)
        );
    }

    #[test]
    fn q6pb_stream_handler_writes_only_the_coordinator_admission_response() {
        let (_dir, store) = open_store();
        let initial = QRunV06ExternalAnchorState::from_store(&store, GENESIS_DIGEST).unwrap();
        let gate = MockAnchorGate {
            current: initial.clone(),
            fail_next_advance: false,
            advance_calls: 0,
        };
        let mut runtime = QRunV06NodeRuntime::new(store, gate, GENESIS_DIGEST, initial).unwrap();
        let frame = encode_qrun_v06_peer_block_request(144, &first_block(&runtime.store)).unwrap();
        let mut stream = TestPeerStream::new(frame);
        let mut replay_guard = QRunV06PeerReplayGuard::new();
        let mut provider = quote_provider();

        let response = handle_qrun_v06_peer_stream(
            &mut stream,
            &mut runtime,
            &mut replay_guard,
            &EmptyAuthenticator,
            &mut provider,
        )
        .unwrap();

        assert_eq!(response.request_id(), 144);
        assert_eq!(response.status(), QRunV06PeerAdmissionStatus::Accepted);
        assert!(response.is_positive_ack());
        assert_eq!(stream.output.len(), QRUN_V06_PEER_ADMISSION_RESPONSE_BYTES);
        assert_eq!(&stream.output[..4], &QRUN_V06_PEER_ADMISSION_MAGIC);
        assert_eq!(
            u16::from_be_bytes([stream.output[6], stream.output[7]]),
            QRunV06PeerAdmissionStatus::Accepted as u16
        );
    }

    #[test]
    fn q6pb_peer_frame_roundtrips_and_rejects_length_mismatch() {
        let frame = encode_qrun_v06_peer_block_request(0x0102_0304_0506_0708, &[1, 2, 3]).unwrap();
        let decoded = decode_qrun_v06_peer_block_request(&frame).unwrap();
        assert_eq!(decoded.request_id, 0x0102_0304_0506_0708);
        assert_eq!(decoded.envelope, vec![1, 2, 3]);

        let mut truncated = frame.clone();
        truncated.pop();
        assert_eq!(
            decode_qrun_v06_peer_block_request(&truncated),
            Err(QRunV06PeerIngressError::LengthMismatch)
        );
        let mut wrong_magic = frame;
        wrong_magic[0] ^= 0x01;
        assert_eq!(
            decode_qrun_v06_peer_block_request(&wrong_magic),
            Err(QRunV06PeerIngressError::BadMagic)
        );
    }

    #[test]
    fn peer_ingress_emits_positive_ack_only_after_local_commit_and_external_anchor() {
        let (_dir, store) = open_store();
        let initial = QRunV06ExternalAnchorState::from_store(&store, GENESIS_DIGEST).unwrap();
        let gate = MockAnchorGate {
            current: initial.clone(),
            fail_next_advance: false,
            advance_calls: 0,
        };
        let mut runtime = QRunV06NodeRuntime::new(store, gate, GENESIS_DIGEST, initial).unwrap();
        let envelope = first_block(&runtime.store);
        let frame = encode_qrun_v06_peer_block_request(77, &envelope).unwrap();
        let mut replay_guard = QRunV06PeerReplayGuard::new();
        let mut provider = quote_provider();

        let response = process_qrun_v06_peer_block_frame(
            &mut runtime,
            &mut replay_guard,
            &frame,
            &EmptyAuthenticator,
            &mut provider,
        )
        .unwrap();
        assert_eq!(response.request_id(), 77);
        assert_eq!(response.status(), QRunV06PeerAdmissionStatus::Accepted);
        assert!(response.is_positive_ack());
        let encoded = response.encode();
        assert_eq!(encoded.len(), QRUN_V06_PEER_ADMISSION_RESPONSE_BYTES);
        assert_eq!(&encoded[..4], &QRUN_V06_PEER_ADMISSION_MAGIC);
        assert_eq!(
            u16::from_be_bytes([encoded[6], encoded[7]]),
            QRunV06PeerAdmissionStatus::Accepted as u16
        );
        assert_eq!(u64::from_be_bytes(encoded[80..88].try_into().unwrap()), 1);
    }

    #[test]
    fn peer_ingress_defers_pending_anchor_without_ack_then_accepts_exact_retry() {
        let (_dir, store) = open_store();
        let initial = QRunV06ExternalAnchorState::from_store(&store, GENESIS_DIGEST).unwrap();
        let gate = MockAnchorGate {
            current: initial.clone(),
            fail_next_advance: true,
            advance_calls: 0,
        };
        let mut runtime = QRunV06NodeRuntime::new(store, gate, GENESIS_DIGEST, initial).unwrap();
        let envelope = first_block(&runtime.store);
        let frame = encode_qrun_v06_peer_block_request(88, &envelope).unwrap();
        let mut replay_guard = QRunV06PeerReplayGuard::new();
        let mut provider = quote_provider();

        let deferred = process_qrun_v06_peer_block_frame(
            &mut runtime,
            &mut replay_guard,
            &frame,
            &EmptyAuthenticator,
            &mut provider,
        )
        .unwrap();
        assert_eq!(deferred.status(), QRunV06PeerAdmissionStatus::Deferred);
        assert!(!deferred.is_positive_ack());
        let deferred_bytes = deferred.encode();
        assert_eq!(
            u16::from_be_bytes([deferred_bytes[6], deferred_bytes[7]]),
            QRunV06PeerAdmissionStatus::Deferred as u16
        );
        assert!(deferred_bytes[16..].iter().all(|byte| *byte == 0));
        assert!(runtime.has_pending_external_anchor());

        assert!(runtime.reconcile_pending().unwrap().is_acknowledged());
        // A retry reuses the exact envelope but receives a fresh, strictly increasing request ID.
        let retry_frame = encode_qrun_v06_peer_block_request(89, &envelope).unwrap();
        let accepted = process_qrun_v06_peer_block_frame(
            &mut runtime,
            &mut replay_guard,
            &retry_frame,
            &EmptyAuthenticator,
            &mut provider,
        )
        .unwrap();
        assert_eq!(accepted.status(), QRunV06PeerAdmissionStatus::Accepted);
        assert!(accepted.is_positive_ack());
        assert_eq!(accepted.request_id(), 89);
    }

    #[test]
    fn peer_ingress_rejects_invalid_block_without_positive_ack() {
        let (_dir, store) = open_store();
        let initial = QRunV06ExternalAnchorState::from_store(&store, GENESIS_DIGEST).unwrap();
        let gate = MockAnchorGate {
            current: initial.clone(),
            fail_next_advance: false,
            advance_calls: 0,
        };
        let mut runtime = QRunV06NodeRuntime::new(store, gate, GENESIS_DIGEST, initial).unwrap();
        let frame = encode_qrun_v06_peer_block_request(99, b"not-a-qfp6-envelope").unwrap();
        let mut replay_guard = QRunV06PeerReplayGuard::new();
        let mut provider = quote_provider();

        let rejected = process_qrun_v06_peer_block_frame(
            &mut runtime,
            &mut replay_guard,
            &frame,
            &EmptyAuthenticator,
            &mut provider,
        )
        .unwrap();
        assert_eq!(rejected.status(), QRunV06PeerAdmissionStatus::Rejected);
        assert!(!rejected.is_positive_ack());
        assert_eq!(rejected.durable_commit(), None);
    }

    #[test]
    fn peer_ingress_rejects_zero_duplicate_and_out_of_order_ids_before_execution() {
        let (_dir, store) = open_store();
        let initial = QRunV06ExternalAnchorState::from_store(&store, GENESIS_DIGEST).unwrap();
        let gate = MockAnchorGate {
            current: initial.clone(),
            fail_next_advance: false,
            advance_calls: 0,
        };
        let mut runtime = QRunV06NodeRuntime::new(store, gate, GENESIS_DIGEST, initial).unwrap();
        let first_envelope = first_block(&runtime.store);
        let mut replay_guard = QRunV06PeerReplayGuard::new();
        let mut provider = quote_provider();

        let accepted = process_qrun_v06_peer_block_frame(
            &mut runtime,
            &mut replay_guard,
            &encode_qrun_v06_peer_block_request(10, &first_envelope).unwrap(),
            &EmptyAuthenticator,
            &mut provider,
        )
        .unwrap();
        assert_eq!(accepted.status(), QRunV06PeerAdmissionStatus::Accepted);
        assert_eq!(runtime.canonical_height().unwrap(), 1);
        assert_eq!(replay_guard.last_request_id(), Some(10));

        // A different valid block cannot be smuggled through by reusing an accepted ID.
        let second_envelope = first_block(&runtime.store);
        for replayed_id in [10, 9, 0] {
            let rejected = process_qrun_v06_peer_block_frame(
                &mut runtime,
                &mut replay_guard,
                &encode_qrun_v06_peer_block_request(replayed_id, &second_envelope).unwrap(),
                &EmptyAuthenticator,
                &mut provider,
            )
            .unwrap();
            assert_eq!(rejected.status(), QRunV06PeerAdmissionStatus::Rejected);
            assert!(!rejected.is_positive_ack());
            assert_eq!(rejected.durable_commit(), None);
            assert_eq!(runtime.canonical_height().unwrap(), 1);
            assert_eq!(replay_guard.last_request_id(), Some(10));
        }

        // The same candidate block is admitted only under the next fresh session sequence.
        let next = process_qrun_v06_peer_block_frame(
            &mut runtime,
            &mut replay_guard,
            &encode_qrun_v06_peer_block_request(11, &second_envelope).unwrap(),
            &EmptyAuthenticator,
            &mut provider,
        )
        .unwrap();
        assert_eq!(next.status(), QRunV06PeerAdmissionStatus::Accepted);
        assert!(next.is_positive_ack());
        assert_eq!(runtime.canonical_height().unwrap(), 2);
        assert_eq!(replay_guard.last_request_id(), Some(11));
    }

    fn noise_keypair() -> ([u8; 32], [u8; 32]) {
        let params: snow::params::NoiseParams = "Noise_XX_25519_ChaChaPoly_SHA256".parse().unwrap();
        let mut pair = snow::Builder::new(params).generate_keypair().unwrap();
        let mut private = [0u8; 32];
        let mut public = [0u8; 32];
        private.copy_from_slice(&pair.private);
        public.copy_from_slice(&pair.public);
        pair.private.fill(0);
        pair.public.fill(0);
        (private, public)
    }

    #[test]
    fn qfp6_block_admission_runs_inside_two_sided_pinned_noise_session() {
        let (_dir, store) = open_store();
        let initial = QRunV06ExternalAnchorState::from_store(&store, GENESIS_DIGEST).unwrap();
        let gate = MockAnchorGate {
            current: initial.clone(),
            fail_next_advance: false,
            advance_calls: 0,
        };
        let mut runtime = QRunV06NodeRuntime::new(store, gate, GENESIS_DIGEST, initial).unwrap();
        let envelope = first_block(&runtime.store);
        let frame = encode_qrun_v06_peer_block_request(240, &envelope).unwrap();

        let (server_private, server_public) = noise_keypair();
        let (client_private, client_public) = noise_keypair();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut noise = crate::qrun_v06_noise_transport_candidate::QRunV06NoiseSession::accept(
                &mut stream,
                &server_private,
                &[client_public],
                &NETWORK,
                &PROFILE,
            )
            .unwrap();
            assert_eq!(noise.remote_static_public_key(), &client_public);
            let mut replay_guard = QRunV06PeerReplayGuard::new();
            let mut provider = quote_provider();
            let response = handle_qrun_v06_noise_peer_request(
                &mut stream,
                &mut noise,
                &mut runtime,
                &mut replay_guard,
                &EmptyAuthenticator,
                &mut provider,
            )
            .unwrap();
            assert_eq!(response.status(), QRunV06PeerAdmissionStatus::Accepted);
            assert_eq!(response.request_id(), 240);
            response
        });

        let mut stream = TcpStream::connect(address).unwrap();
        let mut noise = crate::qrun_v06_noise_transport_candidate::QRunV06NoiseSession::connect(
            &mut stream,
            &client_private,
            &server_public,
            &NETWORK,
            &PROFILE,
        )
        .unwrap();
        assert_eq!(noise.remote_static_public_key(), &server_public);
        noise.write_q6pb_request(&mut stream, &frame).unwrap();
        let response = noise.read_q6pa_response(&mut stream, 240).unwrap();
        assert_eq!(
            u16::from_be_bytes([response[6], response[7]]),
            QRunV06PeerAdmissionStatus::Accepted as u16
        );
        assert_eq!(u64::from_be_bytes(response[8..16].try_into().unwrap()), 240);
        assert_eq!(
            server.join().unwrap().status(),
            QRunV06PeerAdmissionStatus::Accepted
        );
    }

    fn hex_array<const N: usize>(bytes: &[u8; N]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    fn parse_hex_array<const N: usize>(value: &str) -> [u8; N] {
        assert_eq!(
            value.len(),
            N * 2,
            "test worker byte array has an unexpected hex length"
        );
        let mut bytes = [0u8; N];
        for (index, byte) in bytes.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).unwrap();
        }
        bytes
    }

    fn hex32(bytes: &[u8; 32]) -> String {
        hex_array(bytes)
    }

    fn parse_hex32(value: &str) -> [u8; 32] {
        parse_hex_array(value)
    }

    #[test]
    fn qfp6_noise_two_process_worker() {
        let Ok(role) = env::var("QRUN_QFP6_NOISE_PROCESS_ROLE") else {
            return;
        };
        let address: SocketAddr = env::var("QRUN_QFP6_NOISE_PROCESS_ADDR")
            .expect("worker address")
            .parse()
            .unwrap();

        match role.as_str() {
            "server" => {
                let server_private =
                    parse_hex32(&env::var("QRUN_QFP6_NOISE_LOCAL_PRIVATE").unwrap());
                let client_public =
                    parse_hex32(&env::var("QRUN_QFP6_NOISE_REMOTE_PUBLIC").unwrap());
                let listener = TcpListener::bind(address).expect("server bind");
                listener.set_nonblocking(true).unwrap();
                let deadline = Instant::now() + Duration::from_secs(12);
                let (mut stream, _) = loop {
                    match listener.accept() {
                        Ok(connection) => break connection,
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            assert!(
                                Instant::now() < deadline,
                                "two-process client connection timed out"
                            );
                            thread::sleep(Duration::from_millis(20));
                        }
                        Err(error) => panic!("server accept failed: {error}"),
                    }
                };
                stream.set_nodelay(true).unwrap();

                let (_dir, store) = open_store();
                let initial =
                    QRunV06ExternalAnchorState::from_store(&store, GENESIS_DIGEST).unwrap();
                let gate = MockAnchorGate {
                    current: initial.clone(),
                    fail_next_advance: false,
                    advance_calls: 0,
                };
                let mut runtime =
                    QRunV06NodeRuntime::new(store, gate, GENESIS_DIGEST, initial).unwrap();
                let mut noise =
                    crate::qrun_v06_noise_transport_candidate::QRunV06NoiseSession::accept(
                        &mut stream,
                        &server_private,
                        &[client_public],
                        &NETWORK,
                        &PROFILE,
                    )
                    .expect("server pinned Noise handshake");
                assert_eq!(noise.remote_static_public_key(), &client_public);
                let mut replay_guard = QRunV06PeerReplayGuard::new();
                let mut provider = quote_provider();
                let response = handle_qrun_v06_noise_peer_request(
                    &mut stream,
                    &mut noise,
                    &mut runtime,
                    &mut replay_guard,
                    &EmptyAuthenticator,
                    &mut provider,
                )
                .expect("server QFP6 block admission");
                assert_eq!(response.request_id(), 0x5520);
                assert_eq!(response.status(), QRunV06PeerAdmissionStatus::Accepted);
                assert_eq!(runtime.canonical_height().unwrap(), 1);
                println!("QFP6_NOISE_TWO_PROCESS_SERVER=PASS");
            }
            "client" => {
                let client_private =
                    parse_hex32(&env::var("QRUN_QFP6_NOISE_LOCAL_PRIVATE").unwrap());
                let server_public =
                    parse_hex32(&env::var("QRUN_QFP6_NOISE_REMOTE_PUBLIC").unwrap());
                let (_dir, store) = open_store();
                let block = first_block(&store);
                let frame = encode_qrun_v06_peer_block_request(0x5520, &block).unwrap();

                let deadline = Instant::now() + Duration::from_secs(10);
                let mut stream = loop {
                    match TcpStream::connect(address) {
                        Ok(stream) => break stream,
                        Err(error) if Instant::now() < deadline => {
                            let _ = error;
                            thread::sleep(Duration::from_millis(25));
                        }
                        Err(error) => panic!(
                            "client could not connect to independent server process: {error}"
                        ),
                    }
                };
                stream.set_nodelay(true).unwrap();
                let mut noise =
                    crate::qrun_v06_noise_transport_candidate::QRunV06NoiseSession::connect(
                        &mut stream,
                        &client_private,
                        &server_public,
                        &NETWORK,
                        &PROFILE,
                    )
                    .expect("client pinned Noise handshake");
                assert_eq!(noise.remote_static_public_key(), &server_public);
                noise.write_q6pb_request(&mut stream, &frame).unwrap();
                let response = noise.read_q6pa_response(&mut stream, 0x5520).unwrap();
                assert_eq!(
                    u16::from_be_bytes([response[6], response[7]]),
                    QRunV06PeerAdmissionStatus::Accepted as u16
                );
                println!("QFP6_NOISE_TWO_PROCESS_CLIENT=PASS");
            }
            other => panic!("unknown two-process worker role: {other}"),
        }
    }

    #[test]
    fn qfp6_noise_xx_qualifies_two_independent_processes() {
        let (server_private, server_public) = noise_keypair();
        let (client_private, client_public) = noise_keypair();

        // Reserve an ephemeral loopback port, then release it for the independent server child.
        // The client child retries bounded connection establishment while the server binds.
        let probe = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = probe.local_addr().unwrap();
        drop(probe);

        let executable = env::current_exe().unwrap();
        let worker = "qrun_v06_node_runtime_candidate::tests::qfp6_noise_two_process_worker";
        let mut server = Command::new(&executable)
            .arg("--exact")
            .arg(worker)
            .arg("--nocapture")
            .env("QRUN_QFP6_NOISE_PROCESS_ROLE", "server")
            .env("QRUN_QFP6_NOISE_PROCESS_ADDR", address.to_string())
            .env("QRUN_QFP6_NOISE_LOCAL_PRIVATE", hex32(&server_private))
            .env("QRUN_QFP6_NOISE_REMOTE_PUBLIC", hex32(&client_public))
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn independent QFP6 server test process");

        let client_output = Command::new(&executable)
            .arg("--exact")
            .arg(worker)
            .arg("--nocapture")
            .env("QRUN_QFP6_NOISE_PROCESS_ROLE", "client")
            .env("QRUN_QFP6_NOISE_PROCESS_ADDR", address.to_string())
            .env("QRUN_QFP6_NOISE_LOCAL_PRIVATE", hex32(&client_private))
            .env("QRUN_QFP6_NOISE_REMOTE_PUBLIC", hex32(&server_public))
            .output()
            .expect("spawn independent QFP6 client test process");

        if !client_output.status.success() {
            let _ = server.kill();
            let _ = server.wait();
            panic!(
                "independent QFP6 client process failed; stdout={} stderr={}",
                String::from_utf8_lossy(&client_output.stdout),
                String::from_utf8_lossy(&client_output.stderr)
            );
        }
        let server_output = server
            .wait_with_output()
            .expect("wait for QFP6 server child");
        assert!(
            server_output.status.success(),
            "independent QFP6 server process failed; stdout={} stderr={}",
            String::from_utf8_lossy(&server_output.stdout),
            String::from_utf8_lossy(&server_output.stderr)
        );
        assert!(String::from_utf8_lossy(&client_output.stdout)
            .contains("QFP6_NOISE_TWO_PROCESS_CLIENT=PASS"));
        assert!(String::from_utf8_lossy(&server_output.stdout)
            .contains("QFP6_NOISE_TWO_PROCESS_SERVER=PASS"));
    }

    #[test]
    fn startup_fails_closed_when_external_provider_tip_is_stale() {
        let (_dir, store) = open_store();
        let expected = QRunV06ExternalAnchorState::from_store(&store, GENESIS_DIGEST).unwrap();
        let mut stale = expected.clone();
        stale.manifest_anchor[0] ^= 0x01;
        let gate = MockAnchorGate {
            current: stale,
            fail_next_advance: false,
            advance_calls: 0,
        };
        assert!(matches!(
            QRunV06NodeRuntime::new(store, gate, GENESIS_DIGEST, expected),
            Err(QRunV06NodeRuntimeError::ExternalAnchor(error)) if error.contains("anchor")
        ));
    }

    #[test]
    fn qfp6_qap1_process_worker() {
        let Ok(role) = env::var("QRUN_QFP6_QAP1_PROCESS_ROLE") else {
            return;
        };
        assert!(matches!(role.as_str(), "server" | "restart"));
        let remote_connect_timeout = Duration::from_secs(30);
        println!("QFP6_QAP1_REMOTE_CONNECT_TIMEOUT_SECONDS=30");

        use crate::external_cas_anchor_candidate::ExternalCasPin;
        use crate::external_cas_floor_store_candidate::ExternalCasFloorStore;
        use crate::external_cas_noise_transport_candidate::NoiseTcpExternalCasProviderTransport;
        use crate::external_cas_offhost_anchor_noise_transport_candidate::NoiseTcpOffhostAnchorTransport;
        use crate::external_cas_offhost_anchor_protocol_candidate::ExternalCasOffhostAnchorPin;
        use crate::qrun_v06_external_anchor_candidate::QRunV06ExternalAnchorPin;
        use crate::qrun_v06_qap1_coordinator_candidate::QRunV06Qap1ExternalCoordinator;

        let required = |name: &str| env::var(name).unwrap_or_else(|_| panic!("missing {name}"));
        let parse_addr = |name: &str| required(name).parse::<SocketAddr>().unwrap();
        let listen_address = parse_addr("QRUN_QFP6_QAP1_LISTEN_ADDR");
        let provider_address = parse_addr("QRUN_QFP6_QAP1_PROVIDER_ADDR");
        let anchor_address = parse_addr("QRUN_QFP6_QAP1_ANCHOR_ADDR");
        assert_qap1_test_bind_address(listen_address);
        assert_qap1_test_bind_address(provider_address);
        assert_qap1_test_bind_address(anchor_address);
        let listener_private = parse_hex32(&required("QRUN_QFP6_QAP1_LISTENER_PRIVATE"));
        let trusted_peer_public = parse_hex32(&required("QRUN_QFP6_QAP1_PEER_PUBLIC"));
        let provider_client_private =
            parse_hex32(&required("QRUN_QFP6_QAP1_PROVIDER_CLIENT_PRIVATE"));
        let provider_server_public =
            parse_hex32(&required("QRUN_QFP6_QAP1_PROVIDER_SERVER_PUBLIC"));
        let anchor_client_private = parse_hex32(&required("QRUN_QFP6_QAP1_ANCHOR_CLIENT_PRIVATE"));
        let anchor_server_public = parse_hex32(&required("QRUN_QFP6_QAP1_ANCHOR_SERVER_PUBLIC"));
        let provider_receipt_public: [u8;
            crate::v4_fat1_trust_candidate::ML_DSA_65_PUBLIC_KEY_BYTES] =
            parse_hex_array(&required("QRUN_QFP6_QAP1_PROVIDER_RECEIPT_PUBLIC"));
        let anchor_receipt_public: [u8;
            crate::v4_fat1_trust_candidate::ML_DSA_65_PUBLIC_KEY_BYTES] =
            parse_hex_array(&required("QRUN_QFP6_QAP1_ANCHOR_RECEIPT_PUBLIC"));
        let floor_directory = std::path::PathBuf::from(required("QRUN_QFP6_QAP1_FLOOR_DIR"));
        let node_directory = std::path::PathBuf::from(required("QRUN_QFP6_QAP1_NODE_DIR"));
        let trusted_anchor_value = required("QRUN_QFP6_QAP1_TRUSTED_MANIFEST_ANCHOR");
        let trusted_manifest_anchor = if trusted_anchor_value == "none" {
            None
        } else {
            Some(parse_hex32(&trusted_anchor_value))
        };

        let provider_pin = ExternalCasPin {
            provider_id: [0xE7; 32],
            network_id: NETWORK,
            genesis_digest: GENESIS_DIGEST,
            receipt_key_id: [0xE8; 32],
            receipt_public_key: provider_receipt_public,
        };
        let anchor_pin = ExternalCasOffhostAnchorPin {
            anchor_id: [0xE9; 32],
            provider_id: provider_pin.provider_id,
            network_id: provider_pin.network_id,
            genesis_digest: provider_pin.genesis_digest,
            receipt_key_id: [0xEA; 32],
            receipt_public_key: anchor_receipt_public,
        };

        let store = open_store_at_with_genesis(
            &node_directory,
            trusted_manifest_anchor,
            q6ti_test_genesis_state(),
        );
        let initial = QRunV06ExternalAnchorState::from_store(&store, GENESIS_DIGEST).unwrap();
        if role == "server" && env::var("QRUN_QFP6_QAP1_INITIALIZE_FLOOR").as_deref() == Ok("1") {
            let bootstrap_record = ExternalCasRecord {
                generation: 0,
                provider_id: provider_pin.provider_id,
                network_id: provider_pin.network_id,
                genesis_digest: provider_pin.genesis_digest,
                previous_record_digest: [0; 32],
                previous_state_digest: [0; 32],
                next_state_digest: initial.digest().unwrap(),
                operation_id: [0xEB; 32],
                request_digest: [0xEC; 32],
            };
            let floor = ExternalCasFloorStore::initialize(
                &floor_directory,
                provider_pin.clone(),
                bootstrap_record,
                1,
            )
            .expect("initialize remote QFP6 test floor from pinned Genesis bootstrap");
            drop(floor);
        }

        let provider_transport = NoiseTcpExternalCasProviderTransport::with_timeout(
            provider_address,
            provider_client_private,
            provider_server_public,
            provider_pin.clone(),
            remote_connect_timeout,
        )
        .unwrap();
        let anchor_transport = NoiseTcpOffhostAnchorTransport::with_timeout(
            anchor_address,
            anchor_client_private,
            anchor_server_public,
            anchor_pin.clone(),
            provider_pin.clone(),
            remote_connect_timeout,
        )
        .unwrap();
        let floor = ExternalCasFloorStore::open(&floor_directory, provider_pin.clone()).unwrap();
        let coordinator = QRunV06Qap1ExternalCoordinator::new(
            provider_transport,
            floor,
            anchor_transport,
            QRunV06ExternalAnchorPin::new(provider_pin, initial.genesis_descriptor_commitment)
                .unwrap(),
            anchor_pin.clone(),
            LibcruxMlDsa65VerifierCandidate,
            LibcruxMlDsa65VerifierCandidate,
        )
        .unwrap();

        let gate = MockAnchorGate {
            current: initial,
            fail_next_advance: false,
            advance_calls: 0,
        };
        let mut quote_authorizer = quote_provider();
        let authenticator =
            QRunV06HybridTransactionAuthenticator::new(LibcruxMlDsa65VerifierCandidate);
        let mut runtime = QRunV06NodeRuntime::recover_qap1_after_process_restart(
            store,
            gate,
            coordinator,
            GENESIS_DIGEST,
            &authenticator,
            &mut quote_authorizer,
        )
        .unwrap();
        assert!(runtime.qap1_required);

        if role == "restart" {
            let expected_height = required("QRUN_QFP6_QAP1_EXPECTED_HEIGHT")
                .parse::<u64>()
                .unwrap();
            let expected_generation = required("QRUN_QFP6_QAP1_EXPECTED_GENERATION")
                .parse::<u64>()
                .unwrap();
            let expected_state_root = parse_hex32(&required("QRUN_QFP6_QAP1_EXPECTED_STATE_ROOT"));
            let expected_manifest_anchor =
                parse_hex32(&required("QRUN_QFP6_QAP1_TRUSTED_MANIFEST_ANCHOR"));
            assert_eq!(runtime.canonical_height().unwrap(), expected_height);
            assert_eq!(runtime.manifest_generation().unwrap(), expected_generation);
            assert_eq!(
                runtime.store.canonical_state_root().unwrap(),
                expected_state_root
            );
            assert_eq!(
                runtime.store.manifest_anchor().unwrap(),
                expected_manifest_anchor
            );
            assert!(!runtime.store.has_qap1_intent().unwrap());

            let mut transaction_journal = QRunV06TransactionJournal::open(
                node_directory.join("q6ti-pending-journal"),
                QRunV06MempoolLimits::default(),
            )
            .unwrap();
            let mut mempool =
                QRunV06NativeTransactionMempool::new(QRunV06MempoolLimits::default()).unwrap();
            let recovered_fork_choice = runtime.fork_choice_snapshot().unwrap();
            let recovered_state = recovered_fork_choice.canonical_state();
            let restore_timestamp = recovered_state.last_timestamp().checked_add(60).unwrap();
            let restore_summary = transaction_journal
                .restore_into_pool(
                    &mut mempool,
                    recovered_state,
                    &authenticator,
                    PRODUCER,
                    restore_timestamp,
                )
                .unwrap();
            assert_eq!(restore_summary.restored, 1);
            assert_eq!(restore_summary.dropped_invalid_or_stale, 0);
            assert_eq!(mempool.len(), 1);
            let expected_transaction_id =
                parse_hex32(&required("QRUN_QFP6_QAP1_EXPECTED_TRANSACTION_ID"));
            let restored_transaction = mempool.ordered_transactions();
            assert_eq!(restored_transaction.len(), 1);
            let restored_transaction_id = transaction_id_with_signature_limit(
                &restored_transaction[0],
                QRUN_V06_MAX_NATIVE_TX_SIGNATURE_BYTES,
            )
            .unwrap();
            assert_eq!(restored_transaction_id, expected_transaction_id);
            let expected_journal_generation =
                required("QRUN_QFP6_QAP1_EXPECTED_JOURNAL_GENERATION")
                    .parse::<u64>()
                    .unwrap();
            assert_eq!(
                transaction_journal.generation(),
                expected_journal_generation.checked_add(1).unwrap()
            );
            println!(
                "QFP6_Q6MJ_RESTART_GENERATION={}",
                transaction_journal.generation()
            );
            println!("QFP6_Q6MJ_RESTART_PENDING_COUNT={}", mempool.len());
            println!("QFP6_Q6MJ_RESTART_TXID={}", hex32(&restored_transaction_id));
            println!("QFP6_Q6MJ_RESTART=PASS");
            println!("QFP6_QAP1_RESTART_SERVER=PASS");
            drop(transaction_journal);
            drop(runtime);
            return;
        }

        let mut transaction_journal = QRunV06TransactionJournal::open(
            node_directory.join("q6ti-pending-journal"),
            QRunV06MempoolLimits::default(),
        )
        .unwrap();
        let mut mempool =
            QRunV06NativeTransactionMempool::new(QRunV06MempoolLimits::default()).unwrap();
        let startup_fork_choice = runtime.fork_choice_snapshot().unwrap();
        let startup_state = startup_fork_choice.canonical_state();
        let startup_timestamp = startup_state.last_timestamp().checked_add(60).unwrap();
        let startup_restore = transaction_journal
            .restore_into_pool(
                &mut mempool,
                startup_state,
                &authenticator,
                PRODUCER,
                startup_timestamp,
            )
            .unwrap();
        assert_eq!(startup_restore.restored, 0);
        assert_eq!(mempool.len(), 0);
        assert_eq!(transaction_journal.generation(), 1);

        let listener = TcpListener::bind(listen_address).expect("bind private QFP6 test listener");
        let listener_timeout_secs = env::var("QRUN_QFP6_QAP1_LISTENER_TIMEOUT_SECS")
            .ok()
            .map(|value| {
                value
                    .parse::<u64>()
                    .expect("listener timeout must be an integer")
            })
            .unwrap_or(15);
        assert!(
            (1..=900).contains(&listener_timeout_secs),
            "QFP6 test listener timeout must be between 1 and 900 seconds"
        );
        let shutdown = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let watchdog_flag = Arc::clone(&shutdown);
        let watchdog = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(listener_timeout_secs);
            while Instant::now() < deadline {
                if watchdog_flag.load(std::sync::atomic::Ordering::Acquire) {
                    return;
                }
                thread::sleep(Duration::from_millis(10));
            }
            watchdog_flag.store(true, std::sync::atomic::Ordering::Release);
        });

        // NetBird can lazily re-activate an idle peer between the admission and
        // restart processes. Use the supported 30-second connection ceiling for
        // this cross-host qualification worker instead of the 5-second default.
        let mut coordinator = {
            let provider_transport = NoiseTcpExternalCasProviderTransport::with_timeout(
                provider_address,
                provider_client_private,
                provider_server_public,
                ExternalCasPin {
                    provider_id: [0xE7; 32],
                    network_id: NETWORK,
                    genesis_digest: GENESIS_DIGEST,
                    receipt_key_id: [0xE8; 32],
                    receipt_public_key: provider_receipt_public,
                },
                remote_connect_timeout,
            )
            .unwrap();
            let provider_pin = ExternalCasPin {
                provider_id: [0xE7; 32],
                network_id: NETWORK,
                genesis_digest: GENESIS_DIGEST,
                receipt_key_id: [0xE8; 32],
                receipt_public_key: provider_receipt_public,
            };
            let anchor_transport = NoiseTcpOffhostAnchorTransport::with_timeout(
                anchor_address,
                anchor_client_private,
                anchor_server_public,
                anchor_pin.clone(),
                provider_pin.clone(),
                remote_connect_timeout,
            )
            .unwrap();
            let floor =
                ExternalCasFloorStore::open(&floor_directory, provider_pin.clone()).unwrap();
            QRunV06Qap1ExternalCoordinator::new(
                provider_transport,
                floor,
                anchor_transport,
                QRunV06ExternalAnchorPin::new(
                    provider_pin,
                    runtime
                        .committed_anchor_state()
                        .genesis_descriptor_commitment,
                )
                .unwrap(),
                anchor_pin,
                LibcruxMlDsa65VerifierCandidate,
                LibcruxMlDsa65VerifierCandidate,
            )
            .unwrap()
        };

        let report = serve_qfp6_noise_listener(
            &listener,
            QRunV06PeerListenerConfig {
                max_sessions: 1,
                max_requests_per_session: 4,
                max_failed_handshakes: 2,
                accept_poll_interval: Duration::from_millis(10),
            },
            &listener_private,
            &[trusted_peer_public],
            &NETWORK,
            &PROFILE,
            &shutdown,
            |replay_guard, frame| {
                process_qfp6_application_frame_with_qap1(
                    &mut runtime,
                    replay_guard,
                    &mut mempool,
                    &mut transaction_journal,
                    frame,
                    &authenticator,
                    PRODUCER,
                    &mut quote_authorizer,
                    &mut coordinator,
                )
            },
        )
        .unwrap();
        shutdown.store(true, std::sync::atomic::Ordering::Release);
        watchdog.join().unwrap();

        assert_eq!(
            report.stop_reason,
            crate::qrun_v06_peer_listener_candidate::QRunV06PeerListenerStopReason::SessionLimitReached
        );
        assert_eq!(report.stats.accepted_connections, 1);
        assert_eq!(report.stats.authenticated_sessions, 1);
        assert_eq!(report.stats.requests_received, 4);
        assert_eq!(report.stats.responses_written, 4);
        assert_eq!(report.stats.sessions_closed, 1);
        assert_eq!(runtime.canonical_height().unwrap(), 1);
        assert_eq!(runtime.manifest_generation().unwrap(), 1);
        assert!(!runtime.store.has_qap1_intent().unwrap());
        assert_eq!(mempool.len(), 1);
        assert_eq!(transaction_journal.generation(), 4);
        println!(
            "QFP6_QAP1_MANIFEST_ANCHOR={}",
            hex32(&runtime.store.manifest_anchor().unwrap())
        );
        println!(
            "QFP6_QAP1_STATE_ROOT={}",
            hex32(&runtime.store.canonical_state_root().unwrap())
        );
        println!("QFP6_QAP1_HEIGHT={}", runtime.canonical_height().unwrap());
        println!(
            "QFP6_QAP1_GENERATION={}",
            runtime.manifest_generation().unwrap()
        );
        let pending_transactions = mempool.ordered_transactions();
        assert_eq!(pending_transactions.len(), 1);
        let pending_transaction_id = transaction_id_with_signature_limit(
            &pending_transactions[0],
            QRUN_V06_MAX_NATIVE_TX_SIGNATURE_BYTES,
        )
        .unwrap();
        println!("QFP6_Q6MJ_GENERATION={}", transaction_journal.generation());
        println!("QFP6_Q6MJ_PENDING_COUNT={}", mempool.len());
        println!("QFP6_Q6MJ_TXID={}", hex32(&pending_transaction_id));
        println!("QFP6_Q6MJ=PASS");
        println!("QFP6_QAP1_PROCESS_SERVER=PASS");
        drop(transaction_journal);
        drop(runtime);
        drop(coordinator);
    }

    #[test]
    fn qap1_cross_host_node_a_driver_worker() {
        if env::var("QRUN_QFP6_QAP1_PROCESS_ROLE").as_deref() != Ok("driver") {
            return;
        }

        use crate::external_cas_anchor_candidate::ExternalCasPin;
        use crate::external_cas_disk_provider_candidate::DurableExternalCasProvider;
        use crate::external_cas_floor_store_candidate::ExternalCasFloorStore;
        use crate::external_cas_offhost_anchor_candidate::ExternalCasOffhostAnchorState;
        use crate::external_cas_offhost_anchor_protocol_candidate::ExternalCasOffhostAnchorPin;

        let required = |name: &str| env::var(name).unwrap_or_else(|_| panic!("missing {name}"));
        let provider_bind = required("QRUN_QFP6_QAP1_DRIVER_PROVIDER_BIND_ADDR")
            .parse::<SocketAddr>()
            .unwrap();
        let anchor_bind = required("QRUN_QFP6_QAP1_DRIVER_ANCHOR_BIND_ADDR")
            .parse::<SocketAddr>()
            .unwrap();
        let runner_listener_port = required("QRUN_QFP6_QAP1_DRIVER_RUNNER_PORT")
            .parse::<u16>()
            .unwrap();
        assert!((1024..=65535).contains(&runner_listener_port));
        assert_qap1_test_bind_address(provider_bind);
        assert_qap1_test_bind_address(anchor_bind);
        assert_eq!(provider_bind.ip(), anchor_bind.ip());
        assert_eq!(
            provider_bind.port(),
            0,
            "Provider must select an ephemeral TCP port"
        );
        assert_eq!(
            anchor_bind.port(),
            0,
            "Q6EA must select an ephemeral TCP port"
        );

        let (dir, store) = open_store();
        let initial = QRunV06ExternalAnchorState::from_store(&store, GENESIS_DIGEST).unwrap();
        let service_root = dir.0.with_extension("cp0566c-node-a-services");
        fs::create_dir_all(&service_root).unwrap();
        let provider_dir = service_root.join("provider");
        let anchor_dir = service_root.join("q6ea");
        let floor_dir = service_root.join("provider-floor");

        let provider_keys = portable::generate_key_pair([0xE5; 32]);
        let anchor_keys = portable::generate_key_pair([0xE6; 32]);
        let provider_pin = ExternalCasPin {
            provider_id: [0xE7; 32],
            network_id: NETWORK,
            genesis_digest: GENESIS_DIGEST,
            receipt_key_id: [0xE8; 32],
            receipt_public_key: *provider_keys.verification_key.as_ref(),
        };
        let anchor_pin = ExternalCasOffhostAnchorPin {
            anchor_id: [0xE9; 32],
            provider_id: provider_pin.provider_id,
            network_id: provider_pin.network_id,
            genesis_digest: provider_pin.genesis_digest,
            receipt_key_id: [0xEA; 32],
            receipt_public_key: *anchor_keys.verification_key.as_ref(),
        };
        let bootstrap_record = ExternalCasRecord {
            generation: 0,
            provider_id: provider_pin.provider_id,
            network_id: provider_pin.network_id,
            genesis_digest: provider_pin.genesis_digest,
            previous_record_digest: [0; 32],
            previous_state_digest: [0; 32],
            next_state_digest: initial.digest().unwrap(),
            operation_id: [0xEB; 32],
            request_digest: [0xEC; 32],
        };
        let bootstrap_anchor = ExternalCasOffhostAnchorState::provision_bootstrap(
            &provider_pin,
            bootstrap_record.clone(),
            1,
        )
        .unwrap();

        let provider_signing_key = Arc::new(provider_keys.signing_key);
        let provider_init_signer_key = Arc::clone(&provider_signing_key);
        let provider = DurableExternalCasProvider::initialize(
            &provider_dir,
            provider_pin.clone(),
            bootstrap_record.clone(),
            move |digest| {
                let signature = portable::sign(&provider_init_signer_key, digest, &[], [0xED; 32])
                    .map_err(|error| format!("{error:?}"))?;
                Ok(*signature.as_ref())
            },
        )
        .unwrap();
        drop(provider);
        ExternalCasFloorStore::initialize(&floor_dir, provider_pin.clone(), bootstrap_record, 1)
            .unwrap();

        let anchor_signer = Qap1TestSigner {
            key: Arc::new(anchor_keys.signing_key),
        };
        let anchor_server = start_durable_anchor_noise_server_at(
            &anchor_dir,
            provider_pin.clone(),
            anchor_pin.clone(),
            bootstrap_anchor,
            anchor_signer,
            anchor_bind,
        );
        let provider_server = start_durable_provider_noise_server_at(
            &provider_dir,
            provider_pin.clone(),
            provider_signing_key,
            provider_bind,
        );
        assert_eq!(provider_server.address.ip(), provider_bind.ip());
        assert_eq!(anchor_server.address.ip(), anchor_bind.ip());

        let (listener_private, listener_public) = qap1_noise_keypair();
        let (peer_private, peer_public) = qap1_noise_keypair();
        let config_json = format!(
            concat!(
                "{{",
                "\"node_a_provider_address\":\"{}\",",
                "\"node_a_anchor_address\":\"{}\",",
                "\"node_b_listener_port\":{},",
                "\"node_b_listener_private_hex\":\"{}\",",
                "\"node_a_peer_public_hex\":\"{}\",",
                "\"provider_client_private_hex\":\"{}\",",
                "\"provider_server_public_hex\":\"{}\",",
                "\"anchor_client_private_hex\":\"{}\",",
                "\"anchor_server_public_hex\":\"{}\",",
                "\"provider_receipt_public_hex\":\"{}\",",
                "\"anchor_receipt_public_hex\":\"{}\"",
                "}}"
            ),
            provider_server.address,
            anchor_server.address,
            runner_listener_port,
            hex32(&listener_private),
            hex32(&peer_public),
            hex32(&provider_server.client_private),
            hex32(&provider_server.server_public),
            hex32(&anchor_server.client_private),
            hex32(&anchor_server.server_public),
            hex_array(&provider_pin.receipt_public_key),
            hex_array(&anchor_pin.receipt_public_key),
        );
        println!("QFP6_QAP1_DRIVER_TEMP_ROOT={}", service_root.display());
        println!("QFP6_QAP1_DRIVER_CONFIG_JSON={config_json}");
        std::io::Write::flush(&mut std::io::stdout()).unwrap();

        let mut line = String::new();
        std::io::stdin()
            .read_line(&mut line)
            .expect("read Runner endpoint from controller");
        let endpoint_value = line
            .trim()
            .strip_prefix("QFP6_QAP1_RUNNER_ENDPOINT=")
            .expect("controller must supply the Runner endpoint marker");
        let runner_endpoint = endpoint_value.parse::<SocketAddr>().unwrap();
        assert_qap1_test_bind_address(runner_endpoint);
        assert!(!runner_endpoint.ip().is_loopback());
        assert_eq!(runner_endpoint.port(), runner_listener_port);
        assert_ne!(runner_endpoint.ip(), provider_server.address.ip());

        let mut stream = TcpStream::connect_timeout(&runner_endpoint, Duration::from_secs(25))
            .expect("connect to the independently enrolled QFP6 Runner over NetBird");
        stream.set_nodelay(true).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(45)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(45)))
            .unwrap();
        let mut noise = QRunV06NoiseSession::connect(
            &mut stream,
            &peer_private,
            &listener_public,
            &NETWORK,
            &PROFILE,
        )
        .expect("Node A pinned Noise XX handshake with Runner");
        assert_eq!(noise.remote_static_public_key(), &listener_public);

        let envelope = first_block(&store);
        let frame = encode_qrun_v06_peer_block_request(0x566B, &envelope).unwrap();
        noise.write_q6pb_request(&mut stream, &frame).unwrap();
        let accepted = noise.read_q6pa_response(&mut stream, 0x566B).unwrap();
        noise.write_q6pb_request(&mut stream, &frame).unwrap();
        let replayed = noise.read_q6pa_response(&mut stream, 0x566B).unwrap();
        drop(noise);
        drop(stream);

        assert_eq!(
            u16::from_be_bytes([accepted[6], accepted[7]]),
            QRunV06PeerAdmissionStatus::Accepted as u16
        );
        assert_eq!(
            u16::from_be_bytes([replayed[6], replayed[7]]),
            QRunV06PeerAdmissionStatus::Rejected as u16
        );

        let (_reference_dir, reference_store) = open_store();
        let reference_initial =
            QRunV06ExternalAnchorState::from_store(&reference_store, GENESIS_DIGEST).unwrap();
        let gate = MockAnchorGate {
            current: reference_initial.clone(),
            fail_next_advance: false,
            advance_calls: 0,
        };
        let mut expected_runtime = QRunV06NodeRuntime::new(
            reference_store,
            gate,
            GENESIS_DIGEST,
            reference_initial.clone(),
        )
        .unwrap();
        let mut quote_authorizer = quote_provider();
        let expected_admission = expected_runtime
            .submit_envelope(&envelope, &EmptyAuthenticator, &mut quote_authorizer)
            .unwrap();
        assert!(expected_admission.is_acknowledged());
        let expected_successor = expected_runtime.committed_anchor_state().clone();

        let mut external_verifier = durable_noise_qap1_coordinator(
            &provider_server,
            &anchor_server,
            provider_pin,
            anchor_pin,
            &initial,
            &floor_dir,
        );
        external_verifier
            .verify_current(&expected_successor)
            .expect("fresh signed Provider and Q6EA state must match the QFP6 admission");
        drop(external_verifier);

        println!("QFP6_QAP1_NODE_A_PROVIDER_Q6EA_VERIFIED=PASS");
        println!("QFP6_QAP1_NODE_A_ACCEPTED_AND_REPLAY_REJECTED=PASS");
        anchor_server.shutdown_and_join();
        provider_server.shutdown_and_join();
        fs::remove_dir_all(&service_root).unwrap();
    }

    #[test]
    fn qfp6_qap1_node_a_driver() {
        let Ok(role) = env::var("QRUN_QFP6_QAP1_NODE_A_ROLE") else {
            return;
        };
        assert_eq!(role, "driver");

        use crate::external_cas_anchor_candidate::{ExternalCasPin, ExternalCasRecord};
        use crate::external_cas_disk_provider_candidate::DurableExternalCasProvider;
        use crate::external_cas_offhost_anchor_candidate::ExternalCasOffhostAnchorState;
        use crate::external_cas_offhost_anchor_protocol_candidate::ExternalCasOffhostAnchorPin;

        let required = |name: &str| env::var(name).unwrap_or_else(|_| panic!("missing {name}"));
        let node_a_ip: std::net::IpAddr = required("QRUN_QFP6_QAP1_NODE_A_OVERLAY_IP")
            .parse()
            .expect("Node A overlay IP must parse");
        assert_qap1_netbird_overlay_ip(node_a_ip);
        assert_qap1_test_bind_address(SocketAddr::new(node_a_ip, 49_661));
        let config_path = std::path::PathBuf::from(required("QRUN_QFP6_QAP1_NODE_A_CONFIG_PATH"));

        let (dir, store) = open_store_with_genesis(q6ti_test_genesis_state());
        let initial = QRunV06ExternalAnchorState::from_store(&store, GENESIS_DIGEST).unwrap();
        let provider_dir = dir.0.join("cp0566c-provider");
        let anchor_dir = dir.0.join("cp0566c-q6ea");
        fs::create_dir_all(&provider_dir).unwrap();
        fs::create_dir_all(&anchor_dir).unwrap();

        // Derive independent, one-run ML-DSA keys from OS-random Noise private material.
        let (mut provider_seed, _) = qap1_noise_keypair();
        let provider_keys = portable::generate_key_pair(provider_seed);
        provider_seed.fill(0);
        let (mut anchor_seed, _) = qap1_noise_keypair();
        let anchor_keys = portable::generate_key_pair(anchor_seed);
        anchor_seed.fill(0);

        let provider_pin = ExternalCasPin {
            provider_id: [0xE7; 32],
            network_id: NETWORK,
            genesis_digest: GENESIS_DIGEST,
            receipt_key_id: [0xE8; 32],
            receipt_public_key: *provider_keys.verification_key.as_ref(),
        };
        let anchor_pin = ExternalCasOffhostAnchorPin {
            anchor_id: [0xE9; 32],
            provider_id: provider_pin.provider_id,
            network_id: provider_pin.network_id,
            genesis_digest: provider_pin.genesis_digest,
            receipt_key_id: [0xEA; 32],
            receipt_public_key: *anchor_keys.verification_key.as_ref(),
        };
        // Match the explicitly reviewed CP-0566B bootstrap fixture used by the remote worker.
        let bootstrap_record = ExternalCasRecord {
            generation: 0,
            provider_id: provider_pin.provider_id,
            network_id: provider_pin.network_id,
            genesis_digest: provider_pin.genesis_digest,
            previous_record_digest: [0; 32],
            previous_state_digest: [0; 32],
            next_state_digest: initial.digest().unwrap(),
            operation_id: [0xEB; 32],
            request_digest: [0xEC; 32],
        };
        let bootstrap_anchor = ExternalCasOffhostAnchorState::provision_bootstrap(
            &provider_pin,
            bootstrap_record.clone(),
            1,
        )
        .unwrap();

        let provider_signing_key = Arc::new(provider_keys.signing_key);
        let provider_init_signer_key = Arc::clone(&provider_signing_key);
        let provider = DurableExternalCasProvider::initialize(
            &provider_dir,
            provider_pin.clone(),
            bootstrap_record.clone(),
            move |digest| {
                let signature = portable::sign(&provider_init_signer_key, digest, &[], [0xED; 32])
                    .map_err(|error| format!("{error:?}"))?;
                Ok(*signature.as_ref())
            },
        )
        .unwrap();
        drop(provider);

        let provider_bind = SocketAddr::new(node_a_ip, 49_661);
        let anchor_bind = SocketAddr::new(node_a_ip, 49_662);
        let provider_server = start_durable_provider_noise_server_at(
            &provider_dir,
            provider_pin.clone(),
            provider_signing_key,
            provider_bind,
        );
        let anchor_server = start_durable_anchor_noise_server_at(
            &anchor_dir,
            provider_pin.clone(),
            anchor_pin.clone(),
            bootstrap_anchor,
            Qap1TestSigner {
                key: Arc::new(anchor_keys.signing_key),
            },
            anchor_bind,
        );

        // Node A is the sole QFP6 peer identity. Node B has a separate listener identity.
        let (peer_private, peer_public) = qap1_noise_keypair();
        let (listener_private, listener_public) = qap1_noise_keypair();
        let (mut callback_nonce, _) = qap1_noise_keypair();
        let callback_bind = SocketAddr::new(node_a_ip, 49_663);
        let callback_listener =
            TcpListener::bind(callback_bind).expect("bind private Node A callback listener");
        callback_listener.set_nonblocking(true).unwrap();
        let callback_address = callback_listener.local_addr().unwrap();
        let remote_listener_port = 48_664u16;

        let runner_config = format!(
            concat!(
                "{{",
                "\"node_a_provider_address\":\"{}\",",
                "\"node_a_anchor_address\":\"{}\",",
                "\"node_a_callback_address\":\"{}\",",
                "\"callback_nonce_hex\":\"{}\",",
                "\"node_b_listener_port\":{},",
                "\"node_b_listener_private_hex\":\"{}\",",
                "\"node_b_listener_public_hex\":\"{}\",",
                "\"node_a_peer_public_hex\":\"{}\",",
                "\"provider_client_private_hex\":\"{}\",",
                "\"provider_server_public_hex\":\"{}\",",
                "\"anchor_client_private_hex\":\"{}\",",
                "\"anchor_server_public_hex\":\"{}\",",
                "\"provider_receipt_public_hex\":\"{}\",",
                "\"anchor_receipt_public_hex\":\"{}\"",
                "}}"
            ),
            provider_server.address,
            anchor_server.address,
            callback_address,
            hex32(&callback_nonce),
            remote_listener_port,
            hex32(&listener_private),
            hex32(&listener_public),
            hex32(&peer_public),
            hex32(&provider_server.client_private),
            hex32(&provider_server.server_public),
            hex32(&anchor_server.client_private),
            hex32(&anchor_server.server_public),
            hex_array(&provider_pin.receipt_public_key),
            hex_array(&anchor_pin.receipt_public_key),
        );
        let mut config_file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&config_path)
            .expect("create one-shot protected Runner config file");
        std::io::Write::write_all(&mut config_file, runner_config.as_bytes()).unwrap();
        config_file.sync_all().unwrap();
        drop(config_file);
        callback_nonce.fill(0);

        println!("QFP6_QAP1_NODE_A_SERVICES_READY=PASS");
        println!("QFP6_QAP1_NODE_A_CONFIG_READY=PASS");
        std::io::Write::flush(&mut std::io::stdout()).unwrap();

        let callback_deadline = Instant::now() + Duration::from_secs(600);
        let (callback_stream, callback_peer) = loop {
            match callback_listener.accept() {
                Ok(pair) => break pair,
                Err(error)
                    if error.kind() == std::io::ErrorKind::WouldBlock
                        && Instant::now() < callback_deadline =>
                {
                    thread::sleep(Duration::from_millis(25));
                }
                Err(error) => panic!("Node B callback did not arrive: {error}"),
            }
        };
        let callback_ip = callback_peer.ip();
        assert_qap1_netbird_overlay_ip(callback_ip);
        assert_qap1_test_bind_address(SocketAddr::new(callback_ip, 49_663));
        // The callback listener is nonblocking for bounded accept polling. Explicitly
        // restore blocking mode on the accepted stream: on Windows the accepted socket
        // can retain nonblocking behavior, where a delayed DONE line returns WSAEWOULDBLOCK
        // instead of honoring the configured read timeout.
        callback_stream
            .set_nonblocking(false)
            .expect("set Node A callback stream to blocking mode");
        let mut callback_reader = std::io::BufReader::new(callback_stream);
        callback_reader
            .get_ref()
            .set_read_timeout(Some(Duration::from_secs(600)))
            .unwrap();
        println!("QFP6_QAP1_NODE_A_CALLBACK_BLOCKING_MODE=PASS");
        let mut ready_line = String::new();
        std::io::BufRead::read_line(&mut callback_reader, &mut ready_line).unwrap();
        let ready = qap1_callback_fields(&ready_line);
        assert_eq!(ready.len(), 4, "malformed Node B READY callback");
        assert_eq!(ready[0], "READY");
        assert_eq!(
            ready[1],
            hex32(&{
                // Re-read the one-shot nonce from the protected configuration, then erase the file
                // after the callback has authenticated its possession.
                let cfg = fs::read_to_string(&config_path).unwrap();
                let marker = "\"callback_nonce_hex\":\"";
                let start = cfg.find(marker).unwrap() + marker.len();
                let end = cfg[start..].find('"').unwrap() + start;
                parse_hex32(&cfg[start..end])
            })
        );
        let announced_endpoint: SocketAddr = ready[2].parse().unwrap();
        assert_eq!(announced_endpoint.ip(), callback_ip);
        assert_eq!(announced_endpoint.port(), remote_listener_port);
        assert_eq!(ready[3], hex32(&listener_public));
        fs::remove_file(&config_path).expect("remove one-shot Runner config after callback");

        let mut peer_stream = loop {
            match TcpStream::connect_timeout(&announced_endpoint, Duration::from_secs(2)) {
                Ok(stream) => break stream,
                Err(error) if Instant::now() < callback_deadline => {
                    let _ = error;
                    thread::sleep(Duration::from_millis(100));
                }
                Err(error) => panic!("could not connect to Node B QFP6 listener: {error}"),
            }
        };
        peer_stream.set_nodelay(true).unwrap();
        peer_stream
            .set_read_timeout(Some(Duration::from_secs(30)))
            .unwrap();
        let mut noise = QRunV06NoiseSession::connect(
            &mut peer_stream,
            &peer_private,
            &listener_public,
            &NETWORK,
            &PROFILE,
        )
        .expect("Node A pins Node B QFP6 listener Noise identity");
        let envelope = first_block(&store);
        let frame = encode_qrun_v06_peer_block_request(0x566C, &envelope).unwrap();
        noise.write_q6pb_request(&mut peer_stream, &frame).unwrap();
        let accepted = noise.read_q6pa_response(&mut peer_stream, 0x566C).unwrap();
        noise.write_q6pb_request(&mut peer_stream, &frame).unwrap();
        let replayed = noise.read_q6pa_response(&mut peer_stream, 0x566C).unwrap();

        assert_eq!(
            u16::from_be_bytes([accepted[6], accepted[7]]),
            QRunV06PeerAdmissionStatus::Accepted as u16
        );
        assert_eq!(
            u16::from_be_bytes([replayed[6], replayed[7]]),
            QRunV06PeerAdmissionStatus::Rejected as u16
        );
        println!("QFP6_QAP1_NODE_A_ADMISSION_AND_REPLAY=PASS");

        // Submit a cryptographically signed Q6HA native transfer to the independent Node B
        // through the same pinned Noise session used for Q6PB block admission.
        let transaction = q6ti_test_transaction();
        let transaction_id = transaction_id_with_signature_limit(
            &transaction,
            QRUN_V06_MAX_NATIVE_TX_SIGNATURE_BYTES,
        )
        .unwrap();
        let q6ti_frame = encode_q6ti_transaction_request(0x566D, &transaction).unwrap();
        noise.write_record(&mut peer_stream, &q6ti_frame).unwrap();
        let q6ta_bytes = noise.read_record(&mut peer_stream).unwrap();
        let q6ta = decode_q6ta_response(&q6ta_bytes, 0x566D).unwrap();
        assert_eq!(q6ta.status, QRunV06TransactionSubmitStatus::Accepted);
        assert_eq!(q6ta.transaction_id, transaction_id);
        assert_eq!(q6ta.mempool_count, 1);
        assert_eq!(q6ta.canonical_height, 1);
        println!("QFP6_QAP1_NODE_A_Q6TI_ACCEPTED=PASS");
        println!("QFP6_QAP1_NODE_A_Q6TI_TXID={}", hex32(&transaction_id));

        let duplicate_frame = encode_q6ti_transaction_request(0x566E, &transaction).unwrap();
        noise
            .write_record(&mut peer_stream, &duplicate_frame)
            .unwrap();
        let duplicate_bytes = noise.read_record(&mut peer_stream).unwrap();
        let duplicate = decode_q6ta_response(&duplicate_bytes, 0x566E).unwrap();
        assert_eq!(duplicate.status, QRunV06TransactionSubmitStatus::Duplicate);
        assert_eq!(duplicate.transaction_id, transaction_id);
        assert_eq!(duplicate.mempool_count, 1);
        println!("QFP6_QAP1_NODE_A_Q6TI_DUPLICATE=PASS");
        drop(noise);
        drop(peer_stream);
        std::io::Write::flush(&mut std::io::stdout()).unwrap();

        let mut done_line = String::new();
        std::io::BufRead::read_line(&mut callback_reader, &mut done_line).unwrap();
        let done = qap1_callback_fields(&done_line);
        assert_eq!(done.len(), 7, "malformed Node B DONE callback");
        assert_eq!(done[0], "DONE");
        assert_eq!(
            done[1], ready[1],
            "callback nonce changed during Runner lifecycle"
        );
        assert!(done[2].len() == 64 && done[2].bytes().all(|b| b.is_ascii_hexdigit()));
        assert!(done[3].len() == 64 && done[3].bytes().all(|b| b.is_ascii_hexdigit()));
        let accepted_manifest_anchor: [u8; 32] = accepted[96..128]
            .try_into()
            .expect("Q6PA response must contain a 32-byte manifest anchor");
        assert_eq!(
            done[2],
            hex32(&accepted_manifest_anchor),
            "Node B DONE manifest anchor must match the anchor acknowledged to Node A"
        );
        let accepted_height = u64::from_be_bytes(accepted[80..88].try_into().unwrap());
        let accepted_generation = u64::from_be_bytes(accepted[88..96].try_into().unwrap());
        assert_eq!(
            done[4],
            accepted_height.to_string(),
            "Node B DONE height must match the Q6PA acknowledgement"
        );
        assert_eq!(
            done[5],
            accepted_generation.to_string(),
            "Node B DONE generation must match the Q6PA acknowledgement"
        );
        let reported_state_root = parse_hex32(done[3]);
        assert_ne!(
            reported_state_root, [0; 32],
            "Node B DONE state root must not be the zero digest"
        );
        assert_eq!(done[6], "PASS");
        println!("QFP6_QAP1_NODE_A_CONFIRMED_REMOTE_RESTART=PASS");

        anchor_server.shutdown_and_join();
        provider_server.shutdown_and_join();
        println!("QFP6_QAP1_NODE_A_CLEAN_SHUTDOWN=PASS");
    }

    #[test]
    fn qap1_peer_ingress_qualifies_separate_qfp6_process() {
        use crate::external_cas_anchor_candidate::ExternalCasPin;
        use crate::external_cas_disk_provider_candidate::DurableExternalCasProvider;
        use crate::external_cas_offhost_anchor_candidate::ExternalCasOffhostAnchorState;
        use crate::external_cas_offhost_anchor_protocol_candidate::ExternalCasOffhostAnchorPin;

        let (dir, store) = open_store();
        let initial = QRunV06ExternalAnchorState::from_store(&store, GENESIS_DIGEST).unwrap();
        let service_root = dir.0.with_extension("cp0566b-process-services");
        fs::create_dir_all(&service_root).unwrap();
        let provider_dir = service_root.join("provider");
        let anchor_dir = service_root.join("q6ea");
        let floor_dir = service_root.join("provider-floor");
        let node_directory = service_root.join("qfp6-node");

        let provider_keys = portable::generate_key_pair([0xE5; 32]);
        let anchor_keys = portable::generate_key_pair([0xE6; 32]);
        let provider_pin = ExternalCasPin {
            provider_id: [0xE7; 32],
            network_id: NETWORK,
            genesis_digest: GENESIS_DIGEST,
            receipt_key_id: [0xE8; 32],
            receipt_public_key: *provider_keys.verification_key.as_ref(),
        };
        let anchor_pin = ExternalCasOffhostAnchorPin {
            anchor_id: [0xE9; 32],
            provider_id: provider_pin.provider_id,
            network_id: provider_pin.network_id,
            genesis_digest: provider_pin.genesis_digest,
            receipt_key_id: [0xEA; 32],
            receipt_public_key: *anchor_keys.verification_key.as_ref(),
        };
        let bootstrap_record = ExternalCasRecord {
            generation: 0,
            provider_id: provider_pin.provider_id,
            network_id: provider_pin.network_id,
            genesis_digest: provider_pin.genesis_digest,
            previous_record_digest: [0; 32],
            previous_state_digest: [0; 32],
            next_state_digest: initial.digest().unwrap(),
            operation_id: [0xEB; 32],
            request_digest: [0xEC; 32],
        };
        let bootstrap_anchor = ExternalCasOffhostAnchorState::provision_bootstrap(
            &provider_pin,
            bootstrap_record.clone(),
            1,
        )
        .unwrap();

        let provider_signing_key = Arc::new(provider_keys.signing_key);
        let provider_init_signer_key = Arc::clone(&provider_signing_key);
        let provider = DurableExternalCasProvider::initialize(
            &provider_dir,
            provider_pin.clone(),
            bootstrap_record.clone(),
            move |digest| {
                let signature = portable::sign(&provider_init_signer_key, digest, &[], [0xED; 32])
                    .map_err(|error| format!("{error:?}"))?;
                Ok(*signature.as_ref())
            },
        )
        .unwrap();
        drop(provider);

        let anchor_signer = Qap1TestSigner {
            key: Arc::new(anchor_keys.signing_key),
        };
        let anchor_server = start_durable_anchor_noise_server(
            &anchor_dir,
            provider_pin.clone(),
            anchor_pin.clone(),
            bootstrap_anchor,
            anchor_signer,
        );
        let provider_server = start_durable_provider_noise_server(
            &provider_dir,
            provider_pin.clone(),
            provider_signing_key,
        );
        assert!(anchor_server.address.ip().is_loopback());
        assert!(provider_server.address.ip().is_loopback());

        let peer_probe = TcpListener::bind("127.0.0.1:0").unwrap();
        let peer_address = peer_probe.local_addr().unwrap();
        drop(peer_probe);
        let (listener_private, listener_public) = qap1_noise_keypair();
        let (peer_private, peer_public) = qap1_noise_keypair();

        let executable = env::current_exe().unwrap();
        let worker = "qrun_v06_node_runtime_candidate::tests::qfp6_qap1_process_worker";
        let mut server = Command::new(&executable)
            .arg("--exact")
            .arg(worker)
            .arg("--nocapture")
            .env("QRUN_QFP6_QAP1_PROCESS_ROLE", "server")
            .env("QRUN_QFP6_QAP1_INITIALIZE_FLOOR", "1")
            .env(
                "QRUN_QFP6_QAP1_NODE_DIR",
                node_directory.to_string_lossy().to_string(),
            )
            .env("QRUN_QFP6_QAP1_TRUSTED_MANIFEST_ANCHOR", "none")
            .env("QRUN_QFP6_QAP1_LISTEN_ADDR", peer_address.to_string())
            .env("QRUN_QFP6_QAP1_LISTENER_PRIVATE", hex32(&listener_private))
            .env("QRUN_QFP6_QAP1_PEER_PUBLIC", hex32(&peer_public))
            .env(
                "QRUN_QFP6_QAP1_PROVIDER_ADDR",
                provider_server.address.to_string(),
            )
            .env(
                "QRUN_QFP6_QAP1_PROVIDER_CLIENT_PRIVATE",
                hex32(&provider_server.client_private),
            )
            .env(
                "QRUN_QFP6_QAP1_PROVIDER_SERVER_PUBLIC",
                hex32(&provider_server.server_public),
            )
            .env(
                "QRUN_QFP6_QAP1_ANCHOR_ADDR",
                anchor_server.address.to_string(),
            )
            .env(
                "QRUN_QFP6_QAP1_ANCHOR_CLIENT_PRIVATE",
                hex32(&anchor_server.client_private),
            )
            .env(
                "QRUN_QFP6_QAP1_ANCHOR_SERVER_PUBLIC",
                hex32(&anchor_server.server_public),
            )
            .env(
                "QRUN_QFP6_QAP1_PROVIDER_RECEIPT_PUBLIC",
                hex_array(&provider_pin.receipt_public_key),
            )
            .env(
                "QRUN_QFP6_QAP1_ANCHOR_RECEIPT_PUBLIC",
                hex_array(&anchor_pin.receipt_public_key),
            )
            .env(
                "QRUN_QFP6_QAP1_FLOOR_DIR",
                floor_dir.to_string_lossy().to_string(),
            )
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn independent QFP6/QAP1 node process");

        let envelope = first_block(&store);
        let frame = encode_qrun_v06_peer_block_request(0x566B, &envelope).unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut stream = loop {
            match TcpStream::connect(peer_address) {
                Ok(stream) => break stream,
                Err(error) if Instant::now() < deadline => {
                    let _ = error;
                    thread::sleep(Duration::from_millis(25));
                }
                Err(error) => {
                    let _ = server.kill();
                    let _ = server.wait();
                    anchor_server.shutdown_and_join();
                    provider_server.shutdown_and_join();
                    panic!("could not connect to QFP6/QAP1 child process: {error}");
                }
            }
        };
        stream.set_nodelay(true).unwrap();
        let mut noise = QRunV06NoiseSession::connect(
            &mut stream,
            &peer_private,
            &listener_public,
            &NETWORK,
            &PROFILE,
        )
        .unwrap();
        noise.write_q6pb_request(&mut stream, &frame).unwrap();
        let accepted = noise.read_q6pa_response(&mut stream, 0x566B).unwrap();
        noise.write_q6pb_request(&mut stream, &frame).unwrap();
        let replayed = noise.read_q6pa_response(&mut stream, 0x566B).unwrap();
        drop(noise);
        drop(stream);

        assert_eq!(
            u16::from_be_bytes([accepted[6], accepted[7]]),
            QRunV06PeerAdmissionStatus::Accepted as u16
        );
        assert_eq!(
            u16::from_be_bytes([replayed[6], replayed[7]]),
            QRunV06PeerAdmissionStatus::Rejected as u16
        );
        let server_output = server.wait_with_output().unwrap();
        assert!(
            server_output.status.success(),
            "QFP6/QAP1 child failed; stdout={} stderr={}",
            String::from_utf8_lossy(&server_output.stdout),
            String::from_utf8_lossy(&server_output.stderr)
        );
        let server_stdout = String::from_utf8_lossy(&server_output.stdout).to_string();
        assert!(
            server_stdout.contains("QFP6_QAP1_PROCESS_SERVER=PASS"),
            "QFP6/QAP1 child did not report its verified pass"
        );
        let output_value = |key: &str| {
            server_stdout
                .lines()
                .find_map(|line| line.strip_prefix(key))
                .unwrap_or_else(|| panic!("child omitted {key}"))
                .to_string()
        };
        let manifest_anchor_hex = output_value("QFP6_QAP1_MANIFEST_ANCHOR=");
        let manifest_anchor = parse_hex32(&manifest_anchor_hex);
        let state_root = parse_hex32(&output_value("QFP6_QAP1_STATE_ROOT="));
        let expected_height = output_value("QFP6_QAP1_HEIGHT=");
        let expected_generation = output_value("QFP6_QAP1_GENERATION=");

        // Reopen the child's durable archive only with the anchor returned by the child,
        // then independently check that exact local state against Provider and Q6EA.
        let reopened_store = open_store_at(&node_directory, Some(manifest_anchor));
        let externally_checked_state =
            QRunV06ExternalAnchorState::from_store(&reopened_store, GENESIS_DIGEST).unwrap();
        assert_eq!(reopened_store.manifest_anchor().unwrap(), manifest_anchor);
        assert_eq!(reopened_store.canonical_state_root().unwrap(), state_root);
        assert_eq!(
            reopened_store.canonical_height().unwrap().to_string(),
            expected_height
        );
        assert_eq!(
            reopened_store.generation().unwrap().to_string(),
            expected_generation
        );
        let mut external_verifier = durable_noise_qap1_coordinator(
            &provider_server,
            &anchor_server,
            provider_pin.clone(),
            anchor_pin.clone(),
            &externally_checked_state,
            &floor_dir,
        );
        external_verifier
            .verify_current(&externally_checked_state)
            .unwrap();
        drop(external_verifier);
        drop(reopened_store);

        // A second OS process reopens the exact same node archive with the independently
        // checked Manifest anchor and must recover QAP1 before reporting the same state.
        let restart = Command::new(&executable)
            .arg("--exact")
            .arg(worker)
            .arg("--nocapture")
            .env("QRUN_QFP6_QAP1_PROCESS_ROLE", "restart")
            .env(
                "QRUN_QFP6_QAP1_NODE_DIR",
                node_directory.to_string_lossy().to_string(),
            )
            .env(
                "QRUN_QFP6_QAP1_TRUSTED_MANIFEST_ANCHOR",
                &manifest_anchor_hex,
            )
            .env("QRUN_QFP6_QAP1_EXPECTED_HEIGHT", &expected_height)
            .env("QRUN_QFP6_QAP1_EXPECTED_GENERATION", &expected_generation)
            .env("QRUN_QFP6_QAP1_EXPECTED_STATE_ROOT", hex32(&state_root))
            .env("QRUN_QFP6_QAP1_LISTEN_ADDR", peer_address.to_string())
            .env("QRUN_QFP6_QAP1_LISTENER_PRIVATE", hex32(&listener_private))
            .env("QRUN_QFP6_QAP1_PEER_PUBLIC", hex32(&peer_public))
            .env(
                "QRUN_QFP6_QAP1_PROVIDER_ADDR",
                provider_server.address.to_string(),
            )
            .env(
                "QRUN_QFP6_QAP1_PROVIDER_CLIENT_PRIVATE",
                hex32(&provider_server.client_private),
            )
            .env(
                "QRUN_QFP6_QAP1_PROVIDER_SERVER_PUBLIC",
                hex32(&provider_server.server_public),
            )
            .env(
                "QRUN_QFP6_QAP1_ANCHOR_ADDR",
                anchor_server.address.to_string(),
            )
            .env(
                "QRUN_QFP6_QAP1_ANCHOR_CLIENT_PRIVATE",
                hex32(&anchor_server.client_private),
            )
            .env(
                "QRUN_QFP6_QAP1_ANCHOR_SERVER_PUBLIC",
                hex32(&anchor_server.server_public),
            )
            .env(
                "QRUN_QFP6_QAP1_PROVIDER_RECEIPT_PUBLIC",
                hex_array(&provider_pin.receipt_public_key),
            )
            .env(
                "QRUN_QFP6_QAP1_ANCHOR_RECEIPT_PUBLIC",
                hex_array(&anchor_pin.receipt_public_key),
            )
            .env(
                "QRUN_QFP6_QAP1_FLOOR_DIR",
                floor_dir.to_string_lossy().to_string(),
            )
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn second QFP6/QAP1 recovery process");
        let restart_output = restart.wait_with_output().unwrap();
        assert!(
            restart_output.status.success(),
            "QFP6/QAP1 second process failed; stdout={} stderr={}",
            String::from_utf8_lossy(&restart_output.stdout),
            String::from_utf8_lossy(&restart_output.stderr)
        );
        assert!(
            String::from_utf8_lossy(&restart_output.stdout)
                .contains("QFP6_QAP1_RESTART_SERVER=PASS"),
            "second QFP6 process did not report exact QAP1 recovery"
        );

        anchor_server.shutdown_and_join();
        provider_server.shutdown_and_join();
        fs::remove_dir_all(&service_root).unwrap();
    }
}
