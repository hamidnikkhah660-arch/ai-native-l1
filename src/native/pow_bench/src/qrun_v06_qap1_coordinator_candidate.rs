//! CP-0559 candidate: QAP1 orchestration across the signed Provider and Q6EA Anchor.
//!
//! This coordinator owns the exact provider CAS request before it is sent, records every
//! returned signed proof, and only advances QAP1 after the proof has been verified. The Q6EA
//! transport is expected to be an independently administered service; the Noise/TCP adapter
//! encrypts and authenticates its endpoint but does not by itself establish operator separation.

use crate::{
    external_cas_anchor_candidate::{
        ExternalCasPin, ExternalCasProviderTransport, ExternalCasReadRequest, ExternalCasReceipt,
        ExternalCasRecord, ExternalCasWriteRequest, VerifiedExternalCasClient,
    },
    external_cas_floor_store_candidate::{ExternalCasFloorError, ExternalCasFloorStore},
    external_cas_offhost_anchor_candidate::ExternalCasOffhostAnchorState,
    external_cas_offhost_anchor_noise_transport_candidate::NoiseTcpOffhostAnchorTransport,
    external_cas_offhost_anchor_protocol_candidate::{
        ExternalCasOffhostAnchorCasRequest, ExternalCasOffhostAnchorPin,
        ExternalCasOffhostAnchorReadRequest, ExternalCasOffhostAnchorReceipt,
    },
    qrun_v06_external_anchor_candidate::{QRunV06ExternalAnchorPin, QRunV06ExternalAnchorState},
    qrun_v06_pow_fork_store_candidate::{
        QRunV06DurableForkStore, QRunV06ForkStoreError, QRunV06PreparedCommit,
    },
    qrun_v06_qap1_journal_candidate::{QRunV06Qap1Error, QRunV06Qap1Journal, QRunV06Qap1Phase},
    v4_fat1_trust_candidate::MlDsa65Verifier,
};
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QRunV06Qap1CoordinatorError {
    WrongPin,
    AnchorStateMismatch,
    ProviderStateMismatch,
    InvalidProviderRequest,
    MissingEvidence,
    UnsupportedPhase,
    RandomnessUnavailable,
    Provider(String),
    Anchor(String),
    Floor(String),
    Journal(String),
    Store(String),
}

impl std::fmt::Display for QRunV06Qap1CoordinatorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "QFP6 QAP1 coordinator error: {self:?}")
    }
}
impl std::error::Error for QRunV06Qap1CoordinatorError {}

impl From<QRunV06Qap1Error> for QRunV06Qap1CoordinatorError {
    fn from(value: QRunV06Qap1Error) -> Self {
        Self::Journal(value.to_string())
    }
}
impl From<ExternalCasFloorError> for QRunV06Qap1CoordinatorError {
    fn from(value: ExternalCasFloorError) -> Self {
        Self::Floor(value.to_string())
    }
}
impl From<QRunV06ForkStoreError> for QRunV06Qap1CoordinatorError {
    fn from(value: QRunV06ForkStoreError) -> Self {
        Self::Store(value.to_string())
    }
}

/// Small transport seam for the two challenge-bound Q6EA operations used by QAP1.
/// The Noise/TCP implementation below is the production-shaped client adapter; tests may
/// inject a deterministic in-memory transport without weakening receipt verification.
pub trait QRunV06Qap1AnchorTransport {
    fn is_pinned_to(
        &self,
        anchor_pin: &ExternalCasOffhostAnchorPin,
        provider_pin: &ExternalCasPin,
    ) -> bool;
    fn read(
        &mut self,
        request: &ExternalCasOffhostAnchorReadRequest,
    ) -> Result<ExternalCasOffhostAnchorReceipt, String>;
    fn compare_and_swap(
        &mut self,
        request: &ExternalCasOffhostAnchorCasRequest,
        next_record_bytes: &[u8],
        provider_receipt_bytes: &[u8],
    ) -> Result<ExternalCasOffhostAnchorReceipt, String>;
}

impl QRunV06Qap1AnchorTransport for NoiseTcpOffhostAnchorTransport {
    fn is_pinned_to(
        &self,
        anchor_pin: &ExternalCasOffhostAnchorPin,
        provider_pin: &ExternalCasPin,
    ) -> bool {
        NoiseTcpOffhostAnchorTransport::is_pinned_to(self, anchor_pin, provider_pin)
    }

    fn read(
        &mut self,
        request: &ExternalCasOffhostAnchorReadRequest,
    ) -> Result<ExternalCasOffhostAnchorReceipt, String> {
        NoiseTcpOffhostAnchorTransport::read(self, request).map_err(|error| error.to_string())
    }

    fn compare_and_swap(
        &mut self,
        request: &ExternalCasOffhostAnchorCasRequest,
        next_record_bytes: &[u8],
        provider_receipt_bytes: &[u8],
    ) -> Result<ExternalCasOffhostAnchorReceipt, String> {
        NoiseTcpOffhostAnchorTransport::compare_and_swap(
            self,
            request,
            next_record_bytes,
            provider_receipt_bytes,
        )
        .map_err(|error| error.to_string())
    }
}

pub struct QRunV06Qap1ExternalCoordinator<P, PV, AV, Q> {
    provider: VerifiedExternalCasClient<P, PV>,
    provider_verifier: PV,
    floor: ExternalCasFloorStore,
    anchor: Q,
    provider_pin: ExternalCasPin,
    qfp6_pin: QRunV06ExternalAnchorPin,
    anchor_pin: ExternalCasOffhostAnchorPin,
    anchor_verifier: AV,
}

impl<P, PV, AV, Q> QRunV06Qap1ExternalCoordinator<P, PV, AV, Q>
where
    P: ExternalCasProviderTransport,
    PV: MlDsa65Verifier + Clone,
    AV: MlDsa65Verifier,
    Q: QRunV06Qap1AnchorTransport,
{
    pub fn new(
        provider: P,
        floor: ExternalCasFloorStore,
        anchor: Q,
        qfp6_pin: QRunV06ExternalAnchorPin,
        anchor_pin: ExternalCasOffhostAnchorPin,
        provider_verifier: PV,
        anchor_verifier: AV,
    ) -> Result<Self, QRunV06Qap1CoordinatorError> {
        let provider_pin = qfp6_pin.external_cas_pin().clone();
        anchor_pin
            .validate(&provider_pin)
            .map_err(|_| QRunV06Qap1CoordinatorError::WrongPin)?;
        if floor.pin() != &provider_pin || !anchor.is_pinned_to(&anchor_pin, &provider_pin) {
            return Err(QRunV06Qap1CoordinatorError::WrongPin);
        }
        let verified_provider = VerifiedExternalCasClient::new(
            provider_pin.clone(),
            provider,
            provider_verifier.clone(),
        )
        .map_err(|error| QRunV06Qap1CoordinatorError::Provider(error.to_string()))?;
        Ok(Self {
            provider: verified_provider,
            provider_verifier,
            floor,
            anchor,
            provider_pin,
            qfp6_pin,
            anchor_pin,
            anchor_verifier,
        })
    }

    pub fn provider_pin(&self) -> &ExternalCasPin {
        &self.provider_pin
    }

    pub fn qfp6_pin(&self) -> &QRunV06ExternalAnchorPin {
        &self.qfp6_pin
    }

    pub fn anchor_pin(&self) -> &ExternalCasOffhostAnchorPin {
        &self.anchor_pin
    }

    pub fn provider_verifier(&self) -> &PV {
        &self.provider_verifier
    }

    pub fn anchor_verifier(&self) -> &AV {
        &self.anchor_verifier
    }

    pub fn load_latest_journal(
        &self,
        journal_directory: &Path,
    ) -> Result<Option<QRunV06Qap1Journal>, QRunV06Qap1CoordinatorError> {
        if !journal_directory.exists() {
            return Ok(None);
        }
        QRunV06Qap1Journal::load_latest(
            journal_directory,
            &self.provider_pin,
            &self.anchor_pin,
            &self.provider_verifier,
            &self.anchor_verifier,
        )
        .map_err(Into::into)
    }

    /// Obtain fresh signed observations from both authorities and require byte-exact equality
    /// with the state independently provisioned to the node. No provider or anchor bootstrap
    /// is inferred from the local QFP6 manifest.
    pub fn verify_current(
        &mut self,
        expected: &QRunV06ExternalAnchorState,
    ) -> Result<(), QRunV06Qap1CoordinatorError> {
        expected
            .validate()
            .map_err(|_| QRunV06Qap1CoordinatorError::AnchorStateMismatch)?;
        self.verify_domain(expected)?;
        let anchor_state = self.read_anchor_state(
            expected
                .digest()
                .map_err(|_| QRunV06Qap1CoordinatorError::AnchorStateMismatch)?,
        )?;
        if anchor_state.provider_record.next_state_digest
            != expected
                .digest()
                .map_err(|_| QRunV06Qap1CoordinatorError::AnchorStateMismatch)?
        {
            return Err(QRunV06Qap1CoordinatorError::AnchorStateMismatch);
        }
        self.read_and_check_provider(&anchor_state, expected)?;
        Ok(())
    }

    /// Persist the exact prepared QFP6 intent before issuing any Provider CAS. The Q6EA
    /// signed Read and Provider signed Read must agree with the local, independently pinned
    /// predecessor and the floor. The request nonce/operation ID never change on retry.
    pub fn prepare_intent(
        &mut self,
        store: &QRunV06DurableForkStore,
        prepared: &QRunV06PreparedCommit,
        predecessor: &QRunV06ExternalAnchorState,
        successor: &QRunV06ExternalAnchorState,
    ) -> Result<QRunV06Qap1Journal, QRunV06Qap1CoordinatorError> {
        predecessor
            .validate_successor(successor)
            .map_err(|_| QRunV06Qap1CoordinatorError::AnchorStateMismatch)?;
        self.verify_domain(predecessor)?;
        self.verify_domain(successor)?;

        let anchor_predecessor = self.read_anchor_state(
            predecessor
                .digest()
                .map_err(|_| QRunV06Qap1CoordinatorError::AnchorStateMismatch)?,
        )?;
        if anchor_predecessor.provider_record.next_state_digest
            != predecessor
                .digest()
                .map_err(|_| QRunV06Qap1CoordinatorError::AnchorStateMismatch)?
        {
            return Err(QRunV06Qap1CoordinatorError::AnchorStateMismatch);
        }
        let observed = self.read_and_check_provider(&anchor_predecessor, predecessor)?;
        let operation_id = random_digest()?;
        let request_nonce = random_digest()?;
        let next_record = ExternalCasRecord {
            generation: observed
                .record
                .generation
                .checked_add(1)
                .ok_or(QRunV06Qap1CoordinatorError::InvalidProviderRequest)?,
            provider_id: self.provider_pin.provider_id,
            network_id: self.provider_pin.network_id,
            genesis_digest: self.provider_pin.genesis_digest,
            previous_record_digest: observed
                .record
                .digest()
                .map_err(|_| QRunV06Qap1CoordinatorError::InvalidProviderRequest)?,
            previous_state_digest: observed.record.next_state_digest,
            next_state_digest: successor
                .digest()
                .map_err(|_| QRunV06Qap1CoordinatorError::InvalidProviderRequest)?,
            operation_id,
            request_digest: [1; 32],
        };
        observed
            .record
            .validate_successor(&next_record)
            .map_err(|_| QRunV06Qap1CoordinatorError::InvalidProviderRequest)?;
        let mut provider_request = ExternalCasWriteRequest {
            request_nonce,
            operation_id,
            request_digest: [1; 32],
            expected_generation: observed.record.generation,
            expected_object_generation: observed.object_generation,
            expected_record_digest: observed
                .record
                .digest()
                .map_err(|_| QRunV06Qap1CoordinatorError::InvalidProviderRequest)?,
            expected_state_digest: observed.record.next_state_digest,
            next_record,
        };
        provider_request
            .bind_request_digest(&self.provider_pin)
            .map_err(|_| QRunV06Qap1CoordinatorError::InvalidProviderRequest)?;
        provider_request
            .validate(&self.provider_pin)
            .map_err(|_| QRunV06Qap1CoordinatorError::InvalidProviderRequest)?;

        let journal = QRunV06Qap1Journal::new(
            predecessor.clone(),
            successor.clone(),
            anchor_predecessor,
            provider_request,
            prepared.candidate_envelope().to_vec(),
            prepared.manifest_bytes().to_vec(),
            &self.provider_pin,
        )?;
        let directory = store.qap1_directory()?;
        journal.persist_prepared(&directory, &self.provider_pin)?;
        Ok(journal)
    }

    /// Drive the persisted exact intent through Provider ECS1, Q6EA QAR1 CAS and a fresh
    /// challenge-bound Q6EA Read. On any ambiguous error, the last completed QAP1 snapshot
    /// remains durable and the caller must stop admitting blocks until recovery resumes it.
    pub fn advance_to_anchor_confirmed(
        &mut self,
        journal_directory: &Path,
        mut journal: QRunV06Qap1Journal,
    ) -> Result<QRunV06Qap1Journal, QRunV06Qap1CoordinatorError> {
        loop {
            match journal.phase() {
                QRunV06Qap1Phase::Prepared => {
                    let receipt = self
                        .provider
                        .compare_and_swap(journal.provider_request())
                        .map_err(|error| {
                            QRunV06Qap1CoordinatorError::Provider(error.to_string())
                        })?;
                    let bytes = receipt
                        .encode()
                        .map_err(|error| QRunV06Qap1CoordinatorError::Provider(error.to_string()))?
                        .to_vec();
                    let next = journal.record_provider_receipt(
                        &bytes,
                        &self.provider_pin,
                        &self.provider_verifier,
                    )?;
                    next.persist_transition(
                        journal_directory,
                        &journal,
                        &self.provider_pin,
                        &self.anchor_pin,
                        &self.provider_verifier,
                        &self.anchor_verifier,
                    )?;
                    journal = next;
                }
                QRunV06Qap1Phase::ProviderCommitted => {
                    self.sync_floor_from_journal(&journal)?;
                    let anchor_successor = journal
                        .anchor_successor()
                        .ok_or(QRunV06Qap1CoordinatorError::MissingEvidence)?;
                    let request = ExternalCasOffhostAnchorCasRequest {
                        challenge: random_digest()?,
                        operation_id: journal.provider_request().operation_id,
                        request_digest: journal.provider_request().request_digest,
                        expected_sequence: journal.anchor_predecessor().sequence,
                        expected_state_digest: journal
                            .anchor_predecessor()
                            .digest()
                            .map_err(|_| QRunV06Qap1CoordinatorError::AnchorStateMismatch)?,
                        target_state_digest: anchor_successor
                            .digest()
                            .map_err(|_| QRunV06Qap1CoordinatorError::AnchorStateMismatch)?,
                    };
                    let next = journal.prepare_anchor_cas(request, &self.provider_pin)?;
                    next.persist_transition(
                        journal_directory,
                        &journal,
                        &self.provider_pin,
                        &self.anchor_pin,
                        &self.provider_verifier,
                        &self.anchor_verifier,
                    )?;
                    journal = next;
                }
                QRunV06Qap1Phase::AnchorCasPrepared => {
                    self.sync_floor_from_journal(&journal)?;
                    let request = journal
                        .anchor_cas_request()
                        .ok_or(QRunV06Qap1CoordinatorError::MissingEvidence)?;
                    let record =
                        journal
                            .provider_request()
                            .next_record
                            .encode()
                            .map_err(|error| {
                                QRunV06Qap1CoordinatorError::Provider(error.to_string())
                            })?;
                    let provider_receipt = journal
                        .provider_receipt_bytes()
                        .ok_or(QRunV06Qap1CoordinatorError::MissingEvidence)?;
                    let receipt = self
                        .anchor
                        .compare_and_swap(request, &record, provider_receipt)
                        .map_err(QRunV06Qap1CoordinatorError::Anchor)?;
                    let bytes = receipt
                        .encode()
                        .map_err(|error| QRunV06Qap1CoordinatorError::Anchor(error.to_string()))?;
                    let next = journal.record_anchor_receipt(
                        &bytes,
                        &self.anchor_pin,
                        &self.provider_pin,
                        &self.anchor_verifier,
                    )?;
                    next.persist_transition(
                        journal_directory,
                        &journal,
                        &self.provider_pin,
                        &self.anchor_pin,
                        &self.provider_verifier,
                        &self.anchor_verifier,
                    )?;
                    journal = next;
                }
                QRunV06Qap1Phase::AnchorCommitted => {
                    let request = ExternalCasOffhostAnchorReadRequest {
                        challenge: random_digest()?,
                        operation_id: random_digest()?,
                        request_digest: journal
                            .successor()
                            .digest()
                            .map_err(|_| QRunV06Qap1CoordinatorError::AnchorStateMismatch)?,
                    };
                    let receipt = self
                        .anchor
                        .read(&request)
                        .map_err(QRunV06Qap1CoordinatorError::Anchor)?;
                    let bytes = receipt
                        .encode()
                        .map_err(|error| QRunV06Qap1CoordinatorError::Anchor(error.to_string()))?;
                    let next = journal.confirm_anchor_read(
                        request,
                        &bytes,
                        &self.anchor_pin,
                        &self.provider_pin,
                        &self.anchor_verifier,
                    )?;
                    next.persist_transition(
                        journal_directory,
                        &journal,
                        &self.provider_pin,
                        &self.anchor_pin,
                        &self.provider_verifier,
                        &self.anchor_verifier,
                    )?;
                    journal = next;
                }
                QRunV06Qap1Phase::AnchorConfirmed => {
                    journal.verify_saved_evidence(
                        &self.provider_pin,
                        &self.anchor_pin,
                        &self.provider_verifier,
                        &self.anchor_verifier,
                    )?;
                    self.sync_floor_from_journal(&journal)?;
                    return Ok(journal);
                }
                _ => return Err(QRunV06Qap1CoordinatorError::UnsupportedPhase),
            }
        }
    }

    fn sync_floor_from_journal(
        &self,
        journal: &QRunV06Qap1Journal,
    ) -> Result<(), QRunV06Qap1CoordinatorError> {
        let receipt_bytes = journal
            .provider_receipt_bytes()
            .ok_or(QRunV06Qap1CoordinatorError::MissingEvidence)?;
        let receipt = ExternalCasReceipt::decode(receipt_bytes)
            .map_err(|error| QRunV06Qap1CoordinatorError::Provider(error.to_string()))?;
        let snapshot = self.floor.snapshot()?;
        let previous = &journal.anchor_predecessor().provider_record;
        let previous_object_generation = journal.anchor_predecessor().provider_object_generation;
        let next = &journal.provider_request().next_record;
        if snapshot.trusted_record == *next
            && snapshot.minimum_object_generation == receipt.object_generation
        {
            return Ok(());
        }
        if snapshot.trusted_record != *previous
            || snapshot.minimum_object_generation != previous_object_generation
        {
            return Err(QRunV06Qap1CoordinatorError::ProviderStateMismatch);
        }
        self.floor.advance(
            previous,
            previous_object_generation,
            next,
            receipt.object_generation,
        )?;
        Ok(())
    }

    fn verify_domain(
        &self,
        state: &QRunV06ExternalAnchorState,
    ) -> Result<(), QRunV06Qap1CoordinatorError> {
        state
            .validate()
            .map_err(|_| QRunV06Qap1CoordinatorError::AnchorStateMismatch)?;
        if state.network_id != self.provider_pin.network_id
            || state.genesis_digest != self.provider_pin.genesis_digest
            || state.genesis_descriptor_commitment != self.qfp6_pin.genesis_descriptor_commitment()
        {
            return Err(QRunV06Qap1CoordinatorError::WrongPin);
        }
        Ok(())
    }

    fn read_anchor_state(
        &mut self,
        request_digest: [u8; 32],
    ) -> Result<ExternalCasOffhostAnchorState, QRunV06Qap1CoordinatorError> {
        let request = ExternalCasOffhostAnchorReadRequest {
            challenge: random_digest()?,
            operation_id: random_digest()?,
            request_digest,
        };
        let receipt = self
            .anchor
            .read(&request)
            .map_err(QRunV06Qap1CoordinatorError::Anchor)?;
        receipt
            .verify_read(
                &self.anchor_pin,
                &self.provider_pin,
                &request,
                &self.anchor_verifier,
            )
            .map_err(|error| QRunV06Qap1CoordinatorError::Anchor(error.to_string()))
    }

    fn read_and_check_provider(
        &mut self,
        anchor_state: &ExternalCasOffhostAnchorState,
        qfp6_state: &QRunV06ExternalAnchorState,
    ) -> Result<
        crate::external_cas_anchor_candidate::VerifiedExternalCasRead,
        QRunV06Qap1CoordinatorError,
    > {
        let floor = self.floor.snapshot()?;
        if floor.trusted_record != anchor_state.provider_record
            || floor.minimum_object_generation != anchor_state.provider_object_generation
            || anchor_state.provider_record.next_state_digest
                != qfp6_state
                    .digest()
                    .map_err(|_| QRunV06Qap1CoordinatorError::AnchorStateMismatch)?
        {
            return Err(QRunV06Qap1CoordinatorError::ProviderStateMismatch);
        }
        let request: ExternalCasReadRequest = self
            .provider
            .fresh_read_request(
                random_digest()?,
                qfp6_state
                    .digest()
                    .map_err(|_| QRunV06Qap1CoordinatorError::AnchorStateMismatch)?,
            )
            .map_err(|error| QRunV06Qap1CoordinatorError::Provider(error.to_string()))?;
        let observed = self
            .provider
            .read_current(
                &request,
                floor.trusted_record.generation,
                floor.minimum_object_generation,
                Some(&floor.trusted_record),
            )
            .map_err(|error| QRunV06Qap1CoordinatorError::Provider(error.to_string()))?;
        if observed.record != anchor_state.provider_record
            || observed.object_generation != anchor_state.provider_object_generation
        {
            return Err(QRunV06Qap1CoordinatorError::ProviderStateMismatch);
        }
        Ok(observed)
    }
}

fn random_digest() -> Result<[u8; 32], QRunV06Qap1CoordinatorError> {
    let mut value = [0u8; 32];
    getrandom::getrandom(&mut value)
        .map_err(|_| QRunV06Qap1CoordinatorError::RandomnessUnavailable)?;
    if value == [0; 32] {
        return Err(QRunV06Qap1CoordinatorError::RandomnessUnavailable);
    }
    Ok(value)
}
