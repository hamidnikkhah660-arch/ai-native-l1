//! Offline QRun Verifiable Agentic Asset Commerce (QVAAC) settlement candidate.
//!
//! This module composes an externally verified agent-authorization grant with a QVAP
//! evidence bundle and an independent fulfilment attestation. It is a local research
//! state machine only: no live escrow, monetary transfer, AAP token parser, ERC-8004
//! registry, x402 facilitator, canonical transaction, consensus or node integration.
//!
//! Production adapters must verify the referenced authorization, agent-key status,
//! QVAP attestations, trusted time and fulfilment evidence. This state machine never
//! treats an LLM assertion as authorization or proof of delivery.

use crate::qrun_verifiable_asset_passport_candidate::QvapObservedStatus;
use sha2::{Digest, Sha256};

pub const QVAAC_VERSION: u16 = 1;
pub const QVAAC_MAX_SIGNATURE_BYTES: usize = 4096;
pub const QVAAC_MAX_EVENTS: usize = 64;
pub const ACTION_FUND_ESCROW: u16 = 1 << 0;
pub const ACTION_SUBMIT_FULFILMENT: u16 = 1 << 1;
pub const ACTION_MASK: u16 = ACTION_FUND_ESCROW | ACTION_SUBMIT_FULFILMENT;

const GRANT_DOMAIN: &[u8] = b"QRUN-QVAAC-AGENT-GRANT-V1\0";
const EVIDENCE_DOMAIN: &[u8] = b"QRUN-QVAAC-ASSET-EVIDENCE-V1\0";
const INTENT_DOMAIN: &[u8] = b"QRUN-QVAAC-INTENT-V1\0";
const FULFILMENT_DOMAIN: &[u8] = b"QRUN-QVAAC-FULFILMENT-V1\0";
const EVENT_DOMAIN: &[u8] = b"QRUN-QVAAC-EVENT-V1\0";
const RECEIPT_DOMAIN: &[u8] = b"QRUN-QVAAC-SETTLEMENT-RECEIPT-V1\0";

fn is_zero(value: &[u8]) -> bool {
    value.iter().all(|byte| *byte == 0)
}

fn hash_parts(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QvaacError {
    InvalidShape,
    InvalidStateTransition,
    WrongNetwork,
    WrongIntent,
    WrongAsset,
    WrongPrincipal,
    WrongAgent,
    WrongCounterparty,
    WrongEvaluator,
    WrongEvidence,
    EvidenceNotActive,
    EvidenceExpired,
    InsufficientVerifiedQuantity,
    IndependentAttestorsRequired,
    GrantExpired,
    GrantNotYetValid,
    GrantRevoked,
    GrantScopeInsufficient,
    SpendPerTransactionExceeded,
    CumulativeSpendExceeded,
    InvalidSignature,
    FulfilmentNotYetDelivered,
    FulfilmentLate,
    FulfilmentExpired,
    FulfilmentRejected,
    FulfilmentQuantityMismatch,
    ZeroAmount,
    ArithmeticOverflow,
    TooManyEvents,
    EventChainInvalid,
}

impl std::fmt::Display for QvaacError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for QvaacError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QvaacAssetEvidenceBundle {
    pub network_id: [u8; 32],
    pub asset_id: [u8; 32],
    pub asset_class: u16,
    pub passport_digest: [u8; 32],
    pub passport_sequence: u64,
    pub evidence_sequence: u64,
    pub evidence_digest: [u8; 32],
    pub issuer_id: [u8; 32],
    pub issuer_claim_digest: [u8; 32],
    pub custodian_id: [u8; 32],
    pub custody_claim_digest: [u8; 32],
    pub inspector_id: [u8; 32],
    pub inspection_claim_digest: [u8; 32],
    pub observed_status: QvapObservedStatus,
    pub observed_at: u64,
    pub valid_until: u64,
    /// Already expressed in transferable token base units, not physical units.
    pub verified_transferable_quantity: u128,
}

impl QvaacAssetEvidenceBundle {
    pub fn validate(&self, now: u64) -> Result<(), QvaacError> {
        if is_zero(&self.network_id)
            || is_zero(&self.asset_id)
            || self.asset_class == 0
            || is_zero(&self.passport_digest)
            || self.passport_sequence == 0
            || self.evidence_sequence == 0
            || is_zero(&self.evidence_digest)
            || is_zero(&self.issuer_id)
            || is_zero(&self.issuer_claim_digest)
            || is_zero(&self.custodian_id)
            || is_zero(&self.custody_claim_digest)
            || is_zero(&self.inspector_id)
            || is_zero(&self.inspection_claim_digest)
            || self.verified_transferable_quantity == 0
            || self.observed_at >= self.valid_until
        {
            return Err(QvaacError::InvalidShape);
        }
        if self.observed_at > now || self.valid_until <= now {
            return Err(QvaacError::EvidenceExpired);
        }
        if self.observed_status != QvapObservedStatus::Active {
            return Err(QvaacError::EvidenceNotActive);
        }
        if self.issuer_id == self.custodian_id
            || self.issuer_id == self.inspector_id
            || self.custodian_id == self.inspector_id
        {
            return Err(QvaacError::IndependentAttestorsRequired);
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<[u8; 32], QvaacError> {
        if is_zero(&self.network_id)
            || is_zero(&self.asset_id)
            || self.asset_class == 0
            || is_zero(&self.passport_digest)
            || self.passport_sequence == 0
            || self.evidence_sequence == 0
            || is_zero(&self.evidence_digest)
            || self.issuer_id == [0; 32]
            || self.custodian_id == [0; 32]
            || self.inspector_id == [0; 32]
            || self.issuer_claim_digest == [0; 32]
            || self.custody_claim_digest == [0; 32]
            || self.inspection_claim_digest == [0; 32]
            || self.verified_transferable_quantity == 0
        {
            return Err(QvaacError::InvalidShape);
        }
        Ok(hash_parts(&[
            EVIDENCE_DOMAIN,
            &self.network_id,
            &self.asset_id,
            &self.asset_class.to_be_bytes(),
            &self.passport_digest,
            &self.passport_sequence.to_be_bytes(),
            &self.evidence_sequence.to_be_bytes(),
            &self.evidence_digest,
            &self.issuer_id,
            &self.issuer_claim_digest,
            &self.custodian_id,
            &self.custody_claim_digest,
            &self.inspector_id,
            &self.inspection_claim_digest,
            &[self.observed_status as u8],
            &self.observed_at.to_be_bytes(),
            &self.valid_until.to_be_bytes(),
            &self.verified_transferable_quantity.to_be_bytes(),
        ]))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QvaacIntent {
    pub network_id: [u8; 32],
    pub intent_id: [u8; 32],
    pub buyer_id: [u8; 32],
    pub seller_id: [u8; 32],
    pub agent_id: [u8; 32],
    pub evaluator_id: [u8; 32],
    pub asset_id: [u8; 32],
    pub asset_class: u16,
    pub quantity: u128,
    pub payment_asset_id: [u8; 32],
    pub max_price: u128,
    pub passport_digest: [u8; 32],
    pub evidence_bundle_digest: [u8; 32],
    pub expires_at: u64,
    pub delivery_deadline: u64,
    pub challenge_window_seconds: u64,
}

impl QvaacIntent {
    pub fn validate(&self) -> Result<(), QvaacError> {
        if is_zero(&self.network_id)
            || is_zero(&self.intent_id)
            || is_zero(&self.buyer_id)
            || is_zero(&self.seller_id)
            || is_zero(&self.agent_id)
            || is_zero(&self.evaluator_id)
            || is_zero(&self.asset_id)
            || self.asset_class == 0
            || self.quantity == 0
            || is_zero(&self.payment_asset_id)
            || self.max_price == 0
            || is_zero(&self.passport_digest)
            || is_zero(&self.evidence_bundle_digest)
            || self.expires_at == 0
            || self.delivery_deadline == 0
            || self.delivery_deadline > self.expires_at
            || self.challenge_window_seconds == 0
            || self.buyer_id == self.seller_id
            || self.buyer_id == self.evaluator_id
            || self.seller_id == self.evaluator_id
            || self.agent_id == self.buyer_id
            || self.agent_id == self.seller_id
            || self.agent_id == self.evaluator_id
        {
            return Err(QvaacError::InvalidShape);
        }
        self.delivery_deadline
            .checked_add(self.challenge_window_seconds)
            .ok_or(QvaacError::ArithmeticOverflow)?;
        Ok(())
    }

    pub fn digest(&self) -> Result<[u8; 32], QvaacError> {
        self.validate()?;
        Ok(hash_parts(&[
            INTENT_DOMAIN,
            &self.network_id,
            &self.intent_id,
            &self.buyer_id,
            &self.seller_id,
            &self.agent_id,
            &self.evaluator_id,
            &self.asset_id,
            &self.asset_class.to_be_bytes(),
            &self.quantity.to_be_bytes(),
            &self.payment_asset_id,
            &self.max_price.to_be_bytes(),
            &self.passport_digest,
            &self.evidence_bundle_digest,
            &self.expires_at.to_be_bytes(),
            &self.delivery_deadline.to_be_bytes(),
            &self.challenge_window_seconds.to_be_bytes(),
        ]))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QvaacAgentCapabilityGrant {
    pub network_id: [u8; 32],
    pub grant_id: [u8; 32],
    pub principal_id: [u8; 32],
    pub agent_id: [u8; 32],
    pub agent_key_id: [u8; 32],
    pub intent_digest: [u8; 32],
    pub asset_class: u16,
    pub counterparty_id: [u8; 32],
    pub allowed_actions: u16,
    pub max_per_transaction: u128,
    pub max_cumulative_spend: u128,
    pub spent_before: u128,
    pub not_before: u64,
    pub expires_at: u64,
    pub sequence: u64,
    pub revocation_epoch: u64,
    pub signature_algorithm: u16,
    pub signature: Vec<u8>,
}

impl QvaacAgentCapabilityGrant {
    pub fn validate_shape(&self) -> Result<(), QvaacError> {
        if is_zero(&self.network_id)
            || is_zero(&self.grant_id)
            || is_zero(&self.principal_id)
            || is_zero(&self.agent_id)
            || is_zero(&self.agent_key_id)
            || is_zero(&self.intent_digest)
            || self.asset_class == 0
            || is_zero(&self.counterparty_id)
            || self.allowed_actions == 0
            || self.allowed_actions & !ACTION_MASK != 0
            || self.max_per_transaction == 0
            || self.max_cumulative_spend == 0
            || self.spent_before > self.max_cumulative_spend
            || self.not_before >= self.expires_at
            || self.sequence == 0
            || self.revocation_epoch == 0
            || self.signature_algorithm == 0
            || self.signature.is_empty()
            || self.signature.len() > QVAAC_MAX_SIGNATURE_BYTES
        {
            return Err(QvaacError::InvalidShape);
        }
        Ok(())
    }

    pub fn signing_digest(&self) -> Result<[u8; 32], QvaacError> {
        self.validate_shape()?;
        Ok(hash_parts(&[
            GRANT_DOMAIN,
            &self.network_id,
            &self.grant_id,
            &self.principal_id,
            &self.agent_id,
            &self.agent_key_id,
            &self.intent_digest,
            &self.asset_class.to_be_bytes(),
            &self.counterparty_id,
            &self.allowed_actions.to_be_bytes(),
            &self.max_per_transaction.to_be_bytes(),
            &self.max_cumulative_spend.to_be_bytes(),
            &self.spent_before.to_be_bytes(),
            &self.not_before.to_be_bytes(),
            &self.expires_at.to_be_bytes(),
            &self.sequence.to_be_bytes(),
            &self.revocation_epoch.to_be_bytes(),
            &self.signature_algorithm.to_be_bytes(),
        ]))
    }
}

/// The production adapter should consume an AAP / wallet-authorized grant and verify:
/// principal signature, agent/key binding, revocation epoch, sequence and policy.
/// No private root key or bearer credential is ever passed to the model.
pub trait QvaacGrantVerifier {
    fn verify(&self, grant: &QvaacAgentCapabilityGrant, now: u64) -> Result<(), QvaacError>;
}

/// An adapter should verify QVAP attestation signatures, current registry roles and
/// proof/state-root inclusion before allowing the evidence bundle into this state machine.
pub trait QvaacEvidenceVerifier {
    fn verify(&self, bundle: &QvaacAssetEvidenceBundle, now: u64) -> Result<(), QvaacError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QvaacFulfilmentProof {
    pub network_id: [u8; 32],
    pub intent_digest: [u8; 32],
    pub seller_id: [u8; 32],
    pub buyer_id: [u8; 32],
    pub evaluator_id: [u8; 32],
    pub asset_id: [u8; 32],
    pub passport_digest: [u8; 32],
    pub evidence_bundle_digest: [u8; 32],
    pub quantity_delivered: u128,
    /// Evaluator decision; false is a signed rejection and triggers a buyer refund.
    pub accepted: bool,
    pub delivered_at: u64,
    pub expires_at: u64,
    pub delivery_evidence_digest: [u8; 32],
    pub signature_algorithm: u16,
    pub signature: Vec<u8>,
}

impl QvaacFulfilmentProof {
    pub fn signing_digest(&self) -> Result<[u8; 32], QvaacError> {
        if is_zero(&self.network_id)
            || is_zero(&self.intent_digest)
            || is_zero(&self.seller_id)
            || is_zero(&self.buyer_id)
            || is_zero(&self.evaluator_id)
            || is_zero(&self.asset_id)
            || is_zero(&self.passport_digest)
            || is_zero(&self.evidence_bundle_digest)
            || (self.accepted && self.quantity_delivered == 0)
            || self.expires_at <= self.delivered_at
            || is_zero(&self.delivery_evidence_digest)
            || self.signature_algorithm == 0
            || self.signature.is_empty()
            || self.signature.len() > QVAAC_MAX_SIGNATURE_BYTES
        {
            return Err(QvaacError::InvalidShape);
        }
        Ok(hash_parts(&[
            FULFILMENT_DOMAIN,
            &self.network_id,
            &self.intent_digest,
            &self.seller_id,
            &self.buyer_id,
            &self.evaluator_id,
            &self.asset_id,
            &self.passport_digest,
            &self.evidence_bundle_digest,
            &self.quantity_delivered.to_be_bytes(),
            &[u8::from(self.accepted)],
            &self.delivered_at.to_be_bytes(),
            &self.expires_at.to_be_bytes(),
            &self.delivery_evidence_digest,
            &self.signature_algorithm.to_be_bytes(),
        ]))
    }
}

pub trait QvaacFulfilmentVerifier {
    fn verify(
        &self,
        evaluator_id: &[u8; 32],
        signature_algorithm: u16,
        digest: &[u8; 32],
        signature: &[u8],
    ) -> Result<(), QvaacError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum QvaacStatus {
    AwaitingFunding = 1,
    Funded = 2,
    Settled = 3,
    Refunded = 4,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum QvaacEventKind {
    Opened = 1,
    EscrowFunded = 2,
    Settled = 3,
    Refunded = 4,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QvaacEvent {
    pub sequence: u64,
    pub timestamp: u64,
    pub kind: QvaacEventKind,
    pub amount: u128,
    pub subject_digest: [u8; 32],
    pub previous_digest: [u8; 32],
    pub digest: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QvaacSettlementReceipt {
    pub network_id: [u8; 32],
    pub intent_digest: [u8; 32],
    pub grant_digest: [u8; 32],
    pub passport_digest: [u8; 32],
    pub evidence_bundle_digest: [u8; 32],
    pub fulfilment_digest: [u8; 32],
    pub escrow_amount: u128,
    pub status: QvaacStatus,
    pub event_tip: [u8; 32],
    pub receipt_digest: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QvaacEscrowCandidate {
    intent: QvaacIntent,
    grant: QvaacAgentCapabilityGrant,
    grant_digest: [u8; 32],
    evidence_bundle: QvaacAssetEvidenceBundle,
    evidence_digest: [u8; 32],
    status: QvaacStatus,
    escrow_amount: u128,
    spent_after: u128,
    fulfilment_digest: [u8; 32],
    events: Vec<QvaacEvent>,
}

impl QvaacEscrowCandidate {
    pub fn open<G, E>(
        intent: QvaacIntent,
        evidence_bundle: QvaacAssetEvidenceBundle,
        grant: QvaacAgentCapabilityGrant,
        now: u64,
        grant_verifier: &G,
        evidence_verifier: &E,
    ) -> Result<Self, QvaacError>
    where
        G: QvaacGrantVerifier,
        E: QvaacEvidenceVerifier,
    {
        intent.validate()?;
        if now >= intent.expires_at || now >= intent.delivery_deadline {
            return Err(QvaacError::GrantExpired);
        }
        evidence_bundle.validate(now)?;
        evidence_verifier.verify(&evidence_bundle, now)?;
        let evidence_digest = evidence_bundle.digest()?;
        if evidence_bundle.network_id != intent.network_id {
            return Err(QvaacError::WrongNetwork);
        }
        if evidence_bundle.asset_id != intent.asset_id
            || evidence_bundle.asset_class != intent.asset_class
            || evidence_bundle.passport_digest != intent.passport_digest
            || evidence_digest != intent.evidence_bundle_digest
        {
            return Err(QvaacError::WrongEvidence);
        }
        if intent.quantity > evidence_bundle.verified_transferable_quantity {
            return Err(QvaacError::InsufficientVerifiedQuantity);
        }

        grant.validate_shape()?;
        if grant.network_id != intent.network_id {
            return Err(QvaacError::WrongNetwork);
        }
        if grant.principal_id != intent.buyer_id {
            return Err(QvaacError::WrongPrincipal);
        }
        if grant.agent_id != intent.agent_id {
            return Err(QvaacError::WrongAgent);
        }
        if grant.intent_digest != intent.digest()? {
            return Err(QvaacError::WrongIntent);
        }
        if grant.asset_class != intent.asset_class {
            return Err(QvaacError::WrongAsset);
        }
        if grant.counterparty_id != intent.seller_id {
            return Err(QvaacError::WrongCounterparty);
        }
        // The agent is authorized to fund escrow. The independent evaluator,
        // not the agent or seller, authorizes the fulfilment decision.
        if grant.allowed_actions & ACTION_FUND_ESCROW == 0 {
            return Err(QvaacError::GrantScopeInsufficient);
        }
        if now < grant.not_before {
            return Err(QvaacError::GrantNotYetValid);
        }
        if now >= grant.expires_at {
            return Err(QvaacError::GrantExpired);
        }
        if grant.expires_at < intent.expires_at {
            return Err(QvaacError::GrantExpired);
        }
        grant_verifier.verify(&grant, now)?;
        let grant_digest = grant.signing_digest()?;

        let mut escrow = Self {
            intent,
            grant,
            grant_digest,
            evidence_bundle,
            evidence_digest,
            status: QvaacStatus::AwaitingFunding,
            escrow_amount: 0,
            spent_after: 0,
            fulfilment_digest: [0; 32],
            events: Vec::new(),
        };
        let open_subject = hash_parts(&[
            b"QRUN-QVAAC-OPEN-SUBJECT-V1\0",
            &escrow.intent.digest()?,
            &escrow.grant_digest,
            &escrow.evidence_digest,
        ]);
        escrow.append_event(QvaacEventKind::Opened, now, 0, open_subject)?;
        Ok(escrow)
    }

    pub fn status(&self) -> QvaacStatus {
        self.status
    }

    pub fn escrow_amount(&self) -> u128 {
        self.escrow_amount
    }

    pub fn spent_after(&self) -> u128 {
        self.spent_after
    }

    pub fn events(&self) -> &[QvaacEvent] {
        &self.events
    }

    pub fn event_tip(&self) -> [u8; 32] {
        self.events.last().map_or([0; 32], |event| event.digest)
    }

    pub fn fund_escrow<G, E>(
        &mut self,
        amount: u128,
        now: u64,
        grant_verifier: &G,
        evidence_verifier: &E,
    ) -> Result<(), QvaacError>
    where
        G: QvaacGrantVerifier,
        E: QvaacEvidenceVerifier,
    {
        if self.status != QvaacStatus::AwaitingFunding {
            return Err(QvaacError::InvalidStateTransition);
        }
        if amount == 0 {
            return Err(QvaacError::ZeroAmount);
        }
        if now >= self.intent.expires_at
            || now >= self.intent.delivery_deadline
            || now >= self.grant.expires_at
        {
            return Err(QvaacError::GrantExpired);
        }
        self.evidence_bundle.validate(now)?;
        evidence_verifier.verify(&self.evidence_bundle, now)?;
        if self.evidence_bundle.digest()? != self.evidence_digest {
            return Err(QvaacError::WrongEvidence);
        }
        grant_verifier.verify(&self.grant, now)?;
        if amount > self.intent.max_price || amount > self.grant.max_per_transaction {
            return Err(QvaacError::SpendPerTransactionExceeded);
        }
        let spent_after = self
            .grant
            .spent_before
            .checked_add(amount)
            .ok_or(QvaacError::ArithmeticOverflow)?;
        if spent_after > self.grant.max_cumulative_spend {
            return Err(QvaacError::CumulativeSpendExceeded);
        }
        self.append_event(QvaacEventKind::EscrowFunded, now, amount, self.grant_digest)?;
        self.escrow_amount = amount;
        self.spent_after = spent_after;
        self.status = QvaacStatus::Funded;
        Ok(())
    }

    pub fn submit_fulfilment<E, V>(
        &mut self,
        proof: QvaacFulfilmentProof,
        now: u64,
        evidence_verifier: &E,
        fulfilment_verifier: &V,
    ) -> Result<(), QvaacError>
    where
        E: QvaacEvidenceVerifier,
        V: QvaacFulfilmentVerifier,
    {
        if self.status != QvaacStatus::Funded {
            return Err(QvaacError::InvalidStateTransition);
        }
        self.evidence_bundle.validate(now)?;
        evidence_verifier.verify(&self.evidence_bundle, now)?;
        let latest_evidence_digest = self.evidence_bundle.digest()?;
        if latest_evidence_digest != self.evidence_digest {
            return Err(QvaacError::EvidenceExpired);
        }

        let intent_digest = self.intent.digest()?;
        if proof.network_id != self.intent.network_id {
            return Err(QvaacError::WrongNetwork);
        }
        if proof.intent_digest != intent_digest {
            return Err(QvaacError::WrongIntent);
        }
        if proof.seller_id != self.intent.seller_id || proof.buyer_id != self.intent.buyer_id {
            return Err(QvaacError::WrongCounterparty);
        }
        if proof.evaluator_id != self.intent.evaluator_id
            || proof.evaluator_id == self.intent.seller_id
            || proof.evaluator_id == self.intent.buyer_id
        {
            return Err(QvaacError::WrongEvaluator);
        }
        if proof.asset_id != self.intent.asset_id
            || proof.passport_digest != self.intent.passport_digest
            || proof.evidence_bundle_digest != self.evidence_digest
        {
            return Err(QvaacError::WrongEvidence);
        }
        if proof.accepted && proof.quantity_delivered != self.intent.quantity {
            return Err(QvaacError::FulfilmentQuantityMismatch);
        }
        if proof.delivered_at > now {
            return Err(QvaacError::FulfilmentNotYetDelivered);
        }
        if proof.delivered_at > self.intent.delivery_deadline {
            return Err(QvaacError::FulfilmentLate);
        }
        let challenge_end = self
            .intent
            .delivery_deadline
            .checked_add(self.intent.challenge_window_seconds)
            .ok_or(QvaacError::ArithmeticOverflow)?;
        if proof.expires_at <= now || now > challenge_end {
            return Err(QvaacError::FulfilmentExpired);
        }
        let proof_digest = proof.signing_digest()?;
        fulfilment_verifier.verify(
            &proof.evaluator_id,
            proof.signature_algorithm,
            &proof_digest,
            &proof.signature,
        )?;

        let (event_kind, terminal_status) = if proof.accepted {
            (QvaacEventKind::Settled, QvaacStatus::Settled)
        } else {
            (QvaacEventKind::Refunded, QvaacStatus::Refunded)
        };
        self.append_event(event_kind, now, self.escrow_amount, proof_digest)?;
        self.fulfilment_digest = proof_digest;
        self.status = terminal_status;
        Ok(())
    }

    pub fn refund_after_deadline(&mut self, now: u64) -> Result<(), QvaacError> {
        if self.status != QvaacStatus::Funded {
            return Err(QvaacError::InvalidStateTransition);
        }
        let refund_at = self
            .intent
            .delivery_deadline
            .checked_add(self.intent.challenge_window_seconds)
            .ok_or(QvaacError::ArithmeticOverflow)?;
        if now <= refund_at {
            return Err(QvaacError::FulfilmentExpired);
        }
        let subject = hash_parts(&[
            b"QRUN-QVAAC-TIMEOUT-REFUND-V1\0",
            &self.intent.digest()?,
            &self.grant_digest,
        ]);
        self.append_event(QvaacEventKind::Refunded, now, self.escrow_amount, subject)?;
        self.status = QvaacStatus::Refunded;
        Ok(())
    }

    pub fn receipt(&self) -> Result<QvaacSettlementReceipt, QvaacError> {
        let intent_digest = self.intent.digest()?;
        let receipt_digest = hash_parts(&[
            RECEIPT_DOMAIN,
            &self.intent.network_id,
            &intent_digest,
            &self.grant_digest,
            &self.intent.passport_digest,
            &self.evidence_digest,
            &self.fulfilment_digest,
            &self.escrow_amount.to_be_bytes(),
            &[self.status as u8],
            &self.event_tip(),
        ]);
        Ok(QvaacSettlementReceipt {
            network_id: self.intent.network_id,
            intent_digest,
            grant_digest: self.grant_digest,
            passport_digest: self.intent.passport_digest,
            evidence_bundle_digest: self.evidence_digest,
            fulfilment_digest: self.fulfilment_digest,
            escrow_amount: self.escrow_amount,
            status: self.status,
            event_tip: self.event_tip(),
            receipt_digest,
        })
    }

    pub fn verify_event_chain(&self) -> Result<(), QvaacError> {
        if self.events.is_empty() || self.events.len() > QVAAC_MAX_EVENTS {
            return Err(QvaacError::EventChainInvalid);
        }
        let definition_digest = hash_parts(&[
            b"QRUN-QVAAC-STATE-ID-V1\0",
            &self.intent.digest()?,
            &self.grant_digest,
            &self.evidence_digest,
        ]);
        let mut previous = [0; 32];
        for (index, event) in self.events.iter().enumerate() {
            let expected_sequence = u64::try_from(index)
                .ok()
                .and_then(|value| value.checked_add(1))
                .ok_or(QvaacError::EventChainInvalid)?;
            if event.sequence != expected_sequence || event.previous_digest != previous {
                return Err(QvaacError::EventChainInvalid);
            }
            let expected = Self::event_digest(
                &definition_digest,
                event.sequence,
                event.timestamp,
                event.kind,
                event.amount,
                &event.subject_digest,
                &event.previous_digest,
            );
            if expected != event.digest {
                return Err(QvaacError::EventChainInvalid);
            }
            previous = event.digest;
        }
        Ok(())
    }

    fn append_event(
        &mut self,
        kind: QvaacEventKind,
        timestamp: u64,
        amount: u128,
        subject_digest: [u8; 32],
    ) -> Result<(), QvaacError> {
        if self.events.len() >= QVAAC_MAX_EVENTS {
            return Err(QvaacError::TooManyEvents);
        }
        let sequence = u64::try_from(self.events.len())
            .ok()
            .and_then(|value| value.checked_add(1))
            .ok_or(QvaacError::TooManyEvents)?;
        let previous_digest = self.event_tip();
        let definition_digest = hash_parts(&[
            b"QRUN-QVAAC-STATE-ID-V1\0",
            &self.intent.digest()?,
            &self.grant_digest,
            &self.evidence_digest,
        ]);
        let digest = Self::event_digest(
            &definition_digest,
            sequence,
            timestamp,
            kind,
            amount,
            &subject_digest,
            &previous_digest,
        );
        self.events.push(QvaacEvent {
            sequence,
            timestamp,
            kind,
            amount,
            subject_digest,
            previous_digest,
            digest,
        });
        Ok(())
    }

    fn event_digest(
        state_id: &[u8; 32],
        sequence: u64,
        timestamp: u64,
        kind: QvaacEventKind,
        amount: u128,
        subject_digest: &[u8; 32],
        previous_digest: &[u8; 32],
    ) -> [u8; 32] {
        hash_parts(&[
            EVENT_DOMAIN,
            state_id,
            &sequence.to_be_bytes(),
            &timestamp.to_be_bytes(),
            &[kind as u8],
            &amount.to_be_bytes(),
            subject_digest,
            previous_digest,
        ])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(super) struct TestVerifier;

    impl TestVerifier {
        fn sign(domain: &[u8], digest: &[u8; 32]) -> Vec<u8> {
            hash_parts(&[b"QVAAC-TEST-ONLY-NOT-CRYPTOGRAPHIC\0", domain, digest]).to_vec()
        }

        fn signed_grant(mut grant: QvaacAgentCapabilityGrant) -> QvaacAgentCapabilityGrant {
            grant.signature = vec![1];
            let digest = grant.signing_digest().unwrap();
            grant.signature = Self::sign(b"grant", &digest);
            grant
        }

        fn signed_proof(mut proof: QvaacFulfilmentProof) -> QvaacFulfilmentProof {
            proof.signature = vec![1];
            let digest = proof.signing_digest().unwrap();
            proof.signature = Self::sign(b"fulfilment", &digest);
            proof
        }
    }

    impl QvaacGrantVerifier for TestVerifier {
        fn verify(&self, grant: &QvaacAgentCapabilityGrant, now: u64) -> Result<(), QvaacError> {
            if grant.revocation_epoch != 1 {
                return Err(QvaacError::GrantRevoked);
            }
            if now < grant.not_before {
                return Err(QvaacError::GrantNotYetValid);
            }
            if now >= grant.expires_at {
                return Err(QvaacError::GrantExpired);
            }
            let digest = grant.signing_digest()?;
            if grant.signature == Self::sign(b"grant", &digest) {
                Ok(())
            } else {
                Err(QvaacError::InvalidSignature)
            }
        }
    }

    impl QvaacEvidenceVerifier for TestVerifier {
        fn verify(&self, bundle: &QvaacAssetEvidenceBundle, now: u64) -> Result<(), QvaacError> {
            bundle.validate(now)?;
            bundle.digest()?;
            Ok(())
        }
    }

    impl QvaacFulfilmentVerifier for TestVerifier {
        fn verify(
            &self,
            evaluator_id: &[u8; 32],
            signature_algorithm: u16,
            digest: &[u8; 32],
            signature: &[u8],
        ) -> Result<(), QvaacError> {
            if is_zero(evaluator_id) || signature_algorithm != 1 {
                return Err(QvaacError::InvalidSignature);
            }
            if signature == Self::sign(b"fulfilment", digest) {
                Ok(())
            } else {
                Err(QvaacError::InvalidSignature)
            }
        }
    }

    struct RevokedGrantVerifier;
    impl QvaacGrantVerifier for RevokedGrantVerifier {
        fn verify(&self, _grant: &QvaacAgentCapabilityGrant, _now: u64) -> Result<(), QvaacError> {
            Err(QvaacError::GrantRevoked)
        }
    }

    struct RevokedEvidenceVerifier;
    impl QvaacEvidenceVerifier for RevokedEvidenceVerifier {
        fn verify(&self, _bundle: &QvaacAssetEvidenceBundle, _now: u64) -> Result<(), QvaacError> {
            Err(QvaacError::EvidenceNotActive)
        }
    }

    pub(super) fn evidence() -> QvaacAssetEvidenceBundle {
        let value = QvaacAssetEvidenceBundle {
            network_id: [1; 32],
            asset_id: [2; 32],
            asset_class: 7,
            passport_digest: [3; 32],
            passport_sequence: 1,
            evidence_sequence: 1,
            evidence_digest: [4; 32],
            issuer_id: [5; 32],
            issuer_claim_digest: [6; 32],
            custodian_id: [7; 32],
            custody_claim_digest: [8; 32],
            inspector_id: [9; 32],
            inspection_claim_digest: [10; 32],
            observed_status: QvapObservedStatus::Active,
            observed_at: 10,
            valid_until: 1000,
            verified_transferable_quantity: 100,
        };
        value
    }

    pub(super) fn intent(bundle: &QvaacAssetEvidenceBundle) -> QvaacIntent {
        QvaacIntent {
            network_id: bundle.network_id,
            intent_id: [16; 32],
            buyer_id: [11; 32],
            seller_id: [12; 32],
            agent_id: [13; 32],
            evaluator_id: [14; 32],
            asset_id: bundle.asset_id,
            asset_class: bundle.asset_class,
            quantity: 20,
            payment_asset_id: [15; 32],
            max_price: 500,
            passport_digest: bundle.passport_digest,
            evidence_bundle_digest: bundle.digest().unwrap(),
            expires_at: 300,
            delivery_deadline: 250,
            challenge_window_seconds: 30,
        }
    }

    fn grant(intent: &QvaacIntent) -> QvaacAgentCapabilityGrant {
        TestVerifier::signed_grant(QvaacAgentCapabilityGrant {
            network_id: intent.network_id,
            grant_id: [18; 32],
            principal_id: intent.buyer_id,
            agent_id: intent.agent_id,
            agent_key_id: [17; 32],
            intent_digest: intent.digest().unwrap(),
            asset_class: intent.asset_class,
            counterparty_id: intent.seller_id,
            allowed_actions: ACTION_FUND_ESCROW,
            max_per_transaction: 450,
            max_cumulative_spend: 900,
            spent_before: 100,
            not_before: 10,
            expires_at: 300,
            sequence: 1,
            revocation_epoch: 1,
            signature_algorithm: 1,
            signature: Vec::new(),
        })
    }

    pub(super) fn opened() -> (QvaacEscrowCandidate, QvaacIntent, QvaacAssetEvidenceBundle) {
        let bundle = evidence();
        let transaction_intent = intent(&bundle);
        let signed_grant = grant(&transaction_intent);
        let escrow = QvaacEscrowCandidate::open(
            transaction_intent.clone(),
            bundle.clone(),
            signed_grant,
            20,
            &TestVerifier,
            &TestVerifier,
        )
        .unwrap();
        (escrow, transaction_intent, bundle)
    }

    pub(super) fn proof(
        intent: &QvaacIntent,
        bundle: &QvaacAssetEvidenceBundle,
        accepted: bool,
        quantity: u128,
        delivered_at: u64,
        expires_at: u64,
    ) -> QvaacFulfilmentProof {
        TestVerifier::signed_proof(QvaacFulfilmentProof {
            network_id: intent.network_id,
            intent_digest: intent.digest().unwrap(),
            seller_id: intent.seller_id,
            buyer_id: intent.buyer_id,
            evaluator_id: intent.evaluator_id,
            asset_id: intent.asset_id,
            passport_digest: intent.passport_digest,
            evidence_bundle_digest: bundle.digest().unwrap(),
            quantity_delivered: quantity,
            accepted,
            delivered_at,
            expires_at,
            delivery_evidence_digest: [21; 32],
            signature_algorithm: 1,
            signature: Vec::new(),
        })
    }

    #[test]
    fn opens_only_with_active_fresh_qvap_evidence_and_intent_bound_owner_grant() {
        let (escrow, _, _) = opened();
        assert_eq!(escrow.status(), QvaacStatus::AwaitingFunding);
        assert_eq!(escrow.escrow_amount(), 0);
        assert_eq!(escrow.events().len(), 1);
        escrow.verify_event_chain().unwrap();
        assert_ne!(escrow.receipt().unwrap().receipt_digest, [0; 32]);
    }

    #[test]
    fn wrong_asset_evidence_and_wrong_network_are_rejected_before_open() {
        let bundle = evidence();
        let mut transaction_intent = intent(&bundle);
        transaction_intent.asset_id = [99; 32];
        let result = QvaacEscrowCandidate::open(
            transaction_intent.clone(),
            bundle.clone(),
            grant(&transaction_intent),
            20,
            &TestVerifier,
            &TestVerifier,
        );
        assert_eq!(result, Err(QvaacError::WrongEvidence));

        let mut other_network = bundle.clone();
        other_network.network_id = [22; 32];
        let mut other_intent = intent(&other_network);
        other_intent.network_id = [23; 32];
        let result = QvaacEscrowCandidate::open(
            other_intent.clone(),
            other_network,
            grant(&other_intent),
            20,
            &TestVerifier,
            &TestVerifier,
        );
        assert_eq!(result, Err(QvaacError::WrongNetwork));
    }

    #[test]
    fn distinct_issuer_custodian_and_inspector_and_current_passport_are_required() {
        let mut bundle = evidence();
        bundle.inspector_id = bundle.issuer_id;
        bundle.evidence_digest = bundle.digest().unwrap();
        let transaction_intent = intent(&bundle);
        assert_eq!(
            QvaacEscrowCandidate::open(
                transaction_intent.clone(),
                bundle,
                grant(&transaction_intent),
                20,
                &TestVerifier,
                &TestVerifier,
            ),
            Err(QvaacError::IndependentAttestorsRequired)
        );

        let mut stale = evidence();
        stale.observed_status = QvapObservedStatus::EvidenceStale;
        let stale_intent = intent(&stale);
        assert_eq!(
            QvaacEscrowCandidate::open(
                stale_intent.clone(),
                stale,
                grant(&stale_intent),
                20,
                &TestVerifier,
                &TestVerifier,
            ),
            Err(QvaacError::EvidenceNotActive)
        );
    }

    #[test]
    fn grant_must_be_owner_authorized_agent_bound_and_counterparty_scoped() {
        let bundle = evidence();
        let base_intent = intent(&bundle);

        let mut wrong_principal = grant(&base_intent);
        wrong_principal.principal_id = [33; 32];
        wrong_principal = TestVerifier::signed_grant(wrong_principal);
        assert_eq!(
            QvaacEscrowCandidate::open(
                base_intent.clone(),
                bundle.clone(),
                wrong_principal,
                20,
                &TestVerifier,
                &TestVerifier,
            ),
            Err(QvaacError::WrongPrincipal)
        );

        let mut wrong_agent = grant(&base_intent);
        wrong_agent.agent_id = [34; 32];
        wrong_agent = TestVerifier::signed_grant(wrong_agent);
        assert_eq!(
            QvaacEscrowCandidate::open(
                base_intent.clone(),
                bundle.clone(),
                wrong_agent,
                20,
                &TestVerifier,
                &TestVerifier,
            ),
            Err(QvaacError::WrongAgent)
        );

        let mut wrong_seller = grant(&base_intent);
        wrong_seller.counterparty_id = [35; 32];
        wrong_seller = TestVerifier::signed_grant(wrong_seller);
        assert_eq!(
            QvaacEscrowCandidate::open(
                base_intent,
                bundle,
                wrong_seller,
                20,
                &TestVerifier,
                &TestVerifier,
            ),
            Err(QvaacError::WrongCounterparty)
        );
    }

    #[test]
    fn grant_scope_revocation_and_signature_are_checked_by_the_authorization_adapter() {
        let bundle = evidence();
        let transaction_intent = intent(&bundle);

        let mut insufficient = grant(&transaction_intent);
        insufficient.allowed_actions = ACTION_SUBMIT_FULFILMENT;
        insufficient = TestVerifier::signed_grant(insufficient);
        assert_eq!(
            QvaacEscrowCandidate::open(
                transaction_intent.clone(),
                bundle.clone(),
                insufficient,
                20,
                &TestVerifier,
                &TestVerifier,
            ),
            Err(QvaacError::GrantScopeInsufficient)
        );

        let mut revoked = grant(&transaction_intent);
        revoked.revocation_epoch = 2;
        revoked = TestVerifier::signed_grant(revoked);
        assert_eq!(
            QvaacEscrowCandidate::open(
                transaction_intent.clone(),
                bundle.clone(),
                revoked,
                20,
                &TestVerifier,
                &TestVerifier,
            ),
            Err(QvaacError::GrantRevoked)
        );

        let mut bad_signature = grant(&transaction_intent);
        bad_signature.signature[0] ^= 1;
        assert_eq!(
            QvaacEscrowCandidate::open(
                transaction_intent,
                bundle,
                bad_signature,
                20,
                &TestVerifier,
                &TestVerifier,
            ),
            Err(QvaacError::InvalidSignature)
        );
    }

    #[test]
    fn funding_obeys_per_transaction_and_cumulative_owner_spend_limits() {
        let (mut escrow, _, _) = opened();
        assert_eq!(
            escrow.fund_escrow(451, 30, &TestVerifier, &TestVerifier),
            Err(QvaacError::SpendPerTransactionExceeded)
        );
        // Grant has 800 units remaining (900 cap - 100 already spent), while
        // max-per-transaction and intent price cap are both 450.
        escrow
            .fund_escrow(450, 30, &TestVerifier, &TestVerifier)
            .unwrap();
        assert_eq!(escrow.status(), QvaacStatus::Funded);
        assert_eq!(escrow.escrow_amount(), 450);
        assert_eq!(escrow.spent_after(), 550);
        assert_eq!(
            escrow.fund_escrow(1, 31, &TestVerifier, &TestVerifier),
            Err(QvaacError::InvalidStateTransition)
        );
        escrow.verify_event_chain().unwrap();
    }

    #[test]
    fn cumulative_budget_and_verified_asset_quantity_fail_closed() {
        let bundle = evidence();
        let transaction_intent = intent(&bundle);
        let mut low_budget = grant(&transaction_intent);
        low_budget.spent_before = 800;
        low_budget.max_cumulative_spend = 900;
        low_budget = TestVerifier::signed_grant(low_budget);
        let mut escrow = QvaacEscrowCandidate::open(
            transaction_intent.clone(),
            bundle.clone(),
            low_budget,
            20,
            &TestVerifier,
            &TestVerifier,
        )
        .unwrap();
        assert_eq!(
            escrow.fund_escrow(101, 30, &TestVerifier, &TestVerifier),
            Err(QvaacError::CumulativeSpendExceeded)
        );

        let mut low_quantity = bundle.clone();
        low_quantity.verified_transferable_quantity = 10;
        let mut low_quantity_intent = intent(&low_quantity);
        low_quantity_intent.quantity = 20;
        assert_eq!(
            QvaacEscrowCandidate::open(
                low_quantity_intent.clone(),
                low_quantity,
                grant(&low_quantity_intent),
                20,
                &TestVerifier,
                &TestVerifier,
            ),
            Err(QvaacError::InsufficientVerifiedQuantity)
        );
    }

    #[test]
    fn independent_evaluator_acceptance_settles_and_receipt_commits_to_all_inputs() {
        let (mut escrow, transaction_intent, bundle) = opened();
        escrow
            .fund_escrow(400, 30, &TestVerifier, &TestVerifier)
            .unwrap();
        let delivery = proof(&transaction_intent, &bundle, true, 20, 200, 280);
        escrow
            .submit_fulfilment(delivery, 220, &TestVerifier, &TestVerifier)
            .unwrap();
        assert_eq!(escrow.status(), QvaacStatus::Settled);
        assert_eq!(escrow.escrow_amount(), 400);
        let receipt = escrow.receipt().unwrap();
        assert_eq!(receipt.status, QvaacStatus::Settled);
        assert_eq!(receipt.escrow_amount, 400);
        assert_ne!(receipt.fulfilment_digest, [0; 32]);
        escrow.verify_event_chain().unwrap();
        assert_eq!(
            escrow.submit_fulfilment(
                proof(&transaction_intent, &bundle, true, 20, 200, 280),
                221,
                &TestVerifier,
                &TestVerifier
            ),
            Err(QvaacError::InvalidStateTransition)
        );
    }

    #[test]
    fn seller_cannot_be_evaluator_and_proof_must_bind_the_exact_recipient_and_asset() {
        let bundle = evidence();
        let mut self_evaluating_intent = intent(&bundle);
        self_evaluating_intent.evaluator_id = self_evaluating_intent.seller_id;
        assert_eq!(
            self_evaluating_intent.validate(),
            Err(QvaacError::InvalidShape)
        );

        let (mut escrow, transaction_intent, bundle) = opened();
        escrow
            .fund_escrow(300, 30, &TestVerifier, &TestVerifier)
            .unwrap();
        let mut wrong_recipient = proof(&transaction_intent, &bundle, true, 20, 200, 280);
        wrong_recipient.buyer_id = [44; 32];
        wrong_recipient.signature = vec![1];
        let digest = wrong_recipient.signing_digest().unwrap();
        wrong_recipient.signature = TestVerifier::sign(b"fulfilment", &digest);
        assert_eq!(
            escrow.submit_fulfilment(wrong_recipient, 220, &TestVerifier, &TestVerifier),
            Err(QvaacError::WrongCounterparty)
        );
    }

    #[test]
    fn signed_evaluator_rejection_refunds_and_timeout_refunds_after_challenge_window() {
        let (mut rejected, intent_a, bundle_a) = opened();
        rejected
            .fund_escrow(250, 30, &TestVerifier, &TestVerifier)
            .unwrap();
        let rejection = proof(&intent_a, &bundle_a, false, 0, 200, 280);
        rejected
            .submit_fulfilment(rejection, 220, &TestVerifier, &TestVerifier)
            .unwrap();
        assert_eq!(rejected.status(), QvaacStatus::Refunded);
        assert_eq!(
            rejected.events().last().unwrap().kind,
            QvaacEventKind::Refunded
        );

        let (mut timeout, _, _) = opened();
        timeout
            .fund_escrow(250, 30, &TestVerifier, &TestVerifier)
            .unwrap();
        assert_eq!(
            timeout.refund_after_deadline(280),
            Err(QvaacError::FulfilmentExpired)
        );
        timeout.refund_after_deadline(281).unwrap();
        assert_eq!(timeout.status(), QvaacStatus::Refunded);
        timeout.verify_event_chain().unwrap();
    }

    #[test]
    fn expired_or_changed_evidence_cannot_settle_even_with_a_valid_delivery_signature() {
        let bundle = evidence();
        let transaction_intent = intent(&bundle);
        let (mut escrow, _, _) = opened();
        escrow
            .fund_escrow(250, 30, &TestVerifier, &TestVerifier)
            .unwrap();

        // The evidence bundle is immutable in this candidate, so expiry is the
        // relevant invalidation boundary for an already-funded escrow.
        let late_proof = proof(&transaction_intent, &bundle, true, 20, 200, 260);
        assert_eq!(
            escrow.submit_fulfilment(late_proof, 1001, &TestVerifier, &TestVerifier),
            Err(QvaacError::EvidenceExpired)
        );
    }

    #[test]
    fn grant_and_asset_registry_are_rechecked_at_the_moment_of_funding() {
        let (mut grant_revoked, _, _) = opened();
        assert_eq!(
            grant_revoked.fund_escrow(200, 30, &RevokedGrantVerifier, &TestVerifier),
            Err(QvaacError::GrantRevoked)
        );
        assert_eq!(grant_revoked.status(), QvaacStatus::AwaitingFunding);

        let (mut evidence_revoked, _, _) = opened();
        assert_eq!(
            evidence_revoked.fund_escrow(200, 30, &TestVerifier, &RevokedEvidenceVerifier),
            Err(QvaacError::EvidenceNotActive)
        );
        assert_eq!(evidence_revoked.status(), QvaacStatus::AwaitingFunding);
    }

    #[test]
    fn current_asset_registry_is_rechecked_again_before_settlement() {
        let (mut escrow, transaction_intent, bundle) = opened();
        escrow
            .fund_escrow(200, 30, &TestVerifier, &TestVerifier)
            .unwrap();
        let delivery = proof(&transaction_intent, &bundle, true, 20, 200, 280);
        assert_eq!(
            escrow.submit_fulfilment(delivery, 220, &RevokedEvidenceVerifier, &TestVerifier),
            Err(QvaacError::EvidenceNotActive)
        );
        assert_eq!(escrow.status(), QvaacStatus::Funded);
    }

    #[test]
    fn evidence_that_expires_after_open_but_before_funding_cannot_be_escrowed() {
        let mut bundle = evidence();
        bundle.valid_until = 40;
        let transaction_intent = intent(&bundle);
        let mut escrow = QvaacEscrowCandidate::open(
            transaction_intent.clone(),
            bundle.clone(),
            grant(&transaction_intent),
            20,
            &TestVerifier,
            &TestVerifier,
        )
        .unwrap();
        assert_eq!(
            escrow.fund_escrow(200, 50, &TestVerifier, &TestVerifier),
            Err(QvaacError::EvidenceExpired)
        );
        assert_eq!(escrow.status(), QvaacStatus::AwaitingFunding);
    }
}

#[cfg(test)]
mod role_and_time_regression_tests {
    use super::tests::{opened, proof, TestVerifier};
    use super::*;

    #[test]
    fn buyer_seller_agent_and_evaluator_are_distinct_principals() {
        let mut escrow_intent = super::tests::intent(&super::tests::evidence());
        escrow_intent.agent_id = escrow_intent.buyer_id;
        assert_eq!(escrow_intent.validate(), Err(QvaacError::InvalidShape));

        let mut escrow_intent = super::tests::intent(&super::tests::evidence());
        escrow_intent.agent_id = escrow_intent.seller_id;
        assert_eq!(escrow_intent.validate(), Err(QvaacError::InvalidShape));

        let mut escrow_intent = super::tests::intent(&super::tests::evidence());
        escrow_intent.agent_id = escrow_intent.evaluator_id;
        assert_eq!(escrow_intent.validate(), Err(QvaacError::InvalidShape));
    }

    #[test]
    fn evaluator_cannot_attest_delivery_before_the_claimed_delivery_time() {
        let (mut escrow, intent, bundle) = opened();
        escrow
            .fund_escrow(200, 30, &TestVerifier, &TestVerifier)
            .unwrap();
        let future_delivery = proof(&intent, &bundle, true, 20, 230, 280);
        assert_eq!(
            escrow.submit_fulfilment(future_delivery, 220, &TestVerifier, &TestVerifier),
            Err(QvaacError::FulfilmentNotYetDelivered)
        );
        assert_eq!(escrow.status(), QvaacStatus::Funded);
    }
}
