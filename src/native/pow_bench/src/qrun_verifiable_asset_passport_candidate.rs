//! Offline QRun Verifiable Asset Passport (QVAP) state-machine candidate.
//!
//! This module is an isolated research/test candidate. It is not wired into TXN2,
//! LedgerState, QFP5, canonical consensus, the production node, or any live RWA service.
//! The verifier is injected by the caller; tests use a deliberately non-cryptographic
//! fixture verifier and MUST NOT be copied into production.
//!
//! QVAP binds an on-chain asset identity to signed claims about off-chain rights, custody,
//! quantity and inspection. Cryptographic verification proves which key signed a claim;
//! it does not prove that the underlying physical/legal claim is true.

use crate::token_forge::{AssetId, NetworkId};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub const QVAP_MAGIC: [u8; 4] = *b"QVP1";
pub const QVAP_VERSION: u16 = 1;
pub const QVAP_DEFINITION_BYTES: usize = 266;
pub const QVAP_MAX_SIGNATURE_BYTES: usize = 4096;
pub const QVAP_MAX_EVENTS: usize = 4096;

const DEFINITION_DOMAIN: &[u8] = b"QRUN-QVAP-DEFINITION-V1\0";
const ATTESTATION_DOMAIN: &[u8] = b"QRUN-QVAP-ATTESTATION-V1\0";
const EVENT_DOMAIN: &[u8] = b"QRUN-QVAP-EVENT-V1\0";

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

fn put_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn put_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn put_u128(out: &mut Vec<u8>, value: u128) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn array<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N], QvapError> {
    let end = offset
        .checked_add(N)
        .ok_or(QvapError::MalformedDefinition)?;
    bytes
        .get(offset..end)
        .ok_or(QvapError::MalformedDefinition)?
        .try_into()
        .map_err(|_| QvapError::MalformedDefinition)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QvapError {
    InvalidDefinition,
    MalformedDefinition,
    UnsupportedVersion(u16),
    InvalidAttestation,
    WrongNetworkOrAsset,
    WrongIssuerIdentity,
    WrongRoleForClaim,
    DuplicateSignerAcrossRoles,
    InvalidAttestationSequence,
    AttestationNotYetValid,
    AttestationExpired,
    InvalidSignature,
    MissingRequiredEvidence,
    InvalidStateTransition,
    ZeroAmount,
    QuantityOverflow,
    SupplyCapExceeded { requested: u128, allowed: u128 },
    InsufficientOutstandingSupply,
    RedemptionExceedsApproval,
    TooManyEvents,
    EventChainInvalid,
}

impl std::fmt::Display for QvapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for QvapError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QvapDefinition {
    pub network_id: NetworkId,
    pub asset_id: AssetId,
    pub issuer_id: [u8; 32],
    pub issuer_key_id: [u8; 32],
    pub asset_class: u16,
    pub external_reference_commitment: [u8; 32],
    pub rights_commitment: [u8; 32],
    pub policy_profile_id: [u8; 32],
    pub max_supply: u128,
    /// Number of token base units represented by one verified asset unit.
    pub representation_numerator: u64,
    /// Denominator for representation_numerator.
    pub representation_denominator: u64,
}

impl QvapDefinition {
    pub fn validate(&self) -> Result<(), QvapError> {
        if is_zero(&self.network_id)
            || is_zero(&self.asset_id)
            || is_zero(&self.issuer_id)
            || is_zero(&self.issuer_key_id)
            || self.asset_class == 0
            || is_zero(&self.external_reference_commitment)
            || is_zero(&self.rights_commitment)
            || is_zero(&self.policy_profile_id)
            || self.max_supply == 0
            || self.representation_numerator == 0
            || self.representation_denominator == 0
        {
            return Err(QvapError::InvalidDefinition);
        }
        Ok(())
    }

    /// Canonical fixed-width QVP1 definition encoding (266 bytes, big-endian integers).
    pub fn encode(&self) -> Result<[u8; QVAP_DEFINITION_BYTES], QvapError> {
        self.validate()?;
        let mut out = Vec::with_capacity(QVAP_DEFINITION_BYTES);
        out.extend_from_slice(&QVAP_MAGIC);
        put_u16(&mut out, QVAP_VERSION);
        put_u16(&mut out, 0);
        out.extend_from_slice(&self.network_id);
        out.extend_from_slice(&self.asset_id);
        out.extend_from_slice(&self.issuer_id);
        out.extend_from_slice(&self.issuer_key_id);
        put_u16(&mut out, self.asset_class);
        out.extend_from_slice(&self.external_reference_commitment);
        out.extend_from_slice(&self.rights_commitment);
        out.extend_from_slice(&self.policy_profile_id);
        put_u128(&mut out, self.max_supply);
        put_u64(&mut out, self.representation_numerator);
        put_u64(&mut out, self.representation_denominator);
        out.try_into().map_err(|_| QvapError::MalformedDefinition)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, QvapError> {
        if bytes.len() != QVAP_DEFINITION_BYTES || bytes.get(..4) != Some(&QVAP_MAGIC) {
            return Err(QvapError::MalformedDefinition);
        }
        let version = u16::from_be_bytes(array(bytes, 4)?);
        if version != QVAP_VERSION {
            return Err(QvapError::UnsupportedVersion(version));
        }
        if array::<2>(bytes, 6)? != [0, 0] {
            return Err(QvapError::MalformedDefinition);
        }
        let value = Self {
            network_id: array(bytes, 8)?,
            asset_id: array(bytes, 40)?,
            issuer_id: array(bytes, 72)?,
            issuer_key_id: array(bytes, 104)?,
            asset_class: u16::from_be_bytes(array(bytes, 136)?),
            external_reference_commitment: array(bytes, 138)?,
            rights_commitment: array(bytes, 170)?,
            policy_profile_id: array(bytes, 202)?,
            max_supply: u128::from_be_bytes(array(bytes, 234)?),
            representation_numerator: u64::from_be_bytes(array(bytes, 250)?),
            representation_denominator: u64::from_be_bytes(array(bytes, 258)?),
        };
        value.validate()?;
        Ok(value)
    }

    pub fn digest(&self) -> Result<[u8; 32], QvapError> {
        let encoded = self.encode()?;
        Ok(hash_parts(&[DEFINITION_DOMAIN, &encoded]))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum QvapRole {
    Issuer = 1,
    Custodian = 2,
    Inspector = 3,
    Registrar = 4,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum QvapClaimKind {
    Rights = 1,
    CustodyQuantity = 2,
    Inspection = 3,
    Encumbrance = 4,
    EncumbranceRelease = 5,
    RedemptionApproval = 6,
    Revocation = 7,
}

impl QvapClaimKind {
    fn required_role(self) -> QvapRole {
        match self {
            Self::Rights => QvapRole::Issuer,
            Self::CustodyQuantity => QvapRole::Custodian,
            Self::Inspection => QvapRole::Inspector,
            Self::Encumbrance
            | Self::EncumbranceRelease
            | Self::RedemptionApproval
            | Self::Revocation => QvapRole::Registrar,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QvapAttestation {
    pub network_id: NetworkId,
    pub asset_id: AssetId,
    pub role: QvapRole,
    pub claim_kind: QvapClaimKind,
    pub attestor_id: [u8; 32],
    pub key_id: [u8; 32],
    pub sequence: u64,
    pub issued_at: u64,
    pub expires_at: u64,
    /// Set only for custody quantity and redemption approval claims.
    pub quantity_units: u128,
    /// Must equal the passport's canonical commitment to the external asset reference.
    pub external_reference_commitment: [u8; 32],
    pub claim_commitment: [u8; 32],
    pub evidence_hash: [u8; 32],
    /// Versioned algorithm identifier, interpreted by the injected verifier.
    pub signature_algorithm: u16,
    pub signature: Vec<u8>,
}

impl QvapAttestation {
    fn validate_fields(&self) -> Result<(), QvapError> {
        if is_zero(&self.network_id)
            || is_zero(&self.asset_id)
            || is_zero(&self.attestor_id)
            || is_zero(&self.key_id)
            || self.sequence == 0
            || self.issued_at >= self.expires_at
            || is_zero(&self.external_reference_commitment)
            || is_zero(&self.claim_commitment)
            || is_zero(&self.evidence_hash)
            || self.signature_algorithm == 0
            || self.role != self.claim_kind.required_role()
        {
            return Err(QvapError::InvalidAttestation);
        }
        match self.claim_kind {
            QvapClaimKind::CustodyQuantity | QvapClaimKind::RedemptionApproval
                if self.quantity_units == 0 =>
            {
                return Err(QvapError::InvalidAttestation);
            }
            QvapClaimKind::CustodyQuantity | QvapClaimKind::RedemptionApproval => {}
            _ if self.quantity_units != 0 => return Err(QvapError::InvalidAttestation),
            _ => {}
        }
        Ok(())
    }

    pub fn validate_shape(&self) -> Result<(), QvapError> {
        self.validate_fields()?;
        if self.signature.is_empty() || self.signature.len() > QVAP_MAX_SIGNATURE_BYTES {
            return Err(QvapError::InvalidAttestation);
        }
        Ok(())
    }

    /// Hash of every signed field except the signature itself.
    pub fn signing_digest(&self) -> Result<[u8; 32], QvapError> {
        self.validate_fields()?;
        Ok(hash_parts(&[
            ATTESTATION_DOMAIN,
            &self.network_id,
            &self.asset_id,
            &[self.role as u8],
            &[self.claim_kind as u8],
            &self.attestor_id,
            &self.key_id,
            &self.sequence.to_be_bytes(),
            &self.issued_at.to_be_bytes(),
            &self.expires_at.to_be_bytes(),
            &self.quantity_units.to_be_bytes(),
            &self.external_reference_commitment,
            &self.claim_commitment,
            &self.evidence_hash,
            &self.signature_algorithm.to_be_bytes(),
        ]))
    }
}

/// Inject a production verifier (for example, a reviewed ML-DSA implementation).
/// The state machine deliberately does not select a cryptographic algorithm itself.
pub trait QvapAttestationVerifier {
    fn verify(
        &self,
        attestor_id: &[u8; 32],
        role: QvapRole,
        key_id: &[u8; 32],
        signature_algorithm: u16,
        message_digest: &[u8; 32],
        signature: &[u8],
    ) -> Result<(), QvapError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QvapStatus {
    Draft,
    Active,
    Encumbered,
    Suspended,
    Disputed,
    Revoked,
    Redeemed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum QvapObservedStatus {
    Draft = 0,
    Active = 1,
    Encumbered = 2,
    Suspended = 3,
    Disputed = 4,
    Revoked = 5,
    Redeemed = 6,
    EvidenceStale = 7,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum QvapEventKind {
    Created = 1,
    AttestationAccepted = 2,
    Activated = 3,
    Issued = 4,
    Encumbered = 5,
    EncumbranceReleased = 6,
    Redeemed = 7,
    Revoked = 8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QvapEvent {
    pub sequence: u64,
    pub timestamp: u64,
    pub kind: QvapEventKind,
    pub amount: u128,
    /// Attestation/approval digest authorizing this event, or zero when not applicable.
    pub subject_digest: [u8; 32],
    pub previous_digest: [u8; 32],
    pub digest: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QvapPassport {
    definition: QvapDefinition,
    status: QvapStatus,
    attestations: BTreeMap<QvapClaimKind, QvapAttestation>,
    /// Durable within this passport's history: rotating a claim never erases signer-role history.
    signer_roles: BTreeMap<[u8; 32], QvapRole>,
    /// A signing key ID remains bound to one attestor identity for the passport lifetime.
    key_owners: BTreeMap<[u8; 32], [u8; 32]>,
    total_issued: u128,
    total_redeemed: u128,
    /// Amount consumed from the latest signed redemption approval sequence.
    redemption_consumed: u128,
    /// Current lien/encumbrance commitment that a release must reference exactly.
    active_encumbrance_commitment: Option<[u8; 32]>,
    events: Vec<QvapEvent>,
}

impl QvapPassport {
    pub fn new(definition: QvapDefinition, created_at: u64) -> Result<Self, QvapError> {
        definition.validate()?;
        let mut passport = Self {
            definition,
            status: QvapStatus::Draft,
            attestations: BTreeMap::new(),
            signer_roles: BTreeMap::new(),
            key_owners: BTreeMap::new(),
            total_issued: 0,
            total_redeemed: 0,
            redemption_consumed: 0,
            active_encumbrance_commitment: None,
            events: Vec::new(),
        };
        passport.append_event(QvapEventKind::Created, created_at, 0, [0; 32])?;
        Ok(passport)
    }

    pub fn definition(&self) -> &QvapDefinition {
        &self.definition
    }

    pub fn status(&self) -> QvapStatus {
        self.status
    }

    pub fn total_issued(&self) -> u128 {
        self.total_issued
    }

    pub fn total_redeemed(&self) -> u128 {
        self.total_redeemed
    }

    pub fn outstanding_supply(&self) -> Result<u128, QvapError> {
        self.total_issued
            .checked_sub(self.total_redeemed)
            .ok_or(QvapError::QuantityOverflow)
    }

    pub fn events(&self) -> &[QvapEvent] {
        &self.events
    }

    pub fn event_tip(&self) -> [u8; 32] {
        self.events.last().map_or([0; 32], |event| event.digest)
    }

    pub fn record_attestation<V: QvapAttestationVerifier>(
        &mut self,
        attestation: QvapAttestation,
        now: u64,
        verifier: &V,
    ) -> Result<(), QvapError> {
        attestation.validate_shape()?;
        if matches!(self.status, QvapStatus::Revoked | QvapStatus::Redeemed) {
            return Err(QvapError::InvalidStateTransition);
        }
        if attestation.network_id != self.definition.network_id
            || attestation.asset_id != self.definition.asset_id
            || attestation.external_reference_commitment
                != self.definition.external_reference_commitment
        {
            return Err(QvapError::WrongNetworkOrAsset);
        }
        if attestation.claim_kind == QvapClaimKind::Rights
            && attestation.claim_commitment != self.definition.rights_commitment
        {
            return Err(QvapError::InvalidAttestation);
        }
        if attestation.issued_at > now {
            return Err(QvapError::AttestationNotYetValid);
        }
        if attestation.expires_at <= now {
            return Err(QvapError::AttestationExpired);
        }
        if attestation.role == QvapRole::Issuer
            && (attestation.attestor_id != self.definition.issuer_id
                || attestation.key_id != self.definition.issuer_key_id)
        {
            return Err(QvapError::WrongIssuerIdentity);
        }

        let expected_sequence = self
            .attestations
            .get(&attestation.claim_kind)
            .map_or(Some(1), |current| current.sequence.checked_add(1))
            .ok_or(QvapError::InvalidAttestationSequence)?;
        if attestation.sequence != expected_sequence {
            return Err(QvapError::InvalidAttestationSequence);
        }

        if self
            .signer_roles
            .get(&attestation.attestor_id)
            .is_some_and(|existing_role| *existing_role != attestation.role)
            || self
                .key_owners
                .get(&attestation.key_id)
                .is_some_and(|owner| *owner != attestation.attestor_id)
        {
            return Err(QvapError::DuplicateSignerAcrossRoles);
        }

        let digest = attestation.signing_digest()?;
        verifier.verify(
            &attestation.attestor_id,
            attestation.role,
            &attestation.key_id,
            attestation.signature_algorithm,
            &digest,
            &attestation.signature,
        )?;

        if attestation.claim_kind == QvapClaimKind::CustodyQuantity {
            let proposed_cap = attestation
                .quantity_units
                .checked_mul(u128::from(self.definition.representation_numerator))
                .ok_or(QvapError::QuantityOverflow)?
                / u128::from(self.definition.representation_denominator);
            let proposed_cap = proposed_cap.min(self.definition.max_supply);
            if self.total_issued > proposed_cap {
                return Err(QvapError::SupplyCapExceeded {
                    requested: self.total_issued,
                    allowed: proposed_cap,
                });
            }
        }

        self.append_event(QvapEventKind::AttestationAccepted, now, 0, digest)?;
        self.signer_roles
            .entry(attestation.attestor_id)
            .or_insert(attestation.role);
        self.key_owners
            .entry(attestation.key_id)
            .or_insert(attestation.attestor_id);
        if attestation.claim_kind == QvapClaimKind::RedemptionApproval {
            // Each new registrar approval creates a fresh, explicit redemption quota.
            self.redemption_consumed = 0;
        }
        self.attestations
            .insert(attestation.claim_kind, attestation);
        Ok(())
    }

    pub fn activate(&mut self, now: u64) -> Result<(), QvapError> {
        if self.status != QvapStatus::Draft {
            return Err(QvapError::InvalidStateTransition);
        }
        self.require_core_evidence(now)?;
        let evidence_digest = self.core_evidence_digest(now)?;
        self.append_event(QvapEventKind::Activated, now, 0, evidence_digest)?;
        self.status = QvapStatus::Active;
        Ok(())
    }

    pub fn issue(&mut self, amount: u128, now: u64) -> Result<(), QvapError> {
        if amount == 0 {
            return Err(QvapError::ZeroAmount);
        }
        if self.status != QvapStatus::Active {
            return Err(QvapError::InvalidStateTransition);
        }
        self.require_core_evidence(now)?;
        let requested = self
            .total_issued
            .checked_add(amount)
            .ok_or(QvapError::QuantityOverflow)?;
        let allowed = self.maximum_issuable_supply(now)?;
        if requested > allowed {
            return Err(QvapError::SupplyCapExceeded { requested, allowed });
        }
        let evidence_digest = self.core_evidence_digest(now)?;
        self.append_event(QvapEventKind::Issued, now, amount, evidence_digest)?;
        self.total_issued = requested;
        Ok(())
    }

    pub fn encumber(&mut self, now: u64) -> Result<(), QvapError> {
        if self.status != QvapStatus::Active {
            return Err(QvapError::InvalidStateTransition);
        }
        let attestation = self
            .attestations
            .get(&QvapClaimKind::Encumbrance)
            .filter(|value| value.issued_at <= now && value.expires_at > now)
            .ok_or(QvapError::MissingRequiredEvidence)?;
        let subject_digest = attestation.signing_digest()?;
        let commitment = attestation.claim_commitment;
        self.append_event(QvapEventKind::Encumbered, now, 0, subject_digest)?;
        self.active_encumbrance_commitment = Some(commitment);
        self.status = QvapStatus::Encumbered;
        Ok(())
    }

    pub fn release_encumbrance(&mut self, now: u64) -> Result<(), QvapError> {
        if self.status != QvapStatus::Encumbered {
            return Err(QvapError::InvalidStateTransition);
        }
        self.require_core_evidence(now)?;
        let release = self
            .attestations
            .get(&QvapClaimKind::EncumbranceRelease)
            .filter(|value| value.issued_at <= now && value.expires_at > now)
            .ok_or(QvapError::MissingRequiredEvidence)?;
        if Some(release.claim_commitment) != self.active_encumbrance_commitment {
            return Err(QvapError::InvalidStateTransition);
        }
        let subject_digest = release.signing_digest()?;
        self.append_event(QvapEventKind::EncumbranceReleased, now, 0, subject_digest)?;
        self.active_encumbrance_commitment = None;
        self.status = QvapStatus::Active;
        Ok(())
    }

    pub fn revoke(&mut self, now: u64) -> Result<(), QvapError> {
        if matches!(self.status, QvapStatus::Revoked | QvapStatus::Redeemed) {
            return Err(QvapError::InvalidStateTransition);
        }
        let attestation = self
            .attestations
            .get(&QvapClaimKind::Revocation)
            .filter(|value| value.issued_at <= now && value.expires_at > now)
            .ok_or(QvapError::MissingRequiredEvidence)?;
        let subject_digest = attestation.signing_digest()?;
        self.append_event(QvapEventKind::Revoked, now, 0, subject_digest)?;
        self.status = QvapStatus::Revoked;
        Ok(())
    }

    pub fn redeem(&mut self, amount: u128, now: u64) -> Result<(), QvapError> {
        if amount == 0 {
            return Err(QvapError::ZeroAmount);
        }
        if self.status != QvapStatus::Active {
            return Err(QvapError::InvalidStateTransition);
        }
        self.require_core_evidence(now)?;
        let approval = self
            .attestations
            .get(&QvapClaimKind::RedemptionApproval)
            .filter(|value| value.issued_at <= now && value.expires_at > now)
            .ok_or(QvapError::MissingRequiredEvidence)?;
        let approval_quantity = approval.quantity_units;
        let approval_digest = approval.signing_digest()?;
        let approval_consumed = self
            .redemption_consumed
            .checked_add(amount)
            .ok_or(QvapError::QuantityOverflow)?;
        if approval_consumed > approval_quantity {
            return Err(QvapError::RedemptionExceedsApproval);
        }
        let outstanding = self.outstanding_supply()?;
        if amount > outstanding {
            return Err(QvapError::InsufficientOutstandingSupply);
        }
        let redeemed = self
            .total_redeemed
            .checked_add(amount)
            .ok_or(QvapError::QuantityOverflow)?;
        self.append_event(QvapEventKind::Redeemed, now, amount, approval_digest)?;
        self.redemption_consumed = approval_consumed;
        self.total_redeemed = redeemed;
        if redeemed == self.total_issued && self.total_issued != 0 {
            self.status = QvapStatus::Redeemed;
        }
        Ok(())
    }

    pub fn observed_status(&self, now: u64) -> QvapObservedStatus {
        if matches!(self.status, QvapStatus::Active | QvapStatus::Encumbered)
            && !self.core_evidence_is_fresh(now)
        {
            return QvapObservedStatus::EvidenceStale;
        }
        match self.status {
            QvapStatus::Draft => QvapObservedStatus::Draft,
            QvapStatus::Active => QvapObservedStatus::Active,
            QvapStatus::Encumbered => QvapObservedStatus::Encumbered,
            QvapStatus::Suspended => QvapObservedStatus::Suspended,
            QvapStatus::Disputed => QvapObservedStatus::Disputed,
            QvapStatus::Revoked => QvapObservedStatus::Revoked,
            QvapStatus::Redeemed => QvapObservedStatus::Redeemed,
        }
    }

    pub fn maximum_issuable_supply(&self, now: u64) -> Result<u128, QvapError> {
        self.require_core_evidence(now)?;
        let custody = self
            .attestations
            .get(&QvapClaimKind::CustodyQuantity)
            .ok_or(QvapError::MissingRequiredEvidence)?;
        let represented = custody
            .quantity_units
            .checked_mul(u128::from(self.definition.representation_numerator))
            .ok_or(QvapError::QuantityOverflow)?
            / u128::from(self.definition.representation_denominator);
        Ok(represented.min(self.definition.max_supply))
    }

    pub fn verify_event_chain(&self) -> Result<(), QvapError> {
        if self.events.is_empty() || self.events.len() > QVAP_MAX_EVENTS {
            return Err(QvapError::EventChainInvalid);
        }
        let definition_digest = self.definition.digest()?;
        let mut previous = [0u8; 32];
        for (index, event) in self.events.iter().enumerate() {
            let expected_sequence = u64::try_from(index)
                .ok()
                .and_then(|value| value.checked_add(1))
                .ok_or(QvapError::EventChainInvalid)?;
            if event.sequence != expected_sequence || event.previous_digest != previous {
                return Err(QvapError::EventChainInvalid);
            }
            let digest = Self::event_digest(
                &definition_digest,
                event.sequence,
                event.timestamp,
                event.kind,
                event.amount,
                &event.subject_digest,
                &event.previous_digest,
            );
            if digest != event.digest {
                return Err(QvapError::EventChainInvalid);
            }
            previous = event.digest;
        }
        Ok(())
    }

    fn require_core_evidence(&self, now: u64) -> Result<(), QvapError> {
        for kind in [
            QvapClaimKind::Rights,
            QvapClaimKind::CustodyQuantity,
            QvapClaimKind::Inspection,
        ] {
            if !self.claim_is_fresh(kind, now) {
                return Err(QvapError::MissingRequiredEvidence);
            }
        }
        let rights = self.attestations.get(&QvapClaimKind::Rights).unwrap();
        if rights.claim_commitment != self.definition.rights_commitment
            || rights.external_reference_commitment != self.definition.external_reference_commitment
        {
            return Err(QvapError::MissingRequiredEvidence);
        }
        let custody = self
            .attestations
            .get(&QvapClaimKind::CustodyQuantity)
            .unwrap();
        let inspection = self.attestations.get(&QvapClaimKind::Inspection).unwrap();
        if rights.key_id == custody.key_id
            || rights.key_id == inspection.key_id
            || custody.key_id == inspection.key_id
            || rights.attestor_id == custody.attestor_id
            || rights.attestor_id == inspection.attestor_id
            || custody.attestor_id == inspection.attestor_id
        {
            return Err(QvapError::DuplicateSignerAcrossRoles);
        }
        Ok(())
    }

    fn core_evidence_digest(&self, now: u64) -> Result<[u8; 32], QvapError> {
        self.require_core_evidence(now)?;
        let rights = self.attestations.get(&QvapClaimKind::Rights).unwrap();
        let custody = self
            .attestations
            .get(&QvapClaimKind::CustodyQuantity)
            .unwrap();
        let inspection = self.attestations.get(&QvapClaimKind::Inspection).unwrap();
        let rights_digest = rights.signing_digest()?;
        let custody_digest = custody.signing_digest()?;
        let inspection_digest = inspection.signing_digest()?;
        Ok(hash_parts(&[
            b"QRUN-QVAP-CORE-EVIDENCE-SET-V1\0",
            &rights_digest,
            &custody_digest,
            &inspection_digest,
        ]))
    }

    fn core_evidence_is_fresh(&self, now: u64) -> bool {
        self.require_core_evidence(now).is_ok()
    }

    fn claim_is_fresh(&self, kind: QvapClaimKind, now: u64) -> bool {
        self.attestations
            .get(&kind)
            .is_some_and(|value| value.issued_at <= now && value.expires_at > now)
    }

    fn append_event(
        &mut self,
        kind: QvapEventKind,
        timestamp: u64,
        amount: u128,
        subject_digest: [u8; 32],
    ) -> Result<(), QvapError> {
        if self.events.len() >= QVAP_MAX_EVENTS {
            return Err(QvapError::TooManyEvents);
        }
        let sequence = u64::try_from(self.events.len())
            .ok()
            .and_then(|value| value.checked_add(1))
            .ok_or(QvapError::TooManyEvents)?;
        let previous_digest = self.event_tip();
        let definition_digest = self.definition.digest()?;
        let digest = Self::event_digest(
            &definition_digest,
            sequence,
            timestamp,
            kind,
            amount,
            &subject_digest,
            &previous_digest,
        );
        self.events.push(QvapEvent {
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
        definition_digest: &[u8; 32],
        sequence: u64,
        timestamp: u64,
        kind: QvapEventKind,
        amount: u128,
        subject_digest: &[u8; 32],
        previous_digest: &[u8; 32],
    ) -> [u8; 32] {
        hash_parts(&[
            EVENT_DOMAIN,
            definition_digest,
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

    pub(super) struct TestOnlyVerifier;

    impl TestOnlyVerifier {
        pub(super) fn sign(key_id: &[u8; 32], algorithm: u16, digest: &[u8; 32]) -> Vec<u8> {
            hash_parts(&[
                b"QVAP-TEST-ONLY-NOT-CRYPTOGRAPHIC\0",
                key_id,
                &algorithm.to_be_bytes(),
                digest,
            ])
            .to_vec()
        }
    }

    impl QvapAttestationVerifier for TestOnlyVerifier {
        fn verify(
            &self,
            attestor_id: &[u8; 32],
            _role: QvapRole,
            key_id: &[u8; 32],
            signature_algorithm: u16,
            message_digest: &[u8; 32],
            signature: &[u8],
        ) -> Result<(), QvapError> {
            if is_zero(attestor_id) {
                return Err(QvapError::InvalidSignature);
            }
            if signature == Self::sign(key_id, signature_algorithm, message_digest) {
                Ok(())
            } else {
                Err(QvapError::InvalidSignature)
            }
        }
    }

    pub(super) fn definition() -> QvapDefinition {
        QvapDefinition {
            network_id: [1; 32],
            asset_id: [2; 32],
            issuer_id: [3; 32],
            issuer_key_id: [4; 32],
            asset_class: 1,
            external_reference_commitment: [5; 32],
            rights_commitment: [6; 32],
            policy_profile_id: [7; 32],
            max_supply: 500,
            representation_numerator: 10,
            representation_denominator: 1,
        }
    }

    pub(super) fn attestation(
        definition: &QvapDefinition,
        role: QvapRole,
        claim_kind: QvapClaimKind,
        attestor_id: [u8; 32],
        key_id: [u8; 32],
        sequence: u64,
        issued_at: u64,
        expires_at: u64,
        quantity_units: u128,
    ) -> QvapAttestation {
        let mut value = QvapAttestation {
            network_id: definition.network_id,
            asset_id: definition.asset_id,
            role,
            claim_kind,
            attestor_id,
            key_id,
            sequence,
            issued_at,
            expires_at,
            quantity_units,
            external_reference_commitment: definition.external_reference_commitment,
            claim_commitment: if claim_kind == QvapClaimKind::Rights {
                definition.rights_commitment
            } else {
                [0x31; 32]
            },
            evidence_hash: [0x42; 32],
            signature_algorithm: 1,
            signature: Vec::new(),
        };
        let digest = value.signing_digest().unwrap();
        value.signature = TestOnlyVerifier::sign(&value.key_id, value.signature_algorithm, &digest);
        value
    }

    pub(super) fn add_core_evidence(passport: &mut QvapPassport, now: u64, expiry: u64) {
        let definition = passport.definition().clone();
        let verifier = TestOnlyVerifier;
        let rights = attestation(
            &definition,
            QvapRole::Issuer,
            QvapClaimKind::Rights,
            definition.issuer_id,
            definition.issuer_key_id,
            1,
            now.saturating_sub(1),
            expiry,
            0,
        );
        passport.record_attestation(rights, now, &verifier).unwrap();

        let custody = attestation(
            &definition,
            QvapRole::Custodian,
            QvapClaimKind::CustodyQuantity,
            [8; 32],
            [9; 32],
            1,
            now.saturating_sub(1),
            expiry,
            10,
        );
        passport
            .record_attestation(custody, now, &verifier)
            .unwrap();

        let inspection = attestation(
            &definition,
            QvapRole::Inspector,
            QvapClaimKind::Inspection,
            [10; 32],
            [11; 32],
            1,
            now.saturating_sub(1),
            expiry,
            0,
        );
        passport
            .record_attestation(inspection, now, &verifier)
            .unwrap();
    }

    #[test]
    fn definition_codec_is_fixed_width_canonical_and_domain_bound() {
        let definition = definition();
        let encoded = definition.encode().unwrap();
        assert_eq!(encoded.len(), QVAP_DEFINITION_BYTES);
        assert_eq!(QvapDefinition::decode(&encoded).unwrap(), definition);

        let mut reserved = encoded;
        reserved[7] = 1;
        assert_eq!(
            QvapDefinition::decode(&reserved),
            Err(QvapError::MalformedDefinition)
        );

        let mut wrong_version = encoded;
        wrong_version[5] = 2;
        assert_eq!(
            QvapDefinition::decode(&wrong_version),
            Err(QvapError::UnsupportedVersion(2))
        );

        let mut other_network = definition.clone();
        other_network.network_id = [12; 32];
        assert_ne!(
            definition.digest().unwrap(),
            other_network.digest().unwrap()
        );
    }

    #[test]
    fn activation_requires_three_current_independent_attestor_roles() {
        let definition = definition();
        let mut passport = QvapPassport::new(definition, 1).unwrap();
        let verifier = TestOnlyVerifier;
        let def = passport.definition().clone();

        let rights = attestation(
            &def,
            QvapRole::Issuer,
            QvapClaimKind::Rights,
            def.issuer_id,
            def.issuer_key_id,
            1,
            10,
            100,
            0,
        );
        passport.record_attestation(rights, 20, &verifier).unwrap();

        let custody = attestation(
            &def,
            QvapRole::Custodian,
            QvapClaimKind::CustodyQuantity,
            [8; 32],
            [9; 32],
            1,
            10,
            100,
            10,
        );
        passport.record_attestation(custody, 20, &verifier).unwrap();

        assert_eq!(
            passport.activate(20),
            Err(QvapError::MissingRequiredEvidence)
        );

        let inspection = attestation(
            &def,
            QvapRole::Inspector,
            QvapClaimKind::Inspection,
            [10; 32],
            [11; 32],
            1,
            10,
            100,
            0,
        );
        passport
            .record_attestation(inspection, 20, &verifier)
            .unwrap();
        passport.activate(20).unwrap();
        assert_eq!(passport.status(), QvapStatus::Active);
    }

    #[test]
    fn one_key_cannot_claim_both_issuer_and_custodian_roles() {
        let def = definition();
        let mut passport = QvapPassport::new(def.clone(), 1).unwrap();
        let verifier = TestOnlyVerifier;

        let rights = attestation(
            &def,
            QvapRole::Issuer,
            QvapClaimKind::Rights,
            def.issuer_id,
            def.issuer_key_id,
            1,
            10,
            100,
            0,
        );
        passport.record_attestation(rights, 20, &verifier).unwrap();

        let forged_custody_role = attestation(
            &def,
            QvapRole::Custodian,
            QvapClaimKind::CustodyQuantity,
            [8; 32],
            def.issuer_key_id,
            1,
            10,
            100,
            10,
        );
        assert_eq!(
            passport.record_attestation(forged_custody_role, 20, &verifier),
            Err(QvapError::DuplicateSignerAcrossRoles)
        );
    }

    #[test]
    fn custody_quantity_caps_cumulative_issuance_and_redemption_does_not_reopen_cap() {
        let def = definition();
        let mut passport = QvapPassport::new(def.clone(), 1).unwrap();
        add_core_evidence(&mut passport, 20, 100);
        passport.activate(20).unwrap();

        assert_eq!(passport.maximum_issuable_supply(20).unwrap(), 100);
        passport.issue(100, 20).unwrap();
        assert_eq!(passport.total_issued(), 100);
        assert_eq!(
            passport.issue(1, 20),
            Err(QvapError::SupplyCapExceeded {
                requested: 101,
                allowed: 100
            })
        );

        let approval = attestation(
            &def,
            QvapRole::Registrar,
            QvapClaimKind::RedemptionApproval,
            [12; 32],
            [13; 32],
            1,
            10,
            100,
            50,
        );
        passport
            .record_attestation(approval, 20, &TestOnlyVerifier)
            .unwrap();
        assert_eq!(
            passport.redeem(51, 20),
            Err(QvapError::RedemptionExceedsApproval)
        );
        passport.redeem(50, 20).unwrap();
        assert_eq!(
            passport.redeem(1, 20),
            Err(QvapError::RedemptionExceedsApproval)
        );
        assert_eq!(passport.outstanding_supply().unwrap(), 50);
        assert_eq!(passport.total_issued(), 100);

        assert_eq!(
            passport.issue(1, 20),
            Err(QvapError::SupplyCapExceeded {
                requested: 101,
                allowed: 100
            })
        );
    }

    #[test]
    fn expired_core_evidence_marks_status_stale_and_blocks_new_issuance() {
        let mut passport = QvapPassport::new(definition(), 1).unwrap();
        add_core_evidence(&mut passport, 20, 50);
        passport.activate(20).unwrap();

        assert_eq!(
            passport.observed_status(51),
            QvapObservedStatus::EvidenceStale
        );
        assert_eq!(
            passport.issue(1, 51),
            Err(QvapError::MissingRequiredEvidence)
        );
    }

    #[test]
    fn encumbrance_and_release_require_separately_signed_registrar_evidence() {
        let def = definition();
        let mut passport = QvapPassport::new(def.clone(), 1).unwrap();
        add_core_evidence(&mut passport, 20, 100);
        passport.activate(20).unwrap();

        assert_eq!(
            passport.encumber(20),
            Err(QvapError::MissingRequiredEvidence)
        );
        let encumbrance = attestation(
            &def,
            QvapRole::Registrar,
            QvapClaimKind::Encumbrance,
            [12; 32],
            [13; 32],
            1,
            10,
            100,
            0,
        );
        passport
            .record_attestation(encumbrance, 20, &TestOnlyVerifier)
            .unwrap();
        passport.encumber(20).unwrap();
        assert_eq!(passport.status(), QvapStatus::Encumbered);
        assert_eq!(
            passport.issue(1, 20),
            Err(QvapError::InvalidStateTransition)
        );

        let release = attestation(
            &def,
            QvapRole::Registrar,
            QvapClaimKind::EncumbranceRelease,
            [14; 32],
            [15; 32],
            1,
            10,
            100,
            0,
        );
        passport
            .record_attestation(release, 20, &TestOnlyVerifier)
            .unwrap();
        passport.release_encumbrance(20).unwrap();
        assert_eq!(passport.status(), QvapStatus::Active);
    }

    #[test]
    fn invalid_signature_wrong_domain_and_non_monotonic_claim_sequence_fail_closed() {
        let def = definition();
        let mut passport = QvapPassport::new(def.clone(), 1).unwrap();
        let verifier = TestOnlyVerifier;
        let mut invalid = attestation(
            &def,
            QvapRole::Issuer,
            QvapClaimKind::Rights,
            def.issuer_id,
            def.issuer_key_id,
            1,
            10,
            100,
            0,
        );
        invalid.signature[0] ^= 1;
        assert_eq!(
            passport.record_attestation(invalid, 20, &verifier),
            Err(QvapError::InvalidSignature)
        );

        let mut wrong_domain = attestation(
            &def,
            QvapRole::Issuer,
            QvapClaimKind::Rights,
            def.issuer_id,
            def.issuer_key_id,
            1,
            10,
            100,
            0,
        );
        wrong_domain.network_id = [33; 32];
        let digest = wrong_domain.signing_digest().unwrap();
        wrong_domain.signature = TestOnlyVerifier::sign(
            &wrong_domain.key_id,
            wrong_domain.signature_algorithm,
            &digest,
        );
        assert_eq!(
            passport.record_attestation(wrong_domain, 20, &verifier),
            Err(QvapError::WrongNetworkOrAsset)
        );

        let rights = attestation(
            &def,
            QvapRole::Issuer,
            QvapClaimKind::Rights,
            def.issuer_id,
            def.issuer_key_id,
            1,
            10,
            100,
            0,
        );
        passport.record_attestation(rights, 20, &verifier).unwrap();
        let skipped = attestation(
            &def,
            QvapRole::Issuer,
            QvapClaimKind::Rights,
            def.issuer_id,
            def.issuer_key_id,
            3,
            10,
            100,
            0,
        );
        assert_eq!(
            passport.record_attestation(skipped, 20, &verifier),
            Err(QvapError::InvalidAttestationSequence)
        );
    }

    #[test]
    fn event_hash_chain_is_deterministic_and_a_saved_pre_state_can_be_restored() {
        let def = definition();
        let mut left = QvapPassport::new(def.clone(), 1).unwrap();
        let mut right = QvapPassport::new(def, 1).unwrap();
        add_core_evidence(&mut left, 20, 100);
        add_core_evidence(&mut right, 20, 100);
        left.activate(20).unwrap();
        right.activate(20).unwrap();
        assert_eq!(left.event_tip(), right.event_tip());
        left.verify_event_chain().unwrap();

        let before_issue = left.clone();
        left.issue(25, 21).unwrap();
        left.verify_event_chain().unwrap();
        assert_ne!(left.event_tip(), before_issue.event_tip());
        assert_eq!(before_issue.total_issued(), 0);
        assert_eq!(before_issue.status(), QvapStatus::Active);

        let mut replay = before_issue;
        replay.issue(25, 21).unwrap();
        assert_eq!(left.event_tip(), replay.event_tip());
        assert_eq!(left.events(), replay.events());
    }
}

#[cfg(test)]
mod extended_tests {
    use super::tests::{add_core_evidence, attestation, definition, TestOnlyVerifier};
    use super::*;

    #[test]
    fn activation_and_issuance_events_commit_to_the_exact_core_evidence_set() {
        let mut passport = QvapPassport::new(definition(), 1).unwrap();
        add_core_evidence(&mut passport, 20, 100);
        let expected = passport.core_evidence_digest(20).unwrap();
        passport.activate(20).unwrap();
        let activation = passport.events().last().unwrap();
        assert_eq!(activation.kind, QvapEventKind::Activated);
        assert_eq!(activation.subject_digest, expected);

        passport.issue(25, 21).unwrap();
        let issue = passport.events().last().unwrap();
        assert_eq!(issue.kind, QvapEventKind::Issued);
        assert_eq!(issue.subject_digest, expected);
        passport.verify_event_chain().unwrap();
    }

    #[test]
    fn registrar_revocation_is_irreversible_and_blocks_further_asset_operations() {
        let def = definition();
        let mut passport = QvapPassport::new(def.clone(), 1).unwrap();
        add_core_evidence(&mut passport, 20, 100);
        passport.activate(20).unwrap();
        passport.issue(10, 20).unwrap();

        let revocation = attestation(
            &def,
            QvapRole::Registrar,
            QvapClaimKind::Revocation,
            [12; 32],
            [13; 32],
            1,
            10,
            100,
            0,
        );
        passport
            .record_attestation(revocation, 20, &TestOnlyVerifier)
            .unwrap();
        passport.revoke(20).unwrap();
        assert_eq!(passport.status(), QvapStatus::Revoked);
        assert_eq!(
            passport.issue(1, 20),
            Err(QvapError::InvalidStateTransition)
        );
        assert_eq!(
            passport.redeem(1, 20),
            Err(QvapError::InvalidStateTransition)
        );
        assert_eq!(passport.revoke(21), Err(QvapError::InvalidStateTransition));
        assert_eq!(
            passport.events().last().unwrap().kind,
            QvapEventKind::Revoked
        );
        passport.verify_event_chain().unwrap();
    }

    #[test]
    fn encumbrance_release_must_reference_the_exact_active_commitment() {
        let def = definition();
        let mut passport = QvapPassport::new(def.clone(), 1).unwrap();
        add_core_evidence(&mut passport, 20, 100);
        passport.activate(20).unwrap();

        let mut lien = attestation(
            &def,
            QvapRole::Registrar,
            QvapClaimKind::Encumbrance,
            [12; 32],
            [13; 32],
            1,
            10,
            100,
            0,
        );
        lien.claim_commitment = [0x51; 32];
        let digest = lien.signing_digest().unwrap();
        lien.signature = TestOnlyVerifier::sign(&lien.key_id, lien.signature_algorithm, &digest);
        passport
            .record_attestation(lien, 20, &TestOnlyVerifier)
            .unwrap();
        passport.encumber(20).unwrap();

        let mut wrong_release = attestation(
            &def,
            QvapRole::Registrar,
            QvapClaimKind::EncumbranceRelease,
            [14; 32],
            [15; 32],
            1,
            10,
            100,
            0,
        );
        wrong_release.claim_commitment = [0x52; 32];
        let digest = wrong_release.signing_digest().unwrap();
        wrong_release.signature = TestOnlyVerifier::sign(
            &wrong_release.key_id,
            wrong_release.signature_algorithm,
            &digest,
        );
        passport
            .record_attestation(wrong_release, 20, &TestOnlyVerifier)
            .unwrap();

        assert_eq!(
            passport.release_encumbrance(20),
            Err(QvapError::InvalidStateTransition)
        );
        passport.verify_event_chain().unwrap();
    }

    #[test]
    fn revised_redemption_approval_is_new_explicit_authority() {
        let def = definition();
        let mut passport = QvapPassport::new(def.clone(), 1).unwrap();
        add_core_evidence(&mut passport, 20, 100);
        passport.activate(20).unwrap();
        passport.issue(100, 20).unwrap();

        let approval = attestation(
            &def,
            QvapRole::Registrar,
            QvapClaimKind::RedemptionApproval,
            [12; 32],
            [13; 32],
            1,
            10,
            100,
            20,
        );
        passport
            .record_attestation(approval, 20, &TestOnlyVerifier)
            .unwrap();
        passport.redeem(20, 20).unwrap();

        let revised = attestation(
            &def,
            QvapRole::Registrar,
            QvapClaimKind::RedemptionApproval,
            [14; 32],
            [15; 32],
            2,
            21,
            100,
            30,
        );
        passport
            .record_attestation(revised, 21, &TestOnlyVerifier)
            .unwrap();
        passport.redeem(30, 21).unwrap();
        assert_eq!(passport.total_redeemed(), 50);
        assert_eq!(passport.outstanding_supply().unwrap(), 50);
        passport.verify_event_chain().unwrap();
    }

    #[test]
    fn rights_and_external_asset_reference_commitments_must_match_passport() {
        let def = definition();
        let mut passport = QvapPassport::new(def.clone(), 1).unwrap();

        let mut wrong_rights = attestation(
            &def,
            QvapRole::Issuer,
            QvapClaimKind::Rights,
            def.issuer_id,
            def.issuer_key_id,
            1,
            10,
            100,
            0,
        );
        wrong_rights.claim_commitment = [0x71; 32];
        let digest = wrong_rights.signing_digest().unwrap();
        wrong_rights.signature = TestOnlyVerifier::sign(
            &wrong_rights.key_id,
            wrong_rights.signature_algorithm,
            &digest,
        );
        assert_eq!(
            passport.record_attestation(wrong_rights, 20, &TestOnlyVerifier),
            Err(QvapError::InvalidAttestation)
        );

        let mut wrong_external_ref = attestation(
            &def,
            QvapRole::Issuer,
            QvapClaimKind::Rights,
            def.issuer_id,
            def.issuer_key_id,
            1,
            10,
            100,
            0,
        );
        wrong_external_ref.external_reference_commitment = [0x72; 32];
        let digest = wrong_external_ref.signing_digest().unwrap();
        wrong_external_ref.signature = TestOnlyVerifier::sign(
            &wrong_external_ref.key_id,
            wrong_external_ref.signature_algorithm,
            &digest,
        );
        assert_eq!(
            passport.record_attestation(wrong_external_ref, 20, &TestOnlyVerifier),
            Err(QvapError::WrongNetworkOrAsset)
        );
    }

    #[test]
    fn signer_role_history_survives_attestation_supersession() {
        let def = definition();
        let mut passport = QvapPassport::new(def.clone(), 1).unwrap();
        add_core_evidence(&mut passport, 20, 100);

        let replacement = attestation(
            &def,
            QvapRole::Custodian,
            QvapClaimKind::CustodyQuantity,
            [12; 32],
            [13; 32],
            2,
            21,
            100,
            10,
        );
        passport
            .record_attestation(replacement, 21, &TestOnlyVerifier)
            .unwrap();

        let old_custodian_as_registrar = attestation(
            &def,
            QvapRole::Registrar,
            QvapClaimKind::Encumbrance,
            [8; 32],
            [14; 32],
            1,
            22,
            100,
            0,
        );
        assert_eq!(
            passport.record_attestation(old_custodian_as_registrar, 22, &TestOnlyVerifier),
            Err(QvapError::DuplicateSignerAcrossRoles)
        );
    }

    #[test]
    fn custody_attestation_cannot_reduce_verified_quantity_below_issued_supply() {
        let def = definition();
        let mut passport = QvapPassport::new(def.clone(), 1).unwrap();
        add_core_evidence(&mut passport, 20, 100);
        passport.activate(20).unwrap();
        passport.issue(100, 20).unwrap();

        let reduced_custody = attestation(
            &def,
            QvapRole::Custodian,
            QvapClaimKind::CustodyQuantity,
            [12; 32],
            [13; 32],
            2,
            21,
            100,
            5,
        );
        assert_eq!(
            passport.record_attestation(reduced_custody, 21, &TestOnlyVerifier),
            Err(QvapError::SupplyCapExceeded {
                requested: 100,
                allowed: 50
            })
        );
        assert_eq!(passport.maximum_issuable_supply(21).unwrap(), 100);
        assert_eq!(passport.total_issued(), 100);
    }
}
