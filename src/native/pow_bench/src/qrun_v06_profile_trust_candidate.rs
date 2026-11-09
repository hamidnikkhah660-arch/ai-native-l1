//! CP-0539 independently authorized Q6PN profile trust and anti-rollback contract.
//!
//! Q6TS is signed by an authority keyset supplied out of band. Its monotonic floor MUST live
//! in a separately administered durable system (for example, a remote atomic CAS service or
//! hardware-backed monotonic store). A file-local checksum, the node archive, and the existing
//! ExternalCasFloorStore do not satisfy this module's anti-whole-disk-rollback contract.
//!
//! This module defines verification and provider interfaces only. It does not provision trust
//! roots, implement a remote trust service, hold signing keys, or claim a production deployment.
use crate::{
    qrun_v06_profile_pin_candidate::{QRunV06ProfilePinError, QRunV06VerifiedProfilePin},
    qrun_v06_quote_asset_qualification_candidate::{
        require_qualified_quote_asset, Q6QaError, QRunV06SignedQuoteAssetQualificationCandidate,
        QRunV06VerifiedQuoteAssetQualificationCandidate,
    },
    state_machine::TransactionAuthenticator,
    v4_fat1_trust_candidate::{
        MlDsa65Verifier, ED25519_PUBLIC_KEY_BYTES, ED25519_SIGNATURE_BYTES,
        ML_DSA_65_PUBLIC_KEY_BYTES, ML_DSA_65_SIGNATURE_BYTES,
    },
};
use ed25519_dalek::{Signature as EdSignature, VerifyingKey};
use sha2::{Digest, Sha256};
use std::fmt;

pub const QRUN_V06_PROFILE_TRUST_RECORD_BYTES: usize = 144;
pub const QRUN_V06_PROFILE_TRUST_ENVELOPE_BYTES: usize = 8
    + QRUN_V06_PROFILE_TRUST_RECORD_BYTES
    + 32
    + ED25519_SIGNATURE_BYTES
    + ML_DSA_65_SIGNATURE_BYTES;

const RECORD_MAGIC: &[u8; 4] = b"Q6TR";
const ENVELOPE_MAGIC: &[u8; 4] = b"Q6TS";
const VERSION: u16 = 1;
const RECORD_ID_DOMAIN: &[u8] = b"QRUN-V06-PROFILE-TRUST-RECORD-ID-V1\0";
const ENVELOPE_ID_DOMAIN: &[u8] = b"QRUN-V06-PROFILE-TRUST-ENVELOPE-ID-V1\0";
const AUTHORITY_KEYSET_DOMAIN: &[u8] = b"QRUN-V06-PROFILE-TRUST-AUTHORITY-KEYSET-V1\0";
const SIGNING_DOMAIN: &[u8] = b"QRUN-V06-PROFILE-TRUST-SIGNING-V1\0";

fn is_zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}

fn hash_parts(parts: &[&[u8]]) -> [u8; 32] {
    let mut hash = Sha256::new();
    for part in parts {
        hash.update(part);
    }
    hash.finalize().into()
}

fn take<const N: usize>(bytes: &[u8], start: usize) -> Result<[u8; N], QRunV06ProfileTrustError> {
    bytes
        .get(start..start + N)
        .ok_or(QRunV06ProfileTrustError::Malformed)?
        .try_into()
        .map_err(|_| QRunV06ProfileTrustError::Malformed)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum QRunV06ProfileTrustStatus {
    Active = 1,
    Revoked = 2,
}

impl TryFrom<u16> for QRunV06ProfileTrustStatus {
    type Error = QRunV06ProfileTrustError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Active),
            2 => Ok(Self::Revoked),
            _ => Err(QRunV06ProfileTrustError::InvalidStatus),
        }
    }
}

/// The signed authority decision for one network/profile and one complete Q6PN byte commitment.
/// Each epoch is exactly one successor; previous_record_id is zero only at epoch one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QRunV06ProfileTrustRecord {
    pub trust_epoch: u64,
    pub status: QRunV06ProfileTrustStatus,
    pub network_id: [u8; 32],
    pub profile_id: [u8; 32],
    pub profile_pin_commitment: [u8; 32],
    pub previous_record_id: [u8; 32],
}

impl QRunV06ProfileTrustRecord {
    pub fn validate(&self) -> Result<(), QRunV06ProfileTrustError> {
        if self.trust_epoch == 0 {
            return Err(QRunV06ProfileTrustError::EpochZero);
        }
        for (name, value) in [
            ("network_id", &self.network_id[..]),
            ("profile_id", &self.profile_id[..]),
            ("profile_pin_commitment", &self.profile_pin_commitment[..]),
        ] {
            if is_zero(value) {
                return Err(QRunV06ProfileTrustError::ZeroField(name));
            }
        }
        if (self.trust_epoch == 1) != is_zero(&self.previous_record_id) {
            return Err(QRunV06ProfileTrustError::InvalidPredecessor);
        }
        Ok(())
    }

    pub fn encode(
        &self,
    ) -> Result<[u8; QRUN_V06_PROFILE_TRUST_RECORD_BYTES], QRunV06ProfileTrustError> {
        self.validate()?;
        let mut bytes = Vec::with_capacity(QRUN_V06_PROFILE_TRUST_RECORD_BYTES);
        bytes.extend_from_slice(RECORD_MAGIC);
        bytes.extend_from_slice(&VERSION.to_be_bytes());
        bytes.extend_from_slice(&(self.status as u16).to_be_bytes());
        bytes.extend_from_slice(&self.trust_epoch.to_be_bytes());
        bytes.extend_from_slice(&self.network_id);
        bytes.extend_from_slice(&self.profile_id);
        bytes.extend_from_slice(&self.profile_pin_commitment);
        bytes.extend_from_slice(&self.previous_record_id);
        bytes
            .try_into()
            .map_err(|_| QRunV06ProfileTrustError::Malformed)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, QRunV06ProfileTrustError> {
        if bytes.len() != QRUN_V06_PROFILE_TRUST_RECORD_BYTES
            || bytes.get(..4) != Some(RECORD_MAGIC.as_slice())
        {
            return Err(QRunV06ProfileTrustError::WrongRecordLengthOrMagic);
        }
        if u16::from_be_bytes([bytes[4], bytes[5]]) != VERSION {
            return Err(QRunV06ProfileTrustError::UnsupportedVersion);
        }
        let record = Self {
            status: QRunV06ProfileTrustStatus::try_from(u16::from_be_bytes([bytes[6], bytes[7]]))?,
            trust_epoch: u64::from_be_bytes(take(bytes, 8)?),
            network_id: take(bytes, 16)?,
            profile_id: take(bytes, 48)?,
            profile_pin_commitment: take(bytes, 80)?,
            previous_record_id: take(bytes, 112)?,
        };
        record.validate()?;
        if record.encode()?.as_slice() != bytes {
            return Err(QRunV06ProfileTrustError::Malformed);
        }
        Ok(record)
    }

    pub fn record_id(&self) -> Result<[u8; 32], QRunV06ProfileTrustError> {
        Ok(hash_parts(&[RECORD_ID_DOMAIN, &self.encode()?]))
    }

    pub fn signing_digest(
        &self,
        authority_keyset_id: &[u8; 32],
    ) -> Result<[u8; 32], QRunV06ProfileTrustError> {
        if is_zero(authority_keyset_id) {
            return Err(QRunV06ProfileTrustError::WrongAuthorityKeyset);
        }
        Ok(hash_parts(&[
            SIGNING_DOMAIN,
            &self.encode()?,
            authority_keyset_id,
        ]))
    }
}

/// The public-key tuple must be provisioned independently of Q6TS and Q6PN.
/// It is not embedded in the trust envelope, preventing self-signed trust bootstrap.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinnedQRunV06ProfileTrustAuthority {
    pub ed25519_public_key: [u8; ED25519_PUBLIC_KEY_BYTES],
    pub mldsa65_public_key: [u8; ML_DSA_65_PUBLIC_KEY_BYTES],
}

impl PinnedQRunV06ProfileTrustAuthority {
    pub fn keyset_id(&self) -> Result<[u8; 32], QRunV06ProfileTrustError> {
        if is_zero(&self.ed25519_public_key) || is_zero(&self.mldsa65_public_key) {
            return Err(QRunV06ProfileTrustError::WrongAuthorityKeyset);
        }
        VerifyingKey::from_bytes(&self.ed25519_public_key)
            .map_err(|_| QRunV06ProfileTrustError::InvalidEd25519PublicKey)?;
        Ok(hash_parts(&[
            AUTHORITY_KEYSET_DOMAIN,
            &self.ed25519_public_key,
            &self.mldsa65_public_key,
        ]))
    }
}

/// Q6TS carries signatures only. Public keys are supplied from a separately pinned deployment
/// configuration and are not accepted from the same source as the envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QRunV06SignedProfileTrustEnvelope {
    pub record: QRunV06ProfileTrustRecord,
    pub authority_keyset_id: [u8; 32],
    pub ed25519_signature: [u8; ED25519_SIGNATURE_BYTES],
    pub mldsa65_signature: [u8; ML_DSA_65_SIGNATURE_BYTES],
}

impl QRunV06SignedProfileTrustEnvelope {
    pub fn encode(
        &self,
    ) -> Result<[u8; QRUN_V06_PROFILE_TRUST_ENVELOPE_BYTES], QRunV06ProfileTrustError> {
        if is_zero(&self.authority_keyset_id)
            || is_zero(&self.ed25519_signature)
            || is_zero(&self.mldsa65_signature)
        {
            return Err(QRunV06ProfileTrustError::Malformed);
        }
        let mut bytes = Vec::with_capacity(QRUN_V06_PROFILE_TRUST_ENVELOPE_BYTES);
        bytes.extend_from_slice(ENVELOPE_MAGIC);
        bytes.extend_from_slice(&VERSION.to_be_bytes());
        bytes.extend_from_slice(&0u16.to_be_bytes());
        bytes.extend_from_slice(&self.record.encode()?);
        bytes.extend_from_slice(&self.authority_keyset_id);
        bytes.extend_from_slice(&self.ed25519_signature);
        bytes.extend_from_slice(&self.mldsa65_signature);
        bytes
            .try_into()
            .map_err(|_| QRunV06ProfileTrustError::Malformed)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, QRunV06ProfileTrustError> {
        if bytes.len() != QRUN_V06_PROFILE_TRUST_ENVELOPE_BYTES {
            return Err(QRunV06ProfileTrustError::WrongEnvelopeLength);
        }
        if bytes.get(..4) != Some(ENVELOPE_MAGIC.as_slice()) {
            return Err(QRunV06ProfileTrustError::WrongEnvelopeMagic);
        }
        if u16::from_be_bytes([bytes[4], bytes[5]]) != VERSION {
            return Err(QRunV06ProfileTrustError::UnsupportedVersion);
        }
        if bytes[6..8] != [0, 0] {
            return Err(QRunV06ProfileTrustError::NonzeroReserved);
        }
        let record_start = 8;
        let record_end = record_start + QRUN_V06_PROFILE_TRUST_RECORD_BYTES;
        let keyset_start = record_end;
        let ed_start = keyset_start + 32;
        let pq_start = ed_start + ED25519_SIGNATURE_BYTES;
        let envelope = Self {
            record: QRunV06ProfileTrustRecord::decode(&bytes[record_start..record_end])?,
            authority_keyset_id: take(bytes, keyset_start)?,
            ed25519_signature: take(bytes, ed_start)?,
            mldsa65_signature: take(bytes, pq_start)?,
        };
        if envelope.encode()?.as_slice() != bytes {
            return Err(QRunV06ProfileTrustError::Malformed);
        }
        Ok(envelope)
    }

    pub fn envelope_id(&self) -> Result<[u8; 32], QRunV06ProfileTrustError> {
        Ok(hash_parts(&[ENVELOPE_ID_DOMAIN, &self.encode()?]))
    }
}

/// The trusted anti-rollback high-water mark. It must be loaded from a separately administered
/// monotonic store. Storing this value beside Q6PN/Q6TS or in the ordinary node data directory
/// is not sufficient protection against whole-host rollback.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedQRunV06ProfileTrustFloor {
    pub network_id: [u8; 32],
    pub profile_id: [u8; 32],
    pub trust_epoch: u64,
    pub status: Option<QRunV06ProfileTrustStatus>,
    pub record_id: [u8; 32],
    pub envelope_id: [u8; 32],
}

impl TrustedQRunV06ProfileTrustFloor {
    /// Empty floor for a genuinely new profile trust domain only. Do not use this to re-bootstrap
    /// an existing deployment after losing its external floor: provision the known current head.
    pub fn initial(
        network_id: [u8; 32],
        profile_id: [u8; 32],
    ) -> Result<Self, QRunV06ProfileTrustError> {
        if is_zero(&network_id) || is_zero(&profile_id) {
            return Err(QRunV06ProfileTrustError::InvalidFloor);
        }
        Ok(Self {
            network_id,
            profile_id,
            trust_epoch: 0,
            status: None,
            record_id: [0; 32],
            envelope_id: [0; 32],
        })
    }

    /// Construct the non-empty floor from an independently reviewed provisioning ceremony.
    /// The production provider must persist this using its monotonic/CAS guarantee.
    pub fn provisioned(
        network_id: [u8; 32],
        profile_id: [u8; 32],
        trust_epoch: u64,
        status: QRunV06ProfileTrustStatus,
        record_id: [u8; 32],
        envelope_id: [u8; 32],
    ) -> Result<Self, QRunV06ProfileTrustError> {
        let floor = Self {
            network_id,
            profile_id,
            trust_epoch,
            status: Some(status),
            record_id,
            envelope_id,
        };
        floor.validate()?;
        Ok(floor)
    }

    pub fn validate(&self) -> Result<(), QRunV06ProfileTrustError> {
        if is_zero(&self.network_id) || is_zero(&self.profile_id) {
            return Err(QRunV06ProfileTrustError::InvalidFloor);
        }
        if self.trust_epoch == 0 {
            if self.status.is_some() || !is_zero(&self.record_id) || !is_zero(&self.envelope_id) {
                return Err(QRunV06ProfileTrustError::InvalidFloor);
            }
        } else if self.status.is_none() || is_zero(&self.record_id) || is_zero(&self.envelope_id) {
            return Err(QRunV06ProfileTrustError::InvalidFloor);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QRunV06ProfileTrustFloorDecision {
    AlreadyPinnedCurrent,
    AdvanceWithCompareAndSwap,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedQRunV06ProfileTrustRecord {
    // Private fields make the signature-verification result unforgeable outside this module.
    // Only verify_qrun_v06_profile_trust_envelope can construct the value accepted by the CAS API.
    record: QRunV06ProfileTrustRecord,
    record_id: [u8; 32],
    envelope_id: [u8; 32],
    expected_floor: TrustedQRunV06ProfileTrustFloor,
    next_floor: TrustedQRunV06ProfileTrustFloor,
    decision: QRunV06ProfileTrustFloorDecision,
}

impl VerifiedQRunV06ProfileTrustRecord {
    pub fn record(&self) -> &QRunV06ProfileTrustRecord {
        &self.record
    }

    pub fn record_id(&self) -> [u8; 32] {
        self.record_id
    }

    pub fn envelope_id(&self) -> [u8; 32] {
        self.envelope_id
    }

    pub fn next_floor(&self) -> &TrustedQRunV06ProfileTrustFloor {
        &self.next_floor
    }

    pub fn decision(&self) -> QRunV06ProfileTrustFloorDecision {
        self.decision
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QRunV06ProfileTrustError {
    WrongRecordLengthOrMagic,
    WrongEnvelopeLength,
    WrongEnvelopeMagic,
    UnsupportedVersion,
    NonzeroReserved,
    InvalidStatus,
    EpochZero,
    ZeroField(&'static str),
    InvalidPredecessor,
    Malformed,
    InvalidEd25519PublicKey,
    InvalidEd25519Signature,
    InvalidMlDsa65Signature,
    WrongAuthorityKeyset,
    WrongNetworkOrProfile,
    Rollback,
    SameEpochConflict,
    EpochGap,
    PredecessorMismatch,
    ProfilePin(QRunV06ProfilePinError),
    MissingProfilePinBytes,
    ProfilePinContextMismatch,
    ProfileRevoked,
    InvalidFloor,
    FloorUnavailable,
    FloorCasConflict,
    TrustSourceUnavailable(String),
    MissingQuoteAssetTrustPin,
    QuoteAssetQualification(Q6QaError),
    HistoricalTrustHistory(String),
}

impl fmt::Display for QRunV06ProfileTrustError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for QRunV06ProfileTrustError {}
impl From<QRunV06ProfilePinError> for QRunV06ProfileTrustError {
    fn from(value: QRunV06ProfilePinError) -> Self {
        Self::ProfilePin(value)
    }
}
impl From<Q6QaError> for QRunV06ProfileTrustError {
    fn from(value: Q6QaError) -> Self {
        Self::QuoteAssetQualification(value)
    }
}

/// Verify both signature suites, profile context, exact predecessor and one-step trust epoch.
/// The ML-DSA verifier must be the separately reviewed production implementation at deployment.
pub fn verify_qrun_v06_profile_trust_envelope<V: MlDsa65Verifier>(
    envelope: &QRunV06SignedProfileTrustEnvelope,
    authority: &PinnedQRunV06ProfileTrustAuthority,
    pq_verifier: &V,
    floor: &TrustedQRunV06ProfileTrustFloor,
) -> Result<VerifiedQRunV06ProfileTrustRecord, QRunV06ProfileTrustError> {
    floor.validate()?;
    envelope.record.validate()?;
    if envelope.record.network_id != floor.network_id
        || envelope.record.profile_id != floor.profile_id
    {
        return Err(QRunV06ProfileTrustError::WrongNetworkOrProfile);
    }
    if authority.keyset_id()? != envelope.authority_keyset_id {
        return Err(QRunV06ProfileTrustError::WrongAuthorityKeyset);
    }

    let record_id = envelope.record.record_id()?;
    let envelope_id = envelope.envelope_id()?;
    let decision = if envelope.record.trust_epoch < floor.trust_epoch {
        return Err(QRunV06ProfileTrustError::Rollback);
    } else if envelope.record.trust_epoch == floor.trust_epoch {
        if record_id != floor.record_id
            || envelope_id != floor.envelope_id
            || Some(envelope.record.status) != floor.status
        {
            return Err(QRunV06ProfileTrustError::SameEpochConflict);
        }
        QRunV06ProfileTrustFloorDecision::AlreadyPinnedCurrent
    } else {
        if floor.status == Some(QRunV06ProfileTrustStatus::Revoked) {
            return Err(QRunV06ProfileTrustError::ProfileRevoked);
        }
        let expected_epoch = floor
            .trust_epoch
            .checked_add(1)
            .ok_or(QRunV06ProfileTrustError::EpochGap)?;
        if envelope.record.trust_epoch != expected_epoch {
            return Err(QRunV06ProfileTrustError::EpochGap);
        }
        if envelope.record.previous_record_id != floor.record_id {
            return Err(QRunV06ProfileTrustError::PredecessorMismatch);
        }
        QRunV06ProfileTrustFloorDecision::AdvanceWithCompareAndSwap
    };

    let digest = envelope
        .record
        .signing_digest(&envelope.authority_keyset_id)?;
    let ed_key = VerifyingKey::from_bytes(&authority.ed25519_public_key)
        .map_err(|_| QRunV06ProfileTrustError::InvalidEd25519PublicKey)?;
    let ed_signature = EdSignature::from_bytes(&envelope.ed25519_signature);
    ed_key
        .verify_strict(&digest, &ed_signature)
        .map_err(|_| QRunV06ProfileTrustError::InvalidEd25519Signature)?;
    if !pq_verifier.verify(
        &authority.mldsa65_public_key,
        &digest,
        &envelope.mldsa65_signature,
    ) {
        return Err(QRunV06ProfileTrustError::InvalidMlDsa65Signature);
    }

    let next_floor = TrustedQRunV06ProfileTrustFloor::provisioned(
        envelope.record.network_id,
        envelope.record.profile_id,
        envelope.record.trust_epoch,
        envelope.record.status,
        record_id,
        envelope_id,
    )?;
    Ok(VerifiedQRunV06ProfileTrustRecord {
        record: envelope.record.clone(),
        record_id,
        envelope_id,
        expected_floor: floor.clone(),
        next_floor,
        decision,
    })
}

/// The only acceptable production implementation is an atomic, durable monotonic store that is
/// administered separately from the QRun node and its ordinary disks. It must not auto-create a
/// missing floor from whichever Q6TS envelope a remote source happens to return.
pub trait MonotonicQRunV06ProfileTrustFloorStore {
    fn load(
        &self,
        network_id: &[u8; 32],
        profile_id: &[u8; 32],
    ) -> Result<TrustedQRunV06ProfileTrustFloor, QRunV06ProfileTrustError>;

    fn compare_and_swap(
        &mut self,
        expected: &TrustedQRunV06ProfileTrustFloor,
        next: &TrustedQRunV06ProfileTrustFloor,
    ) -> Result<(), QRunV06ProfileTrustError>;
}

/// Verify the loaded floor both before and after CAS. An ambiguous CAS result is reconciled only
/// by reading back the exact next floor; no local fallback or guessed success is permitted.
pub fn commit_verified_qrun_v06_profile_trust_floor<S: MonotonicQRunV06ProfileTrustFloorStore>(
    store: &mut S,
    verified: &VerifiedQRunV06ProfileTrustRecord,
) -> Result<TrustedQRunV06ProfileTrustFloor, QRunV06ProfileTrustError> {
    let current = store.load(
        &verified.expected_floor.network_id,
        &verified.expected_floor.profile_id,
    )?;
    if current != verified.expected_floor {
        return Err(QRunV06ProfileTrustError::FloorCasConflict);
    }

    match verified.decision {
        QRunV06ProfileTrustFloorDecision::AlreadyPinnedCurrent => {
            if verified.next_floor != current {
                return Err(QRunV06ProfileTrustError::FloorCasConflict);
            }
            Ok(current)
        }
        QRunV06ProfileTrustFloorDecision::AdvanceWithCompareAndSwap => {
            if verified.next_floor.network_id != current.network_id
                || verified.next_floor.profile_id != current.profile_id
                || current.trust_epoch.checked_add(1) != Some(verified.next_floor.trust_epoch)
                || verified.next_floor.record_id != verified.record_id
                || verified.next_floor.envelope_id != verified.envelope_id
            {
                return Err(QRunV06ProfileTrustError::FloorCasConflict);
            }
            if store
                .compare_and_swap(&current, &verified.next_floor)
                .is_err()
            {
                // The provider may have committed before its response was lost. Read back; only
                // the exact next state is success. Any other value is a hard conflict.
                return match store.load(&current.network_id, &current.profile_id) {
                    Ok(read_back) if read_back == verified.next_floor => Ok(read_back),
                    Ok(_) => Err(QRunV06ProfileTrustError::FloorCasConflict),
                    Err(_) => Err(QRunV06ProfileTrustError::FloorUnavailable),
                };
            }
            match store.load(&current.network_id, &current.profile_id) {
                Ok(read_back) if read_back == verified.next_floor => Ok(read_back),
                _ => Err(QRunV06ProfileTrustError::FloorCasConflict),
            }
        }
    }
}

/// Control-plane publication step. Verify the next signed Q6TS record against the currently
/// provisioned floor and advance the independent monotonic floor before publishing the envelope
/// to the trust source. Node startup deliberately refuses to advance this floor itself.
pub fn prepublish_qrun_v06_profile_trust_floor<S, V>(
    signed_trust_envelope_bytes: &[u8],
    authority: &PinnedQRunV06ProfileTrustAuthority,
    pq_verifier: &V,
    floor_store: &mut S,
) -> Result<TrustedQRunV06ProfileTrustFloor, QRunV06ProfileTrustError>
where
    S: MonotonicQRunV06ProfileTrustFloorStore,
    V: MlDsa65Verifier,
{
    let envelope = QRunV06SignedProfileTrustEnvelope::decode(signed_trust_envelope_bytes)?;
    let floor = floor_store.load(&envelope.record.network_id, &envelope.record.profile_id)?;
    let verified =
        verify_qrun_v06_profile_trust_envelope(&envelope, authority, pq_verifier, &floor)?;
    commit_verified_qrun_v06_profile_trust_floor(floor_store, &verified)
}

/// Separate source for the signed Q6TS envelope. It may be untrusted for integrity: signatures
/// and the pre-published independent monotonic floor establish acceptance. Returning stale data
/// fails closed; the node never advances the floor from a trust-source response.
pub trait QRunV06ProfileTrustSource {
    type Error: fmt::Display;

    fn read_current_signed_record(
        &mut self,
        network_id: &[u8; 32],
        profile_id: &[u8; 32],
    ) -> Result<Vec<u8>, Self::Error>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QRunV06TrustAuthorizedProfilePin {
    verified_profile_pin: QRunV06VerifiedProfilePin,
    trust_epoch: u64,
    trust_record_id: [u8; 32],
    trust_envelope_id: [u8; 32],
}

impl QRunV06TrustAuthorizedProfilePin {
    pub fn verified_profile_pin(&self) -> &QRunV06VerifiedProfilePin {
        &self.verified_profile_pin
    }

    /// Verify the exact Q6QA bytes using the commitment and authority/asset/epoch tuple
    /// embedded in Q6PN v2. The Q6PN bytes themselves were already authorized by the
    /// dual-signed Q6TS record and the independent monotonic profile-trust floor.
    pub fn authorize_quote_asset<A: TransactionAuthenticator>(
        &self,
        q6qa_bundle_bytes: &[u8],
        current_height: u64,
        authenticator: &A,
    ) -> Result<QRunV06TrustAuthorizedQuoteAsset, QRunV06ProfileTrustError> {
        let quote_pin = self
            .verified_profile_pin
            .quote_asset_trust_pin()
            .ok_or(QRunV06ProfileTrustError::MissingQuoteAssetTrustPin)?;
        let bundle = QRunV06SignedQuoteAssetQualificationCandidate::decode(q6qa_bundle_bytes)?;
        let descriptor = self.verified_profile_pin.descriptor();
        let qualification = bundle.verify_pinned(
            quote_pin.q6qa_bundle_commitment(),
            descriptor.network_id(),
            descriptor.profile_id(),
            quote_pin.asset_id(),
            quote_pin.authority_key_id(),
            quote_pin.authority_account(),
            quote_pin.qualification_epoch(),
            current_height,
            authenticator,
        )?;
        Ok(QRunV06TrustAuthorizedQuoteAsset {
            qualification,
            profile_pin_commitment: self.verified_profile_pin.profile_pin_commitment(),
            profile_trust_epoch: self.trust_epoch,
            profile_trust_record_id: self.trust_record_id,
            profile_trust_envelope_id: self.trust_envelope_id,
            authorized_height: current_height,
        })
    }

    pub fn trust_epoch(&self) -> u64 {
        self.trust_epoch
    }

    pub fn trust_record_id(&self) -> [u8; 32] {
        self.trust_record_id
    }

    pub fn trust_envelope_id(&self) -> [u8; 32] {
        self.trust_envelope_id
    }
}

/// A quote asset whose Q6QA bundle was verified against a Q6PN v2 pin that was itself
/// authorized by the dual-signed Q6TS record and independent profile-trust floor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QRunV06TrustAuthorizedQuoteAsset {
    qualification: QRunV06VerifiedQuoteAssetQualificationCandidate,
    profile_pin_commitment: [u8; 32],
    profile_trust_epoch: u64,
    profile_trust_record_id: [u8; 32],
    profile_trust_envelope_id: [u8; 32],
    authorized_height: u64,
}

#[cfg(test)]
pub(crate) fn test_trust_authorized_quote_asset_candidate(
    network_id: [u8; 32],
    profile_id: [u8; 32],
    asset_id: [u8; 32],
    q6qa_commitment: [u8; 32],
    profile_pin_commitment: [u8; 32],
    qualification_epoch: u64,
    valid_from_height: u64,
    valid_until_height: u64,
    profile_trust_epoch: u64,
    authorized_height: u64,
) -> QRunV06TrustAuthorizedQuoteAsset {
    test_trust_authorized_quote_asset_candidate_with_decimals(
        network_id,
        profile_id,
        asset_id,
        q6qa_commitment,
        profile_pin_commitment,
        qualification_epoch,
        valid_from_height,
        valid_until_height,
        profile_trust_epoch,
        authorized_height,
        6,
    )
}

#[cfg(test)]
pub(crate) fn test_trust_authorized_quote_asset_candidate_with_decimals(
    network_id: [u8; 32],
    profile_id: [u8; 32],
    asset_id: [u8; 32],
    q6qa_commitment: [u8; 32],
    profile_pin_commitment: [u8; 32],
    qualification_epoch: u64,
    valid_from_height: u64,
    valid_until_height: u64,
    profile_trust_epoch: u64,
    authorized_height: u64,
    decimals: u8,
) -> QRunV06TrustAuthorizedQuoteAsset {
    let qualification = if decimals == 6 {
        crate::qrun_v06_quote_asset_qualification_candidate::test_verified_quote_asset_candidate(
            network_id,
            profile_id,
            asset_id,
            q6qa_commitment,
            qualification_epoch,
            valid_from_height,
            valid_until_height,
        )
    } else {
        crate::qrun_v06_quote_asset_qualification_candidate::test_verified_quote_asset_candidate_with_decimals(
            network_id,
            profile_id,
            asset_id,
            q6qa_commitment,
            qualification_epoch,
            valid_from_height,
            valid_until_height,
            decimals,
        )
    };
    QRunV06TrustAuthorizedQuoteAsset {
        qualification,
        profile_pin_commitment,
        profile_trust_epoch,
        profile_trust_record_id: [0x91; 32],
        profile_trust_envelope_id: [0x92; 32],
        authorized_height,
    }
}

impl QRunV06TrustAuthorizedQuoteAsset {
    pub fn qualification(&self) -> &QRunV06VerifiedQuoteAssetQualificationCandidate {
        &self.qualification
    }

    pub fn profile_pin_commitment(&self) -> [u8; 32] {
        self.profile_pin_commitment
    }

    pub fn profile_trust_epoch(&self) -> u64 {
        self.profile_trust_epoch
    }

    pub fn profile_trust_record_id(&self) -> [u8; 32] {
        self.profile_trust_record_id
    }

    pub fn profile_trust_envelope_id(&self) -> [u8; 32] {
        self.profile_trust_envelope_id
    }

    pub fn require_for_pair(
        &self,
        network_id: &[u8; 32],
        profile_id: &[u8; 32],
        quote_asset_id: &[u8; 32],
        current_height: u64,
    ) -> Result<(), QRunV06ProfileTrustError> {
        if current_height != self.authorized_height {
            return Err(QRunV06ProfileTrustError::QuoteAssetQualification(
                Q6QaError::AuthorizationHeightMismatch,
            ));
        }
        require_qualified_quote_asset(
            &self.qualification,
            network_id,
            profile_id,
            quote_asset_id,
            current_height,
        )?;
        Ok(())
    }
}

/// Authorize a Q6PN bundle only when the signed Q6TS record exactly matches the current
/// independently provisioned monotonic floor. A Revoked head is terminal and denies startup.
/// Nodes never advance the floor from a record obtained from the trust source.
pub fn authorize_qrun_v06_profile_pin<S, V>(
    profile_pin_bytes: Option<&[u8]>,
    signed_trust_envelope_bytes: &[u8],
    authority: &PinnedQRunV06ProfileTrustAuthority,
    pq_verifier: &V,
    floor_store: &mut S,
    expected_network_id: [u8; 32],
    expected_profile_id: [u8; 32],
) -> Result<QRunV06TrustAuthorizedProfilePin, QRunV06ProfileTrustError>
where
    S: MonotonicQRunV06ProfileTrustFloorStore,
    V: MlDsa65Verifier,
{
    let floor = floor_store.load(&expected_network_id, &expected_profile_id)?;
    let envelope = QRunV06SignedProfileTrustEnvelope::decode(signed_trust_envelope_bytes)?;
    let verified =
        verify_qrun_v06_profile_trust_envelope(&envelope, authority, pq_verifier, &floor)?;
    if verified.decision != QRunV06ProfileTrustFloorDecision::AlreadyPinnedCurrent {
        // Startup is not a trust-publication authority. An authorized control plane must CAS
        // this exact envelope into the independent floor before publishing it to nodes.
        return Err(QRunV06ProfileTrustError::FloorCasConflict);
    }

    let decoded_profile_pin = match envelope.record.status {
        QRunV06ProfileTrustStatus::Active => {
            let bytes =
                profile_pin_bytes.ok_or(QRunV06ProfileTrustError::MissingProfilePinBytes)?;
            let pin =
                QRunV06VerifiedProfilePin::decode(bytes, envelope.record.profile_pin_commitment)?;
            let descriptor = pin.descriptor();
            if descriptor.network_id() != expected_network_id
                || descriptor.profile_id() != expected_profile_id
                || descriptor.network_id() != envelope.record.network_id
                || descriptor.profile_id() != envelope.record.profile_id
            {
                return Err(QRunV06ProfileTrustError::ProfilePinContextMismatch);
            }
            Some(pin)
        }
        QRunV06ProfileTrustStatus::Revoked => None,
    };

    commit_verified_qrun_v06_profile_trust_floor(floor_store, &verified)?;
    let Some(verified_profile_pin) = decoded_profile_pin else {
        return Err(QRunV06ProfileTrustError::ProfileRevoked);
    };

    Ok(QRunV06TrustAuthorizedProfilePin {
        verified_profile_pin,
        trust_epoch: verified.record.trust_epoch,
        trust_record_id: verified.record_id,
        trust_envelope_id: verified.envelope_id,
    })
}

/// Fetch the latest signed trust record from the configured source, then run the identical
/// signature/context/anti-rollback workflow. Source unavailability is never a local fallback.
pub fn authorize_qrun_v06_profile_pin_from_source<S, V, T>(
    profile_pin_bytes: Option<&[u8]>,
    source: &mut T,
    authority: &PinnedQRunV06ProfileTrustAuthority,
    pq_verifier: &V,
    floor_store: &mut S,
    expected_network_id: [u8; 32],
    expected_profile_id: [u8; 32],
) -> Result<QRunV06TrustAuthorizedProfilePin, QRunV06ProfileTrustError>
where
    S: MonotonicQRunV06ProfileTrustFloorStore,
    V: MlDsa65Verifier,
    T: QRunV06ProfileTrustSource,
{
    let envelope = source
        .read_current_signed_record(&expected_network_id, &expected_profile_id)
        .map_err(|error| QRunV06ProfileTrustError::TrustSourceUnavailable(error.to_string()))?;
    authorize_qrun_v06_profile_pin(
        profile_pin_bytes,
        &envelope,
        authority,
        pq_verifier,
        floor_store,
        expected_network_id,
        expected_profile_id,
    )
}

/// Concrete adapter for fork-choice/durable-store authorization callbacks. Unlike a
/// cached `QRunV06TrustAuthorizedProfilePin`, this adapter re-reads the trust source and
/// independently administered monotonic floor for every requested block height, verifies
/// the dual-signed Q6TS envelope, reloads the exact Q6PN bytes and re-verifies Q6QA.
/// A source/floor outage, stale record, floor advance or terminal revocation therefore
/// aborts the block before branch/store publication.
pub struct QRunV06FreshQuoteAssetAuthorizationProvider<'a, S, V, T, A> {
    profile_pin_bytes: &'a [u8],
    q6qa_bundle_bytes: &'a [u8],
    authority: &'a PinnedQRunV06ProfileTrustAuthority,
    pq_verifier: &'a V,
    floor_store: &'a mut S,
    trust_source: &'a mut T,
    transaction_authenticator: &'a A,
}

impl<'a, S, V, T, A> QRunV06FreshQuoteAssetAuthorizationProvider<'a, S, V, T, A>
where
    S: MonotonicQRunV06ProfileTrustFloorStore,
    V: MlDsa65Verifier,
    T: QRunV06ProfileTrustSource,
    A: TransactionAuthenticator,
{
    pub fn new(
        profile_pin_bytes: &'a [u8],
        q6qa_bundle_bytes: &'a [u8],
        authority: &'a PinnedQRunV06ProfileTrustAuthority,
        pq_verifier: &'a V,
        floor_store: &'a mut S,
        trust_source: &'a mut T,
        transaction_authenticator: &'a A,
    ) -> Self {
        Self {
            profile_pin_bytes,
            q6qa_bundle_bytes,
            authority,
            pq_verifier,
            floor_store,
            trust_source,
            transaction_authenticator,
        }
    }

    /// Perform a fresh trust-source and floor read for one exact QFP6 block. The returned
    /// authorization token is height-bound and cannot be reused for the next block.
    pub fn authorize_for_block(
        &mut self,
        network_id: &[u8; 32],
        profile_id: &[u8; 32],
        quote_asset_id: &[u8; 32],
        block_height: u64,
    ) -> Result<QRunV06TrustAuthorizedQuoteAsset, QRunV06ProfileTrustError> {
        let authorized_profile = authorize_qrun_v06_profile_pin_from_source(
            Some(self.profile_pin_bytes),
            self.trust_source,
            self.authority,
            self.pq_verifier,
            self.floor_store,
            *network_id,
            *profile_id,
        )?;
        let authorized_quote = authorized_profile.authorize_quote_asset(
            self.q6qa_bundle_bytes,
            block_height,
            self.transaction_authenticator,
        )?;
        authorized_quote.require_for_pair(network_id, profile_id, quote_asset_id, block_height)?;
        Ok(authorized_quote)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        external_cas_anchor_candidate::ExternalCasPin,
        qrun_v06_genesis_descriptor_candidate::QRunV06GenesisDescriptor,
        qrun_v06_profile_pin_candidate::{QRunV06ProfilePinCandidate, QRunV06QuoteAssetTrustPin},
        qrun_v06_quote_asset_qualification_candidate::{
            CustodyModel, QRunV06QuoteAssetQualificationCandidate,
            QRunV06SignedQuoteAssetQualificationCandidate, QualificationStatus, RedemptionModel,
        },
        state_machine::AccountId,
        v4_fat1_mldsa65_candidate::LibcruxMlDsa65VerifierCandidate,
    };
    use ed25519_dalek::{Signer, SigningKey};
    use libcrux_ml_dsa::ml_dsa_65::portable;

    const NETWORK: [u8; 32] = [0xA1; 32];
    const PROFILE: [u8; 32] = [0xA2; 32];
    const FOUNDER: [u8; 32] = [0xA3; 32];

    #[derive(Clone)]
    struct MemoryTrustFloor {
        floor: TrustedQRunV06ProfileTrustFloor,
        unavailable: bool,
        fail_cas_before_write: bool,
        fail_cas_after_write: bool,
    }

    impl MonotonicQRunV06ProfileTrustFloorStore for MemoryTrustFloor {
        fn load(
            &self,
            network_id: &[u8; 32],
            profile_id: &[u8; 32],
        ) -> Result<TrustedQRunV06ProfileTrustFloor, QRunV06ProfileTrustError> {
            if self.unavailable {
                return Err(QRunV06ProfileTrustError::FloorUnavailable);
            }
            if &self.floor.network_id != network_id || &self.floor.profile_id != profile_id {
                return Err(QRunV06ProfileTrustError::WrongNetworkOrProfile);
            }
            Ok(self.floor.clone())
        }

        fn compare_and_swap(
            &mut self,
            expected: &TrustedQRunV06ProfileTrustFloor,
            next: &TrustedQRunV06ProfileTrustFloor,
        ) -> Result<(), QRunV06ProfileTrustError> {
            if self.unavailable || self.fail_cas_before_write || self.floor != *expected {
                return Err(QRunV06ProfileTrustError::FloorCasConflict);
            }
            self.floor = next.clone();
            if self.fail_cas_after_write {
                return Err(QRunV06ProfileTrustError::FloorUnavailable);
            }
            Ok(())
        }
    }

    struct TrustFixture {
        authority: PinnedQRunV06ProfileTrustAuthority,
        ed_signing_key: SigningKey,
        profile_bytes: Vec<u8>,
        profile_commitment: [u8; 32],
        verifier: LibcruxMlDsa65VerifierCandidate,
    }

    impl TrustFixture {
        fn new(provider_marker: u8) -> Self {
            let ed_signing_key = SigningKey::from_bytes(&[0x61; 32]);
            let pq_pair = portable::generate_key_pair([0x62; 32]);
            let authority = PinnedQRunV06ProfileTrustAuthority {
                ed25519_public_key: ed_signing_key.verifying_key().to_bytes(),
                mldsa65_public_key: *pq_pair.verification_key.as_ref(),
            };
            let descriptor = QRunV06GenesisDescriptor::new(
                NETWORK,
                PROFILE,
                FOUNDER,
                1_800_000_000,
                [0xA4; 32],
                [0xA5; 32],
            )
            .unwrap();
            let bundle = QRunV06ProfilePinCandidate::new(
                descriptor,
                ExternalCasPin {
                    provider_id: [provider_marker; 32],
                    network_id: NETWORK,
                    genesis_digest: [0xA6; 32],
                    receipt_key_id: [provider_marker.wrapping_add(1); 32],
                    receipt_public_key: [0xA7; ML_DSA_65_PUBLIC_KEY_BYTES],
                },
            )
            .unwrap();
            let profile_bytes = bundle.encode().unwrap().to_vec();
            let profile_commitment = bundle.commitment().unwrap();
            Self {
                authority,
                ed_signing_key,
                profile_bytes,
                profile_commitment,
                verifier: LibcruxMlDsa65VerifierCandidate,
            }
        }

        fn sign(&self, record: QRunV06ProfileTrustRecord) -> QRunV06SignedProfileTrustEnvelope {
            let keyset_id = self.authority.keyset_id().unwrap();
            let digest = record.signing_digest(&keyset_id).unwrap();
            let ed25519_signature = self.ed_signing_key.sign(&digest).to_bytes();
            let pq_pair = portable::generate_key_pair([0x62; 32]);
            let pq_signature =
                portable::sign(&pq_pair.signing_key, &digest, &[], [0x63; 32]).unwrap();
            QRunV06SignedProfileTrustEnvelope {
                record,
                authority_keyset_id: keyset_id,
                ed25519_signature,
                mldsa65_signature: *pq_signature.as_ref(),
            }
        }

        fn record(
            &self,
            epoch: u64,
            status: QRunV06ProfileTrustStatus,
            commitment: [u8; 32],
            previous_record_id: [u8; 32],
        ) -> QRunV06ProfileTrustRecord {
            QRunV06ProfileTrustRecord {
                trust_epoch: epoch,
                status,
                network_id: NETWORK,
                profile_id: PROFILE,
                profile_pin_commitment: commitment,
                previous_record_id,
            }
        }

        fn floor_store(&self) -> MemoryTrustFloor {
            MemoryTrustFloor {
                floor: TrustedQRunV06ProfileTrustFloor::initial(NETWORK, PROFILE).unwrap(),
                unavailable: false,
                fail_cas_before_write: false,
                fail_cas_after_write: false,
            }
        }

        fn prepublish(
            &self,
            envelope: &QRunV06SignedProfileTrustEnvelope,
            floor: &mut MemoryTrustFloor,
        ) {
            prepublish_qrun_v06_profile_trust_floor(
                &envelope.encode().unwrap(),
                &self.authority,
                &self.verifier,
                floor,
            )
            .unwrap();
        }
    }

    struct CountingTrustSource {
        envelope: Vec<u8>,
        reads: std::rc::Rc<std::cell::Cell<usize>>,
    }

    impl QRunV06ProfileTrustSource for CountingTrustSource {
        type Error = String;

        fn read_current_signed_record(
            &mut self,
            network_id: &[u8; 32],
            profile_id: &[u8; 32],
        ) -> Result<Vec<u8>, Self::Error> {
            if network_id != &NETWORK || profile_id != &PROFILE {
                return Err("wrong network/profile".into());
            }
            self.reads.set(self.reads.get().saturating_add(1));
            Ok(self.envelope.clone())
        }
    }

    struct Q6QaTestAuthenticator;

    impl TransactionAuthenticator for Q6QaTestAuthenticator {
        fn verify(
            &self,
            sender: &AccountId,
            digest: &[u8; 32],
            signature: &[u8],
        ) -> Result<(), ()> {
            if *sender == [0x88; 32] && signature == digest {
                Ok(())
            } else {
                Err(())
            }
        }
    }

    fn signed_q6qa_fixture() -> QRunV06SignedQuoteAssetQualificationCandidate {
        let record = QRunV06QuoteAssetQualificationCandidate {
            network_id: NETWORK,
            profile_id: PROFILE,
            asset_id: [0xB1; 32],
            external_chain_id: [0xB2; 32],
            issuer_id: [0xB3; 32],
            custodian_id: [0xB4; 32],
            bridge_id: [0; 32],
            reserve_evidence_digest: [0xB5; 32],
            redemption_evidence_digest: [0xB6; 32],
            control_risk_evidence_digest: [0xB7; 32],
            authority_key_id: [0xAA; 32],
            authority_account: [0x88; 32],
            qualification_epoch: 3,
            valid_from_height: 100,
            valid_until_height: 200,
            decimals: 6,
            custody_model: CustodyModel::IndependentCustodian,
            redemption_model: RedemptionModel::CustodianRedemption,
            status: QualificationStatus::Approved,
            contract_address: vec![0xB8; 20],
            symbol: "USDT".into(),
            representation: "USDT ERC-20 on independently reviewed chain".into(),
        };
        let signature = record.signing_digest().unwrap().to_vec();
        QRunV06SignedQuoteAssetQualificationCandidate { record, signature }
    }

    #[test]
    fn q6ts_authorizes_q6qa_only_through_q6pn_v2_and_profile_floor() {
        let fixture = TrustFixture::new(0x81);
        let original_pin = QRunV06ProfilePinCandidate::decode_pinned(
            &fixture.profile_bytes,
            fixture.profile_commitment,
        )
        .unwrap();
        let q6qa = signed_q6qa_fixture();
        let q6qa_commitment = q6qa.commitment().unwrap();
        let quote_pin = QRunV06QuoteAssetTrustPin::new(
            1,
            q6qa_commitment,
            q6qa.record.asset_id,
            q6qa.record.authority_key_id,
            q6qa.record.authority_account,
            q6qa.record.qualification_epoch,
        )
        .unwrap();
        let q6pn_v2 = QRunV06ProfilePinCandidate::new_with_quote_asset_trust_pin(
            *original_pin.descriptor(),
            original_pin.external_cas_pin().clone(),
            quote_pin,
        )
        .unwrap();
        let q6pn_v2_bytes = q6pn_v2.encode().unwrap();
        let q6pn_v2_commitment = q6pn_v2.commitment().unwrap();

        let signed_q6ts = fixture.sign(fixture.record(
            1,
            QRunV06ProfileTrustStatus::Active,
            q6pn_v2_commitment,
            [0; 32],
        ));
        let signed_q6ts_bytes = signed_q6ts.encode().unwrap();
        let mut floor = fixture.floor_store();
        fixture.prepublish(&signed_q6ts, &mut floor);

        let authorized_profile = authorize_qrun_v06_profile_pin(
            Some(&q6pn_v2_bytes),
            &signed_q6ts_bytes,
            &fixture.authority,
            &fixture.verifier,
            &mut floor,
            NETWORK,
            PROFILE,
        )
        .unwrap();

        let q6qa_bytes = q6qa.encode().unwrap();
        let authorized_quote = authorized_profile
            .authorize_quote_asset(&q6qa_bytes, 150, &Q6QaTestAuthenticator)
            .unwrap();
        assert_eq!(
            authorized_quote.qualification().asset_id(),
            q6qa.record.asset_id
        );
        assert_eq!(
            authorized_quote.qualification().commitment(),
            q6qa_commitment
        );
        assert_eq!(
            authorized_quote.profile_pin_commitment(),
            q6pn_v2_commitment
        );
        assert_eq!(authorized_quote.profile_trust_epoch(), 1);
        assert_eq!(
            authorized_quote.require_for_pair(&NETWORK, &PROFILE, &[0xB1; 32], 150),
            Ok(())
        );
        assert!(matches!(
            authorized_quote.require_for_pair(&NETWORK, &PROFILE, &[0xB9; 32], 150),
            Err(QRunV06ProfileTrustError::QuoteAssetQualification(
                Q6QaError::WrongAsset
            ))
        ));

        let mut mutated_q6qa = q6qa_bytes.clone();
        mutated_q6qa[32] ^= 1;
        assert!(matches!(
            authorized_profile.authorize_quote_asset(&mutated_q6qa, 150, &Q6QaTestAuthenticator),
            Err(QRunV06ProfileTrustError::QuoteAssetQualification(
                Q6QaError::CommitmentMismatch
            ))
        ));
    }

    #[test]
    fn q6ts_fresh_quote_provider_reloads_source_and_floor_for_every_block_and_stops_on_revoke() {
        let fixture = TrustFixture::new(0x85);
        let original_pin = QRunV06ProfilePinCandidate::decode_pinned(
            &fixture.profile_bytes,
            fixture.profile_commitment,
        )
        .unwrap();
        let q6qa = signed_q6qa_fixture();
        let q6qa_commitment = q6qa.commitment().unwrap();
        let quote_pin = QRunV06QuoteAssetTrustPin::new(
            1,
            q6qa_commitment,
            q6qa.record.asset_id,
            q6qa.record.authority_key_id,
            q6qa.record.authority_account,
            q6qa.record.qualification_epoch,
        )
        .unwrap();
        let q6pn_v2 = QRunV06ProfilePinCandidate::new_with_quote_asset_trust_pin(
            *original_pin.descriptor(),
            original_pin.external_cas_pin().clone(),
            quote_pin,
        )
        .unwrap();
        let q6pn_v2_bytes = q6pn_v2.encode().unwrap();
        let q6pn_v2_commitment = q6pn_v2.commitment().unwrap();
        let active = fixture.sign(fixture.record(
            1,
            QRunV06ProfileTrustStatus::Active,
            q6pn_v2_commitment,
            [0; 32],
        ));
        let active_bytes = active.encode().unwrap();
        let mut floor = fixture.floor_store();
        fixture.prepublish(&active, &mut floor);
        let reads = std::rc::Rc::new(std::cell::Cell::new(0));
        let mut source = CountingTrustSource {
            envelope: active_bytes.to_vec(),
            reads: std::rc::Rc::clone(&reads),
        };
        let q6qa_bytes = q6qa.encode().unwrap();

        let (first, second) = {
            let mut provider = QRunV06FreshQuoteAssetAuthorizationProvider::new(
                &q6pn_v2_bytes,
                &q6qa_bytes,
                &fixture.authority,
                &fixture.verifier,
                &mut floor,
                &mut source,
                &Q6QaTestAuthenticator,
            );
            let first = provider
                .authorize_for_block(&NETWORK, &PROFILE, &q6qa.record.asset_id, 150)
                .unwrap();
            let second = provider
                .authorize_for_block(&NETWORK, &PROFILE, &q6qa.record.asset_id, 151)
                .unwrap();
            (first, second)
        };
        assert_eq!(
            reads.get(),
            2,
            "source must be re-read for both block heights"
        );
        assert_eq!(
            first.require_for_pair(&NETWORK, &PROFILE, &q6qa.record.asset_id, 150),
            Ok(())
        );
        assert!(matches!(
            first.require_for_pair(&NETWORK, &PROFILE, &q6qa.record.asset_id, 151),
            Err(QRunV06ProfileTrustError::QuoteAssetQualification(
                Q6QaError::AuthorizationHeightMismatch
            ))
        ));
        assert_eq!(
            second.require_for_pair(&NETWORK, &PROFILE, &q6qa.record.asset_id, 151),
            Ok(())
        );

        let revoked = fixture.sign(fixture.record(
            2,
            QRunV06ProfileTrustStatus::Revoked,
            q6pn_v2_commitment,
            active.record.record_id().unwrap(),
        ));
        fixture.prepublish(&revoked, &mut floor);
        source.envelope = revoked.encode().unwrap().to_vec();
        let mut provider = QRunV06FreshQuoteAssetAuthorizationProvider::new(
            &q6pn_v2_bytes,
            &q6qa_bytes,
            &fixture.authority,
            &fixture.verifier,
            &mut floor,
            &mut source,
            &Q6QaTestAuthenticator,
        );
        assert_eq!(
            provider.authorize_for_block(&NETWORK, &PROFILE, &q6qa.record.asset_id, 152),
            Err(QRunV06ProfileTrustError::ProfileRevoked)
        );
        assert_eq!(
            reads.get(),
            3,
            "revocation attempt must perform a fresh source read"
        );
    }

    #[test]
    fn q6ts_v1_profile_pin_without_q6qa_extension_cannot_authorize_market_quote() {
        let fixture = TrustFixture::new(0x82);
        let signed_q6ts = fixture.sign(fixture.record(
            1,
            QRunV06ProfileTrustStatus::Active,
            fixture.profile_commitment,
            [0; 32],
        ));
        let signed_q6ts_bytes = signed_q6ts.encode().unwrap();
        let mut floor = fixture.floor_store();
        fixture.prepublish(&signed_q6ts, &mut floor);
        let authorized_profile = authorize_qrun_v06_profile_pin(
            Some(&fixture.profile_bytes),
            &signed_q6ts_bytes,
            &fixture.authority,
            &fixture.verifier,
            &mut floor,
            NETWORK,
            PROFILE,
        )
        .unwrap();
        let q6qa = signed_q6qa_fixture();
        assert_eq!(
            authorized_profile.authorize_quote_asset(
                &q6qa.encode().unwrap(),
                150,
                &Q6QaTestAuthenticator
            ),
            Err(QRunV06ProfileTrustError::MissingQuoteAssetTrustPin)
        );
    }

    #[test]
    fn q6ts_record_and_envelope_are_canonical_fixed_width() {
        let fixture = TrustFixture::new(0x71);
        let record = fixture.record(
            1,
            QRunV06ProfileTrustStatus::Active,
            fixture.profile_commitment,
            [0; 32],
        );
        let record_bytes = record.encode().unwrap();
        assert_eq!(record_bytes.len(), QRUN_V06_PROFILE_TRUST_RECORD_BYTES);
        assert_eq!(
            QRunV06ProfileTrustRecord::decode(&record_bytes).unwrap(),
            record
        );

        let envelope = fixture.sign(record);
        let bytes = envelope.encode().unwrap();
        assert_eq!(bytes.len(), QRUN_V06_PROFILE_TRUST_ENVELOPE_BYTES);
        assert_eq!(
            QRunV06SignedProfileTrustEnvelope::decode(&bytes).unwrap(),
            envelope
        );

        let mut reserved = bytes;
        reserved[7] = 1;
        assert_eq!(
            QRunV06SignedProfileTrustEnvelope::decode(&reserved),
            Err(QRunV06ProfileTrustError::NonzeroReserved)
        );
    }

    #[test]
    fn q6ts_authorizes_q6pn_only_after_dual_signature_and_prepublished_floor() {
        let fixture = TrustFixture::new(0x71);
        let record = fixture.record(
            1,
            QRunV06ProfileTrustStatus::Active,
            fixture.profile_commitment,
            [0; 32],
        );
        let envelope = fixture.sign(record);
        let bytes = envelope.encode().unwrap();
        let mut floor = fixture.floor_store();
        fixture.prepublish(&envelope, &mut floor);

        let authorized = authorize_qrun_v06_profile_pin(
            Some(&fixture.profile_bytes),
            &bytes,
            &fixture.authority,
            &fixture.verifier,
            &mut floor,
            NETWORK,
            PROFILE,
        )
        .unwrap();

        assert_eq!(authorized.trust_epoch(), 1);
        assert_eq!(
            authorized.verified_profile_pin().profile_pin_commitment(),
            fixture.profile_commitment
        );
        assert_eq!(floor.floor.trust_epoch, 1);
        assert_eq!(floor.floor.status, Some(QRunV06ProfileTrustStatus::Active));

        // Exact current trust envelopes are idempotent across restart/retry.
        let repeated = authorize_qrun_v06_profile_pin(
            Some(&fixture.profile_bytes),
            &bytes,
            &fixture.authority,
            &fixture.verifier,
            &mut floor,
            NETWORK,
            PROFILE,
        )
        .unwrap();
        assert_eq!(repeated, authorized);
    }

    #[test]
    fn q6ts_node_startup_never_advances_an_unpublished_trust_floor() {
        let fixture = TrustFixture::new(0x71);
        let envelope = fixture.sign(fixture.record(
            1,
            QRunV06ProfileTrustStatus::Active,
            fixture.profile_commitment,
            [0; 32],
        ));
        let mut floor = fixture.floor_store();
        assert_eq!(
            authorize_qrun_v06_profile_pin(
                Some(&fixture.profile_bytes),
                &envelope.encode().unwrap(),
                &fixture.authority,
                &fixture.verifier,
                &mut floor,
                NETWORK,
                PROFILE,
            ),
            Err(QRunV06ProfileTrustError::FloorCasConflict)
        );
        assert_eq!(floor.floor.trust_epoch, 0);
        fixture.prepublish(&envelope, &mut floor);
        assert_eq!(floor.floor.trust_epoch, 1);
    }

    #[test]
    fn q6ts_profile_pin_rotation_requires_one_signed_successor_and_rejects_old_pin() {
        let old_fixture = TrustFixture::new(0x71);
        let first = old_fixture.sign(old_fixture.record(
            1,
            QRunV06ProfileTrustStatus::Active,
            old_fixture.profile_commitment,
            [0; 32],
        ));
        let mut floor = old_fixture.floor_store();
        let first_bytes = first.encode().unwrap();
        old_fixture.prepublish(&first, &mut floor);
        authorize_qrun_v06_profile_pin(
            Some(&old_fixture.profile_bytes),
            &first_bytes,
            &old_fixture.authority,
            &old_fixture.verifier,
            &mut floor,
            NETWORK,
            PROFILE,
        )
        .unwrap();

        let new_fixture = TrustFixture::new(0x72);
        let second = new_fixture.sign(new_fixture.record(
            2,
            QRunV06ProfileTrustStatus::Active,
            new_fixture.profile_commitment,
            first.record.record_id().unwrap(),
        ));
        let second_bytes = second.encode().unwrap();
        new_fixture.prepublish(&second, &mut floor);

        // A signed trust record cannot smuggle a different Q6PN byte bundle.
        assert!(matches!(
            authorize_qrun_v06_profile_pin(
                Some(&old_fixture.profile_bytes),
                &second_bytes,
                &new_fixture.authority,
                &new_fixture.verifier,
                &mut floor,
                NETWORK,
                PROFILE,
            ),
            Err(QRunV06ProfileTrustError::ProfilePin(
                QRunV06ProfilePinError::ProfilePinCommitmentMismatch
            ))
        ));
        assert_eq!(floor.floor.trust_epoch, 2);

        let authorized = authorize_qrun_v06_profile_pin(
            Some(&new_fixture.profile_bytes),
            &second_bytes,
            &new_fixture.authority,
            &new_fixture.verifier,
            &mut floor,
            NETWORK,
            PROFILE,
        )
        .unwrap();
        assert_eq!(authorized.trust_epoch(), 2);
        assert_eq!(
            authorized.verified_profile_pin().profile_pin_commitment(),
            new_fixture.profile_commitment
        );

        assert_eq!(
            authorize_qrun_v06_profile_pin(
                Some(&old_fixture.profile_bytes),
                &first_bytes,
                &old_fixture.authority,
                &old_fixture.verifier,
                &mut floor,
                NETWORK,
                PROFILE,
            ),
            Err(QRunV06ProfileTrustError::Rollback)
        );
    }

    #[test]
    fn q6ts_revocation_advances_floor_and_makes_the_profile_terminal() {
        let fixture = TrustFixture::new(0x71);
        let first = fixture.sign(fixture.record(
            1,
            QRunV06ProfileTrustStatus::Active,
            fixture.profile_commitment,
            [0; 32],
        ));
        let mut floor = fixture.floor_store();
        fixture.prepublish(&first, &mut floor);
        authorize_qrun_v06_profile_pin(
            Some(&fixture.profile_bytes),
            &first.encode().unwrap(),
            &fixture.authority,
            &fixture.verifier,
            &mut floor,
            NETWORK,
            PROFILE,
        )
        .unwrap();

        let revoked = fixture.sign(fixture.record(
            2,
            QRunV06ProfileTrustStatus::Revoked,
            fixture.profile_commitment,
            first.record.record_id().unwrap(),
        ));
        fixture.prepublish(&revoked, &mut floor);
        assert_eq!(
            authorize_qrun_v06_profile_pin(
                None,
                &revoked.encode().unwrap(),
                &fixture.authority,
                &fixture.verifier,
                &mut floor,
                NETWORK,
                PROFILE,
            ),
            Err(QRunV06ProfileTrustError::ProfileRevoked)
        );
        assert_eq!(floor.floor.trust_epoch, 2);
        assert_eq!(floor.floor.status, Some(QRunV06ProfileTrustStatus::Revoked));

        let attempted_reactivation = fixture.sign(fixture.record(
            3,
            QRunV06ProfileTrustStatus::Active,
            fixture.profile_commitment,
            revoked.record.record_id().unwrap(),
        ));
        assert_eq!(
            authorize_qrun_v06_profile_pin(
                Some(&fixture.profile_bytes),
                &attempted_reactivation.encode().unwrap(),
                &fixture.authority,
                &fixture.verifier,
                &mut floor,
                NETWORK,
                PROFILE,
            ),
            Err(QRunV06ProfileTrustError::ProfileRevoked)
        );
        assert_eq!(floor.floor.trust_epoch, 2);
    }

    #[test]
    fn q6ts_rejects_bad_signatures_keyset_context_epoch_gaps_and_predecessors() {
        let fixture = TrustFixture::new(0x71);
        let record = fixture.record(
            1,
            QRunV06ProfileTrustStatus::Active,
            fixture.profile_commitment,
            [0; 32],
        );
        let valid = fixture.sign(record.clone());
        let floor = TrustedQRunV06ProfileTrustFloor::initial(NETWORK, PROFILE).unwrap();

        let mut wrong_ed = valid.clone();
        wrong_ed.ed25519_signature[0] ^= 1;
        assert_eq!(
            verify_qrun_v06_profile_trust_envelope(
                &wrong_ed,
                &fixture.authority,
                &fixture.verifier,
                &floor,
            ),
            Err(QRunV06ProfileTrustError::InvalidEd25519Signature)
        );

        let mut wrong_pq = valid.clone();
        wrong_pq.mldsa65_signature[0] ^= 1;
        assert_eq!(
            verify_qrun_v06_profile_trust_envelope(
                &wrong_pq,
                &fixture.authority,
                &fixture.verifier,
                &floor,
            ),
            Err(QRunV06ProfileTrustError::InvalidMlDsa65Signature)
        );

        let mut wrong_keyset = valid.clone();
        wrong_keyset.authority_keyset_id[0] ^= 1;
        assert_eq!(
            verify_qrun_v06_profile_trust_envelope(
                &wrong_keyset,
                &fixture.authority,
                &fixture.verifier,
                &floor,
            ),
            Err(QRunV06ProfileTrustError::WrongAuthorityKeyset)
        );

        let other_floor = TrustedQRunV06ProfileTrustFloor::initial([0xB1; 32], PROFILE).unwrap();
        assert_eq!(
            verify_qrun_v06_profile_trust_envelope(
                &valid,
                &fixture.authority,
                &fixture.verifier,
                &other_floor,
            ),
            Err(QRunV06ProfileTrustError::WrongNetworkOrProfile)
        );

        let gap = fixture.sign(fixture.record(
            2,
            QRunV06ProfileTrustStatus::Active,
            fixture.profile_commitment,
            [0xB2; 32],
        ));
        assert_eq!(
            verify_qrun_v06_profile_trust_envelope(
                &gap,
                &fixture.authority,
                &fixture.verifier,
                &floor,
            ),
            Err(QRunV06ProfileTrustError::EpochGap)
        );
    }

    #[test]
    fn q6ts_floor_unavailability_and_cas_conflicts_fail_closed() {
        let fixture = TrustFixture::new(0x71);
        let envelope = fixture.sign(fixture.record(
            1,
            QRunV06ProfileTrustStatus::Active,
            fixture.profile_commitment,
            [0; 32],
        ));
        let bytes = envelope.encode().unwrap();

        let mut unavailable = fixture.floor_store();
        unavailable.unavailable = true;
        assert_eq!(
            authorize_qrun_v06_profile_pin(
                Some(&fixture.profile_bytes),
                &bytes,
                &fixture.authority,
                &fixture.verifier,
                &mut unavailable,
                NETWORK,
                PROFILE,
            ),
            Err(QRunV06ProfileTrustError::FloorUnavailable)
        );

        let mut failed = fixture.floor_store();
        failed.fail_cas_before_write = true;
        assert_eq!(
            authorize_qrun_v06_profile_pin(
                Some(&fixture.profile_bytes),
                &bytes,
                &fixture.authority,
                &fixture.verifier,
                &mut failed,
                NETWORK,
                PROFILE,
            ),
            Err(QRunV06ProfileTrustError::FloorCasConflict)
        );
        assert_eq!(failed.floor.trust_epoch, 0);

        // Lost response after a successful provider CAS is reconciled by exact read-back.
        let mut ambiguous = fixture.floor_store();
        ambiguous.fail_cas_after_write = true;
        fixture.prepublish(&envelope, &mut ambiguous);
        let authorized = authorize_qrun_v06_profile_pin(
            Some(&fixture.profile_bytes),
            &bytes,
            &fixture.authority,
            &fixture.verifier,
            &mut ambiguous,
            NETWORK,
            PROFILE,
        )
        .unwrap();
        assert_eq!(authorized.trust_epoch(), 1);
        assert_eq!(ambiguous.floor.trust_epoch, 1);
    }

    struct StaticTrustSource(Vec<u8>);
    impl QRunV06ProfileTrustSource for StaticTrustSource {
        type Error = &'static str;

        fn read_current_signed_record(
            &mut self,
            _: &[u8; 32],
            _: &[u8; 32],
        ) -> Result<Vec<u8>, Self::Error> {
            Ok(self.0.clone())
        }
    }

    #[test]
    fn q6ts_source_path_uses_same_signature_and_monotonic_floor_contract() {
        let fixture = TrustFixture::new(0x71);
        let envelope = fixture.sign(fixture.record(
            1,
            QRunV06ProfileTrustStatus::Active,
            fixture.profile_commitment,
            [0; 32],
        ));
        let mut source = StaticTrustSource(envelope.encode().unwrap().to_vec());
        let mut floor = fixture.floor_store();
        fixture.prepublish(&envelope, &mut floor);
        let authorized = authorize_qrun_v06_profile_pin_from_source(
            Some(&fixture.profile_bytes),
            &mut source,
            &fixture.authority,
            &fixture.verifier,
            &mut floor,
            NETWORK,
            PROFILE,
        )
        .unwrap();
        assert_eq!(authorized.trust_epoch(), 1);
    }
}

/// Exact historical cryptographic payloads are fetched by immutable entry ID.
/// The history source is not trusted for integrity; every commitment and signature is checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QRunV06HistoricalQuoteAssetTrustEvidence {
    pub q6ts_envelope_bytes: Vec<u8>,
    pub q6pn_profile_pin_bytes: Vec<u8>,
    pub q6qa_bundle_bytes: Vec<u8>,
}

pub trait QRunV06HistoricalTrustHistorySource {
    type Error: fmt::Display;

    fn read_history_snapshot_for_checkpoint(
        &mut self,
        network_id: &[u8; 32],
        profile_id: &[u8; 32],
        checkpoint: &crate::qrun_v06_historical_trust_candidate::QRunV06SignedHistoricalTrustCheckpoint,
    ) -> Result<
        crate::qrun_v06_historical_trust_candidate::QRunV06HistoricalTrustHistorySnapshot,
        Self::Error,
    >;

    fn read_entry_evidence(
        &mut self,
        entry_id: &[u8; 32],
    ) -> Result<QRunV06HistoricalQuoteAssetTrustEvidence, Self::Error>;
}

/// This store must be administered separately from both the node archive and the history source.
/// It must return the latest checkpoint independently pinned strictly before the requested block height,
/// and must not return a later head or a stale prefix when a newer qualifying checkpoint exists.
/// It has no method for a node to advance the trusted history.
pub trait MonotonicQRunV06HistoricalTrustCheckpointStore {
    fn load_trusted_checkpoint_at_or_before_height(
        &self,
        network_id: &[u8; 32],
        profile_id: &[u8; 32],
        block_height: u64,
    ) -> Result<
        crate::qrun_v06_historical_trust_candidate::QRunV06SignedHistoricalTrustCheckpoint,
        QRunV06ProfileTrustError,
    >;
}

/// Historical replay adapter. Unlike the forward-admission adapter, it verifies the complete
/// signed history against an independently pinned head, selects the entry effective at the
/// historical block height, then re-verifies that entry's exact Q6TS/Q6PN/Q6QA bytes. A later
/// rotation bounds the prior entry; a terminal revocation denies blocks from its effective height.
pub struct QRunV06HistoricalQuoteAssetAuthorizationProvider<'a, V, T, C, A> {
    history_authority: &'a PinnedQRunV06ProfileTrustAuthority,
    profile_trust_authority: &'a PinnedQRunV06ProfileTrustAuthority,
    pq_verifier: &'a V,
    history_source: &'a mut T,
    checkpoint_store: &'a C,
    transaction_authenticator: &'a A,
}

impl<'a, V, T, C, A> QRunV06HistoricalQuoteAssetAuthorizationProvider<'a, V, T, C, A>
where
    V: MlDsa65Verifier,
    T: QRunV06HistoricalTrustHistorySource,
    C: MonotonicQRunV06HistoricalTrustCheckpointStore,
    A: TransactionAuthenticator,
{
    pub fn new(
        history_authority: &'a PinnedQRunV06ProfileTrustAuthority,
        profile_trust_authority: &'a PinnedQRunV06ProfileTrustAuthority,
        pq_verifier: &'a V,
        history_source: &'a mut T,
        checkpoint_store: &'a C,
        transaction_authenticator: &'a A,
    ) -> Self {
        Self {
            history_authority,
            profile_trust_authority,
            pq_verifier,
            history_source,
            checkpoint_store,
            transaction_authenticator,
        }
    }

    pub fn authorize_for_block(
        &mut self,
        network_id: &[u8; 32],
        profile_id: &[u8; 32],
        quote_asset_id: &[u8; 32],
        block_height: u64,
    ) -> Result<QRunV06TrustAuthorizedQuoteAsset, QRunV06ProfileTrustError> {
        use crate::qrun_v06_historical_trust_candidate::{
            verify_qrun_v06_historical_trust_history, QRunV06HistoricalTrustError,
        };

        let pinned_checkpoint = self
            .checkpoint_store
            .load_trusted_checkpoint_at_or_before_height(network_id, profile_id, block_height)?;
        let snapshot = self
            .history_source
            .read_history_snapshot_for_checkpoint(network_id, profile_id, &pinned_checkpoint)
            .map_err(|error| QRunV06ProfileTrustError::TrustSourceUnavailable(error.to_string()))?;
        if pinned_checkpoint.record.published_at_height >= block_height {
            return Err(QRunV06ProfileTrustError::HistoricalTrustHistory(
                QRunV06HistoricalTrustError::CheckpointNotPrepublished.to_string(),
            ));
        }
        let history = verify_qrun_v06_historical_trust_history(
            &snapshot,
            &pinned_checkpoint,
            self.history_authority,
            self.pq_verifier,
            network_id,
            profile_id,
        )
        .map_err(|error| QRunV06ProfileTrustError::HistoricalTrustHistory(error.to_string()))?;

        let (entry, valid_until_height) = history
            .entry_for_height(block_height)
            .map_err(|error| QRunV06ProfileTrustError::HistoricalTrustHistory(error.to_string()))?;
        if block_height >= valid_until_height {
            return Err(QRunV06ProfileTrustError::HistoricalTrustHistory(
                QRunV06HistoricalTrustError::NoEffectiveEntry.to_string(),
            ));
        }
        if entry.record.status != QRunV06ProfileTrustStatus::Active {
            return Err(QRunV06ProfileTrustError::ProfileRevoked);
        }

        let entry_id = entry
            .entry_id()
            .map_err(|error| QRunV06ProfileTrustError::HistoricalTrustHistory(error.to_string()))?;
        let evidence = self
            .history_source
            .read_entry_evidence(&entry_id)
            .map_err(|error| QRunV06ProfileTrustError::TrustSourceUnavailable(error.to_string()))?;

        let envelope = QRunV06SignedProfileTrustEnvelope::decode(&evidence.q6ts_envelope_bytes)?;
        let record_id = envelope.record.record_id()?;
        let envelope_id = envelope.envelope_id()?;
        if envelope.record.network_id != *network_id
            || envelope.record.profile_id != *profile_id
            || envelope.record.trust_epoch != entry.record.sequence
            || envelope.record.status != entry.record.status
            || record_id != entry.record.q6ts_record_id
            || envelope_id != entry.record.q6ts_envelope_id
            || envelope.record.profile_pin_commitment != entry.record.profile_pin_commitment
            || envelope.record.previous_record_id != entry.record.previous_q6ts_record_id
        {
            return Err(QRunV06ProfileTrustError::HistoricalTrustHistory(
                "Q6TS record does not match immutable history entry".to_owned(),
            ));
        }

        let floor = if entry.record.sequence == 1 {
            TrustedQRunV06ProfileTrustFloor::initial(*network_id, *profile_id)?
        } else {
            let previous = history
                .entries()
                .get(entry.record.sequence as usize - 2)
                .ok_or(QRunV06ProfileTrustError::HistoricalTrustHistory(
                    "missing predecessor history entry".to_owned(),
                ))?;
            if previous.record.status != QRunV06ProfileTrustStatus::Active
                || previous.record.q6ts_record_id != entry.record.previous_q6ts_record_id
                || previous.record.q6ts_envelope_id != entry.record.previous_q6ts_envelope_id
            {
                return Err(QRunV06ProfileTrustError::HistoricalTrustHistory(
                    "Q6TS predecessor history mismatch".to_owned(),
                ));
            }
            TrustedQRunV06ProfileTrustFloor::provisioned(
                *network_id,
                *profile_id,
                previous.record.sequence,
                previous.record.status,
                previous.record.q6ts_record_id,
                previous.record.q6ts_envelope_id,
            )?
        };
        let verified_trust = verify_qrun_v06_profile_trust_envelope(
            &envelope,
            self.profile_trust_authority,
            self.pq_verifier,
            &floor,
        )?;
        if verified_trust.record_id() != entry.record.q6ts_record_id
            || verified_trust.envelope_id() != entry.record.q6ts_envelope_id
            || verified_trust.record().status != QRunV06ProfileTrustStatus::Active
        {
            return Err(QRunV06ProfileTrustError::HistoricalTrustHistory(
                "Q6TS signature verification differs from history head".to_owned(),
            ));
        }

        let verified_profile_pin = QRunV06VerifiedProfilePin::decode(
            &evidence.q6pn_profile_pin_bytes,
            entry.record.profile_pin_commitment,
        )?;
        let descriptor = verified_profile_pin.descriptor();
        if descriptor.network_id() != *network_id || descriptor.profile_id() != *profile_id {
            return Err(QRunV06ProfileTrustError::ProfilePinContextMismatch);
        }
        let quote_pin = verified_profile_pin
            .quote_asset_trust_pin()
            .ok_or(QRunV06ProfileTrustError::MissingQuoteAssetTrustPin)?;
        if quote_pin.q6qa_bundle_commitment() != entry.record.q6qa_commitment
            || quote_pin.asset_id() != entry.record.quote_asset_id
            || quote_pin.qualification_epoch() != entry.record.qualification_epoch
        {
            return Err(QRunV06ProfileTrustError::HistoricalTrustHistory(
                "Q6PN quote pin differs from historical Q6QA receipt".to_owned(),
            ));
        }

        let authorized_profile = QRunV06TrustAuthorizedProfilePin {
            verified_profile_pin,
            trust_epoch: entry.record.sequence,
            trust_record_id: entry.record.q6ts_record_id,
            trust_envelope_id: entry.record.q6ts_envelope_id,
        };
        let authorized_quote = authorized_profile.authorize_quote_asset(
            &evidence.q6qa_bundle_bytes,
            block_height,
            self.transaction_authenticator,
        )?;
        authorized_quote.require_for_pair(network_id, profile_id, quote_asset_id, block_height)?;
        if authorized_quote.qualification().commitment() != entry.record.q6qa_commitment
            || authorized_quote.qualification().qualification_epoch()
                != entry.record.qualification_epoch
        {
            return Err(QRunV06ProfileTrustError::HistoricalTrustHistory(
                "Q6QA verification differs from historical receipt".to_owned(),
            ));
        }
        Ok(authorized_quote)
    }
}
