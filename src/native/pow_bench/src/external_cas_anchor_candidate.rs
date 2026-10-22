//! CP-0313: canonical external CAS record/receipt candidate.
//!
//! This is a provider-independent wire contract for evaluating an independently administered
//! immutable log (for example, Cloud Storage create-only objects plus KMS ML-DSA-65 receipts).
//! It does NOT implement networking, cloud credentials, KMS key discovery, operator separation,
//! immutable retention, durable idempotency, or rollback-resistant provider state. It has no
//! consensus/runtime callsite and must not be used to claim Gate 8 or Mainnet readiness.
use crate::v4_fat1_trust_candidate::{
    MlDsa65Verifier, ML_DSA_65_PUBLIC_KEY_BYTES, ML_DSA_65_SIGNATURE_BYTES,
};
use sha2::{Digest, Sha256};
use std::fmt;

pub const EXTERNAL_CAS_RECORD_BYTES: usize = 272;
pub const EXTERNAL_CAS_RECEIPT_PAYLOAD_BYTES: usize = 380;
pub const EXTERNAL_CAS_RECEIPT_BYTES: usize =
    EXTERNAL_CAS_RECEIPT_PAYLOAD_BYTES + ML_DSA_65_SIGNATURE_BYTES;
pub const EXTERNAL_CAS_RECORD_VERSION: u16 = 1;
pub const EXTERNAL_CAS_RECEIPT_VERSION: u16 = 1;

const RECORD_MAGIC: &[u8; 4] = b"ECR1";
const RECEIPT_MAGIC: &[u8; 4] = b"ECS1";
const RECORD_DIGEST_DOMAIN: &[u8] = b"AIN1-EXT-CAS-RECORD-DIGEST-V1\0";
const RECEIPT_SIGNING_DOMAIN: &[u8] = b"AIN1-EXT-CAS-RECEIPT-SIGN-V1\0";
const WRITE_REQUEST_DIGEST_DOMAIN: &[u8] = b"AIN1-EXT-CAS-WRITE-REQUEST-V1\0";
type Digest32 = [u8; 32];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExternalCasError {
    WrongRecordLength,
    WrongReceiptLength,
    WrongMagic,
    UnsupportedVersion,
    NonzeroReserved,
    UnknownReceiptKind,
    UnknownReceiptOutcome,
    ZeroBinding(&'static str),
    InvalidBootstrapLinks,
    InvalidPredecessorLinks,
    WrongDomain,
    NotExactSuccessor,
    RequestMismatch,
    InvalidReceiptShape,
    InvalidSignature,
    CasConflict,
    InvalidObjectGenerationPrecondition,
    ObjectGenerationNotAdvanced,
}
impl fmt::Display for ExternalCasError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for ExternalCasError {}

fn is_zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|b| *b == 0)
}
fn hash_parts(parts: &[&[u8]]) -> Digest32 {
    let mut h = Sha256::new();
    for part in parts {
        h.update(part);
    }
    h.finalize().into()
}
fn take<const N: usize>(bytes: &[u8], start: usize) -> [u8; N] {
    bytes[start..start + N]
        .try_into()
        .expect("fixed length checked")
}
fn u16_at(bytes: &[u8], start: usize) -> u16 {
    u16::from_be_bytes(take(bytes, start))
}
fn u64_at(bytes: &[u8], start: usize) -> u64 {
    u64::from_be_bytes(take(bytes, start))
}
fn push_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_be_bytes());
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalCasRecord {
    /// Logical chain generation; generation zero is the explicit bootstrap record.
    pub generation: u64,
    pub provider_id: Digest32,
    pub network_id: Digest32,
    pub genesis_digest: Digest32,
    pub previous_record_digest: Digest32,
    pub previous_state_digest: Digest32,
    pub next_state_digest: Digest32,
    pub operation_id: Digest32,
    pub request_digest: Digest32,
}
impl ExternalCasRecord {
    pub fn validate_shape(&self) -> Result<(), ExternalCasError> {
        for (name, value) in [
            ("provider_id", &self.provider_id),
            ("network_id", &self.network_id),
            ("genesis_digest", &self.genesis_digest),
            ("next_state_digest", &self.next_state_digest),
            ("operation_id", &self.operation_id),
            ("request_digest", &self.request_digest),
        ] {
            if is_zero(value) {
                return Err(ExternalCasError::ZeroBinding(name));
            }
        }
        if self.generation == 0 {
            if !is_zero(&self.previous_record_digest) || !is_zero(&self.previous_state_digest) {
                return Err(ExternalCasError::InvalidBootstrapLinks);
            }
        } else if is_zero(&self.previous_record_digest) || is_zero(&self.previous_state_digest) {
            return Err(ExternalCasError::InvalidPredecessorLinks);
        }
        Ok(())
    }

    /// ECR1 is fixed-width, big-endian, with reserved bytes required to be zero.
    pub fn encode(&self) -> Result<[u8; EXTERNAL_CAS_RECORD_BYTES], ExternalCasError> {
        self.validate_shape()?;
        let mut out = Vec::with_capacity(EXTERNAL_CAS_RECORD_BYTES);
        out.extend_from_slice(RECORD_MAGIC);
        push_u16(&mut out, EXTERNAL_CAS_RECORD_VERSION);
        push_u16(&mut out, 0);
        out.extend_from_slice(&self.generation.to_be_bytes());
        out.extend_from_slice(&self.provider_id);
        out.extend_from_slice(&self.network_id);
        out.extend_from_slice(&self.genesis_digest);
        out.extend_from_slice(&self.previous_record_digest);
        out.extend_from_slice(&self.previous_state_digest);
        out.extend_from_slice(&self.next_state_digest);
        out.extend_from_slice(&self.operation_id);
        out.extend_from_slice(&self.request_digest);
        out.try_into()
            .map_err(|_| ExternalCasError::WrongRecordLength)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ExternalCasError> {
        if bytes.len() != EXTERNAL_CAS_RECORD_BYTES {
            return Err(ExternalCasError::WrongRecordLength);
        }
        if &bytes[..4] != RECORD_MAGIC {
            return Err(ExternalCasError::WrongMagic);
        }
        if u16_at(bytes, 4) != EXTERNAL_CAS_RECORD_VERSION {
            return Err(ExternalCasError::UnsupportedVersion);
        }
        if u16_at(bytes, 6) != 0 {
            return Err(ExternalCasError::NonzeroReserved);
        }
        let record = Self {
            generation: u64_at(bytes, 8),
            provider_id: take(bytes, 16),
            network_id: take(bytes, 48),
            genesis_digest: take(bytes, 80),
            previous_record_digest: take(bytes, 112),
            previous_state_digest: take(bytes, 144),
            next_state_digest: take(bytes, 176),
            operation_id: take(bytes, 208),
            request_digest: take(bytes, 240),
        };
        record.validate_shape()?;
        Ok(record)
    }

    pub fn digest(&self) -> Result<Digest32, ExternalCasError> {
        let bytes = self.encode()?;
        Ok(hash_parts(&[RECORD_DIGEST_DOMAIN, &bytes]))
    }

    /// Check one exact link. Call this while walking every record from the pinned bootstrap.
    pub fn validate_successor(&self, next: &Self) -> Result<(), ExternalCasError> {
        self.validate_shape()?;
        next.validate_shape()?;
        if self.provider_id != next.provider_id
            || self.network_id != next.network_id
            || self.genesis_digest != next.genesis_digest
        {
            return Err(ExternalCasError::WrongDomain);
        }
        if self.generation.checked_add(1) != Some(next.generation)
            || self.digest()? != next.previous_record_digest
            || self.next_state_digest != next.previous_state_digest
        {
            return Err(ExternalCasError::NotExactSuccessor);
        }
        Ok(())
    }
}

/// An explicit deployment pin. The key ID and public key must be provisioned together from an
/// independently reviewed configuration; this structure does not discover or trust a provider key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalCasPin {
    pub provider_id: Digest32,
    pub network_id: Digest32,
    pub genesis_digest: Digest32,
    pub receipt_key_id: Digest32,
    pub receipt_public_key: [u8; ML_DSA_65_PUBLIC_KEY_BYTES],
}
impl ExternalCasPin {
    pub fn validate(&self) -> Result<(), ExternalCasError> {
        for (name, value) in [
            ("pin.provider_id", &self.provider_id[..]),
            ("pin.network_id", &self.network_id[..]),
            ("pin.genesis_digest", &self.genesis_digest[..]),
            ("pin.receipt_key_id", &self.receipt_key_id[..]),
            ("pin.receipt_public_key", &self.receipt_public_key[..]),
        ] {
            if is_zero(value) {
                return Err(ExternalCasError::ZeroBinding(name));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalCasReadRequest {
    pub request_nonce: Digest32,
    pub operation_id: Digest32,
    pub request_digest: Digest32,
}
impl ExternalCasReadRequest {
    fn validate(&self) -> Result<(), ExternalCasError> {
        for (name, value) in [
            ("read.request_nonce", &self.request_nonce),
            ("read.operation_id", &self.operation_id),
            ("read.request_digest", &self.request_digest),
        ] {
            if is_zero(value) {
                return Err(ExternalCasError::ZeroBinding(name));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalCasWriteRequest {
    pub request_nonce: Digest32,
    pub operation_id: Digest32,
    pub request_digest: Digest32,
    pub expected_generation: u64,
    /// Exact immutable-provider object generation observed by the preceding signed read.
    /// This is the precondition passed to the provider CAS (e.g. GCS ifGenerationMatch).
    pub expected_object_generation: u64,
    pub expected_record_digest: Digest32,
    pub expected_state_digest: Digest32,
    pub next_record: ExternalCasRecord,
}
impl ExternalCasWriteRequest {
    /// Compute a domain-separated digest of every field that controls the CAS compare-and-swap,
    /// including the provider's object-generation precondition. The next record's request_digest
    /// field is deliberately excluded to avoid a circular hash; bind_request_digest writes this
    /// digest into both the request and ECR1 record before validation/signing.
    pub fn calculate_request_digest(
        &self,
        pin: &ExternalCasPin,
    ) -> Result<Digest32, ExternalCasError> {
        pin.validate()?;
        if self.expected_object_generation == 0 {
            return Err(ExternalCasError::InvalidObjectGenerationPrecondition);
        }
        for (name, value) in [
            ("write.request_nonce", &self.request_nonce),
            ("write.operation_id", &self.operation_id),
            ("write.expected_record_digest", &self.expected_record_digest),
            ("write.expected_state_digest", &self.expected_state_digest),
        ] {
            if is_zero(value) {
                return Err(ExternalCasError::ZeroBinding(name));
            }
        }
        let mut record_for_shape = self.next_record.clone();
        // The request digest itself is filled from this preimage and is not part of that preimage.
        record_for_shape.request_digest = [0xA5; 32];
        record_for_shape.validate_shape()?;
        if record_for_shape.provider_id != pin.provider_id
            || record_for_shape.network_id != pin.network_id
            || record_for_shape.genesis_digest != pin.genesis_digest
        {
            return Err(ExternalCasError::WrongDomain);
        }
        if self.expected_generation.checked_add(1) != Some(record_for_shape.generation)
            || record_for_shape.previous_record_digest != self.expected_record_digest
            || record_for_shape.previous_state_digest != self.expected_state_digest
            || record_for_shape.operation_id != self.operation_id
        {
            return Err(ExternalCasError::NotExactSuccessor);
        }

        Ok(hash_parts(&[
            WRITE_REQUEST_DIGEST_DOMAIN,
            &pin.provider_id,
            &pin.network_id,
            &pin.genesis_digest,
            &pin.receipt_key_id,
            &self.request_nonce,
            &self.operation_id,
            &self.expected_generation.to_be_bytes(),
            &self.expected_object_generation.to_be_bytes(),
            &self.expected_record_digest,
            &self.expected_state_digest,
            &record_for_shape.generation.to_be_bytes(),
            &record_for_shape.previous_record_digest,
            &record_for_shape.previous_state_digest,
            &record_for_shape.next_state_digest,
            &record_for_shape.operation_id,
        ]))
    }

    /// Fill the immutable operation digest before sending the request. Calling this again after
    /// changing any CAS precondition deterministically produces a different request digest.
    pub fn bind_request_digest(
        &mut self,
        pin: &ExternalCasPin,
    ) -> Result<Digest32, ExternalCasError> {
        let digest = self.calculate_request_digest(pin)?;
        self.request_digest = digest;
        self.next_record.request_digest = digest;
        Ok(digest)
    }

    pub fn validate(&self, pin: &ExternalCasPin) -> Result<(), ExternalCasError> {
        pin.validate()?;
        if self.expected_object_generation == 0 {
            return Err(ExternalCasError::InvalidObjectGenerationPrecondition);
        }
        for (name, value) in [
            ("write.request_nonce", &self.request_nonce),
            ("write.operation_id", &self.operation_id),
            ("write.request_digest", &self.request_digest),
            ("write.expected_record_digest", &self.expected_record_digest),
            ("write.expected_state_digest", &self.expected_state_digest),
        ] {
            if is_zero(value) {
                return Err(ExternalCasError::ZeroBinding(name));
            }
        }
        self.next_record.validate_shape()?;
        if self.next_record.provider_id != pin.provider_id
            || self.next_record.network_id != pin.network_id
            || self.next_record.genesis_digest != pin.genesis_digest
        {
            return Err(ExternalCasError::WrongDomain);
        }
        if self.expected_generation.checked_add(1) != Some(self.next_record.generation)
            || self.next_record.previous_record_digest != self.expected_record_digest
            || self.next_record.previous_state_digest != self.expected_state_digest
            || self.next_record.operation_id != self.operation_id
            || self.next_record.request_digest != self.request_digest
        {
            return Err(ExternalCasError::NotExactSuccessor);
        }
        if self.request_digest != self.calculate_request_digest(pin)? {
            return Err(ExternalCasError::RequestMismatch);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum ExternalCasReceiptKind {
    Read = 1,
    Commit = 2,
}
impl TryFrom<u16> for ExternalCasReceiptKind {
    type Error = ExternalCasError;
    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Read),
            2 => Ok(Self::Commit),
            _ => Err(ExternalCasError::UnknownReceiptKind),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum ExternalCasReceiptOutcome {
    Observed = 1,
    Applied = 2,
    AlreadyApplied = 3,
    Conflict = 4,
}
impl TryFrom<u16> for ExternalCasReceiptOutcome {
    type Error = ExternalCasError;
    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Observed),
            2 => Ok(Self::Applied),
            3 => Ok(Self::AlreadyApplied),
            4 => Ok(Self::Conflict),
            _ => Err(ExternalCasError::UnknownReceiptOutcome),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalCasReceipt {
    pub kind: ExternalCasReceiptKind,
    pub outcome: ExternalCasReceiptOutcome,
    pub generation: u64,
    /// Immutable storage-provider object generation, not the logical chain generation.
    pub object_generation: u64,
    pub provider_id: Digest32,
    pub network_id: Digest32,
    pub genesis_digest: Digest32,
    pub receipt_key_id: Digest32,
    pub request_nonce: Digest32,
    pub record_digest: Digest32,
    pub previous_record_digest: Digest32,
    pub previous_state_digest: Digest32,
    pub state_digest: Digest32,
    pub operation_id: Digest32,
    pub request_digest: Digest32,
    pub signature: [u8; ML_DSA_65_SIGNATURE_BYTES],
}
impl ExternalCasReceipt {
    fn validate_shape(&self) -> Result<(), ExternalCasError> {
        if self.object_generation == 0 {
            return Err(ExternalCasError::InvalidReceiptShape);
        }
        for (name, value) in [
            ("receipt.provider_id", &self.provider_id[..]),
            ("receipt.network_id", &self.network_id[..]),
            ("receipt.genesis_digest", &self.genesis_digest[..]),
            ("receipt.receipt_key_id", &self.receipt_key_id[..]),
            ("receipt.request_nonce", &self.request_nonce[..]),
            ("receipt.record_digest", &self.record_digest[..]),
            ("receipt.state_digest", &self.state_digest[..]),
            ("receipt.operation_id", &self.operation_id[..]),
            ("receipt.request_digest", &self.request_digest[..]),
        ] {
            if is_zero(value) {
                return Err(ExternalCasError::ZeroBinding(name));
            }
        }
        if self.generation == 0 {
            if !is_zero(&self.previous_record_digest) || !is_zero(&self.previous_state_digest) {
                return Err(ExternalCasError::InvalidBootstrapLinks);
            }
        } else if is_zero(&self.previous_record_digest) || is_zero(&self.previous_state_digest) {
            return Err(ExternalCasError::InvalidPredecessorLinks);
        }
        match self.kind {
            ExternalCasReceiptKind::Read if self.outcome != ExternalCasReceiptOutcome::Observed => {
                return Err(ExternalCasError::InvalidReceiptShape)
            }
            ExternalCasReceiptKind::Commit
                if self.outcome == ExternalCasReceiptOutcome::Observed =>
            {
                return Err(ExternalCasError::InvalidReceiptShape)
            }
            _ => {}
        }
        Ok(())
    }

    fn canonical_payload(
        &self,
    ) -> Result<[u8; EXTERNAL_CAS_RECEIPT_PAYLOAD_BYTES], ExternalCasError> {
        self.validate_shape()?;
        let mut out = Vec::with_capacity(EXTERNAL_CAS_RECEIPT_PAYLOAD_BYTES);
        out.extend_from_slice(RECEIPT_MAGIC);
        push_u16(&mut out, EXTERNAL_CAS_RECEIPT_VERSION);
        push_u16(&mut out, self.kind as u16);
        push_u16(&mut out, self.outcome as u16);
        push_u16(&mut out, 0);
        out.extend_from_slice(&self.generation.to_be_bytes());
        out.extend_from_slice(&self.object_generation.to_be_bytes());
        out.extend_from_slice(&self.provider_id);
        out.extend_from_slice(&self.network_id);
        out.extend_from_slice(&self.genesis_digest);
        out.extend_from_slice(&self.receipt_key_id);
        out.extend_from_slice(&self.request_nonce);
        out.extend_from_slice(&self.record_digest);
        out.extend_from_slice(&self.previous_record_digest);
        out.extend_from_slice(&self.previous_state_digest);
        out.extend_from_slice(&self.state_digest);
        out.extend_from_slice(&self.operation_id);
        out.extend_from_slice(&self.request_digest);
        out.try_into()
            .map_err(|_| ExternalCasError::WrongReceiptLength)
    }

    pub fn signing_digest(&self) -> Result<Digest32, ExternalCasError> {
        let payload = self.canonical_payload()?;
        Ok(hash_parts(&[RECEIPT_SIGNING_DOMAIN, &payload]))
    }

    pub fn encode(&self) -> Result<[u8; EXTERNAL_CAS_RECEIPT_BYTES], ExternalCasError> {
        let payload = self.canonical_payload()?;
        let mut out = Vec::with_capacity(EXTERNAL_CAS_RECEIPT_BYTES);
        out.extend_from_slice(&payload);
        out.extend_from_slice(&self.signature);
        out.try_into()
            .map_err(|_| ExternalCasError::WrongReceiptLength)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ExternalCasError> {
        if bytes.len() != EXTERNAL_CAS_RECEIPT_BYTES {
            return Err(ExternalCasError::WrongReceiptLength);
        }
        if &bytes[..4] != RECEIPT_MAGIC {
            return Err(ExternalCasError::WrongMagic);
        }
        if u16_at(bytes, 4) != EXTERNAL_CAS_RECEIPT_VERSION {
            return Err(ExternalCasError::UnsupportedVersion);
        }
        if u16_at(bytes, 10) != 0 {
            return Err(ExternalCasError::NonzeroReserved);
        }
        let receipt = Self {
            kind: ExternalCasReceiptKind::try_from(u16_at(bytes, 6))?,
            outcome: ExternalCasReceiptOutcome::try_from(u16_at(bytes, 8))?,
            generation: u64_at(bytes, 12),
            object_generation: u64_at(bytes, 20),
            provider_id: take(bytes, 28),
            network_id: take(bytes, 60),
            genesis_digest: take(bytes, 92),
            receipt_key_id: take(bytes, 124),
            request_nonce: take(bytes, 156),
            record_digest: take(bytes, 188),
            previous_record_digest: take(bytes, 220),
            previous_state_digest: take(bytes, 252),
            state_digest: take(bytes, 284),
            operation_id: take(bytes, 316),
            request_digest: take(bytes, 348),
            signature: take(bytes, EXTERNAL_CAS_RECEIPT_PAYLOAD_BYTES),
        };
        receipt.validate_shape()?;
        Ok(receipt)
    }

    fn check_pin(&self, pin: &ExternalCasPin) -> Result<(), ExternalCasError> {
        pin.validate()?;
        if self.provider_id != pin.provider_id
            || self.network_id != pin.network_id
            || self.genesis_digest != pin.genesis_digest
            || self.receipt_key_id != pin.receipt_key_id
        {
            return Err(ExternalCasError::WrongDomain);
        }
        Ok(())
    }

    fn verify_signature<V: MlDsa65Verifier>(
        &self,
        pin: &ExternalCasPin,
        verifier: &V,
    ) -> Result<(), ExternalCasError> {
        let digest = self.signing_digest()?;
        if !verifier.verify(&pin.receipt_public_key, &digest, &self.signature) {
            return Err(ExternalCasError::InvalidSignature);
        }
        Ok(())
    }

    /// Verify a fresh read receipt against both a caller challenge and the exact observed record.
    pub fn verify_read<V: MlDsa65Verifier>(
        &self,
        pin: &ExternalCasPin,
        request: &ExternalCasReadRequest,
        observed: &ExternalCasRecord,
        verifier: &V,
    ) -> Result<Digest32, ExternalCasError> {
        request.validate()?;
        self.check_pin(pin)?;
        if self.kind != ExternalCasReceiptKind::Read
            || self.outcome != ExternalCasReceiptOutcome::Observed
            || self.request_nonce != request.request_nonce
            || self.operation_id != request.operation_id
            || self.request_digest != request.request_digest
        {
            return Err(ExternalCasError::RequestMismatch);
        }
        if observed.provider_id != pin.provider_id
            || observed.network_id != pin.network_id
            || observed.genesis_digest != pin.genesis_digest
            || self.generation != observed.generation
            || self.record_digest != observed.digest()?
            || self.previous_record_digest != observed.previous_record_digest
            || self.previous_state_digest != observed.previous_state_digest
            || self.state_digest != observed.next_state_digest
        {
            return Err(ExternalCasError::RequestMismatch);
        }
        self.verify_signature(pin, verifier)?;
        Ok(self.state_digest)
    }

    /// Verify a commit receipt. A signed conflict remains a hard conflict, never a success.
    pub fn verify_commit<V: MlDsa65Verifier>(
        &self,
        pin: &ExternalCasPin,
        request: &ExternalCasWriteRequest,
        verifier: &V,
    ) -> Result<(), ExternalCasError> {
        request.validate(pin)?;
        self.check_pin(pin)?;
        if self.kind != ExternalCasReceiptKind::Commit
            || self.request_nonce != request.request_nonce
            || self.operation_id != request.operation_id
            || self.request_digest != request.request_digest
        {
            return Err(ExternalCasError::RequestMismatch);
        }
        self.verify_signature(pin, verifier)?;
        if self.outcome == ExternalCasReceiptOutcome::Conflict {
            return Err(ExternalCasError::CasConflict);
        }
        if self.object_generation <= request.expected_object_generation {
            return Err(ExternalCasError::ObjectGenerationNotAdvanced);
        }
        let record = &request.next_record;
        if !matches!(
            self.outcome,
            ExternalCasReceiptOutcome::Applied | ExternalCasReceiptOutcome::AlreadyApplied
        ) || self.generation != record.generation
            || self.record_digest != record.digest()?
            || self.previous_record_digest != record.previous_record_digest
            || self.previous_state_digest != record.previous_state_digest
            || self.state_digest != record.next_state_digest
        {
            return Err(ExternalCasError::RequestMismatch);
        }
        Ok(())
    }
}

/// Transport boundary for an independently administered CAS service.
///
/// Implementations MUST execute compare_and_swap as an atomic server-side conditional update.
/// A local read followed by an unconditional write does not satisfy this trait's security contract.
/// The returned receipts are always verified by the client with the out-of-band pinned ML-DSA-65
/// key. This trait is not itself a cloud implementation or proof of operator independence.
pub trait ExternalCasProviderTransport {
    type Error: fmt::Display;

    fn read_current(
        &mut self,
        request: &ExternalCasReadRequest,
    ) -> Result<(ExternalCasRecord, ExternalCasReceipt), Self::Error>;

    fn compare_and_swap(
        &mut self,
        request: &ExternalCasWriteRequest,
    ) -> Result<ExternalCasReceipt, Self::Error>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExternalCasClientError {
    Provider(String),
    Contract(ExternalCasError),
    RandomNonceUnavailable,
    MissingExpectedRecord,
    RollbackDetected {
        observed_generation: u64,
        minimum_generation: u64,
        observed_object_generation: u64,
        minimum_object_generation: u64,
    },
    EquivocationAtGeneration(u64),
    UnexpectedGeneration {
        expected: u64,
        observed: u64,
    },
}
impl fmt::Display for ExternalCasClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for ExternalCasClientError {}
impl From<ExternalCasError> for ExternalCasClientError {
    fn from(value: ExternalCasError) -> Self {
        Self::Contract(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedExternalCasRead {
    pub record: ExternalCasRecord,
    /// Provider metadata generation for the exact read receipt, not the logical chain height.
    pub object_generation: u64,
}

/// Strict client-side contract verifier. Floors passed to read_current must come from an
/// independently protected/durable record maintained by the caller; an in-memory floor alone
/// does not resist whole-disk rollback. A read may report the exact same anchor or one exact
/// successor. Larger jumps must be reconciled by the application with independently verified
/// intermediate records; this client never guesses across a missing link.
pub struct VerifiedExternalCasClient<P, V> {
    pin: ExternalCasPin,
    provider: P,
    verifier: V,
}

impl<P, V> VerifiedExternalCasClient<P, V>
where
    P: ExternalCasProviderTransport,
    V: MlDsa65Verifier,
{
    pub fn new(
        pin: ExternalCasPin,
        provider: P,
        verifier: V,
    ) -> Result<Self, ExternalCasClientError> {
        pin.validate()?;
        Ok(Self {
            pin,
            provider,
            verifier,
        })
    }

    /// Return whether this client uses the exact out-of-band pin supplied by its caller.
    /// The full key ID and public key are included; matching only provider/network/genesis IDs
    /// would permit a configuration split at the receipt-verification trust boundary.
    pub fn is_pinned_to(&self, expected: &ExternalCasPin) -> bool {
        &self.pin == expected
    }

    /// Generate a fresh challenge; callers must not replace this with a fixed or persisted nonce.
    pub fn fresh_read_request(
        &self,
        operation_id: Digest32,
        request_digest: Digest32,
    ) -> Result<ExternalCasReadRequest, ExternalCasClientError> {
        let mut request_nonce = [0u8; 32];
        getrandom::getrandom(&mut request_nonce)
            .map_err(|_| ExternalCasClientError::RandomNonceUnavailable)?;
        let request = ExternalCasReadRequest {
            request_nonce,
            operation_id,
            request_digest,
        };
        request.validate()?;
        Ok(request)
    }

    pub fn read_current(
        &mut self,
        request: &ExternalCasReadRequest,
        minimum_generation: u64,
        minimum_object_generation: u64,
        expected_current: Option<&ExternalCasRecord>,
    ) -> Result<VerifiedExternalCasRead, ExternalCasClientError> {
        request.validate()?;
        if minimum_generation > 0 && expected_current.is_none() {
            return Err(ExternalCasClientError::MissingExpectedRecord);
        }
        if let Some(expected) = expected_current {
            expected.validate_shape()?;
            if expected.provider_id != self.pin.provider_id
                || expected.network_id != self.pin.network_id
                || expected.genesis_digest != self.pin.genesis_digest
            {
                return Err(ExternalCasClientError::Contract(
                    ExternalCasError::WrongDomain,
                ));
            }
        }

        let (observed, receipt) = self
            .provider
            .read_current(request)
            .map_err(|error| ExternalCasClientError::Provider(error.to_string()))?;
        receipt.verify_read(&self.pin, request, &observed, &self.verifier)?;

        if observed.generation < minimum_generation
            || receipt.object_generation < minimum_object_generation
        {
            return Err(ExternalCasClientError::RollbackDetected {
                observed_generation: observed.generation,
                minimum_generation,
                observed_object_generation: receipt.object_generation,
                minimum_object_generation,
            });
        }

        match expected_current {
            None if observed.generation != 0 => {
                return Err(ExternalCasClientError::UnexpectedGeneration {
                    expected: 0,
                    observed: observed.generation,
                });
            }
            None => {}
            Some(expected) if observed.generation < expected.generation => {
                return Err(ExternalCasClientError::RollbackDetected {
                    observed_generation: observed.generation,
                    minimum_generation: expected.generation,
                    observed_object_generation: receipt.object_generation,
                    minimum_object_generation,
                });
            }
            Some(expected) if observed.generation == expected.generation => {
                if expected.digest()? != observed.digest()? {
                    return Err(ExternalCasClientError::EquivocationAtGeneration(
                        observed.generation,
                    ));
                }
            }
            Some(expected) if expected.generation.checked_add(1) == Some(observed.generation) => {
                expected.validate_successor(&observed)?;
            }
            Some(expected) => {
                return Err(ExternalCasClientError::UnexpectedGeneration {
                    expected: expected.generation.saturating_add(1),
                    observed: observed.generation,
                });
            }
        }

        Ok(VerifiedExternalCasRead {
            record: observed,
            object_generation: receipt.object_generation,
        })
    }

    /// Submit one exact successor. Provider failures remain errors and are never interpreted as
    /// a rollback, abort, or success; callers must resolve ambiguous outcomes with a fresh signed
    /// read and the same immutable operation ID/request digest.
    pub fn compare_and_swap(
        &mut self,
        request: &ExternalCasWriteRequest,
    ) -> Result<ExternalCasReceipt, ExternalCasClientError> {
        request.validate(&self.pin)?;
        let receipt = self
            .provider
            .compare_and_swap(request)
            .map_err(|error| ExternalCasClientError::Provider(error.to_string()))?;
        receipt.verify_commit(&self.pin, request, &self.verifier)?;
        Ok(receipt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v4_fat1_mldsa65_candidate::LibcruxMlDsa65VerifierCandidate;
    use libcrux_ml_dsa::ml_dsa_65::portable;

    macro_rules! sign_receipt {
        ($receipt:expr, $kp:ident $(,)?) => {{
            let mut receipt = $receipt;
            let digest = receipt.signing_digest().expect("valid receipt payload");
            receipt.signature = *portable::sign(&$kp.signing_key, &digest, &[], [0x71u8; 32])
                .expect("deterministic test signing succeeds")
                .as_ref();
            receipt
        }};
    }

    fn setup(public_key: [u8; ML_DSA_65_PUBLIC_KEY_BYTES]) -> (ExternalCasPin, ExternalCasRecord) {
        let pin = ExternalCasPin {
            provider_id: [1; 32],
            network_id: [2; 32],
            genesis_digest: [3; 32],
            receipt_key_id: [4; 32],
            receipt_public_key: public_key,
        };
        let bootstrap = ExternalCasRecord {
            generation: 0,
            provider_id: pin.provider_id,
            network_id: pin.network_id,
            genesis_digest: pin.genesis_digest,
            previous_record_digest: [0; 32],
            previous_state_digest: [0; 32],
            next_state_digest: [5; 32],
            operation_id: [6; 32],
            request_digest: [7; 32],
        };
        (pin, bootstrap)
    }

    fn receipt_for(
        pin: &ExternalCasPin,
        record: &ExternalCasRecord,
        kind: ExternalCasReceiptKind,
        outcome: ExternalCasReceiptOutcome,
        object_generation: u64,
        nonce: Digest32,
        operation_id: Digest32,
        request_digest: Digest32,
    ) -> ExternalCasReceipt {
        ExternalCasReceipt {
            kind,
            outcome,
            generation: record.generation,
            object_generation,
            provider_id: pin.provider_id,
            network_id: pin.network_id,
            genesis_digest: pin.genesis_digest,
            receipt_key_id: pin.receipt_key_id,
            request_nonce: nonce,
            record_digest: record.digest().unwrap(),
            previous_record_digest: record.previous_record_digest,
            previous_state_digest: record.previous_state_digest,
            state_digest: record.next_state_digest,
            operation_id,
            request_digest,
            signature: [0; ML_DSA_65_SIGNATURE_BYTES],
        }
    }

    struct MemoryCasProvider<F> {
        pin: ExternalCasPin,
        current: ExternalCasRecord,
        object_generation: u64,
        sign: F,
    }

    impl<F> ExternalCasProviderTransport for MemoryCasProvider<F>
    where
        F: Fn(ExternalCasReceipt) -> ExternalCasReceipt,
    {
        type Error = String;

        fn read_current(
            &mut self,
            request: &ExternalCasReadRequest,
        ) -> Result<(ExternalCasRecord, ExternalCasReceipt), Self::Error> {
            request.validate().map_err(|error| error.to_string())?;
            let receipt = receipt_for(
                &self.pin,
                &self.current,
                ExternalCasReceiptKind::Read,
                ExternalCasReceiptOutcome::Observed,
                self.object_generation,
                request.request_nonce,
                request.operation_id,
                request.request_digest,
            );
            Ok((self.current.clone(), (self.sign)(receipt)))
        }

        fn compare_and_swap(
            &mut self,
            request: &ExternalCasWriteRequest,
        ) -> Result<ExternalCasReceipt, Self::Error> {
            request
                .validate(&self.pin)
                .map_err(|error| error.to_string())?;
            let already_applied = self.current.digest().map_err(|e| e.to_string())?
                == request.next_record.digest().map_err(|e| e.to_string())?
                && self.current.operation_id == request.operation_id
                && self.current.request_digest == request.request_digest;
            let can_apply = self.current.generation == request.expected_generation
                && self.object_generation == request.expected_object_generation
                && self.current.digest().map_err(|e| e.to_string())?
                    == request.expected_record_digest
                && self.current.next_state_digest == request.expected_state_digest;

            let outcome = if already_applied {
                ExternalCasReceiptOutcome::AlreadyApplied
            } else if can_apply {
                self.current = request.next_record.clone();
                self.object_generation = self
                    .object_generation
                    .checked_add(1)
                    .ok_or_else(|| "provider object generation overflow".to_string())?;
                ExternalCasReceiptOutcome::Applied
            } else {
                ExternalCasReceiptOutcome::Conflict
            };
            let receipt = receipt_for(
                &self.pin,
                &self.current,
                ExternalCasReceiptKind::Commit,
                outcome,
                self.object_generation,
                request.request_nonce,
                request.operation_id,
                request.request_digest,
            );
            Ok((self.sign)(receipt))
        }
    }

    fn successor(pin: &ExternalCasPin, previous: &ExternalCasRecord) -> ExternalCasRecord {
        ExternalCasRecord {
            generation: previous.generation + 1,
            provider_id: pin.provider_id,
            network_id: pin.network_id,
            genesis_digest: pin.genesis_digest,
            previous_record_digest: previous.digest().unwrap(),
            previous_state_digest: previous.next_state_digest,
            next_state_digest: [0x38; 32],
            operation_id: [0x39; 32],
            request_digest: [0x3A; 32],
        }
    }

    #[test]
    fn verified_provider_client_checks_signed_read_exact_cas_and_successor() {
        let kp = portable::generate_key_pair([0x31u8; 32]);
        let (pin, bootstrap) = setup(*kp.verification_key.as_ref());
        let next = successor(&pin, &bootstrap);
        let sign = |mut receipt: ExternalCasReceipt| {
            let digest = receipt.signing_digest().unwrap();
            receipt.signature = *portable::sign(&kp.signing_key, &digest, &[], [0x73u8; 32])
                .unwrap()
                .as_ref();
            receipt
        };

        let provider = MemoryCasProvider {
            pin: pin.clone(),
            current: bootstrap.clone(),
            object_generation: 40,
            sign,
        };
        let mut client =
            VerifiedExternalCasClient::new(pin.clone(), provider, LibcruxMlDsa65VerifierCandidate)
                .unwrap();

        let read_request = client.fresh_read_request([0x42; 32], [0x43; 32]).unwrap();
        assert!(!is_zero(&read_request.request_nonce));
        let observed = client.read_current(&read_request, 0, 40, None).unwrap();
        assert_eq!(observed.record, bootstrap);
        assert_eq!(observed.object_generation, 40);

        let mut write_request = ExternalCasWriteRequest {
            request_nonce: [0x44; 32],
            operation_id: next.operation_id,
            request_digest: next.request_digest,
            expected_generation: bootstrap.generation,
            expected_object_generation: 40,
            expected_record_digest: bootstrap.digest().unwrap(),
            expected_state_digest: bootstrap.next_state_digest,
            next_record: next.clone(),
        };
        write_request.bind_request_digest(&pin).unwrap();
        let committed_record = write_request.next_record.clone();
        let receipt = client.compare_and_swap(&write_request).unwrap();
        assert_eq!(receipt.outcome, ExternalCasReceiptOutcome::Applied);
        assert_eq!(receipt.generation, 1);
        assert_eq!(receipt.object_generation, 41);

        // Reusing the same logical predecessor with a stale provider-object generation must
        // conflict atomically, even if the caller rebinds the request digest to those stale bytes.
        let mut stale_object_generation = write_request.clone();
        stale_object_generation.expected_object_generation = 39;
        stale_object_generation.bind_request_digest(&pin).unwrap();
        assert_eq!(
            client.compare_and_swap(&stale_object_generation),
            Err(ExternalCasClientError::Contract(
                ExternalCasError::CasConflict
            ))
        );

        let successor_read = ExternalCasReadRequest {
            request_nonce: [0x45; 32],
            operation_id: committed_record.operation_id,
            request_digest: committed_record.request_digest,
        };
        let observed = client
            .read_current(&successor_read, 1, 41, Some(&bootstrap))
            .unwrap();
        assert_eq!(observed.record, committed_record);
        assert_eq!(observed.object_generation, 41);
    }

    #[test]
    fn verified_provider_client_rejects_signed_rollback_and_unavailable_provider() {
        let kp = portable::generate_key_pair([0x51u8; 32]);
        let (pin, bootstrap) = setup(*kp.verification_key.as_ref());
        let sign = |mut receipt: ExternalCasReceipt| {
            let digest = receipt.signing_digest().unwrap();
            receipt.signature = *portable::sign(&kp.signing_key, &digest, &[], [0x73u8; 32])
                .unwrap()
                .as_ref();
            receipt
        };

        let provider = MemoryCasProvider {
            pin: pin.clone(),
            current: bootstrap.clone(),
            object_generation: 41,
            sign,
        };
        let mut client =
            VerifiedExternalCasClient::new(pin.clone(), provider, LibcruxMlDsa65VerifierCandidate)
                .unwrap();
        let request = ExternalCasReadRequest {
            request_nonce: [0x61; 32],
            operation_id: [0x62; 32],
            request_digest: [0x63; 32],
        };
        assert!(matches!(
            client.read_current(&request, 1, 41, Some(&successor(&pin, &bootstrap))),
            Err(ExternalCasClientError::RollbackDetected { .. })
        ));

        struct Unavailable;
        impl ExternalCasProviderTransport for Unavailable {
            type Error = &'static str;
            fn read_current(
                &mut self,
                _request: &ExternalCasReadRequest,
            ) -> Result<(ExternalCasRecord, ExternalCasReceipt), Self::Error> {
                Err("provider unavailable")
            }
            fn compare_and_swap(
                &mut self,
                _request: &ExternalCasWriteRequest,
            ) -> Result<ExternalCasReceipt, Self::Error> {
                Err("provider unavailable")
            }
        }

        let mut offline =
            VerifiedExternalCasClient::new(pin, Unavailable, LibcruxMlDsa65VerifierCandidate)
                .unwrap();
        assert_eq!(
            offline.read_current(&request, 0, 0, None),
            Err(ExternalCasClientError::Provider(
                "provider unavailable".into()
            ))
        );
    }

    #[test]
    fn verified_provider_client_never_treats_cas_conflict_as_success() {
        let kp = portable::generate_key_pair([0x58u8; 32]);
        let (pin, bootstrap) = setup(*kp.verification_key.as_ref());
        let next = successor(&pin, &bootstrap);
        let sign = |mut receipt: ExternalCasReceipt| {
            let digest = receipt.signing_digest().unwrap();
            receipt.signature = *portable::sign(&kp.signing_key, &digest, &[], [0x73u8; 32])
                .unwrap()
                .as_ref();
            receipt
        };

        let mut competing = successor(&pin, &bootstrap);
        competing.next_state_digest = [0x7A; 32];
        competing.operation_id = [0x7B; 32];
        competing.request_digest = [0x7C; 32];
        let provider = MemoryCasProvider {
            pin: pin.clone(),
            current: competing,
            object_generation: 55,
            sign,
        };
        let mut client =
            VerifiedExternalCasClient::new(pin.clone(), provider, LibcruxMlDsa65VerifierCandidate)
                .unwrap();
        let mut request = ExternalCasWriteRequest {
            request_nonce: [0x71; 32],
            operation_id: next.operation_id,
            request_digest: next.request_digest,
            expected_generation: bootstrap.generation,
            expected_object_generation: 40,
            expected_record_digest: bootstrap.digest().unwrap(),
            expected_state_digest: bootstrap.next_state_digest,
            next_record: next,
        };
        request.bind_request_digest(&pin).unwrap();
        assert_eq!(
            client.compare_and_swap(&request),
            Err(ExternalCasClientError::Contract(
                ExternalCasError::CasConflict
            ))
        );
    }

    #[test]
    fn ecr1_record_roundtrip_is_fixed_width_and_reserved_bytes_are_canonical() {
        let kp = portable::generate_key_pair([0x31u8; 32]);
        let (_, bootstrap) = setup(*kp.verification_key.as_ref());
        let encoded = bootstrap.encode().unwrap();
        assert_eq!(encoded.len(), EXTERNAL_CAS_RECORD_BYTES);
        assert_eq!(&encoded[..4], b"ECR1");
        assert_eq!(ExternalCasRecord::decode(&encoded).unwrap(), bootstrap);

        let mut noncanonical = encoded;
        noncanonical[7] = 1;
        assert_eq!(
            ExternalCasRecord::decode(&noncanonical),
            Err(ExternalCasError::NonzeroReserved)
        );
        assert_eq!(
            ExternalCasRecord::decode(&encoded[..encoded.len() - 1]),
            Err(ExternalCasError::WrongRecordLength)
        );
    }

    #[test]
    fn record_chain_requires_exact_generation_scope_and_state_link() {
        let kp = portable::generate_key_pair([0x31u8; 32]);
        let (pin, first) = setup(*kp.verification_key.as_ref());
        let second = ExternalCasRecord {
            generation: 1,
            provider_id: pin.provider_id,
            network_id: pin.network_id,
            genesis_digest: pin.genesis_digest,
            previous_record_digest: first.digest().unwrap(),
            previous_state_digest: first.next_state_digest,
            next_state_digest: [8; 32],
            operation_id: [9; 32],
            request_digest: [10; 32],
        };
        first.validate_successor(&second).unwrap();
        let mut skipped = second.clone();
        skipped.generation = 2;
        assert_eq!(
            first.validate_successor(&skipped),
            Err(ExternalCasError::NotExactSuccessor)
        );
        let mut forked = second.clone();
        forked.previous_state_digest[0] ^= 1;
        assert_eq!(
            first.validate_successor(&forked),
            Err(ExternalCasError::NotExactSuccessor)
        );
        let mut wrong_network = second;
        wrong_network.network_id[0] ^= 1;
        assert_eq!(
            first.validate_successor(&wrong_network),
            Err(ExternalCasError::WrongDomain)
        );
    }

    #[test]
    fn signed_read_receipt_binds_fresh_nonce_tip_record_and_scope() {
        let kp = portable::generate_key_pair([0x31u8; 32]);
        let (pin, record) = setup(*kp.verification_key.as_ref());
        let request = ExternalCasReadRequest {
            request_nonce: [11; 32],
            operation_id: [12; 32],
            request_digest: [13; 32],
        };
        let receipt = sign_receipt!(
            receipt_for(
                &pin,
                &record,
                ExternalCasReceiptKind::Read,
                ExternalCasReceiptOutcome::Observed,
                42,
                request.request_nonce,
                request.operation_id,
                request.request_digest,
            ),
            kp,
        );
        let encoded = receipt.encode().unwrap();
        assert_eq!(encoded.len(), EXTERNAL_CAS_RECEIPT_BYTES);
        let decoded = ExternalCasReceipt::decode(&encoded).unwrap();
        assert_eq!(decoded, receipt);
        assert_eq!(
            decoded
                .verify_read(&pin, &request, &record, &LibcruxMlDsa65VerifierCandidate)
                .unwrap(),
            record.next_state_digest
        );

        let mut stale_request = request.clone();
        stale_request.request_nonce[0] ^= 1;
        assert_eq!(
            decoded.verify_read(
                &pin,
                &stale_request,
                &record,
                &LibcruxMlDsa65VerifierCandidate
            ),
            Err(ExternalCasError::RequestMismatch)
        );
        let mut tampered = decoded.clone();
        tampered.signature[0] ^= 1;
        assert_eq!(
            tampered.verify_read(&pin, &request, &record, &LibcruxMlDsa65VerifierCandidate),
            Err(ExternalCasError::InvalidSignature)
        );
        let mut wrong_scope = pin.clone();
        wrong_scope.network_id[0] ^= 1;
        assert_eq!(
            decoded.verify_read(
                &wrong_scope,
                &request,
                &record,
                &LibcruxMlDsa65VerifierCandidate
            ),
            Err(ExternalCasError::WrongDomain)
        );
    }

    #[test]
    fn signed_commit_receipt_binds_exact_cas_request_and_rejects_conflict() {
        let kp = portable::generate_key_pair([0x31u8; 32]);
        let (pin, first) = setup(*kp.verification_key.as_ref());
        let next = ExternalCasRecord {
            generation: 1,
            provider_id: pin.provider_id,
            network_id: pin.network_id,
            genesis_digest: pin.genesis_digest,
            previous_record_digest: first.digest().unwrap(),
            previous_state_digest: first.next_state_digest,
            next_state_digest: [14; 32],
            operation_id: [15; 32],
            request_digest: [16; 32],
        };
        let mut request = ExternalCasWriteRequest {
            request_nonce: [17; 32],
            operation_id: next.operation_id,
            request_digest: next.request_digest,
            expected_generation: 0,
            expected_object_generation: 42,
            expected_record_digest: first.digest().unwrap(),
            expected_state_digest: first.next_state_digest,
            next_record: next.clone(),
        };
        request.bind_request_digest(&pin).unwrap();
        request.validate(&pin).unwrap();
        let applied = sign_receipt!(
            receipt_for(
                &pin,
                &request.next_record,
                ExternalCasReceiptKind::Commit,
                ExternalCasReceiptOutcome::Applied,
                43,
                request.request_nonce,
                request.operation_id,
                request.request_digest,
            ),
            kp,
        );
        let decoded = ExternalCasReceipt::decode(&applied.encode().unwrap()).unwrap();
        decoded
            .verify_commit(&pin, &request, &LibcruxMlDsa65VerifierCandidate)
            .unwrap();

        let already_applied = sign_receipt!(
            receipt_for(
                &pin,
                &request.next_record,
                ExternalCasReceiptKind::Commit,
                ExternalCasReceiptOutcome::AlreadyApplied,
                43,
                request.request_nonce,
                request.operation_id,
                request.request_digest,
            ),
            kp,
        );
        already_applied
            .verify_commit(&pin, &request, &LibcruxMlDsa65VerifierCandidate)
            .unwrap();

        let mut wrong_payload = request.clone();
        wrong_payload.request_digest[0] ^= 1;
        assert_eq!(
            decoded.verify_commit(&pin, &wrong_payload, &LibcruxMlDsa65VerifierCandidate),
            Err(ExternalCasError::NotExactSuccessor)
        );

        let conflict = sign_receipt!(
            ExternalCasReceipt {
                generation: 2,
                object_generation: 44,
                record_digest: [18; 32],
                previous_record_digest: [19; 32],
                previous_state_digest: [20; 32],
                state_digest: [21; 32],
                outcome: ExternalCasReceiptOutcome::Conflict,
                ..receipt_for(
                    &pin,
                    &next,
                    ExternalCasReceiptKind::Commit,
                    ExternalCasReceiptOutcome::Conflict,
                    44,
                    request.request_nonce,
                    request.operation_id,
                    request.request_digest,
                )
            },
            kp,
        );
        assert_eq!(
            conflict.verify_commit(&pin, &request, &LibcruxMlDsa65VerifierCandidate),
            Err(ExternalCasError::CasConflict)
        );
    }
}
