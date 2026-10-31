//! CP-0482 signed challenge-bound protocol and in-memory concurrency model for QRun's
//! future off-host monotonic Anchor. This is a protocol candidate, not a deployed service.
use crate::{
    external_cas_anchor_candidate::{ExternalCasPin, ExternalCasRecord, EXTERNAL_CAS_RECORD_BYTES},
    external_cas_offhost_anchor_candidate::{
        verify_provider_commit_for_offhost_anchor, ExternalCasOffhostAnchorError,
        ExternalCasOffhostAnchorOutcome, ExternalCasOffhostAnchorState,
    },
    v4_fat1_trust_candidate::{
        MlDsa65Verifier, ML_DSA_65_PUBLIC_KEY_BYTES, ML_DSA_65_SIGNATURE_BYTES,
    },
};
use sha2::{Digest, Sha256};
use std::{
    fmt,
    sync::{Arc, Mutex},
};

type Digest32 = [u8; 32];

pub const OFFHOST_ANCHOR_STATE_BYTES: usize = 8 + 8 + EXTERNAL_CAS_RECORD_BYTES + 96 + 8 + 32;
pub const OFFHOST_ANCHOR_RECEIPT_PAYLOAD_BYTES: usize = 796;
pub const OFFHOST_ANCHOR_RECEIPT_BYTES: usize =
    OFFHOST_ANCHOR_RECEIPT_PAYLOAD_BYTES + ML_DSA_65_SIGNATURE_BYTES;

const RECEIPT_MAGIC: &[u8; 4] = b"QAR1";
const RECEIPT_VERSION: u16 = 1;
const RECEIPT_DOMAIN: &[u8] = b"QRUN-OFFHOST-ANCHOR-RECEIPT-V1\0";

fn hash_parts(parts: &[&[u8]]) -> Digest32 {
    let mut h = Sha256::new();
    for part in parts {
        h.update(part);
    }
    h.finalize().into()
}
fn zero(value: &[u8]) -> bool {
    value.iter().all(|b| *b == 0)
}
fn take<const N: usize>(bytes: &[u8], offset: usize) -> [u8; N] {
    bytes[offset..offset + N]
        .try_into()
        .expect("length checked")
}
fn u16_at(bytes: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes(take(bytes, offset))
}
fn u64_at(bytes: &[u8], offset: usize) -> u64 {
    u64::from_be_bytes(take(bytes, offset))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OffhostAnchorProtocolError {
    InvalidPin,
    ProviderDomainMismatch,
    ProviderAndAnchorKeysNotIndependent,
    InvalidRequest,
    InvalidReceipt,
    WrongChallenge,
    WrongOutcome,
    WrongTarget,
    StateEncoding,
    State(ExternalCasOffhostAnchorError),
    Signing(String),
    Store(ExternalCasOffhostAnchorStoreError),
    Poisoned,
}
impl fmt::Display for OffhostAnchorProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for OffhostAnchorProtocolError {}
impl From<ExternalCasOffhostAnchorError> for OffhostAnchorProtocolError {
    fn from(value: ExternalCasOffhostAnchorError) -> Self {
        Self::State(value)
    }
}

/// This pin is provisioned independently from the Provider pin. Its key ID and ML-DSA-65
/// public key MUST be distinct from the Provider receipt key ID and public key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalCasOffhostAnchorPin {
    pub anchor_id: Digest32,
    pub provider_id: Digest32,
    pub network_id: Digest32,
    pub genesis_digest: Digest32,
    pub receipt_key_id: Digest32,
    pub receipt_public_key: [u8; ML_DSA_65_PUBLIC_KEY_BYTES],
}
impl ExternalCasOffhostAnchorPin {
    pub fn validate(&self, provider: &ExternalCasPin) -> Result<(), OffhostAnchorProtocolError> {
        provider
            .validate()
            .map_err(|_| OffhostAnchorProtocolError::InvalidPin)?;
        if zero(&self.anchor_id) || zero(&self.receipt_key_id) || zero(&self.receipt_public_key) {
            return Err(OffhostAnchorProtocolError::InvalidPin);
        }
        if self.provider_id != provider.provider_id
            || self.network_id != provider.network_id
            || self.genesis_digest != provider.genesis_digest
        {
            return Err(OffhostAnchorProtocolError::ProviderDomainMismatch);
        }
        if self.receipt_key_id == provider.receipt_key_id
            || self.receipt_public_key == provider.receipt_public_key
        {
            return Err(OffhostAnchorProtocolError::ProviderAndAnchorKeysNotIndependent);
        }
        Ok(())
    }
}

/// Minimal signing boundary. Production implementation is expected to use a separately
/// provisioned Anchor ML-DSA-65 key (for example, a distinct KMS key); this module stores none.
pub trait OffhostAnchorReceiptSigner {
    fn sign_digest(&self, digest: &Digest32) -> Result<[u8; ML_DSA_65_SIGNATURE_BYTES], String>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalCasOffhostAnchorReadRequest {
    pub challenge: Digest32,
    pub operation_id: Digest32,
    pub request_digest: Digest32,
}
impl ExternalCasOffhostAnchorReadRequest {
    pub fn validate(&self) -> Result<(), OffhostAnchorProtocolError> {
        if zero(&self.challenge) || zero(&self.operation_id) || zero(&self.request_digest) {
            return Err(OffhostAnchorProtocolError::InvalidRequest);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalCasOffhostAnchorCasRequest {
    pub challenge: Digest32,
    pub operation_id: Digest32,
    pub request_digest: Digest32,
    pub expected_sequence: u64,
    pub expected_state_digest: Digest32,
    pub target_state_digest: Digest32,
}
impl ExternalCasOffhostAnchorCasRequest {
    pub fn validate(&self) -> Result<(), OffhostAnchorProtocolError> {
        if zero(&self.challenge)
            || zero(&self.operation_id)
            || zero(&self.request_digest)
            || self.expected_sequence == 0
            || zero(&self.expected_state_digest)
            || zero(&self.target_state_digest)
            || self.expected_state_digest == self.target_state_digest
        {
            return Err(OffhostAnchorProtocolError::InvalidRequest);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum ExternalCasOffhostAnchorReceiptKind {
    Read = 1,
    Cas = 2,
}
impl TryFrom<u16> for ExternalCasOffhostAnchorReceiptKind {
    type Error = OffhostAnchorProtocolError;
    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Read),
            2 => Ok(Self::Cas),
            _ => Err(OffhostAnchorProtocolError::InvalidReceipt),
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum ExternalCasOffhostAnchorReceiptOutcome {
    Observed = 1,
    Applied = 2,
    AlreadyApplied = 3,
    Conflict = 4,
}
impl TryFrom<u16> for ExternalCasOffhostAnchorReceiptOutcome {
    type Error = OffhostAnchorProtocolError;
    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Observed),
            2 => Ok(Self::Applied),
            3 => Ok(Self::AlreadyApplied),
            4 => Ok(Self::Conflict),
            _ => Err(OffhostAnchorProtocolError::InvalidReceipt),
        }
    }
}

/// Full state is included in each receipt so the verifier can recompute every field and digest.
/// The signature never authenticates a caller-supplied digest alone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalCasOffhostAnchorReceipt {
    pub kind: ExternalCasOffhostAnchorReceiptKind,
    pub outcome: ExternalCasOffhostAnchorReceiptOutcome,
    pub challenge: Digest32,
    pub anchor_id: Digest32,
    pub provider_id: Digest32,
    pub network_id: Digest32,
    pub genesis_digest: Digest32,
    pub receipt_key_id: Digest32,
    pub operation_id: Digest32,
    pub request_digest: Digest32,
    pub expected_sequence: u64,
    pub expected_state_digest: Digest32,
    pub target_state_digest: Digest32,
    pub state_digest: Digest32,
    pub state: ExternalCasOffhostAnchorState,
    pub signature: [u8; ML_DSA_65_SIGNATURE_BYTES],
}
impl ExternalCasOffhostAnchorReceipt {
    fn validate_domain(
        &self,
        anchor: &ExternalCasOffhostAnchorPin,
        provider: &ExternalCasPin,
    ) -> Result<(), OffhostAnchorProtocolError> {
        anchor.validate(provider)?;
        if self.anchor_id != anchor.anchor_id
            || self.provider_id != anchor.provider_id
            || self.network_id != anchor.network_id
            || self.genesis_digest != anchor.genesis_digest
            || self.receipt_key_id != anchor.receipt_key_id
            || zero(&self.challenge)
            || zero(&self.operation_id)
            || zero(&self.request_digest)
        {
            return Err(OffhostAnchorProtocolError::InvalidReceipt);
        }
        self.state.validate(provider)?;
        if self.state.digest()? != self.state_digest {
            return Err(OffhostAnchorProtocolError::InvalidReceipt);
        }
        Ok(())
    }

    fn canonical_payload(
        &self,
    ) -> Result<[u8; OFFHOST_ANCHOR_RECEIPT_PAYLOAD_BYTES], OffhostAnchorProtocolError> {
        if self.kind == ExternalCasOffhostAnchorReceiptKind::Read
            && self.outcome != ExternalCasOffhostAnchorReceiptOutcome::Observed
        {
            return Err(OffhostAnchorProtocolError::InvalidReceipt);
        }
        if self.kind == ExternalCasOffhostAnchorReceiptKind::Cas
            && self.outcome == ExternalCasOffhostAnchorReceiptOutcome::Observed
        {
            return Err(OffhostAnchorProtocolError::InvalidReceipt);
        }
        let state = encode_state(&self.state)?;
        let mut out = Vec::with_capacity(OFFHOST_ANCHOR_RECEIPT_PAYLOAD_BYTES);
        out.extend_from_slice(RECEIPT_MAGIC);
        out.extend_from_slice(&RECEIPT_VERSION.to_be_bytes());
        out.extend_from_slice(&(self.kind as u16).to_be_bytes());
        out.extend_from_slice(&(self.outcome as u16).to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes());
        out.extend_from_slice(&self.challenge);
        out.extend_from_slice(&self.anchor_id);
        out.extend_from_slice(&self.provider_id);
        out.extend_from_slice(&self.network_id);
        out.extend_from_slice(&self.genesis_digest);
        out.extend_from_slice(&self.receipt_key_id);
        out.extend_from_slice(&self.operation_id);
        out.extend_from_slice(&self.request_digest);
        out.extend_from_slice(&self.expected_sequence.to_be_bytes());
        out.extend_from_slice(&self.expected_state_digest);
        out.extend_from_slice(&self.target_state_digest);
        out.extend_from_slice(&self.state_digest);
        out.extend_from_slice(&state);
        out.try_into()
            .map_err(|_| OffhostAnchorProtocolError::InvalidReceipt)
    }

    pub fn signing_digest(&self) -> Result<Digest32, OffhostAnchorProtocolError> {
        Ok(hash_parts(&[RECEIPT_DOMAIN, &self.canonical_payload()?]))
    }

    pub fn sign<S: OffhostAnchorReceiptSigner>(
        &mut self,
        signer: &S,
    ) -> Result<(), OffhostAnchorProtocolError> {
        self.signature = signer
            .sign_digest(&self.signing_digest()?)
            .map_err(OffhostAnchorProtocolError::Signing)?;
        Ok(())
    }

    pub fn encode(&self) -> Result<[u8; OFFHOST_ANCHOR_RECEIPT_BYTES], OffhostAnchorProtocolError> {
        let payload = self.canonical_payload()?;
        let mut out = Vec::with_capacity(OFFHOST_ANCHOR_RECEIPT_BYTES);
        out.extend_from_slice(&payload);
        out.extend_from_slice(&self.signature);
        out.try_into()
            .map_err(|_| OffhostAnchorProtocolError::InvalidReceipt)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, OffhostAnchorProtocolError> {
        if bytes.len() != OFFHOST_ANCHOR_RECEIPT_BYTES
            || &bytes[..4] != RECEIPT_MAGIC
            || u16_at(bytes, 4) != RECEIPT_VERSION
            || u16_at(bytes, 10) != 0
        {
            return Err(OffhostAnchorProtocolError::InvalidReceipt);
        }
        let state_bytes = &bytes[372..372 + OFFHOST_ANCHOR_STATE_BYTES];
        let receipt = Self {
            kind: ExternalCasOffhostAnchorReceiptKind::try_from(u16_at(bytes, 6))?,
            outcome: ExternalCasOffhostAnchorReceiptOutcome::try_from(u16_at(bytes, 8))?,
            challenge: take(bytes, 12),
            anchor_id: take(bytes, 44),
            provider_id: take(bytes, 76),
            network_id: take(bytes, 108),
            genesis_digest: take(bytes, 140),
            receipt_key_id: take(bytes, 172),
            operation_id: take(bytes, 204),
            request_digest: take(bytes, 236),
            expected_sequence: u64_at(bytes, 268),
            expected_state_digest: take(bytes, 276),
            target_state_digest: take(bytes, 308),
            state_digest: take(bytes, 340),
            state: decode_state(state_bytes)?,
            signature: take(bytes, OFFHOST_ANCHOR_RECEIPT_PAYLOAD_BYTES),
        };
        // Re-encoding rejects any noncanonical state or receipt payload.
        if receipt.canonical_payload()?.as_slice() != &bytes[..OFFHOST_ANCHOR_RECEIPT_PAYLOAD_BYTES]
        {
            return Err(OffhostAnchorProtocolError::InvalidReceipt);
        }
        Ok(receipt)
    }

    fn verify_signature<V: MlDsa65Verifier>(
        &self,
        anchor: &ExternalCasOffhostAnchorPin,
        provider: &ExternalCasPin,
        verifier: &V,
    ) -> Result<(), OffhostAnchorProtocolError> {
        self.validate_domain(anchor, provider)?;
        if !verifier.verify(
            &anchor.receipt_public_key,
            &self.signing_digest()?,
            &self.signature,
        ) {
            return Err(OffhostAnchorProtocolError::InvalidReceipt);
        }
        Ok(())
    }

    pub fn verify_read<V: MlDsa65Verifier>(
        &self,
        anchor: &ExternalCasOffhostAnchorPin,
        provider: &ExternalCasPin,
        request: &ExternalCasOffhostAnchorReadRequest,
        verifier: &V,
    ) -> Result<ExternalCasOffhostAnchorState, OffhostAnchorProtocolError> {
        request.validate()?;
        self.verify_signature(anchor, provider, verifier)?;
        if self.kind != ExternalCasOffhostAnchorReceiptKind::Read
            || self.outcome != ExternalCasOffhostAnchorReceiptOutcome::Observed
            || self.challenge != request.challenge
            || self.operation_id != request.operation_id
            || self.request_digest != request.request_digest
            || self.expected_sequence != 0
            || self.expected_state_digest != [0; 32]
            || self.target_state_digest != [0; 32]
        {
            return Err(OffhostAnchorProtocolError::WrongChallenge);
        }
        Ok(self.state.clone())
    }

    pub fn verify_cas<V: MlDsa65Verifier>(
        &self,
        anchor: &ExternalCasOffhostAnchorPin,
        provider: &ExternalCasPin,
        request: &ExternalCasOffhostAnchorCasRequest,
        verifier: &V,
    ) -> Result<
        (
            ExternalCasOffhostAnchorReceiptOutcome,
            ExternalCasOffhostAnchorState,
        ),
        OffhostAnchorProtocolError,
    > {
        request.validate()?;
        self.verify_signature(anchor, provider, verifier)?;
        if self.kind != ExternalCasOffhostAnchorReceiptKind::Cas
            || self.challenge != request.challenge
            || self.operation_id != request.operation_id
            || self.request_digest != request.request_digest
            || self.expected_sequence != request.expected_sequence
            || self.expected_state_digest != request.expected_state_digest
            || self.target_state_digest != request.target_state_digest
        {
            return Err(OffhostAnchorProtocolError::WrongChallenge);
        }
        match self.outcome {
            ExternalCasOffhostAnchorReceiptOutcome::Conflict => {
                // A conflict must prove that the authoritative state differs from the expected
                // predecessor. A lower sequence is an anchor rollback, and a receipt naming the
                // exact requested target is success-shaped rather than a conflict.
                if self.state.sequence < request.expected_sequence
                    || (self.state.sequence == request.expected_sequence
                        && self.state_digest == request.expected_state_digest)
                    || (self.state_digest == request.target_state_digest
                        && self.state.last_operation_id == request.operation_id
                        && self.state.last_request_digest == request.request_digest)
                {
                    return Err(OffhostAnchorProtocolError::WrongOutcome);
                }
                Ok((
                    ExternalCasOffhostAnchorReceiptOutcome::Conflict,
                    self.state.clone(),
                ))
            }
            ExternalCasOffhostAnchorReceiptOutcome::Applied
            | ExternalCasOffhostAnchorReceiptOutcome::AlreadyApplied => {
                let expected_sequence = request
                    .expected_sequence
                    .checked_add(1)
                    .ok_or(OffhostAnchorProtocolError::WrongTarget)?;
                if self.state.sequence != expected_sequence
                    || self.state_digest != request.target_state_digest
                    || self.state.last_operation_id != request.operation_id
                    || self.state.last_request_digest != request.request_digest
                    || self.state.last_expected_anchor_sequence != request.expected_sequence
                    || self.state.last_expected_anchor_state_digest != request.expected_state_digest
                {
                    return Err(OffhostAnchorProtocolError::WrongTarget);
                }
                Ok((self.outcome, self.state.clone()))
            }
            ExternalCasOffhostAnchorReceiptOutcome::Observed => {
                Err(OffhostAnchorProtocolError::WrongOutcome)
            }
        }
    }
}

fn encode_state(
    state: &ExternalCasOffhostAnchorState,
) -> Result<[u8; OFFHOST_ANCHOR_STATE_BYTES], OffhostAnchorProtocolError> {
    let record = state
        .provider_record
        .encode()
        .map_err(|_| OffhostAnchorProtocolError::StateEncoding)?;
    let mut out = Vec::with_capacity(OFFHOST_ANCHOR_STATE_BYTES);
    out.extend_from_slice(&state.sequence.to_be_bytes());
    out.extend_from_slice(&state.provider_object_generation.to_be_bytes());
    out.extend_from_slice(&record);
    out.extend_from_slice(&state.last_operation_id);
    out.extend_from_slice(&state.last_request_digest);
    out.extend_from_slice(&state.last_provider_receipt_digest);
    out.extend_from_slice(&state.last_expected_anchor_sequence.to_be_bytes());
    out.extend_from_slice(&state.last_expected_anchor_state_digest);
    out.try_into()
        .map_err(|_| OffhostAnchorProtocolError::StateEncoding)
}
fn decode_state(bytes: &[u8]) -> Result<ExternalCasOffhostAnchorState, OffhostAnchorProtocolError> {
    if bytes.len() != OFFHOST_ANCHOR_STATE_BYTES {
        return Err(OffhostAnchorProtocolError::StateEncoding);
    }
    let record = ExternalCasRecord::decode(&bytes[16..16 + EXTERNAL_CAS_RECORD_BYTES])
        .map_err(|_| OffhostAnchorProtocolError::StateEncoding)?;
    Ok(ExternalCasOffhostAnchorState {
        sequence: u64_at(bytes, 0),
        provider_object_generation: u64_at(bytes, 8),
        provider_record: record,
        last_operation_id: take(bytes, 16 + EXTERNAL_CAS_RECORD_BYTES),
        last_request_digest: take(bytes, 48 + EXTERNAL_CAS_RECORD_BYTES),
        last_provider_receipt_digest: take(bytes, 80 + EXTERNAL_CAS_RECORD_BYTES),
        last_expected_anchor_sequence: u64_at(bytes, 112 + EXTERNAL_CAS_RECORD_BYTES),
        last_expected_anchor_state_digest: take(bytes, 120 + EXTERNAL_CAS_RECORD_BYTES),
    })
}

fn new_receipt(
    kind: ExternalCasOffhostAnchorReceiptKind,
    outcome: ExternalCasOffhostAnchorReceiptOutcome,
    anchor: &ExternalCasOffhostAnchorPin,
    request_challenge: Digest32,
    operation_id: Digest32,
    request_digest: Digest32,
    expected_sequence: u64,
    expected_state_digest: Digest32,
    target_state_digest: Digest32,
    state: ExternalCasOffhostAnchorState,
) -> Result<ExternalCasOffhostAnchorReceipt, OffhostAnchorProtocolError> {
    Ok(ExternalCasOffhostAnchorReceipt {
        kind,
        outcome,
        challenge: request_challenge,
        anchor_id: anchor.anchor_id,
        provider_id: anchor.provider_id,
        network_id: anchor.network_id,
        genesis_digest: anchor.genesis_digest,
        receipt_key_id: anchor.receipt_key_id,
        operation_id,
        request_digest,
        expected_sequence,
        expected_state_digest,
        target_state_digest,
        state_digest: state.digest()?,
        state,
        signature: [0; ML_DSA_65_SIGNATURE_BYTES],
    })
}

/// Error boundary for an Anchor persistence adapter. Unavailability and malformed/corrupt
/// state are distinct from a conditional-write conflict; neither may be treated as success.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExternalCasOffhostAnchorStoreError {
    Unavailable,
    Corrupt,
    Poisoned,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExternalCasOffhostAnchorStoreCasOutcome {
    Applied,
    Conflict(ExternalCasOffhostAnchorState),
}

/// Production adapters MUST implement load_consistent using an authoritative strongly-consistent
/// read and compare_and_swap as ONE server-side conditional transaction over expected sequence
/// AND expected full-state digest. A client-side read followed by unconditional Put is forbidden.
/// The successful write must install the complete next state atomically and return only Applied.
/// On stale precondition it must return the complete currently stored state as Conflict.
///
/// This contract permits a future DynamoDB conditional PutItem adapter; it does not prove that an
/// adapter or independent administrative domain is deployed.
pub trait ExternalCasOffhostAnchorStore: Send + Sync {
    fn load_consistent(
        &self,
    ) -> Result<ExternalCasOffhostAnchorState, ExternalCasOffhostAnchorStoreError>;

    fn compare_and_swap_atomic(
        &self,
        expected_sequence: u64,
        expected_state_digest: &Digest32,
        next_state: &ExternalCasOffhostAnchorState,
    ) -> Result<ExternalCasOffhostAnchorStoreCasOutcome, ExternalCasOffhostAnchorStoreError>;
}

/// Test-only process-local store implementing the same compare-and-swap contract.
/// It is not crash-durable, cross-process, off-host or anti-rollback protected.
pub struct ExternalCasOffhostAnchorMemoryStore {
    state: Mutex<ExternalCasOffhostAnchorState>,
}
impl ExternalCasOffhostAnchorMemoryStore {
    pub fn new(bootstrap: ExternalCasOffhostAnchorState) -> Self {
        Self {
            state: Mutex::new(bootstrap),
        }
    }
}
impl ExternalCasOffhostAnchorStore for ExternalCasOffhostAnchorMemoryStore {
    fn load_consistent(
        &self,
    ) -> Result<ExternalCasOffhostAnchorState, ExternalCasOffhostAnchorStoreError> {
        self.state
            .lock()
            .map(|state| state.clone())
            .map_err(|_| ExternalCasOffhostAnchorStoreError::Poisoned)
    }

    fn compare_and_swap_atomic(
        &self,
        expected_sequence: u64,
        expected_state_digest: &Digest32,
        next_state: &ExternalCasOffhostAnchorState,
    ) -> Result<ExternalCasOffhostAnchorStoreCasOutcome, ExternalCasOffhostAnchorStoreError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| ExternalCasOffhostAnchorStoreError::Poisoned)?;
        let current_digest = state
            .digest()
            .map_err(|_| ExternalCasOffhostAnchorStoreError::Corrupt)?;
        if state.sequence != expected_sequence || &current_digest != expected_state_digest {
            return Ok(ExternalCasOffhostAnchorStoreCasOutcome::Conflict(
                state.clone(),
            ));
        }
        let expected_next_sequence = expected_sequence
            .checked_add(1)
            .ok_or(ExternalCasOffhostAnchorStoreError::Corrupt)?;
        let expected_next_object_generation = state
            .provider_object_generation
            .checked_add(1)
            .ok_or(ExternalCasOffhostAnchorStoreError::Corrupt)?;
        if next_state.sequence != expected_next_sequence
            || next_state.provider_object_generation != expected_next_object_generation
            || next_state.last_expected_anchor_sequence != expected_sequence
            || next_state.last_expected_anchor_state_digest != *expected_state_digest
            || state
                .provider_record
                .validate_successor(&next_state.provider_record)
                .is_err()
            || next_state.last_operation_id != next_state.provider_record.operation_id
            || next_state.last_request_digest != next_state.provider_record.request_digest
            || next_state.digest().is_err()
        {
            return Err(ExternalCasOffhostAnchorStoreError::Corrupt);
        }
        *state = next_state.clone();
        Ok(ExternalCasOffhostAnchorStoreCasOutcome::Applied)
    }
}

/// Protocol model over an injectable Anchor store. The default constructor uses the process-local
/// test store; production callers must supply a separately administered durable CAS adapter.
pub struct ExternalCasOffhostAnchorMemoryModel {
    anchor_pin: ExternalCasOffhostAnchorPin,
    provider_pin: ExternalCasPin,
    store: Arc<dyn ExternalCasOffhostAnchorStore>,
}
impl ExternalCasOffhostAnchorMemoryModel {
    pub fn new(
        anchor_pin: ExternalCasOffhostAnchorPin,
        provider_pin: ExternalCasPin,
        bootstrap: ExternalCasOffhostAnchorState,
    ) -> Result<Self, OffhostAnchorProtocolError> {
        anchor_pin.validate(&provider_pin)?;
        bootstrap.validate(&provider_pin)?;
        let store: Arc<dyn ExternalCasOffhostAnchorStore> =
            Arc::new(ExternalCasOffhostAnchorMemoryStore::new(bootstrap));
        Self::with_store(anchor_pin, provider_pin, store)
    }

    /// Construct over an injected storage adapter. The adapter must implement the atomic
    /// server-side CAS contract; using a local file or read-then-write implementation is unsafe.
    pub fn with_store(
        anchor_pin: ExternalCasOffhostAnchorPin,
        provider_pin: ExternalCasPin,
        store: Arc<dyn ExternalCasOffhostAnchorStore>,
    ) -> Result<Self, OffhostAnchorProtocolError> {
        anchor_pin.validate(&provider_pin)?;
        store
            .load_consistent()
            .map_err(OffhostAnchorProtocolError::Store)?
            .validate(&provider_pin)?;
        Ok(Self {
            anchor_pin,
            provider_pin,
            store,
        })
    }

    pub fn read<S: OffhostAnchorReceiptSigner>(
        &self,
        request: &ExternalCasOffhostAnchorReadRequest,
        signer: &S,
    ) -> Result<ExternalCasOffhostAnchorReceipt, OffhostAnchorProtocolError> {
        request.validate()?;
        let state = self
            .store
            .load_consistent()
            .map_err(OffhostAnchorProtocolError::Store)?;
        // Revalidate every authoritative observation; a backend can become corrupt after
        // service construction or return data from a restored/incorrect persistence domain.
        state.validate(&self.provider_pin)?;

        let mut receipt = new_receipt(
            ExternalCasOffhostAnchorReceiptKind::Read,
            ExternalCasOffhostAnchorReceiptOutcome::Observed,
            &self.anchor_pin,
            request.challenge,
            request.operation_id,
            request.request_digest,
            0,
            [0; 32],
            [0; 32],
            state,
        )?;
        receipt.sign(signer)?;
        Ok(receipt)
    }

    pub fn compare_and_swap<S: OffhostAnchorReceiptSigner, V: MlDsa65Verifier>(
        &self,
        request: &ExternalCasOffhostAnchorCasRequest,
        next_record_bytes: &[u8],
        provider_receipt_bytes: &[u8],
        provider_verifier: &V,
        anchor_signer: &S,
    ) -> Result<ExternalCasOffhostAnchorReceipt, OffhostAnchorProtocolError> {
        request.validate()?;
        let state = self
            .store
            .load_consistent()
            .map_err(OffhostAnchorProtocolError::Store)?;
        state.validate(&self.provider_pin)?;

        // Exact operation retry is checked before the stale predecessor precondition.
        if state.digest()? == request.target_state_digest
            && state.last_operation_id == request.operation_id
            && state.last_request_digest == request.request_digest
            && state.last_expected_anchor_sequence == request.expected_sequence
            && state.last_expected_anchor_state_digest == request.expected_state_digest
        {
            let verified = verify_provider_commit_for_offhost_anchor(
                &self.provider_pin,
                &state,
                next_record_bytes,
                provider_receipt_bytes,
                provider_verifier,
            )?;
            if verified.outcome != ExternalCasOffhostAnchorOutcome::AlreadyApplied {
                return Err(OffhostAnchorProtocolError::WrongOutcome);
            }
            let mut receipt = new_receipt(
                ExternalCasOffhostAnchorReceiptKind::Cas,
                ExternalCasOffhostAnchorReceiptOutcome::AlreadyApplied,
                &self.anchor_pin,
                request.challenge,
                request.operation_id,
                request.request_digest,
                request.expected_sequence,
                request.expected_state_digest,
                request.target_state_digest,
                state,
            )?;
            receipt.sign(anchor_signer)?;
            return Ok(receipt);
        }

        let expected_state_digest = state.digest()?;
        if state.sequence != request.expected_sequence
            || expected_state_digest != request.expected_state_digest
        {
            let mut receipt = new_receipt(
                ExternalCasOffhostAnchorReceiptKind::Cas,
                ExternalCasOffhostAnchorReceiptOutcome::Conflict,
                &self.anchor_pin,
                request.challenge,
                request.operation_id,
                request.request_digest,
                request.expected_sequence,
                request.expected_state_digest,
                request.target_state_digest,
                state,
            )?;
            receipt.sign(anchor_signer)?;
            return Ok(receipt);
        }

        let expected_next_sequence = request
            .expected_sequence
            .checked_add(1)
            .ok_or(OffhostAnchorProtocolError::WrongTarget)?;
        let verified = verify_provider_commit_for_offhost_anchor(
            &self.provider_pin,
            &state,
            next_record_bytes,
            provider_receipt_bytes,
            provider_verifier,
        )?;
        if verified.outcome != ExternalCasOffhostAnchorOutcome::Advance
            || verified.operation_id != request.operation_id
            || verified.request_digest != request.request_digest
            || verified.next_state.digest()? != request.target_state_digest
            || verified.next_state.sequence != expected_next_sequence
        {
            return Err(OffhostAnchorProtocolError::WrongTarget);
        }

        // The backing adapter performs the only authoritative mutation. It must compare both
        // expected sequence and expected full-state digest in one atomic server-side operation.
        match self
            .store
            .compare_and_swap_atomic(
                request.expected_sequence,
                &request.expected_state_digest,
                &verified.next_state,
            )
            .map_err(OffhostAnchorProtocolError::Store)?
        {
            ExternalCasOffhostAnchorStoreCasOutcome::Applied => {
                // Never sign success from the adapter's return value alone. Re-read the
                // authoritative item and require byte/field-exact equality with the target.
                let read_back = self
                    .store
                    .load_consistent()
                    .map_err(OffhostAnchorProtocolError::Store)?;
                read_back.validate(&self.provider_pin)?;
                if read_back != verified.next_state {
                    return Err(OffhostAnchorProtocolError::Store(
                        ExternalCasOffhostAnchorStoreError::Corrupt,
                    ));
                }
                let mut receipt = new_receipt(
                    ExternalCasOffhostAnchorReceiptKind::Cas,
                    ExternalCasOffhostAnchorReceiptOutcome::Applied,
                    &self.anchor_pin,
                    request.challenge,
                    request.operation_id,
                    request.request_digest,
                    request.expected_sequence,
                    request.expected_state_digest,
                    request.target_state_digest,
                    verified.next_state,
                )?;
                receipt.sign(anchor_signer)?;
                Ok(receipt)
            }
            ExternalCasOffhostAnchorStoreCasOutcome::Conflict(current) => {
                current.validate(&self.provider_pin)?;
                // A concurrent exact retry may have won the CAS while this request was in flight.
                if current.digest()? == request.target_state_digest
                    && current.last_operation_id == request.operation_id
                    && current.last_request_digest == request.request_digest
                    && current.last_expected_anchor_sequence == request.expected_sequence
                    && current.last_expected_anchor_state_digest == request.expected_state_digest
                {
                    let retry_verified = verify_provider_commit_for_offhost_anchor(
                        &self.provider_pin,
                        &current,
                        next_record_bytes,
                        provider_receipt_bytes,
                        provider_verifier,
                    )?;
                    if retry_verified.outcome != ExternalCasOffhostAnchorOutcome::AlreadyApplied {
                        return Err(OffhostAnchorProtocolError::WrongOutcome);
                    }
                    let mut receipt = new_receipt(
                        ExternalCasOffhostAnchorReceiptKind::Cas,
                        ExternalCasOffhostAnchorReceiptOutcome::AlreadyApplied,
                        &self.anchor_pin,
                        request.challenge,
                        request.operation_id,
                        request.request_digest,
                        request.expected_sequence,
                        request.expected_state_digest,
                        request.target_state_digest,
                        current,
                    )?;
                    receipt.sign(anchor_signer)?;
                    return Ok(receipt);
                }
                let mut receipt = new_receipt(
                    ExternalCasOffhostAnchorReceiptKind::Cas,
                    ExternalCasOffhostAnchorReceiptOutcome::Conflict,
                    &self.anchor_pin,
                    request.challenge,
                    request.operation_id,
                    request.request_digest,
                    request.expected_sequence,
                    request.expected_state_digest,
                    request.target_state_digest,
                    current,
                )?;
                receipt.sign(anchor_signer)?;
                Ok(receipt)
            }
        }
    }

    pub fn snapshot(&self) -> Result<ExternalCasOffhostAnchorState, OffhostAnchorProtocolError> {
        let state = self
            .store
            .load_consistent()
            .map_err(OffhostAnchorProtocolError::Store)?;
        state.validate(&self.provider_pin)?;
        Ok(state)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        external_cas_anchor_candidate::{
            ExternalCasReceipt, ExternalCasReceiptKind, ExternalCasReceiptOutcome,
            ExternalCasWriteRequest,
        },
        v4_fat1_mldsa65_candidate::LibcruxMlDsa65VerifierCandidate,
    };
    use libcrux_ml_dsa::ml_dsa_65::{portable, MLDSA65SigningKey};
    use std::{sync::Arc, thread};

    struct UnavailableWriteStore {
        state: Mutex<ExternalCasOffhostAnchorState>,
    }
    impl ExternalCasOffhostAnchorStore for UnavailableWriteStore {
        fn load_consistent(
            &self,
        ) -> Result<ExternalCasOffhostAnchorState, ExternalCasOffhostAnchorStoreError> {
            self.state
                .lock()
                .map(|state| state.clone())
                .map_err(|_| ExternalCasOffhostAnchorStoreError::Poisoned)
        }

        fn compare_and_swap_atomic(
            &self,
            _expected_sequence: u64,
            _expected_state_digest: &Digest32,
            _next_state: &ExternalCasOffhostAnchorState,
        ) -> Result<ExternalCasOffhostAnchorStoreCasOutcome, ExternalCasOffhostAnchorStoreError>
        {
            Err(ExternalCasOffhostAnchorStoreError::Unavailable)
        }
    }

    struct FalseAppliedStore {
        state: Mutex<ExternalCasOffhostAnchorState>,
    }
    impl ExternalCasOffhostAnchorStore for FalseAppliedStore {
        fn load_consistent(
            &self,
        ) -> Result<ExternalCasOffhostAnchorState, ExternalCasOffhostAnchorStoreError> {
            self.state
                .lock()
                .map(|state| state.clone())
                .map_err(|_| ExternalCasOffhostAnchorStoreError::Poisoned)
        }

        fn compare_and_swap_atomic(
            &self,
            _expected_sequence: u64,
            _expected_state_digest: &Digest32,
            _next_state: &ExternalCasOffhostAnchorState,
        ) -> Result<ExternalCasOffhostAnchorStoreCasOutcome, ExternalCasOffhostAnchorStoreError>
        {
            // Malicious/buggy adapter claims success without changing authoritative state.
            Ok(ExternalCasOffhostAnchorStoreCasOutcome::Applied)
        }
    }

    struct Signer(Arc<MLDSA65SigningKey>);
    struct FailingSigner;
    impl OffhostAnchorReceiptSigner for FailingSigner {
        fn sign_digest(
            &self,
            _digest: &Digest32,
        ) -> Result<[u8; ML_DSA_65_SIGNATURE_BYTES], String> {
            Err("injected Anchor response-signing failure".to_owned())
        }
    }
    impl OffhostAnchorReceiptSigner for Signer {
        fn sign_digest(
            &self,
            digest: &Digest32,
        ) -> Result<[u8; ML_DSA_65_SIGNATURE_BYTES], String> {
            let signature = portable::sign(self.0.as_ref(), digest, &[], [0xD2; 32])
                .map_err(|error| format!("{error:?}"))?;
            Ok(*signature.as_ref())
        }
    }
    struct Fixture {
        provider_pin: ExternalCasPin,
        provider_signer: Arc<MLDSA65SigningKey>,
        anchor_pin: ExternalCasOffhostAnchorPin,
        anchor_signer: Arc<MLDSA65SigningKey>,
        bootstrap: ExternalCasOffhostAnchorState,
        bootstrap_record: ExternalCasRecord,
    }
    fn fixture() -> Fixture {
        let provider_keys = portable::generate_key_pair([0xC1; 32]);
        let provider_public: [u8; ML_DSA_65_PUBLIC_KEY_BYTES] =
            *provider_keys.verification_key.as_ref();
        let provider_pin = ExternalCasPin {
            provider_id: [0x11; 32],
            network_id: [0x22; 32],
            genesis_digest: [0x33; 32],
            receipt_key_id: [0x44; 32],
            receipt_public_key: provider_public,
        };
        let bootstrap_record = ExternalCasRecord {
            generation: 0,
            provider_id: provider_pin.provider_id,
            network_id: provider_pin.network_id,
            genesis_digest: provider_pin.genesis_digest,
            previous_record_digest: [0; 32],
            previous_state_digest: [0; 32],
            next_state_digest: [0x55; 32],
            operation_id: [0x66; 32],
            request_digest: [0x77; 32],
        };
        let bootstrap = ExternalCasOffhostAnchorState::provision_bootstrap(
            &provider_pin,
            bootstrap_record.clone(),
            1,
        )
        .unwrap();

        let anchor_keys = portable::generate_key_pair([0xD1; 32]);
        let anchor_public: [u8; ML_DSA_65_PUBLIC_KEY_BYTES] =
            *anchor_keys.verification_key.as_ref();
        let anchor_pin = ExternalCasOffhostAnchorPin {
            anchor_id: [0x91; 32],
            provider_id: provider_pin.provider_id,
            network_id: provider_pin.network_id,
            genesis_digest: provider_pin.genesis_digest,
            receipt_key_id: [0x92; 32],
            receipt_public_key: anchor_public,
        };
        Fixture {
            provider_pin,
            provider_signer: Arc::new(provider_keys.signing_key),
            anchor_pin,
            anchor_signer: Arc::new(anchor_keys.signing_key),
            bootstrap,
            bootstrap_record,
        }
    }
    fn anchor_signer(f: &Fixture) -> Signer {
        Signer(f.anchor_signer.clone())
    }

    fn provider_proof(
        f: &Fixture,
        nonce: u8,
        operation: u8,
        target: u8,
        outcome: ExternalCasReceiptOutcome,
    ) -> (ExternalCasRecord, ExternalCasReceipt) {
        let mut request = ExternalCasWriteRequest {
            request_nonce: [nonce; 32],
            operation_id: [operation; 32],
            request_digest: [1; 32],
            expected_generation: 0,
            expected_object_generation: 1,
            expected_record_digest: f.bootstrap_record.digest().unwrap(),
            expected_state_digest: f.bootstrap_record.next_state_digest,
            next_record: ExternalCasRecord {
                generation: 1,
                provider_id: f.provider_pin.provider_id,
                network_id: f.provider_pin.network_id,
                genesis_digest: f.provider_pin.genesis_digest,
                previous_record_digest: f.bootstrap_record.digest().unwrap(),
                previous_state_digest: f.bootstrap_record.next_state_digest,
                next_state_digest: [target; 32],
                operation_id: [operation; 32],
                request_digest: [1; 32],
            },
        };
        request.bind_request_digest(&f.provider_pin).unwrap();
        let mut receipt = ExternalCasReceipt {
            kind: ExternalCasReceiptKind::Commit,
            outcome,
            generation: 1,
            object_generation: 2,
            provider_id: f.provider_pin.provider_id,
            network_id: f.provider_pin.network_id,
            genesis_digest: f.provider_pin.genesis_digest,
            receipt_key_id: f.provider_pin.receipt_key_id,
            request_nonce: request.request_nonce,
            record_digest: request.next_record.digest().unwrap(),
            previous_record_digest: request.next_record.previous_record_digest,
            previous_state_digest: request.next_record.previous_state_digest,
            state_digest: request.next_record.next_state_digest,
            operation_id: request.operation_id,
            request_digest: request.request_digest,
            signature: [0; ML_DSA_65_SIGNATURE_BYTES],
        };
        let digest = receipt.signing_digest().unwrap();
        let signature =
            portable::sign(f.provider_signer.as_ref(), &digest, &[], [0xC2; 32]).unwrap();
        receipt.signature = *signature.as_ref();
        (request.next_record, receipt)
    }

    fn cas_request(
        current: &ExternalCasOffhostAnchorState,
        operation: u8,
        challenge: u8,
        request_digest: Digest32,
        target_digest: Digest32,
    ) -> ExternalCasOffhostAnchorCasRequest {
        ExternalCasOffhostAnchorCasRequest {
            challenge: [challenge; 32],
            operation_id: [operation; 32],
            request_digest,
            expected_sequence: current.sequence,
            expected_state_digest: current.digest().unwrap(),
            target_state_digest: target_digest,
        }
    }

    #[test]
    fn signed_read_roundtrips_and_rejects_replayed_challenge() {
        let f = fixture();
        let model = ExternalCasOffhostAnchorMemoryModel::new(
            f.anchor_pin.clone(),
            f.provider_pin.clone(),
            f.bootstrap.clone(),
        )
        .unwrap();
        let request = ExternalCasOffhostAnchorReadRequest {
            challenge: [0xA1; 32],
            operation_id: [0xA2; 32],
            request_digest: [0xA3; 32],
        };
        let receipt = model.read(&request, &anchor_signer(&f)).unwrap();
        let wire = receipt.encode().unwrap();
        let decoded = ExternalCasOffhostAnchorReceipt::decode(&wire).unwrap();
        assert_eq!(
            decoded
                .verify_read(
                    &f.anchor_pin,
                    &f.provider_pin,
                    &request,
                    &LibcruxMlDsa65VerifierCandidate
                )
                .unwrap(),
            f.bootstrap
        );
        let fresh = ExternalCasOffhostAnchorReadRequest {
            challenge: [0xA4; 32],
            ..request
        };
        assert_eq!(
            decoded.verify_read(
                &f.anchor_pin,
                &f.provider_pin,
                &fresh,
                &LibcruxMlDsa65VerifierCandidate
            ),
            Err(OffhostAnchorProtocolError::WrongChallenge)
        );
    }

    #[test]
    fn cas_commit_is_signed_idempotent_and_ambiguous_outcome_is_resolved_by_fresh_read() {
        let f = fixture();
        let model = ExternalCasOffhostAnchorMemoryModel::new(
            f.anchor_pin.clone(),
            f.provider_pin.clone(),
            f.bootstrap.clone(),
        )
        .unwrap();
        let (next, provider_receipt) =
            provider_proof(&f, 0xB1, 0xB2, 0xB3, ExternalCasReceiptOutcome::Applied);
        let next_state = verify_provider_commit_for_offhost_anchor(
            &f.provider_pin,
            &f.bootstrap,
            &next.encode().unwrap(),
            &provider_receipt.encode().unwrap(),
            &LibcruxMlDsa65VerifierCandidate,
        )
        .unwrap()
        .next_state;
        let request = cas_request(
            &f.bootstrap,
            0xB2,
            0xB4,
            next.request_digest,
            next_state.digest().unwrap(),
        );

        // Simulate a lost CAS response by deliberately discarding it; the next fresh Read proves
        // whether the exact operation became authoritative.
        let lost_response = model
            .compare_and_swap(
                &request,
                &next.encode().unwrap(),
                &provider_receipt.encode().unwrap(),
                &LibcruxMlDsa65VerifierCandidate,
                &anchor_signer(&f),
            )
            .unwrap();
        let lost_response =
            ExternalCasOffhostAnchorReceipt::decode(&lost_response.encode().unwrap()).unwrap();
        assert_eq!(
            lost_response.outcome,
            ExternalCasOffhostAnchorReceiptOutcome::Applied
        );
        let read = ExternalCasOffhostAnchorReadRequest {
            challenge: [0xB5; 32],
            operation_id: [0xB6; 32],
            request_digest: [0xB7; 32],
        };
        let observed = model
            .read(&read, &anchor_signer(&f))
            .unwrap()
            .verify_read(
                &f.anchor_pin,
                &f.provider_pin,
                &read,
                &LibcruxMlDsa65VerifierCandidate,
            )
            .unwrap();
        assert_eq!(observed, next_state);

        let retry = ExternalCasOffhostAnchorCasRequest {
            challenge: [0xB8; 32],
            ..request.clone()
        };
        let already = model
            .compare_and_swap(
                &retry,
                &next.encode().unwrap(),
                &provider_receipt.encode().unwrap(),
                &LibcruxMlDsa65VerifierCandidate,
                &anchor_signer(&f),
            )
            .unwrap();
        let already = ExternalCasOffhostAnchorReceipt::decode(&already.encode().unwrap()).unwrap();
        assert_eq!(
            already.outcome,
            ExternalCasOffhostAnchorReceiptOutcome::AlreadyApplied
        );
        assert_eq!(
            already
                .verify_cas(
                    &f.anchor_pin,
                    &f.provider_pin,
                    &retry,
                    &LibcruxMlDsa65VerifierCandidate
                )
                .unwrap(),
            (
                ExternalCasOffhostAnchorReceiptOutcome::AlreadyApplied,
                next_state.clone()
            )
        );
        let replayed_with_new_challenge = ExternalCasOffhostAnchorCasRequest {
            challenge: [0xB9; 32],
            ..retry
        };
        assert_eq!(
            already.verify_cas(
                &f.anchor_pin,
                &f.provider_pin,
                &replayed_with_new_challenge,
                &LibcruxMlDsa65VerifierCandidate
            ),
            Err(OffhostAnchorProtocolError::WrongChallenge)
        );
    }

    #[test]
    fn anchor_commit_survives_response_signing_failure_and_fresh_read_resolves_it() {
        let f = fixture();
        let model = ExternalCasOffhostAnchorMemoryModel::new(
            f.anchor_pin.clone(),
            f.provider_pin.clone(),
            f.bootstrap.clone(),
        )
        .unwrap();
        let (next, provider_receipt) =
            provider_proof(&f, 0xE1, 0xE2, 0xE3, ExternalCasReceiptOutcome::Applied);
        let next_state = verify_provider_commit_for_offhost_anchor(
            &f.provider_pin,
            &f.bootstrap,
            &next.encode().unwrap(),
            &provider_receipt.encode().unwrap(),
            &LibcruxMlDsa65VerifierCandidate,
        )
        .unwrap()
        .next_state;
        let request = cas_request(
            &f.bootstrap,
            0xE2,
            0xE4,
            next.request_digest,
            next_state.digest().unwrap(),
        );

        let failure = model.compare_and_swap(
            &request,
            &next.encode().unwrap(),
            &provider_receipt.encode().unwrap(),
            &LibcruxMlDsa65VerifierCandidate,
            &FailingSigner,
        );
        assert!(matches!(
            failure,
            Err(OffhostAnchorProtocolError::Signing(_))
        ));
        assert_eq!(model.snapshot().unwrap(), next_state);

        let read = ExternalCasOffhostAnchorReadRequest {
            challenge: [0xE5; 32],
            operation_id: [0xE6; 32],
            request_digest: [0xE7; 32],
        };
        let recovered = model
            .read(&read, &anchor_signer(&f))
            .unwrap()
            .verify_read(
                &f.anchor_pin,
                &f.provider_pin,
                &read,
                &LibcruxMlDsa65VerifierCandidate,
            )
            .unwrap();
        assert_eq!(recovered, next_state);
    }

    #[test]
    fn two_concurrent_successors_have_exactly_one_applied_receipt() {
        let f = fixture();
        let model = Arc::new(
            ExternalCasOffhostAnchorMemoryModel::new(
                f.anchor_pin.clone(),
                f.provider_pin.clone(),
                f.bootstrap.clone(),
            )
            .unwrap(),
        );
        let (next_a, receipt_a) =
            provider_proof(&f, 0xC1, 0xC2, 0xC3, ExternalCasReceiptOutcome::Applied);
        let (next_b, receipt_b) =
            provider_proof(&f, 0xC4, 0xC5, 0xC6, ExternalCasReceiptOutcome::Applied);
        let state_a = verify_provider_commit_for_offhost_anchor(
            &f.provider_pin,
            &f.bootstrap,
            &next_a.encode().unwrap(),
            &receipt_a.encode().unwrap(),
            &LibcruxMlDsa65VerifierCandidate,
        )
        .unwrap()
        .next_state;
        let state_b = verify_provider_commit_for_offhost_anchor(
            &f.provider_pin,
            &f.bootstrap,
            &next_b.encode().unwrap(),
            &receipt_b.encode().unwrap(),
            &LibcruxMlDsa65VerifierCandidate,
        )
        .unwrap()
        .next_state;
        let req_a = cas_request(
            &f.bootstrap,
            0xC2,
            0xC7,
            next_a.request_digest,
            state_a.digest().unwrap(),
        );
        let req_b = cas_request(
            &f.bootstrap,
            0xC5,
            0xC8,
            next_b.request_digest,
            state_b.digest().unwrap(),
        );

        let req_a_verify = req_a.clone();
        let req_b_verify = req_b.clone();
        let m1 = model.clone();
        let m2 = model.clone();
        let f1 = FixtureRef::new(&f);
        let f2 = FixtureRef::new(&f);
        let a = thread::spawn(move || {
            m1.compare_and_swap(
                &req_a,
                &next_a.encode().unwrap(),
                &receipt_a.encode().unwrap(),
                &LibcruxMlDsa65VerifierCandidate,
                &f1.signer,
            )
            .unwrap()
        });
        let b = thread::spawn(move || {
            m2.compare_and_swap(
                &req_b,
                &next_b.encode().unwrap(),
                &receipt_b.encode().unwrap(),
                &LibcruxMlDsa65VerifierCandidate,
                &f2.signer,
            )
            .unwrap()
        });
        let ra = a.join().unwrap();
        let rb = b.join().unwrap();
        let verified_a = ra
            .verify_cas(
                &f.anchor_pin,
                &f.provider_pin,
                &req_a_verify,
                &LibcruxMlDsa65VerifierCandidate,
            )
            .unwrap();
        let verified_b = rb
            .verify_cas(
                &f.anchor_pin,
                &f.provider_pin,
                &req_b_verify,
                &LibcruxMlDsa65VerifierCandidate,
            )
            .unwrap();
        assert_eq!(verified_a.0, ra.outcome);
        assert_eq!(verified_b.0, rb.outcome);
        let winners = [verified_a.0, verified_b.0]
            .into_iter()
            .filter(|o| *o == ExternalCasOffhostAnchorReceiptOutcome::Applied)
            .count();
        let conflicts = [verified_a.0, verified_b.0]
            .into_iter()
            .filter(|o| *o == ExternalCasOffhostAnchorReceiptOutcome::Conflict)
            .count();
        assert_eq!(winners, 1);
        assert_eq!(conflicts, 1);
        assert_eq!(model.snapshot().unwrap().sequence, 2);
    }

    struct FixtureRef {
        signer: Signer,
    }
    impl FixtureRef {
        fn new(f: &Fixture) -> Self {
            Self {
                signer: anchor_signer(f),
            }
        }
    }

    #[test]
    fn atomic_store_contract_compares_sequence_and_full_digest_in_one_cas() {
        let f = fixture();
        let store = ExternalCasOffhostAnchorMemoryStore::new(f.bootstrap.clone());
        let predecessor_digest = f.bootstrap.digest().unwrap();
        let (next_a, receipt_a) =
            provider_proof(&f, 0xF1, 0xF2, 0xF3, ExternalCasReceiptOutcome::Applied);
        let next_state_a = verify_provider_commit_for_offhost_anchor(
            &f.provider_pin,
            &f.bootstrap,
            &next_a.encode().unwrap(),
            &receipt_a.encode().unwrap(),
            &LibcruxMlDsa65VerifierCandidate,
        )
        .unwrap()
        .next_state;
        assert_eq!(
            store
                .compare_and_swap_atomic(1, &predecessor_digest, &next_state_a)
                .unwrap(),
            ExternalCasOffhostAnchorStoreCasOutcome::Applied
        );
        assert_eq!(store.load_consistent().unwrap(), next_state_a);

        // A second successor built from the same predecessor loses the atomic CAS and receives
        // the complete current high-water item; it cannot overwrite the winner.
        let (next_b, receipt_b) =
            provider_proof(&f, 0xF4, 0xF5, 0xF6, ExternalCasReceiptOutcome::Applied);
        let next_state_b = verify_provider_commit_for_offhost_anchor(
            &f.provider_pin,
            &f.bootstrap,
            &next_b.encode().unwrap(),
            &receipt_b.encode().unwrap(),
            &LibcruxMlDsa65VerifierCandidate,
        )
        .unwrap()
        .next_state;
        assert_eq!(
            store
                .compare_and_swap_atomic(1, &predecessor_digest, &next_state_b)
                .unwrap(),
            ExternalCasOffhostAnchorStoreCasOutcome::Conflict(next_state_a.clone())
        );

        // Sequence alone is insufficient: a matching sequence with a substituted state digest
        // also conflicts and leaves the current item unchanged.
        assert_eq!(
            store
                .compare_and_swap_atomic(2, &[0xA7; 32], &next_state_b)
                .unwrap(),
            ExternalCasOffhostAnchorStoreCasOutcome::Conflict(next_state_a.clone())
        );
        assert_eq!(store.load_consistent().unwrap(), next_state_a);
    }

    #[test]
    fn unavailable_atomic_store_never_falls_back_or_publishes_the_target() {
        let f = fixture();
        let store: Arc<dyn ExternalCasOffhostAnchorStore> = Arc::new(UnavailableWriteStore {
            state: Mutex::new(f.bootstrap.clone()),
        });
        let model = ExternalCasOffhostAnchorMemoryModel::with_store(
            f.anchor_pin.clone(),
            f.provider_pin.clone(),
            store,
        )
        .unwrap();
        let (next, provider_receipt) =
            provider_proof(&f, 0xF7, 0xF8, 0xF9, ExternalCasReceiptOutcome::Applied);
        let next_state = verify_provider_commit_for_offhost_anchor(
            &f.provider_pin,
            &f.bootstrap,
            &next.encode().unwrap(),
            &provider_receipt.encode().unwrap(),
            &LibcruxMlDsa65VerifierCandidate,
        )
        .unwrap()
        .next_state;
        let request = cas_request(
            &f.bootstrap,
            0xF8,
            0xFA,
            next.request_digest,
            next_state.digest().unwrap(),
        );

        assert_eq!(
            model.compare_and_swap(
                &request,
                &next.encode().unwrap(),
                &provider_receipt.encode().unwrap(),
                &LibcruxMlDsa65VerifierCandidate,
                &anchor_signer(&f),
            ),
            Err(OffhostAnchorProtocolError::Store(
                ExternalCasOffhostAnchorStoreError::Unavailable
            ))
        );
        assert_eq!(model.snapshot().unwrap(), f.bootstrap);
    }

    #[test]
    fn every_store_observation_is_revalidated_after_service_construction() {
        let f = fixture();
        let store = Arc::new(UnavailableWriteStore {
            state: Mutex::new(f.bootstrap.clone()),
        });
        let adapter: Arc<dyn ExternalCasOffhostAnchorStore> = store.clone();
        let model = ExternalCasOffhostAnchorMemoryModel::with_store(
            f.anchor_pin.clone(),
            f.provider_pin.clone(),
            adapter,
        )
        .unwrap();

        // Simulate corruption/restoration after the service has already initialized.
        store.state.lock().unwrap().last_operation_id[0] ^= 1;
        let expected_protocol_error =
            OffhostAnchorProtocolError::State(ExternalCasOffhostAnchorError::InvalidAnchorState);
        let read = ExternalCasOffhostAnchorReadRequest {
            challenge: [0x71; 32],
            operation_id: [0x72; 32],
            request_digest: [0x73; 32],
        };
        assert_eq!(
            model.read(&read, &anchor_signer(&f)),
            Err(expected_protocol_error.clone())
        );
        assert_eq!(model.snapshot(), Err(expected_protocol_error.clone()));
        let cas = ExternalCasOffhostAnchorCasRequest {
            challenge: [0x74; 32],
            operation_id: [0x75; 32],
            request_digest: [0x76; 32],
            expected_sequence: 1,
            expected_state_digest: f.bootstrap.digest().unwrap(),
            target_state_digest: [0x77; 32],
        };
        assert_eq!(
            model.compare_and_swap(
                &cas,
                &[],
                &[],
                &LibcruxMlDsa65VerifierCandidate,
                &anchor_signer(&f),
            ),
            Err(expected_protocol_error)
        );
    }

    #[test]
    fn adapter_cannot_claim_applied_without_an_exact_authoritative_read_back() {
        let f = fixture();
        let store: Arc<dyn ExternalCasOffhostAnchorStore> = Arc::new(FalseAppliedStore {
            state: Mutex::new(f.bootstrap.clone()),
        });
        let model = ExternalCasOffhostAnchorMemoryModel::with_store(
            f.anchor_pin.clone(),
            f.provider_pin.clone(),
            store,
        )
        .unwrap();
        let (next, provider_receipt) =
            provider_proof(&f, 0x81, 0x82, 0x83, ExternalCasReceiptOutcome::Applied);
        let next_state = verify_provider_commit_for_offhost_anchor(
            &f.provider_pin,
            &f.bootstrap,
            &next.encode().unwrap(),
            &provider_receipt.encode().unwrap(),
            &LibcruxMlDsa65VerifierCandidate,
        )
        .unwrap()
        .next_state;
        let request = cas_request(
            &f.bootstrap,
            0x82,
            0x84,
            next.request_digest,
            next_state.digest().unwrap(),
        );
        assert_eq!(
            model.compare_and_swap(
                &request,
                &next.encode().unwrap(),
                &provider_receipt.encode().unwrap(),
                &LibcruxMlDsa65VerifierCandidate,
                &anchor_signer(&f),
            ),
            Err(OffhostAnchorProtocolError::Store(
                ExternalCasOffhostAnchorStoreError::Corrupt
            ))
        );
        assert_eq!(model.snapshot().unwrap(), f.bootstrap);
    }

    #[test]
    fn conflict_receipt_cannot_certify_the_expected_or_a_rolled_back_state() {
        let f = fixture();
        let signer = anchor_signer(&f);
        let unchanged_digest = f.bootstrap.digest().unwrap();
        let request = ExternalCasOffhostAnchorCasRequest {
            challenge: [0x91; 32],
            operation_id: [0x92; 32],
            request_digest: [0x93; 32],
            expected_sequence: 1,
            expected_state_digest: unchanged_digest,
            target_state_digest: [0x94; 32],
        };
        let mut unchanged_conflict = new_receipt(
            ExternalCasOffhostAnchorReceiptKind::Cas,
            ExternalCasOffhostAnchorReceiptOutcome::Conflict,
            &f.anchor_pin,
            request.challenge,
            request.operation_id,
            request.request_digest,
            request.expected_sequence,
            request.expected_state_digest,
            request.target_state_digest,
            f.bootstrap.clone(),
        )
        .unwrap();
        unchanged_conflict.sign(&signer).unwrap();
        assert_eq!(
            unchanged_conflict.verify_cas(
                &f.anchor_pin,
                &f.provider_pin,
                &request,
                &LibcruxMlDsa65VerifierCandidate,
            ),
            Err(OffhostAnchorProtocolError::WrongOutcome)
        );

        let rollback_request = ExternalCasOffhostAnchorCasRequest {
            expected_sequence: 2,
            expected_state_digest: [0x95; 32],
            challenge: [0x96; 32],
            operation_id: [0x97; 32],
            request_digest: [0x98; 32],
            target_state_digest: [0x99; 32],
        };
        let mut rollback_conflict = new_receipt(
            ExternalCasOffhostAnchorReceiptKind::Cas,
            ExternalCasOffhostAnchorReceiptOutcome::Conflict,
            &f.anchor_pin,
            rollback_request.challenge,
            rollback_request.operation_id,
            rollback_request.request_digest,
            rollback_request.expected_sequence,
            rollback_request.expected_state_digest,
            rollback_request.target_state_digest,
            f.bootstrap.clone(),
        )
        .unwrap();
        rollback_conflict.sign(&signer).unwrap();
        assert_eq!(
            rollback_conflict.verify_cas(
                &f.anchor_pin,
                &f.provider_pin,
                &rollback_request,
                &LibcruxMlDsa65VerifierCandidate,
            ),
            Err(OffhostAnchorProtocolError::WrongOutcome)
        );
    }

    #[test]
    fn anchor_key_must_be_distinct_from_provider_receipt_key() {
        let f = fixture();
        let mut bad = f.anchor_pin.clone();
        bad.receipt_key_id = f.provider_pin.receipt_key_id;
        assert_eq!(
            bad.validate(&f.provider_pin),
            Err(OffhostAnchorProtocolError::ProviderAndAnchorKeysNotIndependent)
        );
        bad = f.anchor_pin.clone();
        bad.receipt_public_key = f.provider_pin.receipt_public_key;
        assert_eq!(
            bad.validate(&f.provider_pin),
            Err(OffhostAnchorProtocolError::ProviderAndAnchorKeysNotIndependent)
        );
    }

    #[test]
    fn altered_state_or_wrong_anchor_domain_rejects_before_acceptance() {
        let f = fixture();
        let model = ExternalCasOffhostAnchorMemoryModel::new(
            f.anchor_pin.clone(),
            f.provider_pin.clone(),
            f.bootstrap.clone(),
        )
        .unwrap();
        let request = ExternalCasOffhostAnchorReadRequest {
            challenge: [0xD1; 32],
            operation_id: [0xD2; 32],
            request_digest: [0xD3; 32],
        };
        let receipt = model.read(&request, &anchor_signer(&f)).unwrap();
        let mut altered = receipt.clone();
        altered.state.provider_record.next_state_digest[0] ^= 1;
        assert_eq!(
            altered.verify_read(
                &f.anchor_pin,
                &f.provider_pin,
                &request,
                &LibcruxMlDsa65VerifierCandidate
            ),
            Err(OffhostAnchorProtocolError::InvalidReceipt)
        );
        let mut wrong_pin = f.anchor_pin.clone();
        wrong_pin.anchor_id[0] ^= 1;
        assert_eq!(
            receipt.verify_read(
                &wrong_pin,
                &f.provider_pin,
                &request,
                &LibcruxMlDsa65VerifierCandidate
            ),
            Err(OffhostAnchorProtocolError::InvalidReceipt)
        );
    }
}
