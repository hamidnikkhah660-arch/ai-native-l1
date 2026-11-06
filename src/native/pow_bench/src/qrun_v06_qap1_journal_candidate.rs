//! CP-0558 candidate: append-only QAP1 intent journal for QFP6 -> Provider -> Q6EA commits.
//!
//! QAP1 v2 is the append-only crash journal for the QFP6 prepare -> Provider -> Q6EA -> publish
//! protocol. The QFP6 store exposes separate prepare/publish APIs gated by an AnchorConfirmed
//! journal. QRunV06NodeRuntime still uses its legacy anchor-gate seam; production wiring to an
//! independently hosted Provider and Q6EA adapter remains a separate integration gate.
//! Every phase snapshot is immutable; a retry may only reproduce byte-identical phase bytes.

use crate::{
    external_cas_anchor_candidate::{
        ExternalCasPin, ExternalCasReceipt, ExternalCasWriteRequest, EXTERNAL_CAS_RECEIPT_BYTES,
        EXTERNAL_CAS_RECORD_BYTES,
    },
    external_cas_offhost_anchor_candidate::{
        verify_provider_commit_for_offhost_anchor, ExternalCasOffhostAnchorState,
    },
    external_cas_offhost_anchor_protocol_candidate::{
        decode_state as decode_anchor_state, encode_state as encode_anchor_state,
        ExternalCasOffhostAnchorCasRequest, ExternalCasOffhostAnchorPin,
        ExternalCasOffhostAnchorReadRequest, ExternalCasOffhostAnchorReceipt,
        OFFHOST_ANCHOR_RECEIPT_BYTES, OFFHOST_ANCHOR_STATE_BYTES,
    },
    qrun_v06_external_anchor_candidate::QRunV06ExternalAnchorState,
    qrun_v06_pow_fork_store_candidate::MAX_QRUN_V06_MANIFEST_BYTES,
    qrun_v06_pow_wire_candidate::MAX_QRUN_V06_POW_ENVELOPE_BYTES,
    store_writer_lock::StoreWriterLock,
    v4_fat1_trust_candidate::MlDsa65Verifier,
};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

const MAGIC: &[u8; 4] = b"QAP1";
const VERSION: u16 = 2;
const CHECKSUM_BYTES: usize = 32;
const CHECKSUM_DOMAIN: &[u8] = b"QRUN-V06-QAP1-JOURNAL-CHECKSUM-V1\0";
const MANIFEST_COMMITMENT_DOMAIN: &[u8] = b"QRUN-V06-DURABLE-FORK-STORE-COMMITMENT-V1\0";
const WRITE_REQUEST_BYTES: usize = 448;
const ANCHOR_CAS_REQUEST_BYTES: usize = 168;
const ANCHOR_READ_REQUEST_BYTES: usize = 96;
const HEADER_BYTES: usize = 12;
pub const QAP1_DIRECTORY: &str = "qfp6-qap1";
const QAP1_PREFIX: &str = "qfp6-anchor-qap1-";
const QAP1_SUFFIX: &str = ".qap1";
const LOCK_NAME: &str = "qfp6-qap1.writer.lock";
static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QRunV06Qap1Error {
    Io(String),
    InvalidJournal,
    InvalidPhase,
    PhaseGap,
    PhaseConflict,
    ChangedIntent,
    WrongProviderPin,
    WrongAnchorPin,
    InvalidProviderReceipt,
    InvalidAnchorReceipt,
    InvalidAnchorRead,
    LocalManifestMismatch,
    Oversize,
    Truncated,
    NonCanonical,
}

impl std::fmt::Display for QRunV06Qap1Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "QFP6 QAP1 journal error: {self:?}")
    }
}
impl std::error::Error for QRunV06Qap1Error {}
impl From<io::Error> for QRunV06Qap1Error {
    fn from(value: io::Error) -> Self {
        Self::Io(value.to_string())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u16)]
pub enum QRunV06Qap1Phase {
    Prepared = 1,
    ProviderCommitted = 2,
    AnchorCasPrepared = 3,
    AnchorCommitted = 4,
    AnchorConfirmed = 5,
    LocalManifestCommitted = 6,
    Finalized = 7,
}
impl TryFrom<u16> for QRunV06Qap1Phase {
    type Error = QRunV06Qap1Error;
    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Prepared),
            2 => Ok(Self::ProviderCommitted),
            3 => Ok(Self::AnchorCasPrepared),
            4 => Ok(Self::AnchorCommitted),
            5 => Ok(Self::AnchorConfirmed),
            6 => Ok(Self::LocalManifestCommitted),
            7 => Ok(Self::Finalized),
            _ => Err(QRunV06Qap1Error::InvalidPhase),
        }
    }
}

/// One immutable exact transition. Provider/Anchor receipts are retained as their complete
/// canonical wire encodings, not reconstructed from a later Read observation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QRunV06Qap1Journal {
    phase: QRunV06Qap1Phase,
    predecessor: QRunV06ExternalAnchorState,
    successor: QRunV06ExternalAnchorState,
    anchor_predecessor: ExternalCasOffhostAnchorState,
    anchor_successor: Option<ExternalCasOffhostAnchorState>,
    provider_request: ExternalCasWriteRequest,
    candidate_envelope: Vec<u8>,
    provider_receipt: Option<Vec<u8>>,
    anchor_cas_request: Option<ExternalCasOffhostAnchorCasRequest>,
    anchor_cas_receipt: Option<Vec<u8>>,
    anchor_read_request: Option<ExternalCasOffhostAnchorReadRequest>,
    anchor_read_receipt: Option<Vec<u8>>,
    next_manifest_bytes: Vec<u8>,
}

fn hash_domain(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update(bytes);
    hash.finalize().into()
}
fn put_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_be_bytes());
}
fn put_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}
fn put_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_be_bytes());
}
fn take<'a>(
    bytes: &'a [u8],
    cursor: &mut usize,
    length: usize,
) -> Result<&'a [u8], QRunV06Qap1Error> {
    let end = cursor
        .checked_add(length)
        .ok_or(QRunV06Qap1Error::Truncated)?;
    let value = bytes.get(*cursor..end).ok_or(QRunV06Qap1Error::Truncated)?;
    *cursor = end;
    Ok(value)
}
fn take_u16(bytes: &[u8], cursor: &mut usize) -> Result<u16, QRunV06Qap1Error> {
    Ok(u16::from_be_bytes(
        take(bytes, cursor, 2)?
            .try_into()
            .map_err(|_| QRunV06Qap1Error::Truncated)?,
    ))
}
fn take_u32(bytes: &[u8], cursor: &mut usize) -> Result<u32, QRunV06Qap1Error> {
    Ok(u32::from_be_bytes(
        take(bytes, cursor, 4)?
            .try_into()
            .map_err(|_| QRunV06Qap1Error::Truncated)?,
    ))
}
fn take_u64(bytes: &[u8], cursor: &mut usize) -> Result<u64, QRunV06Qap1Error> {
    Ok(u64::from_be_bytes(
        take(bytes, cursor, 8)?
            .try_into()
            .map_err(|_| QRunV06Qap1Error::Truncated)?,
    ))
}
fn take_array<const N: usize>(
    bytes: &[u8],
    cursor: &mut usize,
) -> Result<[u8; N], QRunV06Qap1Error> {
    take(bytes, cursor, N)?
        .try_into()
        .map_err(|_| QRunV06Qap1Error::Truncated)
}

fn encode_write_request(
    request: &ExternalCasWriteRequest,
) -> Result<[u8; WRITE_REQUEST_BYTES], QRunV06Qap1Error> {
    let record = request
        .next_record
        .encode()
        .map_err(|_| QRunV06Qap1Error::InvalidJournal)?;
    let mut out = Vec::with_capacity(WRITE_REQUEST_BYTES);
    out.extend_from_slice(&request.request_nonce);
    out.extend_from_slice(&request.operation_id);
    out.extend_from_slice(&request.request_digest);
    put_u64(&mut out, request.expected_generation);
    put_u64(&mut out, request.expected_object_generation);
    out.extend_from_slice(&request.expected_record_digest);
    out.extend_from_slice(&request.expected_state_digest);
    out.extend_from_slice(&record);
    out.try_into().map_err(|_| QRunV06Qap1Error::InvalidJournal)
}

fn decode_write_request(
    bytes: &[u8],
    pin: &ExternalCasPin,
) -> Result<ExternalCasWriteRequest, QRunV06Qap1Error> {
    if bytes.len() != WRITE_REQUEST_BYTES {
        return Err(QRunV06Qap1Error::Truncated);
    }
    let mut cursor = 0;
    let request = ExternalCasWriteRequest {
        request_nonce: take_array(bytes, &mut cursor)?,
        operation_id: take_array(bytes, &mut cursor)?,
        request_digest: take_array(bytes, &mut cursor)?,
        expected_generation: take_u64(bytes, &mut cursor)?,
        expected_object_generation: take_u64(bytes, &mut cursor)?,
        expected_record_digest: take_array(bytes, &mut cursor)?,
        expected_state_digest: take_array(bytes, &mut cursor)?,
        next_record: crate::external_cas_anchor_candidate::ExternalCasRecord::decode(take(
            bytes,
            &mut cursor,
            EXTERNAL_CAS_RECORD_BYTES,
        )?)
        .map_err(|_| QRunV06Qap1Error::InvalidJournal)?,
    };
    if cursor != bytes.len() {
        return Err(QRunV06Qap1Error::NonCanonical);
    }
    request
        .validate(pin)
        .map_err(|_| QRunV06Qap1Error::InvalidJournal)?;
    if encode_write_request(&request)?.as_slice() != bytes {
        return Err(QRunV06Qap1Error::NonCanonical);
    }
    Ok(request)
}

fn encode_anchor_cas_request(
    request: &ExternalCasOffhostAnchorCasRequest,
) -> [u8; ANCHOR_CAS_REQUEST_BYTES] {
    let mut out = Vec::with_capacity(ANCHOR_CAS_REQUEST_BYTES);
    out.extend_from_slice(&request.challenge);
    out.extend_from_slice(&request.operation_id);
    out.extend_from_slice(&request.request_digest);
    put_u64(&mut out, request.expected_sequence);
    out.extend_from_slice(&request.expected_state_digest);
    out.extend_from_slice(&request.target_state_digest);
    out.try_into().expect("fixed Q6EA CAS request size")
}
fn decode_anchor_cas_request(
    bytes: &[u8],
) -> Result<ExternalCasOffhostAnchorCasRequest, QRunV06Qap1Error> {
    if bytes.len() != ANCHOR_CAS_REQUEST_BYTES {
        return Err(QRunV06Qap1Error::Truncated);
    }
    let mut cursor = 0;
    let request = ExternalCasOffhostAnchorCasRequest {
        challenge: take_array(bytes, &mut cursor)?,
        operation_id: take_array(bytes, &mut cursor)?,
        request_digest: take_array(bytes, &mut cursor)?,
        expected_sequence: take_u64(bytes, &mut cursor)?,
        expected_state_digest: take_array(bytes, &mut cursor)?,
        target_state_digest: take_array(bytes, &mut cursor)?,
    };
    request
        .validate()
        .map_err(|_| QRunV06Qap1Error::InvalidJournal)?;
    Ok(request)
}
fn encode_anchor_read_request(
    request: &ExternalCasOffhostAnchorReadRequest,
) -> [u8; ANCHOR_READ_REQUEST_BYTES] {
    let mut out = Vec::with_capacity(ANCHOR_READ_REQUEST_BYTES);
    out.extend_from_slice(&request.challenge);
    out.extend_from_slice(&request.operation_id);
    out.extend_from_slice(&request.request_digest);
    out.try_into().expect("fixed Q6EA Read request size")
}
fn decode_anchor_read_request(
    bytes: &[u8],
) -> Result<ExternalCasOffhostAnchorReadRequest, QRunV06Qap1Error> {
    if bytes.len() != ANCHOR_READ_REQUEST_BYTES {
        return Err(QRunV06Qap1Error::Truncated);
    }
    let request = ExternalCasOffhostAnchorReadRequest {
        challenge: bytes[0..32]
            .try_into()
            .map_err(|_| QRunV06Qap1Error::Truncated)?,
        operation_id: bytes[32..64]
            .try_into()
            .map_err(|_| QRunV06Qap1Error::Truncated)?,
        request_digest: bytes[64..96]
            .try_into()
            .map_err(|_| QRunV06Qap1Error::Truncated)?,
    };
    request
        .validate()
        .map_err(|_| QRunV06Qap1Error::InvalidJournal)?;
    Ok(request)
}

impl QRunV06Qap1Journal {
    /// Prepare a QAP1 intent before any Provider CAS and before publishing the QFP6 manifest.
    /// The exact next manifest bytes and exact Provider request are immutable for this intent.
    pub fn new(
        predecessor: QRunV06ExternalAnchorState,
        successor: QRunV06ExternalAnchorState,
        anchor_predecessor: ExternalCasOffhostAnchorState,
        provider_request: ExternalCasWriteRequest,
        candidate_envelope: Vec<u8>,
        next_manifest_bytes: Vec<u8>,
        provider_pin: &ExternalCasPin,
    ) -> Result<Self, QRunV06Qap1Error> {
        let value = Self {
            phase: QRunV06Qap1Phase::Prepared,
            predecessor,
            successor,
            anchor_predecessor,
            anchor_successor: None,
            provider_request,
            candidate_envelope,
            provider_receipt: None,
            anchor_cas_request: None,
            anchor_cas_receipt: None,
            anchor_read_request: None,
            anchor_read_receipt: None,
            next_manifest_bytes,
        };
        value.validate_shape(provider_pin)?;
        Ok(value)
    }

    pub fn phase(&self) -> QRunV06Qap1Phase {
        self.phase
    }
    pub fn predecessor(&self) -> &QRunV06ExternalAnchorState {
        &self.predecessor
    }
    pub fn successor(&self) -> &QRunV06ExternalAnchorState {
        &self.successor
    }
    pub fn provider_request(&self) -> &ExternalCasWriteRequest {
        &self.provider_request
    }
    pub fn anchor_predecessor(&self) -> &ExternalCasOffhostAnchorState {
        &self.anchor_predecessor
    }
    pub fn provider_receipt_bytes(&self) -> Option<&[u8]> {
        self.provider_receipt.as_deref()
    }
    pub fn anchor_cas_request(&self) -> Option<&ExternalCasOffhostAnchorCasRequest> {
        self.anchor_cas_request.as_ref()
    }
    pub fn candidate_envelope(&self) -> &[u8] {
        &self.candidate_envelope
    }
    pub fn next_manifest_bytes(&self) -> &[u8] {
        &self.next_manifest_bytes
    }
    pub fn anchor_successor(&self) -> Option<&ExternalCasOffhostAnchorState> {
        self.anchor_successor.as_ref()
    }

    pub fn record_provider_receipt<V: MlDsa65Verifier>(
        &self,
        receipt_bytes: &[u8],
        provider_pin: &ExternalCasPin,
        provider_verifier: &V,
    ) -> Result<Self, QRunV06Qap1Error> {
        if self.phase != QRunV06Qap1Phase::Prepared {
            return Err(QRunV06Qap1Error::InvalidPhase);
        }
        let receipt = ExternalCasReceipt::decode(receipt_bytes)
            .map_err(|_| QRunV06Qap1Error::InvalidProviderReceipt)?;
        receipt
            .verify_commit(provider_pin, &self.provider_request, provider_verifier)
            .map_err(|_| QRunV06Qap1Error::InvalidProviderReceipt)?;
        let record_bytes = self
            .provider_request
            .next_record
            .encode()
            .map_err(|_| QRunV06Qap1Error::InvalidProviderReceipt)?;
        let verified = verify_provider_commit_for_offhost_anchor(
            provider_pin,
            &self.anchor_predecessor,
            &record_bytes,
            receipt_bytes,
            provider_verifier,
        )
        .map_err(|_| QRunV06Qap1Error::InvalidProviderReceipt)?;
        if verified.next_state.provider_record != self.provider_request.next_record
            || verified.next_state.provider_record.next_state_digest
                != self
                    .successor
                    .digest()
                    .map_err(|_| QRunV06Qap1Error::InvalidJournal)?
        {
            return Err(QRunV06Qap1Error::InvalidProviderReceipt);
        }
        let mut next = self.clone();
        next.provider_receipt = Some(receipt_bytes.to_vec());
        next.anchor_successor = Some(verified.next_state);
        next.phase = QRunV06Qap1Phase::ProviderCommitted;
        next.validate_shape(provider_pin)?;
        Ok(next)
    }

    pub fn prepare_anchor_cas(
        &self,
        request: ExternalCasOffhostAnchorCasRequest,
        provider_pin: &ExternalCasPin,
    ) -> Result<Self, QRunV06Qap1Error> {
        if self.phase != QRunV06Qap1Phase::ProviderCommitted {
            return Err(QRunV06Qap1Error::InvalidPhase);
        }
        request
            .validate()
            .map_err(|_| QRunV06Qap1Error::InvalidJournal)?;
        let target = self
            .anchor_successor
            .as_ref()
            .ok_or(QRunV06Qap1Error::InvalidJournal)?;
        if request.expected_sequence != self.anchor_predecessor.sequence
            || request.expected_state_digest
                != self
                    .anchor_predecessor
                    .digest()
                    .map_err(|_| QRunV06Qap1Error::InvalidJournal)?
            || request.target_state_digest
                != target
                    .digest()
                    .map_err(|_| QRunV06Qap1Error::InvalidJournal)?
            || request.operation_id != self.provider_request.operation_id
            || request.request_digest != self.provider_request.request_digest
        {
            return Err(QRunV06Qap1Error::InvalidJournal);
        }
        let mut next = self.clone();
        next.anchor_cas_request = Some(request);
        next.phase = QRunV06Qap1Phase::AnchorCasPrepared;
        next.validate_shape(provider_pin)?;
        Ok(next)
    }

    pub fn record_anchor_receipt<V: MlDsa65Verifier>(
        &self,
        receipt_bytes: &[u8],
        anchor_pin: &ExternalCasOffhostAnchorPin,
        provider_pin: &ExternalCasPin,
        anchor_verifier: &V,
    ) -> Result<Self, QRunV06Qap1Error> {
        if self.phase != QRunV06Qap1Phase::AnchorCasPrepared {
            return Err(QRunV06Qap1Error::InvalidPhase);
        }
        let request = self
            .anchor_cas_request
            .as_ref()
            .ok_or(QRunV06Qap1Error::InvalidJournal)?;
        let receipt = ExternalCasOffhostAnchorReceipt::decode(receipt_bytes)
            .map_err(|_| QRunV06Qap1Error::InvalidAnchorReceipt)?;
        let (outcome, observed) = receipt
            .verify_cas(anchor_pin, provider_pin, request, anchor_verifier)
            .map_err(|_| QRunV06Qap1Error::InvalidAnchorReceipt)?;
        if !matches!(
            outcome,
            crate::external_cas_offhost_anchor_protocol_candidate::ExternalCasOffhostAnchorReceiptOutcome::Applied
                | crate::external_cas_offhost_anchor_protocol_candidate::ExternalCasOffhostAnchorReceiptOutcome::AlreadyApplied
        ) || Some(&observed) != self.anchor_successor.as_ref()
        {
            return Err(QRunV06Qap1Error::InvalidAnchorReceipt);
        }
        let mut next = self.clone();
        next.anchor_cas_receipt = Some(receipt_bytes.to_vec());
        next.phase = QRunV06Qap1Phase::AnchorCommitted;
        next.validate_shape(provider_pin)?;
        Ok(next)
    }

    pub fn confirm_anchor_read<V: MlDsa65Verifier>(
        &self,
        request: ExternalCasOffhostAnchorReadRequest,
        receipt_bytes: &[u8],
        anchor_pin: &ExternalCasOffhostAnchorPin,
        provider_pin: &ExternalCasPin,
        anchor_verifier: &V,
    ) -> Result<Self, QRunV06Qap1Error> {
        if self.phase != QRunV06Qap1Phase::AnchorCommitted {
            return Err(QRunV06Qap1Error::InvalidPhase);
        }
        let receipt = ExternalCasOffhostAnchorReceipt::decode(receipt_bytes)
            .map_err(|_| QRunV06Qap1Error::InvalidAnchorRead)?;
        let observed = receipt
            .verify_read(anchor_pin, provider_pin, &request, anchor_verifier)
            .map_err(|_| QRunV06Qap1Error::InvalidAnchorRead)?;
        if Some(&observed) != self.anchor_successor.as_ref() {
            return Err(QRunV06Qap1Error::InvalidAnchorRead);
        }
        let mut next = self.clone();
        next.anchor_read_request = Some(request);
        next.anchor_read_receipt = Some(receipt_bytes.to_vec());
        next.phase = QRunV06Qap1Phase::AnchorConfirmed;
        next.validate_shape(provider_pin)?;
        Ok(next)
    }

    pub fn mark_local_manifest_committed(
        &self,
        local_state: &QRunV06ExternalAnchorState,
        provider_pin: &ExternalCasPin,
    ) -> Result<Self, QRunV06Qap1Error> {
        if self.phase != QRunV06Qap1Phase::AnchorConfirmed || local_state != &self.successor {
            return Err(QRunV06Qap1Error::LocalManifestMismatch);
        }
        let mut next = self.clone();
        next.phase = QRunV06Qap1Phase::LocalManifestCommitted;
        next.validate_shape(provider_pin)?;
        Ok(next)
    }

    fn finalized(
        &self,
        local_state: &QRunV06ExternalAnchorState,
    ) -> Result<Self, QRunV06Qap1Error> {
        if self.phase != QRunV06Qap1Phase::LocalManifestCommitted || local_state != &self.successor
        {
            return Err(QRunV06Qap1Error::LocalManifestMismatch);
        }
        let mut next = self.clone();
        next.phase = QRunV06Qap1Phase::Finalized;
        Ok(next)
    }

    /// Re-verify every saved cryptographic receipt after process restart. Decoding and the
    /// journal checksum prove canonical local bytes only; they do not establish signature trust.
    pub fn verify_saved_evidence<PV: MlDsa65Verifier, AV: MlDsa65Verifier>(
        &self,
        provider_pin: &ExternalCasPin,
        anchor_pin: &ExternalCasOffhostAnchorPin,
        provider_verifier: &PV,
        anchor_verifier: &AV,
    ) -> Result<(), QRunV06Qap1Error> {
        anchor_pin
            .validate(provider_pin)
            .map_err(|_| QRunV06Qap1Error::WrongAnchorPin)?;
        self.validate_shape(provider_pin)?;
        let mut replay = self.clone();
        replay.phase = QRunV06Qap1Phase::Prepared;
        replay.anchor_successor = None;
        replay.provider_receipt = None;
        replay.anchor_cas_request = None;
        replay.anchor_cas_receipt = None;
        replay.anchor_read_request = None;
        replay.anchor_read_receipt = None;
        if self.phase >= QRunV06Qap1Phase::ProviderCommitted {
            replay = replay.record_provider_receipt(
                self.provider_receipt
                    .as_deref()
                    .ok_or(QRunV06Qap1Error::InvalidProviderReceipt)?,
                provider_pin,
                provider_verifier,
            )?;
        }
        if self.phase >= QRunV06Qap1Phase::AnchorCasPrepared {
            replay = replay.prepare_anchor_cas(
                self.anchor_cas_request
                    .clone()
                    .ok_or(QRunV06Qap1Error::InvalidJournal)?,
                provider_pin,
            )?;
        }
        if self.phase >= QRunV06Qap1Phase::AnchorCommitted {
            replay = replay.record_anchor_receipt(
                self.anchor_cas_receipt
                    .as_deref()
                    .ok_or(QRunV06Qap1Error::InvalidAnchorReceipt)?,
                anchor_pin,
                provider_pin,
                anchor_verifier,
            )?;
        }
        if self.phase >= QRunV06Qap1Phase::AnchorConfirmed {
            replay = replay.confirm_anchor_read(
                self.anchor_read_request
                    .clone()
                    .ok_or(QRunV06Qap1Error::InvalidAnchorRead)?,
                self.anchor_read_receipt
                    .as_deref()
                    .ok_or(QRunV06Qap1Error::InvalidAnchorRead)?,
                anchor_pin,
                provider_pin,
                anchor_verifier,
            )?;
        }
        if self.phase >= QRunV06Qap1Phase::LocalManifestCommitted {
            replay = replay.mark_local_manifest_committed(&self.successor, provider_pin)?;
        }
        if self.phase == QRunV06Qap1Phase::Finalized {
            replay = replay.finalized(&self.successor)?;
        }
        if replay.encode()? != self.encode()? {
            return Err(QRunV06Qap1Error::NonCanonical);
        }
        Ok(())
    }

    fn validate_shape(&self, provider_pin: &ExternalCasPin) -> Result<(), QRunV06Qap1Error> {
        self.predecessor
            .validate()
            .map_err(|_| QRunV06Qap1Error::InvalidJournal)?;
        self.successor
            .validate()
            .map_err(|_| QRunV06Qap1Error::InvalidJournal)?;
        self.predecessor
            .validate_successor(&self.successor)
            .map_err(|_| QRunV06Qap1Error::InvalidJournal)?;
        self.anchor_predecessor
            .validate(provider_pin)
            .map_err(|_| QRunV06Qap1Error::InvalidJournal)?;
        provider_pin
            .validate()
            .map_err(|_| QRunV06Qap1Error::WrongProviderPin)?;
        if self.candidate_envelope.is_empty()
            || self.candidate_envelope.len() > MAX_QRUN_V06_POW_ENVELOPE_BYTES
            || self.next_manifest_bytes.is_empty()
            || self.next_manifest_bytes.len() > MAX_QRUN_V06_MANIFEST_BYTES
            || hash_domain(MANIFEST_COMMITMENT_DOMAIN, &self.next_manifest_bytes)
                != self.successor.manifest_anchor
        {
            return Err(QRunV06Qap1Error::InvalidJournal);
        }
        self.provider_request
            .validate(provider_pin)
            .map_err(|_| QRunV06Qap1Error::InvalidJournal)?;
        let predecessor_digest = self
            .predecessor
            .digest()
            .map_err(|_| QRunV06Qap1Error::InvalidJournal)?;
        let successor_digest = self
            .successor
            .digest()
            .map_err(|_| QRunV06Qap1Error::InvalidJournal)?;
        if self.predecessor.network_id != provider_pin.network_id
            || self.predecessor.genesis_digest != provider_pin.genesis_digest
            || self.successor.network_id != provider_pin.network_id
            || self.successor.genesis_digest != provider_pin.genesis_digest
            || self.anchor_predecessor.provider_record.generation
                != self.provider_request.expected_generation
            || self.anchor_predecessor.provider_object_generation
                != self.provider_request.expected_object_generation
            || self.anchor_predecessor.provider_record.digest().ok()
                != Some(self.provider_request.expected_record_digest)
            || self.anchor_predecessor.provider_record.next_state_digest != predecessor_digest
            || self.provider_request.expected_state_digest != predecessor_digest
            || self.provider_request.next_record.next_state_digest != successor_digest
        {
            return Err(QRunV06Qap1Error::InvalidJournal);
        }
        let has_provider = self.provider_receipt.is_some() && self.anchor_successor.is_some();
        let has_anchor_request = self.anchor_cas_request.is_some();
        let has_anchor_receipt = self.anchor_cas_receipt.is_some();
        let has_anchor_read =
            self.anchor_read_request.is_some() && self.anchor_read_receipt.is_some();
        match self.phase {
            QRunV06Qap1Phase::Prepared => {
                if self.provider_receipt.is_some()
                    || self.anchor_successor.is_some()
                    || has_anchor_request
                    || has_anchor_receipt
                    || has_anchor_read
                {
                    return Err(QRunV06Qap1Error::InvalidJournal);
                }
            }
            QRunV06Qap1Phase::ProviderCommitted => {
                if !has_provider || has_anchor_request || has_anchor_receipt || has_anchor_read {
                    return Err(QRunV06Qap1Error::InvalidJournal);
                }
            }
            QRunV06Qap1Phase::AnchorCasPrepared => {
                if !has_provider || !has_anchor_request || has_anchor_receipt || has_anchor_read {
                    return Err(QRunV06Qap1Error::InvalidJournal);
                }
            }
            QRunV06Qap1Phase::AnchorCommitted => {
                if !has_provider || !has_anchor_request || !has_anchor_receipt || has_anchor_read {
                    return Err(QRunV06Qap1Error::InvalidJournal);
                }
            }
            QRunV06Qap1Phase::AnchorConfirmed
            | QRunV06Qap1Phase::LocalManifestCommitted
            | QRunV06Qap1Phase::Finalized => {
                if !has_provider || !has_anchor_request || !has_anchor_receipt || !has_anchor_read {
                    return Err(QRunV06Qap1Error::InvalidJournal);
                }
            }
        }
        if let Some(anchor_after) = &self.anchor_successor {
            anchor_after
                .validate(provider_pin)
                .map_err(|_| QRunV06Qap1Error::InvalidJournal)?;
            if anchor_after.provider_record != self.provider_request.next_record
                || anchor_after.provider_record.next_state_digest != successor_digest
            {
                return Err(QRunV06Qap1Error::InvalidJournal);
            }
        }
        if let Some(request) = &self.anchor_cas_request {
            request
                .validate()
                .map_err(|_| QRunV06Qap1Error::InvalidJournal)?;
            let anchor_after = self
                .anchor_successor
                .as_ref()
                .ok_or(QRunV06Qap1Error::InvalidJournal)?;
            if request.expected_sequence != self.anchor_predecessor.sequence
                || request.expected_state_digest
                    != self
                        .anchor_predecessor
                        .digest()
                        .map_err(|_| QRunV06Qap1Error::InvalidJournal)?
                || request.target_state_digest
                    != anchor_after
                        .digest()
                        .map_err(|_| QRunV06Qap1Error::InvalidJournal)?
                || request.operation_id != self.provider_request.operation_id
                || request.request_digest != self.provider_request.request_digest
            {
                return Err(QRunV06Qap1Error::InvalidJournal);
            }
        }
        if let Some(bytes) = &self.provider_receipt {
            if bytes.len() != EXTERNAL_CAS_RECEIPT_BYTES
                || ExternalCasReceipt::decode(bytes).is_err()
            {
                return Err(QRunV06Qap1Error::InvalidProviderReceipt);
            }
        }
        if let Some(bytes) = &self.anchor_cas_receipt {
            if bytes.len() != OFFHOST_ANCHOR_RECEIPT_BYTES
                || ExternalCasOffhostAnchorReceipt::decode(bytes).is_err()
            {
                return Err(QRunV06Qap1Error::InvalidAnchorReceipt);
            }
        }
        if let Some(bytes) = &self.anchor_read_receipt {
            if bytes.len() != OFFHOST_ANCHOR_RECEIPT_BYTES
                || ExternalCasOffhostAnchorReceipt::decode(bytes).is_err()
            {
                return Err(QRunV06Qap1Error::InvalidAnchorRead);
            }
        }
        Ok(())
    }

    fn encode(&self) -> Result<Vec<u8>, QRunV06Qap1Error> {
        let mut out = Vec::new();
        out.extend_from_slice(MAGIC);
        put_u16(&mut out, VERSION);
        put_u16(&mut out, self.phase as u16);
        put_u32(&mut out, 0);
        out.extend_from_slice(
            &self
                .predecessor
                .encode()
                .map_err(|_| QRunV06Qap1Error::InvalidJournal)?,
        );
        out.extend_from_slice(
            &self
                .successor
                .encode()
                .map_err(|_| QRunV06Qap1Error::InvalidJournal)?,
        );
        out.extend_from_slice(
            &encode_anchor_state(&self.anchor_predecessor)
                .map_err(|_| QRunV06Qap1Error::InvalidJournal)?,
        );
        match &self.anchor_successor {
            Some(state) => {
                put_u16(&mut out, OFFHOST_ANCHOR_STATE_BYTES as u16);
                out.extend_from_slice(
                    &encode_anchor_state(state).map_err(|_| QRunV06Qap1Error::InvalidJournal)?,
                );
            }
            None => put_u16(&mut out, 0),
        }
        out.extend_from_slice(&encode_write_request(&self.provider_request)?);
        put_u32(
            &mut out,
            self.provider_receipt.as_ref().map_or(0, |v| v.len()) as u32,
        );
        if let Some(bytes) = &self.provider_receipt {
            out.extend_from_slice(bytes);
        }
        match &self.anchor_cas_request {
            Some(request) => {
                put_u16(&mut out, ANCHOR_CAS_REQUEST_BYTES as u16);
                out.extend_from_slice(&encode_anchor_cas_request(request));
            }
            None => put_u16(&mut out, 0),
        }
        put_u32(
            &mut out,
            self.anchor_cas_receipt.as_ref().map_or(0, |v| v.len()) as u32,
        );
        if let Some(bytes) = &self.anchor_cas_receipt {
            out.extend_from_slice(bytes);
        }
        match &self.anchor_read_request {
            Some(request) => {
                put_u16(&mut out, ANCHOR_READ_REQUEST_BYTES as u16);
                out.extend_from_slice(&encode_anchor_read_request(request));
            }
            None => put_u16(&mut out, 0),
        }
        put_u32(
            &mut out,
            self.anchor_read_receipt.as_ref().map_or(0, |v| v.len()) as u32,
        );
        if let Some(bytes) = &self.anchor_read_receipt {
            out.extend_from_slice(bytes);
        }
        put_u32(&mut out, self.candidate_envelope.len() as u32);
        out.extend_from_slice(&self.candidate_envelope);
        put_u32(&mut out, self.next_manifest_bytes.len() as u32);
        out.extend_from_slice(&self.next_manifest_bytes);
        let checksum = hash_domain(CHECKSUM_DOMAIN, &out);
        out.extend_from_slice(&checksum);
        if out.len() > MAX_QAP1_BYTES {
            return Err(QRunV06Qap1Error::Oversize);
        }
        Ok(out)
    }

    fn decode(bytes: &[u8], provider_pin: &ExternalCasPin) -> Result<Self, QRunV06Qap1Error> {
        if bytes.len() > MAX_QAP1_BYTES || bytes.len() < HEADER_BYTES + CHECKSUM_BYTES {
            return Err(QRunV06Qap1Error::Oversize);
        }
        let checksum_at = bytes.len() - CHECKSUM_BYTES;
        if hash_domain(CHECKSUM_DOMAIN, &bytes[..checksum_at]) != bytes[checksum_at..] {
            return Err(QRunV06Qap1Error::NonCanonical);
        }
        let mut cursor = 0;
        if take(bytes, &mut cursor, 4)? != MAGIC {
            return Err(QRunV06Qap1Error::NonCanonical);
        }
        if take_u16(bytes, &mut cursor)? != VERSION {
            return Err(QRunV06Qap1Error::NonCanonical);
        }
        let phase = QRunV06Qap1Phase::try_from(take_u16(bytes, &mut cursor)?)?;
        if take_u32(bytes, &mut cursor)? != 0 {
            return Err(QRunV06Qap1Error::NonCanonical);
        }
        let predecessor = QRunV06ExternalAnchorState::decode(take(bytes, &mut cursor, 384)?)
            .map_err(|_| QRunV06Qap1Error::InvalidJournal)?;
        let successor = QRunV06ExternalAnchorState::decode(take(bytes, &mut cursor, 384)?)
            .map_err(|_| QRunV06Qap1Error::InvalidJournal)?;
        let anchor_predecessor =
            decode_anchor_state(take(bytes, &mut cursor, OFFHOST_ANCHOR_STATE_BYTES)?)
                .map_err(|_| QRunV06Qap1Error::InvalidJournal)?;
        let anchor_successor_len = take_u16(bytes, &mut cursor)? as usize;
        let anchor_successor = match anchor_successor_len {
            0 => None,
            OFFHOST_ANCHOR_STATE_BYTES => Some(
                decode_anchor_state(take(bytes, &mut cursor, OFFHOST_ANCHOR_STATE_BYTES)?)
                    .map_err(|_| QRunV06Qap1Error::InvalidJournal)?,
            ),
            _ => return Err(QRunV06Qap1Error::NonCanonical),
        };
        let provider_request =
            decode_write_request(take(bytes, &mut cursor, WRITE_REQUEST_BYTES)?, provider_pin)?;
        let provider_receipt_len = take_u32(bytes, &mut cursor)? as usize;
        let provider_receipt = match provider_receipt_len {
            0 => None,
            EXTERNAL_CAS_RECEIPT_BYTES => {
                Some(take(bytes, &mut cursor, EXTERNAL_CAS_RECEIPT_BYTES)?.to_vec())
            }
            _ => return Err(QRunV06Qap1Error::NonCanonical),
        };
        let anchor_cas_request_len = take_u16(bytes, &mut cursor)? as usize;
        let anchor_cas_request = match anchor_cas_request_len {
            0 => None,
            ANCHOR_CAS_REQUEST_BYTES => Some(decode_anchor_cas_request(take(
                bytes,
                &mut cursor,
                ANCHOR_CAS_REQUEST_BYTES,
            )?)?),
            _ => return Err(QRunV06Qap1Error::NonCanonical),
        };
        let anchor_cas_receipt_len = take_u32(bytes, &mut cursor)? as usize;
        let anchor_cas_receipt = match anchor_cas_receipt_len {
            0 => None,
            OFFHOST_ANCHOR_RECEIPT_BYTES => {
                Some(take(bytes, &mut cursor, OFFHOST_ANCHOR_RECEIPT_BYTES)?.to_vec())
            }
            _ => return Err(QRunV06Qap1Error::NonCanonical),
        };
        let anchor_read_request_len = take_u16(bytes, &mut cursor)? as usize;
        let anchor_read_request = match anchor_read_request_len {
            0 => None,
            ANCHOR_READ_REQUEST_BYTES => Some(decode_anchor_read_request(take(
                bytes,
                &mut cursor,
                ANCHOR_READ_REQUEST_BYTES,
            )?)?),
            _ => return Err(QRunV06Qap1Error::NonCanonical),
        };
        let anchor_read_receipt_len = take_u32(bytes, &mut cursor)? as usize;
        let anchor_read_receipt = match anchor_read_receipt_len {
            0 => None,
            OFFHOST_ANCHOR_RECEIPT_BYTES => {
                Some(take(bytes, &mut cursor, OFFHOST_ANCHOR_RECEIPT_BYTES)?.to_vec())
            }
            _ => return Err(QRunV06Qap1Error::NonCanonical),
        };
        let candidate_envelope_len = take_u32(bytes, &mut cursor)? as usize;
        if candidate_envelope_len == 0 || candidate_envelope_len > MAX_QRUN_V06_POW_ENVELOPE_BYTES {
            return Err(QRunV06Qap1Error::Oversize);
        }
        let candidate_envelope = take(bytes, &mut cursor, candidate_envelope_len)?.to_vec();
        let manifest_len = take_u32(bytes, &mut cursor)? as usize;
        if manifest_len == 0 || manifest_len > MAX_QRUN_V06_MANIFEST_BYTES {
            return Err(QRunV06Qap1Error::Oversize);
        }
        let next_manifest_bytes = take(bytes, &mut cursor, manifest_len)?.to_vec();
        if cursor != checksum_at {
            return Err(QRunV06Qap1Error::NonCanonical);
        }
        let journal = Self {
            phase,
            predecessor,
            successor,
            anchor_predecessor,
            anchor_successor,
            provider_request,
            candidate_envelope,
            provider_receipt,
            anchor_cas_request,
            anchor_cas_receipt,
            anchor_read_request,
            anchor_read_receipt,
            next_manifest_bytes,
        };
        journal.validate_shape(provider_pin)?;
        if journal.encode()?.as_slice() != bytes {
            return Err(QRunV06Qap1Error::NonCanonical);
        }
        Ok(journal)
    }

    fn same_immutable_intent(&self, other: &Self) -> bool {
        self.predecessor == other.predecessor
            && self.successor == other.successor
            && self.anchor_predecessor == other.anchor_predecessor
            && self.provider_request == other.provider_request
            && self.candidate_envelope == other.candidate_envelope
            && self.next_manifest_bytes == other.next_manifest_bytes
    }

    fn validate_successive_snapshot(&self, previous: &Self) -> Result<(), QRunV06Qap1Error> {
        if !self.same_immutable_intent(previous) || self.phase as u16 != previous.phase as u16 + 1 {
            return Err(QRunV06Qap1Error::ChangedIntent);
        }
        let valid = match (previous.phase, self.phase) {
            (QRunV06Qap1Phase::Prepared, QRunV06Qap1Phase::ProviderCommitted) => {
                self.provider_receipt.is_some()
                    && self.anchor_successor.is_some()
                    && self.anchor_cas_request.is_none()
            }
            (QRunV06Qap1Phase::ProviderCommitted, QRunV06Qap1Phase::AnchorCasPrepared) => {
                self.provider_receipt == previous.provider_receipt
                    && self.anchor_successor == previous.anchor_successor
                    && self.anchor_cas_request.is_some()
            }
            (QRunV06Qap1Phase::AnchorCasPrepared, QRunV06Qap1Phase::AnchorCommitted) => {
                self.provider_receipt == previous.provider_receipt
                    && self.anchor_successor == previous.anchor_successor
                    && self.anchor_cas_request == previous.anchor_cas_request
                    && self.anchor_cas_receipt.is_some()
            }
            (QRunV06Qap1Phase::AnchorCommitted, QRunV06Qap1Phase::AnchorConfirmed) => {
                self.provider_receipt == previous.provider_receipt
                    && self.anchor_successor == previous.anchor_successor
                    && self.anchor_cas_request == previous.anchor_cas_request
                    && self.anchor_cas_receipt == previous.anchor_cas_receipt
                    && self.anchor_read_request.is_some()
                    && self.anchor_read_receipt.is_some()
            }
            (QRunV06Qap1Phase::AnchorConfirmed, QRunV06Qap1Phase::LocalManifestCommitted) => {
                self.provider_receipt == previous.provider_receipt
                    && self.anchor_successor == previous.anchor_successor
                    && self.anchor_cas_request == previous.anchor_cas_request
                    && self.anchor_cas_receipt == previous.anchor_cas_receipt
                    && self.anchor_read_request == previous.anchor_read_request
                    && self.anchor_read_receipt == previous.anchor_read_receipt
            }
            (QRunV06Qap1Phase::LocalManifestCommitted, QRunV06Qap1Phase::Finalized) => {
                self.provider_receipt == previous.provider_receipt
                    && self.anchor_successor == previous.anchor_successor
                    && self.anchor_cas_request == previous.anchor_cas_request
                    && self.anchor_cas_receipt == previous.anchor_cas_receipt
                    && self.anchor_read_request == previous.anchor_read_request
                    && self.anchor_read_receipt == previous.anchor_read_receipt
            }
            _ => false,
        };
        if valid {
            Ok(())
        } else {
            Err(QRunV06Qap1Error::ChangedIntent)
        }
    }

    /// Persist the first immutable Prepared snapshot. The QFP6 store writer lock must already
    /// be held by the caller; this additional OS lock serializes QAP1 phase-file operations.
    pub fn persist_prepared(
        &self,
        directory: &Path,
        provider_pin: &ExternalCasPin,
    ) -> Result<(), QRunV06Qap1Error> {
        if self.phase != QRunV06Qap1Phase::Prepared {
            return Err(QRunV06Qap1Error::InvalidPhase);
        }
        self.validate_shape(provider_pin)?;
        match fs::symlink_metadata(directory) {
            Ok(metadata) if !metadata.file_type().is_symlink() && metadata.file_type().is_dir() => {
            }
            Ok(_) => return Err(QRunV06Qap1Error::NonCanonical),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                // The QFP6 store root must already exist; create only this dedicated child.
                fs::create_dir(directory)?;
            }
            Err(error) => return Err(error.into()),
        }
        let _lock = StoreWriterLock::acquire(directory, LOCK_NAME)?;
        validate_qap1_directory_locked(directory)?;
        let encoded = self.encode()?;
        match load_latest_unlocked(directory, provider_pin)? {
            Some(existing) if existing.encode()? == encoded => return Ok(()),
            Some(_) => return Err(QRunV06Qap1Error::PhaseConflict),
            None => {}
        }
        write_phase_snapshot(directory, self.phase, &encoded)
    }

    /// Append exactly one successor snapshot. Both the old and new snapshots have their
    /// complete Provider and Anchor signatures re-verified before the phase file is installed.
    pub fn persist_transition<PV: MlDsa65Verifier, AV: MlDsa65Verifier>(
        &self,
        directory: &Path,
        previous: &Self,
        provider_pin: &ExternalCasPin,
        anchor_pin: &ExternalCasOffhostAnchorPin,
        provider_verifier: &PV,
        anchor_verifier: &AV,
    ) -> Result<(), QRunV06Qap1Error> {
        self.validate_shape(provider_pin)?;
        self.validate_successive_snapshot(previous)?;
        previous.verify_saved_evidence(
            provider_pin,
            anchor_pin,
            provider_verifier,
            anchor_verifier,
        )?;
        self.verify_saved_evidence(provider_pin, anchor_pin, provider_verifier, anchor_verifier)?;
        let _lock = StoreWriterLock::acquire(directory, LOCK_NAME)?;
        validate_qap1_directory_locked(directory)?;
        let latest =
            load_latest_unlocked(directory, provider_pin)?.ok_or(QRunV06Qap1Error::PhaseGap)?;
        if latest.encode()? != previous.encode()? {
            return Err(QRunV06Qap1Error::PhaseConflict);
        }
        write_phase_snapshot(directory, self.phase, &self.encode()?)
    }

    /// Read and cryptographically verify all evidence saved in the latest QAP1 phase.
    /// A local checksum is never treated as proof that Provider or Anchor receipts are trusted.
    pub fn load_latest<PV: MlDsa65Verifier, AV: MlDsa65Verifier>(
        directory: &Path,
        provider_pin: &ExternalCasPin,
        anchor_pin: &ExternalCasOffhostAnchorPin,
        provider_verifier: &PV,
        anchor_verifier: &AV,
    ) -> Result<Option<Self>, QRunV06Qap1Error> {
        let _lock = StoreWriterLock::acquire(directory, LOCK_NAME)?;
        validate_qap1_directory_locked(directory)?;
        let latest = load_latest_unlocked(directory, provider_pin)?;
        if let Some(journal) = &latest {
            journal.verify_saved_evidence(
                provider_pin,
                anchor_pin,
                provider_verifier,
                anchor_verifier,
            )?;
        }
        Ok(latest)
    }

    /// Write Finalized first, then remove older immutable snapshots. If the process dies during
    /// cleanup, load_latest returns the Finalized journal; cleanup_finalized must verify its
    /// signatures and exact local successor before deleting any remaining phase files.
    pub fn finalize_and_clear<PV: MlDsa65Verifier, AV: MlDsa65Verifier>(
        &self,
        directory: &Path,
        local_state: &QRunV06ExternalAnchorState,
        provider_pin: &ExternalCasPin,
        anchor_pin: &ExternalCasOffhostAnchorPin,
        provider_verifier: &PV,
        anchor_verifier: &AV,
    ) -> Result<(), QRunV06Qap1Error> {
        let finalized = self.finalized(local_state)?;
        finalized.verify_saved_evidence(
            provider_pin,
            anchor_pin,
            provider_verifier,
            anchor_verifier,
        )?;
        let _lock = StoreWriterLock::acquire(directory, LOCK_NAME)?;
        validate_qap1_directory_locked(directory)?;
        let latest =
            load_latest_no_cleanup(directory, provider_pin)?.ok_or(QRunV06Qap1Error::PhaseGap)?;
        if latest.encode()? != self.encode()? {
            return Err(QRunV06Qap1Error::PhaseConflict);
        }
        write_phase_snapshot(directory, QRunV06Qap1Phase::Finalized, &finalized.encode()?)?;
        cleanup_phase_snapshots(directory)?;
        Ok(())
    }

    /// Idempotently finish cleanup after a crash that occurred after Finalized was synced.
    pub fn cleanup_finalized<PV: MlDsa65Verifier, AV: MlDsa65Verifier>(
        &self,
        directory: &Path,
        local_state: &QRunV06ExternalAnchorState,
        provider_pin: &ExternalCasPin,
        anchor_pin: &ExternalCasOffhostAnchorPin,
        provider_verifier: &PV,
        anchor_verifier: &AV,
    ) -> Result<(), QRunV06Qap1Error> {
        if self.phase != QRunV06Qap1Phase::Finalized || local_state != &self.successor {
            return Err(QRunV06Qap1Error::LocalManifestMismatch);
        }
        self.verify_saved_evidence(provider_pin, anchor_pin, provider_verifier, anchor_verifier)?;
        let _lock = StoreWriterLock::acquire(directory, LOCK_NAME)?;
        validate_qap1_directory_locked(directory)?;
        let latest =
            load_latest_unlocked(directory, provider_pin)?.ok_or(QRunV06Qap1Error::PhaseGap)?;
        if latest.encode()? != self.encode()? {
            return Err(QRunV06Qap1Error::PhaseConflict);
        }
        cleanup_phase_snapshots(directory)?;
        Ok(())
    }
}

const MAX_QAP1_BYTES: usize = HEADER_BYTES
    + 384 * 2
    + OFFHOST_ANCHOR_STATE_BYTES * 2
    + WRITE_REQUEST_BYTES
    + 4
    + EXTERNAL_CAS_RECEIPT_BYTES
    + 2
    + ANCHOR_CAS_REQUEST_BYTES
    + 4
    + OFFHOST_ANCHOR_RECEIPT_BYTES
    + 2
    + ANCHOR_READ_REQUEST_BYTES
    + 4
    + OFFHOST_ANCHOR_RECEIPT_BYTES
    + 4
    + MAX_QRUN_V06_POW_ENVELOPE_BYTES
    + 4
    + MAX_QRUN_V06_MANIFEST_BYTES
    + CHECKSUM_BYTES;

fn validate_qap1_directory_locked(directory: &Path) -> Result<(), QRunV06Qap1Error> {
    let metadata = fs::symlink_metadata(directory)?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
        return Err(QRunV06Qap1Error::NonCanonical);
    }
    let mut removed_stale_temp = false;
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let kind = entry.file_type()?;
        if kind.is_symlink() || !kind.is_file() {
            return Err(QRunV06Qap1Error::NonCanonical);
        }
        let name = entry.file_name().to_string_lossy().to_string();
        if name == LOCK_NAME {
            continue;
        }
        let phase_file =
            (1..=7).any(|phase| name == format!("{QAP1_PREFIX}{phase:02}{QAP1_SUFFIX}"));
        if phase_file {
            continue;
        }
        if name.starts_with(".qap1-") && name.ends_with(".tmp") {
            fs::remove_file(entry.path())?;
            removed_stale_temp = true;
            continue;
        }
        return Err(QRunV06Qap1Error::NonCanonical);
    }
    if removed_stale_temp {
        sync_directory(directory)?;
    }
    Ok(())
}

fn phase_path(directory: &Path, phase: u16) -> PathBuf {
    directory.join(format!("{QAP1_PREFIX}{phase:02}{QAP1_SUFFIX}"))
}

#[cfg(target_os = "linux")]
fn open_snapshot_nofollow(path: &Path) -> io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    // Linux O_NOFOLLOW. The descriptor is checked again after open.
    OpenOptions::new()
        .read(true)
        .custom_flags(0x0002_0000)
        .open(path)
}

#[cfg(windows)]
fn open_snapshot_nofollow(path: &Path) -> io::Result<File> {
    use std::os::windows::fs::OpenOptionsExt;
    // FILE_FLAG_OPEN_REPARSE_POINT prevents following a symlink/reparse-point leaf.
    OpenOptions::new()
        .read(true)
        .custom_flags(0x0020_0000)
        .open(path)
}

#[cfg(not(any(target_os = "linux", windows)))]
fn open_snapshot_nofollow(_path: &Path) -> io::Result<File> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "QAP1 no-follow snapshot reads are not qualified on this target",
    ))
}

fn read_snapshot(path: &Path) -> Result<Vec<u8>, QRunV06Qap1Error> {
    let file = open_snapshot_nofollow(path)?;
    let opened = file.metadata()?;
    if !opened.is_file() || opened.len() as usize > MAX_QAP1_BYTES {
        return Err(QRunV06Qap1Error::Oversize);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
        if opened.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(QRunV06Qap1Error::NonCanonical);
        }
    }
    let mut bytes = Vec::with_capacity(opened.len() as usize);
    file.take((MAX_QAP1_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_QAP1_BYTES || bytes.len() as u64 != opened.len() {
        return Err(QRunV06Qap1Error::Oversize);
    }
    Ok(bytes)
}

#[cfg(windows)]
fn atomic_install_new(source: &Path, destination: &Path) -> io::Result<()> {
    use std::{ffi::OsStr, os::windows::ffi::OsStrExt};
    #[link(name = "Kernel32")]
    extern "system" {
        fn MoveFileExW(existing: *const u16, new_name: *const u16, flags: u32) -> i32;
    }
    const MOVEFILE_WRITE_THROUGH: u32 = 0x0000_0008;
    let source_wide: Vec<u16> = OsStr::new(source).encode_wide().chain(Some(0)).collect();
    let destination_wide: Vec<u16> = OsStr::new(destination)
        .encode_wide()
        .chain(Some(0))
        .collect();
    // Deliberately omit MOVEFILE_REPLACE_EXISTING: phase snapshots are immutable.
    let result = unsafe {
        MoveFileExW(
            source_wide.as_ptr(),
            destination_wide.as_ptr(),
            MOVEFILE_WRITE_THROUGH,
        )
    };
    if result == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn atomic_install_new(source: &Path, destination: &Path) -> io::Result<()> {
    // A same-filesystem hard link atomically creates a name only if it does not already exist.
    fs::hard_link(source, destination)?;
    fs::remove_file(source)?;
    Ok(())
}

#[cfg(not(any(target_os = "linux", windows)))]
fn atomic_install_new(_source: &Path, _destination: &Path) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "QAP1 atomic no-replace installation is not qualified on this target",
    ))
}

fn write_phase_snapshot(
    directory: &Path,
    phase: QRunV06Qap1Phase,
    bytes: &[u8],
) -> Result<(), QRunV06Qap1Error> {
    let destination = phase_path(directory, phase as u16);
    if destination.exists() {
        let existing = read_snapshot(&destination)?;
        return if existing == bytes {
            Ok(())
        } else {
            Err(QRunV06Qap1Error::PhaseConflict)
        };
    }
    let id = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
    let temp = directory.join(format!(".qap1-{}-{id}.tmp", std::process::id()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temp)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    match atomic_install_new(&temp, &destination) {
        Ok(()) => {}
        Err(error) => {
            let _ = fs::remove_file(&temp);
            if destination.exists() {
                let existing = read_snapshot(&destination)?;
                return if existing == bytes {
                    Ok(())
                } else {
                    Err(QRunV06Qap1Error::PhaseConflict)
                };
            }
            return Err(error.into());
        }
    }
    sync_directory(directory)?;
    Ok(())
}

fn load_latest_unlocked(
    directory: &Path,
    provider_pin: &ExternalCasPin,
) -> Result<Option<QRunV06Qap1Journal>, QRunV06Qap1Error> {
    if phase_path(directory, QRunV06Qap1Phase::Finalized as u16).exists() {
        let finalized = QRunV06Qap1Journal::decode(
            &read_snapshot(&phase_path(directory, QRunV06Qap1Phase::Finalized as u16))?,
            provider_pin,
        )?;
        if finalized.phase != QRunV06Qap1Phase::Finalized {
            return Err(QRunV06Qap1Error::InvalidPhase);
        }
        return Ok(Some(finalized));
    }
    load_latest_no_cleanup(directory, provider_pin)
}

fn load_latest_no_cleanup(
    directory: &Path,
    provider_pin: &ExternalCasPin,
) -> Result<Option<QRunV06Qap1Journal>, QRunV06Qap1Error> {
    let mut latest: Option<QRunV06Qap1Journal> = None;
    for phase in 1..=6u16 {
        let path = phase_path(directory, phase);
        if !path.exists() {
            if latest.is_some()
                && (phase..=6).any(|remaining| phase_path(directory, remaining).exists())
            {
                return Err(QRunV06Qap1Error::PhaseGap);
            }
            continue;
        }
        let current = QRunV06Qap1Journal::decode(&read_snapshot(&path)?, provider_pin)?;
        if current.phase as u16 != phase {
            return Err(QRunV06Qap1Error::InvalidPhase);
        }
        if let Some(previous) = &latest {
            current.validate_successive_snapshot(previous)?;
        } else if current.phase != QRunV06Qap1Phase::Prepared {
            return Err(QRunV06Qap1Error::PhaseGap);
        }
        latest = Some(current);
    }
    Ok(latest)
}

fn cleanup_phase_snapshots(directory: &Path) -> Result<(), QRunV06Qap1Error> {
    for phase in 1..=7u16 {
        let path = phase_path(directory, phase);
        match fs::remove_file(path) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    sync_directory(directory)?;
    Ok(())
}

fn sync_directory(directory: &Path) -> Result<(), QRunV06Qap1Error> {
    #[cfg(unix)]
    {
        File::open(directory)?.sync_all()?;
    }
    #[cfg(windows)]
    {
        // Windows MoveFileExW(MOVEFILE_WRITE_THROUGH) flushes the installed name transition.
        // Directory handles cannot be flushed through std::fs on all supported Windows versions.
        let _ = directory;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        external_cas_anchor_candidate::{
            ExternalCasPin, ExternalCasReceiptKind, ExternalCasReceiptOutcome, ExternalCasRecord,
            ExternalCasWriteRequest,
        },
        external_cas_offhost_anchor_candidate::ExternalCasOffhostAnchorState,
        external_cas_offhost_anchor_protocol_candidate::{
            ExternalCasOffhostAnchorMemoryModel, ExternalCasOffhostAnchorPin,
            OffhostAnchorReceiptSigner,
        },
        qrun_v06_external_anchor_candidate::QRunV06ExternalAnchorState,
        v4_fat1_mldsa65_candidate::LibcruxMlDsa65VerifierCandidate,
        v4_fat1_trust_candidate::{ML_DSA_65_PUBLIC_KEY_BYTES, ML_DSA_65_SIGNATURE_BYTES},
    };
    use libcrux_ml_dsa::ml_dsa_65::{portable, MLDSA65SigningKey};
    use std::sync::Arc;

    struct FixtureAnchorSigner(Arc<MLDSA65SigningKey>);
    impl OffhostAnchorReceiptSigner for FixtureAnchorSigner {
        fn sign_digest(
            &self,
            digest: &[u8; 32],
        ) -> Result<[u8; ML_DSA_65_SIGNATURE_BYTES], String> {
            let signature = portable::sign(self.0.as_ref(), digest, &[], [0xC3; 32])
                .map_err(|error| format!("{error:?}"))?;
            Ok(*signature.as_ref())
        }
    }

    fn fixture() -> (
        ExternalCasPin,
        ExternalCasOffhostAnchorPin,
        QRunV06Qap1Journal,
        Arc<MLDSA65SigningKey>,
        Arc<MLDSA65SigningKey>,
    ) {
        let keys = portable::generate_key_pair([0xA8; 32]);
        let public_key: [u8; ML_DSA_65_PUBLIC_KEY_BYTES] = *keys.verification_key.as_ref();
        let pin = ExternalCasPin {
            provider_id: [0x11; 32],
            network_id: [0x22; 32],
            genesis_digest: [0x33; 32],
            receipt_key_id: [0x44; 32],
            receipt_public_key: public_key,
        };
        let provider_signing_key = Arc::new(keys.signing_key);
        let anchor_keys = portable::generate_key_pair([0xA9; 32]);
        let anchor_public_key: [u8; ML_DSA_65_PUBLIC_KEY_BYTES] =
            *anchor_keys.verification_key.as_ref();
        let anchor_pin = ExternalCasOffhostAnchorPin {
            anchor_id: [0x10; 32],
            provider_id: pin.provider_id,
            network_id: pin.network_id,
            genesis_digest: pin.genesis_digest,
            receipt_key_id: [0x45; 32],
            receipt_public_key: anchor_public_key,
        };
        let anchor_signing_key = Arc::new(anchor_keys.signing_key);
        let before = QRunV06ExternalAnchorState {
            network_id: pin.network_id,
            genesis_digest: pin.genesis_digest,
            genesis_descriptor_commitment: [0x55; 32],
            profile_id: [0x66; 32],
            consensus_fingerprint: [0x77; 32],
            segment_base_height: 0,
            segment_base_tip: [0x88; 32],
            checkpoint_anchor: [0; 32],
            manifest_generation: 0,
            manifest_anchor: [0x99; 32],
            canonical_height: 0,
            canonical_tip: [0x88; 32],
            canonical_state_root: [0xAA; 32],
            cumulative_chainwork: [0; 32],
        };
        before.validate().unwrap();
        let candidate_envelope = b"QFP6-test-candidate-envelope-v1".to_vec();
        let manifest = b"Q6MF-canonical-test-manifest-v1".to_vec();
        let mut after = before.clone();
        after.manifest_generation = 1;
        after.manifest_anchor = hash_domain(MANIFEST_COMMITMENT_DOMAIN, &manifest);
        after.canonical_height = 1;
        after.canonical_tip = [0xAB; 32];
        after.canonical_state_root = [0xAC; 32];
        after.cumulative_chainwork = [0; 31]
            .into_iter()
            .chain([1])
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        before.validate_successor(&after).unwrap();
        let bootstrap = ExternalCasRecord {
            generation: 0,
            provider_id: pin.provider_id,
            network_id: pin.network_id,
            genesis_digest: pin.genesis_digest,
            previous_record_digest: [0; 32],
            previous_state_digest: [0; 32],
            next_state_digest: before.digest().unwrap(),
            operation_id: [0xAD; 32],
            request_digest: [0xAE; 32],
        };
        let anchor_before =
            ExternalCasOffhostAnchorState::provision_bootstrap(&pin, bootstrap.clone(), 1).unwrap();
        let operation_id = [0xB1; 32];
        let mut request = ExternalCasWriteRequest {
            request_nonce: [0xB2; 32],
            operation_id,
            request_digest: [1; 32],
            expected_generation: 0,
            expected_object_generation: 1,
            expected_record_digest: bootstrap.digest().unwrap(),
            expected_state_digest: before.digest().unwrap(),
            next_record: ExternalCasRecord {
                generation: 1,
                provider_id: pin.provider_id,
                network_id: pin.network_id,
                genesis_digest: pin.genesis_digest,
                previous_record_digest: bootstrap.digest().unwrap(),
                previous_state_digest: before.digest().unwrap(),
                next_state_digest: after.digest().unwrap(),
                operation_id,
                request_digest: [0; 32],
            },
        };
        request.bind_request_digest(&pin).unwrap();
        let journal = QRunV06Qap1Journal::new(
            before,
            after,
            anchor_before,
            request,
            candidate_envelope,
            manifest,
            &pin,
        )
        .unwrap();
        (
            pin,
            anchor_pin,
            journal,
            provider_signing_key,
            anchor_signing_key,
        )
    }

    #[test]
    fn prepared_qap1_roundtrips_with_exact_manifest_and_provider_request() {
        let (pin, _anchor_pin, journal, _provider_signing_key, _anchor_signing_key) = fixture();
        let encoded = journal.encode().unwrap();
        let decoded = QRunV06Qap1Journal::decode(&encoded, &pin).unwrap();
        assert_eq!(decoded, journal);
        assert_eq!(decoded.phase(), QRunV06Qap1Phase::Prepared);
        assert_eq!(decoded.provider_request(), journal.provider_request());
        assert_eq!(decoded.candidate_envelope(), journal.candidate_envelope());
        assert_eq!(decoded.next_manifest_bytes(), journal.next_manifest_bytes());
    }

    #[test]
    fn prepared_qap1_rejects_checksum_tampering() {
        let (pin, _anchor_pin, journal, _provider_signing_key, _anchor_signing_key) = fixture();
        let mut encoded = journal.encode().unwrap();
        let last = encoded.len() - 1;
        encoded[last] ^= 1;
        assert!(QRunV06Qap1Journal::decode(&encoded, &pin).is_err());
    }

    #[test]
    fn prepared_qap1_rejects_manifest_commitment_mismatch() {
        let (pin, _anchor_pin, mut journal, _provider_signing_key, _anchor_signing_key) = fixture();
        journal.next_manifest_bytes.push(0);
        assert_eq!(
            journal.validate_shape(&pin),
            Err(QRunV06Qap1Error::InvalidJournal)
        );
    }

    #[test]
    fn qap1_write_request_codec_is_canonical_and_pin_bound() {
        let (pin, _anchor_pin, journal, _provider_signing_key, _anchor_signing_key) = fixture();
        let encoded = encode_write_request(&journal.provider_request).unwrap();
        assert_eq!(
            decode_write_request(&encoded, &pin).unwrap(),
            journal.provider_request
        );
        let mut wrong_pin = pin.clone();
        wrong_pin.network_id[0] ^= 1;
        assert!(decode_write_request(&encoded, &wrong_pin).is_err());
    }

    fn temp_directory() -> PathBuf {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("qrun-qap1-journal-{}-{stamp}", std::process::id()));
        std::fs::create_dir_all(&path).unwrap();
        path
    }

    #[test]
    fn prepared_qap1_refuses_regular_file_as_journal_directory_before_lock_creation() {
        let (pin, _anchor_pin, journal, _provider_signing_key, _anchor_signing_key) = fixture();
        let base = temp_directory();
        let not_a_directory = base.join("journal-is-a-file");
        std::fs::write(&not_a_directory, b"not a directory").unwrap();

        assert_eq!(
            journal.persist_prepared(&not_a_directory, &pin),
            Err(QRunV06Qap1Error::NonCanonical)
        );
        assert_eq!(std::fs::read(&not_a_directory).unwrap(), b"not a directory");
        std::fs::remove_dir_all(base).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn prepared_qap1_refuses_symlink_directory_without_touching_target() {
        use std::os::unix::fs::symlink;

        let (pin, _anchor_pin, journal, _provider_signing_key, _anchor_signing_key) = fixture();
        let base = temp_directory();
        let target = base.join("external-target");
        let link = base.join("journal-link");
        std::fs::create_dir(&target).unwrap();
        symlink(&target, &link).unwrap();

        assert_eq!(
            journal.persist_prepared(&link, &pin),
            Err(QRunV06Qap1Error::NonCanonical)
        );
        assert!(!target.join(LOCK_NAME).exists());
        assert_eq!(std::fs::read_dir(&target).unwrap().count(), 0);
        std::fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn prepared_qap1_snapshot_is_durable_idempotent_and_reloadable() {
        let (pin, anchor_pin, journal, _provider_signing_key, _anchor_signing_key) = fixture();
        let directory = temp_directory();
        journal.persist_prepared(&directory, &pin).unwrap();
        // Repeating the exact same Prepared intent is harmless; a different intent is not.
        journal.persist_prepared(&directory, &pin).unwrap();
        let verifier = LibcruxMlDsa65VerifierCandidate;
        let loaded =
            QRunV06Qap1Journal::load_latest(&directory, &pin, &anchor_pin, &verifier, &verifier)
                .unwrap()
                .expect("Prepared journal must survive reopen");
        assert_eq!(loaded, journal);
        assert_eq!(loaded.phase(), QRunV06Qap1Phase::Prepared);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn prepared_qap1_corrupt_phase_file_fails_closed_on_reload() {
        let (pin, anchor_pin, journal, _provider_signing_key, _anchor_signing_key) = fixture();
        let directory = temp_directory();
        journal.persist_prepared(&directory, &pin).unwrap();
        let path = phase_path(&directory, QRunV06Qap1Phase::Prepared as u16);
        let mut bytes = std::fs::read(&path).unwrap();
        bytes[20] ^= 1;
        std::fs::write(&path, bytes).unwrap();
        let verifier = LibcruxMlDsa65VerifierCandidate;
        assert!(QRunV06Qap1Journal::load_latest(
            &directory,
            &pin,
            &anchor_pin,
            &verifier,
            &verifier,
        )
        .is_err());
        std::fs::remove_dir_all(directory).unwrap();
    }

    fn signed_provider_receipt(
        pin: &ExternalCasPin,
        request: &ExternalCasWriteRequest,
        signing_key: &MLDSA65SigningKey,
    ) -> Vec<u8> {
        let record = &request.next_record;
        let mut receipt = ExternalCasReceipt {
            kind: ExternalCasReceiptKind::Commit,
            outcome: ExternalCasReceiptOutcome::Applied,
            generation: record.generation,
            object_generation: request.expected_object_generation.checked_add(1).unwrap(),
            provider_id: pin.provider_id,
            network_id: pin.network_id,
            genesis_digest: pin.genesis_digest,
            receipt_key_id: pin.receipt_key_id,
            request_nonce: request.request_nonce,
            record_digest: record.digest().unwrap(),
            previous_record_digest: record.previous_record_digest,
            previous_state_digest: record.previous_state_digest,
            state_digest: record.next_state_digest,
            operation_id: request.operation_id,
            request_digest: request.request_digest,
            signature: [0; ML_DSA_65_SIGNATURE_BYTES],
        };
        let digest = receipt.signing_digest().unwrap();
        let signature = portable::sign(signing_key, &digest, &[], [0xB5; 32]).unwrap();
        receipt.signature = *signature.as_ref();
        receipt.encode().unwrap().to_vec()
    }

    #[test]
    fn qap1_signed_provider_anchor_and_restart_evidence_chain() {
        let (pin, anchor_pin, prepared, provider_key, anchor_key) = fixture();
        let verifier = LibcruxMlDsa65VerifierCandidate;
        let provider_receipt_bytes =
            signed_provider_receipt(&pin, prepared.provider_request(), provider_key.as_ref());

        let provider_committed = prepared
            .record_provider_receipt(&provider_receipt_bytes, &pin, &verifier)
            .unwrap();
        assert_eq!(
            provider_committed.phase(),
            QRunV06Qap1Phase::ProviderCommitted
        );
        provider_committed
            .verify_saved_evidence(&pin, &anchor_pin, &verifier, &verifier)
            .unwrap();

        let anchor_successor = provider_committed.anchor_successor().unwrap();
        let cas_request = ExternalCasOffhostAnchorCasRequest {
            challenge: [0xD1; 32],
            operation_id: provider_committed.provider_request.operation_id,
            request_digest: provider_committed.provider_request.request_digest,
            expected_sequence: provider_committed.anchor_predecessor.sequence,
            expected_state_digest: provider_committed.anchor_predecessor.digest().unwrap(),
            target_state_digest: anchor_successor.digest().unwrap(),
        };
        let anchor_cas_prepared = provider_committed
            .prepare_anchor_cas(cas_request.clone(), &pin)
            .unwrap();

        let model = ExternalCasOffhostAnchorMemoryModel::new(
            anchor_pin.clone(),
            pin.clone(),
            provider_committed.anchor_predecessor.clone(),
        )
        .unwrap();
        let anchor_signer = FixtureAnchorSigner(anchor_key);
        let next_record_bytes = provider_committed
            .provider_request
            .next_record
            .encode()
            .unwrap();
        let anchor_receipt = model
            .compare_and_swap(
                &cas_request,
                &next_record_bytes,
                &provider_receipt_bytes,
                &verifier,
                &anchor_signer,
            )
            .unwrap();
        let anchor_committed = anchor_cas_prepared
            .record_anchor_receipt(
                &anchor_receipt.encode().unwrap(),
                &anchor_pin,
                &pin,
                &verifier,
            )
            .unwrap();
        assert_eq!(anchor_committed.phase(), QRunV06Qap1Phase::AnchorCommitted);

        let read_request = ExternalCasOffhostAnchorReadRequest {
            challenge: [0xD2; 32],
            operation_id: [0xD3; 32],
            request_digest: [0xD4; 32],
        };
        let read_receipt = model.read(&read_request, &anchor_signer).unwrap();
        let anchor_confirmed = anchor_committed
            .confirm_anchor_read(
                read_request,
                &read_receipt.encode().unwrap(),
                &anchor_pin,
                &pin,
                &verifier,
            )
            .unwrap();
        assert_eq!(anchor_confirmed.phase(), QRunV06Qap1Phase::AnchorConfirmed);
        anchor_confirmed
            .verify_saved_evidence(&pin, &anchor_pin, &verifier, &verifier)
            .unwrap();

        let mut forged_provider_proof = anchor_confirmed.clone();
        let provider_proof = forged_provider_proof.provider_receipt.as_mut().unwrap();
        let last = provider_proof.len() - 1;
        provider_proof[last] ^= 1;
        assert!(forged_provider_proof
            .verify_saved_evidence(&pin, &anchor_pin, &verifier, &verifier)
            .is_err());

        let mut forged_anchor_proof = anchor_confirmed.clone();
        let anchor_proof = forged_anchor_proof.anchor_cas_receipt.as_mut().unwrap();
        let last = anchor_proof.len() - 1;
        anchor_proof[last] ^= 1;
        assert!(forged_anchor_proof
            .verify_saved_evidence(&pin, &anchor_pin, &verifier, &verifier)
            .is_err());

        let directory = temp_directory();
        prepared.persist_prepared(&directory, &pin).unwrap();
        provider_committed
            .persist_transition(
                &directory,
                &prepared,
                &pin,
                &anchor_pin,
                &verifier,
                &verifier,
            )
            .unwrap();
        anchor_cas_prepared
            .persist_transition(
                &directory,
                &provider_committed,
                &pin,
                &anchor_pin,
                &verifier,
                &verifier,
            )
            .unwrap();
        anchor_committed
            .persist_transition(
                &directory,
                &anchor_cas_prepared,
                &pin,
                &anchor_pin,
                &verifier,
                &verifier,
            )
            .unwrap();
        anchor_confirmed
            .persist_transition(
                &directory,
                &anchor_committed,
                &pin,
                &anchor_pin,
                &verifier,
                &verifier,
            )
            .unwrap();

        let loaded =
            QRunV06Qap1Journal::load_latest(&directory, &pin, &anchor_pin, &verifier, &verifier)
                .unwrap()
                .unwrap();
        assert_eq!(loaded, anchor_confirmed);

        let local_manifest_committed = loaded
            .mark_local_manifest_committed(&loaded.successor, &pin)
            .unwrap();
        local_manifest_committed
            .persist_transition(&directory, &loaded, &pin, &anchor_pin, &verifier, &verifier)
            .unwrap();

        // Simulate a crash after the Finalized marker is synced but before phase-file cleanup.
        let finalized = local_manifest_committed
            .finalized(&local_manifest_committed.successor)
            .unwrap();
        {
            let _lock = StoreWriterLock::acquire(&directory, LOCK_NAME).unwrap();
            write_phase_snapshot(
                &directory,
                QRunV06Qap1Phase::Finalized,
                &finalized.encode().unwrap(),
            )
            .unwrap();
        }
        let recovered_finalized =
            QRunV06Qap1Journal::load_latest(&directory, &pin, &anchor_pin, &verifier, &verifier)
                .unwrap()
                .unwrap();
        assert_eq!(recovered_finalized, finalized);
        recovered_finalized
            .cleanup_finalized(
                &directory,
                &recovered_finalized.successor,
                &pin,
                &anchor_pin,
                &verifier,
                &verifier,
            )
            .unwrap();
        assert!(QRunV06Qap1Journal::load_latest(
            &directory,
            &pin,
            &anchor_pin,
            &verifier,
            &verifier,
        )
        .unwrap()
        .is_none());
        std::fs::remove_dir_all(directory).unwrap();
    }
}
