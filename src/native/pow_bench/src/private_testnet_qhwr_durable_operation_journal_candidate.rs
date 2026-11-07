//! CP-0412 single-host durable QHWR operation journal candidate.
//!
//! Research candidate only: not wired to the production dispatcher, not a
//! distributed replay authority, and not an anti-rollback mechanism.
//! Successful transitions are acknowledged only after the complete frame is
//! written and sync_all succeeds. Any uncertain append poisons this handle.

use crate::private_testnet_qhwr_idempotent_signer_contract::{
    derive_operation_key, QhwrSignerArtifact, QhwrSignerOperationKey,
};
use crate::snapshot_store::{SnapshotStoreError, SnapshotWriterLock};
use sha2::{Digest, Sha256};
#[cfg(any(unix, test))]
use std::path::PathBuf;
use std::{
    collections::HashMap,
    fs::{self, File, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    path::Path,
};

const MAGIC: &[u8; 8] = b"QHWRJNL1";
const VERSION: u8 = 1;
const KIND_RESERVE: u8 = 1;
const KIND_PREPARE: u8 = 2;
const KIND_ARTIFACT: u8 = 3;
const KIND_COMPLETE: u8 = 4;
const HEADER_BYTES: usize = 8 + 1 + 1 + 4 + 32;
const CHECKSUM_BYTES: usize = 32;
const MAX_SNAPSHOT_BYTES: usize = 4 * 1024 * 1024;
const MAX_ARTIFACT_BYTES: usize = 1024 * 1024;
const MAX_RESPONSE_BYTES: usize = 4 * 1024 * 1024;
const MAX_FRAME_PAYLOAD_BYTES: usize = MAX_SNAPSHOT_BYTES + 4 + 32 + 8 + 32;
const MAX_JOURNAL_BYTES: u64 = 128 * 1024 * 1024;
const MAX_OPERATIONS: usize = 100_000;
const CHECKSUM_DOMAIN: &[u8] = b"AIN1-QHWR-OPERATION-JOURNAL-RECORD-V1\0";

#[derive(Debug)]
pub enum QhwrOperationJournalError {
    Io(io::Error),
    InvalidPath,
    WriterLockUnavailable,
    CorruptRecord { offset: u64 },
    InvalidTransition,
    IdentityConflict,
    InvalidPayload(&'static str),
    LimitExceeded,
    StoreNeedsRecovery,
}

impl std::fmt::Display for QhwrOperationJournalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(f, "QHWR operation journal I/O: {error}"),
            Self::InvalidPath => f.write_str("invalid QHWR operation journal path"),
            Self::WriterLockUnavailable => {
                f.write_str("QHWR operation journal already has an active writer")
            }
            Self::CorruptRecord { offset } => {
                write!(
                    f,
                    "QHWR operation journal corrupt record at offset {offset}"
                )
            }
            Self::InvalidTransition => f.write_str("invalid QHWR operation journal transition"),
            Self::IdentityConflict => {
                f.write_str("QHWR operation journal immutable identity conflict")
            }
            Self::InvalidPayload(reason) => {
                write!(f, "invalid QHWR operation journal payload: {reason}")
            }
            Self::LimitExceeded => f.write_str("QHWR operation journal size limit exceeded"),
            Self::StoreNeedsRecovery => {
                f.write_str("QHWR operation journal has uncertain I/O; close and reopen")
            }
        }
    }
}

impl std::error::Error for QhwrOperationJournalError {}

impl From<io::Error> for QhwrOperationJournalError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<SnapshotStoreError> for QhwrOperationJournalError {
    fn from(value: SnapshotStoreError) -> Self {
        match value {
            SnapshotStoreError::WriterLockBusy(_) => Self::WriterLockUnavailable,
            SnapshotStoreError::Io(error) => Self::Io(error),
            _ => Self::InvalidPath,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QhwrJournalPins {
    pub operation_key: QhwrSignerOperationKey,
    pub qhwr_identity_digest: [u8; 32],
    pub request_digest: [u8; 32],
    pub provider_id: [u8; 32],
}

impl QhwrJournalPins {
    pub fn new(
        qhwr_identity_digest: [u8; 32],
        request_digest: [u8; 32],
        provider_id: [u8; 32],
    ) -> Self {
        Self {
            operation_key: derive_operation_key(&qhwr_identity_digest),
            qhwr_identity_digest,
            request_digest,
            provider_id,
        }
    }

    fn validate(&self) -> Result<(), QhwrOperationJournalError> {
        if self.operation_key != derive_operation_key(&self.qhwr_identity_digest) {
            return Err(QhwrOperationJournalError::IdentityConflict);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QhwrJournalPrepared {
    /// Exact canonical provider snapshot bytes; persisted before signing.
    pub provider_snapshot: Vec<u8>,
    pub signer_key_id: [u8; 32],
    pub signer_key_generation: u64,
    pub signing_digest: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QhwrJournalCompleted {
    /// Exact encoded response bytes; callers replay these bytes without re-encoding.
    pub response_bytes: Vec<u8>,
    pub response_digest: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum QhwrJournalState {
    Reserved {
        pins: QhwrJournalPins,
    },
    Prepared {
        pins: QhwrJournalPins,
        prepared: QhwrJournalPrepared,
    },
    Signed {
        pins: QhwrJournalPins,
        prepared: QhwrJournalPrepared,
        artifact: QhwrSignerArtifact,
    },
    Completed {
        pins: QhwrJournalPins,
        prepared: QhwrJournalPrepared,
        artifact: QhwrSignerArtifact,
        completed: QhwrJournalCompleted,
    },
}

impl QhwrJournalState {
    pub fn completed_response(&self) -> Option<&[u8]> {
        match self {
            Self::Completed { completed, .. } => Some(&completed.response_bytes),
            _ => None,
        }
    }
}

/// Append-only, checksummed, single-writer journal for one local host.
/// The external replay authority and durable idempotent signer remain separate.
#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum QhwrJournalFaultPoint {
    BeforeWrite,
    AfterHeader,
    AfterPayload,
    AfterChecksum,
    AfterSync,
}
pub struct QhwrDurableOperationJournalCandidate {
    #[cfg(unix)]
    path: PathBuf,
    file: File,
    _path_lock: SnapshotWriterLock,
    _file_identity_lock: SnapshotWriterLock,
    states: HashMap<[u8; 32], QhwrJournalState>,
    valid_len: u64,
    poisoned: bool,
    #[cfg(test)]
    fault_at: Option<QhwrJournalFaultPoint>,
}

impl QhwrDurableOperationJournalCandidate {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, QhwrOperationJournalError> {
        let input_path = path.as_ref();
        let file_name = input_path
            .file_name()
            .ok_or(QhwrOperationJournalError::InvalidPath)?;
        let canonical_parent = fs::canonicalize(parent_directory(input_path))?;
        if !canonical_parent.is_dir() {
            return Err(QhwrOperationJournalError::InvalidPath);
        }
        let path = canonical_parent.join(file_name);

        // Windows directory-entry durability is not claimed. Require the file
        // to be provisioned before opening it on that platform.
        #[cfg(windows)]
        if !path.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Windows QHWR journal must be pre-provisioned",
            )
            .into());
        }

        let path_lock = SnapshotWriterLock::acquire(&path)?;
        #[cfg(unix)]
        let existed = path.exists();
        let mut options = OpenOptions::new();
        options.read(true).write(true);
        #[cfg(windows)]
        options.create(false);
        #[cfg(not(windows))]
        options.create(true);
        let file = options.open(&path)?;
        let file_identity_lock = SnapshotWriterLock::acquire_file_identity(&file, &path)?;

        #[cfg(unix)]
        if !existed {
            file.sync_all()?;
            File::open(&canonical_parent)?.sync_all()?;
        }

        let mut journal = Self {
            #[cfg(unix)]
            path,
            file,
            _path_lock: path_lock,
            _file_identity_lock: file_identity_lock,
            states: HashMap::new(),
            valid_len: 0,
            poisoned: false,
            #[cfg(test)]
            fault_at: None,
        };
        journal.recover()?;
        Ok(journal)
    }

    pub fn state(&self, operation_key: &QhwrSignerOperationKey) -> Option<&QhwrJournalState> {
        self.states.get(&operation_key.0)
    }

    pub fn operation_count(&self) -> usize {
        self.states.len()
    }

    pub fn durable_len(&self) -> u64 {
        self.valid_len
    }

    /// Reserve the immutable operation identity before any provider access.
    pub fn reserve(&mut self, pins: QhwrJournalPins) -> Result<bool, QhwrOperationJournalError> {
        pins.validate()?;
        let key = pins.operation_key.0;
        if let Some(existing) = self.states.get(&key) {
            return match existing {
                QhwrJournalState::Reserved { pins: current }
                | QhwrJournalState::Prepared { pins: current, .. }
                | QhwrJournalState::Signed { pins: current, .. }
                | QhwrJournalState::Completed { pins: current, .. }
                    if current == &pins =>
                {
                    Ok(false)
                }
                _ => Err(QhwrOperationJournalError::IdentityConflict),
            };
        }
        if self.states.len() >= MAX_OPERATIONS {
            return Err(QhwrOperationJournalError::LimitExceeded);
        }
        let mut payload = Vec::with_capacity(96);
        payload.extend_from_slice(&pins.qhwr_identity_digest);
        payload.extend_from_slice(&pins.request_digest);
        payload.extend_from_slice(&pins.provider_id);
        self.append_transition(
            key,
            KIND_RESERVE,
            payload,
            QhwrJournalState::Reserved { pins },
        )
    }

    /// Persist the exact provider snapshot and signer pins before sign_once.
    pub fn prepare(
        &mut self,
        operation_key: QhwrSignerOperationKey,
        prepared: QhwrJournalPrepared,
    ) -> Result<bool, QhwrOperationJournalError> {
        validate_prepared(&prepared)?;
        match self.states.get(&operation_key.0) {
            Some(QhwrJournalState::Prepared {
                prepared: current, ..
            })
            | Some(QhwrJournalState::Signed {
                prepared: current, ..
            })
            | Some(QhwrJournalState::Completed {
                prepared: current, ..
            }) if current == &prepared => {
                return Ok(false);
            }
            Some(QhwrJournalState::Reserved { .. }) => {}
            Some(_) => return Err(QhwrOperationJournalError::IdentityConflict),
            None => return Err(QhwrOperationJournalError::InvalidTransition),
        }
        let mut payload = Vec::with_capacity(4 + prepared.provider_snapshot.len() + 72);
        put_bytes(&mut payload, &prepared.provider_snapshot)?;
        payload.extend_from_slice(&prepared.signer_key_id);
        payload.extend_from_slice(&prepared.signer_key_generation.to_be_bytes());
        payload.extend_from_slice(&prepared.signing_digest);
        let pins = state_pins(self.states.get(&operation_key.0).expect("checked above")).clone();
        let next = QhwrJournalState::Prepared { pins, prepared };
        self.append_transition(operation_key.0, KIND_PREPARE, payload, next)
    }

    /// Persist the exact signer artifact returned by CP-0410 sign_once.
    pub fn record_artifact(
        &mut self,
        operation_key: QhwrSignerOperationKey,
        artifact: QhwrSignerArtifact,
    ) -> Result<bool, QhwrOperationJournalError> {
        artifact
            .validate()
            .map_err(|_| QhwrOperationJournalError::InvalidPayload("signer artifact digest"))?;
        if artifact.signature_bytes.len() > MAX_ARTIFACT_BYTES {
            return Err(QhwrOperationJournalError::LimitExceeded);
        }
        match self.states.get(&operation_key.0) {
            Some(QhwrJournalState::Signed {
                artifact: current, ..
            })
            | Some(QhwrJournalState::Completed {
                artifact: current, ..
            }) if current == &artifact => {
                return Ok(false);
            }
            Some(QhwrJournalState::Prepared { .. }) => {}
            Some(_) => return Err(QhwrOperationJournalError::IdentityConflict),
            None => return Err(QhwrOperationJournalError::InvalidTransition),
        }
        let mut payload = Vec::with_capacity(4 + artifact.signature_bytes.len() + 32);
        put_bytes(&mut payload, &artifact.signature_bytes)?;
        payload.extend_from_slice(&artifact.artifact_digest);
        let (pins, prepared) =
            state_pins_prepared(self.states.get(&operation_key.0).expect("checked above"))
                .expect("Prepared state checked above");
        let next = QhwrJournalState::Signed {
            pins: pins.clone(),
            prepared: prepared.clone(),
            artifact,
        };
        self.append_transition(operation_key.0, KIND_ARTIFACT, payload, next)
    }

    /// Persist the exact encoded response before the caller writes to its socket.
    pub fn complete(
        &mut self,
        operation_key: QhwrSignerOperationKey,
        response_bytes: Vec<u8>,
    ) -> Result<bool, QhwrOperationJournalError> {
        if response_bytes.is_empty() || response_bytes.len() > MAX_RESPONSE_BYTES {
            return Err(QhwrOperationJournalError::LimitExceeded);
        }
        let response_digest: [u8; 32] = Sha256::digest(&response_bytes).into();
        let completed = QhwrJournalCompleted {
            response_bytes,
            response_digest,
        };
        if let Some(QhwrJournalState::Completed {
            completed: current, ..
        }) = self.states.get(&operation_key.0)
        {
            return if current == &completed {
                Ok(false)
            } else {
                Err(QhwrOperationJournalError::IdentityConflict)
            };
        }
        let (pins, prepared, artifact) = match self.states.get(&operation_key.0) {
            Some(QhwrJournalState::Signed {
                pins,
                prepared,
                artifact,
            }) => (pins.clone(), prepared.clone(), artifact.clone()),
            Some(_) => return Err(QhwrOperationJournalError::InvalidTransition),
            None => return Err(QhwrOperationJournalError::InvalidTransition),
        };
        let mut payload = Vec::with_capacity(4 + completed.response_bytes.len() + 32);
        put_bytes(&mut payload, &completed.response_bytes)?;
        payload.extend_from_slice(&completed.response_digest);
        let next = QhwrJournalState::Completed {
            pins,
            prepared,
            artifact,
            completed,
        };
        self.append_transition(operation_key.0, KIND_COMPLETE, payload, next)
    }

    fn append_transition(
        &mut self,
        operation_key: [u8; 32],
        kind: u8,
        payload: Vec<u8>,
        next_state: QhwrJournalState,
    ) -> Result<bool, QhwrOperationJournalError> {
        if self.poisoned {
            return Err(QhwrOperationJournalError::StoreNeedsRecovery);
        }
        if payload.len() > MAX_FRAME_PAYLOAD_BYTES {
            return Err(QhwrOperationJournalError::LimitExceeded);
        }
        let new_len = self
            .valid_len
            .checked_add((HEADER_BYTES + payload.len() + CHECKSUM_BYTES) as u64)
            .ok_or(QhwrOperationJournalError::LimitExceeded)?;
        if new_len > MAX_JOURNAL_BYTES {
            return Err(QhwrOperationJournalError::LimitExceeded);
        }
        if self.file.metadata()?.len() != self.valid_len {
            self.poisoned = true;
            return Err(QhwrOperationJournalError::StoreNeedsRecovery);
        }

        let header = make_header(kind, payload.len(), &operation_key)?;
        let checksum = record_checksum(&header, &payload);
        if let Err(error) = self.file.seek(SeekFrom::Start(self.valid_len)) {
            self.poisoned = true;
            return Err(error.into());
        }
        #[cfg(test)]
        self.inject_fault(QhwrJournalFaultPoint::BeforeWrite)?;
        if let Err(error) = self.file.write_all(&header) {
            self.poisoned = true;
            return Err(error.into());
        }
        #[cfg(test)]
        self.inject_fault(QhwrJournalFaultPoint::AfterHeader)?;
        if let Err(error) = self.file.write_all(&payload) {
            self.poisoned = true;
            return Err(error.into());
        }
        #[cfg(test)]
        self.inject_fault(QhwrJournalFaultPoint::AfterPayload)?;
        if let Err(error) = self.file.write_all(&checksum) {
            self.poisoned = true;
            return Err(error.into());
        }
        #[cfg(test)]
        self.inject_fault(QhwrJournalFaultPoint::AfterChecksum)?;
        if let Err(error) = self.file.sync_all() {
            self.poisoned = true;
            return Err(error.into());
        }
        #[cfg(test)]
        self.inject_fault(QhwrJournalFaultPoint::AfterSync)?;
        self.valid_len = new_len;
        self.states.insert(operation_key, next_state);
        Ok(true)
    }

    #[cfg(test)]
    fn inject_fault(
        &mut self,
        point: QhwrJournalFaultPoint,
    ) -> Result<(), QhwrOperationJournalError> {
        if self.fault_at == Some(point) {
            self.fault_at = None;
            self.poisoned = true;
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("injected QHWR journal fault at {point:?}"),
            )
            .into());
        }
        Ok(())
    }
    fn recover(&mut self) -> Result<(), QhwrOperationJournalError> {
        let file_len = self.file.metadata()?.len();
        if file_len > MAX_JOURNAL_BYTES {
            return Err(QhwrOperationJournalError::LimitExceeded);
        }
        self.file.seek(SeekFrom::Start(0))?;
        let mut offset = 0u64;
        while offset < file_len {
            let remaining = file_len - offset;
            if remaining < HEADER_BYTES as u64 {
                self.truncate_incomplete_tail(offset)?;
                break;
            }
            let mut header = [0u8; HEADER_BYTES];
            self.file.read_exact(&mut header)?;
            if &header[..8] != MAGIC || header[8] != VERSION {
                return Err(QhwrOperationJournalError::CorruptRecord { offset });
            }
            let kind = header[9];
            if !(KIND_RESERVE..=KIND_COMPLETE).contains(&kind) {
                return Err(QhwrOperationJournalError::CorruptRecord { offset });
            }
            let payload_len = u32::from_be_bytes(header[10..14].try_into().unwrap()) as usize;
            if payload_len > MAX_FRAME_PAYLOAD_BYTES || !payload_len_valid(kind, payload_len) {
                return Err(QhwrOperationJournalError::CorruptRecord { offset });
            }
            let frame_len = (HEADER_BYTES as u64)
                .checked_add(payload_len as u64)
                .and_then(|value| value.checked_add(CHECKSUM_BYTES as u64))
                .ok_or(QhwrOperationJournalError::CorruptRecord { offset })?;
            if remaining < frame_len {
                self.truncate_incomplete_tail(offset)?;
                break;
            }

            let mut payload = vec![0u8; payload_len];
            self.file.read_exact(&mut payload)?;
            let mut checksum = [0u8; CHECKSUM_BYTES];
            self.file.read_exact(&mut checksum)?;
            if !constant_time_eq(&checksum, &record_checksum(&header, &payload)) {
                return Err(QhwrOperationJournalError::CorruptRecord { offset });
            }
            let operation_key: [u8; 32] = header[14..46].try_into().unwrap();
            if kind == KIND_RESERVE && self.states.len() >= MAX_OPERATIONS {
                return Err(QhwrOperationJournalError::CorruptRecord { offset });
            }
            let next = recover_transition(
                self.states.get(&operation_key),
                operation_key,
                kind,
                &payload,
            )
            .map_err(|_| QhwrOperationJournalError::CorruptRecord { offset })?;
            self.states.insert(operation_key, next);
            offset = offset
                .checked_add(frame_len)
                .ok_or(QhwrOperationJournalError::CorruptRecord { offset })?;
        }
        self.valid_len = offset;
        if let Err(error) = self.file.seek(SeekFrom::Start(self.valid_len)) {
            self.poisoned = true;
            return Err(error.into());
        }
        Ok(())
    }

    fn truncate_incomplete_tail(&mut self, offset: u64) -> Result<(), QhwrOperationJournalError> {
        self.file.set_len(offset)?;
        self.file.sync_all()?;
        Ok(())
    }
}

fn state_pins(state: &QhwrJournalState) -> &QhwrJournalPins {
    match state {
        QhwrJournalState::Reserved { pins }
        | QhwrJournalState::Prepared { pins, .. }
        | QhwrJournalState::Signed { pins, .. }
        | QhwrJournalState::Completed { pins, .. } => pins,
    }
}

fn state_pins_prepared(
    state: &QhwrJournalState,
) -> Option<(&QhwrJournalPins, &QhwrJournalPrepared)> {
    match state {
        QhwrJournalState::Prepared { pins, prepared }
        | QhwrJournalState::Signed { pins, prepared, .. }
        | QhwrJournalState::Completed { pins, prepared, .. } => Some((pins, prepared)),
        QhwrJournalState::Reserved { .. } => None,
    }
}

fn validate_prepared(prepared: &QhwrJournalPrepared) -> Result<(), QhwrOperationJournalError> {
    if prepared.provider_snapshot.is_empty()
        || prepared.provider_snapshot.len() > MAX_SNAPSHOT_BYTES
        || prepared.signer_key_id.iter().all(|byte| *byte == 0)
        || prepared.signer_key_generation == 0
    {
        return Err(QhwrOperationJournalError::InvalidPayload(
            "snapshot or signer pins",
        ));
    }
    Ok(())
}

fn payload_len_valid(kind: u8, len: usize) -> bool {
    match kind {
        KIND_RESERVE => len == 96,
        KIND_PREPARE => len >= 4 + 1 + 32 + 8 + 32,
        KIND_ARTIFACT => len >= 4 + 1 + 32,
        KIND_COMPLETE => len >= 4 + 1 + 32,
        _ => false,
    }
}

fn make_header(
    kind: u8,
    payload_len: usize,
    operation_key: &[u8; 32],
) -> Result<[u8; HEADER_BYTES], QhwrOperationJournalError> {
    let encoded_len =
        u32::try_from(payload_len).map_err(|_| QhwrOperationJournalError::LimitExceeded)?;
    let mut header = [0u8; HEADER_BYTES];
    header[..8].copy_from_slice(MAGIC);
    header[8] = VERSION;
    header[9] = kind;
    header[10..14].copy_from_slice(&encoded_len.to_be_bytes());
    header[14..46].copy_from_slice(operation_key);
    Ok(header)
}

fn record_checksum(header: &[u8], payload: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(CHECKSUM_DOMAIN);
    hasher.update(header);
    hasher.update(payload);
    hasher.finalize().into()
}

fn put_bytes(output: &mut Vec<u8>, bytes: &[u8]) -> Result<(), QhwrOperationJournalError> {
    let len = u32::try_from(bytes.len()).map_err(|_| QhwrOperationJournalError::LimitExceeded)?;
    output.extend_from_slice(&len.to_be_bytes());
    output.extend_from_slice(bytes);
    Ok(())
}

fn read_u32(bytes: &[u8], cursor: &mut usize) -> Result<usize, QhwrOperationJournalError> {
    let end = cursor
        .checked_add(4)
        .ok_or(QhwrOperationJournalError::InvalidPayload("length overflow"))?;
    let value = bytes
        .get(*cursor..end)
        .ok_or(QhwrOperationJournalError::InvalidPayload(
            "truncated length",
        ))?;
    *cursor = end;
    Ok(u32::from_be_bytes(value.try_into().unwrap()) as usize)
}

fn read_sized<'a>(
    bytes: &'a [u8],
    cursor: &mut usize,
    maximum: usize,
) -> Result<&'a [u8], QhwrOperationJournalError> {
    let len = read_u32(bytes, cursor)?;
    if len == 0 || len > maximum {
        return Err(QhwrOperationJournalError::InvalidPayload(
            "bounded byte length",
        ));
    }
    let end = cursor
        .checked_add(len)
        .ok_or(QhwrOperationJournalError::InvalidPayload("length overflow"))?;
    let value = bytes
        .get(*cursor..end)
        .ok_or(QhwrOperationJournalError::InvalidPayload("truncated bytes"))?;
    *cursor = end;
    Ok(value)
}

fn recover_transition(
    current: Option<&QhwrJournalState>,
    operation_key: [u8; 32],
    kind: u8,
    payload: &[u8],
) -> Result<QhwrJournalState, QhwrOperationJournalError> {
    match kind {
        KIND_RESERVE => {
            if current.is_some() || payload.len() != 96 {
                return Err(QhwrOperationJournalError::InvalidTransition);
            }
            let identity: [u8; 32] = payload[..32].try_into().unwrap();
            let pins = QhwrJournalPins {
                operation_key: QhwrSignerOperationKey(operation_key),
                qhwr_identity_digest: identity,
                request_digest: payload[32..64].try_into().unwrap(),
                provider_id: payload[64..96].try_into().unwrap(),
            };
            pins.validate()?;
            Ok(QhwrJournalState::Reserved { pins })
        }
        KIND_PREPARE => {
            let QhwrJournalState::Reserved { pins } =
                current.ok_or(QhwrOperationJournalError::InvalidTransition)?
            else {
                return Err(QhwrOperationJournalError::InvalidTransition);
            };
            let mut cursor = 0;
            let snapshot = read_sized(payload, &mut cursor, MAX_SNAPSHOT_BYTES)?.to_vec();
            let key_end = cursor + 32;
            let signer_key_id: [u8; 32] = payload
                .get(cursor..key_end)
                .ok_or(QhwrOperationJournalError::InvalidPayload("signer key id"))?
                .try_into()
                .unwrap();
            cursor = key_end;
            let generation_end = cursor + 8;
            let generation = u64::from_be_bytes(
                payload
                    .get(cursor..generation_end)
                    .ok_or(QhwrOperationJournalError::InvalidPayload("key generation"))?
                    .try_into()
                    .unwrap(),
            );
            cursor = generation_end;
            let digest_end = cursor + 32;
            let signing_digest: [u8; 32] = payload
                .get(cursor..digest_end)
                .ok_or(QhwrOperationJournalError::InvalidPayload("signing digest"))?
                .try_into()
                .unwrap();
            if digest_end != payload.len() {
                return Err(QhwrOperationJournalError::InvalidPayload(
                    "trailing prepare bytes",
                ));
            }
            let prepared = QhwrJournalPrepared {
                provider_snapshot: snapshot,
                signer_key_id,
                signer_key_generation: generation,
                signing_digest,
            };
            validate_prepared(&prepared)?;
            Ok(QhwrJournalState::Prepared {
                pins: pins.clone(),
                prepared,
            })
        }
        KIND_ARTIFACT => {
            let Some((pins, prepared)) = current.and_then(state_pins_prepared) else {
                return Err(QhwrOperationJournalError::InvalidTransition);
            };
            if !matches!(current, Some(QhwrJournalState::Prepared { .. })) {
                return Err(QhwrOperationJournalError::InvalidTransition);
            }
            let mut cursor = 0;
            let signature = read_sized(payload, &mut cursor, MAX_ARTIFACT_BYTES)?.to_vec();
            let digest_end = cursor + 32;
            let artifact_digest: [u8; 32] = payload
                .get(cursor..digest_end)
                .ok_or(QhwrOperationJournalError::InvalidPayload("artifact digest"))?
                .try_into()
                .unwrap();
            if digest_end != payload.len() {
                return Err(QhwrOperationJournalError::InvalidPayload(
                    "trailing artifact bytes",
                ));
            }
            let artifact = QhwrSignerArtifact {
                signature_bytes: signature,
                artifact_digest,
            };
            artifact
                .validate()
                .map_err(|_| QhwrOperationJournalError::InvalidPayload("artifact digest"))?;
            Ok(QhwrJournalState::Signed {
                pins: pins.clone(),
                prepared: prepared.clone(),
                artifact,
            })
        }
        KIND_COMPLETE => {
            let Some(QhwrJournalState::Signed {
                pins,
                prepared,
                artifact,
            }) = current
            else {
                return Err(QhwrOperationJournalError::InvalidTransition);
            };
            let mut cursor = 0;
            let response = read_sized(payload, &mut cursor, MAX_RESPONSE_BYTES)?.to_vec();
            let digest_end = cursor + 32;
            let response_digest: [u8; 32] = payload
                .get(cursor..digest_end)
                .ok_or(QhwrOperationJournalError::InvalidPayload("response digest"))?
                .try_into()
                .unwrap();
            if digest_end != payload.len()
                || Sha256::digest(&response).as_slice() != response_digest
            {
                return Err(QhwrOperationJournalError::InvalidPayload("response digest"));
            }
            Ok(QhwrJournalState::Completed {
                pins: pins.clone(),
                prepared: prepared.clone(),
                artifact: artifact.clone(),
                completed: QhwrJournalCompleted {
                    response_bytes: response,
                    response_digest,
                },
            })
        }
        _ => Err(QhwrOperationJournalError::InvalidTransition),
    }
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0u8, |difference, (a, b)| difference | (a ^ b))
        == 0
}

fn parent_directory(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

#[cfg(any(unix, test))]
mod tests {
    use super::*;
    use std::{
        io::{Seek, SeekFrom},
        sync::atomic::{AtomicU64, Ordering},
        time::{SystemTime, UNIX_EPOCH},
    };

    static NEXT_TEST_DIR: AtomicU64 = AtomicU64::new(0);

    fn test_path() -> PathBuf {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let sequence = NEXT_TEST_DIR.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "qrun-qhwr-journal-{}-{timestamp}-{sequence}",
            std::process::id()
        ));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("operations.wal");
        #[cfg(windows)]
        File::create(&path).unwrap().sync_all().unwrap();
        path
    }

    fn pins() -> QhwrJournalPins {
        QhwrJournalPins::new([0x11; 32], [0x22; 32], [0x33; 32])
    }

    fn prepared() -> QhwrJournalPrepared {
        QhwrJournalPrepared {
            provider_snapshot: b"canonical-provider-snapshot-v1".to_vec(),
            signer_key_id: [0x44; 32],
            signer_key_generation: 7,
            signing_digest: [0x55; 32],
        }
    }

    fn finish(journal: &mut QhwrDurableOperationJournalCandidate) -> QhwrSignerOperationKey {
        let identity = pins();
        let key = identity.operation_key;
        journal.reserve(identity).unwrap();
        journal.prepare(key, prepared()).unwrap();
        journal
            .record_artifact(
                key,
                QhwrSignerArtifact::new(b"stable-signature".to_vec()).unwrap(),
            )
            .unwrap();
        journal
            .complete(key, b"exact-encoded-response".to_vec())
            .unwrap();
        key
    }

    #[test]
    fn full_lifecycle_survives_reopen_with_byte_identical_response() {
        let path = test_path();
        let key;
        {
            let mut journal = QhwrDurableOperationJournalCandidate::open(&path).unwrap();
            key = finish(&mut journal);
            assert_eq!(
                journal.state(&key).unwrap().completed_response(),
                Some(&b"exact-encoded-response"[..])
            );
        }
        let journal = QhwrDurableOperationJournalCandidate::open(&path).unwrap();
        assert_eq!(
            journal.state(&key).unwrap().completed_response(),
            Some(&b"exact-encoded-response"[..])
        );
        assert_eq!(journal.operation_count(), 1);
    }

    #[test]
    fn exact_retries_are_noops_and_identity_changes_fail_closed() {
        let path = test_path();
        let mut journal = QhwrDurableOperationJournalCandidate::open(&path).unwrap();
        let identity = pins();
        let key = identity.operation_key;
        assert!(matches!(journal.reserve(identity.clone()), Ok(true)));
        assert!(matches!(journal.reserve(identity), Ok(false)));
        assert!(matches!(journal.prepare(key, prepared()), Ok(true)));
        assert!(matches!(journal.prepare(key, prepared()), Ok(false)));
        let mut changed = prepared();
        changed.signer_key_generation += 1;
        assert!(matches!(
            journal.prepare(key, changed),
            Err(QhwrOperationJournalError::IdentityConflict)
        ));
        let mut changed_pins = pins();
        changed_pins.request_digest[0] ^= 1;
        assert!(matches!(
            journal.reserve(changed_pins),
            Err(QhwrOperationJournalError::IdentityConflict)
        ));
    }

    #[test]
    fn illegal_transition_order_is_rejected() {
        let path = test_path();
        let mut journal = QhwrDurableOperationJournalCandidate::open(&path).unwrap();
        let key = pins().operation_key;
        assert!(matches!(
            journal.complete(key, b"response".to_vec()),
            Err(QhwrOperationJournalError::InvalidTransition)
        ));
        assert!(matches!(
            journal.prepare(key, prepared()),
            Err(QhwrOperationJournalError::InvalidTransition)
        ));
    }

    #[test]
    fn partial_final_header_is_truncated_without_losing_acknowledged_records() {
        let path = test_path();
        let key;
        let durable_len;
        {
            let mut journal = QhwrDurableOperationJournalCandidate::open(&path).unwrap();
            key = finish(&mut journal);
            durable_len = journal.durable_len();
        }
        OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(&[0x51, 0x48, 0x57])
            .unwrap();
        let journal = QhwrDurableOperationJournalCandidate::open(&path).unwrap();
        assert_eq!(journal.durable_len(), durable_len);
        assert!(journal.state(&key).unwrap().completed_response().is_some());
        assert_eq!(fs::metadata(&path).unwrap().len(), durable_len);
    }

    #[test]
    fn complete_frame_checksum_corruption_fails_closed() {
        let path = test_path();
        {
            let mut journal = QhwrDurableOperationJournalCandidate::open(&path).unwrap();
            finish(&mut journal);
        }
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        file.seek(SeekFrom::End(-1)).unwrap();
        let mut byte = [0u8; 1];
        file.read_exact(&mut byte).unwrap();
        byte[0] ^= 1;
        file.seek(SeekFrom::End(-1)).unwrap();
        file.write_all(&byte).unwrap();
        file.sync_all().unwrap();
        assert!(matches!(
            QhwrDurableOperationJournalCandidate::open(&path),
            Err(QhwrOperationJournalError::CorruptRecord { .. })
        ));
    }

    #[test]
    fn oversized_declared_frame_length_fails_closed_before_allocation() {
        let path = test_path();
        {
            let mut journal = QhwrDurableOperationJournalCandidate::open(&path).unwrap();
            journal.reserve(pins()).unwrap();
        }
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        file.seek(SeekFrom::Start(10)).unwrap();
        file.write_all(&u32::MAX.to_be_bytes()).unwrap();
        file.sync_all().unwrap();
        assert!(matches!(
            QhwrDurableOperationJournalCandidate::open(&path),
            Err(QhwrOperationJournalError::CorruptRecord { .. })
        ));
    }

    #[test]
    fn response_digest_and_exact_bytes_are_retained() {
        let path = test_path();
        let mut journal = QhwrDurableOperationJournalCandidate::open(&path).unwrap();
        let key = finish(&mut journal);
        let before = journal.durable_len();
        assert!(matches!(
            journal.complete(key, b"exact-encoded-response".to_vec()),
            Ok(false)
        ));
        assert_eq!(journal.durable_len(), before);
        assert!(matches!(
            journal.complete(key, b"changed-response".to_vec()),
            Err(QhwrOperationJournalError::IdentityConflict)
        ));
    }

    #[test]
    fn partial_final_payload_is_truncated_after_reserved_transition() {
        let path = test_path();
        let key;
        let durable_len;
        {
            let mut journal = QhwrDurableOperationJournalCandidate::open(&path).unwrap();
            let identity = pins();
            key = identity.operation_key;
            journal.reserve(identity).unwrap();
            durable_len = journal.durable_len();
        }
        let header = make_header(KIND_PREPARE, 77, &key.0).unwrap();
        let mut file = OpenOptions::new().append(true).open(&path).unwrap();
        file.write_all(&header).unwrap();
        file.write_all(&[0xAB; 3]).unwrap();
        file.sync_all().unwrap();
        let journal = QhwrDurableOperationJournalCandidate::open(&path).unwrap();
        assert_eq!(journal.durable_len(), durable_len);
        assert!(matches!(
            journal.state(&key),
            Some(QhwrJournalState::Reserved { .. })
        ));
        assert_eq!(fs::metadata(&path).unwrap().len(), durable_len);
    }

    #[test]
    fn injected_before_write_poisons_handle_and_reopen_keeps_old_state() {
        let path = test_path();
        let identity = pins();
        {
            let mut journal = QhwrDurableOperationJournalCandidate::open(&path).unwrap();
            journal.fault_at = Some(QhwrJournalFaultPoint::BeforeWrite);
            assert!(matches!(
                journal.reserve(identity.clone()),
                Err(QhwrOperationJournalError::Io(_))
            ));
            assert!(matches!(
                journal.reserve(identity.clone()),
                Err(QhwrOperationJournalError::StoreNeedsRecovery)
            ));
        }
        let mut reopened = QhwrDurableOperationJournalCandidate::open(&path).unwrap();
        assert_eq!(reopened.operation_count(), 0);
        assert_eq!(reopened.durable_len(), 0);
        assert!(matches!(reopened.reserve(identity), Ok(true)));
    }

    #[test]
    fn injected_after_header_poisons_and_restart_discards_unacknowledged_tail() {
        let path = test_path();
        let identity = pins();
        {
            let mut journal = QhwrDurableOperationJournalCandidate::open(&path).unwrap();
            journal.fault_at = Some(QhwrJournalFaultPoint::AfterHeader);
            assert!(matches!(
                journal.reserve(identity.clone()),
                Err(QhwrOperationJournalError::Io(_))
            ));
            assert!(matches!(
                journal.reserve(identity.clone()),
                Err(QhwrOperationJournalError::StoreNeedsRecovery)
            ));
        }
        let mut reopened = QhwrDurableOperationJournalCandidate::open(&path).unwrap();
        assert_eq!(reopened.operation_count(), 0);
        assert_eq!(reopened.durable_len(), 0);
        assert!(matches!(reopened.reserve(identity), Ok(true)));
    }

    #[test]
    fn injected_after_payload_poisons_and_restart_discards_unacknowledged_tail() {
        let path = test_path();
        let identity = pins();
        {
            let mut journal = QhwrDurableOperationJournalCandidate::open(&path).unwrap();
            journal.fault_at = Some(QhwrJournalFaultPoint::AfterPayload);
            assert!(matches!(
                journal.reserve(identity.clone()),
                Err(QhwrOperationJournalError::Io(_))
            ));
            assert!(matches!(
                journal.reserve(identity.clone()),
                Err(QhwrOperationJournalError::StoreNeedsRecovery)
            ));
        }
        let mut reopened = QhwrDurableOperationJournalCandidate::open(&path).unwrap();
        assert_eq!(reopened.operation_count(), 0);
        assert_eq!(reopened.durable_len(), 0);
        assert!(matches!(reopened.reserve(identity), Ok(true)));
    }

    #[test]
    fn injected_before_sync_reopen_adopts_only_complete_valid_record() {
        let path = test_path();
        let identity = pins();
        {
            let mut journal = QhwrDurableOperationJournalCandidate::open(&path).unwrap();
            journal.fault_at = Some(QhwrJournalFaultPoint::AfterChecksum);
            assert!(matches!(
                journal.reserve(identity.clone()),
                Err(QhwrOperationJournalError::Io(_))
            ));
            assert!(matches!(
                journal.reserve(identity.clone()),
                Err(QhwrOperationJournalError::StoreNeedsRecovery)
            ));
        }
        let mut reopened = QhwrDurableOperationJournalCandidate::open(&path).unwrap();
        assert!(reopened.operation_count() <= 1);
        if reopened.operation_count() == 1 {
            assert!(matches!(
                reopened.state(&identity.operation_key),
                Some(QhwrJournalState::Reserved { pins: current }) if current == &identity
            ));
            assert!(matches!(reopened.reserve(identity), Ok(false)));
        } else {
            assert_eq!(reopened.durable_len(), 0);
            assert!(matches!(reopened.reserve(identity), Ok(true)));
        }
    }
    #[test]
    fn injected_lost_ack_after_sync_recovers_the_exact_committed_reservation() {
        let path = test_path();
        let identity = pins();
        {
            let mut journal = QhwrDurableOperationJournalCandidate::open(&path).unwrap();
            journal.fault_at = Some(QhwrJournalFaultPoint::AfterSync);
            assert!(matches!(
                journal.reserve(identity.clone()),
                Err(QhwrOperationJournalError::Io(_))
            ));
            assert!(matches!(
                journal.reserve(identity.clone()),
                Err(QhwrOperationJournalError::StoreNeedsRecovery)
            ));
        }
        let mut reopened = QhwrDurableOperationJournalCandidate::open(&path).unwrap();
        assert_eq!(reopened.operation_count(), 1);
        assert!(matches!(
            reopened.state(&identity.operation_key),
            Some(QhwrJournalState::Reserved { pins: current }) if current == &identity
        ));
        assert!(matches!(reopened.reserve(identity), Ok(false)));
    }

    #[test]
    fn only_one_writer_can_open_the_same_journal() {
        let path = test_path();
        let first = QhwrDurableOperationJournalCandidate::open(&path).unwrap();
        assert!(matches!(
            QhwrDurableOperationJournalCandidate::open(&path),
            Err(QhwrOperationJournalError::WriterLockUnavailable)
        ));
        drop(first);
        assert!(QhwrDurableOperationJournalCandidate::open(&path).is_ok());
    }
}
