//! CP-0395 durable local journal for exact PFM5/ECR1 publication intents.
//!
//! The journal is a crash-safe replay aid, not an independent anti-rollback root of trust.
//! Callers must advance a separately protected monotonic sequence floor after staging a
//! Prepared intent and BEFORE any remote object publication or ECR1 CAS side effect.
//! The exact encoded intent is retained until a verified ECR1 successor is recorded locally.
//!
//! A crash after the remote CAS but before local journal finalization leaves the exact Prepared
//! intent available. Recovery must execute that same intent again; CP-0394 performs a fresh
//! signed read and classifies the remote state without guessing.

use crate::{
    external_cas_anchor_candidate::{ExternalCasPin, ExternalCasRecord},
    private_testnet_pfm5_external_cas_candidate::{
        Pfm5ExternalCasIntent, PFM5_EXTERNAL_CAS_INTENT_BYTES,
    },
    snapshot_store::{SnapshotStoreError, SnapshotWriterLock},
};
use sha2::{Digest, Sha256};
use std::{
    ffi::OsString,
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

const JOURNAL_MAGIC: &[u8; 4] = b"PFJ1";
const JOURNAL_VERSION: u16 = 1;
const JOURNAL_READY: u8 = 1;
const JOURNAL_PREPARED: u8 = 2;
const CHECKSUM_DOMAIN: &[u8] = b"AIN1-PFM5-EXTERNAL-CAS-JOURNAL-CHECKSUM-V1\0";
const HEADER_BYTES: usize = 4 + 2 + 1 + 1 + 8 + 8;
const RECORD_OFFSET: usize = HEADER_BYTES;
const RECORD_BYTES: usize = 272;
const INTENT_OFFSET: usize = RECORD_OFFSET + RECORD_BYTES;
const CHECKSUM_OFFSET: usize = INTENT_OFFSET + PFM5_EXTERNAL_CAS_INTENT_BYTES;
pub const PFM5_EXTERNAL_CAS_JOURNAL_BYTES: usize = CHECKSUM_OFFSET + 32;
static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Pfm5ExternalCasJournalError {
    Io(String),
    WriterLock(String),
    InvalidPath,
    Missing,
    AlreadyInitialized,
    TooManyOrphanTemps,
    InvalidEncoding,
    ChecksumMismatch,
    PinMismatch,
    HardLinkAlias,
    PendingIntentExists,
    NoPendingIntent,
    IntentConflict,
    InvalidTransition,
    SequenceOverflow,
    SequenceRollback { observed: u64, minimum: u64 },
    RecordRollback { observed: u64, minimum: u64 },
    ObjectGenerationRollback { observed: u64, minimum: u64 },
    ReadbackMismatch,
}

impl std::fmt::Display for Pfm5ExternalCasJournalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for Pfm5ExternalCasJournalError {}
impl From<io::Error> for Pfm5ExternalCasJournalError {
    fn from(error: io::Error) -> Self {
        Self::Io(error.to_string())
    }
}
impl From<SnapshotStoreError> for Pfm5ExternalCasJournalError {
    fn from(error: SnapshotStoreError) -> Self {
        Self::WriterLock(error.to_string())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pfm5ExternalCasJournalSnapshot {
    /// Monotonic journal sequence. Persist its high-water mark outside this disk rollback domain.
    pub sequence: u64,
    /// Last locally finalized ECR1 record, or the verified predecessor while Prepared.
    pub last_record: ExternalCasRecord,
    /// Object generation for last_record, or its predecessor while Prepared.
    pub object_generation: u64,
    /// Present only after the exact intent has been durably staged and before finalization.
    pub pending_intent: Option<Pfm5ExternalCasIntent>,
}
impl Pfm5ExternalCasJournalSnapshot {
    pub fn is_prepared(&self) -> bool {
        self.pending_intent.is_some()
    }
}

/// File-backed journal. The file is fixed-size and create-once initialized.
#[derive(Debug, Clone)]
pub struct Pfm5ExternalCasJournalStore {
    path: PathBuf,
}
struct JournalLocks {
    _path_lock: SnapshotWriterLock,
}

impl Pfm5ExternalCasJournalStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// Explicit bootstrap from an already verified ECR1 read and observed object generation.
    /// Missing/corrupt state is never silently reset to this value.
    pub fn initialize(
        &self,
        pin: &ExternalCasPin,
        initial_record: ExternalCasRecord,
        initial_object_generation: u64,
    ) -> Result<Pfm5ExternalCasJournalSnapshot, Pfm5ExternalCasJournalError> {
        validate_record_domain(pin, &initial_record)?;
        if initial_object_generation == 0 {
            return Err(Pfm5ExternalCasJournalError::InvalidTransition);
        }
        let _locks = self.acquire_locks()?;
        match fs::symlink_metadata(&self.path) {
            Ok(_) => return Err(Pfm5ExternalCasJournalError::AlreadyInitialized),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        let snapshot = Pfm5ExternalCasJournalSnapshot {
            sequence: 1,
            last_record: initial_record,
            object_generation: initial_object_generation,
            pending_intent: None,
        };
        self.persist_and_verify(pin, &snapshot)?;
        Ok(snapshot)
    }

    /// Load only if all caller-supplied independent monotonic floors are met.
    pub fn load_checked(
        &self,
        pin: &ExternalCasPin,
        minimum_sequence: u64,
        minimum_record_generation: u64,
        minimum_object_generation: u64,
    ) -> Result<Pfm5ExternalCasJournalSnapshot, Pfm5ExternalCasJournalError> {
        let _locks = self.acquire_locks()?;
        let snapshot = self.load_unlocked(pin)?;
        validate_floors(
            &snapshot,
            minimum_sequence,
            minimum_record_generation,
            minimum_object_generation,
        )?;
        Ok(snapshot)
    }
    /// Durably stage the exact intent before remote object publication or ECR1 CAS.
    ///
    /// If the same intent is already Prepared this is idempotent. A different intent cannot
    /// replace a pending one. After this returns, persist snapshot.sequence to an independent
    /// high-water store BEFORE invoking CP-0394 execute_intent.
    pub fn stage_intent(
        &self,
        pin: &ExternalCasPin,
        intent: &Pfm5ExternalCasIntent,
        minimum_sequence: u64,
        minimum_record_generation: u64,
        minimum_object_generation: u64,
    ) -> Result<Pfm5ExternalCasJournalSnapshot, Pfm5ExternalCasJournalError> {
        intent
            .validate(pin)
            .map_err(|_| Pfm5ExternalCasJournalError::InvalidTransition)?;
        let _locks = self.acquire_locks()?;
        let current = self.load_unlocked(pin)?;
        validate_floors(
            &current,
            minimum_sequence,
            minimum_record_generation,
            minimum_object_generation,
        )?;

        if let Some(pending) = &current.pending_intent {
            return if pending == intent {
                Ok(current)
            } else {
                Err(Pfm5ExternalCasJournalError::PendingIntentExists)
            };
        }
        if current.last_record != intent.expected_current
            || current.object_generation != intent.expected_object_generation
        {
            return Err(Pfm5ExternalCasJournalError::IntentConflict);
        }

        let next = Pfm5ExternalCasJournalSnapshot {
            sequence: current
                .sequence
                .checked_add(1)
                .ok_or(Pfm5ExternalCasJournalError::SequenceOverflow)?,
            last_record: current.last_record,
            object_generation: current.object_generation,
            pending_intent: Some(intent.clone()),
        };
        self.persist_and_verify(pin, &next)?;
        Ok(next)
    }

    /// Finalize only after CP-0394 returned a verified committed outcome, or a fresh signed read
    /// proved the exact successor. A RetrySameIntent result leaves the Prepared entry untouched.
    pub fn mark_committed(
        &self,
        pin: &ExternalCasPin,
        intent: &Pfm5ExternalCasIntent,
        committed_record: ExternalCasRecord,
        committed_object_generation: u64,
        minimum_sequence: u64,
        minimum_record_generation: u64,
        minimum_object_generation: u64,
    ) -> Result<Pfm5ExternalCasJournalSnapshot, Pfm5ExternalCasJournalError> {
        intent
            .validate(pin)
            .map_err(|_| Pfm5ExternalCasJournalError::InvalidTransition)?;
        validate_record_domain(pin, &committed_record)?;
        if committed_record != intent.write_request.next_record
            || committed_object_generation <= intent.expected_object_generation
        {
            return Err(Pfm5ExternalCasJournalError::InvalidTransition);
        }
        let _locks = self.acquire_locks()?;
        let current = self.load_unlocked(pin)?;
        validate_floors(
            &current,
            minimum_sequence,
            minimum_record_generation,
            minimum_object_generation,
        )?;

        // A crash after atomic replacement but before the caller records its independent floors
        // may cause this exact finalization to be repeated. It is safe only byte-for-byte idempotent.
        if current.pending_intent.is_none()
            && current.last_record == committed_record
            && current.object_generation == committed_object_generation
        {
            return Ok(current);
        }
        if current.pending_intent.as_ref() != Some(intent)
            || current.last_record != intent.expected_current
            || current.object_generation != intent.expected_object_generation
        {
            return Err(Pfm5ExternalCasJournalError::IntentConflict);
        }
        current
            .last_record
            .validate_successor(&committed_record)
            .map_err(|_| Pfm5ExternalCasJournalError::InvalidTransition)?;

        let next = Pfm5ExternalCasJournalSnapshot {
            sequence: current
                .sequence
                .checked_add(1)
                .ok_or(Pfm5ExternalCasJournalError::SequenceOverflow)?,
            last_record: committed_record,
            object_generation: committed_object_generation,
            pending_intent: None,
        };
        self.persist_and_verify(pin, &next)?;
        Ok(next)
    }

    /// The pending intent is the sole local replay input after an ambiguous CAS window.
    /// The caller fetches the manifest named by next_record.next_state_digest, then executes
    /// this same intent through CP-0394, which performs a fresh signed ECR1 read.
    pub fn pending_intent(
        &self,
        pin: &ExternalCasPin,
        minimum_sequence: u64,
        minimum_record_generation: u64,
        minimum_object_generation: u64,
    ) -> Result<Option<Pfm5ExternalCasIntent>, Pfm5ExternalCasJournalError> {
        Ok(self
            .load_checked(
                pin,
                minimum_sequence,
                minimum_record_generation,
                minimum_object_generation,
            )?
            .pending_intent)
    }

    fn persist_and_verify(
        &self,
        pin: &ExternalCasPin,
        snapshot: &Pfm5ExternalCasJournalSnapshot,
    ) -> Result<(), Pfm5ExternalCasJournalError> {
        let bytes = encode_snapshot(pin, snapshot)?;
        persist_atomic(&self.path, &bytes)?;
        if self.load_unlocked(pin)? != *snapshot {
            return Err(Pfm5ExternalCasJournalError::ReadbackMismatch);
        }
        Ok(())
    }

    fn load_unlocked(
        &self,
        pin: &ExternalCasPin,
    ) -> Result<Pfm5ExternalCasJournalSnapshot, Pfm5ExternalCasJournalError> {
        let bytes = read_bounded(&self.path)?;
        decode_snapshot(pin, &bytes)
    }

    fn acquire_locks(&self) -> Result<JournalLocks, Pfm5ExternalCasJournalError> {
        // The stable sibling lock is retained across atomic replacement. Existing hard-link
        // aliases are rejected by link-count preflight; locking the data inode itself would
        // prevent Windows from replacing that inode with MoveFileExW.
        let path_lock = SnapshotWriterLock::acquire(&self.path)?;
        match fs::symlink_metadata(&self.path) {
            Ok(metadata) => {
                if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
                    return Err(Pfm5ExternalCasJournalError::InvalidPath);
                }
                if !metadata_has_single_link(&self.path, &metadata) {
                    return Err(Pfm5ExternalCasJournalError::HardLinkAlias);
                }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        cleanup_orphan_temps(&self.path)?;
        Ok(JournalLocks {
            _path_lock: path_lock,
        })
    }
}
fn validate_record_domain(
    pin: &ExternalCasPin,
    record: &ExternalCasRecord,
) -> Result<(), Pfm5ExternalCasJournalError> {
    pin.validate()
        .map_err(|_| Pfm5ExternalCasJournalError::PinMismatch)?;
    record
        .validate_shape()
        .map_err(|_| Pfm5ExternalCasJournalError::InvalidEncoding)?;
    if record.provider_id != pin.provider_id
        || record.network_id != pin.network_id
        || record.genesis_digest != pin.genesis_digest
    {
        return Err(Pfm5ExternalCasJournalError::PinMismatch);
    }
    Ok(())
}

fn validate_floors(
    snapshot: &Pfm5ExternalCasJournalSnapshot,
    minimum_sequence: u64,
    minimum_record_generation: u64,
    minimum_object_generation: u64,
) -> Result<(), Pfm5ExternalCasJournalError> {
    if snapshot.sequence < minimum_sequence {
        return Err(Pfm5ExternalCasJournalError::SequenceRollback {
            observed: snapshot.sequence,
            minimum: minimum_sequence,
        });
    }
    if snapshot.last_record.generation < minimum_record_generation {
        return Err(Pfm5ExternalCasJournalError::RecordRollback {
            observed: snapshot.last_record.generation,
            minimum: minimum_record_generation,
        });
    }
    if snapshot.object_generation < minimum_object_generation {
        return Err(Pfm5ExternalCasJournalError::ObjectGenerationRollback {
            observed: snapshot.object_generation,
            minimum: minimum_object_generation,
        });
    }
    Ok(())
}

fn encode_snapshot(
    pin: &ExternalCasPin,
    snapshot: &Pfm5ExternalCasJournalSnapshot,
) -> Result<[u8; PFM5_EXTERNAL_CAS_JOURNAL_BYTES], Pfm5ExternalCasJournalError> {
    if snapshot.sequence == 0 || snapshot.object_generation == 0 {
        return Err(Pfm5ExternalCasJournalError::InvalidEncoding);
    }
    validate_record_domain(pin, &snapshot.last_record)?;
    let mut bytes = [0u8; PFM5_EXTERNAL_CAS_JOURNAL_BYTES];
    bytes[0..4].copy_from_slice(JOURNAL_MAGIC);
    bytes[4..6].copy_from_slice(&JOURNAL_VERSION.to_be_bytes());
    bytes[6] = if snapshot.pending_intent.is_some() {
        JOURNAL_PREPARED
    } else {
        JOURNAL_READY
    };
    bytes[7] = 0;
    bytes[8..16].copy_from_slice(&snapshot.sequence.to_be_bytes());
    bytes[16..24].copy_from_slice(&snapshot.object_generation.to_be_bytes());
    let record = snapshot
        .last_record
        .encode()
        .map_err(|_| Pfm5ExternalCasJournalError::InvalidEncoding)?;
    bytes[RECORD_OFFSET..INTENT_OFFSET].copy_from_slice(&record);

    if let Some(intent) = &snapshot.pending_intent {
        intent
            .validate(pin)
            .map_err(|_| Pfm5ExternalCasJournalError::InvalidEncoding)?;
        if intent.expected_current != snapshot.last_record
            || intent.expected_object_generation != snapshot.object_generation
        {
            return Err(Pfm5ExternalCasJournalError::InvalidEncoding);
        }
        let encoded_intent = intent
            .encode(pin)
            .map_err(|_| Pfm5ExternalCasJournalError::InvalidEncoding)?;
        bytes[INTENT_OFFSET..CHECKSUM_OFFSET].copy_from_slice(&encoded_intent);
    }
    let digest = checksum(&bytes[..CHECKSUM_OFFSET]);
    bytes[CHECKSUM_OFFSET..].copy_from_slice(&digest);
    Ok(bytes)
}

fn decode_snapshot(
    pin: &ExternalCasPin,
    bytes: &[u8],
) -> Result<Pfm5ExternalCasJournalSnapshot, Pfm5ExternalCasJournalError> {
    if bytes.len() != PFM5_EXTERNAL_CAS_JOURNAL_BYTES
        || &bytes[0..4] != JOURNAL_MAGIC
        || u16::from_be_bytes(bytes[4..6].try_into().unwrap()) != JOURNAL_VERSION
        || bytes[7] != 0
    {
        return Err(Pfm5ExternalCasJournalError::InvalidEncoding);
    }
    if bytes[CHECKSUM_OFFSET..] != checksum(&bytes[..CHECKSUM_OFFSET]) {
        return Err(Pfm5ExternalCasJournalError::ChecksumMismatch);
    }
    let sequence = u64::from_be_bytes(bytes[8..16].try_into().unwrap());
    let object_generation = u64::from_be_bytes(bytes[16..24].try_into().unwrap());
    if sequence == 0 || object_generation == 0 {
        return Err(Pfm5ExternalCasJournalError::InvalidEncoding);
    }
    let last_record = ExternalCasRecord::decode(&bytes[RECORD_OFFSET..INTENT_OFFSET])
        .map_err(|_| Pfm5ExternalCasJournalError::InvalidEncoding)?;
    validate_record_domain(pin, &last_record)?;

    let pending_intent = match bytes[6] {
        JOURNAL_READY => {
            if bytes[INTENT_OFFSET..CHECKSUM_OFFSET]
                .iter()
                .any(|byte| *byte != 0)
            {
                return Err(Pfm5ExternalCasJournalError::InvalidEncoding);
            }
            None
        }
        JOURNAL_PREPARED => {
            let intent = Pfm5ExternalCasIntent::decode(&bytes[INTENT_OFFSET..CHECKSUM_OFFSET], pin)
                .map_err(|_| Pfm5ExternalCasJournalError::InvalidEncoding)?;
            if intent.expected_current != last_record
                || intent.expected_object_generation != object_generation
            {
                return Err(Pfm5ExternalCasJournalError::InvalidEncoding);
            }
            Some(intent)
        }
        _ => return Err(Pfm5ExternalCasJournalError::InvalidEncoding),
    };
    Ok(Pfm5ExternalCasJournalSnapshot {
        sequence,
        last_record,
        object_generation,
        pending_intent,
    })
}

fn checksum(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(CHECKSUM_DOMAIN);
    hasher.update(bytes);
    hasher.finalize().into()
}
fn read_bounded(path: &Path) -> Result<Vec<u8>, Pfm5ExternalCasJournalError> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        if error.kind() == io::ErrorKind::NotFound {
            Pfm5ExternalCasJournalError::Missing
        } else {
            Pfm5ExternalCasJournalError::Io(error.to_string())
        }
    })?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(Pfm5ExternalCasJournalError::InvalidPath);
    }
    if !metadata_has_single_link(path, &metadata) {
        return Err(Pfm5ExternalCasJournalError::HardLinkAlias);
    }
    if metadata.len() != PFM5_EXTERNAL_CAS_JOURNAL_BYTES as u64 {
        return Err(Pfm5ExternalCasJournalError::InvalidEncoding);
    }
    let file = File::open(path)?;
    let mut bytes = Vec::with_capacity(PFM5_EXTERNAL_CAS_JOURNAL_BYTES);
    file.take((PFM5_EXTERNAL_CAS_JOURNAL_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() != PFM5_EXTERNAL_CAS_JOURNAL_BYTES {
        return Err(Pfm5ExternalCasJournalError::InvalidEncoding);
    }
    Ok(bytes)
}

fn persist_atomic(path: &Path, bytes: &[u8]) -> Result<(), Pfm5ExternalCasJournalError> {
    if bytes.len() != PFM5_EXTERNAL_CAS_JOURNAL_BYTES {
        return Err(Pfm5ExternalCasJournalError::InvalidEncoding);
    }
    let parent = parent_directory(path);
    if !parent.is_dir() {
        return Err(Pfm5ExternalCasJournalError::InvalidPath);
    }
    let final_name = path
        .file_name()
        .ok_or(Pfm5ExternalCasJournalError::InvalidPath)?;
    let mut temp_name = OsString::from(".");
    temp_name.push(final_name);
    temp_name.push(format!(
        ".pfm5-cas-journal.{}.{}.tmp",
        std::process::id(),
        NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed)
    ));
    let temp_path = parent.join(temp_name);
    let result = (|| -> io::Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp_path)?;
        file.write_all(bytes)?;
        file.flush()?;
        file.sync_all()?;
        drop(file);
        #[cfg(test)]
        crash_at_journal_boundary("after_temp_sync");
        atomic_replace(&temp_path, path)?;
        #[cfg(test)]
        crash_at_journal_boundary("after_replace");
        sync_parent(parent)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp_path);
    }
    result.map_err(|error| Pfm5ExternalCasJournalError::Io(error.to_string()))
}

fn parent_directory(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

#[cfg(windows)]
fn atomic_replace(source: &Path, destination: &Path) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    const MOVEFILE_REPLACE_EXISTING: u32 = 0x1;
    const MOVEFILE_WRITE_THROUGH: u32 = 0x8;
    let from: Vec<u16> = source.as_os_str().encode_wide().chain(Some(0)).collect();
    let to: Vec<u16> = destination
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect();
    #[link(name = "Kernel32")]
    extern "system" {
        fn MoveFileExW(existing: *const u16, new_name: *const u16, flags: u32) -> i32;
    }
    // SAFETY: both paths are NUL-terminated UTF-16 buffers valid for this call.
    let result = unsafe {
        MoveFileExW(
            from.as_ptr(),
            to.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if result == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(not(windows))]
fn atomic_replace(source: &Path, destination: &Path) -> io::Result<()> {
    fs::rename(source, destination)
}

#[cfg(windows)]
fn sync_parent(_directory: &Path) -> io::Result<()> {
    Ok(())
}
#[cfg(unix)]
fn sync_parent(directory: &Path) -> io::Result<()> {
    File::open(directory)?.sync_all()
}
#[cfg(not(any(windows, unix)))]
fn sync_parent(_directory: &Path) -> io::Result<()> {
    Ok(())
}

#[cfg(unix)]
fn metadata_has_single_link(_path: &Path, metadata: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    metadata.nlink() == 1
}

#[cfg(windows)]
fn metadata_has_single_link(path: &Path, _metadata: &fs::Metadata) -> bool {
    use std::os::windows::io::AsRawHandle;

    #[repr(C)]
    struct FileTime {
        low: u32,
        high: u32,
    }
    #[repr(C)]
    struct ByHandleFileInformation {
        attributes: u32,
        creation_time: FileTime,
        last_access_time: FileTime,
        last_write_time: FileTime,
        volume_serial_number: u32,
        file_size_high: u32,
        file_size_low: u32,
        number_of_links: u32,
        file_index_high: u32,
        file_index_low: u32,
    }
    #[link(name = "kernel32")]
    extern "system" {
        fn GetFileInformationByHandle(
            file: *mut std::ffi::c_void,
            information: *mut ByHandleFileInformation,
        ) -> i32;
    }
    let Ok(file) = File::open(path) else {
        return false;
    };
    let mut information = ByHandleFileInformation {
        attributes: 0,
        creation_time: FileTime { low: 0, high: 0 },
        last_access_time: FileTime { low: 0, high: 0 },
        last_write_time: FileTime { low: 0, high: 0 },
        volume_serial_number: 0,
        file_size_high: 0,
        file_size_low: 0,
        number_of_links: 0,
        file_index_high: 0,
        file_index_low: 0,
    };
    // SAFETY: the file handle is live and the output structure matches the Win32 ABI.
    let result = unsafe {
        GetFileInformationByHandle(
            file.as_raw_handle() as *mut std::ffi::c_void,
            &mut information,
        )
    };
    result != 0 && information.number_of_links == 1
}

#[cfg(not(any(unix, windows)))]
fn metadata_has_single_link(_path: &Path, _metadata: &fs::Metadata) -> bool {
    true
}

#[cfg(test)]
fn crash_at_journal_boundary(stage: &str) {
    if std::env::var("AIN1_PFM5_CAS_JOURNAL_CRASH_STAGE")
        .ok()
        .as_deref()
        == Some(stage)
    {
        std::process::exit(86);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        external_cas_anchor_candidate::ExternalCasWriteRequest,
        v4_fat1_trust_candidate::ML_DSA_65_PUBLIC_KEY_BYTES,
    };
    use std::{
        process::Command,
        sync::atomic::{AtomicU64, Ordering},
    };

    static NEXT_DIR: AtomicU64 = AtomicU64::new(1);
    const CHILD_PATH_ENV: &str = "AIN1_PFM5_CAS_JOURNAL_CHILD_PATH";

    struct TestDir(PathBuf);
    impl TestDir {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "ain1-pfm5-cas-journal-{}-{}",
                std::process::id(),
                NEXT_DIR.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }
        fn file(&self) -> PathBuf {
            self.0.join("intent.pfj1")
        }
    }
    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn fixture() -> (ExternalCasPin, ExternalCasRecord, Pfm5ExternalCasIntent) {
        let pin = ExternalCasPin {
            provider_id: [0x11; 32],
            network_id: [0x22; 32],
            genesis_digest: [0x33; 32],
            receipt_key_id: [0x44; 32],
            receipt_public_key: [0x55; ML_DSA_65_PUBLIC_KEY_BYTES],
        };
        let current = ExternalCasRecord {
            generation: 0,
            provider_id: pin.provider_id,
            network_id: pin.network_id,
            genesis_digest: pin.genesis_digest,
            previous_record_digest: [0; 32],
            previous_state_digest: [0; 32],
            next_state_digest: [0x66; 32],
            operation_id: [0x67; 32],
            request_digest: [0x68; 32],
        };
        let intent = make_intent(&pin, current.clone(), 40, 0x77);
        (pin, current, intent)
    }

    fn make_intent(
        pin: &ExternalCasPin,
        current: ExternalCasRecord,
        object_generation: u64,
        target_byte: u8,
    ) -> Pfm5ExternalCasIntent {
        let operation_id = [target_byte.wrapping_add(1); 32];
        let mut write_request = ExternalCasWriteRequest {
            request_nonce: [target_byte.wrapping_add(2); 32],
            operation_id,
            request_digest: [0; 32],
            expected_generation: current.generation,
            expected_object_generation: object_generation,
            expected_record_digest: current.digest().unwrap(),
            expected_state_digest: current.next_state_digest,
            next_record: ExternalCasRecord {
                generation: current.generation + 1,
                provider_id: pin.provider_id,
                network_id: pin.network_id,
                genesis_digest: pin.genesis_digest,
                previous_record_digest: current.digest().unwrap(),
                previous_state_digest: current.next_state_digest,
                next_state_digest: [target_byte; 32],
                operation_id,
                request_digest: [0; 32],
            },
        };
        write_request.bind_request_digest(pin).unwrap();
        let intent = Pfm5ExternalCasIntent {
            expected_current: current,
            expected_object_generation: object_generation,
            write_request,
        };
        intent.validate(pin).unwrap();
        intent
    }

    fn store(dir: &TestDir) -> Pfm5ExternalCasJournalStore {
        Pfm5ExternalCasJournalStore::new(dir.file())
    }

    #[test]
    fn initialize_is_create_once_and_roundtrips_exact_bootstrap_record() {
        let (pin, current, _) = fixture();
        let dir = TestDir::new();
        let journal = store(&dir);
        let initialized = journal.initialize(&pin, current.clone(), 40).unwrap();
        assert_eq!(initialized.sequence, 1);
        assert_eq!(initialized.last_record, current);
        assert_eq!(initialized.object_generation, 40);
        assert!(!initialized.is_prepared());

        let loaded = journal.load_checked(&pin, 1, 0, 40).unwrap();
        assert_eq!(loaded, initialized);
        assert_eq!(
            journal.initialize(&pin, loaded.last_record.clone(), 40),
            Err(Pfm5ExternalCasJournalError::AlreadyInitialized)
        );
    }

    #[test]
    fn prepared_intent_survives_reopen_and_only_identical_stage_is_idempotent() {
        let (pin, current, intent) = fixture();
        let dir = TestDir::new();
        let journal = store(&dir);
        journal.initialize(&pin, current.clone(), 40).unwrap();

        let staged = journal.stage_intent(&pin, &intent, 1, 0, 40).unwrap();
        assert_eq!(staged.sequence, 2);
        assert_eq!(staged.last_record, current);
        assert_eq!(staged.pending_intent, Some(intent.clone()));

        let reopened = store(&dir);
        assert_eq!(reopened.load_checked(&pin, 2, 0, 40).unwrap(), staged);
        assert_eq!(
            reopened.stage_intent(&pin, &intent, 2, 0, 40).unwrap(),
            staged
        );

        let conflicting = make_intent(&pin, current, 40, 0x91);
        assert_eq!(
            reopened.stage_intent(&pin, &conflicting, 2, 0, 40),
            Err(Pfm5ExternalCasJournalError::PendingIntentExists)
        );
        assert_eq!(
            reopened.pending_intent(&pin, 2, 0, 40).unwrap(),
            Some(intent)
        );
    }

    #[test]
    fn committed_successor_clears_pending_and_finalization_is_idempotent() {
        let (pin, current, intent) = fixture();
        let dir = TestDir::new();
        let journal = store(&dir);
        journal.initialize(&pin, current, 40).unwrap();
        let staged = journal.stage_intent(&pin, &intent, 1, 0, 40).unwrap();
        let committed = intent.write_request.next_record.clone();

        let finalized = journal
            .mark_committed(&pin, &intent, committed.clone(), 41, staged.sequence, 0, 40)
            .unwrap();
        assert_eq!(finalized.sequence, 3);
        assert_eq!(finalized.last_record, committed);
        assert_eq!(finalized.object_generation, 41);
        assert!(!finalized.is_prepared());

        let reopened = store(&dir);
        assert_eq!(reopened.load_checked(&pin, 3, 1, 41).unwrap(), finalized);
        assert_eq!(
            reopened
                .mark_committed(&pin, &intent, committed, 41, 3, 1, 41)
                .unwrap(),
            finalized
        );
    }

    #[test]
    fn independent_highwater_floors_detect_journal_rollback() {
        let (pin, current, intent) = fixture();
        let dir = TestDir::new();
        let journal = store(&dir);
        journal.initialize(&pin, current, 40).unwrap();

        assert!(matches!(
            journal.load_checked(&pin, 2, 0, 40),
            Err(Pfm5ExternalCasJournalError::SequenceRollback {
                observed: 1,
                minimum: 2
            })
        ));
        let staged = journal.stage_intent(&pin, &intent, 1, 0, 40).unwrap();
        assert!(matches!(
            journal.load_checked(&pin, 3, 0, 40),
            Err(Pfm5ExternalCasJournalError::SequenceRollback {
                observed: 2,
                minimum: 3
            })
        ));
        assert!(matches!(
            journal.load_checked(&pin, 2, 1, 40),
            Err(Pfm5ExternalCasJournalError::RecordRollback {
                observed: 0,
                minimum: 1
            })
        ));
        assert!(matches!(
            journal.load_checked(&pin, 2, 0, 41),
            Err(Pfm5ExternalCasJournalError::ObjectGenerationRollback {
                observed: 40,
                minimum: 41
            })
        ));
        assert_eq!(staged.sequence, 2);
    }

    #[test]
    fn checksum_corruption_wrong_pin_and_truncation_fail_closed() {
        let (pin, current, _) = fixture();
        let dir = TestDir::new();
        let journal = store(&dir);
        journal.initialize(&pin, current, 40).unwrap();

        let mut bytes = fs::read(&dir.file()).unwrap();
        assert_eq!(bytes.len(), PFM5_EXTERNAL_CAS_JOURNAL_BYTES);
        bytes[80] ^= 1;
        fs::write(dir.file(), &bytes).unwrap();
        assert_eq!(
            journal.load_checked(&pin, 1, 0, 40),
            Err(Pfm5ExternalCasJournalError::ChecksumMismatch)
        );

        fs::write(dir.file(), vec![0u8; PFM5_EXTERNAL_CAS_JOURNAL_BYTES - 1]).unwrap();
        assert_eq!(
            journal.load_checked(&pin, 1, 0, 40),
            Err(Pfm5ExternalCasJournalError::InvalidEncoding)
        );

        // A copied journal from another provider domain is never accepted.
        let dir2 = TestDir::new();
        let journal2 = store(&dir2);
        let (pin2, current2, _) = fixture();
        journal2.initialize(&pin2, current2, 40).unwrap();
        let mut wrong_pin = pin2.clone();
        wrong_pin.provider_id[0] ^= 1;
        assert_eq!(
            journal2.load_checked(&wrong_pin, 1, 0, 40),
            Err(Pfm5ExternalCasJournalError::PinMismatch)
        );
    }

    #[test]
    fn hard_link_alias_is_rejected_before_journal_read_or_write() {
        let (pin, current, _) = fixture();
        let dir = TestDir::new();
        let journal = store(&dir);
        journal.initialize(&pin, current, 40).unwrap();
        let alias = dir.0.join("alias.pfj1");
        fs::hard_link(dir.file(), &alias).unwrap();

        let alias_store = Pfm5ExternalCasJournalStore::new(alias);
        assert_eq!(
            alias_store.load_checked(&pin, 1, 0, 40),
            Err(Pfm5ExternalCasJournalError::HardLinkAlias)
        );
    }

    #[test]
    fn journal_child_stage_worker() {
        let Ok(path) = std::env::var(CHILD_PATH_ENV) else {
            return;
        };
        let (pin, _current, intent) = fixture();
        let journal = Pfm5ExternalCasJournalStore::new(path);
        journal.stage_intent(&pin, &intent, 1, 0, 40).unwrap();
    }

    #[test]
    fn actual_child_termination_preserves_old_or_complete_prepared_journal() {
        for (stage, expect_prepared) in [("after_temp_sync", false), ("after_replace", true)] {
            let (pin, current, intent) = fixture();
            let dir = TestDir::new();
            let journal = store(&dir);
            journal.initialize(&pin, current.clone(), 40).unwrap();

            let executable = std::env::current_exe().unwrap();
            let status = Command::new(executable)
                .arg("--exact")
                .arg("private_testnet_pfm5_external_cas_journal_candidate::tests::journal_child_stage_worker")
                .arg("--nocapture")
                .env(CHILD_PATH_ENV, dir.file())
                .env("AIN1_PFM5_CAS_JOURNAL_CRASH_STAGE", stage)
                .status()
                .unwrap();
            assert_eq!(status.code(), Some(86), "child did not exit at {stage}");

            let reopened = store(&dir);
            let snapshot = reopened.load_checked(&pin, 1, 0, 40).unwrap();
            if expect_prepared {
                assert_eq!(snapshot.sequence, 2);
                assert_eq!(snapshot.pending_intent, Some(intent));
            } else {
                assert_eq!(snapshot.sequence, 1);
                assert!(snapshot.pending_intent.is_none());
                assert_eq!(snapshot.last_record, current);
                let prefix = format!(
                    ".{}.pfm5-cas-journal.",
                    dir.file().file_name().unwrap().to_string_lossy()
                );
                let orphan_count = fs::read_dir(&dir.0)
                    .unwrap()
                    .filter_map(Result::ok)
                    .filter(|entry| {
                        let name = entry.file_name().to_string_lossy().into_owned();
                        name.starts_with(&prefix) && name.ends_with(".tmp")
                    })
                    .count();
                assert_eq!(
                    orphan_count, 0,
                    "startup must remove uncommitted journal temp files"
                );
            }
        }
    }
}

/// Remove only stale temp files created by this exact journal's atomic writer.
/// A process kill before replace leaves a temp file; it is never interpreted as journal state.
fn cleanup_orphan_temps(path: &Path) -> Result<(), Pfm5ExternalCasJournalError> {
    let final_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(Pfm5ExternalCasJournalError::InvalidPath)?;
    let prefix = format!(".{final_name}.pfm5-cas-journal.");
    let parent = parent_directory(path);
    let mut removed = 0usize;

    for entry in fs::read_dir(parent)? {
        let entry = entry?;
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        let Some(tail) = name
            .strip_prefix(&prefix)
            .and_then(|value| value.strip_suffix(".tmp"))
        else {
            continue;
        };
        let mut parts = tail.split('.');
        let valid_name = parts
            .next()
            .and_then(|part| part.parse::<u32>().ok())
            .is_some()
            && parts
                .next()
                .and_then(|part| part.parse::<u64>().ok())
                .is_some()
            && parts.next().is_none();
        if !valid_name {
            continue;
        }
        let metadata = fs::symlink_metadata(entry.path())?;
        if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
            return Err(Pfm5ExternalCasJournalError::InvalidPath);
        }
        removed += 1;
        if removed > 64 {
            return Err(Pfm5ExternalCasJournalError::TooManyOrphanTemps);
        }
        fs::remove_file(entry.path())?;
    }
    if removed != 0 {
        sync_parent(parent)?;
    }
    Ok(())
}
