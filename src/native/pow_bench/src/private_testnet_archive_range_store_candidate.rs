//! Research-only append-only archive page WAL with restart validation and partial-tail recovery.
//!
//! This is not connected to canonical chain storage, consensus or the node's live archive path.
//! Each page is framed, checksummed and fsynced before the receiver advances. Startup replays every
//! complete record through the same receiver verifier; only an incomplete final record is truncated.
//! A complete record with a bad checksum or invalid page fails closed rather than being skipped.
use crate::private_testnet_archive_range_receiver_candidate::{
    ArchiveRangeReceiverCandidate, ArchiveRangeReceiverError, VerifiedArchiveRangeReceipt,
};
use crate::private_testnet_archive_range_server_candidate::{
    ArchiveSyncServedEntry, ArchiveSyncServedPage,
};
use crate::private_testnet_archive_sync_candidate::{
    ArchiveEntryMeta, ArchiveSyncLimits, ArchiveSyncPage, ARCHIVE_SYNC_CURSOR_BYTES,
    MAX_CANDIDATE_PAGE_ITEMS,
};
use sha2::{Digest, Sha256};
#[cfg(test)]
use std::fs;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

const WAL_DOMAIN: &[u8] = b"AI_NATIVE_L1_ARCHIVE_RANGE_WAL_RECORD_V1\0";
const WAL_RESPONSE_MAGIC: &[u8; 4] = b"ARW1";
pub const MAX_STORED_ARCHIVE_PAGE_BYTES: usize = 5 * 1024 * 1024;
pub const MAX_ARCHIVE_RANGE_WAL_BYTES: u64 = 300 * 1024 * 1024;
const LENGTH_PREFIX_BYTES: usize = 4;
const CHECKSUM_BYTES: usize = 32;

#[derive(Debug)]
pub enum ArchiveRangeStoreError {
    Io(io::Error),
    InvalidPath,
    ManifestInvalid,
    FrameTooLarge(usize),
    InvalidFrame(&'static str),
    ChecksumMismatch { offset: u64 },
    InvalidPage(String),
    InvalidAppendOrder,
    StoreNeedsRecovery,
    WriterLockUnavailable,
    StoreTooLarge(u64),
    InjectedFault(&'static str),
}

impl std::fmt::Display for ArchiveRangeStoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(f, "archive range WAL I/O failed: {error}"),
            Self::InvalidPath => write!(
                f,
                "archive range WAL path must name a file in an existing directory"
            ),
            Self::ManifestInvalid => write!(f, "archive range WAL manifest/limits are invalid"),
            Self::FrameTooLarge(len) => {
                write!(f, "archive range WAL page frame exceeds cap: {len}")
            }
            Self::InvalidFrame(reason) => write!(f, "archive range WAL frame invalid: {reason}"),
            Self::ChecksumMismatch { offset } => {
                write!(f, "archive range WAL checksum mismatch at offset {offset}")
            }
            Self::InvalidPage(reason) => {
                write!(f, "archive range WAL page validation failed: {reason}")
            }
            Self::InvalidAppendOrder => write!(
                f,
                "archive range WAL append is not contiguous with durable receiver progress"
            ),
            Self::StoreNeedsRecovery => write!(
                f,
                "archive range WAL has an uncertain write; reopen and recover before reuse"
            ),
            Self::WriterLockUnavailable => write!(
                f,
                "archive range WAL is already open for writing by another process"
            ),
            Self::StoreTooLarge(len) => write!(f, "archive range WAL exceeds store cap: {len}"),
            Self::InjectedFault(stage) => write!(f, "injected archive range WAL fault at {stage}"),
        }
    }
}

impl std::error::Error for ArchiveRangeStoreError {}

impl From<io::Error> for ArchiveRangeStoreError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CommitStage {
    BeforeWrite,
    AfterPrefix,
    AfterBody,
    AfterChecksum,
    AfterSync,
    BeforeParentSync,
}

impl CommitStage {
    #[cfg(any(test, feature = "devnet-wal-fault-injection"))]
    fn label(self) -> &'static str {
        match self {
            Self::BeforeWrite => "before-write",
            Self::AfterPrefix => "after-prefix",
            Self::AfterBody => "after-body",
            Self::AfterChecksum => "after-checksum",
            Self::AfterSync => "after-sync",
            Self::BeforeParentSync => "before-parent-sync",
        }
    }
}

/// Single-writer append-only page store for an explicitly supplied immutable snapshot manifest.
/// Holds a non-blocking OS file lock for the store lifetime to reject concurrent writers.
/// Re-open after any append error; the store intentionally poisons itself when commit outcome is
/// uncertain. This remains a candidate, not a canonical-chain store or chain selector.
pub struct ArchiveRangeWalCandidate {
    path: PathBuf,
    file: File,
    _writer_lock: crate::snapshot_store::SnapshotWriterLock,
    _file_identity_lock: crate::snapshot_store::SnapshotWriterLock,
    limits: ArchiveSyncLimits,
    expected_snapshot_commitment: [u8; 32],
    expected_total_items: u64,
    expected_total_bytes: u64,
    receiver: ArchiveRangeReceiverCandidate,
    valid_len: u64,
    poisoned: bool,
}

impl ArchiveRangeWalCandidate {
    pub fn open(
        path: &Path,
        limits: ArchiveSyncLimits,
        expected_snapshot_commitment: [u8; 32],
        expected_total_items: u64,
        expected_total_bytes: u64,
    ) -> Result<Self, ArchiveRangeStoreError> {
        let parent = parent_directory(path);
        if path.file_name().is_none() || !parent.is_dir() {
            return Err(ArchiveRangeStoreError::InvalidPath);
        }
        let receiver = ArchiveRangeReceiverCandidate::new(
            limits,
            expected_snapshot_commitment,
            expected_total_items,
            expected_total_bytes,
        )
        .map_err(|_| ArchiveRangeStoreError::ManifestInvalid)?;
        // Acquire the stable sibling lock before opening the WAL for writing or recovery.
        // The lock file is deliberately not deleted; deleting it can split lock ownership.
        let writer_lock = crate::snapshot_store::SnapshotWriterLock::acquire(path).map_err(
            |error| match error {
                crate::snapshot_store::SnapshotStoreError::WriterLockBusy(_) => {
                    ArchiveRangeStoreError::WriterLockUnavailable
                }
                crate::snapshot_store::SnapshotStoreError::Io(error) => {
                    ArchiveRangeStoreError::Io(error)
                }
                other => ArchiveRangeStoreError::Io(io::Error::new(
                    io::ErrorKind::Other,
                    other.to_string(),
                )),
            },
        )?;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(path)?;
        // The path lock protects same-name first-open races. The file-object lock additionally
        // rejects hard-link aliases that have different names but refer to the same underlying WAL.
        let file_identity_lock = crate::snapshot_store::SnapshotWriterLock::acquire_file_identity(
            &file, path,
        )
        .map_err(|error| match error {
            crate::snapshot_store::SnapshotStoreError::WriterLockBusy(_) => {
                ArchiveRangeStoreError::WriterLockUnavailable
            }
            crate::snapshot_store::SnapshotStoreError::Io(error) => {
                ArchiveRangeStoreError::Io(error)
            }
            other => {
                ArchiveRangeStoreError::Io(io::Error::new(io::ErrorKind::Other, other.to_string()))
            }
        })?;
        let mut store = Self {
            path: path.to_path_buf(),
            file,
            _writer_lock: writer_lock,
            _file_identity_lock: file_identity_lock,
            limits,
            expected_snapshot_commitment,
            expected_total_items,
            expected_total_bytes,
            receiver,
            valid_len: 0,
            poisoned: false,
        };
        store.recover()?;
        Ok(store)
    }

    pub fn receipt(&self) -> VerifiedArchiveRangeReceipt {
        self.receiver.receipt()
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Compute a diagnostic digest using this store's already-open, single-writer file handle.
    /// This avoids reopening an exclusively locked WAL from another process during runtime tests.
    /// The caller must use this only for diagnostics; it does not replace record checksums/fsync.
    pub fn diagnostic_sha256(&mut self) -> Result<[u8; 32], ArchiveRangeStoreError> {
        if self.poisoned {
            return Err(ArchiveRangeStoreError::StoreNeedsRecovery);
        }
        let original_position = self.file.stream_position()?;
        let digest_result = (|| -> io::Result<[u8; 32]> {
            self.file.seek(SeekFrom::Start(0))?;
            let mut hasher = Sha256::new();
            let mut buffer = [0u8; 8192];
            loop {
                let count = self.file.read(&mut buffer)?;
                if count == 0 {
                    break;
                }
                hasher.update(&buffer[..count]);
            }
            Ok(hasher.finalize().into())
        })();
        let restore_result = self.file.seek(SeekFrom::Start(original_position));
        let digest = digest_result?;
        restore_result?;
        Ok(digest)
    }

    /// Validate a page against the current durable receiver cursor without advancing it.
    /// The caller can then apply the contained payloads through consensus before fsync-committing
    /// the page and acknowledging progress.
    pub fn validate_page(
        &self,
        page: &ArchiveSyncServedPage,
    ) -> Result<(), ArchiveRangeStoreError> {
        self.receiver
            .validate_page_only(page)
            .map_err(|error| ArchiveRangeStoreError::InvalidPage(format!("{error:?}")))
    }

    pub fn commit_page(
        &mut self,
        page: &ArchiveSyncServedPage,
    ) -> Result<VerifiedArchiveRangeReceipt, ArchiveRangeStoreError> {
        #[cfg(feature = "devnet-wal-fault-injection")]
        if std::env::var_os("CPW_ARCHIVE_WAL_RUNTIME_FAULT_STAGE").is_some() {
            return self.commit_page_with_runtime_fault_injection(page);
        }
        self.commit_page_with_hook(page, |_| Ok(()))
    }

    #[cfg(feature = "devnet-wal-fault-injection")]
    fn commit_page_with_runtime_fault_injection(
        &mut self,
        page: &ArchiveSyncServedPage,
    ) -> Result<VerifiedArchiveRangeReceipt, ArchiveRangeStoreError> {
        let stage_name = std::env::var("CPW_ARCHIVE_WAL_RUNTIME_FAULT_STAGE")
            .map_err(|_| ArchiveRangeStoreError::InvalidFrame("missing WAL fault stage"))?;
        let target = match stage_name.as_str() {
            "after-prefix" => CommitStage::AfterPrefix,
            "after-body" => CommitStage::AfterBody,
            "after-checksum" => CommitStage::AfterChecksum,
            "after-sync" => CommitStage::AfterSync,
            "before-parent-sync" => CommitStage::BeforeParentSync,
            _ => {
                return Err(ArchiveRangeStoreError::InvalidFrame(
                    "unsupported WAL fault stage",
                ))
            }
        };
        let marker = std::env::var_os("CPW_ARCHIVE_WAL_RUNTIME_FAULT_MARKER")
            .map(PathBuf::from)
            .ok_or(ArchiveRangeStoreError::InvalidFrame(
                "missing WAL fault marker path",
            ))?;
        let target_page = std::env::var("CPW_ARCHIVE_WAL_RUNTIME_FAULT_TARGET_PAGE")
            .ok()
            .map(|value| {
                value.parse::<u32>().map_err(|_| {
                    ArchiveRangeStoreError::InvalidFrame("invalid WAL fault target page")
                })
            })
            .transpose()?
            .unwrap_or(1);
        if !(1..=1024).contains(&target_page) {
            return Err(ArchiveRangeStoreError::InvalidFrame(
                "WAL fault target page outside 1..=1024",
            ));
        }
        let pause_ms = std::env::var("CPW_ARCHIVE_WAL_RUNTIME_FAULT_PAUSE_MS")
            .map_err(|_| ArchiveRangeStoreError::InvalidFrame("missing WAL fault pause"))?
            .parse::<u64>()
            .map_err(|_| ArchiveRangeStoreError::InvalidFrame("invalid WAL fault pause"))?;
        if !(100..=30_000).contains(&pause_ms) {
            return Err(ArchiveRangeStoreError::InvalidFrame(
                "WAL fault pause outside 100..=30000 ms",
            ));
        }
        self.commit_page_with_hook(page, |stage| {
            if page.plan.page_number == target_page && stage == target {
                std::fs::write(&marker, stage.label().as_bytes())?;
                std::thread::sleep(std::time::Duration::from_millis(pause_ms));
            }
            Ok(())
        })
    }

    /// Commit only while the supplied archive generation remains active.
    ///
    /// The coordinator holds a read lease through the WAL's durable commit; a reorg transition
    /// using the same coordinator either wins first (and makes this page stale) or waits for this
    /// commit to finish before publishing its replacement generation. This is candidate-only.
    pub fn commit_page_for_generation(
        &mut self,
        page: &ArchiveSyncServedPage,
        coordinator: &crate::private_testnet_archive_generation_coordinator_candidate::ArchiveGenerationCoordinatorCandidate,
        expected: crate::private_testnet_archive_generation_coordinator_candidate::ArchiveGenerationStamp,
    ) -> Result<
        VerifiedArchiveRangeReceipt,
        crate::private_testnet_archive_generation_coordinator_candidate::ArchiveGenerationCommitError<ArchiveRangeStoreError>,
    >{
        coordinator.commit_if_current(expected, || self.commit_page(page))
    }

    fn commit_page_with_hook<F>(
        &mut self,
        page: &ArchiveSyncServedPage,
        mut hook: F,
    ) -> Result<VerifiedArchiveRangeReceipt, ArchiveRangeStoreError>
    where
        F: FnMut(CommitStage) -> Result<(), ArchiveRangeStoreError>,
    {
        if self.poisoned {
            return Err(ArchiveRangeStoreError::StoreNeedsRecovery);
        }
        let before = self.receiver.receipt();
        let expected_snapshot = self.expected_snapshot_commitment;
        let expected_items = self.expected_total_items;
        let expected_bytes = self.expected_total_bytes;
        let limits = self.limits;
        let valid_len = &mut self.valid_len;
        let poisoned = &mut self.poisoned;
        let file = &mut self.file;
        let path = &self.path;
        let result = self.receiver.apply_page_with_commit(page, |candidate| {
            persist_one_record(
                file,
                path,
                limits,
                expected_snapshot,
                expected_items,
                expected_bytes,
                before,
                valid_len,
                poisoned,
                candidate,
                &mut hook,
            )
        });
        match result {
            Ok(receipt) => Ok(receipt),
            Err(ArchiveRangeReceiverError::Commit(error)) => Err(error),
            Err(error) => Err(ArchiveRangeStoreError::InvalidPage(format!("{error:?}"))),
        }
    }

    fn recover(&mut self) -> Result<(), ArchiveRangeStoreError> {
        let file_len = self.file.metadata()?.len();
        if file_len > MAX_ARCHIVE_RANGE_WAL_BYTES {
            return Err(ArchiveRangeStoreError::StoreTooLarge(file_len));
        }
        self.file.seek(SeekFrom::Start(0))?;
        let mut offset = 0u64;
        let mut truncate_tail = false;
        while offset < file_len {
            let remaining = file_len - offset;
            if remaining < LENGTH_PREFIX_BYTES as u64 {
                truncate_tail = true;
                break;
            }
            let mut prefix = [0u8; LENGTH_PREFIX_BYTES];
            self.file.read_exact(&mut prefix)?;
            let body_len = u32::from_be_bytes(prefix) as usize;
            if body_len == 0 {
                return Err(ArchiveRangeStoreError::InvalidFrame("zero-length page"));
            }
            if body_len > MAX_STORED_ARCHIVE_PAGE_BYTES {
                return Err(ArchiveRangeStoreError::FrameTooLarge(body_len));
            }
            let framed_len = (LENGTH_PREFIX_BYTES as u64)
                .checked_add(body_len as u64)
                .and_then(|n| n.checked_add(CHECKSUM_BYTES as u64))
                .ok_or(ArchiveRangeStoreError::InvalidFrame(
                    "record length overflow",
                ))?;
            if remaining < framed_len {
                truncate_tail = true;
                break;
            }
            let mut body = vec![0u8; body_len];
            self.file.read_exact(&mut body)?;
            let mut supplied_checksum = [0u8; CHECKSUM_BYTES];
            self.file.read_exact(&mut supplied_checksum)?;
            let expected_checksum = record_checksum(&prefix, &body);
            if !constant_time_eq(&supplied_checksum, &expected_checksum) {
                return Err(ArchiveRangeStoreError::ChecksumMismatch { offset });
            }
            let page = decode_archive_range_page(&body, self.limits)?;
            self.receiver
                .apply_page_with_commit(&page, |_| Ok::<(), ArchiveRangeStoreError>(()))
                .map_err(|error| {
                    ArchiveRangeStoreError::InvalidPage(format!(
                        "record at offset {offset}: {error:?}"
                    ))
                })?;
            offset = offset
                .checked_add(framed_len)
                .ok_or(ArchiveRangeStoreError::InvalidFrame(
                    "store offset overflow",
                ))?;
            self.valid_len = offset;
        }
        if truncate_tail {
            self.file.set_len(offset)?;
            self.file.sync_all()?;
        }
        self.file.seek(SeekFrom::Start(self.valid_len))?;
        Ok(())
    }
}

fn persist_one_record<F>(
    file: &mut File,
    path: &Path,
    limits: ArchiveSyncLimits,
    expected_snapshot: [u8; 32],
    expected_items: u64,
    expected_bytes: u64,
    before: VerifiedArchiveRangeReceipt,
    valid_len: &mut u64,
    poisoned: &mut bool,
    page: &ArchiveSyncServedPage,
    hook: &mut F,
) -> Result<(), ArchiveRangeStoreError>
where
    F: FnMut(CommitStage) -> Result<(), ArchiveRangeStoreError>,
{
    if page.snapshot_commitment != expected_snapshot
        || page.archive_total_items != expected_items
        || page.archive_total_bytes != expected_bytes
        || page.plan.start_index != before.end_index
        || page.plan.page_number
            != if expected_items == 0 {
                0
            } else {
                before.pages_verified.saturating_add(1)
            }
    {
        return Err(ArchiveRangeStoreError::InvalidAppendOrder);
    }
    let body = encode_archive_range_page(page, limits)?;
    if body.is_empty() || body.len() > MAX_STORED_ARCHIVE_PAGE_BYTES {
        return Err(ArchiveRangeStoreError::FrameTooLarge(body.len()));
    }
    let body_len =
        u32::try_from(body.len()).map_err(|_| ArchiveRangeStoreError::FrameTooLarge(body.len()))?;
    let prefix = body_len.to_be_bytes();
    let checksum = record_checksum(&prefix, &body);
    let framed_len = (LENGTH_PREFIX_BYTES as u64)
        .checked_add(body.len() as u64)
        .and_then(|n| n.checked_add(CHECKSUM_BYTES as u64))
        .ok_or(ArchiveRangeStoreError::InvalidFrame(
            "record length overflow",
        ))?;
    let new_len = valid_len
        .checked_add(framed_len)
        .ok_or(ArchiveRangeStoreError::InvalidFrame(
            "store length overflow",
        ))?;
    if new_len > MAX_ARCHIVE_RANGE_WAL_BYTES {
        return Err(ArchiveRangeStoreError::StoreTooLarge(new_len));
    }
    if file.metadata()?.len() != *valid_len {
        *poisoned = true;
        return Err(ArchiveRangeStoreError::StoreNeedsRecovery);
    }
    let fail_if_injected = |stage, poisoned: &mut bool, hook: &mut F| {
        if let Err(error) = hook(stage) {
            *poisoned = true;
            Err(error)
        } else {
            Ok(())
        }
    };
    fail_if_injected(CommitStage::BeforeWrite, poisoned, hook)?;
    file.seek(SeekFrom::Start(*valid_len))?;
    if let Err(error) = file.write_all(&prefix) {
        *poisoned = true;
        return Err(error.into());
    }
    fail_if_injected(CommitStage::AfterPrefix, poisoned, hook)?;
    if let Err(error) = file.write_all(&body) {
        *poisoned = true;
        return Err(error.into());
    }
    fail_if_injected(CommitStage::AfterBody, poisoned, hook)?;
    if let Err(error) = file.write_all(&checksum) {
        *poisoned = true;
        return Err(error.into());
    }
    // Diagnostic stage: the framed record is complete in the file handle, but has not yet
    // crossed the sync_all durability boundary. This does not simulate power loss or cache loss.
    fail_if_injected(CommitStage::AfterChecksum, poisoned, hook)?;
    if let Err(error) = file.sync_all() {
        *poisoned = true;
        return Err(error.into());
    }
    fail_if_injected(CommitStage::AfterSync, poisoned, hook)?;
    fail_if_injected(CommitStage::BeforeParentSync, poisoned, hook)?;
    if let Err(error) = sync_parent(path) {
        // The record body/checksum may already be durable. Do not advance in-memory
        // offsets or accept another page until reopening replays the authoritative WAL.
        *poisoned = true;
        return Err(error);
    }
    *valid_len = new_len;
    Ok(())
}

pub fn encode_archive_range_page(
    page: &ArchiveSyncServedPage,
    limits: ArchiveSyncLimits,
) -> Result<Vec<u8>, ArchiveRangeStoreError> {
    let mut out = Vec::new();
    out.extend_from_slice(WAL_RESPONSE_MAGIC);
    out.extend_from_slice(&page.snapshot_commitment);
    out.extend_from_slice(&page.archive_total_items.to_be_bytes());
    out.extend_from_slice(&page.archive_total_bytes.to_be_bytes());
    out.extend_from_slice(
        &u64::try_from(page.plan.start_index)
            .map_err(|_| ArchiveRangeStoreError::InvalidFrame("start index overflow"))?
            .to_be_bytes(),
    );
    out.extend_from_slice(
        &u64::try_from(page.plan.end_index)
            .map_err(|_| ArchiveRangeStoreError::InvalidFrame("end index overflow"))?
            .to_be_bytes(),
    );
    out.extend_from_slice(&page.plan.page_number.to_be_bytes());
    out.extend_from_slice(&page.plan.page_bytes.to_be_bytes());
    out.extend_from_slice(&page.plan.total_items_after_page.to_be_bytes());
    out.extend_from_slice(&page.plan.total_bytes_after_page.to_be_bytes());
    out.push(u8::from(page.plan.complete));
    match &page.plan.next_cursor {
        Some(cursor) => {
            out.push(1);
            out.extend_from_slice(cursor);
        }
        None => out.push(0),
    }
    let count = u32::try_from(page.entries.len())
        .map_err(|_| ArchiveRangeStoreError::InvalidFrame("entry count overflow"))?;
    if page.entries.len() > limits.max_page_items as usize
        || page.entries.len() > MAX_CANDIDATE_PAGE_ITEMS as usize
    {
        return Err(ArchiveRangeStoreError::FrameTooLarge(page.entries.len()));
    }
    out.extend_from_slice(&count.to_be_bytes());
    for entry in &page.entries {
        if entry.encoded.is_empty()
            || entry.encoded.len() as u64 != entry.metadata.encoded_len
            || entry.encoded.len() as u64 > limits.max_envelope_bytes
        {
            return Err(ArchiveRangeStoreError::InvalidFrame(
                "entry payload length invalid",
            ));
        }
        out.extend_from_slice(&entry.metadata.height.to_be_bytes());
        out.extend_from_slice(&entry.metadata.digest);
        out.extend_from_slice(&entry.metadata.encoded_len.to_be_bytes());
        out.extend_from_slice(&entry.metadata.payload_sha256);
        let len = u32::try_from(entry.encoded.len())
            .map_err(|_| ArchiveRangeStoreError::InvalidFrame("payload length overflow"))?;
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(&entry.encoded);
        if out.len() > MAX_STORED_ARCHIVE_PAGE_BYTES {
            return Err(ArchiveRangeStoreError::FrameTooLarge(out.len()));
        }
    }
    Ok(out)
}

pub fn decode_archive_range_page(
    body: &[u8],
    limits: ArchiveSyncLimits,
) -> Result<ArchiveSyncServedPage, ArchiveRangeStoreError> {
    if body.len() > MAX_STORED_ARCHIVE_PAGE_BYTES {
        return Err(ArchiveRangeStoreError::FrameTooLarge(body.len()));
    }
    let mut d = Decoder::new(body);
    if d.take(4)? != WAL_RESPONSE_MAGIC {
        return Err(ArchiveRangeStoreError::InvalidFrame("page magic mismatch"));
    }
    let snapshot_commitment = d.array32()?;
    let archive_total_items = d.u64()?;
    let archive_total_bytes = d.u64()?;
    let start_index = usize::try_from(d.u64()?)
        .map_err(|_| ArchiveRangeStoreError::InvalidFrame("start index overflow"))?;
    let end_index = usize::try_from(d.u64()?)
        .map_err(|_| ArchiveRangeStoreError::InvalidFrame("end index overflow"))?;
    let page_number = d.u32()?;
    let page_bytes = d.u64()?;
    let total_items_after_page = d.u64()?;
    let total_bytes_after_page = d.u64()?;
    let complete = match d.u8()? {
        0 => false,
        1 => true,
        _ => {
            return Err(ArchiveRangeStoreError::InvalidFrame(
                "invalid complete flag",
            ))
        }
    };
    let next_cursor = match d.u8()? {
        0 => None,
        1 => Some(d.take(ARCHIVE_SYNC_CURSOR_BYTES)?.try_into().unwrap()),
        _ => return Err(ArchiveRangeStoreError::InvalidFrame("invalid cursor flag")),
    };
    let count = d.u32()? as usize;
    if count > limits.max_page_items as usize
        || count > MAX_CANDIDATE_PAGE_ITEMS as usize
        || end_index < start_index
        || end_index - start_index != count
    {
        return Err(ArchiveRangeStoreError::InvalidFrame("range count invalid"));
    }
    let mut entries = Vec::with_capacity(count);
    for _ in 0..count {
        let height = d.u64()?;
        let digest = d.array32()?;
        let encoded_len = d.u64()?;
        let payload_sha256 = d.array32()?;
        let actual_len = d.u32()? as usize;
        if actual_len == 0
            || actual_len as u64 != encoded_len
            || encoded_len > limits.max_envelope_bytes
        {
            return Err(ArchiveRangeStoreError::InvalidFrame(
                "payload length invalid",
            ));
        }
        let encoded = d.take(actual_len)?.to_vec();
        entries.push(ArchiveSyncServedEntry {
            metadata: ArchiveEntryMeta {
                height,
                digest,
                encoded_len,
                payload_sha256,
            },
            encoded,
        });
    }
    if d.offset != body.len() {
        return Err(ArchiveRangeStoreError::InvalidFrame("trailing page bytes"));
    }
    Ok(ArchiveSyncServedPage {
        plan: ArchiveSyncPage {
            start_index,
            end_index,
            page_number,
            page_bytes,
            total_items_after_page,
            total_bytes_after_page,
            complete,
            next_cursor,
        },
        archive_total_items,
        archive_total_bytes,
        snapshot_commitment,
        entries,
    })
}

struct Decoder<'a> {
    bytes: &'a [u8],
    offset: usize,
}
impl<'a> Decoder<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }
    fn take(&mut self, len: usize) -> Result<&'a [u8], ArchiveRangeStoreError> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or(ArchiveRangeStoreError::InvalidFrame("offset overflow"))?;
        let part = self
            .bytes
            .get(self.offset..end)
            .ok_or(ArchiveRangeStoreError::InvalidFrame("truncated page body"))?;
        self.offset = end;
        Ok(part)
    }
    fn u8(&mut self) -> Result<u8, ArchiveRangeStoreError> {
        Ok(self.take(1)?[0])
    }
    fn u32(&mut self) -> Result<u32, ArchiveRangeStoreError> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn u64(&mut self) -> Result<u64, ArchiveRangeStoreError> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into().unwrap()))
    }
    fn array32(&mut self) -> Result<[u8; 32], ArchiveRangeStoreError> {
        Ok(self.take(32)?.try_into().unwrap())
    }
}

fn record_checksum(prefix: &[u8; LENGTH_PREFIX_BYTES], body: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(WAL_DOMAIN);
    hash.update(prefix);
    hash.update(body);
    hash.finalize().into()
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (left, right) in a.iter().zip(b.iter()) {
        diff |= left ^ right;
    }
    diff == 0
}

fn parent_directory(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

fn sync_parent(path: &Path) -> Result<(), ArchiveRangeStoreError> {
    #[cfg(unix)]
    File::open(parent_directory(path))?.sync_all()?;
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::private_testnet_archive_range_server_candidate::{
        ArchiveRangeBudgetConfig, ArchiveRangeServerCandidate, ArchiveSyncPayload,
    };
    use crate::private_testnet_archive_sync_candidate::ArchiveSyncIndex;
    use sha2::Digest;
    use std::process::{Command, Stdio};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::thread;
    use std::time::{Duration, Instant};

    static NEXT_DIR: AtomicU64 = AtomicU64::new(1);
    const SESSION: [u8; 32] = [0x51; 32];
    const KEY: [u8; 32] = [0x61; 32];

    struct TestDir(PathBuf);
    impl TestDir {
        fn new() -> Self {
            let id = NEXT_DIR.fetch_add(1, Ordering::Relaxed);
            let path =
                std::env::temp_dir().join(format!("cpw_archive_wal_{}_{}", std::process::id(), id));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }
        fn file(&self) -> PathBuf {
            self.0.join("archive.wal")
        }
    }
    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn limits() -> ArchiveSyncLimits {
        ArchiveSyncLimits {
            max_page_items: 2,
            max_page_bytes: 8,
            max_envelope_bytes: 8,
            max_total_items: 5,
            max_total_bytes: 32,
            max_pages: 3,
        }
    }

    fn meta(height: u64, digest: u8, bytes: &[u8]) -> ArchiveEntryMeta {
        ArchiveEntryMeta {
            height,
            digest: [digest; 32],
            encoded_len: bytes.len() as u64,
            payload_sha256: Sha256::digest(bytes).into(),
        }
    }

    fn fixture() -> (ArchiveRangeServerCandidate, Vec<ArchiveSyncServedPage>) {
        let specs = vec![
            (3, 3, b"ccccc".to_vec()),
            (1, 1, b"aaaa".to_vec()),
            (5, 5, b"e".to_vec()),
            (2, 2, b"bbb".to_vec()),
            (4, 4, b"dd".to_vec()),
        ];
        let metadata = specs.iter().map(|(h, d, b)| meta(*h, *d, b)).collect();
        let index = ArchiveSyncIndex::new([0xC0; 32], [0xA1; 32], 77, metadata, limits()).unwrap();
        let payloads = specs
            .into_iter()
            .map(|(h, d, b)| ArchiveSyncPayload::new(meta(h, d, &b), b))
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let budget = ArchiveRangeBudgetConfig {
            max_sessions: 1,
            per_session_max_pages: 6,
            per_session_max_items: 10,
            per_session_max_bytes: 30,
            global_max_pages: 6,
            global_max_items: 10,
            global_max_bytes: 30,
        };
        let server = ArchiveRangeServerCandidate::new(index, payloads, limits(), budget).unwrap();
        server.register_authenticated_session(SESSION, KEY).unwrap();
        let first = (*server.serve_first_page(SESSION).unwrap()).clone();
        let cursor1 = first.plan.next_cursor.unwrap();
        let second = (*server.serve_next_page(SESSION, &cursor1).unwrap()).clone();
        let cursor2 = second.plan.next_cursor.unwrap();
        let third = (*server.serve_next_page(SESSION, &cursor2).unwrap()).clone();
        (server, vec![first, second, third])
    }

    fn open(
        path: &Path,
        server: &ArchiveRangeServerCandidate,
    ) -> Result<ArchiveRangeWalCandidate, ArchiveRangeStoreError> {
        ArchiveRangeWalCandidate::open(path, limits(), server.snapshot_commitment(), 5, 15)
    }

    #[test]
    fn rejected_writer_does_not_create_or_open_wal_before_lock() {
        let dir = TestDir::new();
        let path = dir.file();
        let (server, _) = fixture();
        let owner = crate::snapshot_store::SnapshotWriterLock::acquire(&path).unwrap();
        assert!(!path.exists());

        assert!(matches!(
            open(&path, &server),
            Err(ArchiveRangeStoreError::WriterLockUnavailable)
        ));
        assert!(!path.exists(), "lock rejection must precede WAL creation");

        drop(owner);
        let recovered = open(&path, &server).unwrap();
        assert!(path.exists());
        assert_eq!(recovered.receipt().end_index, 0);
    }

    #[test]
    fn hard_link_alias_cannot_open_same_wal_for_writing() {
        let dir = TestDir::new();
        let path = dir.file();
        let alias = path.with_file_name("archive-hardlink-alias.wal");
        let (server, pages) = fixture();
        fs::write(&path, b"").unwrap();
        fs::hard_link(&path, &alias).unwrap();

        let mut primary = open(&path, &server).unwrap();
        assert!(matches!(
            open(&alias, &server),
            Err(ArchiveRangeStoreError::WriterLockUnavailable)
        ));
        assert_eq!(primary.receipt().end_index, 0);
        assert_eq!(fs::metadata(&path).unwrap().len(), 0);

        primary.commit_page(&pages[0]).unwrap();
        let committed_len = fs::metadata(&path).unwrap().len();
        assert!(committed_len > 0);
        drop(primary);

        let recovered = open(&alias, &server).unwrap();
        assert_eq!(recovered.receipt().end_index, 2);
        assert_eq!(fs::metadata(&alias).unwrap().len(), committed_len);
    }

    #[test]
    fn generation_guard_rejects_old_page_after_reorg_before_persisting() {
        use crate::private_testnet_archive_generation_coordinator_candidate::{
            ArchiveGenerationCommitError, ArchiveGenerationCoordinatorCandidate,
            ArchiveGenerationStamp,
        };

        let dir = TestDir::new();
        let path = dir.file();
        let (server, pages) = fixture();
        let expected = ArchiveGenerationStamp::new(77, server.snapshot_commitment());
        let active = ArchiveGenerationStamp::new(78, [0x78; 32]);
        let coordinator = ArchiveGenerationCoordinatorCandidate::new(active);
        let mut store = open(&path, &server).unwrap();

        assert!(matches!(
            store.commit_page_for_generation(&pages[0], &coordinator, expected),
            Err(ArchiveGenerationCommitError::StaleGeneration {
                expected: stale,
                actual
            }) if stale == expected && actual == active
        ));
        assert_eq!(store.receipt().end_index, 0);
        assert_eq!(store.receipt().total_bytes_verified, 0);
        assert_eq!(fs::metadata(&path).unwrap().len(), 0);
    }

    #[test]
    fn generation_guard_commits_when_snapshot_stamp_is_current() {
        use crate::private_testnet_archive_generation_coordinator_candidate::{
            ArchiveGenerationCoordinatorCandidate, ArchiveGenerationStamp,
        };

        let dir = TestDir::new();
        let path = dir.file();
        let (server, pages) = fixture();
        let active = ArchiveGenerationStamp::new(77, server.snapshot_commitment());
        let coordinator = ArchiveGenerationCoordinatorCandidate::new(active);
        let mut store = open(&path, &server).unwrap();

        let receipt = store
            .commit_page_for_generation(&pages[0], &coordinator, active)
            .unwrap();
        assert_eq!(receipt.end_index, 2);
        assert_eq!(receipt.pages_verified, 1);
        assert!(fs::metadata(&path).unwrap().len() > 0);
        assert_eq!(coordinator.current(), Ok(active));
    }

    #[test]
    fn diagnostic_digest_matches_closed_wal_and_preserves_append_position() {
        let dir = TestDir::new();
        let path = dir.file();
        let (server, pages) = fixture();
        let first_digest;
        let second_digest;
        {
            let mut store = open(&path, &server).unwrap();
            assert_eq!(store.commit_page(&pages[0]).unwrap().end_index, 2);
            first_digest = store.diagnostic_sha256().unwrap();
            assert_eq!(store.receipt().end_index, 2);
            assert_eq!(store.commit_page(&pages[1]).unwrap().end_index, 4);
            second_digest = store.diagnostic_sha256().unwrap();
            assert_ne!(first_digest, second_digest);
        }
        let bytes = fs::read(&path).unwrap();
        let closed_digest: [u8; 32] = Sha256::digest(&bytes).into();
        assert_eq!(second_digest, closed_digest);
    }

    #[test]
    fn durable_pages_replay_after_restart_and_resume_from_verified_offset() {
        let dir = TestDir::new();
        let path = dir.file();
        let (server, pages) = fixture();
        {
            let mut store = open(&path, &server).unwrap();
            assert_eq!(store.commit_page(&pages[0]).unwrap().end_index, 2);
            assert_eq!(store.commit_page(&pages[1]).unwrap().end_index, 4);
        }
        let mut recovered = open(&path, &server).unwrap();
        let checkpoint = recovered.receipt();
        assert_eq!(
            (
                checkpoint.end_index,
                checkpoint.total_bytes_verified,
                checkpoint.pages_verified
            ),
            (4, 14, 2)
        );
        let final_receipt = recovered.commit_page(&pages[2]).unwrap();
        assert!(final_receipt.complete);
        assert_eq!(
            (
                final_receipt.total_items_verified,
                final_receipt.total_bytes_verified,
                final_receipt.pages_verified
            ),
            (5, 15, 3)
        );
        drop(recovered);
        let reopened_complete = open(&path, &server).unwrap();
        assert!(reopened_complete.receipt().complete);
        assert_eq!(reopened_complete.receipt().end_index, 5);
    }

    #[test]
    fn partial_record_tail_is_truncated_then_page_can_be_retried() {
        let dir = TestDir::new();
        let path = dir.file();
        let (server, pages) = fixture();
        let committed_len;
        {
            let mut store = open(&path, &server).unwrap();
            store.commit_page(&pages[0]).unwrap();
            committed_len = store.valid_len;
            let result = store.commit_page_with_hook(&pages[1], |stage| {
                if stage == CommitStage::AfterBody {
                    Err(ArchiveRangeStoreError::InjectedFault(stage.label()))
                } else {
                    Ok(())
                }
            });
            assert!(matches!(
                result,
                Err(ArchiveRangeStoreError::InjectedFault("after-body"))
            ));
            assert!(matches!(
                store.commit_page(&pages[1]),
                Err(ArchiveRangeStoreError::StoreNeedsRecovery)
            ));
        }
        let mut recovered = open(&path, &server).unwrap();
        assert_eq!(recovered.receipt().end_index, 2);
        assert_eq!(fs::metadata(&path).unwrap().len(), committed_len);
        recovered.commit_page(&pages[1]).unwrap();
        assert!(recovered.commit_page(&pages[2]).unwrap().complete);
    }

    #[test]
    fn after_sync_ambiguous_failure_is_recovered_as_a_committed_page() {
        let dir = TestDir::new();
        let path = dir.file();
        let (server, pages) = fixture();
        {
            let mut store = open(&path, &server).unwrap();
            store.commit_page(&pages[0]).unwrap();
            let result = store.commit_page_with_hook(&pages[1], |stage| {
                if stage == CommitStage::AfterSync {
                    Err(ArchiveRangeStoreError::InjectedFault(stage.label()))
                } else {
                    Ok(())
                }
            });
            assert!(matches!(
                result,
                Err(ArchiveRangeStoreError::InjectedFault("after-sync"))
            ));
        }
        let mut recovered = open(&path, &server).unwrap();
        assert_eq!(
            (
                recovered.receipt().end_index,
                recovered.receipt().total_bytes_verified
            ),
            (4, 14)
        );
        assert!(recovered.commit_page(&pages[2]).unwrap().complete);
    }

    #[test]
    fn parent_sync_stage_failure_poison_requires_reopen_and_replays_durable_page() {
        let dir = TestDir::new();
        let path = dir.file();
        let (server, pages) = fixture();
        {
            let mut store = open(&path, &server).unwrap();
            store.commit_page(&pages[0]).unwrap();
            let result = store.commit_page_with_hook(&pages[1], |stage| {
                if stage == CommitStage::BeforeParentSync {
                    Err(ArchiveRangeStoreError::InjectedFault(stage.label()))
                } else {
                    Ok(())
                }
            });
            assert!(matches!(
                result,
                Err(ArchiveRangeStoreError::InjectedFault("before-parent-sync"))
            ));
            assert!(matches!(
                store.commit_page(&pages[2]),
                Err(ArchiveRangeStoreError::StoreNeedsRecovery)
            ));
            // Receiver progress did not advance, even though the complete WAL record may exist.
            assert_eq!(store.receipt().end_index, 2);
        }

        let mut recovered = open(&path, &server).unwrap();
        assert_eq!(recovered.receipt().end_index, 4);
        assert_eq!(recovered.receipt().pages_verified, 2);
        assert!(recovered.commit_page(&pages[2]).unwrap().complete);
    }

    #[test]
    fn external_partial_tail_while_open_poisoned_store_recovers_without_double_append() {
        let dir = TestDir::new();
        let path = dir.file();
        let (server, pages) = fixture();
        let mut store = open(&path, &server).unwrap();
        store.commit_page(&pages[0]).unwrap();
        let committed_len = store.valid_len;

        OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(&[0, 1])
            .unwrap();

        assert!(matches!(
            store.commit_page(&pages[1]),
            Err(ArchiveRangeStoreError::StoreNeedsRecovery)
        ));
        assert_eq!(store.receipt().end_index, 2);
        drop(store);

        let mut recovered = open(&path, &server).unwrap();
        assert_eq!(recovered.receipt().end_index, 2);
        assert_eq!(fs::metadata(&path).unwrap().len(), committed_len);
        assert!(recovered.commit_page(&pages[1]).unwrap().end_index == 4);
        assert!(recovered.commit_page(&pages[2]).unwrap().complete);
    }

    #[test]
    fn incomplete_length_prefix_tail_is_removed_without_losing_prior_records() {
        let dir = TestDir::new();
        let path = dir.file();
        let (server, pages) = fixture();
        let valid_len;
        {
            let mut store = open(&path, &server).unwrap();
            store.commit_page(&pages[0]).unwrap();
            valid_len = store.valid_len;
        }
        OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(&[0, 1])
            .unwrap();
        let recovered = open(&path, &server).unwrap();
        assert_eq!(recovered.receipt().end_index, 2);
        assert_eq!(fs::metadata(&path).unwrap().len(), valid_len);
    }

    #[test]
    fn complete_record_checksum_corruption_fails_closed_not_truncate() {
        let dir = TestDir::new();
        let path = dir.file();
        let (server, pages) = fixture();
        {
            let mut store = open(&path, &server).unwrap();
            store.commit_page(&pages[0]).unwrap();
            store.commit_page(&pages[1]).unwrap();
        }
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        file.seek(SeekFrom::Start((LENGTH_PREFIX_BYTES + 7) as u64))
            .unwrap();
        let mut byte = [0u8; 1];
        file.read_exact(&mut byte).unwrap();
        byte[0] ^= 0x80;
        file.seek(SeekFrom::Start((LENGTH_PREFIX_BYTES + 7) as u64))
            .unwrap();
        file.write_all(&byte).unwrap();
        file.sync_all().unwrap();
        assert!(matches!(
            open(&path, &server),
            Err(ArchiveRangeStoreError::ChecksumMismatch { offset: 0 })
        ));
    }

    #[test]
    fn oversize_record_length_is_rejected_before_page_allocation() {
        let dir = TestDir::new();
        let path = dir.file();
        let oversized = (MAX_STORED_ARCHIVE_PAGE_BYTES as u32) + 1;
        fs::write(&path, oversized.to_be_bytes()).unwrap();
        let (server, _) = fixture();
        assert!(
            matches!(open(&path, &server), Err(ArchiveRangeStoreError::FrameTooLarge(n)) if n == oversized as usize)
        );
    }

    #[test]
    fn wrong_snapshot_or_out_of_order_page_is_never_persisted() {
        let dir = TestDir::new();
        let path = dir.file();
        let (server, pages) = fixture();
        let mut store = open(&path, &server).unwrap();
        let result = store.commit_page(&pages[1]);
        assert!(matches!(
            result,
            Err(ArchiveRangeStoreError::InvalidPage(_))
        ));
        assert_eq!(fs::metadata(&path).unwrap().len(), 0);
        store.commit_page(&pages[0]).unwrap();
        drop(store);
        assert!(matches!(
            ArchiveRangeWalCandidate::open(&path, limits(), [0x99; 32], 5, 15),
            Err(ArchiveRangeStoreError::InvalidPage(_))
        ));
    }

    #[test]
    fn prewrite_fault_poison_requires_reopen_but_keeps_prior_page() {
        let dir = TestDir::new();
        let path = dir.file();
        let (server, pages) = fixture();
        {
            let mut store = open(&path, &server).unwrap();
            store.commit_page(&pages[0]).unwrap();
            let result = store.commit_page_with_hook(&pages[1], |stage| {
                if stage == CommitStage::BeforeWrite {
                    Err(ArchiveRangeStoreError::InjectedFault(stage.label()))
                } else {
                    Ok(())
                }
            });
            assert!(matches!(
                result,
                Err(ArchiveRangeStoreError::InjectedFault("before-write"))
            ));
        }
        let recovered = open(&path, &server).unwrap();
        assert_eq!(recovered.receipt().end_index, 2);
    }
    const CRASH_PATH_ENV: &str = "CPW_ARCHIVE_WAL_CRASH_PATH";
    const CRASH_STAGE_ENV: &str = "CPW_ARCHIVE_WAL_CRASH_STAGE";
    const CRASH_MARKER_ENV: &str = "CPW_ARCHIVE_WAL_CRASH_MARKER";

    #[test]
    fn wal_crash_child_probe() {
        let (Ok(path), Ok(stage_name), Ok(marker)) = (
            std::env::var(CRASH_PATH_ENV),
            std::env::var(CRASH_STAGE_ENV),
            std::env::var(CRASH_MARKER_ENV),
        ) else {
            return;
        };
        let (server, pages) = fixture();
        if stage_name == "probe-lock" {
            match open(Path::new(&path), &server) {
                Err(ArchiveRangeStoreError::WriterLockUnavailable) => {
                    fs::write(&marker, b"locked").expect("write lock-probe marker");
                    return;
                }
                Err(error) => panic!("lock probe returned an unexpected error: {error}"),
                Ok(_) => panic!("second process unexpectedly acquired the WAL writer lock"),
            }
        }
        let mut store = open(Path::new(&path), &server).expect("child opens the committed prefix");
        let target = match stage_name.as_str() {
            "after-prefix" => CommitStage::AfterPrefix,
            "after-body" => CommitStage::AfterBody,
            "after-checksum" => CommitStage::AfterChecksum,
            _ => panic!("unsupported crash stage: {stage_name}"),
        };
        let result = store.commit_page_with_hook(&pages[1], |stage| {
            if stage == target {
                fs::write(&marker, stage.label().as_bytes()).expect("write ready marker");
                loop {
                    thread::sleep(Duration::from_secs(1));
                }
            }
            Ok(())
        });
        panic!("crash child unexpectedly returned: {result:?}");
    }

    fn kill_writer_at_stage(stage: &str) {
        let dir = TestDir::new();
        let path = dir.file();
        let marker = dir.0.join(format!("{stage}.ready"));
        let (server, pages) = fixture();
        {
            let mut store = open(&path, &server).unwrap();
            store.commit_page(&pages[0]).unwrap();
        }
        let executable = std::env::current_exe().unwrap();
        let mut child = Command::new(executable)
            .arg("--exact")
            .arg("private_testnet_archive_range_store_candidate::tests::wal_crash_child_probe")
            .arg("--nocapture")
            .env(CRASH_PATH_ENV, &path)
            .env(CRASH_STAGE_ENV, stage)
            .env(CRASH_MARKER_ENV, &marker)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn dedicated writer process");
        let until = Instant::now() + Duration::from_secs(8);
        while Instant::now() < until && !marker.exists() {
            if let Some(status) = child.try_wait().unwrap() {
                panic!("crash-window child exited before marker: {status:?}");
            }
            thread::sleep(Duration::from_millis(10));
        }
        assert!(marker.exists(), "writer did not reach crash stage {stage}");
        child
            .kill()
            .expect("terminate writer at injected crash window");
        let _ = child.wait().expect("reap terminated writer");

        // Reopening must either truncate the partial tail or replay only fully verified records.
        let mut recovered = open(&path, &server).unwrap();
        assert_eq!(recovered.receipt().end_index, 2);
        assert_eq!(recovered.receipt().pages_verified, 1);
        assert!(fs::metadata(&path).unwrap().len() > 0);
        recovered.commit_page(&pages[1]).unwrap();
        let final_receipt = recovered.commit_page(&pages[2]).unwrap();
        assert!(final_receipt.complete);
        assert_eq!(
            (
                final_receipt.total_items_verified,
                final_receipt.total_bytes_verified
            ),
            (5, 15)
        );
    }

    #[test]
    fn actual_child_process_kill_after_length_prefix_recovers_previous_page() {
        kill_writer_at_stage("after-prefix");
    }

    #[test]
    fn actual_child_process_kill_after_page_body_recovers_previous_page() {
        kill_writer_at_stage("after-body");
    }

    #[test]
    fn second_process_cannot_open_existing_wal_for_writing() {
        let dir = TestDir::new();
        let path = dir.file();
        let marker = dir.0.join("lock-probe.ready");
        let (server, pages) = fixture();
        let mut store = open(&path, &server).unwrap();
        store.commit_page(&pages[0]).unwrap();

        let status = Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg("private_testnet_archive_range_store_candidate::tests::wal_crash_child_probe")
            .arg("--nocapture")
            .env(CRASH_PATH_ENV, &path)
            .env(CRASH_STAGE_ENV, "probe-lock")
            .env(CRASH_MARKER_ENV, &marker)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .expect("run second writer process");
        assert!(status.success(), "child lock probe failed: {status}");
        assert_eq!(fs::read(&marker).unwrap(), b"locked");

        // The lock probe must not disturb the active writer's ability to continue safely.
        let receipt = store.commit_page(&pages[1]).unwrap();
        assert!(!receipt.complete);
    }
}
