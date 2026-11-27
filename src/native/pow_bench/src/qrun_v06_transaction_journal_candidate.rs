//! CP-0586 bounded durable snapshot journal for pending QFP6 NativeTransfer transactions.
//!
//! This journal persists signed pending transactions, not canonical blocks or finality. A restored
//! entry must be revalidated against the recovered QAP1 canonical state before service resumes.
//! Snapshots are immutable generations, installed atomically and pruned only after a newer
//! generation has been durably installed. A local checksum is integrity evidence, not an external
//! anti-rollback anchor.

use crate::{
    qrun_v06_canonical_execution_candidate::QRunV06CanonicalExecutionState,
    qrun_v06_transaction_mempool_candidate::{
        QRunV06MempoolLimits, QRunV06NativeTransactionMempool,
    },
    state_machine::{
        decode_transaction_with_signature_limit, encode_transaction_with_signature_limit,
        transaction_id_with_signature_limit, AccountId, Transaction, TransactionAuthenticator,
        QRUN_V06_MAX_NATIVE_TX_SIGNATURE_BYTES,
    },
    store_writer_lock::StoreWriterLock,
};
use sha2::{Digest, Sha256};
use std::{
    collections::HashSet,
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

const MAGIC: &[u8; 4] = b"Q6MJ";
const VERSION: u16 = 1;
const HEADER_BYTES: usize = 24;
const CHECKSUM_BYTES: usize = 32;
const CHECKSUM_DOMAIN: &[u8] = b"QUANTUMZXB-QFP6-PENDING-TRANSACTION-JOURNAL-V1\0";
const LOCK_FILE: &str = "qfp6-pending-transactions.lock";
const SNAPSHOT_PREFIX: &str = "pending-";
const SNAPSHOT_SUFFIX: &str = ".q6mj";
const TEMP_PREFIX: &str = ".q6mj-";
const TEMP_SUFFIX: &str = ".tmp";
const MAX_RETAINED_SNAPSHOTS: usize = 16;
static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QRunV06TransactionJournalError {
    InvalidPath,
    SymlinkOrSpecialFile,
    InvalidLimits,
    Incomplete,
    BadMagic,
    UnsupportedVersion(u16),
    InvalidHeader,
    InvalidGeneration,
    LengthMismatch,
    Oversize,
    ChecksumMismatch,
    DuplicateTransaction,
    TransactionCodec(String),
    WriterLockHeld,
    GenerationOverflow,
    UnexpectedEntry,
    StartupNotReconciled,
    AlreadyRestored,
    Io(String),
}
impl std::fmt::Display for QRunV06TransactionJournalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "QFP6 transaction journal error: {self:?}")
    }
}
impl std::error::Error for QRunV06TransactionJournalError {}
impl From<io::Error> for QRunV06TransactionJournalError {
    fn from(value: io::Error) -> Self {
        Self::Io(value.to_string())
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct QRunV06TransactionJournalRestoreSummary {
    pub restored: usize,
    pub dropped_invalid_or_stale: usize,
}

pub struct QRunV06TransactionJournal {
    directory: PathBuf,
    limits: QRunV06MempoolLimits,
    generation: u64,
    pending_on_open: Vec<Transaction>,
    startup_reconciled: bool,
    _writer_lock: StoreWriterLock,
}

impl QRunV06TransactionJournal {
    /// Open the journal directory under an OS-backed exclusive writer lock. The directory is
    /// created when absent, but a symlink or non-directory path is rejected.
    /// Returns the latest complete snapshot; callers must restore/revalidate it before serving.
    pub fn open(
        directory: impl AsRef<Path>,
        limits: QRunV06MempoolLimits,
    ) -> Result<Self, QRunV06TransactionJournalError> {
        QRunV06NativeTransactionMempool::new(limits)
            .map_err(|_| QRunV06TransactionJournalError::InvalidLimits)?;
        let directory = directory.as_ref().to_path_buf();
        if !directory.is_absolute() {
            return Err(QRunV06TransactionJournalError::InvalidPath);
        }
        fs::create_dir_all(&directory)?;
        let metadata = fs::symlink_metadata(&directory)?;
        if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
            return Err(QRunV06TransactionJournalError::SymlinkOrSpecialFile);
        }
        let lock_path = directory.join(LOCK_FILE);
        reject_symlink_or_special_if_present(&lock_path)?;
        let writer_lock = StoreWriterLock::acquire(&directory, LOCK_FILE).map_err(|error| {
            if error.kind() == io::ErrorKind::WouldBlock {
                QRunV06TransactionJournalError::WriterLockHeld
            } else {
                error.into()
            }
        })?;

        let (generation, transactions) = load_latest_snapshot(&directory, limits)?;
        cleanup_stale_temporary_files(&directory)?;
        Ok(Self {
            directory,
            limits,
            generation,
            pending_on_open: transactions,
            startup_reconciled: false,
            _writer_lock: writer_lock,
        })
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }
    pub fn limits(&self) -> QRunV06MempoolLimits {
        self.limits
    }
    pub fn directory(&self) -> &Path {
        &self.directory
    }

    /// Durably install a new immutable snapshot of the current bounded mempool.
    pub fn persist_pool(
        &mut self,
        pool: &QRunV06NativeTransactionMempool,
    ) -> Result<u64, QRunV06TransactionJournalError> {
        if !self.startup_reconciled {
            return Err(QRunV06TransactionJournalError::StartupNotReconciled);
        }
        self.persist_snapshot(pool)
    }

    fn persist_snapshot(
        &mut self,
        pool: &QRunV06NativeTransactionMempool,
    ) -> Result<u64, QRunV06TransactionJournalError> {
        if pool.limits() != self.limits {
            return Err(QRunV06TransactionJournalError::InvalidLimits);
        }
        let generation = self
            .generation
            .checked_add(1)
            .ok_or(QRunV06TransactionJournalError::GenerationOverflow)?;
        let bytes = encode_snapshot(generation, &pool.ordered_transactions(), self.limits)?;
        let path = snapshot_path(&self.directory, generation);
        write_new_atomic(&path, &bytes)?;
        self.generation = generation;
        prune_old_snapshots(&self.directory, generation)?;
        Ok(generation)
    }

    /// Rebuild a fresh mempool against the recovered canonical state. Transactions which are
    /// already confirmed, expired, conflicting or non-executable are dropped. The pruned result
    /// is persisted before the caller should accept new traffic.
    pub fn restore_into_pool<A: TransactionAuthenticator>(
        &mut self,
        pool: &mut QRunV06NativeTransactionMempool,
        state: &QRunV06CanonicalExecutionState,
        authenticator: &A,
        producer: AccountId,
        candidate_timestamp: u64,
    ) -> Result<QRunV06TransactionJournalRestoreSummary, QRunV06TransactionJournalError> {
        if self.startup_reconciled {
            return Err(QRunV06TransactionJournalError::AlreadyRestored);
        }
        if pool.limits() != self.limits || candidate_timestamp <= state.last_timestamp() {
            return Err(QRunV06TransactionJournalError::InvalidLimits);
        }
        let mut transactions = std::mem::take(&mut self.pending_on_open);
        transactions.sort_by_key(|transaction| {
            let id = transaction_id_with_signature_limit(
                transaction,
                QRUN_V06_MAX_NATIVE_TX_SIGNATURE_BYTES,
            )
            .unwrap_or([0; 32]);
            (transaction.sender, transaction.nonce, id)
        });
        let mut summary = QRunV06TransactionJournalRestoreSummary::default();
        for transaction in transactions {
            if pool
                .submit(
                    transaction,
                    state,
                    authenticator,
                    producer,
                    candidate_timestamp,
                )
                .is_ok()
            {
                summary.restored += 1;
            } else {
                summary.dropped_invalid_or_stale += 1;
            }
        }
        self.persist_snapshot(pool)?;
        self.startup_reconciled = true;
        Ok(summary)
    }
}

fn maximum_snapshot_bytes(
    limits: QRunV06MempoolLimits,
) -> Result<usize, QRunV06TransactionJournalError> {
    limits
        .max_bytes
        .checked_add(
            limits
                .max_transactions
                .checked_mul(4)
                .ok_or(QRunV06TransactionJournalError::Oversize)?,
        )
        .and_then(|value| value.checked_add(HEADER_BYTES + CHECKSUM_BYTES))
        .ok_or(QRunV06TransactionJournalError::Oversize)
}

fn snapshot_path(directory: &Path, generation: u64) -> PathBuf {
    directory.join(format!(
        "{SNAPSHOT_PREFIX}{generation:020}{SNAPSHOT_SUFFIX}"
    ))
}

fn parse_snapshot_generation(name: &str) -> Option<u64> {
    let digits = name
        .strip_prefix(SNAPSHOT_PREFIX)?
        .strip_suffix(SNAPSHOT_SUFFIX)?;
    if digits.len() != 20 || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    digits.parse().ok()
}

fn encode_snapshot(
    generation: u64,
    transactions: &[Transaction],
    limits: QRunV06MempoolLimits,
) -> Result<Vec<u8>, QRunV06TransactionJournalError> {
    if generation == 0 || transactions.len() > limits.max_transactions {
        return Err(QRunV06TransactionJournalError::InvalidGeneration);
    }
    let mut body = Vec::new();
    let mut ids = HashSet::with_capacity(transactions.len());
    let mut total_transaction_bytes = 0usize;
    for transaction in transactions {
        let encoded = encode_transaction_with_signature_limit(
            transaction,
            QRUN_V06_MAX_NATIVE_TX_SIGNATURE_BYTES,
        )
        .map_err(|error| QRunV06TransactionJournalError::TransactionCodec(format!("{error:?}")))?;
        total_transaction_bytes = total_transaction_bytes
            .checked_add(encoded.len())
            .ok_or(QRunV06TransactionJournalError::Oversize)?;
        if encoded.is_empty() || total_transaction_bytes > limits.max_bytes {
            return Err(QRunV06TransactionJournalError::Oversize);
        }
        let id = transaction_id_with_signature_limit(
            transaction,
            QRUN_V06_MAX_NATIVE_TX_SIGNATURE_BYTES,
        )
        .map_err(|error| QRunV06TransactionJournalError::TransactionCodec(format!("{error:?}")))?;
        if !ids.insert(id) {
            return Err(QRunV06TransactionJournalError::DuplicateTransaction);
        }
        let length =
            u32::try_from(encoded.len()).map_err(|_| QRunV06TransactionJournalError::Oversize)?;
        body.extend_from_slice(&length.to_be_bytes());
        body.extend_from_slice(&encoded);
    }
    let count =
        u32::try_from(transactions.len()).map_err(|_| QRunV06TransactionJournalError::Oversize)?;
    let body_len =
        u32::try_from(body.len()).map_err(|_| QRunV06TransactionJournalError::Oversize)?;
    let mut bytes = Vec::with_capacity(HEADER_BYTES + body.len() + CHECKSUM_BYTES);
    bytes.extend_from_slice(MAGIC);
    bytes.extend_from_slice(&VERSION.to_be_bytes());
    bytes.extend_from_slice(&0u16.to_be_bytes());
    bytes.extend_from_slice(&generation.to_be_bytes());
    bytes.extend_from_slice(&count.to_be_bytes());
    bytes.extend_from_slice(&body_len.to_be_bytes());
    bytes.extend_from_slice(&body);
    let mut hash = Sha256::new();
    hash.update(CHECKSUM_DOMAIN);
    hash.update(&bytes);
    bytes.extend_from_slice(&hash.finalize());
    if bytes.len() > maximum_snapshot_bytes(limits)? {
        return Err(QRunV06TransactionJournalError::Oversize);
    }
    Ok(bytes)
}

fn decode_snapshot(
    bytes: &[u8],
    limits: QRunV06MempoolLimits,
) -> Result<(u64, Vec<Transaction>), QRunV06TransactionJournalError> {
    if bytes.len() < HEADER_BYTES + CHECKSUM_BYTES {
        return Err(QRunV06TransactionJournalError::Incomplete);
    }
    if bytes.len() > maximum_snapshot_bytes(limits)? {
        return Err(QRunV06TransactionJournalError::Oversize);
    }
    if &bytes[..4] != MAGIC {
        return Err(QRunV06TransactionJournalError::BadMagic);
    }
    let version = u16::from_be_bytes([bytes[4], bytes[5]]);
    if version != VERSION {
        return Err(QRunV06TransactionJournalError::UnsupportedVersion(version));
    }
    if bytes[6..8] != [0, 0] {
        return Err(QRunV06TransactionJournalError::InvalidHeader);
    }
    let generation = u64::from_be_bytes(bytes[8..16].try_into().unwrap());
    if generation == 0 {
        return Err(QRunV06TransactionJournalError::InvalidGeneration);
    }
    let count = u32::from_be_bytes(bytes[16..20].try_into().unwrap()) as usize;
    let body_len = u32::from_be_bytes(bytes[20..24].try_into().unwrap()) as usize;
    if count > limits.max_transactions {
        return Err(QRunV06TransactionJournalError::Oversize);
    }
    let checksum_start = HEADER_BYTES
        .checked_add(body_len)
        .ok_or(QRunV06TransactionJournalError::Oversize)?;
    let expected_len = checksum_start
        .checked_add(CHECKSUM_BYTES)
        .ok_or(QRunV06TransactionJournalError::Oversize)?;
    if bytes.len() != expected_len {
        return Err(QRunV06TransactionJournalError::LengthMismatch);
    }
    let mut hash = Sha256::new();
    hash.update(CHECKSUM_DOMAIN);
    hash.update(&bytes[..checksum_start]);
    if hash.finalize().as_slice() != &bytes[checksum_start..] {
        return Err(QRunV06TransactionJournalError::ChecksumMismatch);
    }

    let mut transactions = Vec::with_capacity(count);
    let mut ids = HashSet::with_capacity(count);
    let mut offset = HEADER_BYTES;
    let mut total_transaction_bytes = 0usize;
    for _ in 0..count {
        if offset + 4 > checksum_start {
            return Err(QRunV06TransactionJournalError::Incomplete);
        }
        let length = u32::from_be_bytes(bytes[offset..offset + 4].try_into().unwrap()) as usize;
        offset += 4;
        if length == 0
            || offset
                .checked_add(length)
                .filter(|end| *end <= checksum_start)
                .is_none()
        {
            return Err(QRunV06TransactionJournalError::LengthMismatch);
        }
        total_transaction_bytes = total_transaction_bytes
            .checked_add(length)
            .ok_or(QRunV06TransactionJournalError::Oversize)?;
        if total_transaction_bytes > limits.max_bytes {
            return Err(QRunV06TransactionJournalError::Oversize);
        }
        let transaction = decode_transaction_with_signature_limit(
            &bytes[offset..offset + length],
            QRUN_V06_MAX_NATIVE_TX_SIGNATURE_BYTES,
        )
        .map_err(|error| QRunV06TransactionJournalError::TransactionCodec(format!("{error:?}")))?;
        offset += length;
        let id = transaction_id_with_signature_limit(
            &transaction,
            QRUN_V06_MAX_NATIVE_TX_SIGNATURE_BYTES,
        )
        .map_err(|error| QRunV06TransactionJournalError::TransactionCodec(format!("{error:?}")))?;
        if !ids.insert(id) {
            return Err(QRunV06TransactionJournalError::DuplicateTransaction);
        }
        transactions.push(transaction);
    }
    if offset != checksum_start {
        return Err(QRunV06TransactionJournalError::LengthMismatch);
    }
    Ok((generation, transactions))
}

fn reject_symlink_or_special_if_present(path: &Path) -> Result<(), QRunV06TransactionJournalError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.file_type().is_file() => {
            Err(QRunV06TransactionJournalError::SymlinkOrSpecialFile)
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn load_snapshot_file(
    path: &Path,
    limits: QRunV06MempoolLimits,
) -> Result<(u64, Vec<Transaction>), QRunV06TransactionJournalError> {
    reject_symlink_or_special_if_present(path)?;
    let max = maximum_snapshot_bytes(limits)?;
    let file = File::open(path)?;
    let mut bytes = Vec::new();
    file.take(max as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > max {
        return Err(QRunV06TransactionJournalError::Oversize);
    }
    decode_snapshot(&bytes, limits)
}

fn load_latest_snapshot(
    directory: &Path,
    limits: QRunV06MempoolLimits,
) -> Result<(u64, Vec<Transaction>), QRunV06TransactionJournalError> {
    let mut snapshots = Vec::new();
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name == LOCK_FILE || name.starts_with(TEMP_PREFIX) {
            continue;
        }
        let generation = parse_snapshot_generation(&name)
            .ok_or(QRunV06TransactionJournalError::UnexpectedEntry)?;
        let metadata = fs::symlink_metadata(entry.path())?;
        if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
            return Err(QRunV06TransactionJournalError::SymlinkOrSpecialFile);
        }
        snapshots.push((generation, entry.path()));
    }
    snapshots.sort_by_key(|entry| entry.0);
    if let Some((generation, path)) = snapshots.last() {
        let (encoded_generation, transactions) = load_snapshot_file(path, limits)?;
        if encoded_generation != *generation {
            return Err(QRunV06TransactionJournalError::InvalidGeneration);
        }
        Ok((*generation, transactions))
    } else {
        Ok((0, Vec::new()))
    }
}

fn write_new_atomic(path: &Path, bytes: &[u8]) -> Result<(), QRunV06TransactionJournalError> {
    let directory = path
        .parent()
        .ok_or(QRunV06TransactionJournalError::InvalidPath)?;
    let file_name = path
        .file_name()
        .ok_or(QRunV06TransactionJournalError::InvalidPath)?;
    let sequence = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
    let mut temp_name = std::ffi::OsString::from(TEMP_PREFIX);
    temp_name.push(format!("{}.{}.", std::process::id(), sequence));
    temp_name.push(file_name);
    temp_name.push(TEMP_SUFFIX);
    let temp_path = directory.join(temp_name);
    let mut cleanup = TempCleanup::new(temp_path.clone());
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temp_path)?;
    file.write_all(bytes)?;
    file.flush()?;
    file.sync_all()?;
    drop(file);
    atomic_install_new(&temp_path, path)?;
    cleanup.disarm();
    Ok(())
}

struct TempCleanup {
    path: PathBuf,
    armed: bool,
}
impl TempCleanup {
    fn new(path: PathBuf) -> Self {
        Self { path, armed: true }
    }
    fn disarm(&mut self) {
        self.armed = false;
    }
}
impl Drop for TempCleanup {
    fn drop(&mut self) {
        if self.armed {
            let _ = fs::remove_file(&self.path);
        }
    }
}

#[cfg(windows)]
fn atomic_install_new(
    source: &Path,
    destination: &Path,
) -> Result<(), QRunV06TransactionJournalError> {
    use std::os::windows::ffi::OsStrExt;
    const MOVEFILE_WRITE_THROUGH: u32 = 0x0000_0008;
    let source_wide: Vec<u16> = source.as_os_str().encode_wide().chain(Some(0)).collect();
    let destination_wide: Vec<u16> = destination
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect();
    #[link(name = "Kernel32")]
    extern "system" {
        fn MoveFileExW(existing: *const u16, new_name: *const u16, flags: u32) -> i32;
    }
    let success = unsafe {
        MoveFileExW(
            source_wide.as_ptr(),
            destination_wide.as_ptr(),
            MOVEFILE_WRITE_THROUGH,
        )
    };
    if success == 0 {
        return Err(io::Error::last_os_error().into());
    }
    Ok(())
}

#[cfg(unix)]
fn atomic_install_new(
    source: &Path,
    destination: &Path,
) -> Result<(), QRunV06TransactionJournalError> {
    fs::hard_link(source, destination)?;
    fs::remove_file(source)?;
    let parent = destination
        .parent()
        .ok_or(QRunV06TransactionJournalError::InvalidPath)?;
    File::open(parent)?.sync_all()?;
    Ok(())
}

#[cfg(not(any(windows, unix)))]
fn atomic_install_new(
    _source: &Path,
    _destination: &Path,
) -> Result<(), QRunV06TransactionJournalError> {
    Err(QRunV06TransactionJournalError::Io(
        "atomic no-replace install unsupported".into(),
    ))
}

fn prune_old_snapshots(
    directory: &Path,
    latest_generation: u64,
) -> Result<(), QRunV06TransactionJournalError> {
    let minimum = latest_generation.saturating_sub(MAX_RETAINED_SNAPSHOTS as u64 - 1);
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(generation) = parse_snapshot_generation(&name.to_string_lossy()) else {
            continue;
        };
        if generation < minimum {
            reject_symlink_or_special_if_present(&entry.path())?;
            fs::remove_file(entry.path())?;
        }
    }
    sync_directory(directory)?;
    Ok(())
}

fn cleanup_stale_temporary_files(directory: &Path) -> Result<(), QRunV06TransactionJournalError> {
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        if entry.file_name().to_string_lossy().starts_with(TEMP_PREFIX) {
            let metadata = fs::symlink_metadata(entry.path())?;
            if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
                return Err(QRunV06TransactionJournalError::SymlinkOrSpecialFile);
            }
            fs::remove_file(entry.path())?;
        }
    }
    sync_directory(directory)?;
    Ok(())
}

#[cfg(unix)]
fn sync_directory(directory: &Path) -> Result<(), QRunV06TransactionJournalError> {
    File::open(directory)?.sync_all()?;
    Ok(())
}

#[cfg(windows)]
fn sync_directory(_directory: &Path) -> Result<(), QRunV06TransactionJournalError> {
    // Windows directory handles cannot be opened with File::open; immutable snapshot installation
    // already uses MoveFileExW(MOVEFILE_WRITE_THROUGH) to request durable namespace updates.
    Ok(())
}

#[cfg(not(any(windows, unix)))]
fn sync_directory(_directory: &Path) -> Result<(), QRunV06TransactionJournalError> {
    Err(QRunV06TransactionJournalError::Io(
        "directory sync unsupported on this platform".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        consensus::{ConsensusParameters, PowAlgorithm, PowParameters, Uint256},
        qrun_v06_genesis_descriptor_candidate::QRunV06GenesisDescriptor,
        qrun_v06_hybrid_auth_candidate::{
            QRunV06HybridTransactionAuthenticator, QRunV06HybridTransactionSigner,
        },
        qrun_v06_tokenomics_candidate::{QRunV06MiningScheduleCandidate, QRunV06TokenomicsState},
        state_machine::Transaction,
        v4_fat1_mldsa65_candidate::LibcruxMlDsa65VerifierCandidate,
    };
    use std::{
        fs,
        time::{SystemTime, UNIX_EPOCH},
    };

    const NETWORK: [u8; 32] = [0x91; 32];
    const PROFILE: [u8; 32] = [0x92; 32];
    const PRODUCER: [u8; 32] = [0x93; 32];
    const RECIPIENT: [u8; 32] = [0x94; 32];

    fn params() -> ConsensusParameters {
        let mut value = ConsensusParameters::candidate_testnet().unwrap();
        value.protocol_version = 6;
        value.target_block_time_secs = 30;
        value.difficulty_window_blocks = 2;
        value.difficulty_min_ratio_divisor = 4;
        value.difficulty_max_ratio = 4;
        value.initial_target = Uint256::from_be_bytes([0x7F; 32]);
        value.pow_limit = Uint256::MAX;
        value.pow = PowParameters {
            algorithm: PowAlgorithm::Argon2id,
            memory_kib: 8,
            iterations: 1,
            lanes: 1,
            output_bytes: 32,
        };
        value.validate().unwrap();
        value
    }
    fn genesis(founder: [u8; 32]) -> QRunV06CanonicalExecutionState {
        let schedule = QRunV06MiningScheduleCandidate::cp0422_research_candidate();
        let economics = QRunV06TokenomicsState::genesis(NETWORK, founder, schedule).unwrap();
        let descriptor = QRunV06GenesisDescriptor::new(
            NETWORK,
            PROFILE,
            founder,
            1,
            crate::qrun_v06_checkpoint_candidate::qrun_v06_consensus_fingerprint(&params())
                .unwrap(),
            economics.policy_fingerprint(),
        )
        .unwrap();
        QRunV06CanonicalExecutionState::cp0528_genesis_candidate_with_descriptor(
            descriptor, schedule,
        )
        .unwrap()
    }
    fn signed_transaction(signer: &QRunV06HybridTransactionSigner) -> Transaction {
        let mut value = Transaction {
            network_id: NETWORK,
            sender: signer.account_id(),
            recipient: RECIPIENT,
            nonce: 1,
            amount: 10_000,
            fee: 10,
            expires_at: 10_000,
            signature: Vec::new(),
        };
        signer.sign_transaction(&mut value).unwrap();
        value
    }
    fn temp_dir() -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("q6mj-{}-{nonce}", std::process::id()));
        fs::create_dir_all(&path).unwrap();
        path
    }

    #[test]
    fn journal_restores_pending_transaction_and_prunes_after_canonical_commit() {
        let directory = temp_dir();
        let signer = QRunV06HybridTransactionSigner::from_seeds([0xA1; 32], [0xA2; 32]).unwrap();
        let transaction = signed_transaction(&signer);
        let authenticator =
            QRunV06HybridTransactionAuthenticator::new(LibcruxMlDsa65VerifierCandidate);
        let state = genesis(signer.account_id());
        let timestamp = state.last_timestamp() + 60;
        let limits = QRunV06MempoolLimits::default();
        let mut pool = QRunV06NativeTransactionMempool::new(limits).unwrap();
        pool.submit(
            transaction.clone(),
            &state,
            &authenticator,
            PRODUCER,
            timestamp,
        )
        .unwrap();

        {
            let mut journal = QRunV06TransactionJournal::open(&directory, limits).unwrap();
            let mut empty = QRunV06NativeTransactionMempool::new(limits).unwrap();
            let state = genesis(signer.account_id());
            let timestamp = state.last_timestamp() + 60;
            journal
                .restore_into_pool(&mut empty, &state, &authenticator, PRODUCER, timestamp)
                .unwrap();
            assert!(empty.is_empty());
            assert_eq!(journal.persist_pool(&pool).unwrap(), 2);
        }
        let mut journal = QRunV06TransactionJournal::open(&directory, limits).unwrap();
        let mut restored = QRunV06NativeTransactionMempool::new(limits).unwrap();
        let summary = journal
            .restore_into_pool(&mut restored, &state, &authenticator, PRODUCER, timestamp)
            .unwrap();
        assert_eq!(summary.restored, 1);
        assert_eq!(restored.len(), 1);
        let block = restored
            .build_block(&state, &authenticator, PRODUCER, timestamp)
            .unwrap();
        let mut committed = state.clone();
        committed.apply_block(&block, &authenticator).unwrap();
        drop(journal);

        let mut after_restart = QRunV06TransactionJournal::open(&directory, limits).unwrap();
        let mut empty = QRunV06NativeTransactionMempool::new(limits).unwrap();
        let recovered = after_restart
            .restore_into_pool(
                &mut empty,
                &committed,
                &authenticator,
                PRODUCER,
                committed.last_timestamp() + 60,
            )
            .unwrap();
        assert_eq!(recovered.restored, 0);
        assert_eq!(recovered.dropped_invalid_or_stale, 1);
        assert!(empty.is_empty());
        drop(after_restart);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn journal_detects_checksum_tampering_and_wrong_lengths() {
        let signer = QRunV06HybridTransactionSigner::from_seeds([0xB1; 32], [0xB2; 32]).unwrap();
        let transaction = signed_transaction(&signer);
        let limits = QRunV06MempoolLimits::default();
        let encoded = encode_snapshot(1, &[transaction], limits).unwrap();
        let (generation, transactions) = decode_snapshot(&encoded, limits).unwrap();
        assert_eq!(generation, 1);
        assert_eq!(transactions.len(), 1);
        let mut tampered = encoded.clone();
        tampered[HEADER_BYTES] ^= 1;
        assert_eq!(
            decode_snapshot(&tampered, limits),
            Err(QRunV06TransactionJournalError::ChecksumMismatch)
        );
        let mut wrong_length = encoded;
        wrong_length[20..24].copy_from_slice(&0u32.to_be_bytes());
        assert!(decode_snapshot(&wrong_length, limits).is_err());
    }

    #[test]
    fn journal_refuses_to_persist_until_startup_reconciliation_completes() {
        let directory = temp_dir();
        let limits = QRunV06MempoolLimits::default();
        let mut journal = QRunV06TransactionJournal::open(&directory, limits).unwrap();
        let pool = QRunV06NativeTransactionMempool::new(limits).unwrap();
        assert_eq!(
            journal.persist_pool(&pool),
            Err(QRunV06TransactionJournalError::StartupNotReconciled)
        );
        drop(journal);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn journal_exclusive_lock_prevents_concurrent_writer_handles() {
        let directory = temp_dir();
        let limits = QRunV06MempoolLimits::default();
        let first = QRunV06TransactionJournal::open(&directory, limits).unwrap();
        assert!(matches!(
            QRunV06TransactionJournal::open(&directory, limits),
            Err(QRunV06TransactionJournalError::WriterLockHeld)
        ));
        drop(first);
        fs::remove_dir_all(directory).unwrap();
    }
}
