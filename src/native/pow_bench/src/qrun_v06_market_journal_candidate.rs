//! CP-0659 Q6MM immutable, bounded durable journal for pending Q6MO market operations.
//!
//! This journal records pending signed AMM/OrderBook operations, never mined/finalized trades.
//! Restored entries must be revalidated against the recovered canonical state and the currently
//! restored Q6TI native mempool before Q6MO ingress is enabled.
use crate::{
    qrun_v06_canonical_execution_candidate::decode_qrun_v06_market_operation,
    qrun_v06_canonical_execution_candidate::QRunV06CanonicalExecutionState,
    qrun_v06_market_ingress_candidate::market_operation_id,
    qrun_v06_market_mempool_candidate::QRunV06MarketOperationMempool,
    qrun_v06_pow_fork_choice_candidate::QRunV06QuoteAssetAuthorizationProvider,
    qrun_v06_transaction_mempool_candidate::QRunV06MempoolLimits,
    state_machine::{AccountId, Transaction, TransactionAuthenticator},
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

const MAGIC: &[u8; 4] = b"Q6MM";
const VERSION: u16 = 1;
const HEADER_BYTES: usize = 24;
const CHECKSUM_BYTES: usize = 32;
const CHECKSUM_DOMAIN: &[u8] = b"QUANTUMZXB-QFP6-PENDING-MARKET-JOURNAL-V1\0";
const LOCK_FILE: &str = "qfp6-pending-market-operations.lock";
const SNAPSHOT_PREFIX: &str = "market-";
const SNAPSHOT_SUFFIX: &str = ".q6mm";
const TEMP_PREFIX: &str = ".q6mm-";
const TEMP_SUFFIX: &str = ".tmp";
const MAX_RETAINED_SNAPSHOTS: usize = 16;
static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QRunV06MarketJournalError {
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
    DuplicateOperation,
    OperationCodec(String),
    WriterLockHeld,
    GenerationOverflow,
    UnexpectedEntry,
    StartupNotReconciled,
    AlreadyRestored,
    Io(String),
}
impl std::fmt::Display for QRunV06MarketJournalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "QFP6 market journal error: {self:?}")
    }
}
impl std::error::Error for QRunV06MarketJournalError {}
impl From<io::Error> for QRunV06MarketJournalError {
    fn from(value: io::Error) -> Self {
        Self::Io(value.to_string())
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct QRunV06MarketJournalRestoreSummary {
    pub restored: usize,
    pub dropped_invalid_or_stale: usize,
}

pub struct QRunV06MarketOperationJournal {
    directory: PathBuf,
    limits: QRunV06MempoolLimits,
    generation: u64,
    pending_on_open: Vec<crate::qrun_v06_canonical_execution_candidate::QRunV06BlockOperation>,
    startup_reconciled: bool,
    _writer_lock: StoreWriterLock,
}

impl QRunV06MarketOperationJournal {
    /// Open the separate Q6MM directory under an OS-backed exclusive writer lock.
    pub fn open(
        directory: impl AsRef<Path>,
        limits: QRunV06MempoolLimits,
    ) -> Result<Self, QRunV06MarketJournalError> {
        QRunV06MarketOperationMempool::new(limits)
            .map_err(|_| QRunV06MarketJournalError::InvalidLimits)?;
        let directory = directory.as_ref().to_path_buf();
        if !directory.is_absolute() {
            return Err(QRunV06MarketJournalError::InvalidPath);
        }
        fs::create_dir_all(&directory)?;
        let metadata = fs::symlink_metadata(&directory)?;
        if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
            return Err(QRunV06MarketJournalError::SymlinkOrSpecialFile);
        }
        let lock_path = directory.join(LOCK_FILE);
        reject_symlink_or_special_if_present(&lock_path)?;
        let writer_lock = StoreWriterLock::acquire(&directory, LOCK_FILE).map_err(|error| {
            if error.kind() == io::ErrorKind::WouldBlock {
                QRunV06MarketJournalError::WriterLockHeld
            } else {
                error.into()
            }
        })?;
        let (generation, pending) = load_latest_snapshot(&directory, limits)?;
        cleanup_stale_temporary_files(&directory)?;
        Ok(Self {
            directory,
            limits,
            generation,
            pending_on_open: pending,
            startup_reconciled: false,
            _writer_lock: writer_lock,
        })
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn directory(&self) -> &Path {
        &self.directory
    }

    /// Durably install a complete current market-pool snapshot after startup reconciliation.
    pub fn persist_pool(
        &mut self,
        pool: &QRunV06MarketOperationMempool,
    ) -> Result<u64, QRunV06MarketJournalError> {
        if !self.startup_reconciled {
            return Err(QRunV06MarketJournalError::StartupNotReconciled);
        }
        self.persist_snapshot(pool)
    }

    fn persist_snapshot(
        &mut self,
        pool: &QRunV06MarketOperationMempool,
    ) -> Result<u64, QRunV06MarketJournalError> {
        if pool.limits() != self.limits {
            return Err(QRunV06MarketJournalError::InvalidLimits);
        }
        let generation = self
            .generation
            .checked_add(1)
            .ok_or(QRunV06MarketJournalError::GenerationOverflow)?;
        let bytes = encode_snapshot(generation, &pool.ordered_operations(), self.limits)?;
        let path = snapshot_path(&self.directory, generation);
        write_new_atomic(&path, &bytes)?;
        self.generation = generation;
        prune_old_snapshots(&self.directory, generation)?;
        Ok(generation)
    }

    /// Restore and revalidate against current canonical state AND the Q6TI pending set.
    /// The reconciled snapshot is persisted before the caller may expose ingress.
    pub fn restore_into_pool<A: TransactionAuthenticator>(
        &mut self,
        pool: &mut QRunV06MarketOperationMempool,
        state: &QRunV06CanonicalExecutionState,
        authenticator: &A,
        producer: AccountId,
        candidate_timestamp: u64,
        native_transactions: &[Transaction],
    ) -> Result<QRunV06MarketJournalRestoreSummary, QRunV06MarketJournalError> {
        self.restore_into_pool_with_quote_asset_authorization(
            pool,
            state,
            authenticator,
            producer,
            candidate_timestamp,
            native_transactions,
            None,
        )
    }

    pub fn restore_into_pool_with_quote_asset_authorization<A: TransactionAuthenticator>(
        &mut self,
        pool: &mut QRunV06MarketOperationMempool,
        state: &QRunV06CanonicalExecutionState,
        authenticator: &A,
        producer: AccountId,
        candidate_timestamp: u64,
        native_transactions: &[Transaction],
        mut quote_authorizer: Option<&mut QRunV06QuoteAssetAuthorizationProvider<'_>>,
    ) -> Result<QRunV06MarketJournalRestoreSummary, QRunV06MarketJournalError> {
        if self.startup_reconciled {
            return Err(QRunV06MarketJournalError::AlreadyRestored);
        }
        if pool.limits() != self.limits || candidate_timestamp <= state.last_timestamp() {
            return Err(QRunV06MarketJournalError::InvalidLimits);
        }
        let mut pending = std::mem::take(&mut self.pending_on_open);
        pending.sort_by_key(|operation| market_operation_id(operation).unwrap_or([0; 32]));
        let mut summary = QRunV06MarketJournalRestoreSummary::default();
        for operation in pending {
            if pool
                .submit_with_quote_asset_authorization(
                    operation,
                    state,
                    authenticator,
                    producer,
                    candidate_timestamp,
                    native_transactions,
                    quote_authorizer.as_deref_mut(),
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
) -> Result<usize, QRunV06MarketJournalError> {
    limits
        .max_bytes
        .checked_add(
            limits
                .max_transactions
                .checked_mul(4)
                .ok_or(QRunV06MarketJournalError::Oversize)?,
        )
        .and_then(|value| value.checked_add(HEADER_BYTES + CHECKSUM_BYTES))
        .ok_or(QRunV06MarketJournalError::Oversize)
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
    operations: &[crate::qrun_v06_canonical_execution_candidate::QRunV06BlockOperation],
    limits: QRunV06MempoolLimits,
) -> Result<Vec<u8>, QRunV06MarketJournalError> {
    if generation == 0 || operations.len() > limits.max_transactions {
        return Err(QRunV06MarketJournalError::InvalidGeneration);
    }
    let mut body = Vec::new();
    let mut ids = HashSet::with_capacity(operations.len());
    let mut total_operation_bytes = 0usize;
    for operation in operations {
        let encoded =
            crate::qrun_v06_canonical_execution_candidate::encode_qrun_v06_market_operation(
                operation,
            )
            .map_err(|error| QRunV06MarketJournalError::OperationCodec(format!("{error:?}")))?;
        total_operation_bytes = total_operation_bytes
            .checked_add(encoded.len())
            .ok_or(QRunV06MarketJournalError::Oversize)?;
        if encoded.is_empty() || total_operation_bytes > limits.max_bytes {
            return Err(QRunV06MarketJournalError::Oversize);
        }
        let id = market_operation_id(operation)
            .map_err(|error| QRunV06MarketJournalError::OperationCodec(format!("{error:?}")))?;
        if !ids.insert(id) {
            return Err(QRunV06MarketJournalError::DuplicateOperation);
        }
        let length =
            u32::try_from(encoded.len()).map_err(|_| QRunV06MarketJournalError::Oversize)?;
        body.extend_from_slice(&length.to_be_bytes());
        body.extend_from_slice(&encoded);
    }
    let count = u32::try_from(operations.len()).map_err(|_| QRunV06MarketJournalError::Oversize)?;
    let body_len = u32::try_from(body.len()).map_err(|_| QRunV06MarketJournalError::Oversize)?;
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
        return Err(QRunV06MarketJournalError::Oversize);
    }
    Ok(bytes)
}

fn decode_snapshot(
    bytes: &[u8],
    limits: QRunV06MempoolLimits,
) -> Result<
    (
        u64,
        Vec<crate::qrun_v06_canonical_execution_candidate::QRunV06BlockOperation>,
    ),
    QRunV06MarketJournalError,
> {
    if bytes.len() < HEADER_BYTES + CHECKSUM_BYTES {
        return Err(QRunV06MarketJournalError::Incomplete);
    }
    if bytes.len() > maximum_snapshot_bytes(limits)? {
        return Err(QRunV06MarketJournalError::Oversize);
    }
    if &bytes[..4] != MAGIC {
        return Err(QRunV06MarketJournalError::BadMagic);
    }
    let version = u16::from_be_bytes([bytes[4], bytes[5]]);
    if version != VERSION {
        return Err(QRunV06MarketJournalError::UnsupportedVersion(version));
    }
    if bytes[6..8] != [0, 0] {
        return Err(QRunV06MarketJournalError::InvalidHeader);
    }
    let generation = u64::from_be_bytes(bytes[8..16].try_into().unwrap());
    if generation == 0 {
        return Err(QRunV06MarketJournalError::InvalidGeneration);
    }
    let count = u32::from_be_bytes(bytes[16..20].try_into().unwrap()) as usize;
    let body_len = u32::from_be_bytes(bytes[20..24].try_into().unwrap()) as usize;
    if count > limits.max_transactions {
        return Err(QRunV06MarketJournalError::Oversize);
    }
    let checksum_start = HEADER_BYTES
        .checked_add(body_len)
        .ok_or(QRunV06MarketJournalError::Oversize)?;
    let expected_len = checksum_start
        .checked_add(CHECKSUM_BYTES)
        .ok_or(QRunV06MarketJournalError::Oversize)?;
    if bytes.len() != expected_len {
        return Err(QRunV06MarketJournalError::LengthMismatch);
    }
    let mut hash = Sha256::new();
    hash.update(CHECKSUM_DOMAIN);
    hash.update(&bytes[..checksum_start]);
    if hash.finalize().as_slice() != &bytes[checksum_start..] {
        return Err(QRunV06MarketJournalError::ChecksumMismatch);
    }

    let mut operations = Vec::with_capacity(count);
    let mut ids = HashSet::with_capacity(count);
    let mut offset = HEADER_BYTES;
    let mut total_operation_bytes = 0usize;
    for _ in 0..count {
        if offset + 4 > checksum_start {
            return Err(QRunV06MarketJournalError::Incomplete);
        }
        let length = u32::from_be_bytes(bytes[offset..offset + 4].try_into().unwrap()) as usize;
        offset += 4;
        if length == 0
            || offset
                .checked_add(length)
                .filter(|end| *end <= checksum_start)
                .is_none()
        {
            return Err(QRunV06MarketJournalError::LengthMismatch);
        }
        total_operation_bytes = total_operation_bytes
            .checked_add(length)
            .ok_or(QRunV06MarketJournalError::Oversize)?;
        if total_operation_bytes > limits.max_bytes {
            return Err(QRunV06MarketJournalError::Oversize);
        }
        let operation = decode_qrun_v06_market_operation(&bytes[offset..offset + length])
            .map_err(|error| QRunV06MarketJournalError::OperationCodec(format!("{error:?}")))?;
        offset += length;
        let id = market_operation_id(&operation)
            .map_err(|error| QRunV06MarketJournalError::OperationCodec(format!("{error:?}")))?;
        if !ids.insert(id) {
            return Err(QRunV06MarketJournalError::DuplicateOperation);
        }
        operations.push(operation);
    }
    if offset != checksum_start {
        return Err(QRunV06MarketJournalError::LengthMismatch);
    }
    Ok((generation, operations))
}

fn reject_symlink_or_special_if_present(path: &Path) -> Result<(), QRunV06MarketJournalError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.file_type().is_file() => {
            Err(QRunV06MarketJournalError::SymlinkOrSpecialFile)
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn load_snapshot_file(
    path: &Path,
    limits: QRunV06MempoolLimits,
) -> Result<
    (
        u64,
        Vec<crate::qrun_v06_canonical_execution_candidate::QRunV06BlockOperation>,
    ),
    QRunV06MarketJournalError,
> {
    reject_symlink_or_special_if_present(path)?;
    let max = maximum_snapshot_bytes(limits)?;
    let file = File::open(path)?;
    let mut bytes = Vec::new();
    file.take(max as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > max {
        return Err(QRunV06MarketJournalError::Oversize);
    }
    decode_snapshot(&bytes, limits)
}

fn load_latest_snapshot(
    directory: &Path,
    limits: QRunV06MempoolLimits,
) -> Result<
    (
        u64,
        Vec<crate::qrun_v06_canonical_execution_candidate::QRunV06BlockOperation>,
    ),
    QRunV06MarketJournalError,
> {
    let mut snapshots = Vec::new();
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name == LOCK_FILE || name.starts_with(TEMP_PREFIX) {
            continue;
        }
        let generation =
            parse_snapshot_generation(&name).ok_or(QRunV06MarketJournalError::UnexpectedEntry)?;
        let metadata = fs::symlink_metadata(entry.path())?;
        if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
            return Err(QRunV06MarketJournalError::SymlinkOrSpecialFile);
        }
        snapshots.push((generation, entry.path()));
    }
    snapshots.sort_by_key(|entry| entry.0);
    if let Some((generation, path)) = snapshots.last() {
        let (encoded_generation, operations) = load_snapshot_file(path, limits)?;
        if encoded_generation != *generation {
            return Err(QRunV06MarketJournalError::InvalidGeneration);
        }
        Ok((*generation, operations))
    } else {
        Ok((0, Vec::new()))
    }
}

fn write_new_atomic(path: &Path, bytes: &[u8]) -> Result<(), QRunV06MarketJournalError> {
    let directory = path
        .parent()
        .ok_or(QRunV06MarketJournalError::InvalidPath)?;
    let file_name = path
        .file_name()
        .ok_or(QRunV06MarketJournalError::InvalidPath)?;
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
fn atomic_install_new(source: &Path, destination: &Path) -> Result<(), QRunV06MarketJournalError> {
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
fn atomic_install_new(source: &Path, destination: &Path) -> Result<(), QRunV06MarketJournalError> {
    fs::hard_link(source, destination)?;
    fs::remove_file(source)?;
    let parent = destination
        .parent()
        .ok_or(QRunV06MarketJournalError::InvalidPath)?;
    File::open(parent)?.sync_all()?;
    Ok(())
}

#[cfg(not(any(windows, unix)))]
fn atomic_install_new(
    _source: &Path,
    _destination: &Path,
) -> Result<(), QRunV06MarketJournalError> {
    Err(QRunV06MarketJournalError::Io(
        "atomic no-replace install unsupported".into(),
    ))
}

fn prune_old_snapshots(
    directory: &Path,
    latest_generation: u64,
) -> Result<(), QRunV06MarketJournalError> {
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

fn cleanup_stale_temporary_files(directory: &Path) -> Result<(), QRunV06MarketJournalError> {
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        if entry.file_name().to_string_lossy().starts_with(TEMP_PREFIX) {
            let metadata = fs::symlink_metadata(entry.path())?;
            if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
                return Err(QRunV06MarketJournalError::SymlinkOrSpecialFile);
            }
            fs::remove_file(entry.path())?;
        }
    }
    sync_directory(directory)?;
    Ok(())
}

#[cfg(unix)]
fn sync_directory(directory: &Path) -> Result<(), QRunV06MarketJournalError> {
    File::open(directory)?.sync_all()?;
    Ok(())
}

#[cfg(windows)]
fn sync_directory(_directory: &Path) -> Result<(), QRunV06MarketJournalError> {
    // MoveFileExW(MOVEFILE_WRITE_THROUGH) supplies durable namespace installation on Windows.
    Ok(())
}

#[cfg(not(any(windows, unix)))]
fn sync_directory(_directory: &Path) -> Result<(), QRunV06MarketJournalError> {
    Err(QRunV06MarketJournalError::Io(
        "directory sync unsupported on this target".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        qrun_v06_asset_registry_candidate::{
            AssetRegistration, AssetSupplyPolicy, AssetTrustPolicy,
        },
        qrun_v06_canonical_execution_candidate::{QRunV06Block, QRunV06BlockOperation},
        qrun_v06_orderbook_candidate::{
            QRunV06OrderBookOperation, QRunV06SignedOrderBookOperation,
        },
        qrun_v06_unified_asset_candidate::QRunV06UnifiedAssetState,
        qzxb_amm_candidate::{qzxb_native_asset_id, QzxbAmmStateCandidate},
        state_machine::LedgerState,
    };
    use std::{
        fs,
        time::{SystemTime, UNIX_EPOCH},
    };

    const NETWORK: [u8; 32] = [0xC1; 32];
    const PROFILE: [u8; 32] = [0xC2; 32];
    const ALICE: [u8; 32] = [0xC3; 32];
    const BOB: [u8; 32] = [0xC4; 32];
    const PRODUCER: [u8; 32] = [0xC5; 32];

    struct DigestAuthenticator;
    impl TransactionAuthenticator for DigestAuthenticator {
        fn verify(
            &self,
            sender: &AccountId,
            digest: &[u8; 32],
            signature: &[u8],
        ) -> Result<(), ()> {
            if sender.iter().any(|byte| *byte != 0) && signature == digest {
                Ok(())
            } else {
                Err(())
            }
        }
    }

    fn state_and_pending_operation() -> (
        QRunV06CanonicalExecutionState,
        crate::qrun_v06_canonical_execution_candidate::QRunV06BlockOperation,
    ) {
        let ledger = LedgerState::genesis(NETWORK, vec![(ALICE, 20_000)]).unwrap();
        let amm = QzxbAmmStateCandidate::new(NETWORK, 32, 64, 512).unwrap();
        let unified = QRunV06UnifiedAssetState::new(ledger, amm).unwrap();
        let mut state = QRunV06CanonicalExecutionState::new(unified, PROFILE).unwrap();

        let mut registration = AssetRegistration {
            network_id: NETWORK,
            issuer: ALICE,
            issuer_nonce: 1,
            salt: [0xD1; 32],
            name: "Q6MM Journal Asset".to_string(),
            symbol: "Q6MJ".to_string(),
            decimals: 8,
            supply_policy: AssetSupplyPolicy::Fixed {
                total_supply: 1_000,
            },
            initial_supply: 1_000,
            initial_recipient: ALICE,
            trust_policy: AssetTrustPolicy::Unverified,
            expires_at: 10_000,
            signature: Vec::new(),
        };
        registration.signature = registration.signing_digest().unwrap().to_vec();
        let base_asset = registration.asset_id();

        let mut first = QRunV06Block {
            network_id: NETWORK,
            profile_id: PROFILE,
            height: 1,
            timestamp: 100,
            parent_hash: state.tip_hash(),
            state_root: [0; 32],
            producer: PRODUCER,
            operations: vec![QRunV06BlockOperation::AssetRegistration(registration)],
        };
        first.state_root = state
            .preview_state_root_after(&first, &DigestAuthenticator)
            .unwrap();
        state.apply_block(&first, &DigestAuthenticator).unwrap();

        let mut create_pair = QRunV06SignedOrderBookOperation {
            network_id: NETWORK,
            sender: ALICE,
            nonce: 1,
            expires_at: 10_000,
            operation: QRunV06OrderBookOperation::CreatePair {
                base: base_asset,
                quote: qzxb_native_asset_id(NETWORK).unwrap(),
                base_lot_atoms: 1,
                quote_tick_atoms: 1,
                max_price_ticks: 1_000,
                max_quantity_lots: 1_000,
                min_notional: 1,
                maker_fee_bps: 10,
                taker_fee_bps: 20,
                fee_collector: BOB,
            },
            signature: Vec::new(),
        };
        create_pair.signature = create_pair.signing_digest().unwrap().to_vec();
        (
            state,
            crate::qrun_v06_canonical_execution_candidate::QRunV06BlockOperation::OrderBook(
                create_pair,
            ),
        )
    }

    fn temp_dir() -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("q6mm-{}-{nonce}", std::process::id()))
    }

    #[test]
    fn q6mm_snapshot_roundtrips_and_rejects_checksum_tampering() {
        let (_, operation) = state_and_pending_operation();
        let limits = QRunV06MempoolLimits::default();
        let encoded = encode_snapshot(1, &[operation.clone()], limits).unwrap();
        let (generation, decoded) = decode_snapshot(&encoded, limits).unwrap();
        assert_eq!(generation, 1);
        assert_eq!(decoded, vec![operation]);
        let mut tampered = encoded;
        tampered[HEADER_BYTES] ^= 1;
        assert_eq!(
            decode_snapshot(&tampered, limits),
            Err(QRunV06MarketJournalError::ChecksumMismatch)
        );
    }

    #[test]
    fn q6mm_restores_only_revalidated_pending_market_operations() {
        let directory = temp_dir();
        let (state, operation) = state_and_pending_operation();
        let limits = QRunV06MempoolLimits::default();
        let timestamp = state.last_timestamp() + 100;
        let mut pool = QRunV06MarketOperationMempool::new(limits).unwrap();

        {
            let mut journal = QRunV06MarketOperationJournal::open(&directory, limits).unwrap();
            let summary = journal
                .restore_into_pool(
                    &mut pool,
                    &state,
                    &DigestAuthenticator,
                    PRODUCER,
                    timestamp,
                    &[],
                )
                .unwrap();
            assert_eq!(summary.restored, 0);
            assert_eq!(journal.generation(), 1);
            pool.submit(
                operation.clone(),
                &state,
                &DigestAuthenticator,
                PRODUCER,
                timestamp,
                &[],
            )
            .unwrap();
            assert_eq!(journal.persist_pool(&pool).unwrap(), 2);
        }

        let mut recovered_journal =
            QRunV06MarketOperationJournal::open(&directory, limits).unwrap();
        let mut recovered_pool = QRunV06MarketOperationMempool::new(limits).unwrap();
        let summary = recovered_journal
            .restore_into_pool(
                &mut recovered_pool,
                &state,
                &DigestAuthenticator,
                PRODUCER,
                timestamp,
                &[],
            )
            .unwrap();
        assert_eq!(summary.restored, 1);
        assert_eq!(summary.dropped_invalid_or_stale, 0);
        assert_eq!(recovered_pool.ordered_operations(), vec![operation]);
        drop(recovered_journal);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn q6mm_refuses_persistence_until_startup_reconciliation() {
        let directory = temp_dir();
        let limits = QRunV06MempoolLimits::default();
        let mut journal = QRunV06MarketOperationJournal::open(&directory, limits).unwrap();
        let pool = QRunV06MarketOperationMempool::new(limits).unwrap();
        assert_eq!(
            journal.persist_pool(&pool),
            Err(QRunV06MarketJournalError::StartupNotReconciled)
        );
        drop(journal);
        fs::remove_dir_all(directory).unwrap();
    }
}
