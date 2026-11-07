//! CP-0405 single-host durable QHWR replay ledger candidate.
//!
//! Reservations are append-only and acknowledged only after sync_all succeeds. The store
//! retains every v1 challenge because QHWR v1 has no server-issued expiry lease. OS locks
//! serialize writers on one host; this is not a distributed or multi-host consensus ledger.
//! Windows parent-directory durability is not independently established here and requires
//! platform-specific power-loss qualification before production use.
//! The unkeyed record checksum detects accidental corruption, not malicious local rewrite or
//! rollback; resisting that threat requires an independent external monotonic authority.

use crate::private_testnet_pfm5_highwater_rpc_dispatch_candidate::{
    QhwrDurableReplayLedger, QhwrReplayScope,
};
use crate::private_testnet_pfm5_highwater_rpc_wire_candidate::QhwrOperation;
use crate::snapshot_store::{SnapshotStoreError, SnapshotWriterLock};
use sha2::{Digest, Sha256};
#[cfg(any(unix, test))]
use std::path::PathBuf;
use std::{
    collections::HashSet,
    fs::{self, File, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    path::Path,
};

const RECORD_MAGIC: &[u8; 8] = b"QHWRRPL1";
const RECORD_VERSION: u8 = 1;
const RECORD_PREFIX_BYTES: usize = 8 + 1 + 32;
const CHECKSUM_BYTES: usize = 32;
const RECORD_BYTES: usize = RECORD_PREFIX_BYTES + CHECKSUM_BYTES;
const MAX_LEDGER_BYTES: u64 = 64 * 1024 * 1024;
const KEY_DOMAIN: &[u8] = b"AIN1-QHWR-REPLAY-KEY-V1\0";
const RECORD_DOMAIN: &[u8] = b"AIN1-QHWR-REPLAY-RECORD-V1\0";

#[derive(Debug)]
pub enum QhwrReplayLedgerError {
    Io(io::Error),
    InvalidPath,
    WriterLockUnavailable,
    CorruptRecord { offset: u64 },
    DuplicateRecordInJournal { offset: u64 },
    StoreTooLarge(u64),
    StoreNeedsRecovery,
}

impl std::fmt::Display for QhwrReplayLedgerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(f, "QHWR replay ledger I/O: {error}"),
            Self::InvalidPath => f.write_str("invalid QHWR replay ledger path"),
            Self::WriterLockUnavailable => {
                f.write_str("QHWR replay ledger writer is already active")
            }
            Self::CorruptRecord { offset } => {
                write!(f, "QHWR replay ledger corrupt record at offset {offset}")
            }
            Self::DuplicateRecordInJournal { offset } => {
                write!(f, "QHWR replay ledger duplicate key at offset {offset}")
            }
            Self::StoreTooLarge(size) => {
                write!(f, "QHWR replay ledger size limit exceeded: {size}")
            }
            Self::StoreNeedsRecovery => {
                f.write_str("QHWR replay ledger has uncertain I/O; reopen before reuse")
            }
        }
    }
}
impl std::error::Error for QhwrReplayLedgerError {}
impl From<io::Error> for QhwrReplayLedgerError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}
impl From<SnapshotStoreError> for QhwrReplayLedgerError {
    fn from(value: SnapshotStoreError) -> Self {
        match value {
            SnapshotStoreError::WriterLockBusy(_) => Self::WriterLockUnavailable,
            SnapshotStoreError::Io(error) => Self::Io(error),
            _ => Self::InvalidPath,
        }
    }
}

/// Append-only, checksummed replay reservations with a single active writer per file.
/// A successful `reserve_once` is returned only after the record's `sync_all` barrier.
pub struct QhwrDurableReplayLedgerCandidate {
    #[cfg(unix)]
    path: PathBuf,
    file: File,
    _path_lock: SnapshotWriterLock,
    _file_identity_lock: SnapshotWriterLock,
    keys: HashSet<[u8; 32]>,
    valid_len: u64,
    poisoned: bool,
}

impl QhwrDurableReplayLedgerCandidate {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, QhwrReplayLedgerError> {
        let input_path = path.as_ref();
        let file_name = input_path
            .file_name()
            .ok_or(QhwrReplayLedgerError::InvalidPath)?;
        let canonical_parent = fs::canonicalize(parent_directory(input_path))?;
        let path = canonical_parent.join(file_name);
        if !canonical_parent.is_dir() {
            return Err(QhwrReplayLedgerError::InvalidPath);
        }
        // Windows has no validated parent-directory flush in this candidate. Require
        // the WAL name to be provisioned before open; never create a name and then
        // report successful reservations without proving that directory entry durable.
        #[cfg(windows)]
        if !path.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Windows QHWR WAL must be pre-provisioned; directory-entry durability is not established",
            )
            .into());
        }
        // Pin the parent directory at open time. A later process-wide current-directory
        // change must not redirect syncs or lock diagnostics to a different WAL path.
        let path_lock = SnapshotWriterLock::acquire(&path)?;
        let mut file_options = OpenOptions::new();
        file_options.read(true).write(true);
        #[cfg(windows)]
        file_options.create(false);
        #[cfg(not(windows))]
        file_options.create(true);
        let file = file_options.open(&path)?;
        let file_identity_lock = SnapshotWriterLock::acquire_file_identity(&file, &path)?;
        let mut ledger = Self {
            #[cfg(unix)]
            path,
            file,
            _path_lock: path_lock,
            _file_identity_lock: file_identity_lock,
            keys: HashSet::new(),
            valid_len: 0,
            poisoned: false,
        };
        ledger.recover()?;
        Ok(ledger)
    }

    pub fn reservation_count(&self) -> usize {
        self.keys.len()
    }

    fn recover(&mut self) -> Result<(), QhwrReplayLedgerError> {
        let file_len = self.file.metadata()?.len();
        if file_len > MAX_LEDGER_BYTES {
            return Err(QhwrReplayLedgerError::StoreTooLarge(file_len));
        }
        self.file.seek(SeekFrom::Start(0))?;
        let mut offset = 0u64;
        while offset < file_len {
            let remaining = file_len - offset;
            if remaining < RECORD_BYTES as u64 {
                // An incomplete final frame was never acknowledged by reserve_once.
                self.file.set_len(offset)?;
                self.file.sync_all()?;
                break;
            }
            let mut record = [0u8; RECORD_BYTES];
            self.file.read_exact(&mut record)?;
            if &record[..8] != RECORD_MAGIC || record[8] != RECORD_VERSION {
                return Err(QhwrReplayLedgerError::CorruptRecord { offset });
            }
            let expected = record_checksum(&record[..RECORD_PREFIX_BYTES]);
            if !constant_time_eq(&record[RECORD_PREFIX_BYTES..], &expected) {
                return Err(QhwrReplayLedgerError::CorruptRecord { offset });
            }
            let mut key = [0u8; 32];
            key.copy_from_slice(&record[9..RECORD_PREFIX_BYTES]);
            if !self.keys.insert(key) {
                return Err(QhwrReplayLedgerError::DuplicateRecordInJournal { offset });
            }
            offset = offset
                .checked_add(RECORD_BYTES as u64)
                .ok_or(QhwrReplayLedgerError::StoreTooLarge(file_len))?;
            self.valid_len = offset;
        }
        self.file.seek(SeekFrom::Start(self.valid_len))?;
        Ok(())
    }
}

impl QhwrDurableReplayLedger for QhwrDurableReplayLedgerCandidate {
    type Error = QhwrReplayLedgerError;

    fn reserve_once(
        &mut self,
        scope: &QhwrReplayScope,
        challenge: &[u8; 32],
    ) -> Result<bool, Self::Error> {
        if self.poisoned {
            return Err(QhwrReplayLedgerError::StoreNeedsRecovery);
        }
        let key = replay_key(scope, challenge);
        if self.keys.contains(&key) {
            return Ok(false);
        }
        let new_len = self
            .valid_len
            .checked_add(RECORD_BYTES as u64)
            .ok_or(QhwrReplayLedgerError::StoreTooLarge(u64::MAX))?;
        if new_len > MAX_LEDGER_BYTES {
            return Err(QhwrReplayLedgerError::StoreTooLarge(new_len));
        }
        if self.file.metadata()?.len() != self.valid_len {
            self.poisoned = true;
            return Err(QhwrReplayLedgerError::StoreNeedsRecovery);
        }
        let mut record = [0u8; RECORD_BYTES];
        record[..8].copy_from_slice(RECORD_MAGIC);
        record[8] = RECORD_VERSION;
        record[9..RECORD_PREFIX_BYTES].copy_from_slice(&key);
        let checksum = record_checksum(&record[..RECORD_PREFIX_BYTES]);
        record[RECORD_PREFIX_BYTES..].copy_from_slice(&checksum);
        self.file.seek(SeekFrom::Start(self.valid_len))?;
        if let Err(error) = self.file.write_all(&record) {
            self.poisoned = true;
            return Err(error.into());
        }
        if let Err(error) = self.file.sync_all() {
            self.poisoned = true;
            return Err(error.into());
        }
        #[cfg(unix)]
        if let Err(error) = sync_parent(&self.path) {
            self.poisoned = true;
            return Err(error);
        }
        self.valid_len = new_len;
        self.keys.insert(key);
        Ok(true)
    }
}

fn replay_key(scope: &QhwrReplayScope, challenge: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(KEY_DOMAIN);
    hasher.update(scope.network_id);
    hasher.update(scope.authenticated_peer);
    hasher.update([match scope.operation {
        QhwrOperation::Read => 1,
        QhwrOperation::CompareAndAdvance => 2,
    }]);
    hasher.update(challenge);
    hasher.finalize().into()
}

fn record_checksum(prefix: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(RECORD_DOMAIN);
    hasher.update(prefix);
    hasher.finalize().into()
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0u8, |diff, (a, b)| diff | (a ^ b))
        == 0
}

fn parent_directory(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

#[cfg(unix)]
fn sync_parent(path: &Path) -> Result<(), QhwrReplayLedgerError> {
    File::open(parent_directory(path))?.sync_all()?;
    Ok(())
}
#[cfg(not(any(windows, unix)))]
fn sync_parent(_path: &Path) -> Result<(), QhwrReplayLedgerError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::process::{Command, Stdio};
    use std::{
        sync::atomic::{AtomicU64, Ordering},
        time::{SystemTime, UNIX_EPOCH},
    };
    use std::{
        thread,
        time::{Duration, Instant},
    };

    static NEXT: AtomicU64 = AtomicU64::new(0);
    struct TestDir(PathBuf);
    impl TestDir {
        fn new() -> Self {
            let id = NEXT.fetch_add(1, Ordering::Relaxed);
            let stamp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let path = std::env::temp_dir()
                .join(format!("qhwr-replay-{}-{stamp}-{id}", std::process::id()));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }
        fn file(&self) -> PathBuf {
            let path = self.0.join("replay.wal");
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
                .unwrap();
            path
        }
    }
    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn scope(network: u8, peer: u8, operation: QhwrOperation) -> QhwrReplayScope {
        QhwrReplayScope {
            network_id: [network; 32],
            authenticated_peer: [peer; 32],
            operation,
        }
    }

    #[cfg(windows)]
    #[test]
    fn windows_open_rejects_unprovisioned_wal_path() {
        let dir = TestDir::new();
        let path = dir.0.join("not-created.wal");
        assert!(matches!(
            QhwrDurableReplayLedgerCandidate::open(&path),
            Err(QhwrReplayLedgerError::Io(ref error))
                if error.kind() == io::ErrorKind::Unsupported
        ));
        assert!(!path.exists());
    }

    #[test]
    fn reservation_is_durable_across_reopen_and_scope_isolated() {
        let dir = TestDir::new();
        let path = dir.file();
        let challenge = [7; 32];
        {
            let mut ledger = QhwrDurableReplayLedgerCandidate::open(&path).unwrap();
            assert!(ledger
                .reserve_once(&scope(1, 2, QhwrOperation::Read), &challenge)
                .unwrap());
            assert!(!ledger
                .reserve_once(&scope(1, 2, QhwrOperation::Read), &challenge)
                .unwrap());
            assert!(ledger
                .reserve_once(&scope(1, 3, QhwrOperation::Read), &challenge)
                .unwrap());
            assert!(ledger
                .reserve_once(&scope(1, 2, QhwrOperation::CompareAndAdvance), &challenge)
                .unwrap());
        }
        let mut reopened = QhwrDurableReplayLedgerCandidate::open(&path).unwrap();
        assert_eq!(reopened.reservation_count(), 3);
        assert!(!reopened
            .reserve_once(&scope(1, 2, QhwrOperation::Read), &challenge)
            .unwrap());
        assert!(reopened
            .reserve_once(&scope(9, 2, QhwrOperation::Read), &challenge)
            .unwrap());
    }

    #[test]
    fn incomplete_tail_is_removed_without_losing_committed_reservations() {
        let dir = TestDir::new();
        let path = dir.file();
        let challenge = [8; 32];
        {
            let mut ledger = QhwrDurableReplayLedgerCandidate::open(&path).unwrap();
            assert!(ledger
                .reserve_once(&scope(1, 2, QhwrOperation::Read), &challenge)
                .unwrap());
        }
        OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(b"QHWRRPL")
            .unwrap();
        let mut reopened = QhwrDurableReplayLedgerCandidate::open(&path).unwrap();
        assert_eq!(fs::metadata(&path).unwrap().len(), RECORD_BYTES as u64);
        assert_eq!(reopened.reservation_count(), 1);
        assert!(!reopened
            .reserve_once(&scope(1, 2, QhwrOperation::Read), &challenge)
            .unwrap());
    }

    #[test]
    fn complete_checksum_corruption_fails_closed() {
        let dir = TestDir::new();
        let path = dir.file();
        {
            let mut ledger = QhwrDurableReplayLedgerCandidate::open(&path).unwrap();
            assert!(ledger
                .reserve_once(&scope(1, 2, QhwrOperation::Read), &[9; 32])
                .unwrap());
        }
        let mut bytes = fs::read(&path).unwrap();
        bytes[RECORD_PREFIX_BYTES] ^= 0x80;
        fs::write(&path, bytes).unwrap();
        assert!(matches!(
            QhwrDurableReplayLedgerCandidate::open(&path),
            Err(QhwrReplayLedgerError::CorruptRecord { offset: 0 })
        ));
    }

    #[test]
    fn child_crash_probe() {
        let Ok(path) = std::env::var("QHWR_LEDGER_CHILD_PATH") else {
            return;
        };
        let mut ledger = QhwrDurableReplayLedgerCandidate::open(&path).unwrap();
        assert!(ledger
            .reserve_once(&scope(1, 2, QhwrOperation::Read), &[11; 32])
            .unwrap());
        let mut file = OpenOptions::new().append(true).open(&path).unwrap();
        file.write_all(b"QHWRRPL").unwrap();
        file.flush().unwrap();
        // Exit without Rust destructors to model abrupt process termination and lock release.
        std::process::exit(0);
    }

    #[test]
    fn actual_child_process_exit_recovers_committed_key_and_discards_torn_tail() {
        let dir = TestDir::new();
        let path = dir.file();
        let status = Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg("private_testnet_qhwr_durable_replay_ledger_candidate::tests::child_crash_probe")
            .arg("--nocapture")
            .env("QHWR_LEDGER_CHILD_PATH", &path)
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .status()
            .unwrap();
        assert!(status.success(), "child process failed: {status}");
        let mut reopened = QhwrDurableReplayLedgerCandidate::open(&path).unwrap();
        assert_eq!(reopened.reservation_count(), 1);
        assert_eq!(fs::metadata(&path).unwrap().len(), RECORD_BYTES as u64);
        assert!(!reopened
            .reserve_once(&scope(1, 2, QhwrOperation::Read), &[11; 32])
            .unwrap());
    }
    #[test]
    fn child_lock_probe() {
        let (Ok(path), Ok(ready), Ok(release)) = (
            std::env::var("QHWR_LEDGER_LOCK_CHILD_PATH"),
            std::env::var("QHWR_LEDGER_LOCK_READY_PATH"),
            std::env::var("QHWR_LEDGER_LOCK_RELEASE_PATH"),
        ) else {
            return;
        };
        let _ledger = QhwrDurableReplayLedgerCandidate::open(&path).unwrap();
        fs::write(&ready, b"ready").unwrap();
        for _ in 0..500 {
            if Path::new(&release).exists() {
                return;
            }
            thread::sleep(Duration::from_millis(10));
        }
        panic!("parent did not release child-held QHWR ledger lock");
    }

    #[test]
    fn separate_process_writer_is_excluded_until_owner_exits() {
        let dir = TestDir::new();
        let path = dir.file();
        let ready = dir.0.join("child.ready");
        let release = dir.0.join("child.release");
        let mut child = Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg("private_testnet_qhwr_durable_replay_ledger_candidate::tests::child_lock_probe")
            .arg("--nocapture")
            .env("QHWR_LEDGER_LOCK_CHILD_PATH", &path)
            .env("QHWR_LEDGER_LOCK_READY_PATH", &ready)
            .env("QHWR_LEDGER_LOCK_RELEASE_PATH", &release)
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while !ready.exists() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(10));
        }
        if !ready.exists() {
            let _ = child.kill();
            let _ = child.wait();
            panic!("child process did not acquire the QHWR ledger lock");
        }
        assert!(matches!(
            QhwrDurableReplayLedgerCandidate::open(&path),
            Err(QhwrReplayLedgerError::WriterLockUnavailable)
        ));
        fs::write(&release, b"release").unwrap();
        let status = child.wait().unwrap();
        assert!(status.success(), "child process failed: {status}");
        assert!(QhwrDurableReplayLedgerCandidate::open(&path).is_ok());
    }

    #[test]
    fn hard_link_alias_cannot_open_the_same_wal_for_writing() {
        let dir = TestDir::new();
        let path = dir.file();
        let alias = dir.0.join("replay-alias.wal");
        fs::hard_link(&path, &alias).unwrap();
        let first = QhwrDurableReplayLedgerCandidate::open(&path).unwrap();
        assert!(matches!(
            QhwrDurableReplayLedgerCandidate::open(&alias),
            Err(QhwrReplayLedgerError::WriterLockUnavailable)
        ));
        drop(first);
        assert!(QhwrDurableReplayLedgerCandidate::open(&alias).is_ok());
    }

    #[test]
    fn concurrent_writer_open_is_rejected_while_ledger_is_owned() {
        let dir = TestDir::new();
        let path = dir.file();
        let first = QhwrDurableReplayLedgerCandidate::open(&path).unwrap();
        assert!(matches!(
            QhwrDurableReplayLedgerCandidate::open(&path),
            Err(QhwrReplayLedgerError::WriterLockUnavailable)
        ));
        drop(first);
        assert!(QhwrDurableReplayLedgerCandidate::open(&path).is_ok());
    }
}
