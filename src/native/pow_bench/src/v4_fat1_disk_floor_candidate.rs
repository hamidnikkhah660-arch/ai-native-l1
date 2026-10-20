//! CP-0227: durable local FAT1 trust-floor provider candidate.
//!
//! This gives the CP-0226 trust-floor contract a crash-safe file implementation with
//! OS-level writer exclusion and process-kill tests. A file on ordinary local storage
//! is NOT an independent anti-rollback trust domain: disk-image rollback or a privileged
//! host attacker can still roll it back. Production must pin this floor independently.
use crate::{
    snapshot_store::{SnapshotStoreError, SnapshotWriterLock},
    v4_fat1_trust_candidate::{Fat1Error, MonotonicFat1FloorStore, TrustedFat1Floor},
};
use sha2::{Digest, Sha256};
use std::{
    ffi::OsString,
    fmt,
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

const MAGIC: &[u8; 4] = b"TFF1";
const VERSION: u16 = 1;
const HEADER_BYTES: usize = 8;
const NETWORK_OFFSET: usize = HEADER_BYTES;
const EPOCH_OFFSET: usize = NETWORK_OFFSET + 32;
const RECORD_OFFSET: usize = EPOCH_OFFSET + 8;
const ENVELOPE_OFFSET: usize = RECORD_OFFSET + 32;
const CORE_BYTES: usize = ENVELOPE_OFFSET + 32;
const CHECKSUM_BYTES: usize = 32;
const FLOOR_BYTES: usize = CORE_BYTES + CHECKSUM_BYTES;
const FLOOR_CHECKSUM_DOMAIN: &[u8] = b"AIN1-FAT1-FLOOR-FILE-CHECKSUM-V1\0";
static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Debug)]
pub enum DurableFat1FloorError {
    Io(io::Error),
    WriterLock(SnapshotStoreError),
    InvalidPath,
    InvalidEncoding,
    NetworkMismatch,
    AlreadyInitialized,
    Missing,
    InvalidInitialFloor,
    InvalidTransition,
    CompareAndSwapConflict,
}

impl fmt::Display for DurableFat1FloorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "durable FAT1 floor I/O failed: {e}"),
            Self::WriterLock(e) => write!(f, "durable FAT1 floor writer lock failed: {e}"),
            Self::InvalidPath => write!(f, "durable FAT1 floor path must name a regular file"),
            Self::InvalidEncoding => {
                write!(f, "durable FAT1 floor bytes are invalid or non-canonical")
            }
            Self::NetworkMismatch => write!(f, "durable FAT1 floor network mismatch"),
            Self::AlreadyInitialized => write!(f, "durable FAT1 floor already initialized"),
            Self::Missing => write!(f, "durable FAT1 floor is missing"),
            Self::InvalidInitialFloor => {
                write!(f, "initial FAT1 floor must have epoch and IDs zero")
            }
            Self::InvalidTransition => {
                write!(f, "FAT1 floor update must advance exactly one epoch")
            }
            Self::CompareAndSwapConflict => {
                write!(f, "durable FAT1 floor compare-and-swap conflict")
            }
        }
    }
}
impl std::error::Error for DurableFat1FloorError {}
impl From<io::Error> for DurableFat1FloorError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}
impl From<SnapshotStoreError> for DurableFat1FloorError {
    fn from(value: SnapshotStoreError) -> Self {
        Self::WriterLock(value)
    }
}
impl DurableFat1FloorError {
    fn as_fat1_error(&self) -> Fat1Error {
        match self {
            Self::NetworkMismatch => Fat1Error::TrustFloorNetworkMismatch,
            Self::InvalidTransition | Self::CompareAndSwapConflict => Fat1Error::FloorCasConflict,
            _ => Fat1Error::FloorUnavailable,
        }
    }
}

/// File-backed implementation of the FAT1 floor contract; not an independent root of trust.
#[derive(Debug, Clone)]
pub struct DurableFat1FloorStore {
    path: PathBuf,
}
impl DurableFat1FloorStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// Explicit first-time initialization. Never silently resets a missing/corrupt floor.
    pub fn initialize(&self, initial: &TrustedFat1Floor) -> Result<(), DurableFat1FloorError> {
        if initial.trust_epoch != 0
            || initial.record_id != [0; 32]
            || initial.envelope_id != [0; 32]
            || initial.network_id == [0; 32]
        {
            return Err(DurableFat1FloorError::InvalidInitialFloor);
        }
        let _lock = SnapshotWriterLock::acquire(&self.path)?;
        match fs::symlink_metadata(&self.path) {
            Ok(_) => return Err(DurableFat1FloorError::AlreadyInitialized),
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        persist_atomic(&self.path, initial)?;
        if load_unlocked(&self.path)? != *initial {
            return Err(DurableFat1FloorError::CompareAndSwapConflict);
        }
        Ok(())
    }

    /// Operator/test inspection path. Production callers must verify the expected network.
    pub fn load_checked(
        &self,
        expected_network_id: &[u8; 32],
    ) -> Result<TrustedFat1Floor, DurableFat1FloorError> {
        let _lock = SnapshotWriterLock::acquire(&self.path)?;
        let floor = load_unlocked(&self.path)?;
        if &floor.network_id != expected_network_id {
            return Err(DurableFat1FloorError::NetworkMismatch);
        }
        Ok(floor)
    }

    /// Test-only crash hook persists a complete successor while the caller holds the OS lock.
    #[cfg(test)]
    fn persist_locked_for_test(
        &self,
        floor: &TrustedFat1Floor,
    ) -> Result<(), DurableFat1FloorError> {
        persist_atomic(&self.path, floor)
    }
}
impl MonotonicFat1FloorStore for DurableFat1FloorStore {
    fn load(&self, network_id: &[u8; 32]) -> Result<TrustedFat1Floor, Fat1Error> {
        self.load_checked(network_id).map_err(|e| e.as_fat1_error())
    }

    fn compare_and_swap(
        &mut self,
        expected: &TrustedFat1Floor,
        next: &TrustedFat1Floor,
    ) -> Result<(), Fat1Error> {
        let _lock =
            SnapshotWriterLock::acquire(&self.path).map_err(|_| Fat1Error::FloorUnavailable)?;
        let current = load_unlocked(&self.path).map_err(|e| e.as_fat1_error())?;
        if &current != expected {
            return Err(Fat1Error::FloorCasConflict);
        }
        if next.network_id != current.network_id {
            return Err(Fat1Error::TrustFloorNetworkMismatch);
        }
        if current.trust_epoch.checked_add(1) != Some(next.trust_epoch)
            || next.record_id == [0; 32]
            || next.envelope_id == [0; 32]
        {
            return Err(Fat1Error::FloorCasConflict);
        }
        persist_atomic(&self.path, next).map_err(|e| e.as_fat1_error())?;
        let read_back = load_unlocked(&self.path).map_err(|e| e.as_fat1_error())?;
        if read_back != *next {
            return Err(Fat1Error::FloorCasConflict);
        }
        Ok(())
    }
}

fn encode_floor(floor: &TrustedFat1Floor) -> Result<[u8; FLOOR_BYTES], DurableFat1FloorError> {
    if floor.network_id == [0; 32]
        || (floor.trust_epoch == 0 && (floor.record_id != [0; 32] || floor.envelope_id != [0; 32]))
        || (floor.trust_epoch != 0 && (floor.record_id == [0; 32] || floor.envelope_id == [0; 32]))
    {
        return Err(DurableFat1FloorError::InvalidEncoding);
    }
    let mut bytes = [0u8; FLOOR_BYTES];
    bytes[0..4].copy_from_slice(MAGIC);
    bytes[4..6].copy_from_slice(&VERSION.to_be_bytes());
    bytes[6..8].copy_from_slice(&0u16.to_be_bytes());
    bytes[NETWORK_OFFSET..EPOCH_OFFSET].copy_from_slice(&floor.network_id);
    bytes[EPOCH_OFFSET..RECORD_OFFSET].copy_from_slice(&floor.trust_epoch.to_be_bytes());
    bytes[RECORD_OFFSET..ENVELOPE_OFFSET].copy_from_slice(&floor.record_id);
    bytes[ENVELOPE_OFFSET..CORE_BYTES].copy_from_slice(&floor.envelope_id);
    let mut hasher = Sha256::new();
    hasher.update(FLOOR_CHECKSUM_DOMAIN);
    hasher.update(&bytes[..CORE_BYTES]);
    bytes[CORE_BYTES..].copy_from_slice(&hasher.finalize());
    Ok(bytes)
}

fn decode_floor(bytes: &[u8]) -> Result<TrustedFat1Floor, DurableFat1FloorError> {
    if bytes.len() != FLOOR_BYTES
        || &bytes[..4] != MAGIC
        || u16::from_be_bytes(
            bytes[4..6]
                .try_into()
                .map_err(|_| DurableFat1FloorError::InvalidEncoding)?,
        ) != VERSION
        || bytes[6..8] != [0, 0]
    {
        return Err(DurableFat1FloorError::InvalidEncoding);
    }
    let mut hasher = Sha256::new();
    hasher.update(FLOOR_CHECKSUM_DOMAIN);
    hasher.update(&bytes[..CORE_BYTES]);
    if hasher.finalize().as_slice() != &bytes[CORE_BYTES..] {
        return Err(DurableFat1FloorError::InvalidEncoding);
    }
    let network_id = bytes[NETWORK_OFFSET..NETWORK_OFFSET + 32]
        .try_into()
        .map_err(|_| DurableFat1FloorError::InvalidEncoding)?;
    let trust_epoch = u64::from_be_bytes(
        bytes[EPOCH_OFFSET..RECORD_OFFSET]
            .try_into()
            .map_err(|_| DurableFat1FloorError::InvalidEncoding)?,
    );
    let record_id = bytes[RECORD_OFFSET..ENVELOPE_OFFSET]
        .try_into()
        .map_err(|_| DurableFat1FloorError::InvalidEncoding)?;
    let envelope_id = bytes[ENVELOPE_OFFSET..CORE_BYTES]
        .try_into()
        .map_err(|_| DurableFat1FloorError::InvalidEncoding)?;
    let floor = TrustedFat1Floor {
        network_id,
        trust_epoch,
        record_id,
        envelope_id,
    };
    encode_floor(&floor)?;
    Ok(floor)
}

fn load_unlocked(path: &Path) -> Result<TrustedFat1Floor, DurableFat1FloorError> {
    let mut file = File::open(path).map_err(|e| {
        if e.kind() == io::ErrorKind::NotFound {
            DurableFat1FloorError::Missing
        } else {
            DurableFat1FloorError::Io(e)
        }
    })?;
    let length = file.metadata()?.len();
    if length != FLOOR_BYTES as u64 {
        return Err(DurableFat1FloorError::InvalidEncoding);
    }
    let mut bytes = Vec::with_capacity(FLOOR_BYTES);
    Read::by_ref(&mut file)
        .take((FLOOR_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    decode_floor(&bytes)
}

fn persist_atomic(path: &Path, floor: &TrustedFat1Floor) -> Result<(), DurableFat1FloorError> {
    let bytes = encode_floor(floor)?;
    let parent = parent_directory(path);
    if !parent.is_dir() {
        return Err(DurableFat1FloorError::InvalidPath);
    }
    let final_name = path.file_name().ok_or(DurableFat1FloorError::InvalidPath)?;
    let mut temp_name = OsString::from(".");
    temp_name.push(final_name);
    temp_name.push(format!(
        ".fat1-floor.{}.{}.tmp",
        std::process::id(),
        NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed)
    ));
    let temp_path = parent.join(temp_name);
    let result = (|| -> io::Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp_path)?;
        file.write_all(&bytes)?;
        file.flush()?;
        file.sync_all()?;
        drop(file);
        atomic_replace(&temp_path, path)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp_path);
    }
    result.map_err(DurableFat1FloorError::Io)
}

fn parent_directory(path: &Path) -> &Path {
    path.parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

#[cfg(windows)]
fn atomic_replace(source: &Path, destination: &Path) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    const MOVEFILE_REPLACE_EXISTING: u32 = 0x1;
    const MOVEFILE_WRITE_THROUGH: u32 = 0x8;
    let source_wide: Vec<u16> = source
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let destination_wide: Vec<u16> = destination
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    #[link(name = "Kernel32")]
    extern "system" {
        fn MoveFileExW(existing: *const u16, new_name: *const u16, flags: u32) -> i32;
    }
    // SAFETY: both paths are NUL-terminated UTF-16 buffers valid for this call.
    let result = unsafe {
        MoveFileExW(
            source_wide.as_ptr(),
            destination_wide.as_ptr(),
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
    fs::rename(source, destination)?;
    #[cfg(unix)]
    File::open(parent_directory(destination))?.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        process::{Child, Command, Stdio},
        thread,
        time::{Duration, Instant},
    };

    static TEST_ID: AtomicU64 = AtomicU64::new(1);
    struct TestDir(PathBuf);
    impl TestDir {
        fn new(label: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "cp0227_fat1_floor_{label}_{}_{}",
                std::process::id(),
                TEST_ID.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }
        fn file(&self) -> PathBuf {
            self.0.join("floor.tff1")
        }
    }
    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn floor(epoch: u64, record: u8, envelope: u8) -> TrustedFat1Floor {
        TrustedFat1Floor {
            network_id: [0xA7; 32],
            trust_epoch: epoch,
            record_id: if epoch == 0 { [0; 32] } else { [record; 32] },
            envelope_id: if epoch == 0 { [0; 32] } else { [envelope; 32] },
        }
    }

    #[test]
    fn canonical_wire_is_fixed_size_checksummed_and_roundtrips() {
        let initial = floor(0, 0, 0);
        let encoded = encode_floor(&initial).unwrap();
        assert_eq!(encoded.len(), 144);
        assert_eq!(decode_floor(&encoded).unwrap(), initial);
        let mut changed = encoded;
        changed[45] ^= 1;
        assert!(matches!(
            decode_floor(&changed),
            Err(DurableFat1FloorError::InvalidEncoding)
        ));
        assert!(decode_floor(&encoded[..encoded.len() - 1]).is_err());
    }

    #[test]
    fn initializes_once_fails_closed_and_cas_requires_exact_successor() {
        let dir = TestDir::new("basic");
        let path = dir.file();
        let initial = floor(0, 0, 0);
        let mut store = DurableFat1FloorStore::new(&path);
        store.initialize(&initial).unwrap();
        assert_eq!(store.load_checked(&initial.network_id).unwrap(), initial);
        assert!(matches!(
            store.initialize(&initial),
            Err(DurableFat1FloorError::AlreadyInitialized)
        ));
        assert!(matches!(
            store.compare_and_swap(&initial, &floor(2, 2, 2)),
            Err(Fat1Error::FloorCasConflict)
        ));
        assert!(matches!(
            store.compare_and_swap(&initial, &floor(1, 1, 0)),
            Err(Fat1Error::FloorCasConflict)
        ));
        store
            .compare_and_swap(&initial, &floor(1, 1, 0xB1))
            .unwrap();
        assert_eq!(store.load(&initial.network_id).unwrap(), floor(1, 1, 0xB1));
        assert!(matches!(
            store.load(&[0xBB; 32]),
            Err(Fat1Error::TrustFloorNetworkMismatch)
        ));
        assert!(matches!(
            store.compare_and_swap(&initial, &floor(2, 2, 2)),
            Err(Fat1Error::FloorCasConflict)
        ));
    }

    #[test]
    fn missing_or_corrupt_floor_never_resets_to_epoch_zero() {
        let dir = TestDir::new("fail_closed");
        let path = dir.file();
        let store = DurableFat1FloorStore::new(&path);
        assert!(matches!(
            store.load(&[0xA7; 32]),
            Err(Fat1Error::FloorUnavailable)
        ));
        store.initialize(&floor(0, 0, 0)).unwrap();
        fs::write(&path, b"").unwrap();
        assert!(matches!(
            store.load(&[0xA7; 32]),
            Err(Fat1Error::FloorUnavailable)
        ));
        assert!(matches!(
            store.initialize(&floor(0, 0, 0)),
            Err(DurableFat1FloorError::AlreadyInitialized)
        ));
    }

    fn wait_for_marker(child: &mut Child, marker: &Path) {
        let deadline = Instant::now() + Duration::from_secs(15);
        while Instant::now() < deadline {
            if marker.exists() {
                return;
            }
            if let Some(status) = child.try_wait().unwrap() {
                panic!("crash probe exited before marker: {status:?}");
            }
            thread::sleep(Duration::from_millis(20));
        }
        let _ = child.kill();
        let _ = child.wait();
        panic!("crash probe marker timeout");
    }

    #[test]
    fn child_process_crash_probe() {
        let Ok(mode) = std::env::var("CP0227_FAT1_CHILD_MODE") else {
            return;
        };
        let path = PathBuf::from(std::env::var_os("CP0227_FAT1_CHILD_PATH").unwrap());
        let marker = PathBuf::from(std::env::var_os("CP0227_FAT1_CHILD_MARKER").unwrap());
        let store = DurableFat1FloorStore::new(&path);
        let _lock = SnapshotWriterLock::acquire(&path).unwrap();
        match mode.as_str() {
            "before_commit" => {
                let temp =
                    path.with_file_name(format!("floor.crash-orphan.{}.tmp", std::process::id()));
                let mut f = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(temp)
                    .unwrap();
                f.write_all(b"TFF1 partial commit").unwrap();
                f.sync_all().unwrap();
            }
            "after_commit" => {
                store
                    .persist_locked_for_test(&floor(1, 0x51, 0x61))
                    .unwrap();
            }
            _ => panic!("unknown child crash mode"),
        }
        File::create(&marker).unwrap().sync_all().unwrap();
        loop {
            thread::sleep(Duration::from_secs(1));
        }
    }

    fn kill_child_at_stage(path: &Path, marker: &Path, mode: &str) {
        let executable = std::env::current_exe().unwrap();
        let mut child = Command::new(executable)
            .arg("--exact")
            .arg("v4_fat1_disk_floor_candidate::tests::child_process_crash_probe")
            .arg("--nocapture")
            .env("CP0227_FAT1_CHILD_MODE", mode)
            .env("CP0227_FAT1_CHILD_PATH", path)
            .env("CP0227_FAT1_CHILD_MARKER", marker)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        wait_for_marker(&mut child, marker);
        child.kill().unwrap();
        let _ = child.wait().unwrap();
    }

    #[test]
    fn real_child_kill_before_and_after_commit_preserves_only_committed_floor_and_releases_lock() {
        let dir = TestDir::new("kill_restart");
        let path = dir.file();
        let marker1 = dir.0.join("before.marker");
        let marker2 = dir.0.join("after.marker");
        let initial = floor(0, 0, 0);
        let mut store = DurableFat1FloorStore::new(&path);
        store.initialize(&initial).unwrap();

        kill_child_at_stage(&path, &marker1, "before_commit");
        assert_eq!(store.load(&initial.network_id).unwrap(), initial);
        assert!(store
            .compare_and_swap(&initial, &floor(1, 0x51, 0x61))
            .is_ok());
        let epoch1 = floor(1, 0x51, 0x61);

        // Child writes+flushes+atomically installs epoch 1 while holding the OS lock,
        // signals only after installation, then is forcibly killed without Rust destructors.
        kill_child_at_stage(&path, &marker2, "after_commit");
        assert_eq!(store.load(&initial.network_id).unwrap(), epoch1);
        store
            .compare_and_swap(&epoch1, &floor(2, 0x52, 0x62))
            .unwrap();
        assert_eq!(
            store.load(&initial.network_id).unwrap(),
            floor(2, 0x52, 0x62)
        );
    }
}
