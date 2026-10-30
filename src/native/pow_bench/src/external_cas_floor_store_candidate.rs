//! Separate durable high-water state for a QRun external-CAS node.
//!
//! The floor pins the last independently verified ECR1 record and provider object generation
//! outside the mutable node archive directory. It accepts only an exact one-record successor.
//! This detects rollback of the node archive while this floor remains intact; it does not protect
//! against restoring the floor itself (or the entire host) from an older backup. Production still
//! needs a separately administered off-host or hardware-backed monotonic anchor.

use crate::{
    external_cas_anchor_candidate::{ExternalCasError, ExternalCasPin, ExternalCasRecord},
    store_writer_lock::StoreWriterLock,
};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    thread,
    time::Duration,
};

const MAGIC: &[u8; 4] = b"QCF1";
const VERSION: u16 = 1;
const DOMAIN: &[u8] = b"QRUN-V05-EXTERNAL-CAS-FLOOR-V1\0";
const STATE_FILE: &str = "external-cas-floor.qcf1";
const LOCK_FILE: &str = "external-cas-floor.writer.lock";
const PREFIX_BYTES: usize = 448;
const CHECKSUM_BYTES: usize = 32;
const FILE_BYTES: usize = PREFIX_BYTES + CHECKSUM_BYTES;
static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Debug)]
pub enum ExternalCasFloorError {
    Io(io::Error),
    Contract(ExternalCasError),
    InvalidDirectory,
    AlreadyInitialized,
    MissingState,
    CorruptState,
    WrongPin,
    InvalidBootstrap,
    StaleObservation,
    NotExactSuccessor,
    GenerationOverflow,
}
impl std::fmt::Display for ExternalCasFloorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "external-CAS floor I/O failed: {e}"),
            Self::Contract(e) => write!(f, "external-CAS floor record rejected: {e}"),
            Self::InvalidDirectory => write!(f, "external-CAS floor directory is invalid"),
            Self::AlreadyInitialized => write!(f, "external-CAS floor is already initialized"),
            Self::MissingState => write!(f, "initialized external-CAS floor state is missing"),
            Self::CorruptState => write!(f, "external-CAS floor state is corrupt"),
            Self::WrongPin => write!(
                f,
                "external-CAS floor belongs to another provider or Genesis"
            ),
            Self::InvalidBootstrap => write!(f, "external-CAS floor bootstrap is invalid"),
            Self::StaleObservation => write!(f, "external-CAS floor compare-and-swap is stale"),
            Self::NotExactSuccessor => write!(f, "external-CAS floor requires one exact successor"),
            Self::GenerationOverflow => write!(f, "external-CAS floor generation overflow"),
        }
    }
}
impl std::error::Error for ExternalCasFloorError {}
impl From<io::Error> for ExternalCasFloorError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}
impl From<ExternalCasError> for ExternalCasFloorError {
    fn from(value: ExternalCasError) -> Self {
        Self::Contract(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalCasFloorSnapshot {
    pub trusted_record: ExternalCasRecord,
    pub minimum_object_generation: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FloorState {
    object_generation: u64,
    record: ExternalCasRecord,
}
impl FloorState {
    fn validate(&self, pin: &ExternalCasPin) -> Result<(), ExternalCasFloorError> {
        pin.validate()?;
        self.record.validate_shape()?;
        if self.record.provider_id != pin.provider_id
            || self.record.network_id != pin.network_id
            || self.record.genesis_digest != pin.genesis_digest
        {
            return Err(ExternalCasFloorError::WrongPin);
        }
        if self.object_generation == 0
            || self.record.generation.checked_add(1) != Some(self.object_generation)
        {
            return Err(ExternalCasFloorError::CorruptState);
        }
        Ok(())
    }

    fn encode(&self, pin: &ExternalCasPin) -> Result<[u8; FILE_BYTES], ExternalCasFloorError> {
        self.validate(pin)?;
        let mut bytes = Vec::with_capacity(FILE_BYTES);
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&VERSION.to_be_bytes());
        bytes.extend_from_slice(&0u16.to_be_bytes());
        bytes.extend_from_slice(&pin.provider_id);
        bytes.extend_from_slice(&pin.network_id);
        bytes.extend_from_slice(&pin.genesis_digest);
        bytes.extend_from_slice(&pin.receipt_key_id);
        let public_key_hash: [u8; 32] = Sha256::digest(pin.receipt_public_key).into();
        bytes.extend_from_slice(&public_key_hash);
        bytes.extend_from_slice(&self.object_generation.to_be_bytes());
        bytes.extend_from_slice(&self.record.encode()?);
        if bytes.len() != PREFIX_BYTES {
            return Err(ExternalCasFloorError::CorruptState);
        }
        let checksum = checksum(&bytes);
        bytes.extend_from_slice(&checksum);
        bytes
            .try_into()
            .map_err(|_| ExternalCasFloorError::CorruptState)
    }

    fn decode(bytes: &[u8], pin: &ExternalCasPin) -> Result<Self, ExternalCasFloorError> {
        if bytes.len() != FILE_BYTES
            || &bytes[..4] != MAGIC
            || u16::from_be_bytes([bytes[4], bytes[5]]) != VERSION
            || bytes[6..8] != [0, 0]
            || checksum(&bytes[..PREFIX_BYTES]) != bytes[PREFIX_BYTES..]
        {
            return Err(ExternalCasFloorError::CorruptState);
        }
        let public_key_hash: [u8; 32] = Sha256::digest(pin.receipt_public_key).into();
        if bytes[8..40] != pin.provider_id
            || bytes[40..72] != pin.network_id
            || bytes[72..104] != pin.genesis_digest
            || bytes[104..136] != pin.receipt_key_id
            || bytes[136..168] != public_key_hash
        {
            return Err(ExternalCasFloorError::WrongPin);
        }
        let state = Self {
            object_generation: u64::from_be_bytes(
                bytes[168..176]
                    .try_into()
                    .map_err(|_| ExternalCasFloorError::CorruptState)?,
            ),
            record: ExternalCasRecord::decode(&bytes[176..PREFIX_BYTES])?,
        };
        state.validate(pin)?;
        Ok(state)
    }
}

fn checksum(bytes: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(DOMAIN);
    hash.update(bytes);
    hash.finalize().into()
}

/// A pinned ECR1/object-generation high-water mark persisted separately from the mutable node
/// archive. initialize is create-once; open never invents a missing floor.
pub struct ExternalCasFloorStore {
    directory: PathBuf,
    pin: ExternalCasPin,
}
impl std::fmt::Debug for ExternalCasFloorStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExternalCasFloorStore")
            .field("directory", &self.directory)
            .field("provider_id", &self.pin.provider_id)
            .field("network_id", &self.pin.network_id)
            .field("genesis_digest", &self.pin.genesis_digest)
            .field("receipt_key_id", &self.pin.receipt_key_id)
            .finish()
    }
}

impl ExternalCasFloorStore {
    /// Explicitly install the trusted bootstrap record. This must be done from independently
    /// reviewed provisioning data, not by accepting whatever a remote provider first returns.
    pub fn initialize(
        directory: impl AsRef<Path>,
        pin: ExternalCasPin,
        bootstrap: ExternalCasRecord,
        bootstrap_object_generation: u64,
    ) -> Result<Self, ExternalCasFloorError> {
        pin.validate()?;
        let state = FloorState {
            object_generation: bootstrap_object_generation,
            record: bootstrap,
        };
        state.validate(&pin)?;
        if state.record.generation != 0 || state.object_generation != 1 {
            return Err(ExternalCasFloorError::InvalidBootstrap);
        }
        let directory = directory.as_ref().to_path_buf();
        fs::create_dir_all(&directory)?;
        validate_directory(&directory)?;
        let lock_existed = directory.join(LOCK_FILE).exists();
        let _lock = StoreWriterLock::acquire(&directory, LOCK_FILE)?;
        let state_path = directory.join(STATE_FILE);
        if path_exists_no_follow(&state_path)? {
            return Err(ExternalCasFloorError::AlreadyInitialized);
        }
        if lock_existed {
            return Err(ExternalCasFloorError::MissingState);
        }
        write_initial_state(&state_path, &state.encode(&pin)?)?;
        Ok(Self { directory, pin })
    }

    /// Open only an existing floor. A missing state after the lock was once initialized is not
    /// treated as an invitation to trust the remote provider's current answer.
    pub fn open(
        directory: impl AsRef<Path>,
        pin: ExternalCasPin,
    ) -> Result<Self, ExternalCasFloorError> {
        pin.validate()?;
        let directory = directory.as_ref().to_path_buf();
        validate_directory(&directory)?;
        let store = Self { directory, pin };
        let _lock = store.acquire_lock()?;
        store.load_state()?;
        Ok(store)
    }

    pub fn pin(&self) -> &ExternalCasPin {
        &self.pin
    }

    pub fn state_path(&self) -> PathBuf {
        self.directory.join(STATE_FILE)
    }

    pub fn snapshot(&self) -> Result<ExternalCasFloorSnapshot, ExternalCasFloorError> {
        let _lock = self.acquire_lock()?;
        let state = self.load_state()?;
        Ok(ExternalCasFloorSnapshot {
            trusted_record: state.record,
            minimum_object_generation: state.object_generation,
        })
    }

    /// Advance only from the exact currently persisted record and object generation to one
    /// cryptographically linked successor. The caller must verify the remote read/commit receipt
    /// with VerifiedExternalCasClient before calling this method.
    ///
    /// An exact retry is idempotent. A stale writer, skipped generation, altered predecessor or
    /// non-successor is rejected without changing the floor.
    pub fn advance(
        &self,
        expected_record: &ExternalCasRecord,
        expected_object_generation: u64,
        next_record: &ExternalCasRecord,
        next_object_generation: u64,
    ) -> Result<(), ExternalCasFloorError> {
        expected_record.validate_shape()?;
        next_record.validate_shape()?;
        if expected_record.provider_id != self.pin.provider_id
            || expected_record.network_id != self.pin.network_id
            || expected_record.genesis_digest != self.pin.genesis_digest
            || next_record.provider_id != self.pin.provider_id
            || next_record.network_id != self.pin.network_id
            || next_record.genesis_digest != self.pin.genesis_digest
        {
            return Err(ExternalCasFloorError::WrongPin);
        }
        if expected_object_generation == 0
            || expected_object_generation.checked_add(1) != Some(next_object_generation)
            || next_record.generation
                != expected_record
                    .generation
                    .checked_add(1)
                    .ok_or(ExternalCasFloorError::GenerationOverflow)?
        {
            return Err(ExternalCasFloorError::NotExactSuccessor);
        }
        expected_record.validate_successor(next_record)?;

        let _lock = self.acquire_lock()?;
        let current = self.load_state()?;
        if current.record == *next_record && current.object_generation == next_object_generation {
            return Ok(());
        }
        if current.record != *expected_record
            || current.object_generation != expected_object_generation
        {
            return Err(ExternalCasFloorError::StaleObservation);
        }

        let next = FloorState {
            object_generation: next_object_generation,
            record: next_record.clone(),
        };
        write_state_atomic(&self.state_path(), &next.encode(&self.pin)?)?;
        Ok(())
    }

    /// Reconcile the floor after a process restart. The caller must first obtain and verify a fresh
    /// signed provider read. This method accepts only the same record or one exact successor;
    /// larger remote jumps require independent intermediate evidence and are rejected.
    pub fn reconcile_verified_observation(
        &self,
        observed_record: &ExternalCasRecord,
        observed_object_generation: u64,
    ) -> Result<(), ExternalCasFloorError> {
        let current = self.snapshot()?;
        if current.trusted_record == *observed_record
            && current.minimum_object_generation == observed_object_generation
        {
            return Ok(());
        }
        self.advance(
            &current.trusted_record,
            current.minimum_object_generation,
            observed_record,
            observed_object_generation,
        )
    }

    fn acquire_lock(&self) -> Result<StoreWriterLock, ExternalCasFloorError> {
        const ATTEMPTS: usize = 200;
        for attempt in 0..ATTEMPTS {
            match StoreWriterLock::acquire(&self.directory, LOCK_FILE) {
                Ok(lock) => return Ok(lock),
                Err(error)
                    if error.kind() == io::ErrorKind::WouldBlock && attempt + 1 < ATTEMPTS =>
                {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(error) => return Err(ExternalCasFloorError::Io(error)),
            }
        }
        Err(ExternalCasFloorError::Io(io::Error::new(
            io::ErrorKind::WouldBlock,
            "external-CAS floor writer lock deadline elapsed",
        )))
    }

    fn load_state(&self) -> Result<FloorState, ExternalCasFloorError> {
        let path = self.state_path();
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Err(ExternalCasFloorError::MissingState)
            }
            Err(error) => return Err(ExternalCasFloorError::Io(error)),
        };
        if !metadata.file_type().is_file() || metadata.len() != FILE_BYTES as u64 {
            return Err(ExternalCasFloorError::CorruptState);
        }
        let file = File::open(path)?;
        let mut bytes = Vec::with_capacity(FILE_BYTES);
        file.take((FILE_BYTES + 1) as u64).read_to_end(&mut bytes)?;
        FloorState::decode(&bytes, &self.pin)
    }
}

fn validate_directory(directory: &Path) -> Result<(), ExternalCasFloorError> {
    let metadata = fs::symlink_metadata(directory).map_err(|error| {
        if error.kind() == io::ErrorKind::NotFound {
            ExternalCasFloorError::InvalidDirectory
        } else {
            ExternalCasFloorError::Io(error)
        }
    })?;
    if !metadata.file_type().is_dir() {
        return Err(ExternalCasFloorError::InvalidDirectory);
    }
    Ok(())
}

fn path_exists_no_follow(path: &Path) -> Result<bool, ExternalCasFloorError> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(ExternalCasFloorError::Io(error)),
    }
}

fn write_initial_state(path: &Path, bytes: &[u8]) -> Result<(), ExternalCasFloorError> {
    let parent = path
        .parent()
        .ok_or(ExternalCasFloorError::InvalidDirectory)?;
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    let result = file
        .write_all(bytes)
        .and_then(|_| file.flush())
        .and_then(|_| file.sync_all());
    drop(file);
    if let Err(error) = result {
        let _ = fs::remove_file(path);
        return Err(ExternalCasFloorError::Io(error));
    }
    sync_parent(parent)?;
    Ok(())
}

fn write_state_atomic(path: &Path, bytes: &[u8]) -> Result<(), ExternalCasFloorError> {
    if bytes.len() != FILE_BYTES {
        return Err(ExternalCasFloorError::CorruptState);
    }
    let parent = path
        .parent()
        .ok_or(ExternalCasFloorError::InvalidDirectory)?;
    let final_name = path
        .file_name()
        .ok_or(ExternalCasFloorError::InvalidDirectory)?;
    let temp = unique_temp_path(parent, final_name)?;
    let mut cleanup = TempCleanup::new(temp.clone());
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temp)?;
    let result = file
        .write_all(bytes)
        .and_then(|_| file.flush())
        .and_then(|_| file.sync_all());
    drop(file);
    if let Err(error) = result {
        return Err(ExternalCasFloorError::Io(error));
    }
    atomic_replace(&temp, path)?;
    cleanup.disarm();
    sync_parent(parent)?;
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

fn unique_temp_path(
    parent: &Path,
    final_name: &std::ffi::OsStr,
) -> Result<PathBuf, ExternalCasFloorError> {
    let sequence = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
    let mut random = [0u8; 16];
    getrandom::getrandom(&mut random).map_err(|error| {
        ExternalCasFloorError::Io(io::Error::new(io::ErrorKind::Other, error.to_string()))
    })?;
    let mut name = std::ffi::OsString::from(".");
    name.push(final_name);
    name.push(format!(".{}.{}.", std::process::id(), sequence));
    for byte in random {
        name.push(format!("{byte:02x}"));
    }
    name.push(".tmp");
    Ok(parent.join(name))
}

#[cfg(windows)]
fn atomic_replace(source: &Path, destination: &Path) -> Result<(), ExternalCasFloorError> {
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
    let success = unsafe {
        MoveFileExW(
            from.as_ptr(),
            to.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if success == 0 {
        Err(ExternalCasFloorError::Io(io::Error::last_os_error()))
    } else {
        Ok(())
    }
}
#[cfg(not(windows))]
fn atomic_replace(source: &Path, destination: &Path) -> Result<(), ExternalCasFloorError> {
    fs::rename(source, destination)?;
    Ok(())
}
#[cfg(windows)]
fn sync_parent(_directory: &Path) -> Result<(), ExternalCasFloorError> {
    Ok(())
}
#[cfg(unix)]
fn sync_parent(directory: &Path) -> Result<(), ExternalCasFloorError> {
    File::open(directory)?.sync_all()?;
    Ok(())
}
#[cfg(not(any(windows, unix)))]
fn sync_parent(_directory: &Path) -> Result<(), ExternalCasFloorError> {
    Err(ExternalCasFloorError::Io(io::Error::new(
        io::ErrorKind::Unsupported,
        "external-CAS floor directory sync is unsupported on this target",
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use libcrux_ml_dsa::ml_dsa_65::portable;
    use std::{
        sync::{Arc, Barrier},
        thread,
        time::{SystemTime, UNIX_EPOCH},
    };

    struct TestDir(PathBuf);
    impl TestDir {
        fn new() -> Self {
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "qrun_external_cas_floor_{}_{}",
                std::process::id(),
                nonce
            ));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn setup() -> (ExternalCasPin, ExternalCasRecord) {
        let keys = portable::generate_key_pair([0xE1u8; 32]);
        let public_key: [u8; crate::v4_fat1_trust_candidate::ML_DSA_65_PUBLIC_KEY_BYTES] =
            *keys.verification_key.as_ref();
        let pin = ExternalCasPin {
            provider_id: [0x11; 32],
            network_id: [0x22; 32],
            genesis_digest: [0x33; 32],
            receipt_key_id: [0x44; 32],
            receipt_public_key: public_key,
        };
        let bootstrap = ExternalCasRecord {
            generation: 0,
            provider_id: pin.provider_id,
            network_id: pin.network_id,
            genesis_digest: pin.genesis_digest,
            previous_record_digest: [0; 32],
            previous_state_digest: [0; 32],
            next_state_digest: [0x55; 32],
            operation_id: [0x66; 32],
            request_digest: [0x77; 32],
        };
        (pin, bootstrap)
    }

    fn successor(
        pin: &ExternalCasPin,
        previous: &ExternalCasRecord,
        operation: u8,
        state: u8,
    ) -> ExternalCasRecord {
        ExternalCasRecord {
            generation: previous.generation + 1,
            provider_id: pin.provider_id,
            network_id: pin.network_id,
            genesis_digest: pin.genesis_digest,
            previous_record_digest: previous.digest().unwrap(),
            previous_state_digest: previous.next_state_digest,
            next_state_digest: [state; 32],
            operation_id: [operation; 32],
            request_digest: [operation.wrapping_add(1); 32],
        }
    }

    #[test]
    fn floor_initializes_once_reopens_and_binds_all_provider_pins() {
        let dir = TestDir::new();
        let (pin, bootstrap) = setup();
        let store =
            ExternalCasFloorStore::initialize(&dir.0, pin.clone(), bootstrap.clone(), 1).unwrap();
        assert!(store.state_path().exists());
        assert_eq!(
            store.snapshot().unwrap(),
            ExternalCasFloorSnapshot {
                trusted_record: bootstrap.clone(),
                minimum_object_generation: 1,
            }
        );
        assert!(matches!(
            ExternalCasFloorStore::initialize(&dir.0, pin.clone(), bootstrap, 1),
            Err(ExternalCasFloorError::AlreadyInitialized)
        ));
        drop(store);

        let reopened = ExternalCasFloorStore::open(&dir.0, pin.clone()).unwrap();
        assert_eq!(reopened.snapshot().unwrap().minimum_object_generation, 1);

        let mut wrong_pin = pin;
        wrong_pin.receipt_key_id = [0x99; 32];
        assert!(matches!(
            ExternalCasFloorStore::open(&dir.0, wrong_pin),
            Err(ExternalCasFloorError::WrongPin)
        ));
    }

    #[test]
    fn floor_advance_is_exact_monotonic_and_idempotent() {
        let dir = TestDir::new();
        let (pin, bootstrap) = setup();
        let store =
            ExternalCasFloorStore::initialize(&dir.0, pin.clone(), bootstrap.clone(), 1).unwrap();
        let first = successor(&pin, &bootstrap, 0x81, 0x82);

        store.advance(&bootstrap, 1, &first, 2).unwrap();
        store.advance(&bootstrap, 1, &first, 2).unwrap();
        assert_eq!(
            store.snapshot().unwrap(),
            ExternalCasFloorSnapshot {
                trusted_record: first.clone(),
                minimum_object_generation: 2,
            }
        );

        let competing = successor(&pin, &bootstrap, 0x83, 0x84);
        assert!(matches!(
            store.advance(&bootstrap, 1, &competing, 2),
            Err(ExternalCasFloorError::StaleObservation)
        ));

        let skipped = successor(&pin, &first, 0x85, 0x86);
        assert!(matches!(
            store.advance(&first, 2, &skipped, 4),
            Err(ExternalCasFloorError::NotExactSuccessor)
        ));
        assert_eq!(store.snapshot().unwrap().trusted_record, first);
    }

    #[test]
    fn verified_observation_reconciliation_accepts_only_same_record_or_one_successor() {
        let dir = TestDir::new();
        let (pin, bootstrap) = setup();
        let store =
            ExternalCasFloorStore::initialize(&dir.0, pin.clone(), bootstrap.clone(), 1).unwrap();
        store.reconcile_verified_observation(&bootstrap, 1).unwrap();

        let first = successor(&pin, &bootstrap, 0x91, 0x92);
        store.reconcile_verified_observation(&first, 2).unwrap();
        assert_eq!(store.snapshot().unwrap().trusted_record, first);

        let current_record = store.snapshot().unwrap().trusted_record;
        let second = successor(&pin, &current_record, 0x93, 0x94);
        assert!(matches!(
            store.reconcile_verified_observation(&second, 4),
            Err(ExternalCasFloorError::NotExactSuccessor)
        ));
        assert_eq!(store.snapshot().unwrap().minimum_object_generation, 2);
    }

    #[test]
    fn concurrent_floor_writers_cannot_replace_one_another_from_the_same_predecessor() {
        let dir = TestDir::new();
        let (pin, bootstrap) = setup();
        let store = Arc::new(
            ExternalCasFloorStore::initialize(&dir.0, pin.clone(), bootstrap.clone(), 1).unwrap(),
        );
        let first = successor(&pin, &bootstrap, 0xA1, 0xA2);
        let second = successor(&pin, &bootstrap, 0xA3, 0xA4);
        let gate = Arc::new(Barrier::new(3));

        let store_a = store.clone();
        let gate_a = gate.clone();
        let first_a = first.clone();
        let bootstrap_a = bootstrap.clone();
        let thread_a = thread::spawn(move || {
            gate_a.wait();
            store_a.advance(&bootstrap_a, 1, &first_a, 2)
        });

        let store_b = store.clone();
        let gate_b = gate.clone();
        let bootstrap_b = bootstrap.clone();
        let thread_b = thread::spawn(move || {
            gate_b.wait();
            store_b.advance(&bootstrap_b, 1, &second, 2)
        });
        gate.wait();

        let result_a = thread_a.join().unwrap();
        let result_b = thread_b.join().unwrap();
        assert_ne!(result_a.is_ok(), result_b.is_ok());
        let loser = if result_a.is_err() {
            result_a
        } else {
            result_b
        };
        assert!(matches!(
            loser,
            Err(ExternalCasFloorError::StaleObservation)
        ));
        let current = store.snapshot().unwrap();
        assert_eq!(current.minimum_object_generation, 2);
        assert!(
            current.trusted_record == first || current.trusted_record.operation_id == [0xA3; 32]
        );
    }

    #[test]
    fn initialized_floor_does_not_rebootstrap_after_state_deletion_or_corruption() {
        let dir = TestDir::new();
        let (pin, bootstrap) = setup();
        let store = ExternalCasFloorStore::initialize(&dir.0, pin.clone(), bootstrap, 1).unwrap();
        let state_path = store.state_path();
        drop(store);

        fs::remove_file(&state_path).unwrap();
        assert!(matches!(
            ExternalCasFloorStore::open(&dir.0, pin.clone()),
            Err(ExternalCasFloorError::MissingState)
        ));
        assert!(matches!(
            ExternalCasFloorStore::initialize(
                &dir.0,
                pin.clone(),
                ExternalCasRecord {
                    generation: 0,
                    provider_id: pin.provider_id,
                    network_id: pin.network_id,
                    genesis_digest: pin.genesis_digest,
                    previous_record_digest: [0; 32],
                    previous_state_digest: [0; 32],
                    next_state_digest: [0x55; 32],
                    operation_id: [0x66; 32],
                    request_digest: [0x77; 32],
                },
                1
            ),
            Err(ExternalCasFloorError::MissingState)
        ));
    }

    #[test]
    fn floor_rejects_corrupt_bytes_without_fallback() {
        let dir = TestDir::new();
        let (pin, bootstrap) = setup();
        let store = ExternalCasFloorStore::initialize(&dir.0, pin.clone(), bootstrap, 1).unwrap();
        let state_path = store.state_path();
        drop(store);

        let mut bytes = fs::read(&state_path).unwrap();
        bytes[188] ^= 0x40;
        fs::write(&state_path, bytes).unwrap();
        assert!(matches!(
            ExternalCasFloorStore::open(&dir.0, pin),
            Err(ExternalCasFloorError::CorruptState)
        ));
    }
}
