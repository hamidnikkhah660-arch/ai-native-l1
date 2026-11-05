//! Local durable Q6EA state adapter for development and process-recovery qualification.
//!
//! This adapter serializes cooperating processes with an OS writer lock and commits a complete
//! pinned state file via atomic replacement. It is NOT an independent administrative domain,
//! hardware monotonic counter, cloud conditional-write service, or defense against restoration
//! of the entire host/filesystem from an older backup. Production Q6EA must use a separately
//! administered conditional-write store (for example the DynamoDB adapter) and independent
//! anti-rollback/recovery controls.

use crate::{
    external_cas_anchor_candidate::ExternalCasPin,
    external_cas_offhost_anchor_candidate::ExternalCasOffhostAnchorState,
    external_cas_offhost_anchor_protocol_candidate::{
        decode_state, encode_state, ExternalCasOffhostAnchorPin, ExternalCasOffhostAnchorStore,
        ExternalCasOffhostAnchorStoreCasOutcome, ExternalCasOffhostAnchorStoreError,
        ExternalCasOffhostAnchorStoreProvisionOutcome, OFFHOST_ANCHOR_STATE_BYTES,
    },
    store_writer_lock::StoreWriterLock,
    v4_fat1_trust_candidate::ML_DSA_65_PUBLIC_KEY_BYTES,
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

const MAGIC: &[u8; 4] = b"QAF1";
const VERSION: u16 = 1;
const DOMAIN: &[u8] = b"QRUN-OFFHOST-ANCHOR-LOCAL-FILE-STORE-V1\0";
const STATE_FILE: &str = "q6ea-anchor-state.qaf1";
const LOCK_FILE: &str = "q6ea-anchor-writer.lock";
const HEADER_BYTES: usize = 8 + (8 * 32);
const PREFIX_BYTES: usize = HEADER_BYTES + OFFHOST_ANCHOR_STATE_BYTES;
const CHECKSUM_BYTES: usize = 32;
const FILE_BYTES: usize = PREFIX_BYTES + CHECKSUM_BYTES;
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(1);

fn checksum(bytes: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(DOMAIN);
    hash.update(bytes);
    hash.finalize().into()
}
fn public_key_hash(key: &[u8; ML_DSA_65_PUBLIC_KEY_BYTES]) -> [u8; 32] {
    Sha256::digest(key).into()
}
fn exists_no_follow(path: &Path) -> Result<bool, ExternalCasOffhostAnchorStoreError> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err(ExternalCasOffhostAnchorStoreError::Unavailable),
    }
}
fn validate_directory(path: &Path) -> Result<(), ExternalCasOffhostAnchorStoreError> {
    let metadata =
        fs::symlink_metadata(path).map_err(|_| ExternalCasOffhostAnchorStoreError::Unavailable)?;
    if !metadata.file_type().is_dir() {
        return Err(ExternalCasOffhostAnchorStoreError::Unavailable);
    }
    Ok(())
}

pub struct ExternalCasOffhostAnchorFileStore {
    directory: PathBuf,
    anchor_pin: ExternalCasOffhostAnchorPin,
    provider_pin: ExternalCasPin,
}
impl std::fmt::Debug for ExternalCasOffhostAnchorFileStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExternalCasOffhostAnchorFileStore")
            .field("directory", &self.directory)
            .field("anchor_id", &self.anchor_pin.anchor_id)
            .field("provider_id", &self.provider_pin.provider_id)
            .field("network_id", &self.provider_pin.network_id)
            .field(
                "warning",
                &"local development store; not an independent production anchor",
            )
            .finish()
    }
}
impl ExternalCasOffhostAnchorFileStore {
    /// Open only an already-provisioned state. This method never invents a bootstrap.
    pub fn open(
        directory: impl AsRef<Path>,
        anchor_pin: ExternalCasOffhostAnchorPin,
        provider_pin: ExternalCasPin,
    ) -> Result<Self, ExternalCasOffhostAnchorStoreError> {
        anchor_pin
            .validate(&provider_pin)
            .map_err(|_| ExternalCasOffhostAnchorStoreError::Corrupt)?;
        let directory = directory.as_ref().to_path_buf();
        validate_directory(&directory)?;
        let store = Self {
            directory,
            anchor_pin,
            provider_pin,
        };
        let _lock = store.acquire_lock()?;
        store.load_unlocked()?;
        Ok(store)
    }

    /// Explicit one-time local provisioning. Existing state is returned, never overwritten.
    pub fn provision(
        directory: impl AsRef<Path>,
        anchor_pin: ExternalCasOffhostAnchorPin,
        provider_pin: ExternalCasPin,
        bootstrap: ExternalCasOffhostAnchorState,
    ) -> Result<
        (Self, ExternalCasOffhostAnchorStoreProvisionOutcome),
        ExternalCasOffhostAnchorStoreError,
    > {
        anchor_pin
            .validate(&provider_pin)
            .map_err(|_| ExternalCasOffhostAnchorStoreError::Corrupt)?;
        bootstrap
            .validate(&provider_pin)
            .map_err(|_| ExternalCasOffhostAnchorStoreError::Corrupt)?;
        if bootstrap.sequence != 1
            || bootstrap.provider_object_generation != 1
            || bootstrap.provider_record.generation != 0
        {
            return Err(ExternalCasOffhostAnchorStoreError::Corrupt);
        }
        let directory = directory.as_ref().to_path_buf();
        fs::create_dir_all(&directory)
            .map_err(|_| ExternalCasOffhostAnchorStoreError::Unavailable)?;
        validate_directory(&directory)?;
        let store = Self {
            directory,
            anchor_pin,
            provider_pin,
        };
        let _lock = store.acquire_lock()?;
        let path = store.state_path();
        let outcome = if exists_no_follow(&path)? {
            ExternalCasOffhostAnchorStoreProvisionOutcome::AlreadyExists(store.load_unlocked()?)
        } else {
            store.write_initial(&bootstrap)?;
            ExternalCasOffhostAnchorStoreProvisionOutcome::Provisioned
        };
        Ok((store, outcome))
    }

    pub fn state_path(&self) -> PathBuf {
        self.directory.join(STATE_FILE)
    }

    fn acquire_lock(&self) -> Result<StoreWriterLock, ExternalCasOffhostAnchorStoreError> {
        const ATTEMPTS: usize = 200;
        for attempt in 0..ATTEMPTS {
            match StoreWriterLock::acquire(&self.directory, LOCK_FILE) {
                Ok(lock) => return Ok(lock),
                Err(error)
                    if error.kind() == io::ErrorKind::WouldBlock && attempt + 1 < ATTEMPTS =>
                {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(_) => return Err(ExternalCasOffhostAnchorStoreError::Unavailable),
            }
        }
        Err(ExternalCasOffhostAnchorStoreError::Unavailable)
    }

    fn encode_file(
        &self,
        state: &ExternalCasOffhostAnchorState,
    ) -> Result<[u8; FILE_BYTES], ExternalCasOffhostAnchorStoreError> {
        state
            .validate(&self.provider_pin)
            .map_err(|_| ExternalCasOffhostAnchorStoreError::Corrupt)?;
        let wire = encode_state(state).map_err(|_| ExternalCasOffhostAnchorStoreError::Corrupt)?;
        let mut bytes = Vec::with_capacity(FILE_BYTES);
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&VERSION.to_be_bytes());
        bytes.extend_from_slice(&0u16.to_be_bytes());
        bytes.extend_from_slice(&self.anchor_pin.anchor_id);
        bytes.extend_from_slice(&self.provider_pin.provider_id);
        bytes.extend_from_slice(&self.provider_pin.network_id);
        bytes.extend_from_slice(&self.provider_pin.genesis_digest);
        bytes.extend_from_slice(&self.provider_pin.receipt_key_id);
        bytes.extend_from_slice(&public_key_hash(&self.provider_pin.receipt_public_key));
        bytes.extend_from_slice(&self.anchor_pin.receipt_key_id);
        bytes.extend_from_slice(&public_key_hash(&self.anchor_pin.receipt_public_key));
        if bytes.len() != HEADER_BYTES {
            return Err(ExternalCasOffhostAnchorStoreError::Corrupt);
        }
        bytes.extend_from_slice(&wire);
        let digest = checksum(&bytes);
        bytes.extend_from_slice(&digest);
        bytes
            .try_into()
            .map_err(|_| ExternalCasOffhostAnchorStoreError::Corrupt)
    }

    fn decode_file(
        &self,
        bytes: &[u8],
    ) -> Result<ExternalCasOffhostAnchorState, ExternalCasOffhostAnchorStoreError> {
        if bytes.len() != FILE_BYTES
            || &bytes[..4] != MAGIC
            || u16::from_be_bytes([bytes[4], bytes[5]]) != VERSION
            || bytes[6..8] != [0, 0]
            || checksum(&bytes[..PREFIX_BYTES]) != bytes[PREFIX_BYTES..]
        {
            return Err(ExternalCasOffhostAnchorStoreError::Corrupt);
        }
        let fields: [(&[u8], &[u8]); 8] = [
            (&bytes[8..40], &self.anchor_pin.anchor_id),
            (&bytes[40..72], &self.provider_pin.provider_id),
            (&bytes[72..104], &self.provider_pin.network_id),
            (&bytes[104..136], &self.provider_pin.genesis_digest),
            (&bytes[136..168], &self.provider_pin.receipt_key_id),
            (
                &bytes[168..200],
                &public_key_hash(&self.provider_pin.receipt_public_key),
            ),
            (&bytes[200..232], &self.anchor_pin.receipt_key_id),
            (
                &bytes[232..264],
                &public_key_hash(&self.anchor_pin.receipt_public_key),
            ),
        ];
        if fields.iter().any(|(actual, expected)| *actual != *expected) {
            return Err(ExternalCasOffhostAnchorStoreError::Corrupt);
        }
        let state = decode_state(&bytes[HEADER_BYTES..PREFIX_BYTES])
            .map_err(|_| ExternalCasOffhostAnchorStoreError::Corrupt)?;
        state
            .validate(&self.provider_pin)
            .map_err(|_| ExternalCasOffhostAnchorStoreError::Corrupt)?;
        Ok(state)
    }

    fn load_unlocked(
        &self,
    ) -> Result<ExternalCasOffhostAnchorState, ExternalCasOffhostAnchorStoreError> {
        let path = self.state_path();
        let metadata = fs::symlink_metadata(&path)
            .map_err(|_| ExternalCasOffhostAnchorStoreError::Unavailable)?;
        if !metadata.file_type().is_file() || metadata.len() != FILE_BYTES as u64 {
            return Err(ExternalCasOffhostAnchorStoreError::Corrupt);
        }
        let file = File::open(path).map_err(|_| ExternalCasOffhostAnchorStoreError::Unavailable)?;
        let mut bytes = Vec::with_capacity(FILE_BYTES);
        file.take((FILE_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|_| ExternalCasOffhostAnchorStoreError::Unavailable)?;
        self.decode_file(&bytes)
    }

    fn write_initial(
        &self,
        state: &ExternalCasOffhostAnchorState,
    ) -> Result<(), ExternalCasOffhostAnchorStoreError> {
        let bytes = self.encode_file(state)?;
        let path = self.state_path();
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .map_err(|_| ExternalCasOffhostAnchorStoreError::Unavailable)?;
        file.write_all(&bytes)
            .and_then(|_| file.flush())
            .and_then(|_| file.sync_all())
            .map_err(|_| ExternalCasOffhostAnchorStoreError::Unavailable)?;
        sync_parent(&self.directory)?;
        Ok(())
    }

    fn write_atomic(
        &self,
        state: &ExternalCasOffhostAnchorState,
    ) -> Result<(), ExternalCasOffhostAnchorStoreError> {
        let bytes = self.encode_file(state)?;
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let mut random = [0u8; 16];
        getrandom::getrandom(&mut random)
            .map_err(|_| ExternalCasOffhostAnchorStoreError::Unavailable)?;
        let mut name = std::ffi::OsString::from(".");
        name.push(STATE_FILE);
        name.push(format!(".{}.{}.", std::process::id(), sequence));
        for byte in random {
            name.push(format!("{byte:02x}"));
        }
        name.push(".tmp");
        let temp = self.directory.join(name);
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp)
            .map_err(|_| ExternalCasOffhostAnchorStoreError::Unavailable)?;
        let write_result = file
            .write_all(&bytes)
            .and_then(|_| file.flush())
            .and_then(|_| file.sync_all());
        drop(file);
        if write_result.is_err() {
            let _ = fs::remove_file(&temp);
            return Err(ExternalCasOffhostAnchorStoreError::Unavailable);
        }
        if atomic_replace(&temp, &self.state_path()).is_err() {
            let _ = fs::remove_file(&temp);
            return Err(ExternalCasOffhostAnchorStoreError::Unavailable);
        }
        sync_parent(&self.directory)?;
        Ok(())
    }
}

impl ExternalCasOffhostAnchorStore for ExternalCasOffhostAnchorFileStore {
    fn provision_bootstrap_if_absent(
        &self,
        bootstrap: &ExternalCasOffhostAnchorState,
    ) -> Result<ExternalCasOffhostAnchorStoreProvisionOutcome, ExternalCasOffhostAnchorStoreError>
    {
        bootstrap
            .validate(&self.provider_pin)
            .map_err(|_| ExternalCasOffhostAnchorStoreError::Corrupt)?;
        let _lock = self.acquire_lock()?;
        let path = self.state_path();
        if exists_no_follow(&path)? {
            return Ok(
                ExternalCasOffhostAnchorStoreProvisionOutcome::AlreadyExists(self.load_unlocked()?),
            );
        }
        if bootstrap.sequence != 1
            || bootstrap.provider_object_generation != 1
            || bootstrap.provider_record.generation != 0
        {
            return Err(ExternalCasOffhostAnchorStoreError::Corrupt);
        }
        self.write_initial(bootstrap)?;
        Ok(ExternalCasOffhostAnchorStoreProvisionOutcome::Provisioned)
    }

    fn load_consistent(
        &self,
    ) -> Result<ExternalCasOffhostAnchorState, ExternalCasOffhostAnchorStoreError> {
        let _lock = self.acquire_lock()?;
        self.load_unlocked()
    }

    fn compare_and_swap_atomic(
        &self,
        expected_sequence: u64,
        expected_state_digest: &[u8; 32],
        next_state: &ExternalCasOffhostAnchorState,
    ) -> Result<ExternalCasOffhostAnchorStoreCasOutcome, ExternalCasOffhostAnchorStoreError> {
        let _lock = self.acquire_lock()?;
        let current = self.load_unlocked()?;
        let current_digest = current
            .digest()
            .map_err(|_| ExternalCasOffhostAnchorStoreError::Corrupt)?;
        if current.sequence != expected_sequence || &current_digest != expected_state_digest {
            return Ok(ExternalCasOffhostAnchorStoreCasOutcome::Conflict(current));
        }
        let next_sequence = expected_sequence
            .checked_add(1)
            .ok_or(ExternalCasOffhostAnchorStoreError::Corrupt)?;
        let next_object_generation = current
            .provider_object_generation
            .checked_add(1)
            .ok_or(ExternalCasOffhostAnchorStoreError::Corrupt)?;
        if next_state.sequence != next_sequence
            || next_state.provider_object_generation != next_object_generation
            || next_state.last_expected_anchor_sequence != expected_sequence
            || next_state.last_expected_anchor_state_digest != *expected_state_digest
            || current
                .provider_record
                .validate_successor(&next_state.provider_record)
                .is_err()
            || next_state.last_operation_id != next_state.provider_record.operation_id
            || next_state.last_request_digest != next_state.provider_record.request_digest
        {
            return Err(ExternalCasOffhostAnchorStoreError::Corrupt);
        }
        next_state
            .validate(&self.provider_pin)
            .map_err(|_| ExternalCasOffhostAnchorStoreError::Corrupt)?;
        self.write_atomic(next_state)?;
        let read_back = self.load_unlocked()?;
        if read_back != *next_state {
            return Err(ExternalCasOffhostAnchorStoreError::Corrupt);
        }
        Ok(ExternalCasOffhostAnchorStoreCasOutcome::Applied)
    }
}

fn atomic_replace(source: &Path, destination: &Path) -> io::Result<()> {
    #[cfg(windows)]
    {
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
        unsafe extern "system" {
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
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
    #[cfg(not(windows))]
    {
        fs::rename(source, destination)
    }
}
fn sync_parent(directory: &Path) -> Result<(), ExternalCasOffhostAnchorStoreError> {
    #[cfg(unix)]
    {
        File::open(directory)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| ExternalCasOffhostAnchorStoreError::Unavailable)?;
    }
    #[cfg(windows)]
    {
        let _ = directory;
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = directory;
        return Err(ExternalCasOffhostAnchorStoreError::Unavailable);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::external_cas_anchor_candidate::ExternalCasRecord;
    use std::{
        sync::Arc,
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
                "q6ea_file_store_{}_{}",
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

    fn fixture() -> (
        ExternalCasOffhostAnchorPin,
        ExternalCasPin,
        ExternalCasOffhostAnchorState,
    ) {
        let provider_pin = ExternalCasPin {
            provider_id: [0x11; 32],
            network_id: [0x22; 32],
            genesis_digest: [0x33; 32],
            receipt_key_id: [0x44; 32],
            receipt_public_key: [0x45; ML_DSA_65_PUBLIC_KEY_BYTES],
        };
        let anchor_pin = ExternalCasOffhostAnchorPin {
            anchor_id: [0x55; 32],
            provider_id: provider_pin.provider_id,
            network_id: provider_pin.network_id,
            genesis_digest: provider_pin.genesis_digest,
            receipt_key_id: [0x66; 32],
            receipt_public_key: [0x67; ML_DSA_65_PUBLIC_KEY_BYTES],
        };
        let bootstrap_record = ExternalCasRecord {
            generation: 0,
            provider_id: provider_pin.provider_id,
            network_id: provider_pin.network_id,
            genesis_digest: provider_pin.genesis_digest,
            previous_record_digest: [0; 32],
            previous_state_digest: [0; 32],
            next_state_digest: [0x77; 32],
            operation_id: [0x78; 32],
            request_digest: [0x79; 32],
        };
        let bootstrap =
            ExternalCasOffhostAnchorState::provision_bootstrap(&provider_pin, bootstrap_record, 1)
                .unwrap();
        (anchor_pin, provider_pin, bootstrap)
    }

    fn successor(current: &ExternalCasOffhostAnchorState) -> ExternalCasOffhostAnchorState {
        let mut record = ExternalCasRecord {
            generation: current.provider_record.generation + 1,
            provider_id: current.provider_record.provider_id,
            network_id: current.provider_record.network_id,
            genesis_digest: current.provider_record.genesis_digest,
            previous_record_digest: current.provider_record.digest().unwrap(),
            previous_state_digest: current.provider_record.next_state_digest,
            next_state_digest: [0x88; 32],
            operation_id: [0x99; 32],
            request_digest: [0xAA; 32],
        };
        record.operation_id = [0x99; 32];
        ExternalCasOffhostAnchorState {
            sequence: current.sequence + 1,
            provider_object_generation: current.provider_object_generation + 1,
            provider_record: record.clone(),
            last_operation_id: record.operation_id,
            last_request_digest: record.request_digest,
            last_provider_receipt_digest: [0xAB; 32],
            last_expected_anchor_sequence: current.sequence,
            last_expected_anchor_state_digest: current.digest().unwrap(),
        }
    }

    #[test]
    fn provisions_once_reopens_and_cas_is_pinned_and_durable() {
        let dir = TestDir::new();
        let (anchor_pin, provider_pin, bootstrap) = fixture();
        let (store, outcome) = ExternalCasOffhostAnchorFileStore::provision(
            &dir.0,
            anchor_pin.clone(),
            provider_pin.clone(),
            bootstrap.clone(),
        )
        .unwrap();
        assert_eq!(
            outcome,
            ExternalCasOffhostAnchorStoreProvisionOutcome::Provisioned
        );
        let (again, outcome) = ExternalCasOffhostAnchorFileStore::provision(
            &dir.0,
            anchor_pin.clone(),
            provider_pin.clone(),
            bootstrap.clone(),
        )
        .unwrap();
        assert_eq!(
            outcome,
            ExternalCasOffhostAnchorStoreProvisionOutcome::AlreadyExists(bootstrap.clone())
        );
        let next = successor(&bootstrap);
        assert_eq!(
            store
                .compare_and_swap_atomic(bootstrap.sequence, &bootstrap.digest().unwrap(), &next)
                .unwrap(),
            ExternalCasOffhostAnchorStoreCasOutcome::Applied
        );
        drop(store);
        drop(again);
        let reopened =
            ExternalCasOffhostAnchorFileStore::open(&dir.0, anchor_pin, provider_pin).unwrap();
        assert_eq!(reopened.load_consistent().unwrap(), next);
    }

    #[test]
    fn stale_conflict_and_corrupt_or_wrong_pin_state_fail_closed() {
        let dir = TestDir::new();
        let (anchor_pin, provider_pin, bootstrap) = fixture();
        let (store, _) = ExternalCasOffhostAnchorFileStore::provision(
            &dir.0,
            anchor_pin.clone(),
            provider_pin.clone(),
            bootstrap.clone(),
        )
        .unwrap();
        let next = successor(&bootstrap);
        assert_eq!(
            store
                .compare_and_swap_atomic(bootstrap.sequence, &[0xFE; 32], &next)
                .unwrap(),
            ExternalCasOffhostAnchorStoreCasOutcome::Conflict(bootstrap)
        );
        drop(store);
        let mut wrong_anchor = anchor_pin.clone();
        wrong_anchor.anchor_id = [0xFA; 32];
        assert!(ExternalCasOffhostAnchorFileStore::open(
            &dir.0,
            wrong_anchor,
            provider_pin.clone()
        )
        .is_err());
        let path = dir.0.join(STATE_FILE);
        let mut bytes = fs::read(&path).unwrap();
        bytes[HEADER_BYTES + 3] ^= 1;
        fs::write(&path, bytes).unwrap();
        let reopened = ExternalCasOffhostAnchorFileStore::open(&dir.0, anchor_pin, provider_pin);
        assert!(reopened.is_err());
    }

    #[test]
    fn independent_handles_serialize_competing_cas_requests() {
        let dir = TestDir::new();
        let (anchor_pin, provider_pin, bootstrap) = fixture();
        let (first, _) = ExternalCasOffhostAnchorFileStore::provision(
            &dir.0,
            anchor_pin.clone(),
            provider_pin.clone(),
            bootstrap.clone(),
        )
        .unwrap();
        let second =
            ExternalCasOffhostAnchorFileStore::open(&dir.0, anchor_pin, provider_pin).unwrap();
        let next_a = successor(&bootstrap);
        let mut next_b = successor(&bootstrap);
        next_b.provider_record.next_state_digest = [0xBC; 32];
        let first = Arc::new(first);
        let second = Arc::new(second);
        let digest = bootstrap.digest().unwrap();
        let a = {
            let store = Arc::clone(&first);
            std::thread::spawn(move || {
                store
                    .compare_and_swap_atomic(bootstrap.sequence, &digest, &next_a)
                    .unwrap()
            })
        };
        let digest = bootstrap.digest().unwrap();
        let b = {
            let store = Arc::clone(&second);
            std::thread::spawn(move || {
                store
                    .compare_and_swap_atomic(bootstrap.sequence, &digest, &next_b)
                    .unwrap()
            })
        };
        let results = [a.join().unwrap(), b.join().unwrap()];
        assert_eq!(
            results
                .iter()
                .filter(|r| matches!(r, ExternalCasOffhostAnchorStoreCasOutcome::Applied))
                .count(),
            1
        );
        assert_eq!(
            results
                .iter()
                .filter(|r| matches!(r, ExternalCasOffhostAnchorStoreCasOutcome::Conflict(_)))
                .count(),
            1
        );
    }

    const CP0564_PROCESS_ROOT: &str = "QRUN_CP0564_Q6EA_PROCESS_ROOT";
    const CP0564_PROCESS_ROLE: &str = "QRUN_CP0564_Q6EA_PROCESS_ROLE";

    #[test]
    fn q6ea_file_store_process_competitor_child() {
        let root = match std::env::var_os(CP0564_PROCESS_ROOT) {
            Some(root) => PathBuf::from(root),
            None => return,
        };
        let role = std::env::var(CP0564_PROCESS_ROLE).unwrap();
        assert!(role == "a" || role == "b");
        let (anchor_pin, provider_pin, bootstrap) = fixture();
        let store =
            ExternalCasOffhostAnchorFileStore::open(&root, anchor_pin, provider_pin).unwrap();

        // Both child processes report readiness only after independently opening the same store.
        let ready = root.join(format!("ready-{role}"));
        File::create_new(ready).unwrap().sync_all().unwrap();
        let start = root.join("start");
        let deadline = std::time::Instant::now() + Duration::from_secs(20);
        while !start.exists() {
            assert!(
                std::time::Instant::now() < deadline,
                "CP-0564 parent did not release the process race"
            );
            std::thread::sleep(Duration::from_millis(5));
        }

        let mut next = successor(&bootstrap);
        if role == "b" {
            next.provider_record.next_state_digest = [0xBC; 32];
        }
        let outcome = store
            .compare_and_swap_atomic(bootstrap.sequence, &bootstrap.digest().unwrap(), &next)
            .unwrap();
        let result = match outcome {
            ExternalCasOffhostAnchorStoreCasOutcome::Applied => "APPLIED",
            ExternalCasOffhostAnchorStoreCasOutcome::Conflict(_) => "CONFLICT",
        };
        let result_path = root.join(format!("result-{role}"));
        let mut file = File::create_new(result_path).unwrap();
        file.write_all(result.as_bytes()).unwrap();
        file.sync_all().unwrap();
    }

    #[test]
    fn q6ea_file_store_competing_processes_have_exactly_one_atomic_winner() {
        use std::process::Command;

        let dir = TestDir::new();
        let (anchor_pin, provider_pin, bootstrap) = fixture();
        let (store, outcome) = ExternalCasOffhostAnchorFileStore::provision(
            &dir.0,
            anchor_pin,
            provider_pin,
            bootstrap.clone(),
        )
        .unwrap();
        assert_eq!(
            outcome,
            ExternalCasOffhostAnchorStoreProvisionOutcome::Provisioned
        );
        drop(store);

        let executable = std::env::current_exe().unwrap();
        let child_test =
            "external_cas_offhost_anchor_file_store_candidate::tests::q6ea_file_store_process_competitor_child";
        let spawn_child = |role: &str| {
            Command::new(&executable)
                .arg("--exact")
                .arg(child_test)
                .arg("--nocapture")
                .env(CP0564_PROCESS_ROOT, &dir.0)
                .env(CP0564_PROCESS_ROLE, role)
                .spawn()
                .unwrap()
        };
        let mut child_a = spawn_child("a");
        let mut child_b = spawn_child("b");

        let ready_a = dir.0.join("ready-a");
        let ready_b = dir.0.join("ready-b");
        let deadline = std::time::Instant::now() + Duration::from_secs(20);
        while !ready_a.exists() || !ready_b.exists() {
            assert!(
                std::time::Instant::now() < deadline,
                "CP-0564 child processes did not both reach the CAS barrier"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        File::create_new(dir.0.join("start"))
            .unwrap()
            .sync_all()
            .unwrap();

        let status_a = child_a.wait().unwrap();
        let status_b = child_b.wait().unwrap();
        assert!(status_a.success(), "process A failed: {status_a:?}");
        assert!(status_b.success(), "process B failed: {status_b:?}");

        let result_a = fs::read_to_string(dir.0.join("result-a")).unwrap();
        let result_b = fs::read_to_string(dir.0.join("result-b")).unwrap();
        assert!(
            (result_a == "APPLIED" && result_b == "CONFLICT")
                || (result_a == "CONFLICT" && result_b == "APPLIED"),
            "exactly one independent process must win, got A={result_a}, B={result_b}"
        );

        let (reopened_anchor_pin, reopened_provider_pin, _) = fixture();
        let reopened = ExternalCasOffhostAnchorFileStore::open(
            &dir.0,
            reopened_anchor_pin,
            reopened_provider_pin,
        )
        .unwrap();
        let final_state = reopened.load_consistent().unwrap();
        assert_eq!(final_state.sequence, bootstrap.sequence + 1);
        assert_eq!(
            final_state.provider_object_generation,
            bootstrap.provider_object_generation + 1
        );
        assert!(
            final_state.last_operation_id == [0x99; 32],
            "winning candidate operation must be preserved"
        );
    }
}
