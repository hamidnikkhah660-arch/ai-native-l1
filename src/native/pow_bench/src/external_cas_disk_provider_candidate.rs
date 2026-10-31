//! Durable single-host backend for the QRun external-CAS provider protocol.
//!
//! This backend serializes provider operations across processes and persists each accepted CAS
//! with atomic replacement. It is not a cloud object-store adapter, hardware monotonic counter,
//! or protection against an administrator restoring the entire provider filesystem from backup.
//! Production still requires independent operator control, restrictive OS ACLs, off-host
//! anti-rollback evidence, and separately protected receipt signing keys.

use crate::{
    external_cas_anchor_candidate::{
        ExternalCasError, ExternalCasPin, ExternalCasProviderTransport, ExternalCasReadRequest,
        ExternalCasReceipt, ExternalCasReceiptKind, ExternalCasReceiptOutcome, ExternalCasRecord,
        ExternalCasWriteRequest,
    },
    store_writer_lock::StoreWriterLock,
    v4_fat1_trust_candidate::ML_DSA_65_SIGNATURE_BYTES,
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

const STATE_MAGIC: &[u8; 4] = b"QCAS";
const STATE_VERSION: u16 = 1;
const STATE_DOMAIN: &[u8] = b"QRUN-V05-DURABLE-EXTERNAL-CAS-STATE-V1\0";
const STATE_FILE: &str = "provider-state.qcas";
const LOCK_FILE: &str = "provider-writer.lock";
const STATE_PREFIX_BYTES: usize = 448;
const STATE_CHECKSUM_BYTES: usize = 32;
const STATE_FILE_BYTES: usize = STATE_PREFIX_BYTES + STATE_CHECKSUM_BYTES;
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(1);

pub type ReceiptSignature = [u8; ML_DSA_65_SIGNATURE_BYTES];

#[derive(Debug)]
pub enum DurableExternalCasError {
    Io(io::Error),
    Contract(ExternalCasError),
    InvalidDirectory,
    AlreadyInitialized,
    MissingState,
    CorruptState,
    WrongPin,
    InvalidBootstrap,
    InvalidReadRequest,
    Signing(String),
    GenerationOverflow,
}
impl std::fmt::Display for DurableExternalCasError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "durable external-CAS I/O failed: {e}"),
            Self::Contract(e) => write!(f, "external-CAS contract rejected request: {e}"),
            Self::InvalidDirectory => write!(f, "external-CAS provider directory is invalid"),
            Self::AlreadyInitialized => write!(f, "external-CAS provider is already initialized"),
            Self::MissingState => write!(f, "external-CAS provider state is missing"),
            Self::CorruptState => write!(f, "external-CAS provider state is corrupt"),
            Self::WrongPin => write!(f, "external-CAS provider state does not match its pin"),
            Self::InvalidBootstrap => write!(f, "external-CAS bootstrap record is invalid"),
            Self::InvalidReadRequest => write!(f, "external-CAS read request is malformed"),
            Self::Signing(e) => write!(f, "external-CAS receipt signing failed: {e}"),
            Self::GenerationOverflow => write!(f, "external-CAS provider generation overflow"),
        }
    }
}
impl std::error::Error for DurableExternalCasError {}
impl From<io::Error> for DurableExternalCasError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}
impl From<ExternalCasError> for DurableExternalCasError {
    fn from(value: ExternalCasError) -> Self {
        Self::Contract(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ProviderState {
    object_generation: u64,
    current: ExternalCasRecord,
}
impl ProviderState {
    fn validate(&self, pin: &ExternalCasPin) -> Result<(), DurableExternalCasError> {
        pin.validate()?;
        self.current.validate_shape()?;
        if self.current.provider_id != pin.provider_id
            || self.current.network_id != pin.network_id
            || self.current.genesis_digest != pin.genesis_digest
            || self.object_generation == 0
            || self.current.generation.checked_add(1) != Some(self.object_generation)
        {
            return Err(DurableExternalCasError::WrongPin);
        }
        Ok(())
    }

    fn encode(
        &self,
        pin: &ExternalCasPin,
    ) -> Result<[u8; STATE_FILE_BYTES], DurableExternalCasError> {
        self.validate(pin)?;
        let mut out = Vec::with_capacity(STATE_FILE_BYTES);
        out.extend_from_slice(STATE_MAGIC);
        out.extend_from_slice(&STATE_VERSION.to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes());
        out.extend_from_slice(&pin.provider_id);
        out.extend_from_slice(&pin.network_id);
        out.extend_from_slice(&pin.genesis_digest);
        out.extend_from_slice(&pin.receipt_key_id);
        let pk_hash: [u8; 32] = Sha256::digest(pin.receipt_public_key).into();
        out.extend_from_slice(&pk_hash);
        out.extend_from_slice(&self.object_generation.to_be_bytes());
        out.extend_from_slice(&self.current.encode()?);
        if out.len() != STATE_PREFIX_BYTES {
            return Err(DurableExternalCasError::CorruptState);
        }
        let checksum = state_checksum(&out);
        out.extend_from_slice(&checksum);
        out.try_into()
            .map_err(|_| DurableExternalCasError::CorruptState)
    }

    fn decode(bytes: &[u8], pin: &ExternalCasPin) -> Result<Self, DurableExternalCasError> {
        if bytes.len() != STATE_FILE_BYTES
            || &bytes[..4] != STATE_MAGIC
            || u16::from_be_bytes([bytes[4], bytes[5]]) != STATE_VERSION
            || bytes[6..8] != [0, 0]
            || state_checksum(&bytes[..STATE_PREFIX_BYTES]) != bytes[STATE_PREFIX_BYTES..]
        {
            return Err(DurableExternalCasError::CorruptState);
        }
        let pk_hash: [u8; 32] = Sha256::digest(pin.receipt_public_key).into();
        if bytes[8..40] != pin.provider_id
            || bytes[40..72] != pin.network_id
            || bytes[72..104] != pin.genesis_digest
            || bytes[104..136] != pin.receipt_key_id
            || bytes[136..168] != pk_hash
        {
            return Err(DurableExternalCasError::WrongPin);
        }
        let state = Self {
            object_generation: u64::from_be_bytes(
                bytes[168..176]
                    .try_into()
                    .map_err(|_| DurableExternalCasError::CorruptState)?,
            ),
            current: ExternalCasRecord::decode(&bytes[176..STATE_PREFIX_BYTES])?,
        };
        state.validate(pin)?;
        Ok(state)
    }
}
fn state_checksum(bytes: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(STATE_DOMAIN);
    hash.update(bytes);
    hash.finalize().into()
}

/// The signer signs the exact digest with the key matching the configured ML-DSA-65 pin.
/// The private key remains caller/KMS-owned and is never written to this provider directory.
pub struct DurableExternalCasProvider<S> {
    directory: PathBuf,
    pin: ExternalCasPin,
    signer: S,
}
impl<S> std::fmt::Debug for DurableExternalCasProvider<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DurableExternalCasProvider")
            .field("directory", &self.directory)
            .field("provider_id", &self.pin.provider_id)
            .field("network_id", &self.pin.network_id)
            .field("genesis_digest", &self.pin.genesis_digest)
            .field("receipt_key_id", &self.pin.receipt_key_id)
            .field("signer", &"<redacted signer>")
            .finish()
    }
}

impl<S> DurableExternalCasProvider<S>
where
    S: FnMut(&[u8; 32]) -> Result<ReceiptSignature, String>,
{
    /// Initialize exactly once with an explicitly provisioned generation-zero bootstrap.
    /// Existing, missing-but-corrupt, or conflicting state is never silently reset.
    pub fn initialize(
        directory: impl AsRef<Path>,
        pin: ExternalCasPin,
        bootstrap: ExternalCasRecord,
        signer: S,
    ) -> Result<Self, DurableExternalCasError> {
        pin.validate()?;
        bootstrap.validate_shape()?;
        if bootstrap.generation != 0
            || bootstrap.provider_id != pin.provider_id
            || bootstrap.network_id != pin.network_id
            || bootstrap.genesis_digest != pin.genesis_digest
        {
            return Err(DurableExternalCasError::InvalidBootstrap);
        }
        let directory = directory.as_ref().to_path_buf();
        fs::create_dir_all(&directory)?;
        validate_directory(&directory)?;
        let _lock = StoreWriterLock::acquire(&directory, LOCK_FILE)?;
        let state_path = directory.join(STATE_FILE);
        if path_exists_no_follow(&state_path)? {
            return Err(DurableExternalCasError::AlreadyInitialized);
        }
        let state = ProviderState {
            object_generation: 1,
            current: bootstrap,
        };
        write_initial_state(&state_path, &state.encode(&pin)?)?;
        Ok(Self {
            directory,
            pin,
            signer,
        })
    }

    /// Open an initialized provider. Missing or corrupt state fails closed; no bootstrap is made.
    pub fn open(
        directory: impl AsRef<Path>,
        pin: ExternalCasPin,
        signer: S,
    ) -> Result<Self, DurableExternalCasError> {
        pin.validate()?;
        let directory = directory.as_ref().to_path_buf();
        validate_directory(&directory)?;
        let provider = Self {
            directory,
            pin,
            signer,
        };
        {
            let _lock = provider.acquire_lock()?;
            provider.load_state()?;
        }
        Ok(provider)
    }

    pub fn pin(&self) -> &ExternalCasPin {
        &self.pin
    }
    pub fn state_path(&self) -> PathBuf {
        self.directory.join(STATE_FILE)
    }

    fn acquire_lock(&self) -> Result<StoreWriterLock, DurableExternalCasError> {
        // StoreWriterLock is deliberately nonblocking. A provider request should queue briefly
        // behind another valid CAS instead of exposing a transient lock race as a provider error.
        // The bounded deadline still fails closed if a writer hangs or the store is wedged.
        const ATTEMPTS: usize = 200;
        for attempt in 0..ATTEMPTS {
            match StoreWriterLock::acquire(&self.directory, LOCK_FILE) {
                Ok(lock) => return Ok(lock),
                Err(error)
                    if error.kind() == io::ErrorKind::WouldBlock && attempt + 1 < ATTEMPTS =>
                {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(error) => return Err(DurableExternalCasError::Io(error)),
            }
        }
        Err(DurableExternalCasError::Io(io::Error::new(
            io::ErrorKind::WouldBlock,
            "external-CAS provider writer lock deadline elapsed",
        )))
    }

    fn load_state(&self) -> Result<ProviderState, DurableExternalCasError> {
        let path = self.state_path();
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Err(DurableExternalCasError::MissingState)
            }
            Err(error) => return Err(DurableExternalCasError::Io(error)),
        };
        if !metadata.file_type().is_file() || metadata.len() != STATE_FILE_BYTES as u64 {
            return Err(DurableExternalCasError::CorruptState);
        }
        let file = File::open(path)?;
        let mut bytes = Vec::with_capacity(STATE_FILE_BYTES);
        file.take((STATE_FILE_BYTES + 1) as u64)
            .read_to_end(&mut bytes)?;
        ProviderState::decode(&bytes, &self.pin)
    }

    fn sign_receipt(
        &mut self,
        state: &ProviderState,
        kind: ExternalCasReceiptKind,
        outcome: ExternalCasReceiptOutcome,
        request_nonce: [u8; 32],
        operation_id: [u8; 32],
        request_digest: [u8; 32],
    ) -> Result<ExternalCasReceipt, DurableExternalCasError> {
        let mut receipt = ExternalCasReceipt {
            kind,
            outcome,
            generation: state.current.generation,
            object_generation: state.object_generation,
            provider_id: self.pin.provider_id,
            network_id: self.pin.network_id,
            genesis_digest: self.pin.genesis_digest,
            receipt_key_id: self.pin.receipt_key_id,
            request_nonce,
            record_digest: state.current.digest()?,
            previous_record_digest: state.current.previous_record_digest,
            previous_state_digest: state.current.previous_state_digest,
            state_digest: state.current.next_state_digest,
            operation_id,
            request_digest,
            signature: [0; ML_DSA_65_SIGNATURE_BYTES],
        };
        let digest = receipt.signing_digest()?;
        receipt.signature = (self.signer)(&digest).map_err(DurableExternalCasError::Signing)?;
        receipt.encode()?;
        Ok(receipt)
    }

    fn persist_state(&self, state: &ProviderState) -> Result<(), DurableExternalCasError> {
        write_state_atomic(&self.state_path(), &state.encode(&self.pin)?)?;
        Ok(())
    }
}

impl<S> ExternalCasProviderTransport for DurableExternalCasProvider<S>
where
    S: FnMut(&[u8; 32]) -> Result<ReceiptSignature, String>,
{
    type Error = DurableExternalCasError;

    fn read_current(
        &mut self,
        request: &ExternalCasReadRequest,
    ) -> Result<(ExternalCasRecord, ExternalCasReceipt), Self::Error> {
        if request.request_nonce.iter().all(|b| *b == 0)
            || request.operation_id.iter().all(|b| *b == 0)
            || request.request_digest.iter().all(|b| *b == 0)
        {
            return Err(DurableExternalCasError::InvalidReadRequest);
        }
        let _lock = self.acquire_lock()?;
        let state = self.load_state()?;
        let receipt = self.sign_receipt(
            &state,
            ExternalCasReceiptKind::Read,
            ExternalCasReceiptOutcome::Observed,
            request.request_nonce,
            request.operation_id,
            request.request_digest,
        )?;
        Ok((state.current, receipt))
    }

    fn compare_and_swap(
        &mut self,
        request: &ExternalCasWriteRequest,
    ) -> Result<ExternalCasReceipt, Self::Error> {
        request.validate(&self.pin)?;
        let _lock = self.acquire_lock()?;
        let mut state = self.load_state()?;

        let already_applied = state.current == request.next_record
            && state.current.operation_id == request.operation_id
            && state.current.request_digest == request.request_digest
            && request.expected_object_generation.checked_add(1) == Some(state.object_generation);

        let outcome = if already_applied {
            ExternalCasReceiptOutcome::AlreadyApplied
        } else {
            let can_apply = state.current.generation == request.expected_generation
                && state.object_generation == request.expected_object_generation
                && state.current.digest()? == request.expected_record_digest
                && state.current.next_state_digest == request.expected_state_digest;
            if can_apply {
                state.current.validate_successor(&request.next_record)?;
                state.object_generation = state
                    .object_generation
                    .checked_add(1)
                    .ok_or(DurableExternalCasError::GenerationOverflow)?;
                state.current = request.next_record.clone();
                // Atomic file replacement is the commit point. A lost response or signer failure
                // after this line must be resolved with a fresh signed read.
                self.persist_state(&state)?;
                ExternalCasReceiptOutcome::Applied
            } else {
                ExternalCasReceiptOutcome::Conflict
            }
        };
        self.sign_receipt(
            &state,
            ExternalCasReceiptKind::Commit,
            outcome,
            request.request_nonce,
            request.operation_id,
            request.request_digest,
        )
    }
}

fn validate_directory(directory: &Path) -> Result<(), DurableExternalCasError> {
    let metadata = fs::symlink_metadata(directory).map_err(|error| {
        if error.kind() == io::ErrorKind::NotFound {
            DurableExternalCasError::InvalidDirectory
        } else {
            DurableExternalCasError::Io(error)
        }
    })?;
    if !metadata.file_type().is_dir() {
        return Err(DurableExternalCasError::InvalidDirectory);
    }
    Ok(())
}

fn path_exists_no_follow(path: &Path) -> Result<bool, DurableExternalCasError> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(DurableExternalCasError::Io(error)),
    }
}

fn write_initial_state(path: &Path, bytes: &[u8]) -> Result<(), DurableExternalCasError> {
    let parent = path
        .parent()
        .ok_or(DurableExternalCasError::InvalidDirectory)?;
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    let result = file
        .write_all(bytes)
        .and_then(|_| file.flush())
        .and_then(|_| file.sync_all());
    drop(file);
    if let Err(error) = result {
        let _ = fs::remove_file(path);
        return Err(DurableExternalCasError::Io(error));
    }
    sync_parent(parent)?;
    Ok(())
}

fn write_state_atomic(path: &Path, bytes: &[u8]) -> Result<(), DurableExternalCasError> {
    if bytes.len() != STATE_FILE_BYTES {
        return Err(DurableExternalCasError::CorruptState);
    }
    let parent = path
        .parent()
        .ok_or(DurableExternalCasError::InvalidDirectory)?;
    let final_name = path
        .file_name()
        .ok_or(DurableExternalCasError::InvalidDirectory)?;
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
        return Err(DurableExternalCasError::Io(error));
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
) -> Result<PathBuf, DurableExternalCasError> {
    let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let mut random = [0u8; 16];
    getrandom::getrandom(&mut random).map_err(|e| {
        DurableExternalCasError::Io(io::Error::new(io::ErrorKind::Other, e.to_string()))
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
fn atomic_replace(source: &Path, destination: &Path) -> Result<(), DurableExternalCasError> {
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
        Err(DurableExternalCasError::Io(io::Error::last_os_error()))
    } else {
        Ok(())
    }
}
#[cfg(not(windows))]
fn atomic_replace(source: &Path, destination: &Path) -> Result<(), DurableExternalCasError> {
    fs::rename(source, destination)?;
    Ok(())
}
#[cfg(windows)]
fn sync_parent(_directory: &Path) -> Result<(), DurableExternalCasError> {
    Ok(())
}
#[cfg(unix)]
fn sync_parent(directory: &Path) -> Result<(), DurableExternalCasError> {
    File::open(directory)?.sync_all()?;
    Ok(())
}
#[cfg(not(any(windows, unix)))]
fn sync_parent(_directory: &Path) -> Result<(), DurableExternalCasError> {
    Err(DurableExternalCasError::Io(io::Error::new(
        io::ErrorKind::Unsupported,
        "durable directory sync unsupported on this target",
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        external_cas_anchor_candidate::{
            ExternalCasClientError, ExternalCasReadRequest, ExternalCasWriteRequest,
            VerifiedExternalCasClient,
        },
        external_cas_floor_store_candidate::ExternalCasFloorStore,
        external_cas_noise_transport_candidate::{
            serve_external_cas_noise_connection, NoiseTcpExternalCasProviderTransport,
        },
        v4_fat1_mldsa65_candidate::LibcruxMlDsa65VerifierCandidate,
    };
    use libcrux_ml_dsa::ml_dsa_65::portable;
    use std::{
        net::TcpListener,
        sync::Arc,
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
                "qrun_durable_external_cas_{}_{}",
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

    fn signer(
        key: Arc<libcrux_ml_dsa::ml_dsa_65::MLDSA65SigningKey>,
    ) -> impl FnMut(&[u8; 32]) -> Result<ReceiptSignature, String> {
        move |digest| {
            let signature = portable::sign(&key, digest, &[], [0x63u8; 32])
                .map_err(|error| format!("{error:?}"))?;
            Ok(*signature.as_ref())
        }
    }

    fn setup() -> (
        ExternalCasPin,
        ExternalCasRecord,
        Arc<libcrux_ml_dsa::ml_dsa_65::MLDSA65SigningKey>,
    ) {
        let keys = portable::generate_key_pair([0x71u8; 32]);
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
        (pin, bootstrap, Arc::new(keys.signing_key))
    }

    fn write_request(
        pin: &ExternalCasPin,
        previous: &ExternalCasRecord,
        nonce: u8,
        operation: u8,
        next_state: u8,
        expected_object_generation: u64,
    ) -> ExternalCasWriteRequest {
        let mut request = ExternalCasWriteRequest {
            request_nonce: [nonce; 32],
            operation_id: [operation; 32],
            request_digest: [1; 32],
            expected_generation: previous.generation,
            expected_object_generation,
            expected_record_digest: previous.digest().unwrap(),
            expected_state_digest: previous.next_state_digest,
            next_record: ExternalCasRecord {
                generation: previous.generation + 1,
                provider_id: pin.provider_id,
                network_id: pin.network_id,
                genesis_digest: pin.genesis_digest,
                previous_record_digest: previous.digest().unwrap(),
                previous_state_digest: previous.next_state_digest,
                next_state_digest: [next_state; 32],
                operation_id: [operation; 32],
                request_digest: [1; 32],
            },
        };
        request.bind_request_digest(pin).unwrap();
        request
    }

    #[test]
    fn initializes_once_reopens_and_rejects_corrupt_or_wrong_pin_state() {
        let dir = TestDir::new();
        let (pin, bootstrap, key) = setup();
        let provider = DurableExternalCasProvider::initialize(
            &dir.0,
            pin.clone(),
            bootstrap.clone(),
            signer(key.clone()),
        )
        .unwrap();
        assert!(provider.state_path().exists());
        assert!(matches!(
            DurableExternalCasProvider::initialize(
                &dir.0,
                pin.clone(),
                bootstrap.clone(),
                signer(key.clone())
            ),
            Err(DurableExternalCasError::AlreadyInitialized)
        ));
        drop(provider);

        let mut reopened =
            DurableExternalCasProvider::open(&dir.0, pin.clone(), signer(key.clone())).unwrap();
        let (record, receipt) = reopened
            .read_current(&ExternalCasReadRequest {
                request_nonce: [0x81; 32],
                operation_id: [0x82; 32],
                request_digest: [0x83; 32],
            })
            .unwrap();
        assert_eq!(record, bootstrap);
        assert_eq!(receipt.object_generation, 1);

        let mut wrong_pin = pin.clone();
        wrong_pin.receipt_key_id = [0x99; 32];
        assert!(matches!(
            DurableExternalCasProvider::open(&dir.0, wrong_pin, signer(key.clone())),
            Err(DurableExternalCasError::WrongPin)
        ));

        let path = dir.0.join(STATE_FILE);
        let mut bytes = fs::read(&path).unwrap();
        bytes[200] ^= 0x80;
        fs::write(&path, bytes).unwrap();
        assert!(matches!(
            DurableExternalCasProvider::open(&dir.0, pin, signer(key)),
            Err(DurableExternalCasError::CorruptState)
        ));
    }

    #[test]
    fn cas_is_idempotent_and_serializes_independent_provider_handles() {
        let dir = TestDir::new();
        let (pin, bootstrap, key) = setup();
        let mut first = DurableExternalCasProvider::initialize(
            &dir.0,
            pin.clone(),
            bootstrap.clone(),
            signer(key.clone()),
        )
        .unwrap();
        let mut second =
            DurableExternalCasProvider::open(&dir.0, pin.clone(), signer(key.clone())).unwrap();

        let request = write_request(&pin, &bootstrap, 0x91, 0x92, 0x93, 1);
        let expected_successor = request.next_record.clone();
        let receipt = first.compare_and_swap(&request).unwrap();
        assert_eq!(receipt.outcome, ExternalCasReceiptOutcome::Applied);
        assert_eq!(receipt.generation, 1);
        assert_eq!(receipt.object_generation, 2);

        let retry = second.compare_and_swap(&request).unwrap();
        assert_eq!(retry.outcome, ExternalCasReceiptOutcome::AlreadyApplied);
        assert_eq!(retry.object_generation, 2);

        let stale = write_request(&pin, &bootstrap, 0x94, 0x95, 0x96, 1);
        let conflict = second.compare_and_swap(&stale).unwrap();
        assert_eq!(conflict.outcome, ExternalCasReceiptOutcome::Conflict);
        assert_eq!(conflict.generation, 1);
        assert_eq!(conflict.object_generation, 2);

        let reopened = DurableExternalCasProvider::open(&dir.0, pin.clone(), signer(key)).unwrap();
        let state = reopened.load_state().unwrap();
        assert_eq!(state.current, expected_successor);
        assert_eq!(state.object_generation, 2);
    }

    #[test]
    fn committed_cas_survives_signer_failure_and_recovers_by_signed_read() {
        let dir = TestDir::new();
        let (pin, bootstrap, key) = setup();
        let mut fail_once = true;
        let signing_key = key.clone();
        let mut provider = DurableExternalCasProvider::initialize(
            &dir.0,
            pin.clone(),
            bootstrap.clone(),
            move |digest| {
                if fail_once {
                    fail_once = false;
                    return Err("injected signer outage after durable commit".into());
                }
                let signature = portable::sign(&signing_key, digest, &[], [0x63u8; 32])
                    .map_err(|error| format!("{error:?}"))?;
                Ok(*signature.as_ref())
            },
        )
        .unwrap();
        let request = write_request(&pin, &bootstrap, 0xA1, 0xA2, 0xA3, 1);
        assert!(matches!(
            provider.compare_and_swap(&request),
            Err(DurableExternalCasError::Signing(_))
        ));

        let reopened =
            DurableExternalCasProvider::open(&dir.0, pin.clone(), signer(key.clone())).unwrap();
        let mut client =
            VerifiedExternalCasClient::new(pin.clone(), reopened, LibcruxMlDsa65VerifierCandidate)
                .unwrap();
        let read = ExternalCasReadRequest {
            request_nonce: [0xA4; 32],
            operation_id: request.operation_id,
            request_digest: request.request_digest,
        };
        let observed = client.read_current(&read, 1, 2, Some(&bootstrap)).unwrap();
        assert_eq!(observed.record, request.next_record);
        assert_eq!(observed.object_generation, 2);

        let receipt = client.compare_and_swap(&request).unwrap();
        assert_eq!(receipt.outcome, ExternalCasReceiptOutcome::AlreadyApplied);
        assert_eq!(receipt.object_generation, 2);
    }

    #[test]
    fn preserved_qcf1_floor_rejects_a_restored_provider_backup() {
        let root = TestDir::new();
        let provider_dir = root.0.join("provider");
        let floor_dir = root.0.join("independent-floor");
        fs::create_dir_all(&provider_dir).unwrap();
        fs::create_dir_all(&floor_dir).unwrap();
        let (pin, bootstrap, key) = setup();
        let provider = DurableExternalCasProvider::initialize(
            &provider_dir,
            pin.clone(),
            bootstrap.clone(),
            signer(key.clone()),
        )
        .unwrap();
        // This byte-for-byte image models a valid provider backup taken before a CAS.
        let old_provider_backup = fs::read(provider.state_path()).unwrap();
        let floor =
            ExternalCasFloorStore::initialize(&floor_dir, pin.clone(), bootstrap.clone(), 1)
                .unwrap();
        let mut client =
            VerifiedExternalCasClient::new(pin.clone(), provider, LibcruxMlDsa65VerifierCandidate)
                .unwrap();

        let initial_read = client.fresh_read_request([0xA8; 32], [0xA9; 32]).unwrap();
        let observed = client.read_current(&initial_read, 0, 1, None).unwrap();
        assert_eq!(observed.record, bootstrap);

        let request = write_request(&pin, &bootstrap, 0xAA, 0xAB, 0xAC, 1);
        let receipt = client.compare_and_swap(&request).unwrap();
        assert_eq!(receipt.outcome, ExternalCasReceiptOutcome::Applied);
        assert_eq!(receipt.generation, 1);
        assert_eq!(receipt.object_generation, 2);
        // Advance the separately retained floor only after the client verified the signed CAS.
        floor
            .advance(&bootstrap, 1, &request.next_record, 2)
            .unwrap();
        drop(client);

        // Simulate restoring only the provider's whole-directory backup. QCF1 remains ahead.
        fs::write(provider_dir.join(STATE_FILE), old_provider_backup).unwrap();
        let restored_provider =
            DurableExternalCasProvider::open(&provider_dir, pin.clone(), signer(key)).unwrap();
        let mut restored_client =
            VerifiedExternalCasClient::new(pin, restored_provider, LibcruxMlDsa65VerifierCandidate)
                .unwrap();
        let trusted = floor.snapshot().unwrap();
        let fresh_read = restored_client
            .fresh_read_request(request.operation_id, request.request_digest)
            .unwrap();
        assert!(matches!(
            restored_client.read_current(
                &fresh_read,
                trusted.trusted_record.generation,
                trusted.minimum_object_generation,
                Some(&trusted.trusted_record),
            ),
            Err(ExternalCasClientError::RollbackDetected {
                observed_generation: 0,
                minimum_generation: 1,
                observed_object_generation: 1,
                minimum_object_generation: 2,
            })
        ));
    }

    #[test]
    fn writer_lock_contention_and_missing_state_fail_closed() {
        let dir = TestDir::new();
        let (pin, bootstrap, key) = setup();
        let mut provider = DurableExternalCasProvider::initialize(
            &dir.0,
            pin.clone(),
            bootstrap,
            signer(key.clone()),
        )
        .unwrap();

        let lock = StoreWriterLock::acquire(&dir.0, LOCK_FILE).unwrap();
        assert!(matches!(
            provider.read_current(&ExternalCasReadRequest {
                request_nonce: [0xB1; 32],
                operation_id: [0xB2; 32],
                request_digest: [0xB3; 32],
            }),
            Err(DurableExternalCasError::Io(ref error))
                if error.kind() == io::ErrorKind::WouldBlock
        ));
        drop(lock);

        fs::remove_file(dir.0.join(STATE_FILE)).unwrap();
        assert!(matches!(
            provider.read_current(&ExternalCasReadRequest {
                request_nonce: [0xB4; 32],
                operation_id: [0xB5; 32],
                request_digest: [0xB6; 32],
            }),
            Err(DurableExternalCasError::MissingState)
        ));
        assert!(matches!(
            DurableExternalCasProvider::open(&dir.0, pin, signer(key)),
            Err(DurableExternalCasError::MissingState)
        ));
    }

    #[test]
    fn noise_tcp_handler_serves_signed_reads_and_cas_from_persistent_backend() {
        let dir = TestDir::new();
        let (pin, bootstrap, receipt_key) = setup();
        drop(
            DurableExternalCasProvider::initialize(
                &dir.0,
                pin.clone(),
                bootstrap.clone(),
                signer(receipt_key.clone()),
            )
            .unwrap(),
        );

        let server_noise = snow::Builder::new(
            "Noise_XX_25519_ChaChaPoly_SHA256"
                .parse::<snow::params::NoiseParams>()
                .unwrap(),
        )
        .generate_keypair()
        .unwrap();
        let client_noise = snow::Builder::new(
            "Noise_XX_25519_ChaChaPoly_SHA256"
                .parse::<snow::params::NoiseParams>()
                .unwrap(),
        )
        .generate_keypair()
        .unwrap();
        let server_private: [u8; 32] = server_noise.private.as_slice().try_into().unwrap();
        let server_public: [u8; 32] = server_noise.public.as_slice().try_into().unwrap();
        let client_private: [u8; 32] = client_noise.private.as_slice().try_into().unwrap();
        let client_public: [u8; 32] = client_noise.public.as_slice().try_into().unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server_dir = dir.0.clone();
        let server_pin = pin.clone();
        let server_key = receipt_key.clone();
        let server = thread::spawn(move || {
            for _ in 0..2 {
                let (mut stream, _) = listener.accept().unwrap();
                let mut provider = DurableExternalCasProvider::open(
                    &server_dir,
                    server_pin.clone(),
                    signer(server_key.clone()),
                )
                .unwrap();
                serve_external_cas_noise_connection(
                    &mut stream,
                    &server_private,
                    &[client_public],
                    &server_pin,
                    &mut provider,
                )
                .unwrap();
            }
        });

        let transport = NoiseTcpExternalCasProviderTransport::new(
            address,
            client_private,
            server_public,
            pin.clone(),
        )
        .unwrap();
        let mut client =
            VerifiedExternalCasClient::new(pin.clone(), transport, LibcruxMlDsa65VerifierCandidate)
                .unwrap();
        let read = client.fresh_read_request([0xC1; 32], [0xC2; 32]).unwrap();
        let observed = client.read_current(&read, 0, 1, None).unwrap();
        assert_eq!(observed.record, bootstrap);

        let request = write_request(&pin, &bootstrap, 0xC3, 0xC4, 0xC5, 1);
        let receipt = client.compare_and_swap(&request).unwrap();
        assert_eq!(receipt.outcome, ExternalCasReceiptOutcome::Applied);
        assert_eq!(receipt.object_generation, 2);
        server.join().unwrap();

        let reopened = DurableExternalCasProvider::open(&dir.0, pin, signer(receipt_key)).unwrap();
        let state = reopened.load_state().unwrap();
        assert_eq!(state.current, request.next_record);
        assert_eq!(state.object_generation, 2);
    }

    #[test]
    fn bootstrap_from_another_pin_domain_is_rejected_without_creating_state() {
        let dir = TestDir::new();
        let (pin, mut bootstrap, key) = setup();
        bootstrap.genesis_digest = [0xFE; 32];
        assert!(matches!(
            DurableExternalCasProvider::initialize(&dir.0, pin, bootstrap, signer(key)),
            Err(DurableExternalCasError::InvalidBootstrap)
        ));
        assert!(!dir.0.join(STATE_FILE).exists());
    }

    #[test]
    fn simultaneous_writers_have_exactly_one_atomic_cas_winner() {
        use std::sync::Barrier;

        let dir = TestDir::new();
        let (pin, bootstrap, key) = setup();
        let first = DurableExternalCasProvider::initialize(
            &dir.0,
            pin.clone(),
            bootstrap.clone(),
            signer(key.clone()),
        )
        .unwrap();
        let second =
            DurableExternalCasProvider::open(&dir.0, pin.clone(), signer(key.clone())).unwrap();
        let request_a = write_request(&pin, &bootstrap, 0xE1, 0xE2, 0xE3, 1);
        let request_b = write_request(&pin, &bootstrap, 0xE4, 0xE5, 0xE6, 1);
        let barrier = Arc::new(Barrier::new(3));

        let gate_a = barrier.clone();
        let thread_a = thread::spawn(move || {
            let mut provider = first;
            gate_a.wait();
            provider.compare_and_swap(&request_a).unwrap()
        });
        let gate_b = barrier.clone();
        let thread_b = thread::spawn(move || {
            let mut provider = second;
            gate_b.wait();
            provider.compare_and_swap(&request_b).unwrap()
        });
        barrier.wait();

        let receipt_a = thread_a.join().unwrap();
        let receipt_b = thread_b.join().unwrap();
        let outcomes = [receipt_a.outcome, receipt_b.outcome];
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| **outcome == ExternalCasReceiptOutcome::Applied)
                .count(),
            1
        );
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| **outcome == ExternalCasReceiptOutcome::Conflict)
                .count(),
            1
        );
        let state = DurableExternalCasProvider::open(&dir.0, pin, signer(key))
            .unwrap()
            .load_state()
            .unwrap();
        assert_eq!(state.current.generation, 1);
        assert_eq!(state.object_generation, 2);
    }

    #[test]
    fn signed_conflict_receipt_is_verified_as_conflict_not_success() {
        let dir = TestDir::new();
        let (pin, bootstrap, key) = setup();
        let mut provider = DurableExternalCasProvider::initialize(
            &dir.0,
            pin.clone(),
            bootstrap.clone(),
            signer(key.clone()),
        )
        .unwrap();
        let stale = write_request(&pin, &bootstrap, 0xD1, 0xD2, 0xD3, 7);
        let conflict = provider.compare_and_swap(&stale).unwrap();
        assert_eq!(conflict.outcome, ExternalCasReceiptOutcome::Conflict);
        assert_eq!(conflict.object_generation, 1);

        let reopened = DurableExternalCasProvider::open(&dir.0, pin.clone(), signer(key)).unwrap();
        let mut client =
            VerifiedExternalCasClient::new(pin, reopened, LibcruxMlDsa65VerifierCandidate).unwrap();
        assert_eq!(
            client.compare_and_swap(&stale),
            Err(ExternalCasClientError::Contract(
                ExternalCasError::CasConflict
            ))
        );
    }

    #[test]
    fn symlinked_state_file_is_not_followed() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            let dir = TestDir::new();
            let target_dir = TestDir::new();
            let (pin, bootstrap, key) = setup();
            drop(
                DurableExternalCasProvider::initialize(
                    &target_dir.0,
                    pin.clone(),
                    bootstrap,
                    signer(key.clone()),
                )
                .unwrap(),
            );
            symlink(target_dir.0.join(STATE_FILE), dir.0.join(STATE_FILE)).unwrap();
            assert!(matches!(
                DurableExternalCasProvider::open(&dir.0, pin, signer(key)),
                Err(DurableExternalCasError::CorruptState)
            ));
        }
    }
}
