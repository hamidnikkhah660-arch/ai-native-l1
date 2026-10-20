//! Durable anti-rollback high-water for an issuer-signed peer identity record.
//!
//! This state detects provider-record rollback across process restarts while the state file
//! and stable writer-lock sibling are protected by operator-controlled filesystem ACLs.
//! It is not hardware-backed against rollback/deletion of the entire protected directory.
use crate::{
    identity_policy::{
        decode as decode_key_record, KeyAlgorithm, KeyPurpose, KeyRecord, KeyState, HEADER_LEN,
    },
    snapshot_store::{SnapshotStoreError, SnapshotWriterLock},
};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicU64, Ordering},
        Mutex,
    },
};

const STATE_MAGIC: &[u8; 4] = b"NIG1";
const STATE_VERSION: u16 = 1;
const STATE_BODY_LEN: usize = 164;
const STATE_WIRE_LEN: usize = STATE_BODY_LEN + 32;
const ROTATION_MAGIC: &[u8; 4] = b"NRT1";
const ROTATION_VERSION: u16 = 1;
const ROTATION_CORE_LEN: usize = 135;
pub const ROTATION_WIRE_LEN: usize = ROTATION_CORE_LEN + 64;
const ROTATION_DOMAIN: &[u8] = b"AIN1-NOISE-KEY-ROTATION-V1\0";
static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdentityGenerationError {
    InvalidPath,
    Persistence,
    Locked,
    StateMissing,
    StateMalformed,
    IdentityMismatch,
    RecordMalformed,
    GenerationRollback,
    RevokedTerminal,
    SameGenerationMutation,
    RotationMissing,
    RotationMalformed,
    RotationSignature,
    RotationMismatch,
    InvalidInitialState,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct IdentityConfig {
    network_id: [u8; 32],
    key_id: u32,
    purpose: KeyPurpose,
    credential_id: u128,
    issuer_id: u32,
    issuer_public_key: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PersistedState {
    high_generation: u32,
    record_digest: [u8; 32],
    identity_digest: [u8; 32],
    state: u8, // 0 = uninitialized, 1 = active, 2 = retired, 3 = revoked
}

impl PersistedState {
    fn empty() -> Self {
        Self {
            high_generation: 0,
            record_digest: [0; 32],
            identity_digest: [0; 32],
            state: 0,
        }
    }

    fn encode(&self, identity: &IdentityConfig) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(STATE_WIRE_LEN);
        bytes.extend_from_slice(STATE_MAGIC);
        bytes.extend_from_slice(&STATE_VERSION.to_be_bytes());
        bytes.extend_from_slice(&identity.network_id);
        bytes.extend_from_slice(&identity.key_id.to_be_bytes());
        bytes.push(identity.purpose as u8);
        bytes.extend_from_slice(&identity.credential_id.to_be_bytes());
        bytes.extend_from_slice(&identity.issuer_id.to_be_bytes());
        let issuer_fingerprint: [u8; 32] = Sha256::digest(identity.issuer_public_key).into();
        bytes.extend_from_slice(&issuer_fingerprint);
        bytes.extend_from_slice(&self.high_generation.to_be_bytes());
        bytes.extend_from_slice(&self.record_digest);
        bytes.extend_from_slice(&self.identity_digest);
        bytes.push(self.state);
        debug_assert_eq!(bytes.len(), STATE_BODY_LEN);
        let checksum: [u8; 32] = Sha256::digest(&bytes).into();
        bytes.extend_from_slice(&checksum);
        bytes
    }

    fn decode(bytes: &[u8], expected: &IdentityConfig) -> Result<Self, IdentityGenerationError> {
        if bytes.len() != STATE_WIRE_LEN
            || &bytes[..4] != STATE_MAGIC
            || u16::from_be_bytes(bytes[4..6].try_into().unwrap()) != STATE_VERSION
        {
            return Err(IdentityGenerationError::StateMalformed);
        }
        let checksum: [u8; 32] = Sha256::digest(&bytes[..STATE_BODY_LEN]).into();
        if checksum.as_slice() != &bytes[STATE_BODY_LEN..] {
            return Err(IdentityGenerationError::StateMalformed);
        }

        let network_id: [u8; 32] = bytes[6..38].try_into().unwrap();
        let key_id = u32::from_be_bytes(bytes[38..42].try_into().unwrap());
        let purpose =
            KeyPurpose::try_from(bytes[42]).map_err(|_| IdentityGenerationError::StateMalformed)?;
        let credential_id = u128::from_be_bytes(bytes[43..59].try_into().unwrap());
        let issuer_id = u32::from_be_bytes(bytes[59..63].try_into().unwrap());
        let issuer_fingerprint: [u8; 32] = bytes[63..95].try_into().unwrap();
        let expected_issuer_fingerprint: [u8; 32] =
            Sha256::digest(expected.issuer_public_key).into();
        if network_id != expected.network_id
            || key_id != expected.key_id
            || purpose != expected.purpose
            || credential_id != expected.credential_id
            || issuer_id != expected.issuer_id
            || issuer_fingerprint != expected_issuer_fingerprint
        {
            return Err(IdentityGenerationError::IdentityMismatch);
        }

        let state = Self {
            high_generation: u32::from_be_bytes(bytes[95..99].try_into().unwrap()),
            record_digest: bytes[99..131].try_into().unwrap(),
            identity_digest: bytes[131..163].try_into().unwrap(),
            state: bytes[163],
        };
        if state.state > 3
            || (state.high_generation == 0
                && (state.state != 0
                    || state.record_digest != [0; 32]
                    || state.identity_digest != [0; 32]))
            || (state.high_generation != 0 && state.state == 0)
        {
            return Err(IdentityGenerationError::StateMalformed);
        }
        Ok(state)
    }
}

/// One file protects the high-water for one network/issuer/credential/key/purpose tuple.
/// Hold its OS writer lock for the whole node lifetime.
pub struct IdentityGenerationStateStore {
    path: PathBuf,
    identity: IdentityConfig,
    _writer_lock: SnapshotWriterLock,
    state: Mutex<PersistedState>,
}

impl IdentityGenerationStateStore {
    pub fn open(
        path: impl AsRef<Path>,
        network_id: &[u8; 32],
        key_id: u32,
        purpose: KeyPurpose,
        credential_id: u128,
        issuer_id: u32,
        issuer_public_key: [u8; 32],
    ) -> Result<Self, IdentityGenerationError> {
        let path = path.as_ref().to_path_buf();
        if path.file_name().is_none() || !parent_directory(&path).is_dir() {
            return Err(IdentityGenerationError::InvalidPath);
        }
        VerifyingKey::from_bytes(&issuer_public_key)
            .map_err(|_| IdentityGenerationError::IdentityMismatch)?;
        if key_id == 0 || credential_id == 0 || issuer_id == 0 {
            return Err(IdentityGenerationError::IdentityMismatch);
        }

        let lock_path = lock_path_for(&path)?;
        let lock_existed_before = lock_path.exists();
        let identity = IdentityConfig {
            network_id: *network_id,
            key_id,
            purpose,
            credential_id,
            issuer_id,
            issuer_public_key,
        };
        let writer_lock = SnapshotWriterLock::acquire(&path).map_err(map_lock_error)?;

        let state = if path.exists() {
            let mut file = File::open(&path).map_err(|_| IdentityGenerationError::Persistence)?;
            let length = file
                .metadata()
                .map_err(|_| IdentityGenerationError::Persistence)?
                .len();
            if length != STATE_WIRE_LEN as u64 {
                return Err(IdentityGenerationError::StateMalformed);
            }
            let mut bytes = Vec::with_capacity(STATE_WIRE_LEN);
            file.read_to_end(&mut bytes)
                .map_err(|_| IdentityGenerationError::Persistence)?;
            PersistedState::decode(&bytes, &identity)?
        } else if lock_existed_before {
            // The stable lock file intentionally survives process exit. Its presence with a
            // missing state means initialized state was deleted or rolled back.
            return Err(IdentityGenerationError::StateMissing);
        } else {
            let initial = PersistedState::empty();
            persist_atomic(&path, &initial.encode(&identity))?;
            initial
        };

        Ok(Self {
            path,
            identity,
            _writer_lock: writer_lock,
            state: Mutex::new(state),
        })
    }

    pub fn high_generation(&self) -> Result<Option<u32>, IdentityGenerationError> {
        let state = self
            .state
            .lock()
            .map_err(|_| IdentityGenerationError::Persistence)?;
        Ok((state.high_generation != 0).then_some(state.high_generation))
    }

    /// The caller must first verify the detached issuer signature on record_bytes.
    /// Advancing a generation also requires a signed transition from the currently persisted
    /// record digest to the exact new record digest. Every state change is persisted atomically.
    pub fn observe_signed_record(
        &self,
        record_bytes: &[u8],
        record: &KeyRecord,
        rotation_wire: Option<&[u8]>,
    ) -> Result<(), IdentityGenerationError> {
        let decoded = decode_key_record(record_bytes)
            .map_err(|_| IdentityGenerationError::RecordMalformed)?;
        if &decoded != record
            || record.algorithm != KeyAlgorithm::NoiseX25519
            || record.purpose != self.identity.purpose
            || record.key_id != self.identity.key_id
            || record.generation == 0
        {
            return Err(IdentityGenerationError::IdentityMismatch);
        }

        let record_digest: [u8; 32] = Sha256::digest(record_bytes).into();
        let identity_digest = identity_projection_digest(record_bytes)?;
        let new_state = state_to_byte(record.state);
        let mut current = self
            .state
            .lock()
            .map_err(|_| IdentityGenerationError::Persistence)?;

        if current.high_generation == 0 {
            if record.state != KeyState::Active {
                return Err(IdentityGenerationError::InvalidInitialState);
            }
            let next = PersistedState {
                high_generation: record.generation,
                record_digest,
                identity_digest,
                state: new_state,
            };
            persist_atomic(&self.path, &next.encode(&self.identity))?;
            *current = next;
            return Ok(());
        }

        if record.generation < current.high_generation {
            return Err(IdentityGenerationError::GenerationRollback);
        }

        if record.generation == current.high_generation {
            if record_digest == current.record_digest && new_state == current.state {
                return Ok(());
            }
            if current.state == 3 {
                return Err(IdentityGenerationError::RevokedTerminal);
            }
            let permitted_lifecycle_change = identity_digest == current.identity_digest
                && ((new_state == 3 && matches!(current.state, 1 | 2))
                    || (new_state == 2 && current.state == 1));
            if !permitted_lifecycle_change {
                return Err(IdentityGenerationError::SameGenerationMutation);
            }
            let next = PersistedState {
                high_generation: record.generation,
                record_digest,
                identity_digest,
                state: new_state,
            };
            persist_atomic(&self.path, &next.encode(&self.identity))?;
            *current = next;
            return Ok(());
        }

        if current.state == 3 {
            return Err(IdentityGenerationError::RevokedTerminal);
        }
        if record.state != KeyState::Active
            || current.high_generation.checked_add(1) != Some(record.generation)
        {
            return Err(IdentityGenerationError::RotationMismatch);
        }
        let rotation = rotation_wire.ok_or(IdentityGenerationError::RotationMissing)?;
        self.verify_rotation_statement(rotation, &current, record.generation, &record_digest)?;

        let next = PersistedState {
            high_generation: record.generation,
            record_digest,
            identity_digest,
            state: new_state,
        };
        persist_atomic(&self.path, &next.encode(&self.identity))?;
        *current = next;
        Ok(())
    }

    fn verify_rotation_statement(
        &self,
        wire: &[u8],
        current: &PersistedState,
        to_generation: u32,
        to_digest: &[u8; 32],
    ) -> Result<(), IdentityGenerationError> {
        if wire.len() != ROTATION_WIRE_LEN
            || &wire[..4] != ROTATION_MAGIC
            || u16::from_be_bytes(wire[4..6].try_into().unwrap()) != ROTATION_VERSION
        {
            return Err(IdentityGenerationError::RotationMalformed);
        }
        let network_id: [u8; 32] = wire[6..38].try_into().unwrap();
        let credential_id = u128::from_be_bytes(wire[38..54].try_into().unwrap());
        let issuer_id = u32::from_be_bytes(wire[54..58].try_into().unwrap());
        let key_id = u32::from_be_bytes(wire[58..62].try_into().unwrap());
        let purpose = KeyPurpose::try_from(wire[62])
            .map_err(|_| IdentityGenerationError::RotationMalformed)?;
        let from_generation = u32::from_be_bytes(wire[63..67].try_into().unwrap());
        let from_digest: [u8; 32] = wire[67..99].try_into().unwrap();
        let to_gen = u32::from_be_bytes(wire[99..103].try_into().unwrap());
        let stated_to_digest: [u8; 32] = wire[103..135].try_into().unwrap();
        if network_id != self.identity.network_id
            || credential_id != self.identity.credential_id
            || issuer_id != self.identity.issuer_id
            || key_id != self.identity.key_id
            || purpose != self.identity.purpose
            || from_generation != current.high_generation
            || from_digest != current.record_digest
            || to_gen != to_generation
            || &stated_to_digest != to_digest
        {
            return Err(IdentityGenerationError::RotationMismatch);
        }
        let issuer = VerifyingKey::from_bytes(&self.identity.issuer_public_key)
            .map_err(|_| IdentityGenerationError::IdentityMismatch)?;
        let signature = Signature::from_slice(&wire[ROTATION_CORE_LEN..])
            .map_err(|_| IdentityGenerationError::RotationMalformed)?;
        let mut message = Vec::with_capacity(ROTATION_DOMAIN.len() + ROTATION_CORE_LEN);
        message.extend_from_slice(ROTATION_DOMAIN);
        message.extend_from_slice(&wire[..ROTATION_CORE_LEN]);
        issuer
            .verify_strict(&message, &signature)
            .map_err(|_| IdentityGenerationError::RotationSignature)
    }
}

/// Encode an issuer-authorized, exact-successor Noise peer-key rotation statement (NRT1).
/// The old and new KeyRecords must already be canonically encoded; callers must also verify the
/// issuer's authorization and ensure the signing key matches the active immutable issuer entry.
pub fn encode_signed_rotation_statement(
    network_id: [u8; 32],
    credential_id: u128,
    issuer_id: u32,
    old_record_bytes: &[u8],
    new_record_bytes: &[u8],
    issuer_signing_key: &SigningKey,
) -> Result<Vec<u8>, IdentityGenerationError> {
    if network_id.iter().all(|byte| *byte == 0) || credential_id == 0 || issuer_id == 0 {
        return Err(IdentityGenerationError::IdentityMismatch);
    }
    let old_record = decode_key_record(old_record_bytes)
        .map_err(|_| IdentityGenerationError::RecordMalformed)?;
    let new_record = decode_key_record(new_record_bytes)
        .map_err(|_| IdentityGenerationError::RecordMalformed)?;
    if old_record.key_id == 0
        || old_record.key_id != new_record.key_id
        || old_record.algorithm != KeyAlgorithm::NoiseX25519
        || new_record.algorithm != KeyAlgorithm::NoiseX25519
        || old_record.purpose != KeyPurpose::PeerAuth
        || new_record.purpose != KeyPurpose::PeerAuth
        || old_record.public_key.len() != 32
        || new_record.public_key.len() != 32
        || old_record.public_key.iter().all(|byte| *byte == 0)
        || new_record.public_key.iter().all(|byte| *byte == 0)
        || old_record.state == KeyState::Revoked
        || new_record.state != KeyState::Active
        || old_record.public_key == new_record.public_key
        || old_record.generation == 0
        || old_record.generation.checked_add(1) != Some(new_record.generation)
    {
        return Err(IdentityGenerationError::RotationMismatch);
    }

    let old_digest: [u8; 32] = Sha256::digest(old_record_bytes).into();
    let new_digest: [u8; 32] = Sha256::digest(new_record_bytes).into();
    let mut core = Vec::with_capacity(ROTATION_CORE_LEN);
    core.extend_from_slice(ROTATION_MAGIC);
    core.extend_from_slice(&ROTATION_VERSION.to_be_bytes());
    core.extend_from_slice(&network_id);
    core.extend_from_slice(&credential_id.to_be_bytes());
    core.extend_from_slice(&issuer_id.to_be_bytes());
    core.extend_from_slice(&old_record.key_id.to_be_bytes());
    core.push(KeyPurpose::PeerAuth as u8);
    core.extend_from_slice(&old_record.generation.to_be_bytes());
    core.extend_from_slice(&old_digest);
    core.extend_from_slice(&new_record.generation.to_be_bytes());
    core.extend_from_slice(&new_digest);
    if core.len() != ROTATION_CORE_LEN {
        return Err(IdentityGenerationError::RotationMalformed);
    }
    let mut message = Vec::with_capacity(ROTATION_DOMAIN.len() + ROTATION_CORE_LEN);
    message.extend_from_slice(ROTATION_DOMAIN);
    message.extend_from_slice(&core);
    core.extend_from_slice(&issuer_signing_key.sign(&message).to_bytes());
    if core.len() != ROTATION_WIRE_LEN {
        return Err(IdentityGenerationError::RotationMalformed);
    }
    Ok(core)
}

fn state_to_byte(state: KeyState) -> u8 {
    match state {
        KeyState::Active => 1,
        KeyState::Retired => 2,
        KeyState::Revoked => 3,
    }
}

fn identity_projection_digest(record_bytes: &[u8]) -> Result<[u8; 32], IdentityGenerationError> {
    if record_bytes.len() < HEADER_LEN {
        return Err(IdentityGenerationError::RecordMalformed);
    }
    let mut projection = record_bytes.to_vec();
    // State is the only record field allowed to change without incrementing generation.
    projection[5] = 0;
    Ok(Sha256::digest(&projection).into())
}

fn lock_path_for(path: &Path) -> Result<PathBuf, IdentityGenerationError> {
    let name = path
        .file_name()
        .ok_or(IdentityGenerationError::InvalidPath)?;
    Ok(parent_directory(path).join(format!("{}.writer.lock", name.to_string_lossy())))
}

fn map_lock_error(_: SnapshotStoreError) -> IdentityGenerationError {
    IdentityGenerationError::Locked
}

fn parent_directory(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

fn persist_atomic(path: &Path, bytes: &[u8]) -> Result<(), IdentityGenerationError> {
    let parent = parent_directory(path);
    let name = path
        .file_name()
        .ok_or(IdentityGenerationError::InvalidPath)?
        .to_string_lossy();
    let id = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
    let temporary = parent.join(format!(
        ".{name}.identity.{}.{}.tmp",
        std::process::id(),
        id
    ));
    let result = (|| -> io::Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        file.write_all(bytes)?;
        file.flush()?;
        file.sync_all()?;
        drop(file);
        atomic_replace(&temporary, path)?;
        #[cfg(unix)]
        File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result.map_err(|_| IdentityGenerationError::Persistence)
}

#[cfg(windows)]
fn atomic_replace(source: &Path, destination: &Path) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    const REPLACE_EXISTING: u32 = 0x1;
    const WRITE_THROUGH: u32 = 0x8;
    let from: Vec<u16> = source
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let to: Vec<u16> = destination
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    #[link(name = "Kernel32")]
    extern "system" {
        fn MoveFileExW(existing: *const u16, new_name: *const u16, flags: u32) -> i32;
    }
    let ok = unsafe { MoveFileExW(from.as_ptr(), to.as_ptr(), REPLACE_EXISTING | WRITE_THROUGH) };
    if ok == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(not(windows))]
fn atomic_replace(source: &Path, destination: &Path) -> io::Result<()> {
    fs::rename(source, destination)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use std::{
        sync::atomic::{AtomicU64, Ordering},
        time::{SystemTime, UNIX_EPOCH},
    };

    static NEXT_TEST_ID: AtomicU64 = AtomicU64::new(1);

    struct Fixture {
        root: PathBuf,
        path: PathBuf,
        network: [u8; 32],
        issuer: SigningKey,
    }

    impl Fixture {
        fn new() -> Self {
            let tick = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let root = std::env::temp_dir().join(format!(
                "ain1_identity_state_{}_{}_{}",
                std::process::id(),
                tick,
                NEXT_TEST_ID.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir_all(&root).unwrap();
            Self {
                path: root.join("identity.highwater"),
                root,
                network: [0x42; 32],
                issuer: SigningKey::from_bytes(&[0x91; 32]),
            }
        }

        fn record(&self, generation: u32, state: KeyState, public: [u8; 32]) -> Vec<u8> {
            let record = KeyRecord {
                key_id: 700,
                generation,
                algorithm: KeyAlgorithm::NoiseX25519,
                purpose: KeyPurpose::PeerAuth,
                state,
                not_before: 100,
                not_after: 900,
                public_key: public.to_vec(),
            };
            crate::identity_policy::encode(&record).unwrap()
        }

        fn store(&self) -> IdentityGenerationStateStore {
            IdentityGenerationStateStore::open(
                &self.path,
                &self.network,
                700,
                KeyPurpose::PeerAuth,
                9001,
                17,
                self.issuer.verifying_key().to_bytes(),
            )
            .unwrap()
        }

        fn rotation(&self, from: u32, old: &[u8], to: u32, new: &[u8]) -> Vec<u8> {
            let old_digest: [u8; 32] = Sha256::digest(old).into();
            let new_digest: [u8; 32] = Sha256::digest(new).into();
            let mut core = Vec::with_capacity(ROTATION_CORE_LEN);
            core.extend_from_slice(ROTATION_MAGIC);
            core.extend_from_slice(&ROTATION_VERSION.to_be_bytes());
            core.extend_from_slice(&self.network);
            core.extend_from_slice(&9001u128.to_be_bytes());
            core.extend_from_slice(&17u32.to_be_bytes());
            core.extend_from_slice(&700u32.to_be_bytes());
            core.push(KeyPurpose::PeerAuth as u8);
            core.extend_from_slice(&from.to_be_bytes());
            core.extend_from_slice(&old_digest);
            core.extend_from_slice(&to.to_be_bytes());
            core.extend_from_slice(&new_digest);
            assert_eq!(core.len(), ROTATION_CORE_LEN);
            let mut message = ROTATION_DOMAIN.to_vec();
            message.extend_from_slice(&core);
            let signature = self.issuer.sign(&message);
            core.extend_from_slice(&signature.to_bytes());
            core
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    fn observe(
        store: &IdentityGenerationStateStore,
        bytes: &[u8],
        rotation: Option<&[u8]>,
    ) -> Result<(), IdentityGenerationError> {
        let record = decode_key_record(bytes).unwrap();
        store.observe_signed_record(bytes, &record, rotation)
    }

    #[test]
    fn signed_rotation_persists_high_water_and_rejects_old_record_after_restart() {
        let f = Fixture::new();
        let old = f.record(2, KeyState::Active, [0x21; 32]);
        let next = f.record(3, KeyState::Active, [0x22; 32]);
        {
            let store = f.store();
            observe(&store, &old, None).unwrap();
            let rotation = f.rotation(2, &old, 3, &next);
            observe(&store, &next, Some(&rotation)).unwrap();
            assert_eq!(store.high_generation().unwrap(), Some(3));
        }
        let store = f.store();
        assert_eq!(
            observe(&store, &old, None),
            Err(IdentityGenerationError::GenerationRollback)
        );
        observe(&store, &next, None).unwrap();
    }

    #[test]
    fn higher_generation_requires_exact_signed_rotation_statement() {
        let f = Fixture::new();
        let old = f.record(2, KeyState::Active, [0x21; 32]);
        let next = f.record(3, KeyState::Active, [0x22; 32]);
        let store = f.store();
        observe(&store, &old, None).unwrap();
        assert_eq!(
            observe(&store, &next, None),
            Err(IdentityGenerationError::RotationMissing)
        );
        let mut rotation = f.rotation(2, &old, 3, &next);
        rotation[ROTATION_CORE_LEN] ^= 0x80;
        assert_eq!(
            observe(&store, &next, Some(&rotation)),
            Err(IdentityGenerationError::RotationSignature)
        );
        let rotation = f.rotation(1, &old, 3, &next);
        assert_eq!(
            observe(&store, &next, Some(&rotation)),
            Err(IdentityGenerationError::RotationMismatch)
        );
    }

    #[test]
    fn same_generation_key_substitution_rejected_and_revocation_is_terminal() {
        let f = Fixture::new();
        let active = f.record(2, KeyState::Active, [0x21; 32]);
        let changed_key = f.record(2, KeyState::Active, [0x22; 32]);
        let revoked = f.record(2, KeyState::Revoked, [0x21; 32]);
        let store = f.store();
        observe(&store, &active, None).unwrap();
        assert_eq!(
            observe(&store, &changed_key, None),
            Err(IdentityGenerationError::SameGenerationMutation)
        );
        observe(&store, &revoked, None).unwrap();
        assert_eq!(
            observe(&store, &active, None),
            Err(IdentityGenerationError::RevokedTerminal)
        );
    }

    #[test]
    fn missing_state_after_initialization_fails_closed() {
        let f = Fixture::new();
        {
            let _store = f.store();
            assert!(f.path.exists());
        }
        fs::remove_file(&f.path).unwrap();
        assert_eq!(
            IdentityGenerationStateStore::open(
                &f.path,
                &f.network,
                700,
                KeyPurpose::PeerAuth,
                9001,
                17,
                f.issuer.verifying_key().to_bytes()
            )
            .err(),
            Some(IdentityGenerationError::StateMissing)
        );
    }

    #[test]
    fn state_file_is_bound_to_trusted_issuer_and_identity_configuration() {
        let f = Fixture::new();
        {
            let _store = f.store();
        }
        let other_issuer = SigningKey::from_bytes(&[0x92; 32]);
        assert_eq!(
            IdentityGenerationStateStore::open(
                &f.path,
                &f.network,
                700,
                KeyPurpose::PeerAuth,
                9001,
                17,
                other_issuer.verifying_key().to_bytes()
            )
            .err(),
            Some(IdentityGenerationError::IdentityMismatch)
        );
    }
}
