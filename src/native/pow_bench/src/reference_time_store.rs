//! Durable, process-exclusive high-water state for authenticated reference time.
//!
//! The checksum detects accidental corruption; it is not an authentication tag. The state
//! file must live in an operator-controlled directory with restrictive filesystem ACLs.
use crate::chain_admission::ReferenceTimeError;
use crate::{
    reference_time::{PolicyTrustState, VerifiedReferenceTimePolicy},
    snapshot_store::{SnapshotStoreError, SnapshotWriterLock},
};
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

const MAGIC: &[u8; 4] = b"RTS1";
const VERSION: u16 = 1;
const BODY_LEN: usize = 86;
const WIRE_LEN: usize = BODY_LEN + 32;
static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone, PartialEq, Eq)]
struct State {
    network_id: [u8; 32],
    policy_sequence: u64,
    policy_digest: [u8; 32],
    authority_sequence: u64,
}

impl State {
    fn empty(network_id: [u8; 32]) -> Self {
        Self {
            network_id,
            policy_sequence: 0,
            policy_digest: [0; 32],
            authority_sequence: 0,
        }
    }

    fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(WIRE_LEN);
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&VERSION.to_be_bytes());
        bytes.extend_from_slice(&self.network_id);
        bytes.extend_from_slice(&self.policy_sequence.to_be_bytes());
        bytes.extend_from_slice(&self.policy_digest);
        bytes.extend_from_slice(&self.authority_sequence.to_be_bytes());
        let checksum: [u8; 32] = Sha256::digest(&bytes).into();
        bytes.extend_from_slice(&checksum);
        debug_assert_eq!(bytes.len(), WIRE_LEN);
        bytes
    }

    fn decode(bytes: &[u8], expected_network: &[u8; 32]) -> Result<Self, ReferenceTimeError> {
        if bytes.len() != WIRE_LEN
            || &bytes[..4] != MAGIC
            || u16::from_be_bytes(bytes[4..6].try_into().unwrap()) != VERSION
        {
            return Err(ReferenceTimeError::StateMalformed);
        }
        let checksum: [u8; 32] = Sha256::digest(&bytes[..BODY_LEN]).into();
        if checksum.as_slice() != &bytes[BODY_LEN..] {
            return Err(ReferenceTimeError::StateMalformed);
        }
        let network_id: [u8; 32] = bytes[6..38].try_into().unwrap();
        if &network_id != expected_network {
            return Err(ReferenceTimeError::PolicyNetworkMismatch);
        }
        let policy_sequence = u64::from_be_bytes(bytes[38..46].try_into().unwrap());
        let policy_digest: [u8; 32] = bytes[46..78].try_into().unwrap();
        let authority_sequence = u64::from_be_bytes(bytes[78..86].try_into().unwrap());
        if (policy_sequence == 0) != (policy_digest == [0; 32]) {
            return Err(ReferenceTimeError::StateMalformed);
        }
        Ok(Self {
            network_id,
            policy_sequence,
            policy_digest,
            authority_sequence,
        })
    }
}

/// Holds the OS-level exclusive lock for its entire lifetime. Open a fresh instance only
/// after the previous process has closed; simultaneous node instances fail closed.
pub struct ReferenceTimeStateStore {
    path: PathBuf,
    _writer_lock: SnapshotWriterLock,
    state: Mutex<State>,
}

impl ReferenceTimeStateStore {
    pub fn open(
        path: impl AsRef<Path>,
        expected_network_id: &[u8; 32],
    ) -> Result<Self, ReferenceTimeError> {
        let path = path.as_ref().to_path_buf();
        let parent = parent_directory(&path);
        if path.file_name().is_none() || !parent.is_dir() {
            return Err(ReferenceTimeError::StatePersistence);
        }
        let writer_lock = SnapshotWriterLock::acquire(&path).map_err(map_lock_error)?;
        let state = if path.exists() {
            let mut file = File::open(&path).map_err(|_| ReferenceTimeError::StatePersistence)?;
            let length = file
                .metadata()
                .map_err(|_| ReferenceTimeError::StatePersistence)?
                .len();
            if length != WIRE_LEN as u64 {
                return Err(ReferenceTimeError::StateMalformed);
            }
            let mut bytes = Vec::with_capacity(WIRE_LEN);
            file.read_to_end(&mut bytes)
                .map_err(|_| ReferenceTimeError::StatePersistence)?;
            State::decode(&bytes, expected_network_id)?
        } else {
            let state = State::empty(*expected_network_id);
            persist_atomic(&path, &state.encode())?;
            state
        };
        Ok(Self {
            path,
            _writer_lock: writer_lock,
            state: Mutex::new(state),
        })
    }

    pub fn policy_trust_state(&self) -> Result<PolicyTrustState, ReferenceTimeError> {
        let state = self
            .state
            .lock()
            .map_err(|_| ReferenceTimeError::StatePersistence)?;
        PolicyTrustState::from_persisted(
            state.policy_sequence,
            (state.policy_sequence != 0).then_some(state.policy_digest),
        )
        .map_err(|_| ReferenceTimeError::StateMalformed)
    }

    pub fn last_accepted_sequence(&self) -> Result<u64, ReferenceTimeError> {
        Ok(self
            .state
            .lock()
            .map_err(|_| ReferenceTimeError::StatePersistence)?
            .authority_sequence)
    }

    /// Persist a newly authenticated policy before using it. Equal-sequence documents must
    /// have exactly the same digest; an authority-key rotation needs a greater policy sequence.
    pub fn record_policy(
        &self,
        policy: &VerifiedReferenceTimePolicy,
    ) -> Result<(), ReferenceTimeError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| ReferenceTimeError::StatePersistence)?;
        if policy.network_id() != &state.network_id
            || policy.sequence() < state.policy_sequence
            || (policy.sequence() == state.policy_sequence
                && state.policy_sequence != 0
                && policy.digest() != &state.policy_digest)
        {
            return Err(ReferenceTimeError::PolicyRollback);
        }
        if policy.sequence() > state.policy_sequence {
            let mut next = state.clone();
            next.policy_sequence = policy.sequence();
            next.policy_digest = *policy.digest();
            persist_atomic(&self.path, &next.encode())?;
            *state = next;
        }
        Ok(())
    }

    /// Advance the per-network authority sequence only after signature/challenge validation.
    /// Sequence numbers are global across key rotations for this network, preventing an old
    /// authority key from resetting the rollback floor when it is re-authorized later.
    pub fn advance_authority_sequence(&self, sequence: u64) -> Result<(), ReferenceTimeError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| ReferenceTimeError::StatePersistence)?;
        if sequence == 0 || sequence <= state.authority_sequence {
            return Err(ReferenceTimeError::SequenceRollback);
        }
        let mut next = state.clone();
        next.authority_sequence = sequence;
        persist_atomic(&self.path, &next.encode())?;
        *state = next;
        Ok(())
    }
}

fn map_lock_error(error: SnapshotStoreError) -> ReferenceTimeError {
    match error {
        SnapshotStoreError::WriterLockBusy(_) => ReferenceTimeError::StateLocked,
        _ => ReferenceTimeError::StatePersistence,
    }
}

fn parent_directory(path: &Path) -> &Path {
    path.parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

fn persist_atomic(path: &Path, bytes: &[u8]) -> Result<(), ReferenceTimeError> {
    let parent = parent_directory(path);
    let name = path
        .file_name()
        .ok_or(ReferenceTimeError::StatePersistence)?
        .to_string_lossy();
    let id = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
    let temporary = parent.join(format!(".{name}.rtstate.{}.{}.tmp", std::process::id(), id));
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
    result.map_err(|_| ReferenceTimeError::StatePersistence)
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
    use crate::reference_time::{POLICY_DOMAIN, POLICY_MAGIC, WIRE_VERSION};
    use ed25519_dalek::{Signer, SigningKey};
    use std::{
        sync::atomic::{AtomicU64, Ordering},
        time::{SystemTime, UNIX_EPOCH},
    };
    static ID: AtomicU64 = AtomicU64::new(1);
    const NETWORK: [u8; 32] = [0xA5; 32];
    const ADMIN_SEED: [u8; 32] = [0x42; 32];
    const AUTHORITY_SEED: [u8; 32] = [0x24; 32];

    fn unique_path() -> PathBuf {
        std::env::temp_dir().join(format!(
            "ain1-reference-time-state-{}-{}.bin",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            ID.fetch_add(1, Ordering::Relaxed)
        ))
    }
    fn key(seed: [u8; 32]) -> SigningKey {
        SigningKey::from_bytes(&seed)
    }
    fn policy_wire(sequence: u64, authority: [u8; 32]) -> Vec<u8> {
        let admin = key(ADMIN_SEED);
        let mut bytes = Vec::new();
        bytes.extend_from_slice(POLICY_MAGIC);
        bytes.extend_from_slice(&WIRE_VERSION.to_be_bytes());
        bytes.extend_from_slice(&NETWORK);
        bytes.extend_from_slice(&sequence.to_be_bytes());
        bytes.extend_from_slice(&authority);
        bytes.extend_from_slice(&500u32.to_be_bytes());
        bytes.extend_from_slice(&u64::MAX.to_be_bytes());
        let signature = admin.sign(&[POLICY_DOMAIN, &bytes].concat()).to_bytes();
        bytes.extend_from_slice(&signature);
        bytes
    }
    fn verified(
        store: &ReferenceTimeStateStore,
        sequence: u64,
        authority_seed: [u8; 32],
    ) -> VerifiedReferenceTimePolicy {
        let admin = key(ADMIN_SEED);
        VerifiedReferenceTimePolicy::verify(
            &policy_wire(sequence, key(authority_seed).verifying_key().to_bytes()),
            &NETWORK,
            &admin.verifying_key().to_bytes(),
            &store.policy_trust_state().unwrap(),
        )
        .unwrap()
    }
    fn remove_store(path: &Path) {
        let _ = fs::remove_file(path);
        let lock = path.with_file_name(format!(
            "{}.writer.lock",
            path.file_name().unwrap().to_string_lossy()
        ));
        let _ = fs::remove_file(lock);
    }

    #[test]
    fn policy_and_authority_high_waters_survive_store_reopen_and_key_rotation() {
        let path = unique_path();
        {
            let store = ReferenceTimeStateStore::open(&path, &NETWORK).unwrap();
            assert_eq!(store.last_accepted_sequence().unwrap(), 0);
            let first = verified(&store, 1, AUTHORITY_SEED);
            store.record_policy(&first).unwrap();
            store.advance_authority_sequence(42).unwrap();
            assert_eq!(store.policy_trust_state().unwrap().highest_sequence(), 1);
        }
        {
            let store = ReferenceTimeStateStore::open(&path, &NETWORK).unwrap();
            assert_eq!(store.last_accepted_sequence().unwrap(), 42);
            assert_eq!(store.policy_trust_state().unwrap().highest_sequence(), 1);
            assert_eq!(
                store.record_policy(&verified(&store, 1, AUTHORITY_SEED)),
                Ok(())
            );
            assert_eq!(
                store.advance_authority_sequence(41),
                Err(ReferenceTimeError::SequenceRollback)
            );
            let rotated = verified(&store, 2, [0x31; 32]);
            store.record_policy(&rotated).unwrap();
            store.advance_authority_sequence(43).unwrap();
            assert_eq!(store.last_accepted_sequence().unwrap(), 43);
        }
        {
            let store = ReferenceTimeStateStore::open(&path, &NETWORK).unwrap();
            assert_eq!(store.last_accepted_sequence().unwrap(), 43);
            assert_eq!(store.policy_trust_state().unwrap().highest_sequence(), 2);
            let old = policy_wire(1, key(AUTHORITY_SEED).verifying_key().to_bytes());
            let admin = key(ADMIN_SEED);
            assert_eq!(
                VerifiedReferenceTimePolicy::verify(
                    &old,
                    &NETWORK,
                    &admin.verifying_key().to_bytes(),
                    &store.policy_trust_state().unwrap()
                ),
                Err(ReferenceTimeError::PolicyRollback)
            );
        }
        remove_store(&path);
    }

    #[test]
    fn corrupted_state_wrong_network_and_concurrent_writer_fail_closed() {
        let path = unique_path();
        let store = ReferenceTimeStateStore::open(&path, &NETWORK).unwrap();
        assert!(matches!(
            ReferenceTimeStateStore::open(&path, &NETWORK),
            Err(ReferenceTimeError::StateLocked)
        ));
        drop(store);
        fs::write(&path, b"broken").unwrap();
        assert_eq!(
            ReferenceTimeStateStore::open(&path, &NETWORK).err(),
            Some(ReferenceTimeError::StateMalformed)
        );
        remove_store(&path);

        let path = unique_path();
        let store = ReferenceTimeStateStore::open(&path, &NETWORK).unwrap();
        drop(store);
        let mut valid_length_but_corrupt = fs::read(&path).unwrap();
        valid_length_but_corrupt[80] ^= 0x01;
        fs::write(&path, valid_length_but_corrupt).unwrap();
        assert_eq!(
            ReferenceTimeStateStore::open(&path, &NETWORK).err(),
            Some(ReferenceTimeError::StateMalformed)
        );
        remove_store(&path);

        let path = unique_path();
        let store = ReferenceTimeStateStore::open(&path, &NETWORK).unwrap();
        drop(store);
        assert_eq!(
            ReferenceTimeStateStore::open(&path, &[0x88; 32]).err(),
            Some(ReferenceTimeError::PolicyNetworkMismatch)
        );
        remove_store(&path);
    }
}
