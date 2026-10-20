//! Signed, versioned issuer governance for provider-bound Noise identities.
//!
//! IRG1 registries are signed by an out-of-band pinned governance root. Issuer IDs are immutable:
//! changing signing keys requires a new issuer ID. Status can move Active -> Retired/Revoked and
//! Retired -> Revoked, never backwards. The durable local high-water detects registry rollback
//! while its protected state file and stable writer-lock sibling remain intact; it is not a
//! hardware monotonic counter.
use crate::{
    governance_root_chain::VerifiedGovernanceRootChain,
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

const REGISTRY_MAGIC: &[u8; 4] = b"IRG1";
const STORE_MAGIC: &[u8; 4] = b"IRH1";
const VERSION: u16 = 1;
const PREFIX_LEN: usize = 48;
const ENTRY_LEN: usize = 37;
const SIGNATURE_LEN: usize = 64;
pub const MAX_ISSUER_ENTRIES: usize = 32;
pub const MAX_REGISTRY_WIRE_LEN: usize =
    PREFIX_LEN + ENTRY_LEN * MAX_ISSUER_ENTRIES + SIGNATURE_LEN;
const STORE_HEADER_LEN: usize = 72;
const STORE_CHECKSUM_LEN: usize = 32;
static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(1);
const SIGNING_DOMAIN: &[u8] = b"AIN1-NOISE-ISSUER-REGISTRY-V1\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum IssuerStatus {
    Active = 1,
    Retired = 2,
    Revoked = 3,
}

impl TryFrom<u8> for IssuerStatus {
    type Error = IssuerRegistryError;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Active),
            2 => Ok(Self::Retired),
            3 => Ok(Self::Revoked),
            _ => Err(IssuerRegistryError::Malformed),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuerEntry {
    pub issuer_id: u32,
    pub public_key: [u8; 32],
    pub status: IssuerStatus,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IssuerRegistryError {
    Malformed,
    UnsupportedVersion,
    InvalidSignature,
    NetworkMismatch,
    InvalidGovernanceKey,
    InvalidIssuerKey,
    IssuerNotFound,
    IssuerInactive,
    SequenceRollback,
    SequenceBelowMinimum,
    InvalidMinimumSequence,
    SameSequenceConflict,
    IssuerRemoved,
    IssuerKeyChanged,
    StatusRollback,
    StateMissing,
    StateMalformed,
    StateIdentityMismatch,
    Persistence,
    Locked,
    InvalidPath,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedIssuerRegistry {
    network_id: [u8; 32],
    sequence: u64,
    digest: [u8; 32],
    entries: Vec<IssuerEntry>,
}

impl VerifiedIssuerRegistry {
    pub fn sequence(&self) -> u64 {
        self.sequence
    }
    pub fn digest(&self) -> &[u8; 32] {
        &self.digest
    }
    pub fn network_id(&self) -> &[u8; 32] {
        &self.network_id
    }
    pub fn entries(&self) -> &[IssuerEntry] {
        &self.entries
    }

    pub fn active_key(&self, issuer_id: u32) -> Result<[u8; 32], IssuerRegistryError> {
        let entry = self
            .entries
            .binary_search_by_key(&issuer_id, |entry| entry.issuer_id)
            .ok()
            .map(|index| &self.entries[index])
            .ok_or(IssuerRegistryError::IssuerNotFound)?;
        if entry.status != IssuerStatus::Active {
            return Err(IssuerRegistryError::IssuerInactive);
        }
        Ok(entry.public_key)
    }
}

pub fn verify_signed_registry(
    wire: &[u8],
    expected_network_id: &[u8; 32],
    governance_public_key: &[u8; 32],
) -> Result<VerifiedIssuerRegistry, IssuerRegistryError> {
    if wire.len() < PREFIX_LEN + ENTRY_LEN + SIGNATURE_LEN
        || wire.len() > MAX_REGISTRY_WIRE_LEN
        || &wire[..4] != REGISTRY_MAGIC
    {
        return Err(IssuerRegistryError::Malformed);
    }
    if u16::from_be_bytes(
        wire[4..6]
            .try_into()
            .map_err(|_| IssuerRegistryError::Malformed)?,
    ) != VERSION
    {
        return Err(IssuerRegistryError::UnsupportedVersion);
    }
    let network_id: [u8; 32] = wire[6..38]
        .try_into()
        .map_err(|_| IssuerRegistryError::Malformed)?;
    if &network_id != expected_network_id {
        return Err(IssuerRegistryError::NetworkMismatch);
    }
    let sequence = u64::from_be_bytes(
        wire[38..46]
            .try_into()
            .map_err(|_| IssuerRegistryError::Malformed)?,
    );
    let count = u16::from_be_bytes(
        wire[46..48]
            .try_into()
            .map_err(|_| IssuerRegistryError::Malformed)?,
    ) as usize;
    if sequence == 0
        || count == 0
        || count > MAX_ISSUER_ENTRIES
        || wire.len() != PREFIX_LEN + count * ENTRY_LEN + SIGNATURE_LEN
    {
        return Err(IssuerRegistryError::Malformed);
    }
    let governance = VerifyingKey::from_bytes(governance_public_key)
        .map_err(|_| IssuerRegistryError::InvalidGovernanceKey)?;
    let signature_offset = wire.len() - SIGNATURE_LEN;
    let signature = Signature::from_slice(&wire[signature_offset..])
        .map_err(|_| IssuerRegistryError::InvalidSignature)?;
    let mut preimage = Vec::with_capacity(SIGNING_DOMAIN.len() + signature_offset);
    preimage.extend_from_slice(SIGNING_DOMAIN);
    preimage.extend_from_slice(&wire[..signature_offset]);
    governance
        .verify_strict(&preimage, &signature)
        .map_err(|_| IssuerRegistryError::InvalidSignature)?;

    let mut entries = Vec::with_capacity(count);
    let mut last_id = 0u32;
    let mut offset = PREFIX_LEN;
    for _ in 0..count {
        let issuer_id = u32::from_be_bytes(
            wire[offset..offset + 4]
                .try_into()
                .map_err(|_| IssuerRegistryError::Malformed)?,
        );
        let status = IssuerStatus::try_from(wire[offset + 4])?;
        let public_key: [u8; 32] = wire[offset + 5..offset + ENTRY_LEN]
            .try_into()
            .map_err(|_| IssuerRegistryError::Malformed)?;
        if issuer_id == 0 || issuer_id <= last_id || public_key == [0; 32] {
            return Err(IssuerRegistryError::Malformed);
        }
        VerifyingKey::from_bytes(&public_key).map_err(|_| IssuerRegistryError::InvalidIssuerKey)?;
        entries.push(IssuerEntry {
            issuer_id,
            public_key,
            status,
        });
        last_id = issuer_id;
        offset += ENTRY_LEN;
    }
    Ok(VerifiedIssuerRegistry {
        network_id,
        sequence,
        digest: Sha256::digest(wire).into(),
        entries,
    })
}

/// Encode and self-verify an IRG1 registry using the canonical wire format.
pub fn encode_signed_registry(
    network_id: [u8; 32],
    sequence: u64,
    entries: &[IssuerEntry],
    signing_key: &SigningKey,
) -> Result<Vec<u8>, IssuerRegistryError> {
    if network_id.iter().all(|b| *b == 0)
        || sequence == 0
        || entries.is_empty()
        || entries.len() > MAX_ISSUER_ENTRIES
    {
        return Err(IssuerRegistryError::Malformed);
    }
    let mut wire = Vec::with_capacity(PREFIX_LEN + entries.len() * ENTRY_LEN + SIGNATURE_LEN);
    wire.extend_from_slice(REGISTRY_MAGIC);
    wire.extend_from_slice(&VERSION.to_be_bytes());
    wire.extend_from_slice(&network_id);
    wire.extend_from_slice(&sequence.to_be_bytes());
    wire.extend_from_slice(&(entries.len() as u16).to_be_bytes());
    let mut previous_id = 0u32;
    for entry in entries {
        if entry.issuer_id == 0 || entry.issuer_id <= previous_id || entry.public_key == [0; 32] {
            return Err(IssuerRegistryError::Malformed);
        }
        VerifyingKey::from_bytes(&entry.public_key)
            .map_err(|_| IssuerRegistryError::InvalidIssuerKey)?;
        wire.extend_from_slice(&entry.issuer_id.to_be_bytes());
        wire.push(entry.status as u8);
        wire.extend_from_slice(&entry.public_key);
        previous_id = entry.issuer_id;
    }
    let mut preimage = Vec::with_capacity(SIGNING_DOMAIN.len() + wire.len());
    preimage.extend_from_slice(SIGNING_DOMAIN);
    preimage.extend_from_slice(&wire);
    wire.extend_from_slice(&signing_key.sign(&preimage).to_bytes());
    verify_signed_registry(&wire, &network_id, &signing_key.verifying_key().to_bytes())?;
    Ok(wire)
}

#[derive(Debug, Clone)]
struct PersistedRegistry {
    network_id: [u8; 32],
    governance_fingerprint: [u8; 32],
    wire: Vec<u8>,
}

impl PersistedRegistry {
    fn empty(network_id: [u8; 32], governance_fingerprint: [u8; 32]) -> Self {
        Self {
            network_id,
            governance_fingerprint,
            wire: Vec::new(),
        }
    }

    fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(STORE_HEADER_LEN + self.wire.len() + STORE_CHECKSUM_LEN);
        bytes.extend_from_slice(STORE_MAGIC);
        bytes.extend_from_slice(&VERSION.to_be_bytes());
        bytes.extend_from_slice(&self.network_id);
        bytes.extend_from_slice(&self.governance_fingerprint);
        bytes.extend_from_slice(&(self.wire.len() as u16).to_be_bytes());
        bytes.extend_from_slice(&self.wire);
        let checksum: [u8; 32] = Sha256::digest(&bytes).into();
        bytes.extend_from_slice(&checksum);
        bytes
    }

    fn decode(
        bytes: &[u8],
        expected_network_id: &[u8; 32],
        root_chain: &VerifiedGovernanceRootChain,
    ) -> Result<Self, IssuerRegistryError> {
        if bytes.len() < STORE_HEADER_LEN + STORE_CHECKSUM_LEN
            || bytes.len() > STORE_HEADER_LEN + MAX_REGISTRY_WIRE_LEN + STORE_CHECKSUM_LEN
            || &bytes[..4] != STORE_MAGIC
            || u16::from_be_bytes(
                bytes[4..6]
                    .try_into()
                    .map_err(|_| IssuerRegistryError::StateMalformed)?,
            ) != VERSION
        {
            return Err(IssuerRegistryError::StateMalformed);
        }
        let payload_end = bytes.len() - STORE_CHECKSUM_LEN;
        let checksum: [u8; 32] = Sha256::digest(&bytes[..payload_end]).into();
        if checksum.as_slice() != &bytes[payload_end..] {
            return Err(IssuerRegistryError::StateMalformed);
        }
        let network_id: [u8; 32] = bytes[6..38]
            .try_into()
            .map_err(|_| IssuerRegistryError::StateMalformed)?;
        let governance_fingerprint: [u8; 32] = bytes[38..70]
            .try_into()
            .map_err(|_| IssuerRegistryError::StateMalformed)?;
        if &network_id != expected_network_id || root_chain.network_id() != expected_network_id {
            return Err(IssuerRegistryError::StateIdentityMismatch);
        }
        let historical_governance_key = root_chain
            .key_for_fingerprint(&governance_fingerprint)
            .ok_or(IssuerRegistryError::StateIdentityMismatch)?;
        let wire_len = u16::from_be_bytes(
            bytes[70..72]
                .try_into()
                .map_err(|_| IssuerRegistryError::StateMalformed)?,
        ) as usize;
        if STORE_HEADER_LEN + wire_len + STORE_CHECKSUM_LEN != bytes.len()
            || wire_len > MAX_REGISTRY_WIRE_LEN
        {
            return Err(IssuerRegistryError::StateMalformed);
        }
        let wire = bytes[STORE_HEADER_LEN..payload_end].to_vec();
        if !wire.is_empty() {
            let verified =
                verify_signed_registry(&wire, expected_network_id, &historical_governance_key)?;
            if verified.sequence == 0 {
                return Err(IssuerRegistryError::StateMalformed);
            }
        }
        Ok(Self {
            network_id,
            governance_fingerprint,
            wire,
        })
    }
}

/// Serializes registry updates and persists the last signed document before it can authorize a
/// peer. The pinned governance key is an out-of-band trust root and is public configuration.
pub struct IssuerRegistryStateStore {
    path: PathBuf,
    governance_public_key: [u8; 32],
    root_chain: VerifiedGovernanceRootChain,
    minimum_sequence: u64,
    _writer_lock: SnapshotWriterLock,
    state: Mutex<PersistedRegistry>,
}

impl IssuerRegistryStateStore {
    pub fn open(
        path: impl AsRef<Path>,
        network_id: &[u8; 32],
        governance_public_key: [u8; 32],
        minimum_sequence: u64,
    ) -> Result<Self, IssuerRegistryError> {
        let root_chain =
            VerifiedGovernanceRootChain::pinned_anchor(*network_id, governance_public_key)
                .map_err(|_| IssuerRegistryError::InvalidGovernanceKey)?;
        Self::open_with_root_chain(path, network_id, root_chain, minimum_sequence)
    }

    pub fn open_with_root_chain(
        path: impl AsRef<Path>,
        network_id: &[u8; 32],
        root_chain: VerifiedGovernanceRootChain,
        minimum_sequence: u64,
    ) -> Result<Self, IssuerRegistryError> {
        if root_chain.network_id() != network_id {
            return Err(IssuerRegistryError::StateIdentityMismatch);
        }
        let governance_public_key = *root_chain.current_key();
        VerifyingKey::from_bytes(&governance_public_key)
            .map_err(|_| IssuerRegistryError::InvalidGovernanceKey)?;
        if minimum_sequence == 0 {
            return Err(IssuerRegistryError::InvalidMinimumSequence);
        }
        let path = path.as_ref().to_path_buf();
        let parent = parent_directory(&path);
        if path.file_name().is_none() || !parent.is_dir() {
            return Err(IssuerRegistryError::InvalidPath);
        }
        let lock_path = lock_path_for(&path)?;
        let lock_existed_before = lock_path.exists();
        let writer_lock = SnapshotWriterLock::acquire(&path).map_err(map_lock_error)?;
        let current_governance_fingerprint: [u8; 32] = Sha256::digest(governance_public_key).into();
        let state = if path.exists() {
            let mut file = File::open(&path).map_err(|_| IssuerRegistryError::Persistence)?;
            let length = file
                .metadata()
                .map_err(|_| IssuerRegistryError::Persistence)?
                .len();
            if length < (STORE_HEADER_LEN + STORE_CHECKSUM_LEN) as u64
                || length > (STORE_HEADER_LEN + MAX_REGISTRY_WIRE_LEN + STORE_CHECKSUM_LEN) as u64
            {
                return Err(IssuerRegistryError::StateMalformed);
            }
            let mut bytes = Vec::with_capacity(length as usize);
            file.read_to_end(&mut bytes)
                .map_err(|_| IssuerRegistryError::Persistence)?;
            PersistedRegistry::decode(&bytes, network_id, &root_chain)?
        } else if lock_existed_before {
            return Err(IssuerRegistryError::StateMissing);
        } else {
            let initial = PersistedRegistry::empty(*network_id, current_governance_fingerprint);
            persist_atomic(&path, &initial.encode())?;
            initial
        };
        if !state.wire.is_empty() {
            let historical_key = root_chain
                .key_for_fingerprint(&state.governance_fingerprint)
                .ok_or(IssuerRegistryError::StateIdentityMismatch)?;
            let persisted = verify_signed_registry(&state.wire, network_id, &historical_key)?;
            let current_fingerprint: [u8; 32] = Sha256::digest(governance_public_key).into();
            // Existing state signed by the prior, chain-authorized root may be below a newly
            // raised floor while being migrated. The first document under the current root must
            // meet the new independent floor before it can replace that historical state.
            if persisted.sequence < minimum_sequence
                && state.governance_fingerprint == current_fingerprint
            {
                return Err(IssuerRegistryError::SequenceBelowMinimum);
            }
        }
        Ok(Self {
            path,
            governance_public_key,
            root_chain,
            minimum_sequence,
            _writer_lock: writer_lock,
            state: Mutex::new(state),
        })
    }

    /// Verify and durably accept a signed registry document; return the selected active issuer's
    /// public key. Revocations are persisted even though selection then returns IssuerInactive.
    pub fn accept_signed_registry(
        &self,
        wire: &[u8],
        selected_issuer_id: u32,
    ) -> Result<[u8; 32], IssuerRegistryError> {
        let next_verified =
            verify_signed_registry(wire, &self.state_network_id()?, &self.governance_public_key)?;
        if next_verified.sequence < self.minimum_sequence {
            return Err(IssuerRegistryError::SequenceBelowMinimum);
        }
        let mut current = self
            .state
            .lock()
            .map_err(|_| IssuerRegistryError::Persistence)?;
        if current.wire.is_empty() {
            let next = PersistedRegistry {
                network_id: current.network_id,
                governance_fingerprint: Sha256::digest(self.governance_public_key).into(),
                wire: wire.to_vec(),
            };
            persist_atomic(&self.path, &next.encode())?;
            *current = next;
        } else {
            let previous_governance_key = self
                .root_chain
                .key_for_fingerprint(&current.governance_fingerprint)
                .ok_or(IssuerRegistryError::StateIdentityMismatch)?;
            let previous = verify_signed_registry(
                &current.wire,
                &current.network_id,
                &previous_governance_key,
            )?;
            if next_verified.sequence < previous.sequence {
                return Err(IssuerRegistryError::SequenceRollback);
            }
            if next_verified.sequence == previous.sequence {
                if next_verified.digest != previous.digest {
                    return Err(IssuerRegistryError::SameSequenceConflict);
                }
            } else {
                validate_registry_transition(&previous, &next_verified)?;
                let next = PersistedRegistry {
                    network_id: current.network_id,
                    governance_fingerprint: Sha256::digest(self.governance_public_key).into(),
                    wire: wire.to_vec(),
                };
                persist_atomic(&self.path, &next.encode())?;
                *current = next;
            }
        }
        next_verified.active_key(selected_issuer_id)
    }

    fn state_network_id(&self) -> Result<[u8; 32], IssuerRegistryError> {
        Ok(self
            .state
            .lock()
            .map_err(|_| IssuerRegistryError::Persistence)?
            .network_id)
    }
}

/// Validate that a signed issuer-registry update preserves issuer identity and only advances
/// lifecycle state (Active -> Retired/Revoked, Retired -> Revoked). Removed IDs, changed keys,
/// reactivation and any transition out of Revoked are rejected.
pub fn validate_registry_transition(
    previous: &VerifiedIssuerRegistry,
    next: &VerifiedIssuerRegistry,
) -> Result<(), IssuerRegistryError> {
    for old in &previous.entries {
        let new = next
            .entries
            .iter()
            .find(|entry| entry.issuer_id == old.issuer_id)
            .ok_or(IssuerRegistryError::IssuerRemoved)?;
        if old.public_key != new.public_key {
            return Err(IssuerRegistryError::IssuerKeyChanged);
        }
        let permitted = match old.status {
            IssuerStatus::Active => true,
            IssuerStatus::Retired => {
                matches!(new.status, IssuerStatus::Retired | IssuerStatus::Revoked)
            }
            IssuerStatus::Revoked => new.status == IssuerStatus::Revoked,
        };
        if !permitted {
            return Err(IssuerRegistryError::StatusRollback);
        }
    }
    for new in &next.entries {
        if !previous
            .entries
            .iter()
            .any(|entry| entry.issuer_id == new.issuer_id)
            && new.status != IssuerStatus::Active
        {
            return Err(IssuerRegistryError::StatusRollback);
        }
    }
    Ok(())
}

fn lock_path_for(path: &Path) -> Result<PathBuf, IssuerRegistryError> {
    let name = path.file_name().ok_or(IssuerRegistryError::InvalidPath)?;
    Ok(parent_directory(path).join(format!("{}.writer.lock", name.to_string_lossy())))
}
fn parent_directory(path: &Path) -> &Path {
    path.parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}
fn map_lock_error(_: SnapshotStoreError) -> IssuerRegistryError {
    IssuerRegistryError::Locked
}

fn persist_atomic(path: &Path, bytes: &[u8]) -> Result<(), IssuerRegistryError> {
    let parent = parent_directory(path);
    let name = path
        .file_name()
        .ok_or(IssuerRegistryError::InvalidPath)?
        .to_string_lossy();
    let id = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
    let temporary = parent.join(format!(
        ".{name}.issuer-registry.{}.{}.tmp",
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
    result.map_err(|_| IssuerRegistryError::Persistence)
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
    use crate::governance_root_chain::{
        verify_governance_root_chain, verify_governance_root_chain_with_recovery,
    };
    use ed25519_dalek::{Signer, SigningKey};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_path(label: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "ain1-issuer-registry-{label}-{}-{nonce}.bin",
            std::process::id()
        ))
    }
    fn encode_signed(
        sequence: u64,
        network: [u8; 32],
        entries: &[IssuerEntry],
        root: &SigningKey,
    ) -> Vec<u8> {
        let mut sorted = entries.to_vec();
        sorted.sort_by_key(|entry| entry.issuer_id);
        let mut bytes = Vec::new();
        bytes.extend_from_slice(REGISTRY_MAGIC);
        bytes.extend_from_slice(&VERSION.to_be_bytes());
        bytes.extend_from_slice(&network);
        bytes.extend_from_slice(&sequence.to_be_bytes());
        bytes.extend_from_slice(&(sorted.len() as u16).to_be_bytes());
        for entry in sorted {
            bytes.extend_from_slice(&entry.issuer_id.to_be_bytes());
            bytes.push(entry.status as u8);
            bytes.extend_from_slice(&entry.public_key);
        }
        let mut preimage = SIGNING_DOMAIN.to_vec();
        preimage.extend_from_slice(&bytes);
        bytes.extend_from_slice(&root.sign(&preimage).to_bytes());
        bytes
    }
    fn encode_root_chain(network: [u8; 32], roots: &[SigningKey]) -> Vec<u8> {
        let count = roots.len().saturating_sub(1);
        let mut wire = Vec::new();
        wire.extend_from_slice(b"GRC1");
        wire.extend_from_slice(&1u16.to_be_bytes());
        wire.extend_from_slice(&network);
        wire.extend_from_slice(&(count as u16).to_be_bytes());
        for (index, pair) in roots.windows(2).enumerate() {
            let epoch = index as u64 + 2;
            let old_root = pair[0].verifying_key().to_bytes();
            let new_root = pair[1].verifying_key().to_bytes();
            let mut core = Vec::with_capacity(72);
            core.extend_from_slice(&epoch.to_be_bytes());
            core.extend_from_slice(&old_root);
            core.extend_from_slice(&new_root);
            let mut preimage = b"AIN1-NOISE-GOVERNANCE-ROOT-ROTATION-V1\0".to_vec();
            preimage.extend_from_slice(&network);
            preimage.extend_from_slice(&core);
            wire.extend_from_slice(&core);
            wire.extend_from_slice(&pair[0].sign(&preimage).to_bytes());
            wire.extend_from_slice(&pair[1].sign(&preimage).to_bytes());
        }
        wire
    }

    /// Re-encodes an already-signed v1 history as GRC1-v2 and appends a recovery transition.
    /// The appended transition uses only the recovery key and new-root key, not the displaced
    /// root's private key.
    fn encode_recovery_root_chain(
        network: [u8; 32],
        roots: &[SigningKey],
        recovery: &SigningKey,
    ) -> Vec<u8> {
        assert!(roots.len() >= 2);
        let historical = encode_root_chain(network, &roots[..roots.len() - 1]);
        append_recovery_to_v1(&historical, roots.last().unwrap(), recovery)
    }

    fn append_recovery_to_v1(
        historical: &[u8],
        new_root: &SigningKey,
        recovery: &SigningKey,
    ) -> Vec<u8> {
        const PREFIX: usize = 40;
        const CORE_V1: usize = 72;
        const SIG: usize = 64;
        const ENTRY_V1: usize = CORE_V1 + SIG * 2;
        const CORE_V2: usize = CORE_V1 + 1;
        const ENTRY_V2: usize = CORE_V2 + SIG * 2;
        assert_eq!(&historical[..4], b"GRC1");
        assert_eq!(u16::from_be_bytes([historical[4], historical[5]]), 1);
        let network: [u8; 32] = historical[6..38].try_into().unwrap();
        let count = u16::from_be_bytes([historical[38], historical[39]]) as usize;
        assert!(count > 0 && count < crate::governance_root_chain::MAX_GOVERNANCE_ROOT_TRANSITIONS);
        assert_eq!(historical.len(), PREFIX + count * ENTRY_V1);
        let new_count = count + 1;
        let mut wire = Vec::with_capacity(PREFIX + new_count * ENTRY_V2);
        wire.extend_from_slice(b"GRC1");
        wire.extend_from_slice(&2u16.to_be_bytes());
        wire.extend_from_slice(&network);
        wire.extend_from_slice(&(new_count as u16).to_be_bytes());
        for index in 0..count {
            let offset = PREFIX + index * ENTRY_V1;
            wire.extend_from_slice(&historical[offset..offset + CORE_V1]);
            wire.push(1);
            wire.extend_from_slice(&historical[offset + CORE_V1..offset + CORE_V1 + SIG]);
            wire.extend_from_slice(&historical[offset + CORE_V1 + SIG..offset + ENTRY_V1]);
        }
        let last_offset = PREFIX + (count - 1) * ENTRY_V1;
        let prior_tip: [u8; 32] = historical[last_offset + 40..last_offset + 72]
            .try_into()
            .unwrap();
        let next_public = new_root.verifying_key().to_bytes();
        let mut core = Vec::with_capacity(CORE_V2);
        core.extend_from_slice(&((count as u64) + 2).to_be_bytes());
        core.extend_from_slice(&prior_tip);
        core.extend_from_slice(&next_public);
        core.push(2);
        let mut preimage = b"AIN1-NOISE-GOVERNANCE-ROOT-ROTATION-V1\0".to_vec();
        preimage.extend_from_slice(&network);
        preimage.extend_from_slice(&core);
        wire.extend_from_slice(&core);
        wire.extend_from_slice(&recovery.sign(&preimage).to_bytes());
        wire.extend_from_slice(&new_root.sign(&preimage).to_bytes());
        wire
    }

    fn entry(id: u32, key: &SigningKey, status: IssuerStatus) -> IssuerEntry {
        IssuerEntry {
            issuer_id: id,
            public_key: key.verifying_key().to_bytes(),
            status,
        }
    }

    #[test]
    fn signed_registry_is_canonical_and_signature_bound() {
        let root = SigningKey::from_bytes(&[0x41; 32]);
        let issuer = SigningKey::from_bytes(&[0x42; 32]);
        let network = [0xb6; 32];
        let wire = encode_signed(
            1,
            network,
            &[entry(17, &issuer, IssuerStatus::Active)],
            &root,
        );
        let verified =
            verify_signed_registry(&wire, &network, &root.verifying_key().to_bytes()).unwrap();
        assert_eq!(verified.sequence(), 1);
        assert_eq!(
            verified.active_key(17),
            Ok(issuer.verifying_key().to_bytes())
        );
        let mut tampered = wire.clone();
        tampered[50] ^= 1;
        assert_eq!(
            verify_signed_registry(&tampered, &network, &root.verifying_key().to_bytes())
                .unwrap_err(),
            IssuerRegistryError::InvalidSignature
        );
    }

    #[test]
    fn durable_registry_high_water_and_terminal_revocation_survive_restart() {
        let path = temp_path("highwater");
        let root = SigningKey::from_bytes(&[0x51; 32]);
        let issuer = SigningKey::from_bytes(&[0x52; 32]);
        let network = [0xb7; 32];
        let root_public = root.verifying_key().to_bytes();
        {
            let store = IssuerRegistryStateStore::open(&path, &network, root_public, 1).unwrap();
            let active = encode_signed(
                1,
                network,
                &[entry(17, &issuer, IssuerStatus::Active)],
                &root,
            );
            assert_eq!(
                store.accept_signed_registry(&active, 17),
                Ok(issuer.verifying_key().to_bytes())
            );
        }
        {
            let store = IssuerRegistryStateStore::open(&path, &network, root_public, 1).unwrap();
            let old = encode_signed(
                1,
                network,
                &[entry(17, &issuer, IssuerStatus::Active)],
                &root,
            );
            assert_eq!(
                store.accept_signed_registry(&old, 17),
                Ok(issuer.verifying_key().to_bytes())
            );
            let revoked = encode_signed(
                2,
                network,
                &[entry(17, &issuer, IssuerStatus::Revoked)],
                &root,
            );
            assert_eq!(
                store.accept_signed_registry(&revoked, 17),
                Err(IssuerRegistryError::IssuerInactive)
            );
            let reactivated = encode_signed(
                3,
                network,
                &[entry(17, &issuer, IssuerStatus::Active)],
                &root,
            );
            assert_eq!(
                store.accept_signed_registry(&reactivated, 17),
                Err(IssuerRegistryError::StatusRollback)
            );
        }
        let _ = fs::remove_file(&path);
        let lock = path.with_file_name(format!(
            "{}.writer.lock",
            path.file_name().unwrap().to_string_lossy()
        ));
        let _ = fs::remove_file(lock);
    }

    #[test]
    fn issuer_key_rotation_requires_new_immutable_id_and_rejects_registry_rollback() {
        let path = temp_path("issuer-rotation");
        let root = SigningKey::from_bytes(&[0x61; 32]);
        let issuer_old = SigningKey::from_bytes(&[0x62; 32]);
        let issuer_new = SigningKey::from_bytes(&[0x63; 32]);
        let network = [0xb8; 32];
        let root_public = root.verifying_key().to_bytes();
        let v1 = encode_signed(
            4,
            network,
            &[entry(17, &issuer_old, IssuerStatus::Active)],
            &root,
        );
        {
            let store = IssuerRegistryStateStore::open(&path, &network, root_public, 1).unwrap();
            assert_eq!(
                store.accept_signed_registry(&v1, 17),
                Ok(issuer_old.verifying_key().to_bytes())
            );
            let substituted = encode_signed(
                5,
                network,
                &[entry(17, &issuer_new, IssuerStatus::Active)],
                &root,
            );
            assert_eq!(
                store.accept_signed_registry(&substituted, 17),
                Err(IssuerRegistryError::IssuerKeyChanged)
            );
            let rotated = encode_signed(
                5,
                network,
                &[
                    entry(17, &issuer_old, IssuerStatus::Revoked),
                    entry(18, &issuer_new, IssuerStatus::Active),
                ],
                &root,
            );
            assert_eq!(
                store.accept_signed_registry(&rotated, 18),
                Ok(issuer_new.verifying_key().to_bytes())
            );
            assert_eq!(
                store.accept_signed_registry(&rotated, 17),
                Err(IssuerRegistryError::IssuerInactive)
            );
        }
        {
            let store = IssuerRegistryStateStore::open(&path, &network, root_public, 1).unwrap();
            assert_eq!(
                store.accept_signed_registry(&v1, 17),
                Err(IssuerRegistryError::SequenceRollback)
            );
            let revive_old = encode_signed(
                6,
                network,
                &[
                    entry(17, &issuer_old, IssuerStatus::Active),
                    entry(18, &issuer_new, IssuerStatus::Active),
                ],
                &root,
            );
            assert_eq!(
                store.accept_signed_registry(&revive_old, 18),
                Err(IssuerRegistryError::StatusRollback)
            );
        }
        let _ = fs::remove_file(&path);
        let lock = path.with_file_name(format!(
            "{}.writer.lock",
            path.file_name().unwrap().to_string_lossy()
        ));
        let _ = fs::remove_file(lock);
    }

    #[test]
    fn multi_step_root_rotation_migrates_state_and_blocks_restored_old_registry() {
        let path = temp_path("root-rotation");
        let root1 = SigningKey::from_bytes(&[0x91; 32]);
        let root2 = SigningKey::from_bytes(&[0x92; 32]);
        let root3 = SigningKey::from_bytes(&[0x94; 32]);
        let recovery = SigningKey::from_bytes(&[0x95; 32]);
        let issuer = SigningKey::from_bytes(&[0x93; 32]);
        let network = [0xc4; 32];
        let root1_public = root1.verifying_key().to_bytes();
        let root2_public = root2.verifying_key().to_bytes();
        let root3_public = root3.verifying_key().to_bytes();

        let v1 = encode_signed(
            1,
            network,
            &[entry(17, &issuer, IssuerStatus::Active)],
            &root1,
        );
        {
            let store = IssuerRegistryStateStore::open(&path, &network, root1_public, 1).unwrap();
            assert_eq!(
                store.accept_signed_registry(&v1, 17),
                Ok(issuer.verifying_key().to_bytes())
            );
        }
        // Capture a state-directory backup from epoch 1 to model an administrator/attacker
        // restoring an old local state file after two legitimate root rotations.
        let state_v1_backup = fs::read(&path).unwrap();

        let chain12_wire = encode_root_chain(network, &[root1.clone(), root2.clone()]);
        let chain12 =
            verify_governance_root_chain(&chain12_wire, &network, &root1_public, &root2_public, 2)
                .unwrap();
        let v2 = encode_signed(
            2,
            network,
            &[entry(17, &issuer, IssuerStatus::Active)],
            &root2,
        );
        {
            let store = IssuerRegistryStateStore::open_with_root_chain(&path, &network, chain12, 2)
                .unwrap();
            assert_eq!(
                store.accept_signed_registry(&v2, 17),
                Ok(issuer.verifying_key().to_bytes())
            );
            assert_eq!(
                store.accept_signed_registry(&v1, 17),
                Err(IssuerRegistryError::InvalidSignature)
            );
        }
        let fingerprint2: [u8; 32] = Sha256::digest(root2_public).into();
        assert_eq!(&fs::read(&path).unwrap()[38..70], &fingerprint2);

        // Root 2 is considered unavailable/compromised. Epoch 3 is therefore authorized by
        // the offline recovery root plus the new root 3, not by root 2's private key.
        let chain123_wire = encode_recovery_root_chain(
            network,
            &[root1.clone(), root2.clone(), root3.clone()],
            &recovery,
        );
        let recovery_public = recovery.verifying_key().to_bytes();
        let chain123 = verify_governance_root_chain_with_recovery(
            &chain123_wire,
            &network,
            &root1_public,
            &recovery_public,
            &root3_public,
            3,
        )
        .unwrap();
        let v3 = encode_signed(
            3,
            network,
            &[entry(17, &issuer, IssuerStatus::Active)],
            &root3,
        );
        {
            let store = IssuerRegistryStateStore::open_with_root_chain(
                &path,
                &network,
                chain123.clone(),
                3,
            )
            .unwrap();
            assert_eq!(
                store.accept_signed_registry(&v3, 17),
                Ok(issuer.verifying_key().to_bytes())
            );
        }
        let fingerprint3: [u8; 32] = Sha256::digest(root3_public).into();
        assert_eq!(&fs::read(&path).unwrap()[38..70], &fingerprint3);

        {
            let store = IssuerRegistryStateStore::open_with_root_chain(
                &path,
                &network,
                chain123.clone(),
                3,
            )
            .unwrap();
            assert_eq!(
                store.accept_signed_registry(&v3, 17),
                Ok(issuer.verifying_key().to_bytes())
            );
        }

        // Restore epoch-1 registry state while the external root chain and floors remain at
        // epoch/sequence 3. State decoding can identify its historical signer, but that cannot
        // make the old root-1-signed registry admissible under the current root-3 trust input.
        fs::write(&path, &state_v1_backup).unwrap();
        {
            let store =
                IssuerRegistryStateStore::open_with_root_chain(&path, &network, chain123, 3)
                    .unwrap();
            assert_eq!(
                store.accept_signed_registry(&v1, 17),
                Err(IssuerRegistryError::InvalidSignature)
            );
        }
        assert_eq!(fs::read(&path).unwrap(), state_v1_backup);
        let stale_chain_wire = encode_root_chain(network, &[root1.clone(), root2.clone()]);
        assert_eq!(
            verify_governance_root_chain(
                &stale_chain_wire,
                &network,
                &root1_public,
                &root3_public,
                3,
            )
            .unwrap_err(),
            crate::governance_root_chain::GovernanceRootChainError::RootEpochRollback
        );
        let _ = fs::remove_file(&path);
        let lock = path.with_file_name(format!(
            "{}.writer.lock",
            path.file_name().unwrap().to_string_lossy()
        ));
        let _ = fs::remove_file(lock);
    }

    #[test]
    fn minimum_registry_sequence_blocks_stale_first_bootstrap_and_upgrade_floor() {
        let path = temp_path("minimum-sequence");
        let root = SigningKey::from_bytes(&[0x71; 32]);
        let issuer = SigningKey::from_bytes(&[0x72; 32]);
        let network = [0xb9; 32];
        let root_public = root.verifying_key().to_bytes();
        {
            let store = IssuerRegistryStateStore::open(&path, &network, root_public, 2).unwrap();
            let stale = encode_signed(
                1,
                network,
                &[entry(17, &issuer, IssuerStatus::Active)],
                &root,
            );
            assert_eq!(
                store.accept_signed_registry(&stale, 17),
                Err(IssuerRegistryError::SequenceBelowMinimum)
            );
            let current = encode_signed(
                2,
                network,
                &[entry(17, &issuer, IssuerStatus::Active)],
                &root,
            );
            assert_eq!(
                store.accept_signed_registry(&current, 17),
                Ok(issuer.verifying_key().to_bytes())
            );
        }
        assert!(matches!(
            IssuerRegistryStateStore::open(&path, &network, root_public, 3),
            Err(IssuerRegistryError::SequenceBelowMinimum)
        ));
        let _ = fs::remove_file(&path);
        let lock = path.with_file_name(format!(
            "{}.writer.lock",
            path.file_name().unwrap().to_string_lossy()
        ));
        let _ = fs::remove_file(lock);
    }
}
