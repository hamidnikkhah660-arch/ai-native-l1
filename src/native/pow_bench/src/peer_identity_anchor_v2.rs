//! Version-separated PIV2 peer-identity anchor store candidate.
//!
//! PIV2 stores the canonical PIS2 scope digest. It is a separate on-disk format from PIV1:
//! PIV2 files use a distinct magic, version, digest domain, and ".piv2" event suffix. Opening
//! either version against event files from the other version fails closed. Both versions use the
//! same stable writer-lock pathname and the same staged no-overwrite publication primitive.
//!
//! This module is a persistence candidate only. It does not verify NPI1/NRT1 signatures, establish
//! signer-pin provenance, authorize recovery, activate a node identity, or defend against rollback
//! of the entire host / both physical disks. It must not be connected to production C:/D: paths or
//! node startup until the separate Windows path, ACL, volume, recovery, and review gates pass.

use crate::{
    peer_identity_anchor_vault::{publish_new_event, PeerAnchorError},
    peer_identity_scope_v2::PeerIdentityScopeV2,
    snapshot_store::{SnapshotStoreError, SnapshotWriterLock},
};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(1);

const MAGIC: &[u8; 4] = b"PIV2";
const VERSION: u16 = 2;
const DOMAIN: &[u8] = b"AI-NATIVE-L1-PEER-IDENTITY-ANCHOR\0v2";
const CORE_LEN: usize = 4 + 2 + 8 + 1 + 32 + 4 + 4 + 1 + 32 * 10;
const WIRE_LEN: usize = CORE_LEN + 32;
const MAX_EVENTS: u64 = 1_000_000;
const LOCK_FILE_NAME: &str = "peer-identity-vault.lockstate";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerIdentityAnchorV2Error {
    InvalidPath,
    Persistence,
    Locked,
    Corrupt,
    ScopeMismatch,
    AlreadyEnrolled,
    EnrollmentRequired,
    GenerationMismatch,
    NonceReplay,
    PreparedMissing,
    RotationPending,
    InvalidEvent,
}

impl From<SnapshotStoreError> for PeerIdentityAnchorV2Error {
    fn from(error: SnapshotStoreError) -> Self {
        match error {
            SnapshotStoreError::WriterLockBusy(_) => Self::Locked,
            SnapshotStoreError::InvalidPath => Self::InvalidPath,
            _ => Self::Persistence,
        }
    }
}

fn map_publish_error(error: PeerAnchorError) -> PeerIdentityAnchorV2Error {
    match error {
        PeerAnchorError::InvalidPath => PeerIdentityAnchorV2Error::InvalidPath,
        PeerAnchorError::Locked => PeerIdentityAnchorV2Error::Locked,
        PeerAnchorError::Corrupt => PeerIdentityAnchorV2Error::Corrupt,
        PeerAnchorError::ScopeMismatch => PeerIdentityAnchorV2Error::ScopeMismatch,
        PeerAnchorError::AlreadyEnrolled => PeerIdentityAnchorV2Error::AlreadyEnrolled,
        PeerAnchorError::EnrollmentRequired => PeerIdentityAnchorV2Error::EnrollmentRequired,
        PeerAnchorError::GenerationMismatch => PeerIdentityAnchorV2Error::GenerationMismatch,
        PeerAnchorError::NonceReplay => PeerIdentityAnchorV2Error::NonceReplay,
        PeerAnchorError::PreparedMissing => PeerIdentityAnchorV2Error::PreparedMissing,
        PeerAnchorError::RotationPending => PeerIdentityAnchorV2Error::RotationPending,
        PeerAnchorError::InvalidEvent => PeerIdentityAnchorV2Error::InvalidEvent,
        PeerAnchorError::Persistence => PeerIdentityAnchorV2Error::Persistence,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PeerIdentityAnchorV2EventKind {
    EnrolledActive = 1,
    RotationPrepared = 2,
    RotationActive = 3,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerIdentityAnchorV2Event {
    pub kind: PeerIdentityAnchorV2EventKind,
    pub generation: u32,
    pub previous_generation: u32,
    pub lifecycle: u8,
    pub noise_fingerprint: [u8; 32],
    pub npi1_digest: [u8; 32],
    pub key_record_digest: [u8; 32],
    pub previous_key_record_digest: [u8; 32],
    pub nrt1_digest: [u8; 32],
    pub intent_digest: [u8; 32],
    pub nonce: [u8; 32],
    pub owner_pin_fingerprint: [u8; 32],
    pub operator_pin_fingerprint: [u8; 32],
}

/// Read-only proof material from a PIV2 ROTATION_ACTIVE tail event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerIdentityAnchorV2ActiveBinding {
    pub sequence: u64,
    pub generation: u32,
    pub previous_generation: u32,
    pub lifecycle: u8,
    pub noise_fingerprint: [u8; 32],
    pub npi1_digest: [u8; 32],
    pub key_record_digest: [u8; 32],
    pub previous_key_record_digest: [u8; 32],
    pub nrt1_digest: [u8; 32],
    pub intent_digest: [u8; 32],
    pub nonce: [u8; 32],
    pub owner_pin_fingerprint: [u8; 32],
    pub operator_pin_fingerprint: [u8; 32],
    pub predecessor_event_digest: [u8; 32],
    pub event_digest: [u8; 32],
}

#[derive(Debug, Clone)]
struct StoredV2Event {
    sequence: u64,
    scope_digest: [u8; 32],
    event: PeerIdentityAnchorV2Event,
    previous_digest: [u8; 32],
    digest: [u8; 32],
}

impl StoredV2Event {
    fn core(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(CORE_LEN);
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&VERSION.to_be_bytes());
        bytes.extend_from_slice(&self.sequence.to_be_bytes());
        bytes.push(self.event.kind as u8);
        bytes.extend_from_slice(&self.scope_digest);
        bytes.extend_from_slice(&self.event.generation.to_be_bytes());
        bytes.extend_from_slice(&self.event.previous_generation.to_be_bytes());
        bytes.push(self.event.lifecycle);
        bytes.extend_from_slice(&self.event.noise_fingerprint);
        bytes.extend_from_slice(&self.event.npi1_digest);
        bytes.extend_from_slice(&self.event.key_record_digest);
        bytes.extend_from_slice(&self.event.previous_key_record_digest);
        bytes.extend_from_slice(&self.event.nrt1_digest);
        bytes.extend_from_slice(&self.event.intent_digest);
        bytes.extend_from_slice(&self.event.nonce);
        bytes.extend_from_slice(&self.event.owner_pin_fingerprint);
        bytes.extend_from_slice(&self.event.operator_pin_fingerprint);
        bytes.extend_from_slice(&self.previous_digest);
        debug_assert_eq!(bytes.len(), CORE_LEN);
        bytes
    }

    fn seal(&mut self) {
        let mut hasher = Sha256::new();
        hasher.update(DOMAIN);
        hasher.update(self.core());
        self.digest = hasher.finalize().into();
    }

    fn encode(&self) -> Vec<u8> {
        let mut bytes = self.core();
        bytes.extend_from_slice(&self.digest);
        bytes
    }

    fn decode(bytes: &[u8]) -> Result<Self, PeerIdentityAnchorV2Error> {
        if bytes.len() != WIRE_LEN || &bytes[..4] != MAGIC {
            return Err(PeerIdentityAnchorV2Error::Corrupt);
        }
        if u16::from_be_bytes([bytes[4], bytes[5]]) != VERSION {
            return Err(PeerIdentityAnchorV2Error::Corrupt);
        }

        let kind = match bytes[14] {
            1 => PeerIdentityAnchorV2EventKind::EnrolledActive,
            2 => PeerIdentityAnchorV2EventKind::RotationPrepared,
            3 => PeerIdentityAnchorV2EventKind::RotationActive,
            _ => return Err(PeerIdentityAnchorV2Error::Corrupt),
        };

        let mut offset = 15;
        let scope_digest = take32(bytes, &mut offset)?;
        let generation = take_u32(bytes, &mut offset)?;
        let previous_generation = take_u32(bytes, &mut offset)?;
        let lifecycle = take_u8(bytes, &mut offset)?;
        let noise_fingerprint = take32(bytes, &mut offset)?;
        let npi1_digest = take32(bytes, &mut offset)?;
        let key_record_digest = take32(bytes, &mut offset)?;
        let previous_key_record_digest = take32(bytes, &mut offset)?;
        let nrt1_digest = take32(bytes, &mut offset)?;
        let intent_digest = take32(bytes, &mut offset)?;
        let nonce = take32(bytes, &mut offset)?;
        let owner_pin_fingerprint = take32(bytes, &mut offset)?;
        let operator_pin_fingerprint = take32(bytes, &mut offset)?;
        let previous_digest = take32(bytes, &mut offset)?;
        if offset != CORE_LEN {
            return Err(PeerIdentityAnchorV2Error::Corrupt);
        }

        let supplied_digest: [u8; 32] = bytes[CORE_LEN..]
            .try_into()
            .map_err(|_| PeerIdentityAnchorV2Error::Corrupt)?;
        let mut stored = Self {
            sequence: u64::from_be_bytes(
                bytes[6..14]
                    .try_into()
                    .map_err(|_| PeerIdentityAnchorV2Error::Corrupt)?,
            ),
            scope_digest,
            event: PeerIdentityAnchorV2Event {
                kind,
                generation,
                previous_generation,
                lifecycle,
                noise_fingerprint,
                npi1_digest,
                key_record_digest,
                previous_key_record_digest,
                nrt1_digest,
                intent_digest,
                nonce,
                owner_pin_fingerprint,
                operator_pin_fingerprint,
            },
            previous_digest,
            digest: supplied_digest,
        };
        stored.seal();
        if stored.digest != supplied_digest {
            return Err(PeerIdentityAnchorV2Error::Corrupt);
        }
        Ok(stored)
    }
}

fn take_u8(bytes: &[u8], offset: &mut usize) -> Result<u8, PeerIdentityAnchorV2Error> {
    let value = *bytes
        .get(*offset)
        .ok_or(PeerIdentityAnchorV2Error::Corrupt)?;
    *offset += 1;
    Ok(value)
}

fn take32(bytes: &[u8], offset: &mut usize) -> Result<[u8; 32], PeerIdentityAnchorV2Error> {
    let end = offset
        .checked_add(32)
        .ok_or(PeerIdentityAnchorV2Error::Corrupt)?;
    let slice = bytes
        .get(*offset..end)
        .ok_or(PeerIdentityAnchorV2Error::Corrupt)?;
    let value = slice
        .try_into()
        .map_err(|_| PeerIdentityAnchorV2Error::Corrupt)?;
    *offset = end;
    Ok(value)
}

fn take_u32(bytes: &[u8], offset: &mut usize) -> Result<u32, PeerIdentityAnchorV2Error> {
    let end = offset
        .checked_add(4)
        .ok_or(PeerIdentityAnchorV2Error::Corrupt)?;
    let slice = bytes
        .get(*offset..end)
        .ok_or(PeerIdentityAnchorV2Error::Corrupt)?;
    let value = u32::from_be_bytes(
        slice
            .try_into()
            .map_err(|_| PeerIdentityAnchorV2Error::Corrupt)?,
    );
    *offset = end;
    Ok(value)
}

/// Holds the same stable OS writer lock pathname as PIV1 but reads/writes only PIV2 records.
/// A root containing PIV1 records is rejected, and PIV1's filename/version checks reject PIV2.
pub struct PeerIdentityAnchorVaultV2 {
    root: PathBuf,
    scope_digest: [u8; 32],
    _lock: SnapshotWriterLock,
    events: Vec<StoredV2Event>,
}

impl PeerIdentityAnchorVaultV2 {
    /// Open an existing directory. This never creates a baseline or enrolls an identity.
    pub fn open(
        root: impl AsRef<Path>,
        scope: &PeerIdentityScopeV2,
    ) -> Result<Self, PeerIdentityAnchorV2Error> {
        let root = root.as_ref().to_path_buf();
        if !root.is_absolute() {
            return Err(PeerIdentityAnchorV2Error::InvalidPath);
        }
        let metadata =
            fs::symlink_metadata(&root).map_err(|_| PeerIdentityAnchorV2Error::InvalidPath)?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(PeerIdentityAnchorV2Error::InvalidPath);
        }

        let lock_path = root.join(LOCK_FILE_NAME);
        let lock = SnapshotWriterLock::acquire(&lock_path)?;
        let mut paths = Vec::new();

        for entry in fs::read_dir(&root).map_err(|_| PeerIdentityAnchorV2Error::Persistence)? {
            let entry = entry.map_err(|_| PeerIdentityAnchorV2Error::Persistence)?;
            let name = entry.file_name();
            let name_text = name.to_string_lossy();

            if name_text.starts_with(".peer-identity-event-") {
                // A staged event indicates interruption. Do not promote or delete it on open.
                return Err(PeerIdentityAnchorV2Error::Corrupt);
            }
            if name_text.starts_with("event-") {
                let entry_metadata = fs::symlink_metadata(entry.path())
                    .map_err(|_| PeerIdentityAnchorV2Error::Persistence)?;
                if !entry_metadata.is_file() || entry_metadata.file_type().is_symlink() {
                    return Err(PeerIdentityAnchorV2Error::Corrupt);
                }
                paths.push((name, entry.path()));
            }
        }

        paths.sort_by(|left, right| left.0.cmp(&right.0));
        if paths.len() as u64 > MAX_EVENTS {
            return Err(PeerIdentityAnchorV2Error::Corrupt);
        }

        let expected_scope = scope.digest();
        let mut events = Vec::with_capacity(paths.len());
        let mut previous_digest = [0u8; 32];
        for (index, (name, path)) in paths.into_iter().enumerate() {
            let sequence = index as u64 + 1;
            let expected_name = format!("event-{sequence:020}.piv2");
            if name.to_string_lossy() != expected_name {
                // Includes PIV1 ".piv1" files: never reinterpret a different version.
                return Err(PeerIdentityAnchorV2Error::Corrupt);
            }

            let mut file = File::open(path).map_err(|_| PeerIdentityAnchorV2Error::Persistence)?;
            if file
                .metadata()
                .map_err(|_| PeerIdentityAnchorV2Error::Persistence)?
                .len()
                != WIRE_LEN as u64
            {
                return Err(PeerIdentityAnchorV2Error::Corrupt);
            }
            let mut bytes = Vec::with_capacity(WIRE_LEN);
            file.read_to_end(&mut bytes)
                .map_err(|_| PeerIdentityAnchorV2Error::Persistence)?;
            let event = StoredV2Event::decode(&bytes)?;
            if event.sequence != sequence
                || event.scope_digest != expected_scope
                || event.previous_digest != previous_digest
            {
                return Err(PeerIdentityAnchorV2Error::ScopeMismatch);
            }
            validate_transition(events.last(), &event)?;
            previous_digest = event.digest;
            events.push(event);
        }

        Ok(Self {
            root,
            scope_digest: expected_scope,
            _lock: lock,
            events,
        })
    }

    pub fn event_count(&self) -> usize {
        self.events.len()
    }

    pub fn matches_scope(&self, scope: &PeerIdentityScopeV2) -> bool {
        self.scope_digest == scope.digest()
    }

    pub fn active_generation(&self) -> Option<u32> {
        self.events
            .iter()
            .rev()
            .find(|stored| {
                matches!(
                    stored.event.kind,
                    PeerIdentityAnchorV2EventKind::EnrolledActive
                        | PeerIdentityAnchorV2EventKind::RotationActive
                )
            })
            .map(|stored| stored.event.generation)
    }

    pub fn pending_generation(&self) -> Option<u32> {
        self.events
            .last()
            .filter(|stored| stored.event.kind == PeerIdentityAnchorV2EventKind::RotationPrepared)
            .map(|stored| stored.event.generation)
    }

    pub fn contains_nonce(&self, nonce: &[u8; 32]) -> bool {
        self.events.iter().any(|stored| {
            stored.event.kind == PeerIdentityAnchorV2EventKind::RotationPrepared
                && &stored.event.nonce == nonce
        })
    }

    /// Return only a ROTATION_ACTIVE event that is the chain tail.
    pub fn latest_rotation_active_binding(&self) -> Option<PeerIdentityAnchorV2ActiveBinding> {
        self.events
            .last()
            .filter(|stored| stored.event.kind == PeerIdentityAnchorV2EventKind::RotationActive)
            .map(|stored| PeerIdentityAnchorV2ActiveBinding {
                sequence: stored.sequence,
                generation: stored.event.generation,
                previous_generation: stored.event.previous_generation,
                lifecycle: stored.event.lifecycle,
                noise_fingerprint: stored.event.noise_fingerprint,
                npi1_digest: stored.event.npi1_digest,
                key_record_digest: stored.event.key_record_digest,
                previous_key_record_digest: stored.event.previous_key_record_digest,
                nrt1_digest: stored.event.nrt1_digest,
                intent_digest: stored.event.intent_digest,
                nonce: stored.event.nonce,
                owner_pin_fingerprint: stored.event.owner_pin_fingerprint,
                operator_pin_fingerprint: stored.event.operator_pin_fingerprint,
                predecessor_event_digest: stored.previous_digest,
                event_digest: stored.digest,
            })
    }

    /// Explicit enrollment ceremony only. Opening an empty store does not enroll an identity.
    pub fn enroll_genesis(
        &mut self,
        event: PeerIdentityAnchorV2Event,
    ) -> Result<(), PeerIdentityAnchorV2Error> {
        if !self.events.is_empty() {
            return Err(PeerIdentityAnchorV2Error::AlreadyEnrolled);
        }
        if event.kind != PeerIdentityAnchorV2EventKind::EnrolledActive
            || event.generation == 0
            || event.previous_generation != 0
            || event.lifecycle != 1
            || !all_nonzero(&[
                &event.noise_fingerprint,
                &event.npi1_digest,
                &event.key_record_digest,
            ])
            || event.nrt1_digest != [0; 32]
            || event.intent_digest != [0; 32]
            || event.nonce != [0; 32]
            || !all_nonzero(&[
                &event.owner_pin_fingerprint,
                &event.operator_pin_fingerprint,
            ])
            || event.owner_pin_fingerprint == event.operator_pin_fingerprint
        {
            return Err(PeerIdentityAnchorV2Error::InvalidEvent);
        }
        self.append(event)
    }

    /// Persist a verified successor as PREPARED. This is not an activation operation.
    pub fn prepare_rotation(
        &mut self,
        event: PeerIdentityAnchorV2Event,
    ) -> Result<(), PeerIdentityAnchorV2Error> {
        if event.kind != PeerIdentityAnchorV2EventKind::RotationPrepared
            || event.lifecycle != 1
            || !all_nonzero(&[
                &event.noise_fingerprint,
                &event.npi1_digest,
                &event.key_record_digest,
                &event.nrt1_digest,
                &event.intent_digest,
                &event.nonce,
                &event.owner_pin_fingerprint,
                &event.operator_pin_fingerprint,
            ])
            || event.owner_pin_fingerprint == event.operator_pin_fingerprint
        {
            return Err(PeerIdentityAnchorV2Error::InvalidEvent);
        }

        if let Some(last) = self.events.last() {
            if last.event.kind == PeerIdentityAnchorV2EventKind::RotationPrepared {
                if last.event == event {
                    return Ok(());
                }
                if last.event.nonce == event.nonce || self.contains_nonce(&event.nonce) {
                    return Err(PeerIdentityAnchorV2Error::NonceReplay);
                }
                return Err(PeerIdentityAnchorV2Error::RotationPending);
            }
        }
        if self.contains_nonce(&event.nonce) {
            return Err(PeerIdentityAnchorV2Error::NonceReplay);
        }

        let active = self
            .active_generation()
            .ok_or(PeerIdentityAnchorV2Error::EnrollmentRequired)?;
        if event.previous_generation != active
            || event.generation
                != active
                    .checked_add(1)
                    .ok_or(PeerIdentityAnchorV2Error::GenerationMismatch)?
        {
            return Err(PeerIdentityAnchorV2Error::GenerationMismatch);
        }
        self.append(event)
    }

    /// Append ROTATION_ACTIVE only for the exact most recent PREPARED nonce.
    pub fn activate_prepared(&mut self, nonce: [u8; 32]) -> Result<(), PeerIdentityAnchorV2Error> {
        let last = self
            .events
            .last()
            .ok_or(PeerIdentityAnchorV2Error::PreparedMissing)?
            .clone();

        if last.event.kind == PeerIdentityAnchorV2EventKind::RotationActive
            && last.event.nonce == nonce
        {
            return Ok(());
        }
        if last.event.kind != PeerIdentityAnchorV2EventKind::RotationPrepared
            || last.event.nonce != nonce
        {
            return Err(PeerIdentityAnchorV2Error::PreparedMissing);
        }

        let mut event = last.event;
        event.kind = PeerIdentityAnchorV2EventKind::RotationActive;
        self.append(event)
    }

    fn append(
        &mut self,
        event: PeerIdentityAnchorV2Event,
    ) -> Result<(), PeerIdentityAnchorV2Error> {
        let sequence = self.events.len() as u64 + 1;
        if sequence > MAX_EVENTS {
            return Err(PeerIdentityAnchorV2Error::Corrupt);
        }

        let previous_digest = self
            .events
            .last()
            .map(|stored| stored.digest)
            .unwrap_or([0; 32]);
        let mut stored = StoredV2Event {
            sequence,
            scope_digest: self.scope_digest,
            event,
            previous_digest,
            digest: [0; 32],
        };
        stored.seal();
        validate_transition(self.events.last(), &stored)?;

        let final_path = self.root.join(format!("event-{sequence:020}.piv2"));
        let temp_id = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
        let temp_path = self.root.join(format!(
            ".peer-identity-event-v2-{sequence:020}-{}-{temp_id}.tmp",
            std::process::id()
        ));
        let encoded = stored.encode();

        let result = (|| -> Result<(), PeerIdentityAnchorV2Error> {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temp_path)
                .map_err(|_| PeerIdentityAnchorV2Error::Persistence)?;
            file.write_all(&encoded)
                .map_err(|_| PeerIdentityAnchorV2Error::Persistence)?;
            file.flush()
                .map_err(|_| PeerIdentityAnchorV2Error::Persistence)?;
            file.sync_all()
                .map_err(|_| PeerIdentityAnchorV2Error::Persistence)?;
            drop(file);

            let mut staged = Vec::with_capacity(WIRE_LEN);
            File::open(&temp_path)
                .and_then(|mut file| file.read_to_end(&mut staged))
                .map_err(|_| PeerIdentityAnchorV2Error::Persistence)?;
            let decoded = StoredV2Event::decode(&staged)?;
            if staged != encoded
                || decoded.sequence != sequence
                || decoded.scope_digest != self.scope_digest
                || decoded.previous_digest != previous_digest
            {
                return Err(PeerIdentityAnchorV2Error::Corrupt);
            }

            publish_new_event(&temp_path, &final_path).map_err(map_publish_error)?;
            Ok(())
        })();

        // On any failure a staged temp is kept as forensic evidence; open() quarantines it.
        result?;
        self.events.push(stored);
        Ok(())
    }
}

fn all_nonzero(values: &[&[u8; 32]]) -> bool {
    values.iter().all(|value| **value != [0; 32])
}

fn validate_transition(
    previous: Option<&StoredV2Event>,
    current: &StoredV2Event,
) -> Result<(), PeerIdentityAnchorV2Error> {
    let event = &current.event;
    match (previous, event.kind) {
        (None, PeerIdentityAnchorV2EventKind::EnrolledActive)
            if event.generation > 0
                && event.previous_generation == 0
                && event.lifecycle == 1
                && all_nonzero(&[
                    &event.noise_fingerprint,
                    &event.npi1_digest,
                    &event.key_record_digest,
                    &event.owner_pin_fingerprint,
                    &event.operator_pin_fingerprint,
                ])
                && event.owner_pin_fingerprint != event.operator_pin_fingerprint
                && event.nrt1_digest == [0; 32]
                && event.intent_digest == [0; 32]
                && event.nonce == [0; 32]
                && event.previous_key_record_digest == [0; 32] =>
        {
            Ok(())
        }
        (Some(previous), PeerIdentityAnchorV2EventKind::RotationPrepared)
            if (previous.event.kind == PeerIdentityAnchorV2EventKind::EnrolledActive
                || previous.event.kind == PeerIdentityAnchorV2EventKind::RotationActive)
                && previous.event.generation.checked_add(1) == Some(event.generation)
                && event.previous_generation == previous.event.generation
                && event.previous_key_record_digest == previous.event.key_record_digest
                && event.lifecycle == 1
                && all_nonzero(&[
                    &event.noise_fingerprint,
                    &event.npi1_digest,
                    &event.key_record_digest,
                    &event.nrt1_digest,
                    &event.intent_digest,
                    &event.nonce,
                    &event.owner_pin_fingerprint,
                    &event.operator_pin_fingerprint,
                ])
                && event.owner_pin_fingerprint == previous.event.owner_pin_fingerprint
                && event.operator_pin_fingerprint == previous.event.operator_pin_fingerprint =>
        {
            Ok(())
        }
        (Some(previous), PeerIdentityAnchorV2EventKind::RotationActive)
            if previous.event.kind == PeerIdentityAnchorV2EventKind::RotationPrepared =>
        {
            let mut expected = previous.event.clone();
            expected.kind = PeerIdentityAnchorV2EventKind::RotationActive;
            if event == &expected {
                Ok(())
            } else {
                Err(PeerIdentityAnchorV2Error::InvalidEvent)
            }
        }
        _ => Err(PeerIdentityAnchorV2Error::InvalidEvent),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        devnet_profile_candidate::DevnetProfileCandidate,
        peer_identity_anchor_vault::{
            PeerAnchorEvent, PeerAnchorEventKind, PeerIdentityAnchorScope, PeerIdentityAnchorVault,
        },
        peer_identity_scope_v2::{PeerIdentityRoleV2, PeerIdentityScopeV2},
    };
    use std::sync::atomic::AtomicU64;

    static NEXT_TEST_ID: AtomicU64 = AtomicU64::new(1);

    struct TestDir(PathBuf);

    impl TestDir {
        fn new(label: &str) -> Self {
            let id = NEXT_TEST_ID.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "peer-anchor-v2-{label}-{}-{id}",
                std::process::id()
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn scope_v2() -> PeerIdentityScopeV2 {
        let profile = DevnetProfileCandidate::new([0x52; 32]).unwrap();
        PeerIdentityScopeV2::from_expected_qvdn_profile(
            &profile,
            &profile.encode_manifest(),
            PeerIdentityRoleV2::Seed,
            7,
            [0x77; 32],
            1,
            42,
            9,
        )
        .unwrap()
    }

    fn enrollment() -> PeerIdentityAnchorV2Event {
        PeerIdentityAnchorV2Event {
            kind: PeerIdentityAnchorV2EventKind::EnrolledActive,
            generation: 1,
            previous_generation: 0,
            lifecycle: 1,
            noise_fingerprint: [4; 32],
            npi1_digest: [5; 32],
            key_record_digest: [6; 32],
            previous_key_record_digest: [0; 32],
            nrt1_digest: [0; 32],
            intent_digest: [0; 32],
            nonce: [0; 32],
            owner_pin_fingerprint: [12; 32],
            operator_pin_fingerprint: [13; 32],
        }
    }

    fn prepared(nonce: u8) -> PeerIdentityAnchorV2Event {
        PeerIdentityAnchorV2Event {
            kind: PeerIdentityAnchorV2EventKind::RotationPrepared,
            generation: 2,
            previous_generation: 1,
            lifecycle: 1,
            noise_fingerprint: [7; 32],
            npi1_digest: [8; 32],
            key_record_digest: [9; 32],
            previous_key_record_digest: [6; 32],
            nrt1_digest: [10; 32],
            intent_digest: [11; 32],
            nonce: [nonce; 32],
            owner_pin_fingerprint: [12; 32],
            operator_pin_fingerprint: [13; 32],
        }
    }

    fn legacy_scope() -> PeerIdentityAnchorScope {
        PeerIdentityAnchorScope {
            network_id: [1; 32],
            profile_id: [2; 32],
            genesis_root: [3; 32],
            role: 1,
            issuer_id: 7,
            issuer_public_key_fingerprint: [14; 32],
            key_purpose: 3,
            credential_id: 9,
            key_id: 11,
        }
    }

    fn legacy_enrollment() -> PeerAnchorEvent {
        PeerAnchorEvent {
            kind: PeerAnchorEventKind::EnrolledActive,
            generation: 1,
            previous_generation: 0,
            lifecycle: 1,
            noise_fingerprint: [4; 32],
            npi1_digest: [5; 32],
            key_record_digest: [6; 32],
            previous_key_record_digest: [0; 32],
            nrt1_digest: [0; 32],
            intent_digest: [0; 32],
            nonce: [0; 32],
            owner_pin_fingerprint: [12; 32],
            operator_pin_fingerprint: [13; 32],
        }
    }

    #[test]
    fn piv2_enrollment_reopen_and_scope_binding_are_durable() {
        let dir = TestDir::new("enrollment");
        let scope = scope_v2();
        {
            let mut store = PeerIdentityAnchorVaultV2::open(&dir.0, &scope).unwrap();
            assert_eq!(store.event_count(), 0);
            assert_eq!(store.active_generation(), None);
            store.enroll_genesis(enrollment()).unwrap();
            assert_eq!(store.active_generation(), Some(1));
            assert!(store.matches_scope(&scope));
        }
        let store = PeerIdentityAnchorVaultV2::open(&dir.0, &scope).unwrap();
        assert_eq!(store.event_count(), 1);
        assert_eq!(store.active_generation(), Some(1));
    }

    #[test]
    fn piv2_prepared_nonce_is_persistent_and_activation_is_exact() {
        let dir = TestDir::new("rotation");
        let scope = scope_v2();
        {
            let mut store = PeerIdentityAnchorVaultV2::open(&dir.0, &scope).unwrap();
            store.enroll_genesis(enrollment()).unwrap();
            let first = prepared(21);
            store.prepare_rotation(first.clone()).unwrap();
            store.prepare_rotation(first).unwrap();
            assert_eq!(
                store.prepare_rotation(prepared(24)),
                Err(PeerIdentityAnchorV2Error::RotationPending)
            );
            assert!(store.contains_nonce(&[21; 32]));
            let mut changed = prepared(21);
            changed.npi1_digest = [99; 32];
            assert_eq!(
                store.prepare_rotation(changed),
                Err(PeerIdentityAnchorV2Error::NonceReplay)
            );
            assert_eq!(
                store.activate_prepared([22; 32]),
                Err(PeerIdentityAnchorV2Error::PreparedMissing)
            );
            store.activate_prepared([21; 32]).unwrap();
            assert_eq!(store.active_generation(), Some(2));
        }
        let store = PeerIdentityAnchorVaultV2::open(&dir.0, &scope).unwrap();
        assert_eq!(store.active_generation(), Some(2));
        assert!(store.contains_nonce(&[21; 32]));
        assert_eq!(
            store.latest_rotation_active_binding().unwrap().generation,
            2
        );
    }

    #[test]
    fn piv2_never_self_enrolls_and_requires_successor_generation() {
        let dir = TestDir::new("empty");
        let scope = scope_v2();
        let mut store = PeerIdentityAnchorVaultV2::open(&dir.0, &scope).unwrap();
        assert_eq!(
            store.prepare_rotation(prepared(30)),
            Err(PeerIdentityAnchorV2Error::EnrollmentRequired)
        );
        assert_eq!(store.event_count(), 0);
        assert_eq!(
            store.enroll_genesis({
                let mut event = enrollment();
                event.generation = 0;
                event
            }),
            Err(PeerIdentityAnchorV2Error::InvalidEvent)
        );
    }

    #[test]
    fn piv2_and_piv1_event_formats_are_mutually_rejected() {
        let piv2_dir = TestDir::new("piv2-rejects-piv1");
        {
            let mut store = PeerIdentityAnchorVaultV2::open(&piv2_dir.0, &scope_v2()).unwrap();
            store.enroll_genesis(enrollment()).unwrap();
        }
        assert!(PeerIdentityAnchorVault::open(&piv2_dir.0, legacy_scope()).is_err());

        let piv1_dir = TestDir::new("piv1-rejects-piv2");
        {
            let mut store = PeerIdentityAnchorVault::open(&piv1_dir.0, legacy_scope()).unwrap();
            store.enroll_genesis(legacy_enrollment()).unwrap();
        }
        assert!(PeerIdentityAnchorVaultV2::open(&piv1_dir.0, &scope_v2()).is_err());
    }

    #[test]
    fn piv2_tamper_wrong_scope_and_truncated_record_fail_closed() {
        let dir = TestDir::new("tamper");
        let scope = scope_v2();
        {
            let mut store = PeerIdentityAnchorVaultV2::open(&dir.0, &scope).unwrap();
            store.enroll_genesis(enrollment()).unwrap();
        }

        let event_path = dir.0.join("event-00000000000000000001.piv2");
        let original = fs::read(&event_path).unwrap();
        let mut tampered = original.clone();
        tampered[40] ^= 1;
        fs::write(&event_path, &tampered).unwrap();
        assert!(matches!(
            PeerIdentityAnchorVaultV2::open(&dir.0, &scope),
            Err(PeerIdentityAnchorV2Error::Corrupt)
        ));
        fs::write(&event_path, &original).unwrap();

        let other_profile = DevnetProfileCandidate::new([0x53; 32]).unwrap();
        let other_scope = PeerIdentityScopeV2::from_expected_qvdn_profile(
            &other_profile,
            &other_profile.encode_manifest(),
            PeerIdentityRoleV2::Seed,
            7,
            [0x77; 32],
            1,
            42,
            9,
        )
        .unwrap();
        assert!(matches!(
            PeerIdentityAnchorVaultV2::open(&dir.0, &other_scope),
            Err(PeerIdentityAnchorV2Error::ScopeMismatch)
        ));

        fs::write(&event_path, &original[..original.len() - 1]).unwrap();
        assert!(PeerIdentityAnchorVaultV2::open(&dir.0, &scope).is_err());
    }

    #[test]
    fn piv2_unsupported_version_and_magic_fail_closed() {
        let dir = TestDir::new("version");
        let scope = scope_v2();
        {
            let mut store = PeerIdentityAnchorVaultV2::open(&dir.0, &scope).unwrap();
            store.enroll_genesis(enrollment()).unwrap();
        }
        let path = dir.0.join("event-00000000000000000001.piv2");
        let original = fs::read(&path).unwrap();
        for (offset, value) in [(0usize, b'X'), (5usize, 3u8)] {
            let mut invalid = original.clone();
            invalid[offset] = value;
            fs::write(&path, invalid).unwrap();
            assert!(PeerIdentityAnchorVaultV2::open(&dir.0, &scope).is_err());
        }
        fs::write(path, original).unwrap();
    }

    #[test]
    fn piv2_interrupted_stage_is_quarantined_without_repair() {
        let dir = TestDir::new("stage");
        let staged = dir
            .0
            .join(".peer-identity-event-v2-00000000000000000001-44-1.tmp");
        fs::write(&staged, b"partial-piv2-record").unwrap();
        assert!(matches!(
            PeerIdentityAnchorVaultV2::open(&dir.0, &scope_v2()),
            Err(PeerIdentityAnchorV2Error::Corrupt)
        ));
        assert_eq!(fs::read(staged).unwrap(), b"partial-piv2-record");
    }

    #[test]
    fn piv2_final_publication_never_overwrites_an_existing_sequence() {
        let dir = TestDir::new("no-overwrite");
        let source = dir.0.join(".peer-identity-event-stage.tmp");
        let destination = dir.0.join("event-00000000000000000001.piv2");
        fs::write(&source, b"staged-piv2").unwrap();
        fs::write(&destination, b"existing-piv2").unwrap();
        assert_eq!(
            publish_new_event(&source, &destination),
            Err(PeerAnchorError::Persistence)
        );
        assert_eq!(fs::read(source).unwrap(), b"staged-piv2");
        assert_eq!(fs::read(destination).unwrap(), b"existing-piv2");
    }

    #[test]
    fn piv2_writer_lock_is_exclusive_and_released_on_drop() {
        let dir = TestDir::new("writer-lock");
        let scope = scope_v2();
        let first = PeerIdentityAnchorVaultV2::open(&dir.0, &scope).unwrap();
        assert!(matches!(
            PeerIdentityAnchorVaultV2::open(&dir.0, &scope),
            Err(PeerIdentityAnchorV2Error::Locked)
        ));
        drop(first);
        let reopened = PeerIdentityAnchorVaultV2::open(&dir.0, &scope).unwrap();
        drop(reopened);
    }
}
