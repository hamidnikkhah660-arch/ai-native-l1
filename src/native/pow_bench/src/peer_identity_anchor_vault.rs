//! Append-only local peer-identity anchor chain, separate from QFP6 manifest anchors.
//!
//! This module is a persistence primitive only. It does not verify NPI1/NRT1 signatures,
//! establish signer-pin provenance, activate a node identity, or claim protection from
//! full-machine rollback. Callers must perform those checks before appending events.
use crate::snapshot_store::{SnapshotStoreError, SnapshotWriterLock};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(1);

const MAGIC: &[u8; 4] = b"PIV1";
const VERSION: u16 = 1;
const DOMAIN: &[u8] = b"AI-NATIVE-L1-PEER-IDENTITY-ANCHOR\0v1";
const CORE_LEN: usize = 4 + 2 + 8 + 1 + 32 + 4 + 4 + 1 + 32 * 10;
const WIRE_LEN: usize = CORE_LEN + 32;
const MAX_EVENTS: u64 = 1_000_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerAnchorError {
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

impl From<SnapshotStoreError> for PeerAnchorError {
    fn from(error: SnapshotStoreError) -> Self {
        match error {
            SnapshotStoreError::WriterLockBusy(_) => Self::Locked,
            SnapshotStoreError::InvalidPath => Self::InvalidPath,
            _ => Self::Persistence,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerIdentityAnchorScope {
    pub network_id: [u8; 32],
    pub profile_id: [u8; 32],
    pub genesis_root: [u8; 32],
    pub role: u8,
    pub issuer_id: u32,
    pub issuer_public_key_fingerprint: [u8; 32],
    pub key_purpose: u8,
    pub credential_id: u128,
    pub key_id: u32,
}

impl PeerIdentityAnchorScope {
    fn digest(&self) -> [u8; 32] {
        let mut b = Vec::with_capacity(32 * 4 + 1 + 4 + 1 + 16 + 4);
        b.extend_from_slice(&self.network_id);
        b.extend_from_slice(&self.profile_id);
        b.extend_from_slice(&self.genesis_root);
        b.push(self.role);
        b.extend_from_slice(&self.issuer_id.to_be_bytes());
        b.extend_from_slice(&self.issuer_public_key_fingerprint);
        b.push(self.key_purpose);
        b.extend_from_slice(&self.credential_id.to_be_bytes());
        b.extend_from_slice(&self.key_id.to_be_bytes());
        Sha256::digest(b).into()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PeerAnchorEventKind {
    EnrolledActive = 1,
    RotationPrepared = 2,
    RotationActive = 3,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerAnchorEvent {
    pub kind: PeerAnchorEventKind,
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

/// Immutable metadata for the latest C-side ROTATION_ACTIVE event.
/// This is evidence for a separate verifier, not proof that NPI1/NRT1 or signer pins are valid.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerAnchorRotationActiveBinding {
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
struct StoredEvent {
    sequence: u64,
    scope_digest: [u8; 32],
    event: PeerAnchorEvent,
    previous_digest: [u8; 32],
    digest: [u8; 32],
}

impl StoredEvent {
    fn core(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(CORE_LEN);
        b.extend_from_slice(MAGIC);
        b.extend_from_slice(&VERSION.to_be_bytes());
        b.extend_from_slice(&self.sequence.to_be_bytes());
        b.push(self.event.kind as u8);
        b.extend_from_slice(&self.scope_digest);
        b.extend_from_slice(&self.event.generation.to_be_bytes());
        b.extend_from_slice(&self.event.previous_generation.to_be_bytes());
        b.push(self.event.lifecycle);
        b.extend_from_slice(&self.event.noise_fingerprint);
        b.extend_from_slice(&self.event.npi1_digest);
        b.extend_from_slice(&self.event.key_record_digest);
        b.extend_from_slice(&self.event.previous_key_record_digest);
        b.extend_from_slice(&self.event.nrt1_digest);
        b.extend_from_slice(&self.event.intent_digest);
        b.extend_from_slice(&self.event.nonce);
        b.extend_from_slice(&self.event.owner_pin_fingerprint);
        b.extend_from_slice(&self.event.operator_pin_fingerprint);
        b.extend_from_slice(&self.previous_digest);
        debug_assert_eq!(b.len(), CORE_LEN);
        b
    }
    fn seal(&mut self) {
        let mut h = Sha256::new();
        h.update(DOMAIN);
        h.update(self.core());
        self.digest = h.finalize().into();
    }
    fn encode(&self) -> Vec<u8> {
        let mut b = self.core();
        b.extend_from_slice(&self.digest);
        b
    }
    fn decode(b: &[u8]) -> Result<Self, PeerAnchorError> {
        if b.len() != WIRE_LEN
            || &b[..4] != MAGIC
            || u16::from_be_bytes(b[4..6].try_into().unwrap()) != VERSION
        {
            return Err(PeerAnchorError::Corrupt);
        }
        let kind = match b[14] {
            1 => PeerAnchorEventKind::EnrolledActive,
            2 => PeerAnchorEventKind::RotationPrepared,
            3 => PeerAnchorEventKind::RotationActive,
            _ => return Err(PeerAnchorError::Corrupt),
        };
        let mut o = 15;
        let scope_digest = take32(b, &mut o);
        let generation = take_u32(b, &mut o);
        let previous_generation = take_u32(b, &mut o);
        let lifecycle = b[o];
        o += 1;
        let noise_fingerprint = take32(b, &mut o);
        let npi1_digest = take32(b, &mut o);
        let key_record_digest = take32(b, &mut o);
        let previous_key_record_digest = take32(b, &mut o);
        let nrt1_digest = take32(b, &mut o);
        let intent_digest = take32(b, &mut o);
        let nonce = take32(b, &mut o);
        let owner_pin_fingerprint = take32(b, &mut o);
        let operator_pin_fingerprint = take32(b, &mut o);
        let previous_digest = take32(b, &mut o);
        let digest: [u8; 32] = b[CORE_LEN..].try_into().unwrap();
        let mut v = Self {
            sequence: u64::from_be_bytes(b[6..14].try_into().unwrap()),
            scope_digest,
            event: PeerAnchorEvent {
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
            digest,
        };
        let supplied = v.digest;
        v.seal();
        if v.digest != supplied {
            return Err(PeerAnchorError::Corrupt);
        }
        Ok(v)
    }
}
fn take32(b: &[u8], o: &mut usize) -> [u8; 32] {
    let x = b[*o..*o + 32].try_into().unwrap();
    *o += 32;
    x
}
fn take_u32(b: &[u8], o: &mut usize) -> u32 {
    let x = u32::from_be_bytes(b[*o..*o + 4].try_into().unwrap());
    *o += 4;
    x
}

/// Holds the stable OS writer lock for the vault lifetime and validates the full chain on open.
pub struct PeerIdentityAnchorVault {
    root: PathBuf,
    scope_digest: [u8; 32],
    _lock: SnapshotWriterLock,
    events: Vec<StoredEvent>,
}

impl PeerIdentityAnchorVault {
    /// Open an already provisioned directory. This function never creates a vault or baseline.
    pub fn open(
        root: impl AsRef<Path>,
        scope: PeerIdentityAnchorScope,
    ) -> Result<Self, PeerAnchorError> {
        if scope.network_id == [0; 32]
            || scope.profile_id == [0; 32]
            || scope.genesis_root == [0; 32]
            || scope.role == 0
            || scope.issuer_id == 0
            || scope.issuer_public_key_fingerprint == [0; 32]
            || scope.key_purpose == 0
            || scope.credential_id == 0
            || scope.key_id == 0
        {
            return Err(PeerAnchorError::ScopeMismatch);
        }
        let root = root.as_ref().to_path_buf();
        if !root.is_absolute() {
            return Err(PeerAnchorError::InvalidPath);
        }
        let md = fs::symlink_metadata(&root).map_err(|_| PeerAnchorError::InvalidPath)?;
        if !md.is_dir() || md.file_type().is_symlink() {
            return Err(PeerAnchorError::InvalidPath);
        }
        let lock_path = root.join("peer-identity-vault.lockstate");
        let lock = SnapshotWriterLock::acquire(&lock_path)?;
        let mut paths = Vec::new();
        for entry in fs::read_dir(&root).map_err(|_| PeerAnchorError::Persistence)? {
            let entry = entry.map_err(|_| PeerAnchorError::Persistence)?;
            let name = entry.file_name();
            if name.to_string_lossy().starts_with(".peer-identity-event-") {
                // An interrupted staging write is never promoted or deleted at open.
                // Quarantine the vault for an explicit operator recovery decision.
                return Err(PeerAnchorError::Corrupt);
            }
            if name.to_string_lossy().starts_with("event-") {
                let m =
                    fs::symlink_metadata(entry.path()).map_err(|_| PeerAnchorError::Persistence)?;
                if !m.is_file() || m.file_type().is_symlink() {
                    return Err(PeerAnchorError::Corrupt);
                }
                paths.push((name, entry.path()));
            }
        }
        paths.sort_by(|a, b| a.0.cmp(&b.0));
        if paths.len() as u64 > MAX_EVENTS {
            return Err(PeerAnchorError::Corrupt);
        }
        let expected_scope = scope.digest();
        let mut events = Vec::with_capacity(paths.len());
        let mut previous = [0u8; 32];
        for (i, (name, path)) in paths.into_iter().enumerate() {
            let expected_name = format!("event-{:020}.piv1", i as u64 + 1);
            if name.to_string_lossy() != expected_name {
                return Err(PeerAnchorError::Corrupt);
            }
            let mut f = File::open(path).map_err(|_| PeerAnchorError::Persistence)?;
            if f.metadata()
                .map_err(|_| PeerAnchorError::Persistence)?
                .len()
                != WIRE_LEN as u64
            {
                return Err(PeerAnchorError::Corrupt);
            }
            let mut b = Vec::with_capacity(WIRE_LEN);
            f.read_to_end(&mut b)
                .map_err(|_| PeerAnchorError::Persistence)?;
            let e = StoredEvent::decode(&b)?;
            if e.sequence != i as u64 + 1
                || e.scope_digest != expected_scope
                || e.previous_digest != previous
            {
                return Err(PeerAnchorError::ScopeMismatch);
            }
            validate_transition(events.last(), &e).map_err(|_| PeerAnchorError::Corrupt)?;
            previous = e.digest;
            events.push(e);
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

    /// Confirm that the supplied scope is exactly the one validated when this vault was opened.
    pub fn matches_scope(&self, scope: &PeerIdentityAnchorScope) -> bool {
        self.scope_digest == scope.digest()
    }

    /// Exact active identity tuple persisted by the latest ACTIVE event.
    pub fn active_record_binding(&self) -> Option<(u32, [u8; 32], u8)> {
        self.events
            .iter()
            .rev()
            .find(|e| {
                e.event.kind == PeerAnchorEventKind::EnrolledActive
                    || e.event.kind == PeerAnchorEventKind::RotationActive
            })
            .map(|e| {
                (
                    e.event.generation,
                    e.event.key_record_digest,
                    e.event.lifecycle,
                )
            })
    }

    /// Return the pending successor generation, if the last event is PREPARED.
    pub fn pending_generation(&self) -> Option<u32> {
        self.events
            .last()
            .filter(|e| e.event.kind == PeerAnchorEventKind::RotationPrepared)
            .map(|e| e.event.generation)
    }
    pub fn active_generation(&self) -> Option<u32> {
        self.events
            .iter()
            .rev()
            .find(|e| {
                e.event.kind == PeerAnchorEventKind::EnrolledActive
                    || e.event.kind == PeerAnchorEventKind::RotationActive
            })
            .map(|e| e.event.generation)
    }

    /// Return the latest ROTATION_ACTIVE event only when it is the chain tail.
    /// A PREPARED tail must not be mistaken for an activated successor.
    pub fn latest_rotation_active_binding(&self) -> Option<PeerAnchorRotationActiveBinding> {
        self.events
            .last()
            .filter(|stored| stored.event.kind == PeerAnchorEventKind::RotationActive)
            .map(|stored| PeerAnchorRotationActiveBinding {
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

    pub fn contains_nonce(&self, nonce: &[u8; 32]) -> bool {
        self.events.iter().any(|e| {
            e.event.kind == PeerAnchorEventKind::RotationPrepared && &e.event.nonce == nonce
        })
    }

    /// Explicit enrollment ceremony only; callers must not invoke this as startup recovery.
    pub fn enroll_genesis(&mut self, event: PeerAnchorEvent) -> Result<(), PeerAnchorError> {
        if !self.events.is_empty() {
            return Err(PeerAnchorError::AlreadyEnrolled);
        }
        if event.kind != PeerAnchorEventKind::EnrolledActive
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
            return Err(PeerAnchorError::InvalidEvent);
        }
        self.append(event)
    }

    /// Persist a verified, dual-authorized successor as PREPARED; this does not activate it.
    pub fn prepare_rotation(&mut self, event: PeerAnchorEvent) -> Result<(), PeerAnchorError> {
        if event.kind != PeerAnchorEventKind::RotationPrepared
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
            return Err(PeerAnchorError::InvalidEvent);
        }
        if let Some(last) = self.events.last() {
            if last.event.kind == PeerAnchorEventKind::RotationPrepared {
                if last.event == event {
                    return Ok(());
                }
                if last.event.nonce == event.nonce || self.contains_nonce(&event.nonce) {
                    return Err(PeerAnchorError::NonceReplay);
                }
                return Err(PeerAnchorError::RotationPending);
            }
        }
        if self.contains_nonce(&event.nonce) {
            return Err(PeerAnchorError::NonceReplay);
        }
        let active = self
            .active_generation()
            .ok_or(PeerAnchorError::EnrollmentRequired)?;
        if event.previous_generation != active
            || event.generation
                != active
                    .checked_add(1)
                    .ok_or(PeerAnchorError::GenerationMismatch)?
        {
            return Err(PeerAnchorError::GenerationMismatch);
        }
        self.append(event)
    }

    /// Activate only the exact latest PREPARED event. Higher-level reload/session gates remain external.
    pub fn activate_prepared(&mut self, nonce: [u8; 32]) -> Result<(), PeerAnchorError> {
        let last = self
            .events
            .last()
            .ok_or(PeerAnchorError::PreparedMissing)?
            .clone();
        if last.event.kind == PeerAnchorEventKind::RotationActive && last.event.nonce == nonce {
            return Ok(());
        }
        if last.event.kind != PeerAnchorEventKind::RotationPrepared || last.event.nonce != nonce {
            return Err(PeerAnchorError::PreparedMissing);
        }
        let mut event = last.event;
        event.kind = PeerAnchorEventKind::RotationActive;
        self.append(event)
    }

    fn append(&mut self, event: PeerAnchorEvent) -> Result<(), PeerAnchorError> {
        let sequence = self.events.len() as u64 + 1;
        if sequence > MAX_EVENTS {
            return Err(PeerAnchorError::Corrupt);
        }
        let previous_digest = self.events.last().map(|e| e.digest).unwrap_or([0; 32]);
        let mut stored = StoredEvent {
            sequence,
            scope_digest: self.scope_digest,
            event,
            previous_digest,
            digest: [0; 32],
        };
        stored.seal();
        validate_transition(self.events.last(), &stored)?;
        let final_path = self.root.join(format!("event-{sequence:020}.piv1"));
        let temp_id = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
        let temp_path = self.root.join(format!(
            ".peer-identity-event-{sequence:020}-{}-{temp_id}.tmp",
            std::process::id()
        ));
        let encoded = stored.encode();
        let result = (|| -> Result<(), PeerAnchorError> {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temp_path)
                .map_err(|_| PeerAnchorError::Persistence)?;
            file.write_all(&encoded)
                .map_err(|_| PeerAnchorError::Persistence)?;
            file.flush().map_err(|_| PeerAnchorError::Persistence)?;
            file.sync_all().map_err(|_| PeerAnchorError::Persistence)?;
            drop(file);
            let mut staged = Vec::with_capacity(WIRE_LEN);
            File::open(&temp_path)
                .and_then(|mut f| f.read_to_end(&mut staged))
                .map_err(|_| PeerAnchorError::Persistence)?;
            let decoded = StoredEvent::decode(&staged)?;
            if staged != encoded
                || decoded.sequence != sequence
                || decoded.scope_digest != self.scope_digest
                || decoded.previous_digest != previous_digest
            {
                return Err(PeerAnchorError::Corrupt);
            }
            publish_new_event(&temp_path, &final_path)?;
            Ok(())
        })();
        if result.is_err() {
            // Never remove an interrupted stage automatically: it is forensic evidence.
            return result;
        }
        self.events.push(stored);
        Ok(())
    }
}

pub(crate) fn publish_new_event(source: &Path, destination: &Path) -> Result<(), PeerAnchorError> {
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        const MOVEFILE_WRITE_THROUGH: u32 = 0x8;
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
        // Deliberately omit REPLACE_EXISTING: an existing sequence is a hard conflict.
        let ok = unsafe { MoveFileExW(from.as_ptr(), to.as_ptr(), MOVEFILE_WRITE_THROUGH) };
        if ok == 0 {
            return Err(PeerAnchorError::Persistence);
        }
    }
    #[cfg(not(windows))]
    {
        fs::hard_link(source, destination).map_err(|_| PeerAnchorError::Persistence)?;
        let _ = fs::remove_file(source);
        File::open(destination.parent().ok_or(PeerAnchorError::InvalidPath)?)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| PeerAnchorError::Persistence)?;
    }
    Ok(())
}
fn all_nonzero(values: &[&[u8; 32]]) -> bool {
    values.iter().all(|v| **v != [0; 32])
}
fn validate_transition(
    previous: Option<&StoredEvent>,
    current: &StoredEvent,
) -> Result<(), PeerAnchorError> {
    let e = &current.event;
    match (previous, e.kind) {
        (None, PeerAnchorEventKind::EnrolledActive)
            if e.generation > 0
                && e.previous_generation == 0
                && e.lifecycle == 1
                && all_nonzero(&[
                    &e.noise_fingerprint,
                    &e.npi1_digest,
                    &e.key_record_digest,
                    &e.owner_pin_fingerprint,
                    &e.operator_pin_fingerprint,
                ])
                && e.owner_pin_fingerprint != e.operator_pin_fingerprint
                && e.nrt1_digest == [0; 32]
                && e.intent_digest == [0; 32]
                && e.nonce == [0; 32]
                && e.previous_key_record_digest == [0; 32] =>
        {
            Ok(())
        }
        (Some(p), PeerAnchorEventKind::RotationPrepared)
            if (p.event.kind == PeerAnchorEventKind::EnrolledActive
                || p.event.kind == PeerAnchorEventKind::RotationActive)
                && p.event.generation.checked_add(1) == Some(e.generation)
                && e.previous_generation == p.event.generation
                && e.previous_key_record_digest == p.event.key_record_digest
                && e.lifecycle == 1
                && all_nonzero(&[
                    &e.noise_fingerprint,
                    &e.npi1_digest,
                    &e.key_record_digest,
                    &e.nrt1_digest,
                    &e.intent_digest,
                    &e.nonce,
                    &e.owner_pin_fingerprint,
                    &e.operator_pin_fingerprint,
                ])
                && e.owner_pin_fingerprint == p.event.owner_pin_fingerprint
                && e.operator_pin_fingerprint == p.event.operator_pin_fingerprint =>
        {
            Ok(())
        }
        (Some(p), PeerAnchorEventKind::RotationActive)
            if p.event.kind == PeerAnchorEventKind::RotationPrepared =>
        {
            let mut expected = p.event.clone();
            expected.kind = PeerAnchorEventKind::RotationActive;
            if e == &expected {
                Ok(())
            } else {
                Err(PeerAnchorError::InvalidEvent)
            }
        }
        _ => Err(PeerAnchorError::InvalidEvent),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(1);
    fn temp() -> PathBuf {
        let p = std::env::temp_dir().join(format!(
            "peer-anchor-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&p).unwrap();
        p
    }
    fn scope() -> PeerIdentityAnchorScope {
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
    fn enrollment() -> PeerAnchorEvent {
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
    fn prepared(nonce: u8) -> PeerAnchorEvent {
        PeerAnchorEvent {
            kind: PeerAnchorEventKind::RotationPrepared,
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
    #[test]
    fn explicit_enrollment_and_reopen_preserve_high_water() {
        let p = temp();
        {
            let mut v = PeerIdentityAnchorVault::open(&p, scope()).unwrap();
            v.enroll_genesis(enrollment()).unwrap();
            assert_eq!(v.active_generation(), Some(1));
        }
        let v = PeerIdentityAnchorVault::open(&p, scope()).unwrap();
        assert_eq!(v.active_generation(), Some(1));
        assert_eq!(v.event_count(), 1);
        fs::remove_dir_all(p).unwrap();
    }
    #[test]
    fn prepared_nonce_is_durable_and_conflicting_reuse_rejected() {
        let p = temp();
        {
            let mut v = PeerIdentityAnchorVault::open(&p, scope()).unwrap();
            v.enroll_genesis(enrollment()).unwrap();
            let first = prepared(21);
            v.prepare_rotation(first.clone()).unwrap();
            v.prepare_rotation(first).unwrap(); // exact retry is idempotent
            assert_eq!(
                v.prepare_rotation(prepared(24)),
                Err(PeerAnchorError::RotationPending)
            );
            assert!(v.contains_nonce(&[21; 32]));
            assert_eq!(v.active_generation(), Some(1));
            let mut changed = prepared(21);
            changed.npi1_digest = [99; 32];
            assert_eq!(
                v.prepare_rotation(changed),
                Err(PeerAnchorError::NonceReplay)
            );
        }
        let mut v = PeerIdentityAnchorVault::open(&p, scope()).unwrap();
        assert!(v.contains_nonce(&[21; 32]));
        v.prepare_rotation(prepared(21)).unwrap();
        assert_eq!(v.active_generation(), Some(1));
        drop(v);
        fs::remove_dir_all(p).unwrap();
    }
    #[test]
    fn activation_requires_exact_prepared_nonce() {
        let p = temp();
        let mut v = PeerIdentityAnchorVault::open(&p, scope()).unwrap();
        v.enroll_genesis(enrollment()).unwrap();
        v.prepare_rotation(prepared(22)).unwrap();
        assert_eq!(
            v.activate_prepared([23; 32]),
            Err(PeerAnchorError::PreparedMissing)
        );
        v.activate_prepared([22; 32]).unwrap();
        v.activate_prepared([22; 32]).unwrap(); // exact retry is idempotent
        assert_eq!(
            v.prepare_rotation(prepared(22)),
            Err(PeerAnchorError::NonceReplay)
        );
        assert_eq!(v.active_generation(), Some(2));
        drop(v);
        let mut v = PeerIdentityAnchorVault::open(&p, scope()).unwrap();
        assert_eq!(v.active_generation(), Some(2));
        v.activate_prepared([22; 32]).unwrap();
        drop(v);
        fs::remove_dir_all(p).unwrap();
    }
    #[test]
    fn tampered_chain_is_rejected() {
        let p = temp();
        {
            let mut v = PeerIdentityAnchorVault::open(&p, scope()).unwrap();
            v.enroll_genesis(enrollment()).unwrap();
        }
        let f = p.join("event-00000000000000000001.piv1");
        let mut b = fs::read(&f).unwrap();
        b[40] ^= 1;
        fs::write(f, b).unwrap();
        assert!(PeerIdentityAnchorVault::open(&p, scope()).is_err());
        fs::remove_dir_all(p).unwrap();
    }
    #[test]
    fn invalid_transition_is_rejected_before_file_creation() {
        let p = temp();
        let mut v = PeerIdentityAnchorVault::open(&p, scope()).unwrap();
        v.enroll_genesis(enrollment()).unwrap();
        let mut invalid = prepared(31);
        invalid.previous_generation = 0;
        assert_eq!(v.append(invalid), Err(PeerAnchorError::InvalidEvent));
        assert!(!p.join("event-00000000000000000002.piv1").exists());
        let mut changed_predecessor = prepared(34);
        changed_predecessor.previous_key_record_digest = [88; 32];
        assert_eq!(
            v.append(changed_predecessor),
            Err(PeerAnchorError::InvalidEvent)
        );
        assert!(!p.join("event-00000000000000000002.piv1").exists());
        let mut changed_pin = prepared(35);
        changed_pin.owner_pin_fingerprint = [55; 32];
        assert_eq!(v.append(changed_pin), Err(PeerAnchorError::InvalidEvent));
        assert!(!p.join("event-00000000000000000002.piv1").exists());
        drop(v);
        fs::remove_dir_all(p).unwrap();
    }

    #[test]
    fn next_rotation_can_be_prepared_only_after_previous_activation() {
        let p = temp();
        let mut v = PeerIdentityAnchorVault::open(&p, scope()).unwrap();
        v.enroll_genesis(enrollment()).unwrap();
        v.prepare_rotation(prepared(32)).unwrap();
        v.activate_prepared([32; 32]).unwrap();
        let mut next = prepared(33);
        next.generation = 3;
        next.previous_generation = 2;
        next.previous_key_record_digest = [9; 32];
        v.prepare_rotation(next).unwrap();
        assert_eq!(v.active_generation(), Some(2));
        assert!(v.contains_nonce(&[33; 32]));
        drop(v);
        let v = PeerIdentityAnchorVault::open(&p, scope()).unwrap();
        assert_eq!(v.active_generation(), Some(2));
        assert!(v.contains_nonce(&[33; 32]));
        drop(v);
        fs::remove_dir_all(p).unwrap();
    }
    #[test]
    fn empty_vault_never_self_enrolls() {
        let p = temp();
        let mut v = PeerIdentityAnchorVault::open(&p, scope()).unwrap();
        assert_eq!(v.active_generation(), None);
        assert_eq!(v.event_count(), 0);
        assert_eq!(
            v.prepare_rotation(prepared(40)),
            Err(PeerAnchorError::EnrollmentRequired)
        );
        assert_eq!(v.event_count(), 0);
        drop(v);
        fs::remove_dir_all(p).unwrap();
    }

    #[test]
    fn exclusive_writer_lock_blocks_a_second_open() {
        let p = temp();
        let first = PeerIdentityAnchorVault::open(&p, scope()).unwrap();
        assert!(matches!(
            PeerIdentityAnchorVault::open(&p, scope()),
            Err(PeerAnchorError::Locked)
        ));
        drop(first);
        let reopened = PeerIdentityAnchorVault::open(&p, scope()).unwrap();
        drop(reopened);
        fs::remove_dir_all(p).unwrap();
    }
    #[test]
    fn scope_mismatch_is_rejected() {
        let p = temp();
        {
            let mut v = PeerIdentityAnchorVault::open(&p, scope()).unwrap();
            v.enroll_genesis(enrollment()).unwrap();
        }
        let mut other = scope();
        other.issuer_public_key_fingerprint = [44; 32];
        assert!(PeerIdentityAnchorVault::open(&p, other).is_err());
        fs::remove_dir_all(p).unwrap();
    }
    #[test]
    fn interrupted_staging_file_quarantines_vault_without_auto_repair() {
        let p = temp();
        let staged = p.join(".peer-identity-event-00000000000000000001-123-1.tmp");
        fs::write(&staged, b"partial-event").unwrap();

        assert!(matches!(
            PeerIdentityAnchorVault::open(&p, scope()),
            Err(PeerAnchorError::Corrupt)
        ));
        assert_eq!(fs::read(&staged).unwrap(), b"partial-event");
        fs::remove_dir_all(p).unwrap();
    }

    #[test]
    fn final_event_publication_never_overwrites_existing_sequence() {
        let p = temp();
        let source = p.join(".peer-identity-event-stage.tmp");
        let destination = p.join("event-00000000000000000001.piv1");
        fs::write(&source, b"new-event").unwrap();
        fs::write(&destination, b"preexisting-event").unwrap();

        assert_eq!(
            publish_new_event(&source, &destination),
            Err(PeerAnchorError::Persistence)
        );
        assert_eq!(fs::read(&destination).unwrap(), b"preexisting-event");
        assert_eq!(fs::read(&source).unwrap(), b"new-event");
        fs::remove_dir_all(p).unwrap();
    }
}
