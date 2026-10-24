//! CP-0404 candidate adapter for explicit-profile QZB4 v2 import and durable recovery.
//!
//! This adapter is not connected to the public node listener or canonical PoW/fork-choice path.
//! It requires an externally persistent compare-and-set anti-rollback anchor; there is no local
//! or in-memory default. QZB4 v1, BLK2, MBK3 and MBK4 are never accepted as fallbacks.

use crate::{
    monetary_genesis_v04_candidate::GenesisManifestV04,
    monetary_transition_v04_candidate::{
        MonetaryLedgerStateV04TransitionCandidate, V04ConsensusProfileCandidate,
        V04ExecutionApplySummary, V04ExecutionBlockCandidate, V04TransitionError,
        MAX_ENCODED_V04_EXECUTION_BLOCK_BYTES, MAX_ENCODED_V04_PROFILE_BOUND_SNAPSHOT_BYTES,
        V04_MINING_BLOCK_MAGIC,
    },
    snapshot_store::{self, SnapshotStoreError, SnapshotWriterLock},
    state_machine::TransactionAuthenticator,
};
use sha2::{Digest, Sha256};
use std::{
    fmt,
    fs::{self, File},
    io::{self, Read},
    path::{Path, PathBuf},
};

const QZB4_EXECUTION_VERSION: u16 = 2;
const SNAPSHOT_DIGEST_DOMAIN: &[u8] = b"QUANTUMZXB-V04-RUNTIME-SNAPSHOT-DIGEST-CANDIDATE-V1\0";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct V04RuntimeAnchorRecord {
    /// Monotonic storage commit sequence, independent of chain height (reorgs may lower height).
    pub sequence: u64,
    pub network_id: [u8; 32],
    pub genesis_manifest_hash: [u8; 32],
    pub profile_fingerprint: [u8; 32],
    pub height: u64,
    pub tip_hash: [u8; 32],
    pub state_root: [u8; 32],
    /// Commits the exact canonical snapshot bytes, not just a self-described height or tip.
    pub snapshot_digest: [u8; 32],
}

/// Must be backed by a durable external monotonic source, independent of the node snapshot file.
/// Implementations must make compare-and-set atomic and must not accept stale sequence values.
/// A test-only in-memory implementation exists below only inside cfg(test).
pub trait V04MonotonicAnchor: Send + Sync {
    fn load(&self) -> Result<Option<V04RuntimeAnchorRecord>, String>;

    fn compare_and_set(
        &self,
        expected: Option<&V04RuntimeAnchorRecord>,
        next: &V04RuntimeAnchorRecord,
    ) -> Result<(), String>;
}

#[derive(Debug)]
pub enum V04RuntimeError {
    Transition(V04TransitionError),
    Storage(SnapshotStoreError),
    AnchorRead(String),
    AnchorWrite(String),
    AnchorMismatch,
    AnchorChanged,
    MissingSnapshot,
    MissingAnchorForSnapshot,
    UnsupportedBlockFamily,
    TruncatedBlockHeader,
    UnsupportedBlockVersion(u16),
    ProfileMismatch,
    SnapshotTooLarge,
    InvalidPath,
    SequenceOverflow,
    RecoveryRequired,
}

impl fmt::Display for V04RuntimeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for V04RuntimeError {}
impl From<V04TransitionError> for V04RuntimeError {
    fn from(value: V04TransitionError) -> Self {
        Self::Transition(value)
    }
}
impl From<SnapshotStoreError> for V04RuntimeError {
    fn from(value: SnapshotStoreError) -> Self {
        Self::Storage(value)
    }
}
impl From<io::Error> for V04RuntimeError {
    fn from(value: io::Error) -> Self {
        Self::Storage(SnapshotStoreError::Io(value))
    }
}

/// Decodes only the configured QZB4 v2 execution family and pins every block to one profile.
/// A v1 block or an unrelated legacy-family payload is rejected, never retried via another codec.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct V04ExecutionBlockDispatcher {
    profile_fingerprint: [u8; 32],
}

impl V04ExecutionBlockDispatcher {
    pub fn new(profile: &V04ConsensusProfileCandidate) -> Self {
        Self {
            profile_fingerprint: *profile.profile_fingerprint(),
        }
    }

    pub fn decode(&self, bytes: &[u8]) -> Result<V04ExecutionBlockCandidate, V04RuntimeError> {
        if bytes.len() > MAX_ENCODED_V04_EXECUTION_BLOCK_BYTES {
            return Err(V04RuntimeError::Transition(
                V04TransitionError::MalformedExecutionBlock,
            ));
        }
        if bytes.len() < 6 {
            return Err(V04RuntimeError::TruncatedBlockHeader);
        }
        if bytes[..4] != V04_MINING_BLOCK_MAGIC {
            return Err(V04RuntimeError::UnsupportedBlockFamily);
        }
        let version = u16::from_be_bytes([bytes[4], bytes[5]]);
        if version != QZB4_EXECUTION_VERSION {
            return Err(V04RuntimeError::UnsupportedBlockVersion(version));
        }
        let block = V04ExecutionBlockCandidate::decode(bytes)?;
        if block.profile_fingerprint != self.profile_fingerprint {
            return Err(V04RuntimeError::ProfileMismatch);
        }
        Ok(block)
    }
}

/// Profile-pinned QZB4 v2 importer with crash-safe two-phase snapshot/anchor commit.
///
/// The pending snapshot is first written atomically. The external monotonic anchor then commits
/// its exact digest by CAS, and only afterward is the canonical snapshot path replaced. If a crash
/// occurs between the external CAS and the canonical replacement, startup promotes the pending
/// file only when its bytes exactly match the current external anchor. This is a candidate adapter,
/// not yet wired to node networking, PoW header verification, or consensus fork choice.
pub struct V04ExecutionImportService<A, M> {
    state: MonetaryLedgerStateV04TransitionCandidate,
    manifest: GenesisManifestV04,
    profile: V04ConsensusProfileCandidate,
    authenticator: A,
    anchor: M,
    anchor_record: V04RuntimeAnchorRecord,
    snapshot_path: PathBuf,
    pending_path: PathBuf,
    _writer_lock: SnapshotWriterLock,
    poisoned: bool,
}

impl<A, M> V04ExecutionImportService<A, M>
where
    A: TransactionAuthenticator,
    M: V04MonotonicAnchor,
{
    /// Open only an anchored canonical snapshot, recover an anchored pending commit, or initialize
    /// Genesis when both the snapshot and external anchor are absent. Economic schedule parameters
    /// must be supplied explicitly in the caller-created profile; this API defines no default.
    pub fn open(
        manifest: GenesisManifestV04,
        profile: V04ConsensusProfileCandidate,
        authenticator: A,
        anchor: M,
        snapshot_path: impl AsRef<Path>,
    ) -> Result<Self, V04RuntimeError> {
        profile.validate_for_manifest(&manifest)?;
        let snapshot_path = snapshot_path.as_ref().to_path_buf();
        let pending_path = pending_path_for(&snapshot_path)?;
        let writer_lock = SnapshotWriterLock::acquire(&snapshot_path)?;
        let anchored = anchor.load().map_err(V04RuntimeError::AnchorRead)?;

        let state = if regular_file_exists(&snapshot_path)? {
            let bytes =
                read_bounded_file(&snapshot_path, MAX_ENCODED_V04_PROFILE_BOUND_SNAPSHOT_BYTES)?;
            let decoded = MonetaryLedgerStateV04TransitionCandidate::decode_snapshot(
                &bytes, &manifest, &profile,
            )?;
            if let Some(record) = anchored.as_ref() {
                if anchor_matches(record, &decoded, &bytes) {
                    remove_pending_file_if_present(&pending_path)?;
                    decoded
                } else if regular_file_exists(&pending_path)? {
                    Self::promote_pending(
                        &pending_path,
                        &snapshot_path,
                        &manifest,
                        &profile,
                        anchored.as_ref(),
                    )?
                } else {
                    return Err(V04RuntimeError::AnchorMismatch);
                }
            } else {
                return Err(V04RuntimeError::MissingAnchorForSnapshot);
            }
        } else if regular_file_exists(&pending_path)? {
            match anchored.as_ref() {
                Some(record) => Self::promote_pending(
                    &pending_path,
                    &snapshot_path,
                    &manifest,
                    &profile,
                    Some(record),
                )?,
                None => {
                    // Without a committed anchor, a pending file is not committed state.
                    remove_pending_file_if_present(&pending_path)?;
                    Self::initialize_genesis(
                        &manifest,
                        &profile,
                        &anchor,
                        &snapshot_path,
                        &pending_path,
                    )?
                }
            }
        } else {
            match anchored.as_ref() {
                None => Self::initialize_genesis(
                    &manifest,
                    &profile,
                    &anchor,
                    &snapshot_path,
                    &pending_path,
                )?,
                Some(_) => return Err(V04RuntimeError::MissingSnapshot),
            }
        };

        let snapshot_bytes =
            read_bounded_file(&snapshot_path, MAX_ENCODED_V04_PROFILE_BOUND_SNAPSHOT_BYTES)?;
        let anchor_record = anchor
            .load()
            .map_err(V04RuntimeError::AnchorRead)?
            .ok_or(V04RuntimeError::MissingAnchorForSnapshot)?;
        if !anchor_matches(&anchor_record, &state, &snapshot_bytes) {
            return Err(V04RuntimeError::AnchorMismatch);
        }

        Ok(Self {
            state,
            manifest,
            profile,
            authenticator,
            anchor,
            anchor_record,
            snapshot_path,
            pending_path,
            _writer_lock: writer_lock,
            poisoned: false,
        })
    }

    fn initialize_genesis(
        manifest: &GenesisManifestV04,
        profile: &V04ConsensusProfileCandidate,
        anchor: &M,
        snapshot_path: &Path,
        pending_path: &Path,
    ) -> Result<MonetaryLedgerStateV04TransitionCandidate, V04RuntimeError> {
        let state =
            MonetaryLedgerStateV04TransitionCandidate::from_genesis_manifest(manifest, profile)?;
        let bytes = state.encode_snapshot()?;
        let record = make_anchor_record(0, &state, &bytes)?;
        atomic_write(pending_path, &bytes)?;
        if let Err(error) = anchor.compare_and_set(None, &record) {
            let now = anchor.load().map_err(V04RuntimeError::AnchorRead)?;
            if now.as_ref() != Some(&record) {
                if now.is_none() {
                    remove_pending_file_if_present(pending_path)?;
                    return Err(V04RuntimeError::AnchorWrite(error));
                }
                return Err(V04RuntimeError::AnchorMismatch);
            }
        }
        let now = anchor.load().map_err(V04RuntimeError::AnchorRead)?;
        if now.as_ref() != Some(&record) {
            return Err(V04RuntimeError::AnchorMismatch);
        }
        atomic_write(snapshot_path, &bytes)?;
        remove_pending_file_if_present(pending_path)?;
        Ok(state)
    }

    fn promote_pending(
        pending_path: &Path,
        snapshot_path: &Path,
        manifest: &GenesisManifestV04,
        profile: &V04ConsensusProfileCandidate,
        anchored: Option<&V04RuntimeAnchorRecord>,
    ) -> Result<MonetaryLedgerStateV04TransitionCandidate, V04RuntimeError> {
        let bytes = read_bounded_file(pending_path, MAX_ENCODED_V04_PROFILE_BOUND_SNAPSHOT_BYTES)?;
        let decoded =
            MonetaryLedgerStateV04TransitionCandidate::decode_snapshot(&bytes, manifest, profile)?;
        let record = anchored.ok_or(V04RuntimeError::MissingAnchorForSnapshot)?;
        if !anchor_matches(record, &decoded, &bytes) {
            return Err(V04RuntimeError::AnchorMismatch);
        }
        atomic_write(snapshot_path, &bytes)?;
        remove_pending_file_if_present(pending_path)?;
        Ok(decoded)
    }

    fn ensure_anchor_current(&self) -> Result<(), V04RuntimeError> {
        if self.poisoned {
            return Err(V04RuntimeError::RecoveryRequired);
        }
        let current = self.anchor.load().map_err(V04RuntimeError::AnchorRead)?;
        if current.as_ref() != Some(&self.anchor_record) {
            return Err(V04RuntimeError::AnchorChanged);
        }
        Ok(())
    }

    pub fn build_next_block(
        &self,
        timestamp: u64,
        miner: [u8; 32],
        transactions: Vec<crate::state_machine::Transaction>,
    ) -> Result<V04ExecutionBlockCandidate, V04RuntimeError> {
        self.ensure_anchor_current()?;
        Ok(self.state.build_next_execution_block(
            timestamp,
            miner,
            transactions,
            &self.authenticator,
        )?)
    }

    /// Dispatch, independently execute and durably commit a QZB4 v2 block.
    /// Invalid blocks and failed CAS checks never publish staged in-memory state.
    pub fn import_bytes(
        &mut self,
        bytes: &[u8],
    ) -> Result<V04ExecutionApplySummary, V04RuntimeError> {
        self.ensure_anchor_current()?;
        let dispatcher = V04ExecutionBlockDispatcher::new(&self.profile);
        let block = dispatcher.decode(bytes)?;
        let mut staged = self.state.clone();
        let summary = staged.apply_execution_block(&block, &self.authenticator)?;
        self.commit_staged(staged)?;
        Ok(summary)
    }

    fn commit_staged(
        &mut self,
        staged: MonetaryLedgerStateV04TransitionCandidate,
    ) -> Result<(), V04RuntimeError> {
        self.ensure_anchor_current()?;
        let bytes = staged.encode_snapshot()?;
        let next_sequence = self
            .anchor_record
            .sequence
            .checked_add(1)
            .ok_or(V04RuntimeError::SequenceOverflow)?;
        let next = make_anchor_record(next_sequence, &staged, &bytes)?;
        atomic_write(&self.pending_path, &bytes)?;

        if let Err(error) = self
            .anchor
            .compare_and_set(Some(&self.anchor_record), &next)
        {
            let now = self.anchor.load().map_err(V04RuntimeError::AnchorRead)?;
            if now.as_ref() == Some(&self.anchor_record) {
                remove_pending_file_if_present(&self.pending_path)?;
                return Err(V04RuntimeError::AnchorWrite(error));
            }
            if now.as_ref() != Some(&next) {
                self.poisoned = true;
                return Err(V04RuntimeError::AnchorChanged);
            }
        }

        let now = self.anchor.load().map_err(V04RuntimeError::AnchorRead)?;
        if now.as_ref() != Some(&next) {
            self.poisoned = true;
            return Err(V04RuntimeError::AnchorChanged);
        }
        if let Err(error) = atomic_write(&self.snapshot_path, &bytes) {
            // The new anchored pending snapshot lets the next process recover without a downgrade.
            self.poisoned = true;
            return Err(error);
        }
        // Canonical path and external anchor agree; a leftover pending copy is harmless.
        let _ = remove_pending_file_if_present(&self.pending_path);
        self.state = staged;
        self.anchor_record = next;
        Ok(())
    }

    pub fn state(&self) -> &MonetaryLedgerStateV04TransitionCandidate {
        &self.state
    }

    pub fn anchor_record(&self) -> &V04RuntimeAnchorRecord {
        &self.anchor_record
    }

    pub fn snapshot_path(&self) -> &Path {
        &self.snapshot_path
    }

    pub fn manifest(&self) -> &GenesisManifestV04 {
        &self.manifest
    }
}

fn make_anchor_record(
    sequence: u64,
    state: &MonetaryLedgerStateV04TransitionCandidate,
    snapshot: &[u8],
) -> Result<V04RuntimeAnchorRecord, V04RuntimeError> {
    Ok(V04RuntimeAnchorRecord {
        sequence,
        network_id: *state.profile().network_id(),
        genesis_manifest_hash: *state.profile().genesis_manifest_hash(),
        profile_fingerprint: *state.profile().profile_fingerprint(),
        height: state.ledger().height(),
        tip_hash: state.ledger().tip_hash(),
        state_root: state.state_root()?,
        snapshot_digest: snapshot_digest(snapshot),
    })
}

fn anchor_matches(
    record: &V04RuntimeAnchorRecord,
    state: &MonetaryLedgerStateV04TransitionCandidate,
    snapshot: &[u8],
) -> bool {
    make_anchor_record(record.sequence, state, snapshot).is_ok_and(|expected| expected == *record)
}

fn snapshot_digest(snapshot: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(SNAPSHOT_DIGEST_DOMAIN);
    hash.update(snapshot);
    hash.finalize().into()
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), V04RuntimeError> {
    if bytes.len() > MAX_ENCODED_V04_PROFILE_BOUND_SNAPSHOT_BYTES {
        return Err(V04RuntimeError::SnapshotTooLarge);
    }
    snapshot_store::atomic_write_bytes_with_hook(path, bytes, |_| Ok(()))?;
    Ok(())
}

fn pending_path_for(path: &Path) -> Result<PathBuf, V04RuntimeError> {
    let file_name = path.file_name().ok_or(V04RuntimeError::InvalidPath)?;
    let mut pending_name = file_name.to_os_string();
    pending_name.push(".qzpending");
    Ok(path.with_file_name(pending_name))
}

fn regular_file_exists(path: &Path) -> Result<bool, V04RuntimeError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            Err(V04RuntimeError::InvalidPath)
        }
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

fn read_bounded_file(path: &Path, max_bytes: usize) -> Result<Vec<u8>, V04RuntimeError> {
    if !regular_file_exists(path)? {
        return Err(V04RuntimeError::MissingSnapshot);
    }
    let file = File::open(path)?;
    let length = file.metadata()?.len();
    if length > max_bytes as u64 {
        return Err(V04RuntimeError::SnapshotTooLarge);
    }
    let mut bytes = Vec::with_capacity(length as usize);
    file.take(max_bytes as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > max_bytes || bytes.len() as u64 != length {
        return Err(V04RuntimeError::SnapshotTooLarge);
    }
    Ok(bytes)
}

fn remove_pending_file_if_present(path: &Path) -> Result<(), V04RuntimeError> {
    if regular_file_exists(path)? {
        fs::remove_file(path)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        monetary_genesis_v04_candidate::GenesisManifestV04,
        monetary_issuance_v04_candidate::V04MiningIssuanceScheduleCandidate,
        state_machine::{AccountId, Transaction},
    };
    use std::{
        fs,
        sync::atomic::{AtomicU64, Ordering},
        sync::{Arc, Mutex},
    };

    const NETWORK: [u8; 32] = [0x31; 32];
    const OWNER: [u8; 32] = [0xA7; 32];
    const RECIPIENT: [u8; 32] = [0xB2; 32];
    const MINER: [u8; 32] = [0xC4; 32];
    static NEXT_DIR: AtomicU64 = AtomicU64::new(1);

    #[derive(Clone, Default)]
    struct MemoryAnchor(Arc<Mutex<Option<V04RuntimeAnchorRecord>>>);

    impl V04MonotonicAnchor for MemoryAnchor {
        fn load(&self) -> Result<Option<V04RuntimeAnchorRecord>, String> {
            self.0
                .lock()
                .map(|value| value.clone())
                .map_err(|_| "poisoned test anchor".into())
        }

        fn compare_and_set(
            &self,
            expected: Option<&V04RuntimeAnchorRecord>,
            next: &V04RuntimeAnchorRecord,
        ) -> Result<(), String> {
            let mut current = self
                .0
                .lock()
                .map_err(|_| "poisoned test anchor".to_string())?;
            if current.as_ref() != expected {
                return Err("test anchor CAS conflict".into());
            }
            match current.as_ref() {
                None if next.sequence != 0 => return Err("first sequence must be zero".into()),
                Some(old) if next.sequence != old.sequence.saturating_add(1) => {
                    return Err("anchor sequence must increase by one".into())
                }
                _ => {}
            }
            *current = Some(next.clone());
            Ok(())
        }
    }

    struct TestAuthenticator;
    impl TransactionAuthenticator for TestAuthenticator {
        fn verify(&self, _: &AccountId, _: &[u8; 32], signature: &[u8]) -> Result<(), ()> {
            if signature == [0x5A] {
                Ok(())
            } else {
                Err(())
            }
        }
    }

    /// Producer-only fixture deliberately differs from the importer's verifier.
    struct AcceptAnyAuthenticator;
    impl TransactionAuthenticator for AcceptAnyAuthenticator {
        fn verify(&self, _: &AccountId, _: &[u8; 32], signature: &[u8]) -> Result<(), ()> {
            if !signature.is_empty() {
                Ok(())
            } else {
                Err(())
            }
        }
    }

    fn manifest() -> GenesisManifestV04 {
        GenesisManifestV04::new(NETWORK, OWNER).unwrap()
    }

    fn profile(manifest: &GenesisManifestV04, subsidy: u128) -> V04ConsensusProfileCandidate {
        let schedule = V04MiningIssuanceScheduleCandidate::new(subsidy, 2).unwrap();
        V04ConsensusProfileCandidate::from_manifest_and_schedule(manifest, schedule).unwrap()
    }

    fn transfer() -> Transaction {
        Transaction {
            network_id: NETWORK,
            sender: OWNER,
            recipient: RECIPIENT,
            nonce: 1,
            amount: 2_500,
            fee: 7,
            expires_at: 100,
            signature: vec![0x5A],
        }
    }

    fn path() -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "qzb4-cp0404-{}-{}",
            std::process::id(),
            NEXT_DIR.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&path).unwrap();
        path.join("state.qzp4")
    }

    fn open(
        path: &Path,
        genesis: GenesisManifestV04,
        configured_profile: V04ConsensusProfileCandidate,
        anchor: MemoryAnchor,
    ) -> V04ExecutionImportService<TestAuthenticator, MemoryAnchor> {
        V04ExecutionImportService::open(
            genesis,
            configured_profile,
            TestAuthenticator,
            anchor,
            path,
        )
        .unwrap()
    }

    #[test]
    fn explicit_dispatcher_and_importer_reject_implicit_downgrade() {
        let manifest = manifest();
        let configured = profile(&manifest, 10_000);
        let anchor = MemoryAnchor::default();
        let path = path();
        let mut service = open(&path, manifest.clone(), configured.clone(), anchor.clone());

        let v1 = service
            .state()
            .build_next_block(1, MINER)
            .unwrap()
            .encode()
            .unwrap();
        assert!(matches!(
            service.import_bytes(&v1),
            Err(V04RuntimeError::UnsupportedBlockVersion(1))
        ));
        assert!(matches!(
            service.import_bytes(b"BLK2\0\x01"),
            Err(V04RuntimeError::UnsupportedBlockFamily)
        ));

        let block = service
            .build_next_block(1, MINER, vec![transfer()])
            .unwrap();
        let encoded = block.encode().unwrap();
        let summary = service.import_bytes(&encoded).unwrap();
        assert_eq!(summary.height, 1);
        assert_eq!(service.state().ledger().height(), 1);
        assert_eq!(service.anchor_record().sequence, 1);
        drop(service);

        let mut reopened = open(&path, manifest, configured, anchor);
        assert_eq!(reopened.state().ledger().height(), 1);
        assert!(matches!(
            reopened.import_bytes(&encoded),
            Err(V04RuntimeError::Transition(V04TransitionError::State(_)))
        ));
        assert_eq!(reopened.state().ledger().height(), 1);
        assert_eq!(reopened.anchor_record().sequence, 1);
    }

    #[test]
    fn profile_mismatch_and_invalid_signature_leave_snapshot_and_anchor_unchanged() {
        let manifest = manifest();
        let configured = profile(&manifest, 10_000);
        let anchor = MemoryAnchor::default();
        let path = path();
        let mut service = open(&path, manifest.clone(), configured, anchor.clone());
        let initial_bytes = fs::read(&path).unwrap();
        let initial_anchor = service.anchor_record().clone();

        let alternate = profile(&manifest, 20_000);
        let other =
            MonetaryLedgerStateV04TransitionCandidate::from_genesis_manifest(&manifest, &alternate)
                .unwrap();
        let other_block = other
            .build_next_execution_block(1, MINER, vec![], &TestAuthenticator)
            .unwrap()
            .encode()
            .unwrap();
        assert!(matches!(
            service.import_bytes(&other_block),
            Err(V04RuntimeError::ProfileMismatch)
        ));

        let mut invalid = transfer();
        invalid.signature = vec![0x00];
        let block = service
            .state()
            .build_next_execution_block(1, MINER, vec![invalid], &AcceptAnyAuthenticator)
            .unwrap();
        assert!(matches!(
            service.import_bytes(&block.encode().unwrap()),
            Err(V04RuntimeError::Transition(V04TransitionError::State(_)))
        ));

        assert_eq!(fs::read(&path).unwrap(), initial_bytes);
        assert_eq!(service.anchor_record(), &initial_anchor);
        assert_eq!(anchor.load().unwrap(), Some(initial_anchor));
        assert_eq!(service.state().ledger().height(), 0);
    }

    #[test]
    fn startup_promotes_pending_snapshot_only_when_external_anchor_committed_it() {
        let manifest = manifest();
        let configured = profile(&manifest, 10_000);
        let anchor = MemoryAnchor::default();
        let path = path();
        let service = open(&path, manifest.clone(), configured.clone(), anchor.clone());

        let block = service
            .build_next_block(1, MINER, vec![transfer()])
            .unwrap();
        let mut staged = service.state().clone();
        staged
            .apply_execution_block(&block, &TestAuthenticator)
            .unwrap();
        let bytes = staged.encode_snapshot().unwrap();
        let next =
            make_anchor_record(service.anchor_record().sequence + 1, &staged, &bytes).unwrap();
        let pending = pending_path_for(&path).unwrap();
        atomic_write(&pending, &bytes).unwrap();
        anchor
            .compare_and_set(Some(service.anchor_record()), &next)
            .unwrap();
        drop(service);

        let recovered = open(&path, manifest, configured, anchor.clone());
        assert_eq!(recovered.state().ledger().height(), 1);
        assert_eq!(recovered.anchor_record(), &next);
        assert_eq!(fs::read(&path).unwrap(), bytes);
        assert!(!pending.exists());
    }

    #[test]
    fn local_snapshot_rollback_is_rejected_against_external_anchor() {
        let manifest = manifest();
        let configured = profile(&manifest, 10_000);
        let anchor = MemoryAnchor::default();
        let path = path();
        let service = open(&path, manifest.clone(), configured.clone(), anchor.clone());
        let genesis_snapshot = fs::read(&path).unwrap();
        let block = service
            .build_next_block(1, MINER, vec![transfer()])
            .unwrap();
        drop(service);

        // Use a fresh service to commit height one, then overwrite the local file with old Genesis.
        let mut service = open(&path, manifest.clone(), configured.clone(), anchor.clone());
        service.import_bytes(&block.encode().unwrap()).unwrap();
        drop(service);
        fs::write(&path, genesis_snapshot).unwrap();

        assert!(matches!(
            V04ExecutionImportService::open(manifest, configured, TestAuthenticator, anchor, &path,),
            Err(V04RuntimeError::AnchorMismatch)
        ));
    }
}
