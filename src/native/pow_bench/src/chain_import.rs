//! Durable block-import facade for CP-0026-H.
//!
//! All live and replay imports pass through one service. It stages state in memory,
//! validates it through ChainAdmissionBoundary, commits the canonical snapshot, and
//! only then publishes the new in-memory state. Research/testbed integration only.

use crate::v4_account_identity_candidate::MlDsa65Verifier;
use crate::{
    chain_admission::{
        BlockAdmissionReceipt, ChainAdmissionBoundary, ChainAdmissionError, ReferenceTimeProvider,
    },
    snapshot_store::{self, SnapshotStoreError},
    state_machine::{
        decode_block, decode_v4_hybrid_monetary_block, LedgerState, MonetaryLedgerState,
        StateError, TransactionAuthenticator, V4HybridMonetaryBlock, MAX_ENCODED_BLOCK_BYTES,
        MAX_ENCODED_SNAPSHOT_BYTES,
    },
};
use sha2::{Digest, Sha256};
use std::{
    fmt,
    fs::File,
    io::Read,
    path::{Path, PathBuf},
};

#[derive(Debug)]
pub enum ChainImportError {
    State(StateError),
    Admission(ChainAdmissionError),
    Storage(SnapshotStoreError),
    InvalidMonetaryProfile,
    MonetaryProfileMismatch,
    MonetaryGenesisMismatch,
}

impl fmt::Display for ChainImportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::State(error) => write!(f, "block decode failed: {error:?}"),
            Self::Admission(error) => write!(f, "block admission rejected: {error:?}"),
            Self::Storage(error) => write!(f, "durable snapshot commit failed: {error}"),
            Self::InvalidMonetaryProfile => {
                write!(
                    f,
                    "the MBK4 import profile needs Genesis at height zero and non-zero network and manifest IDs"
                )
            }
            Self::MonetaryProfileMismatch => {
                write!(
                    f,
                    "the persisted snapshot is bound to a different network or manifest"
                )
            }
            Self::MonetaryGenesisMismatch => {
                write!(
                    f,
                    "the persisted snapshot was initialized from a different Genesis state"
                )
            }
        }
    }
}
impl std::error::Error for ChainImportError {}
impl From<StateError> for ChainImportError {
    fn from(value: StateError) -> Self {
        Self::State(value)
    }
}
impl From<ChainAdmissionError> for ChainImportError {
    fn from(value: ChainAdmissionError) -> Self {
        Self::Admission(value)
    }
}
impl From<SnapshotStoreError> for ChainImportError {
    fn from(value: SnapshotStoreError) -> Self {
        Self::Storage(value)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImportMode {
    Live,
    HistoricalReplay,
}

/// Caller used by the actual TCP import node and deterministic local tests.
pub struct ChainImportService<A, C> {
    state: LedgerState,
    admission: ChainAdmissionBoundary,
    authenticator: A,
    clock: C,
    snapshot_path: PathBuf,
    _writer_lock: snapshot_store::SnapshotWriterLock,
}

impl<A, C> ChainImportService<A, C>
where
    A: TransactionAuthenticator,
    C: ReferenceTimeProvider,
{
    /// Load the committed snapshot if present; otherwise durably initialize from genesis.
    /// Orphan temp files are deliberately never interpreted as committed state.
    pub fn open(
        initial_state: LedgerState,
        admission: ChainAdmissionBoundary,
        authenticator: A,
        clock: C,
        snapshot_path: impl AsRef<Path>,
    ) -> Result<Self, ChainImportError> {
        let snapshot_path = snapshot_path.as_ref().to_path_buf();
        // Claim one process-wide writer for this stable snapshot path before loading it.
        // The lock remains held for the lifetime of this service; a competing node fails closed.
        let writer_lock = snapshot_store::SnapshotWriterLock::acquire(&snapshot_path)?;
        let network_id = initial_state.network_id();
        let state = if snapshot_path.exists() {
            snapshot_store::load(&snapshot_path, &network_id)?
        } else {
            snapshot_store::save_atomic(&snapshot_path, &initial_state)?;
            initial_state
        };
        Ok(Self {
            state,
            admission,
            authenticator,
            clock,
            snapshot_path,
            _writer_lock: writer_lock,
        })
    }

    /// Import one bounded canonical BLK2 payload. State is staged and validated first,
    /// its snapshot is committed second, and the live in-memory state is published last.
    /// Validation or persistence failure therefore leaves the published state unchanged.
    pub fn import_bytes(
        &mut self,
        bytes: &[u8],
        mode: ImportMode,
    ) -> Result<BlockAdmissionReceipt, ChainImportError> {
        if bytes.len() > MAX_ENCODED_BLOCK_BYTES {
            return Err(StateError::Oversize {
                actual: bytes.len(),
                limit: MAX_ENCODED_BLOCK_BYTES,
            }
            .into());
        }
        let block = decode_block(bytes)?;
        let mut staged = self.state.clone();
        let receipt = match mode {
            ImportMode::Live => {
                self.admission
                    .admit_live(&mut staged, &block, &self.authenticator, &self.clock)?
            }
            ImportMode::HistoricalReplay => {
                self.admission
                    .replay_historical(&mut staged, &block, &self.authenticator)?
            }
        };
        snapshot_store::save_atomic(&self.snapshot_path, &staged)?;
        self.state = staged;
        Ok(receipt)
    }

    pub fn state(&self) -> &LedgerState {
        &self.state
    }
    pub fn snapshot_path(&self) -> &Path {
        &self.snapshot_path
    }
}

/// Candidate-only durable state importer for the explicit MBK4/TXN4 monetary profile.
///
/// Unlike the legacy BLK2 importer above, this service persists the monetary issuance counter,
/// network ID, manifest ID, and a fingerprint of the exact supplied Genesis state. It validates
/// a staged state, atomically commits its profile-bound snapshot, and only then publishes memory.
/// This layer does not verify PoW headers, chainwork, or fork choice; callers must validate those
/// first. Its checksum detects accidental corruption, not malicious tampering, and it has no
/// external anti-rollback anchor. The canonical TCP node is not dispatched to this service.
const MCS4_SNAPSHOT_MAGIC: [u8; 4] = *b"MCS4";
const MCS4_SNAPSHOT_VERSION: u16 = 1;
const MCS4_SNAPSHOT_CHECKSUM_DOMAIN: &[u8] = b"AIN1-MCS4-PROFILE-SNAPSHOT-CHECK-V1\0";
const MCS4_GENESIS_FINGERPRINT_DOMAIN: &[u8] = b"AIN1-MCS4-GENESIS-SNAPSHOT-FINGERPRINT-V1\0";
const MCS4_SNAPSHOT_HEADER_LEN: usize = 4 + 2 + 32 + 32 + 32 + 4;
const MCS4_SNAPSHOT_CHECKSUM_LEN: usize = 32;
const MONETARY_SNAPSHOT_INNER_OVERHEAD: usize = 4 + 2 + 32 + 16 + 4 + 32;
const MAX_MCS4_SNAPSHOT_BYTES: usize = MAX_ENCODED_SNAPSHOT_BYTES
    + MONETARY_SNAPSHOT_INNER_OVERHEAD
    + MCS4_SNAPSHOT_HEADER_LEN
    + MCS4_SNAPSHOT_CHECKSUM_LEN;

fn mcs4_snapshot_checksum(payload: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(MCS4_SNAPSHOT_CHECKSUM_DOMAIN);
    hasher.update(payload);
    hasher.finalize().into()
}

fn mcs4_genesis_fingerprint(genesis_snapshot: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(MCS4_GENESIS_FINGERPRINT_DOMAIN);
    hasher.update(genesis_snapshot);
    hasher.finalize().into()
}

fn encode_mcs4_snapshot(
    state: &MonetaryLedgerState,
    expected_manifest_id: &[u8; 32],
    genesis_fingerprint: &[u8; 32],
) -> Result<Vec<u8>, ChainImportError> {
    let network_id = state.ledger().network_id();
    if network_id.iter().all(|byte| *byte == 0)
        || expected_manifest_id.iter().all(|byte| *byte == 0)
    {
        return Err(ChainImportError::InvalidMonetaryProfile);
    }
    let nested = state.encode_snapshot()?;
    let nested_len = u32::try_from(nested.len()).map_err(|_| StateError::Malformed)?;
    let mut bytes =
        Vec::with_capacity(MCS4_SNAPSHOT_HEADER_LEN + nested.len() + MCS4_SNAPSHOT_CHECKSUM_LEN);
    bytes.extend_from_slice(&MCS4_SNAPSHOT_MAGIC);
    bytes.extend_from_slice(&MCS4_SNAPSHOT_VERSION.to_be_bytes());
    bytes.extend_from_slice(&network_id);
    bytes.extend_from_slice(expected_manifest_id);
    bytes.extend_from_slice(genesis_fingerprint);
    bytes.extend_from_slice(&nested_len.to_be_bytes());
    bytes.extend_from_slice(&nested);
    let checksum = mcs4_snapshot_checksum(&bytes);
    bytes.extend_from_slice(&checksum);

    let restored = decode_mcs4_snapshot(
        &bytes,
        &network_id,
        expected_manifest_id,
        genesis_fingerprint,
    )?;
    if restored != *state {
        return Err(StateError::SnapshotNonCanonical.into());
    }
    Ok(bytes)
}

fn decode_mcs4_snapshot(
    bytes: &[u8],
    expected_network_id: &[u8; 32],
    expected_manifest_id: &[u8; 32],
    expected_genesis_fingerprint: &[u8; 32],
) -> Result<MonetaryLedgerState, ChainImportError> {
    if bytes.len() > MAX_MCS4_SNAPSHOT_BYTES {
        return Err(StateError::Oversize {
            actual: bytes.len(),
            limit: MAX_MCS4_SNAPSHOT_BYTES,
        }
        .into());
    }
    if bytes.len() < MCS4_SNAPSHOT_HEADER_LEN + MCS4_SNAPSHOT_CHECKSUM_LEN {
        return Err(StateError::Malformed.into());
    }
    let payload_len = bytes.len() - MCS4_SNAPSHOT_CHECKSUM_LEN;
    let actual_checksum = mcs4_snapshot_checksum(&bytes[..payload_len]);
    if bytes[payload_len..] != actual_checksum[..] {
        return Err(StateError::MonetarySnapshotChecksumMismatch.into());
    }
    if bytes[..4] != MCS4_SNAPSHOT_MAGIC {
        return Err(StateError::BadMagic.into());
    }
    let version = u16::from_be_bytes([bytes[4], bytes[5]]);
    if version != MCS4_SNAPSHOT_VERSION {
        return Err(StateError::UnsupportedVersion(version).into());
    }
    let network_id: [u8; 32] = bytes[6..38].try_into().map_err(|_| StateError::Malformed)?;
    if &network_id != expected_network_id {
        return Err(StateError::SnapshotNetworkMismatch.into());
    }
    let manifest_id: [u8; 32] = bytes[38..70]
        .try_into()
        .map_err(|_| StateError::Malformed)?;
    if &manifest_id != expected_manifest_id {
        return Err(ChainImportError::MonetaryProfileMismatch);
    }
    let genesis_fingerprint: [u8; 32] = bytes[70..102]
        .try_into()
        .map_err(|_| StateError::Malformed)?;
    if &genesis_fingerprint != expected_genesis_fingerprint {
        return Err(ChainImportError::MonetaryGenesisMismatch);
    }
    let nested_len = u32::from_be_bytes(
        bytes[102..106]
            .try_into()
            .map_err(|_| StateError::Malformed)?,
    ) as usize;
    let nested_start = MCS4_SNAPSHOT_HEADER_LEN;
    let nested_end = nested_start
        .checked_add(nested_len)
        .ok_or(StateError::Malformed)?;
    if nested_end != payload_len || nested_len == 0 {
        return Err(StateError::Malformed.into());
    }
    let restored = MonetaryLedgerState::decode_snapshot(
        &bytes[nested_start..nested_end],
        expected_network_id,
    )?;
    if restored.ledger().network_id() != *expected_network_id {
        return Err(StateError::SnapshotNetworkMismatch.into());
    }
    Ok(restored)
}

fn load_mcs4_snapshot(
    path: &Path,
    expected_network_id: &[u8; 32],
    expected_manifest_id: &[u8; 32],
    expected_genesis_fingerprint: &[u8; 32],
) -> Result<MonetaryLedgerState, ChainImportError> {
    let file = File::open(path).map_err(SnapshotStoreError::from)?;
    let length = file.metadata().map_err(SnapshotStoreError::from)?.len();
    if length > MAX_MCS4_SNAPSHOT_BYTES as u64 {
        return Err(StateError::Oversize {
            actual: usize::try_from(length).unwrap_or(usize::MAX),
            limit: MAX_MCS4_SNAPSHOT_BYTES,
        }
        .into());
    }
    let mut bytes = Vec::with_capacity(length as usize);
    file.take(MAX_MCS4_SNAPSHOT_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(SnapshotStoreError::from)?;
    decode_mcs4_snapshot(
        &bytes,
        expected_network_id,
        expected_manifest_id,
        expected_genesis_fingerprint,
    )
}

fn save_mcs4_snapshot(
    path: &Path,
    state: &MonetaryLedgerState,
    expected_manifest_id: &[u8; 32],
    genesis_fingerprint: &[u8; 32],
) -> Result<(), ChainImportError> {
    let bytes = encode_mcs4_snapshot(state, expected_manifest_id, genesis_fingerprint)?;
    snapshot_store::atomic_write_bytes_with_hook(path, &bytes, |_| Ok(()))?;
    Ok(())
}

/// Linear canonical-profile admission plus profile-bound durable recovery for MBK4/TXN4.
///
/// Fork selection remains the responsibility of the selected branch/fork-choice layer. This
/// service only admits the candidate canonical successor; it is deliberately not node-wired.
pub struct V4HybridMonetaryImportService<C, V> {
    state: MonetaryLedgerState,
    admission: ChainAdmissionBoundary,
    verifier: V,
    expected_manifest_id: [u8; 32],
    genesis_fingerprint: [u8; 32],
    clock: C,
    snapshot_path: PathBuf,
    _writer_lock: snapshot_store::SnapshotWriterLock,
}

impl<C, V> V4HybridMonetaryImportService<C, V>
where
    C: ReferenceTimeProvider,
    V: MlDsa65Verifier,
{
    /// Open only if the supplied state, network and manifest form one explicit non-zero profile.
    /// Existing snapshots from a different network or manifest are rejected, never migrated.
    pub fn open(
        initial_state: MonetaryLedgerState,
        admission: ChainAdmissionBoundary,
        expected_manifest_id: [u8; 32],
        verifier: V,
        clock: C,
        snapshot_path: impl AsRef<Path>,
    ) -> Result<Self, ChainImportError> {
        let snapshot_path = snapshot_path.as_ref().to_path_buf();
        let network_id = initial_state.ledger().network_id();
        if network_id.iter().all(|byte| *byte == 0)
            || expected_manifest_id.iter().all(|byte| *byte == 0)
            || initial_state.height() != 0
        {
            return Err(ChainImportError::InvalidMonetaryProfile);
        }
        // The snapshot must remain tied to the exact Genesis allocation/state, not only to
        // caller-supplied network and manifest labels.
        let genesis_snapshot = initial_state.encode_snapshot()?;
        let genesis_fingerprint = mcs4_genesis_fingerprint(&genesis_snapshot);
        let writer_lock = snapshot_store::SnapshotWriterLock::acquire(&snapshot_path)?;
        let state = if snapshot_path.exists() {
            load_mcs4_snapshot(
                &snapshot_path,
                &network_id,
                &expected_manifest_id,
                &genesis_fingerprint,
            )?
        } else {
            save_mcs4_snapshot(
                &snapshot_path,
                &initial_state,
                &expected_manifest_id,
                &genesis_fingerprint,
            )?;
            initial_state
        };
        Ok(Self {
            state,
            admission,
            verifier,
            expected_manifest_id,
            genesis_fingerprint,
            clock,
            snapshot_path,
            _writer_lock: writer_lock,
        })
    }

    /// Decode and apply one MBK4 body after the caller has validated its PoW header and
    /// selected the canonical branch. On rejection or a failed durable write, memory is unchanged.
    /// This method alone is not a complete consensus or anti-rollback decision.
    pub fn import_bytes(
        &mut self,
        bytes: &[u8],
        mode: ImportMode,
    ) -> Result<BlockAdmissionReceipt, ChainImportError> {
        let block: V4HybridMonetaryBlock = decode_v4_hybrid_monetary_block(bytes)?;
        let mut staged = self.state.clone();
        let receipt = match mode {
            ImportMode::Live => self.admission.admit_live_v4_hybrid_monetary(
                &mut staged,
                &block,
                &self.expected_manifest_id,
                &self.verifier,
                &self.clock,
            )?,
            ImportMode::HistoricalReplay => self.admission.replay_v4_hybrid_monetary(
                &mut staged,
                &block,
                &self.expected_manifest_id,
                &self.verifier,
            )?,
        };
        save_mcs4_snapshot(
            &self.snapshot_path,
            &staged,
            &self.expected_manifest_id,
            &self.genesis_fingerprint,
        )?;
        self.state = staged;
        Ok(receipt)
    }

    pub fn state(&self) -> &MonetaryLedgerState {
        &self.state
    }

    pub fn snapshot_path(&self) -> &Path {
        &self.snapshot_path
    }

    pub fn expected_manifest_id(&self) -> &[u8; 32] {
        &self.expected_manifest_id
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        chain_admission::{
            ChainAdmissionConfig, ChainAdmissionError, ReferenceTimeError, ReferenceTimeProvenance,
            ReferenceTimeSample, ReferenceTimeSourcePolicy,
        },
        state_machine::{
            AccountId, Block, MonetaryLedgerState, NetworkId, V4HybridMonetaryBlock,
            MONETARY_PUBLIC_GOODS_BUDGET_ATOMS,
        },
        timestamp_policy::TimestampPolicy,
        v4_fat1_mldsa65_candidate::LibcruxMlDsa65VerifierCandidate,
    };
    use std::{
        fs,
        sync::atomic::{AtomicU64, Ordering},
    };

    const NETWORK: NetworkId = [0xB6; 32];
    static NEXT_DIR: AtomicU64 = AtomicU64::new(1);

    struct NoTransactionsAuthenticator;
    impl TransactionAuthenticator for NoTransactionsAuthenticator {
        fn verify(&self, _: &AccountId, _: &[u8; 32], _: &[u8]) -> Result<(), ()> {
            Err(())
        }
    }

    #[derive(Clone)]
    struct FixedClock(u64, &'static str);
    impl ReferenceTimeProvider for FixedClock {
        fn sample(&self) -> Result<ReferenceTimeSample, ReferenceTimeError> {
            Ok(ReferenceTimeSample {
                unix_seconds: self.0,
                provenance: ReferenceTimeProvenance::ConfiguredProvider,
                source_id: self.1,
            })
        }
    }

    fn dir() -> PathBuf {
        let p = std::env::temp_dir().join(format!(
            "ain1-cp0026h-{}-{}",
            std::process::id(),
            NEXT_DIR.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&p).unwrap();
        p
    }

    fn boundary() -> ChainAdmissionBoundary {
        ChainAdmissionBoundary::testnet()
    }
    fn genesis() -> LedgerState {
        LedgerState::genesis(NETWORK, vec![([0x11; 32], 1_000_000)]).unwrap()
    }

    fn monetary_genesis() -> MonetaryLedgerState {
        MonetaryLedgerState::genesis(
            NETWORK,
            [0x21; 32],
            vec![([0x22; 32], MONETARY_PUBLIC_GOODS_BUDGET_ATOMS as u64)],
        )
        .unwrap()
    }

    fn v4_monetary_candidate(
        state: &MonetaryLedgerState,
        timestamp: u64,
        manifest_id: &[u8; 32],
    ) -> V4HybridMonetaryBlock {
        let verifier = LibcruxMlDsa65VerifierCandidate;
        let mut block = V4HybridMonetaryBlock {
            height: state.height() + 1,
            timestamp,
            parent_hash: state.tip_hash(),
            state_root: [0; 32],
            transactions: Vec::new(),
            miner: [0x33; 32],
            claimed_subsidy_atoms: state.expected_miner_reward().unwrap(),
        };
        block.state_root = state
            .preview_v4_hybrid_state_root_after(&block, manifest_id, &verifier)
            .unwrap();
        block
    }

    fn candidate(state: &LedgerState, timestamp: u64) -> Block {
        let mut block = Block {
            height: state.height() + 1,
            timestamp,
            parent_hash: state.tip_hash(),
            state_root: [0; 32],
            transactions: vec![],
        };
        block.state_root = state
            .preview_state_root_after(&block, &NoTransactionsAuthenticator)
            .unwrap();
        block
    }

    #[test]
    fn mbk4_import_commits_manifest_bound_snapshot_and_reopens_same_state() {
        let dir = dir();
        let path = dir.join("monetary.snapshot");
        let manifest_id = [0xD4; 32];
        let verifier = LibcruxMlDsa65VerifierCandidate;
        let mut service = V4HybridMonetaryImportService::open(
            monetary_genesis(),
            boundary(),
            manifest_id,
            verifier,
            FixedClock(1_000, "shared-ntp"),
            &path,
        )
        .unwrap();

        let block = v4_monetary_candidate(service.state(), 1_120, &manifest_id);
        let bytes = crate::state_machine::encode_v4_hybrid_monetary_block(&block).unwrap();
        let receipt = service.import_bytes(&bytes, ImportMode::Live).unwrap();
        assert_eq!(receipt.summary.height, 1);
        assert_eq!(service.state().height(), 1);
        assert_eq!(service.expected_manifest_id(), &manifest_id);

        let committed_bytes = fs::read(&path).unwrap();
        assert!(committed_bytes.starts_with(&MCS4_SNAPSHOT_MAGIC));
        let expected_state = service.state().clone();
        drop(service);

        let reopened = V4HybridMonetaryImportService::open(
            monetary_genesis(),
            boundary(),
            manifest_id,
            LibcruxMlDsa65VerifierCandidate,
            FixedClock(1_000, "shared-ntp"),
            &path,
        )
        .unwrap();
        assert_eq!(reopened.state(), &expected_state);
        assert_eq!(fs::read(&path).unwrap(), committed_bytes);
        drop(reopened);

        let mismatch = V4HybridMonetaryImportService::open(
            monetary_genesis(),
            boundary(),
            [0xD5; 32],
            LibcruxMlDsa65VerifierCandidate,
            FixedClock(1_000, "shared-ntp"),
            &path,
        );
        assert!(matches!(
            mismatch,
            Err(ChainImportError::MonetaryProfileMismatch)
        ));

        let wrong_genesis = MonetaryLedgerState::genesis(
            NETWORK,
            [0x23; 32],
            vec![([0x24; 32], MONETARY_PUBLIC_GOODS_BUDGET_ATOMS as u64)],
        )
        .unwrap();
        let genesis_mismatch = V4HybridMonetaryImportService::open(
            wrong_genesis,
            boundary(),
            manifest_id,
            LibcruxMlDsa65VerifierCandidate,
            FixedClock(1_000, "shared-ntp"),
            &path,
        );
        assert!(matches!(
            genesis_mismatch,
            Err(ChainImportError::MonetaryGenesisMismatch)
        ));

        let mut corrupted = committed_bytes.clone();
        corrupted[12] ^= 0x80;
        fs::write(&path, corrupted).unwrap();
        let checksum_mismatch = V4HybridMonetaryImportService::open(
            monetary_genesis(),
            boundary(),
            manifest_id,
            LibcruxMlDsa65VerifierCandidate,
            FixedClock(1_000, "shared-ntp"),
            &path,
        );
        assert!(matches!(
            checksum_mismatch,
            Err(ChainImportError::State(
                StateError::MonetarySnapshotChecksumMismatch
            ))
        ));
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn rejected_mbk4_live_import_preserves_memory_and_profile_snapshot() {
        let dir = dir();
        let path = dir.join("monetary.snapshot");
        let manifest_id = [0xD6; 32];
        let mut service = V4HybridMonetaryImportService::open(
            monetary_genesis(),
            boundary(),
            manifest_id,
            LibcruxMlDsa65VerifierCandidate,
            FixedClock(1_000, "shared-ntp"),
            &path,
        )
        .unwrap();
        let before_state = service.state().clone();
        let before_snapshot = fs::read(&path).unwrap();

        // The block has a valid candidate state root, but its timestamp exceeds the configured
        // live future-window by one second, so admission must fail before either commit occurs.
        let block = v4_monetary_candidate(service.state(), 1_121, &manifest_id);
        let bytes = crate::state_machine::encode_v4_hybrid_monetary_block(&block).unwrap();
        assert!(matches!(
            service.import_bytes(&bytes, ImportMode::Live),
            Err(ChainImportError::Admission(_))
        ));
        assert_eq!(service.state(), &before_state);
        assert_eq!(fs::read(&path).unwrap(), before_snapshot);
        drop(service);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn live_import_commits_snapshot_before_publishing_state() {
        let dir = dir();
        let path = dir.join("chain.snapshot");
        let mut service = ChainImportService::open(
            genesis(),
            boundary(),
            NoTransactionsAuthenticator,
            FixedClock(1_000, "shared-ntp"),
            &path,
        )
        .unwrap();
        let block = candidate(service.state(), 1_120);
        let bytes = crate::state_machine::encode_block(&block).unwrap();
        let receipt = service.import_bytes(&bytes, ImportMode::Live).unwrap();
        assert_eq!(receipt.summary.height, 1);
        assert_eq!(receipt.reference_time.unwrap().source_id, "shared-ntp");
        let restored = snapshot_store::load(&path, &NETWORK).unwrap();
        assert_eq!(restored, *service.state());
        assert_eq!(restored.height(), 1);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn rejected_live_import_preserves_memory_and_durable_snapshot() {
        let dir = dir();
        let path = dir.join("chain.snapshot");
        let mut service = ChainImportService::open(
            genesis(),
            boundary(),
            NoTransactionsAuthenticator,
            FixedClock(1_000, "shared-ntp"),
            &path,
        )
        .unwrap();
        let before = fs::read(&path).unwrap();
        let block = candidate(service.state(), 1_121);
        let bytes = crate::state_machine::encode_block(&block).unwrap();
        let error = service.import_bytes(&bytes, ImportMode::Live).unwrap_err();
        assert!(matches!(
            error,
            ChainImportError::Admission(ChainAdmissionError::State(_))
        ));
        assert_eq!(service.state().height(), 0);
        assert_eq!(fs::read(&path).unwrap(), before);
        drop(service);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn reopen_uses_committed_state_and_rejects_old_parent() {
        let dir = dir();
        let path = dir.join("chain.snapshot");
        let mut first = ChainImportService::open(
            genesis(),
            boundary(),
            NoTransactionsAuthenticator,
            FixedClock(1_000, "shared-ntp"),
            &path,
        )
        .unwrap();
        let block1 = candidate(first.state(), 900);
        let bytes = crate::state_machine::encode_block(&block1).unwrap();
        first.import_bytes(&bytes, ImportMode::Live).unwrap();
        drop(first);

        let mut reopened = ChainImportService::open(
            genesis(),
            boundary(),
            NoTransactionsAuthenticator,
            FixedClock(1_000, "shared-ntp"),
            &path,
        )
        .unwrap();
        assert_eq!(reopened.state().height(), 1);
        let stale_block1 = candidate(&genesis(), 901);
        let bytes = crate::state_machine::encode_block(&stale_block1).unwrap();
        assert!(reopened.import_bytes(&bytes, ImportMode::Live).is_err());
        assert_eq!(reopened.state().height(), 1);
        drop(reopened);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn historical_replay_uses_chain_rules_without_current_time_window() {
        let dir = dir();
        let path = dir.join("chain.snapshot");
        let mut service = ChainImportService::open(
            genesis(),
            ChainAdmissionBoundary::new(ChainAdmissionConfig::new(
                TimestampPolicy::new(120),
                ReferenceTimeSourcePolicy::ConfiguredProviderOnly,
            )),
            NoTransactionsAuthenticator,
            FixedClock(100, "shared-ntp"),
            &path,
        )
        .unwrap();
        let block = candidate(service.state(), 10_000);
        let bytes = crate::state_machine::encode_block(&block).unwrap();
        let receipt = service
            .import_bytes(&bytes, ImportMode::HistoricalReplay)
            .unwrap();
        assert_eq!(receipt.reference_time, None);
        assert_eq!(service.state().height(), 1);
        drop(service);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn reference_time_failure_keeps_service_and_snapshot_unchanged() {
        struct BrokenClock;
        impl ReferenceTimeProvider for BrokenClock {
            fn sample(&self) -> Result<ReferenceTimeSample, ReferenceTimeError> {
                Err(ReferenceTimeError::ProviderUnavailable)
            }
        }
        let dir = dir();
        let path = dir.join("chain.snapshot");
        let mut service = ChainImportService::open(
            genesis(),
            boundary(),
            NoTransactionsAuthenticator,
            BrokenClock,
            &path,
        )
        .unwrap();
        let before = fs::read(&path).unwrap();
        let block = candidate(service.state(), 10);
        let bytes = crate::state_machine::encode_block(&block).unwrap();
        assert!(matches!(
            service.import_bytes(&bytes, ImportMode::Live),
            Err(ChainImportError::Admission(
                ChainAdmissionError::ReferenceTimeUnavailable(_)
            ))
        ));
        assert_eq!(service.state().height(), 0);
        assert_eq!(fs::read(&path).unwrap(), before);
        drop(service);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn coordinated_reference_source_detects_near_boundary_clock_skew() {
        let dir_a = dir();
        let dir_b = dir();
        let path_a = dir_a.join("chain.snapshot");
        let path_b = dir_b.join("chain.snapshot");
        let coordinated = ChainAdmissionBoundary::new(ChainAdmissionConfig::new(
            TimestampPolicy::testnet(),
            ReferenceTimeSourcePolicy::RequireConfiguredSourceId("cluster-utc-v1"),
        ));
        let mut node_a = ChainImportService::open(
            genesis(),
            coordinated,
            NoTransactionsAuthenticator,
            FixedClock(1_000, "cluster-utc-v1"),
            &path_a,
        )
        .unwrap();
        let mut node_b = ChainImportService::open(
            genesis(),
            coordinated,
            NoTransactionsAuthenticator,
            FixedClock(999, "cluster-utc-v1"),
            &path_b,
        )
        .unwrap();

        // A timestamp exactly at node A's inclusive future bound is one second
        // beyond node B's bound. This test deliberately proves clock coordination
        // is a real consensus-sensitive operator requirement, not something labels fix.
        let block = candidate(node_a.state(), 1_120);
        let bytes = crate::state_machine::encode_block(&block).unwrap();
        assert!(node_a.import_bytes(&bytes, ImportMode::Live).is_ok());
        assert!(matches!(
            node_b.import_bytes(&bytes, ImportMode::Live),
            Err(ChainImportError::Admission(ChainAdmissionError::State(
                StateError::TimestampTooFarInFuture {
                    latest_allowed: 1_119,
                    actual: 1_120
                }
            )))
        ));
        assert_eq!(node_b.state().height(), 0);
        assert_eq!(snapshot_store::load(&path_b, &NETWORK).unwrap().height(), 0);
        drop(node_a);
        drop(node_b);
        let _ = fs::remove_dir_all(dir_a);
        let _ = fs::remove_dir_all(dir_b);
    }

    #[test]
    fn failed_snapshot_commit_does_not_publish_staged_state() {
        let dir = dir();
        let path = dir.join("chain.snapshot");
        let backup = dir.join("chain.snapshot.committed-backup");
        let mut service = ChainImportService::open(
            genesis(),
            boundary(),
            NoTransactionsAuthenticator,
            FixedClock(1_000, "shared-ntp"),
            &path,
        )
        .unwrap();
        let committed_bytes = fs::read(&path).unwrap();

        // Force the final atomic replacement to fail after the candidate has been
        // validated: preserve the prior snapshot under a sibling name and place a
        // directory at the committed path. The OS must reject file-over-directory replace.
        fs::rename(&path, &backup).unwrap();
        fs::create_dir(&path).unwrap();
        let block = candidate(service.state(), 900);
        let bytes = crate::state_machine::encode_block(&block).unwrap();
        assert!(matches!(
            service.import_bytes(&bytes, ImportMode::Live),
            Err(ChainImportError::Storage(_))
        ));
        assert_eq!(service.state().height(), 0);
        assert_eq!(fs::read(&backup).unwrap(), committed_bytes);
        assert_eq!(snapshot_store::cleanup_orphan_temps(&path).unwrap(), 0);

        drop(service);
        fs::remove_dir(&path).unwrap();
        fs::rename(&backup, &path).unwrap();
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn mismatched_reference_source_id_fails_closed_before_state_change() {
        let dir = dir();
        let path = dir.join("chain.snapshot");
        let boundary = ChainAdmissionBoundary::new(ChainAdmissionConfig::new(
            TimestampPolicy::testnet(),
            ReferenceTimeSourcePolicy::RequireConfiguredSourceId("cluster-utc-v1"),
        ));
        let mut service = ChainImportService::open(
            genesis(),
            boundary,
            NoTransactionsAuthenticator,
            FixedClock(1_000, "node-local-clock"),
            &path,
        )
        .unwrap();
        let block = candidate(service.state(), 1_000);
        let bytes = crate::state_machine::encode_block(&block).unwrap();
        assert!(matches!(
            service.import_bytes(&bytes, ImportMode::Live),
            Err(ChainImportError::Admission(
                ChainAdmissionError::ReferenceTimeSourceMismatch {
                    expected_source_id: "cluster-utc-v1",
                    actual_source_id: "node-local-clock"
                }
            ))
        ));
        assert_eq!(service.state().height(), 0);
        assert_eq!(snapshot_store::load(&path, &NETWORK).unwrap().height(), 0);
        drop(service);
        let _ = fs::remove_dir_all(dir);
    }
}
