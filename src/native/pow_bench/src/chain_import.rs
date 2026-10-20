//! Durable block-import facade for CP-0026-H.
//!
//! All live and replay imports pass through one service. It stages state in memory,
//! validates it through ChainAdmissionBoundary, commits the canonical snapshot, and
//! only then publishes the new in-memory state. Research/testbed integration only.

use crate::{
    chain_admission::{
        BlockAdmissionReceipt, ChainAdmissionBoundary, ChainAdmissionError, ReferenceTimeProvider,
    },
    snapshot_store::{self, SnapshotStoreError},
    state_machine::{
        decode_block, LedgerState, StateError, TransactionAuthenticator, MAX_ENCODED_BLOCK_BYTES,
    },
};
use std::{
    fmt,
    path::{Path, PathBuf},
};

#[derive(Debug)]
pub enum ChainImportError {
    State(StateError),
    Admission(ChainAdmissionError),
    Storage(SnapshotStoreError),
}

impl fmt::Display for ChainImportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::State(error) => write!(f, "block decode failed: {error:?}"),
            Self::Admission(error) => write!(f, "block admission rejected: {error:?}"),
            Self::Storage(error) => write!(f, "durable snapshot commit failed: {error}"),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        chain_admission::{
            ChainAdmissionConfig, ChainAdmissionError, ReferenceTimeError, ReferenceTimeProvenance,
            ReferenceTimeSample, ReferenceTimeSourcePolicy,
        },
        state_machine::{AccountId, Block, NetworkId},
        timestamp_policy::TimestampPolicy,
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
