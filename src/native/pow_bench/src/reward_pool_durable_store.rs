//! Research-only durable file wrapper for bounded reward-pool snapshots.
//!
//! The final path is the only committed state. Data is validated before filesystem mutation,
//! written to a unique sibling temp file, flushed/synced, then atomically replaced. The shared
//! OS-level writer lock prevents concurrent callers using this store from racing.
//!
//! IMPORTANT: an unkeyed snapshot checksum is not authentication or anti-rollback protection.
//! This module is not the canonical ledger store and is not connected to consensus/Genesis.

use crate::{
    bounded_reward_pools_candidate::{PoolAccounting, PoolError, RewardPoolConfig},
    snapshot_store::{self, CommitStage, SnapshotStoreError, SnapshotWriterLock},
};
use std::{
    fmt,
    fs::File,
    io::{self, Read},
    path::{Path, PathBuf},
};

const MAX_REWARD_POOL_SNAPSHOT_BYTES: u64 = 8 * 1024 * 1024;

#[derive(Debug)]
pub enum RewardPoolStoreError {
    Io(io::Error),
    Pool(PoolError),
    Persistence(SnapshotStoreError),
    InvalidPath,
    TooLarge(u64),
}

impl fmt::Display for RewardPoolStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "reward-pool store I/O failed: {error}"),
            Self::Pool(error) => write!(f, "reward-pool snapshot validation failed: {error}"),
            Self::Persistence(error) => write!(f, "atomic persistence failed: {error}"),
            Self::InvalidPath => write!(f, "reward-pool store path must name a file"),
            Self::TooLarge(size) => write!(f, "reward-pool snapshot exceeds byte limit: {size}"),
        }
    }
}

impl std::error::Error for RewardPoolStoreError {}

impl From<io::Error> for RewardPoolStoreError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<PoolError> for RewardPoolStoreError {
    fn from(value: PoolError) -> Self {
        Self::Pool(value)
    }
}

impl From<SnapshotStoreError> for RewardPoolStoreError {
    fn from(value: SnapshotStoreError) -> Self {
        Self::Persistence(value)
    }
}

/// File-backed snapshot store for the research-only PoolAccounting model.
/// Configuration must be supplied independently and is fingerprint-checked during restore.
#[derive(Debug, Clone)]
pub struct RewardPoolDurableStore {
    path: PathBuf,
    config: RewardPoolConfig,
}

impl RewardPoolDurableStore {
    pub fn new(
        path: impl Into<PathBuf>,
        config: RewardPoolConfig,
    ) -> Result<Self, RewardPoolStoreError> {
        let path = path.into();
        if path.file_name().is_none() {
            return Err(RewardPoolStoreError::InvalidPath);
        }
        // Validate configuration before using this store for reads/writes.
        PoolAccounting::new(config.clone())?;
        Ok(Self { path, config })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Persist a validated model snapshot. A competing process receives WriterLockBusy.
    pub fn save(&self, state: &PoolAccounting) -> Result<(), RewardPoolStoreError> {
        self.save_with_hook(state, |_| Ok(()))
    }

    /// Read only the committed final file. Atomic replacement means an already-open handle
    /// continues to reference either the old complete file or the new complete file.
    pub fn load(&self) -> Result<PoolAccounting, RewardPoolStoreError> {
        let file = File::open(&self.path)?;
        let length = file.metadata()?.len();
        if length > MAX_REWARD_POOL_SNAPSHOT_BYTES {
            return Err(RewardPoolStoreError::TooLarge(length));
        }
        let mut bytes = Vec::with_capacity(length as usize);
        file.take(MAX_REWARD_POOL_SNAPSHOT_BYTES + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() as u64 > MAX_REWARD_POOL_SNAPSHOT_BYTES {
            return Err(RewardPoolStoreError::TooLarge(bytes.len() as u64));
        }
        Ok(PoolAccounting::restore_snapshot(
            self.config.clone(),
            &bytes,
        )?)
    }

    /// Remove only orphan temp files for this destination. Excludes writers while scanning.
    pub fn cleanup_orphan_temps(&self) -> Result<usize, RewardPoolStoreError> {
        let _lock = SnapshotWriterLock::acquire(&self.path)?;
        Ok(snapshot_store::cleanup_orphan_temps(&self.path)?)
    }

    fn save_with_hook<F>(&self, state: &PoolAccounting, hook: F) -> Result<(), RewardPoolStoreError>
    where
        F: FnMut(CommitStage) -> Result<(), SnapshotStoreError>,
    {
        let _lock = SnapshotWriterLock::acquire(&self.path)?;

        // Serialize and restore under the store's independently configured profile before
        // touching the filesystem. This refuses a state object from a different config.
        let bytes = state.snapshot_bytes()?;
        let checked = PoolAccounting::restore_snapshot(self.config.clone(), &bytes)?;
        if checked != *state {
            return Err(PoolError::SnapshotInvariantViolation.into());
        }

        snapshot_store::atomic_write_bytes_with_hook(&self.path, &bytes, hook)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bounded_reward_pools_candidate::{ClaimSignature, RewardClaim, RewardPool};
    use ed25519_dalek::{Signer, SigningKey};
    use std::{
        collections::{BTreeMap, BTreeSet},
        fs,
        process::Command,
        sync::atomic::{AtomicUsize, Ordering},
    };

    const NETWORK: [u8; 32] = [0xC6; 32];
    static TEST_DIR_ID: AtomicUsize = AtomicUsize::new(1);

    struct TestDir(PathBuf);

    impl TestDir {
        fn new(label: &str) -> Self {
            let id = TEST_DIR_ID.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "cpw_reward_pool_store_{label}_{}_{}",
                std::process::id(),
                id
            ));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }

        fn file(&self, name: &str) -> PathBuf {
            self.0.join(name)
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn fixture_config() -> (RewardPoolConfig, [SigningKey; 3]) {
        let keys = [
            SigningKey::from_bytes(&[61; 32]),
            SigningKey::from_bytes(&[62; 32]),
            SigningKey::from_bytes(&[63; 32]),
        ];
        let authorized_signers: BTreeSet<[u8; 32]> = keys
            .iter()
            .map(|key| key.verifying_key().to_bytes())
            .collect();
        let pool_ceilings_atoms: BTreeMap<RewardPool, u128> = [
            (RewardPool::Adoption, 100),
            (RewardPool::DeveloperEcosystem, 100),
            (RewardPool::Security, 50),
            (RewardPool::CommunityInfrastructure, 50),
        ]
        .into_iter()
        .collect();
        (
            RewardPoolConfig {
                network_id: NETWORK,
                maximum_supply_atoms: 1_000,
                initially_issued_atoms: 100,
                miner_budget_atoms: 600,
                pool_ceilings_atoms,
                authorized_signers,
                signature_threshold: 2,
            },
            keys,
        )
    }

    fn model(miner_reward: u128, claim_amount: u128, claim_id: u8) -> PoolAccounting {
        let (config, keys) = fixture_config();
        let mut state = PoolAccounting::new(config).unwrap();
        if miner_reward > 0 {
            state.record_mining_reward(miner_reward).unwrap();
        }
        let mut claim = RewardClaim {
            network_id: NETWORK,
            pool: RewardPool::Adoption,
            amount_atoms: claim_amount,
            recipient: [0x77; 32],
            claim_id: [claim_id; 32],
            valid_from_epoch: 4,
            expires_at_epoch: 12,
            signatures: Vec::new(),
        };
        let message = claim.signing_bytes();
        claim.signatures = keys[..2]
            .iter()
            .map(|key| ClaimSignature {
                signer_public_key: key.verifying_key().to_bytes(),
                signature: key.sign(&message).to_bytes(),
            })
            .collect();
        state.apply_claim(&claim, 6).unwrap();
        state
    }

    fn store(path: &Path) -> RewardPoolDurableStore {
        let (config, _) = fixture_config();
        RewardPoolDurableStore::new(path, config).unwrap()
    }

    #[test]
    fn atomic_first_save_replace_and_load_preserve_exact_snapshot() {
        let dir = TestDir::new("replace");
        let path = dir.file("reward-pool.rps1");
        let store = store(&path);
        let first = model(8, 25, 1);
        let second = model(14, 31, 2);

        store.save(&first).unwrap();
        let first_bytes = fs::read(&path).unwrap();
        assert_eq!(store.load().unwrap(), first);

        store.save(&second).unwrap();
        let second_bytes = fs::read(&path).unwrap();
        assert_ne!(first_bytes, second_bytes);
        assert_eq!(store.load().unwrap(), second);
        assert_eq!(store.cleanup_orphan_temps().unwrap(), 0);
    }

    #[test]
    fn each_precommit_injected_failure_preserves_previous_bytes() {
        let dir = TestDir::new("faults");
        let path = dir.file("reward-pool.rps1");
        let store = store(&path);
        let committed = model(8, 25, 3);
        let candidate = model(12, 29, 4);
        store.save(&committed).unwrap();
        let original = fs::read(&path).unwrap();

        for target in [
            CommitStage::TempCreated,
            CommitStage::PartialWritten,
            CommitStage::FileSynced,
            CommitStage::BeforeReplace,
        ] {
            let result = store.save_with_hook(&candidate, |stage| {
                if stage == target {
                    Err(SnapshotStoreError::InjectedFault(stage.label()))
                } else {
                    Ok(())
                }
            });
            assert!(matches!(
                result,
                Err(RewardPoolStoreError::Persistence(
                    SnapshotStoreError::InjectedFault(_)
                ))
            ));
            assert_eq!(fs::read(&path).unwrap(), original, "fault={target:?}");
            assert_eq!(store.load().unwrap(), committed, "fault={target:?}");
            assert_eq!(store.cleanup_orphan_temps().unwrap(), 0);
        }
    }

    #[test]
    fn postreplace_fault_leaves_new_complete_snapshot_committed() {
        let dir = TestDir::new("postreplace");
        let path = dir.file("reward-pool.rps1");
        let store = store(&path);
        let old = model(8, 25, 5);
        let new = model(16, 33, 6);
        store.save(&old).unwrap();
        let result = store.save_with_hook(&new, |stage| {
            if stage == CommitStage::AfterReplace {
                Err(SnapshotStoreError::InjectedFault(stage.label()))
            } else {
                Ok(())
            }
        });
        assert!(matches!(
            result,
            Err(RewardPoolStoreError::Persistence(
                SnapshotStoreError::InjectedFault("after-replace")
            ))
        ));
        // The caller must reload after an error at this stage: replacement already committed.
        assert_eq!(store.load().unwrap(), new);
    }

    #[test]
    fn writer_lock_excludes_competing_store_writer() {
        let dir = TestDir::new("lock");
        let path = dir.file("reward-pool.rps1");
        let store = store(&path);
        let existing = model(8, 25, 7);
        store.save(&existing).unwrap();
        let old_bytes = fs::read(&path).unwrap();

        let lock = SnapshotWriterLock::acquire(&path).unwrap();
        let result = store.save(&model(10, 26, 8));
        assert!(matches!(
            result,
            Err(RewardPoolStoreError::Persistence(
                SnapshotStoreError::WriterLockBusy(_)
            ))
        ));
        assert_eq!(fs::read(&path).unwrap(), old_bytes);
        drop(lock);
        store.save(&model(10, 26, 8)).unwrap();
    }

    #[test]
    fn load_rejects_corrupt_crossconfig_and_oversized_files() {
        let dir = TestDir::new("bad");
        let path = dir.file("reward-pool.rps1");
        let store = store(&path);
        store.save(&model(8, 25, 9)).unwrap();

        let good = fs::read(&path).unwrap();
        let mut corrupt = good.clone();
        corrupt[10] ^= 1;
        fs::write(&path, corrupt).unwrap();
        assert!(matches!(
            store.load(),
            Err(RewardPoolStoreError::Pool(
                PoolError::SnapshotChecksumMismatch
            ))
        ));

        fs::write(&path, vec![0u8; 8 * 1024 * 1024 + 1]).unwrap();
        assert!(matches!(
            store.load(),
            Err(RewardPoolStoreError::TooLarge(_))
        ));

        let (mut changed_config, _) = fixture_config();
        changed_config.network_id = [0xD7; 32];
        let wrong_store = RewardPoolDurableStore::new(&path, changed_config).unwrap();
        fs::write(&path, good).unwrap();
        assert!(matches!(
            wrong_store.load(),
            Err(RewardPoolStoreError::Pool(
                PoolError::SnapshotConfigMismatch
            ))
        ));
    }

    #[test]
    fn independent_process_writers_leave_only_a_complete_committed_snapshot() {
        const CHILD_ID: &str = "CPW_RP_STORE_RACE_ID";
        const CHILD_PATH: &str = "CPW_RP_STORE_RACE_PATH";
        const CHILD_READY: &str = "CPW_RP_STORE_RACE_READY";
        const CHILD_GO: &str = "CPW_RP_STORE_RACE_GO";

        if let Some(id) = std::env::var_os(CHILD_ID) {
            let id: u8 = id.to_string_lossy().parse().expect("writer id");
            let path = PathBuf::from(std::env::var_os(CHILD_PATH).expect("child path"));
            let ready = PathBuf::from(std::env::var_os(CHILD_READY).expect("ready path"));
            let go = PathBuf::from(std::env::var_os(CHILD_GO).expect("go path"));
            fs::write(ready, b"ready").expect("signal child ready");
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
            while !go.exists() {
                assert!(
                    std::time::Instant::now() < deadline,
                    "race barrier timed out"
                );
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
            let candidate = model(10 + id as u128, 20 + id as u128, 30 + id);
            match store(&path).save(&candidate) {
                Ok(()) => std::process::exit(0),
                Err(RewardPoolStoreError::Persistence(SnapshotStoreError::WriterLockBusy(_))) => {
                    std::process::exit(75)
                }
                Err(error) => panic!("unexpected independent writer error: {error}"),
            }
        }

        let dir = TestDir::new("multi-writer");
        let path = dir.file("reward-pool.rps1");
        let store = store(&path);
        let baseline = model(8, 25, 29);
        store.save(&baseline).unwrap();
        let go = dir.file("go");
        let executable = std::env::current_exe().unwrap();
        let mut children = Vec::new();
        let mut ready_files = Vec::new();

        for id in 1u8..=4 {
            let ready = dir.file(&format!("ready-{id}"));
            let child = Command::new(&executable)
                .arg("--exact")
                .arg("reward_pool_durable_store::tests::independent_process_writers_leave_only_a_complete_committed_snapshot")
                .arg("--nocapture")
                .env(CHILD_ID, id.to_string())
                .env(CHILD_PATH, &path)
                .env(CHILD_READY, &ready)
                .env(CHILD_GO, &go)
                .spawn()
                .expect("spawn independent writer process");
            children.push(child);
            ready_files.push(ready);
        }

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while ready_files.iter().any(|ready| !ready.exists()) {
            assert!(
                std::time::Instant::now() < deadline,
                "writer readiness timed out"
            );
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        fs::write(&go, b"go").unwrap();

        let mut committed_writers = 0usize;
        for child in &mut children {
            let status = child.wait().expect("wait for writer process");
            match status.code() {
                Some(0) => committed_writers += 1,
                Some(75) => {}
                other => panic!("unexpected writer exit status: {other:?}"),
            }
        }
        assert!(committed_writers >= 1, "at least one writer must commit");

        let restored = store.load().expect("final snapshot remains valid");
        let restored_bytes = fs::read(&path).unwrap();
        let is_known_complete_state = (1u8..=4).any(|id| {
            let candidate = model(10 + id as u128, 20 + id as u128, 30 + id);
            candidate == restored && candidate.snapshot_bytes().unwrap() == restored_bytes
        });
        assert!(
            is_known_complete_state,
            "final file must match one complete writer snapshot"
        );
        assert_eq!(store.cleanup_orphan_temps().unwrap(), 0);
    }

    #[test]
    fn real_child_termination_at_commit_boundaries_recovers_old_or_new_complete_state() {
        const CHILD_MODE: &str = "CPW_RP_STORE_HARD_EXIT_STAGE";
        const CHILD_PATH: &str = "CPW_RP_STORE_HARD_EXIT_PATH";

        if let Some(stage_name) = std::env::var_os(CHILD_MODE) {
            let stage_name = stage_name.to_string_lossy();
            let path = PathBuf::from(std::env::var_os(CHILD_PATH).expect("child path"));
            let target = match stage_name.as_ref() {
                "temp-created" => CommitStage::TempCreated,
                "partial-written" => CommitStage::PartialWritten,
                "file-synced" => CommitStage::FileSynced,
                "before-replace" => CommitStage::BeforeReplace,
                "after-replace" => CommitStage::AfterReplace,
                other => panic!("unknown child crash stage: {other}"),
            };
            let result = store(&path).save_with_hook(&model(19, 37, 12), |stage| {
                if stage == target {
                    // Bypass Rust destructors to model abrupt process termination. The OS
                    // closes handles; this does not simulate kernel crash or power loss.
                    std::process::exit(73);
                }
                Ok(())
            });
            panic!("child save unexpectedly returned: {result:?}");
        }

        let dir = TestDir::new("hard-exit");
        let path = dir.file("reward-pool.rps1");
        let store = store(&path);
        let old_state = model(8, 25, 13);
        let new_state = model(19, 37, 12);
        store.save(&old_state).unwrap();
        let old_bytes = fs::read(&path).unwrap();
        let new_bytes = new_state.snapshot_bytes().unwrap();
        let executable = std::env::current_exe().unwrap();

        for stage in [
            "temp-created",
            "partial-written",
            "file-synced",
            "before-replace",
            "after-replace",
        ] {
            // Reset a known committed old state before each independent crash trial.
            fs::write(&path, &old_bytes).unwrap();
            let status = Command::new(&executable)
                .arg("--exact")
                .arg("reward_pool_durable_store::tests::real_child_termination_at_commit_boundaries_recovers_old_or_new_complete_state")
                .arg("--nocapture")
                .env(CHILD_MODE, stage)
                .env(CHILD_PATH, &path)
                .status()
                .expect("spawn crash-injection child");
            assert_eq!(status.code(), Some(73), "stage={stage}");

            let actual = fs::read(&path).unwrap();
            if stage == "after-replace" {
                assert_eq!(actual, new_bytes, "stage={stage}");
                assert_eq!(store.load().unwrap(), new_state, "stage={stage}");
            } else {
                assert_eq!(actual, old_bytes, "stage={stage}");
                assert_eq!(store.load().unwrap(), old_state, "stage={stage}");
            }

            // Abrupt exit can leave a sibling temp file; recovery only removes that orphan
            // and must not alter the committed destination.
            let removed = store.cleanup_orphan_temps().unwrap();
            if stage == "after-replace" {
                assert_eq!(removed, 0, "stage={stage}");
            } else {
                assert_eq!(removed, 1, "stage={stage}");
            }
            assert_eq!(
                store.load().unwrap(),
                if stage == "after-replace" {
                    new_state.clone()
                } else {
                    old_state.clone()
                }
            );
        }
    }

    #[test]
    fn separate_process_reopens_committed_reward_pool_snapshot() {
        if std::env::var_os("CPW_RP_STORE_SOURCE").is_some() {
            let source = std::env::var("CPW_RP_STORE_SOURCE").unwrap();
            let output = std::env::var("CPW_RP_STORE_OUTPUT").unwrap();
            let store = store(Path::new(&source));
            let state = store.load().expect("child loads committed snapshot");
            fs::write(output, state.snapshot_bytes().unwrap())
                .expect("child emits canonical restored snapshot");
            return;
        }

        let dir = TestDir::new("child");
        let path = dir.file("reward-pool.rps1");
        let output = dir.file("restored.rps1");
        let expected = model(11, 27, 10);
        store(&path).save(&expected).unwrap();
        let expected_bytes = fs::read(&path).unwrap();
        let executable = std::env::current_exe().unwrap();
        let status = Command::new(executable)
            .arg("--exact")
            .arg("reward_pool_durable_store::tests::separate_process_reopens_committed_reward_pool_snapshot")
            .arg("--nocapture")
            .env("CPW_RP_STORE_SOURCE", &path)
            .env("CPW_RP_STORE_OUTPUT", &output)
            .status()
            .expect("spawn child test process");
        assert!(status.success());
        assert_eq!(fs::read(output).unwrap(), expected_bytes);
    }

    #[test]
    fn cleanup_removes_only_orphan_temps_for_target_file() {
        let dir = TestDir::new("cleanup");
        let path = dir.file("reward-pool.rps1");
        let store = store(&path);
        let state = model(8, 25, 11);
        store.save(&state).unwrap();
        let committed = fs::read(&path).unwrap();

        let orphan = dir.file(".reward-pool.rps1.cp0026e.4242.99.tmp");
        let unrelated = dir.file(".unrelated.cp0026e.4242.99.tmp");
        fs::write(&orphan, b"partial").unwrap();
        fs::write(&unrelated, b"keep").unwrap();
        assert_eq!(store.cleanup_orphan_temps().unwrap(), 1);
        assert!(!orphan.exists());
        assert!(unrelated.exists());
        assert_eq!(fs::read(&path).unwrap(), committed);
        assert_eq!(store.load().unwrap(), state);
    }
}
