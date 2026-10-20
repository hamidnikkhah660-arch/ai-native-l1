//! Candidate durable store for ASV1 asset-state snapshots.
//!
//! This mirrors the repository's established snapshot-store safety pattern, but operates
//! on AssetStateCandidate bytes. It is pre-activation and deliberately does not replace
//! the canonical LedgerState snapshot path.

use crate::asset_state_candidate::{AssetStateCandidate, AssetStateCandidateError};
use std::{
    ffi::OsString,
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(1);
const TEMP_MARKER: &str = ".cpw-asv1.";
const TEMP_SUFFIX: &str = ".tmp";
const MAX_STORED_ASSET_STATE_BYTES: usize = 8 * 1024 * 1024;

#[derive(Debug)]
pub enum AssetStateStoreError {
    Io(io::Error),
    State(AssetStateCandidateError),
    InvalidPath,
    InjectedFault(&'static str),
}

impl std::fmt::Display for AssetStateStoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(f, "asset-state store I/O failed: {error}"),
            Self::State(error) => write!(f, "asset-state validation failed: {error}"),
            Self::InvalidPath => write!(f, "asset-state path must name a file"),
            Self::InjectedFault(stage) => write!(f, "injected asset-state fault at {stage}"),
        }
    }
}

impl std::error::Error for AssetStateStoreError {}

impl From<io::Error> for AssetStateStoreError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<AssetStateCandidateError> for AssetStateStoreError {
    fn from(value: AssetStateCandidateError) -> Self {
        Self::State(value)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CommitStage {
    TempCreated,
    PartialWritten,
    FileSynced,
    BeforeReplace,
    AfterReplace,
}

impl CommitStage {
    fn label(self) -> &'static str {
        match self {
            Self::TempCreated => "temp-created",
            Self::PartialWritten => "partial-written",
            Self::FileSynced => "file-synced",
            Self::BeforeReplace => "before-replace",
            Self::AfterReplace => "after-replace",
        }
    }
}

struct TempCleanup {
    path: PathBuf,
    armed: bool,
}

impl TempCleanup {
    fn unarmed(path: PathBuf) -> Self {
        Self { path, armed: false }
    }
}

impl Drop for TempCleanup {
    fn drop(&mut self) {
        if self.armed {
            let _ = fs::remove_file(&self.path);
        }
    }
}

pub fn save_atomic(path: &Path, state: &AssetStateCandidate) -> Result<(), AssetStateStoreError> {
    save_atomic_with_hook(path, state, |_| Ok(()))
}

pub fn load(
    path: &Path,
    expected_network_id: &[u8; 32],
) -> Result<AssetStateCandidate, AssetStateStoreError> {
    let file = File::open(path)?;
    let length = file.metadata()?.len();
    if length > MAX_STORED_ASSET_STATE_BYTES as u64 {
        return Err(AssetStateStoreError::State(
            AssetStateCandidateError::SnapshotOversize {
                actual: usize::try_from(length).unwrap_or(usize::MAX),
                limit: MAX_STORED_ASSET_STATE_BYTES,
            },
        ));
    }
    let mut bytes = Vec::with_capacity(length as usize);
    file.take((MAX_STORED_ASSET_STATE_BYTES as u64) + 1)
        .read_to_end(&mut bytes)?;
    AssetStateCandidate::decode_snapshot(&bytes, expected_network_id).map_err(Into::into)
}

pub fn cleanup_orphan_temps(path: &Path) -> Result<usize, AssetStateStoreError> {
    let file_name = path.file_name().ok_or(AssetStateStoreError::InvalidPath)?;
    let parent = parent_directory(path);
    let prefix = format!(".{}{}", file_name.to_string_lossy(), TEMP_MARKER);
    let mut removed = 0usize;

    for entry in fs::read_dir(parent)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.starts_with(&prefix) && name.ends_with(TEMP_SUFFIX) && entry.file_type()?.is_file()
        {
            fs::remove_file(entry.path())?;
            removed += 1;
        }
    }
    Ok(removed)
}

fn save_atomic_with_hook<F>(
    path: &Path,
    state: &AssetStateCandidate,
    mut hook: F,
) -> Result<(), AssetStateStoreError>
where
    F: FnMut(CommitStage) -> Result<(), AssetStateStoreError>,
{
    let bytes = state.encode_snapshot()?;
    let decoded = AssetStateCandidate::decode_snapshot(&bytes, &state.network_id())?;
    if decoded != *state {
        return Err(AssetStateStoreError::State(
            AssetStateCandidateError::SnapshotNonCanonical,
        ));
    }

    let parent = parent_directory(path);
    if !parent.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "asset-state parent directory does not exist",
        )
        .into());
    }

    let final_name = path.file_name().ok_or(AssetStateStoreError::InvalidPath)?;
    let temp_path = unique_temp_path(parent, final_name);
    let mut cleanup = TempCleanup::unarmed(temp_path.clone());
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temp_path)?;
    cleanup.armed = true;

    hook(CommitStage::TempCreated)?;

    let midpoint = (bytes.len() / 2).max(1);
    file.write_all(&bytes[..midpoint])?;
    file.flush()?;
    hook(CommitStage::PartialWritten)?;

    file.write_all(&bytes[midpoint..])?;
    file.flush()?;
    file.sync_all()?;
    hook(CommitStage::FileSynced)?;

    hook(CommitStage::BeforeReplace)?;
    drop(file);

    atomic_replace(&temp_path, path)?;
    hook(CommitStage::AfterReplace)?;

    drop(cleanup);
    Ok(())
}

fn parent_directory(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

fn unique_temp_path(parent: &Path, final_name: &std::ffi::OsStr) -> PathBuf {
    let sequence = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
    let mut name = OsString::from(".");
    name.push(final_name);
    name.push(format!(
        "{TEMP_MARKER}{}.{}{TEMP_SUFFIX}",
        std::process::id(),
        sequence
    ));
    parent.join(name)
}

#[cfg(windows)]
fn atomic_replace(source: &Path, destination: &Path) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt;

    const MOVEFILE_REPLACE_EXISTING: u32 = 0x1;
    const MOVEFILE_WRITE_THROUGH: u32 = 0x8;

    let source_wide: Vec<u16> = source
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let destination_wide: Vec<u16> = destination
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    #[link(name = "Kernel32")]
    extern "system" {
        fn MoveFileExW(existing: *const u16, new_name: *const u16, flags: u32) -> i32;
    }

    let success = unsafe {
        MoveFileExW(
            source_wide.as_ptr(),
            destination_wide.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if success == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(not(windows))]
fn atomic_replace(source: &Path, destination: &Path) -> io::Result<()> {
    fs::rename(source, destination)?;
    #[cfg(unix)]
    File::open(parent_directory(destination))?.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        asset_state_candidate::CandidateResourceLimits,
        asset_transactions::AssetOperation,
        token_forge::{
            asset_id, AccountId, AssetDefinition, BurnAuthority, FreezePolicy, MintAuthority,
            SupplyPolicy,
        },
    };
    use std::{
        process::{Child, Command},
        sync::atomic::AtomicUsize,
        thread,
        time::{Duration, Instant},
    };

    static TEST_DIR_ID: AtomicUsize = AtomicUsize::new(1);
    const NETWORK: [u8; 32] = [0xD1; 32];
    const ALICE: AccountId = [0x11; 32];
    const BOB: AccountId = [0x22; 32];

    struct TestDir(PathBuf);

    impl TestDir {
        fn new(label: &str) -> Self {
            let id = TEST_DIR_ID.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "cpw_asv1_store_{label}_{}_{}",
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

    fn limits() -> CandidateResourceLimits {
        CandidateResourceLimits {
            max_operations: 16,
            max_operation_bytes: 4096,
            max_assets: 8,
            max_holdings: 16,
        }
    }

    fn definition(creator: AccountId, nonce: u64, symbol: &str) -> AssetDefinition {
        AssetDefinition {
            network_id: NETWORK,
            creator,
            creation_nonce: nonce,
            name: format!("Store Asset {nonce}"),
            symbol: symbol.to_owned(),
            decimals: 8,
            metadata_hash: [0x55; 32],
            supply_policy: SupplyPolicy::Capped {
                initial_supply: 1_000,
                max_supply: 5_000,
            },
            mint_authority: MintAuthority::Creator,
            burn_authority: BurnAuthority::Holder,
            freeze_policy: FreezePolicy::Creator,
        }
    }

    fn state(height: u64, nonce: u64, recipient: Option<AccountId>) -> AssetStateCandidate {
        let mut state = AssetStateCandidate::genesis(NETWORK).unwrap();
        state.advance_height(height).unwrap();
        let create = AssetOperation::Create {
            definition: definition(ALICE, nonce, "STO"),
        };
        state.apply_operation(&ALICE, &create, limits()).unwrap();
        if let Some(recipient) = recipient {
            let id = if let AssetOperation::Create { ref definition } = create {
                asset_id(definition).unwrap()
            } else {
                unreachable!()
            };
            state
                .apply_operation(
                    &ALICE,
                    &AssetOperation::Transfer {
                        asset_id: id,
                        recipient,
                        amount: 123,
                    },
                    limits(),
                )
                .unwrap();
        }
        state
    }

    #[test]
    fn atomic_save_load_is_exact_and_replaces_complete_snapshot() {
        let dir = TestDir::new("replace");
        let path = dir.file("asset.asv1");
        let first = state(1, 1, None);
        let second = state(2, 2, Some(BOB));

        save_atomic(&path, &first).unwrap();
        assert_eq!(load(&path, &NETWORK).unwrap(), first);
        let first_bytes = fs::read(&path).unwrap();

        save_atomic(&path, &second).unwrap();
        let second_bytes = fs::read(&path).unwrap();
        assert_ne!(first_bytes, second_bytes);
        assert_eq!(load(&path, &NETWORK).unwrap(), second);
        assert_eq!(cleanup_orphan_temps(&path).unwrap(), 0);
    }

    #[test]
    fn precommit_faults_preserve_previous_snapshot_and_remove_temp() {
        let dir = TestDir::new("faults");
        let path = dir.file("asset.asv1");
        let committed = state(10, 10, Some(BOB));
        let candidate = state(11, 11, None);
        save_atomic(&path, &committed).unwrap();
        let committed_bytes = fs::read(&path).unwrap();

        for target in [
            CommitStage::TempCreated,
            CommitStage::PartialWritten,
            CommitStage::FileSynced,
            CommitStage::BeforeReplace,
        ] {
            let result = save_atomic_with_hook(&path, &candidate, |stage| {
                if stage == target {
                    Err(AssetStateStoreError::InjectedFault(stage.label()))
                } else {
                    Ok(())
                }
            });
            assert!(matches!(
                result,
                Err(AssetStateStoreError::InjectedFault(_))
            ));
            assert_eq!(fs::read(&path).unwrap(), committed_bytes);
            assert_eq!(load(&path, &NETWORK).unwrap(), committed);
            assert_eq!(cleanup_orphan_temps(&path).unwrap(), 0);
        }
    }

    #[test]
    fn postreplace_fault_leaves_a_new_complete_snapshot() {
        let dir = TestDir::new("postreplace");
        let path = dir.file("asset.asv1");
        let old = state(10, 10, None);
        let new = state(11, 11, Some(BOB));
        save_atomic(&path, &old).unwrap();

        let result = save_atomic_with_hook(&path, &new, |stage| {
            if stage == CommitStage::AfterReplace {
                Err(AssetStateStoreError::InjectedFault(stage.label()))
            } else {
                Ok(())
            }
        });
        assert!(matches!(
            result,
            Err(AssetStateStoreError::InjectedFault("after-replace"))
        ));
        assert_eq!(load(&path, &NETWORK).unwrap(), new);
        assert_eq!(cleanup_orphan_temps(&path).unwrap(), 0);
    }

    #[test]
    fn orphan_cleanup_never_selects_uncommitted_temp_as_state() {
        let dir = TestDir::new("orphan");
        let path = dir.file("asset.asv1");
        let committed = state(7, 7, None);
        save_atomic(&path, &committed).unwrap();
        let unrelated = dir.file(".other.cpw-asv1.1.1.tmp");
        let orphan = dir.file(".asset.asv1.cpw-asv1.222.3.tmp");
        fs::write(&orphan, b"partial").unwrap();
        fs::write(&unrelated, b"keep").unwrap();

        assert_eq!(load(&path, &NETWORK).unwrap(), committed);
        assert_eq!(cleanup_orphan_temps(&path).unwrap(), 1);
        assert!(!orphan.exists());
        assert_eq!(fs::read(unrelated).unwrap(), b"keep");
    }

    fn wait_for_marker(path: &Path, child: &mut Child) {
        let deadline = Instant::now() + Duration::from_secs(3);
        while Instant::now() < deadline {
            if path.exists() {
                return;
            }
            if let Ok(Some(status)) = child.try_wait() {
                panic!("crash-window child exited early: {status:?}");
            }
            thread::sleep(Duration::from_millis(10));
        }
        panic!("timed out waiting for crash-window marker");
    }

    #[test]
    fn actual_child_process_kill_before_replace_preserves_committed_snapshot() {
        let Ok(input_path) = std::env::var("CPW_ASSET_STATE_STORE_CRASH_INPUT") else {
            return;
        };
        let output_path =
            std::env::var("CPW_ASSET_STATE_STORE_CRASH_OUTPUT").expect("crash-window output path");
        let marker_path =
            std::env::var("CPW_ASSET_STATE_STORE_CRASH_MARKER").expect("crash-window marker path");

        let input = fs::read(&input_path).expect("read committed snapshot");
        let mut base = AssetStateCandidate::decode_snapshot(&input, &NETWORK).unwrap();
        let amount: u128 = std::env::var("CPW_ASSET_STATE_STORE_CRASH_AMOUNT")
            .unwrap_or_else(|_| "17".to_owned())
            .parse()
            .expect("crash-window amount");
        let definition = definition(ALICE, 12, "STO");
        let asset_id = asset_id(&definition).unwrap();
        base.advance_height(base.height() + 1)
            .expect("advance crash-window height");
        let candidate = {
            let operation = AssetOperation::Transfer {
                asset_id,
                recipient: BOB,
                amount,
            };
            base.apply_operation(&ALICE, &operation, limits())
                .expect("prepare crash-window candidate");
            base
        };

        let result = save_atomic_with_hook(Path::new(&output_path), &candidate, |stage| {
            if stage == CommitStage::PartialWritten {
                fs::write(&marker_path, b"partial-written").expect("write crash marker");
                thread::sleep(Duration::from_secs(30));
            }
            Ok(())
        });
        panic!("crash-window child unexpectedly returned: {result:?}");
    }

    #[test]
    fn separate_child_kill_before_replace_keeps_old_snapshot_and_cleans_orphan() {
        let dir = TestDir::new("child-kill");
        let path = dir.file("asset.asv1");
        let marker = dir.file("marker");
        let child_output = dir.file("asset-child.asv1");
        let committed = state(12, 12, Some(BOB));
        save_atomic(&path, &committed).unwrap();
        let committed_bytes = fs::read(&path).unwrap();

        let exe = std::env::current_exe().unwrap();
        let mut child = Command::new(exe)
            .arg("--exact")
            .arg("asset_state_candidate_store::tests::actual_child_process_kill_before_replace_preserves_committed_snapshot")
            .arg("--nocapture")
            .env("CPW_ASSET_STATE_STORE_CRASH_INPUT", &path)
            .env("CPW_ASSET_STATE_STORE_CRASH_OUTPUT", &child_output)
            .env("CPW_ASSET_STATE_STORE_CRASH_MARKER", &marker)
            .spawn()
            .expect("spawn crash-window child");

        wait_for_marker(&marker, &mut child);
        let _ = child.kill();
        let status = child.wait().expect("wait for killed child");
        assert!(!status.success());

        assert_eq!(fs::read(&path).unwrap(), committed_bytes);
        assert_eq!(load(&path, &NETWORK).unwrap(), committed);
        assert_eq!(cleanup_orphan_temps(&child_output).unwrap(), 1);
        assert!(!child_output.exists());
    }

    #[test]
    fn repeated_child_crash_cycles_preserve_commit_and_recovery_across_generations() {
        let dir = TestDir::new("repeated-crash");
        let path = dir.file("asset.asv1");
        let definition = definition(ALICE, 12, "STO");
        let asset_id = asset_id(&definition).unwrap();

        let mut committed = state(20, 12, None);
        save_atomic(&path, &committed).unwrap();
        let exe = std::env::current_exe().unwrap();

        for (round, amount) in [7u128, 11, 13, 17, 19].into_iter().enumerate() {
            let marker = dir.file(&format!("marker-{round}"));
            let child_output = dir.file(&format!("asset-child-{round}.asv1"));
            let _ = fs::remove_file(&marker);
            let _ = fs::remove_file(&child_output);
            let before_bytes = fs::read(&path).unwrap();
            let before = load(&path, &NETWORK).unwrap();
            assert_eq!(before, committed);

            let mut child = Command::new(&exe)
                .arg("--exact")
                .arg("asset_state_candidate_store::tests::actual_child_process_kill_before_replace_preserves_committed_snapshot")
                .arg("--nocapture")
                .env("CPW_ASSET_STATE_STORE_CRASH_INPUT", &path)
                .env("CPW_ASSET_STATE_STORE_CRASH_OUTPUT", &child_output)
                .env("CPW_ASSET_STATE_STORE_CRASH_MARKER", &marker)
                .env("CPW_ASSET_STATE_STORE_CRASH_AMOUNT", amount.to_string())
                .spawn()
                .expect("spawn repeated crash-window child");

            wait_for_marker(&marker, &mut child);
            let _ = child.kill();
            let status = child.wait().expect("wait for repeated crash-window child");
            assert!(!status.success());

            assert_eq!(fs::read(&path).unwrap(), before_bytes);
            assert_eq!(load(&path, &NETWORK).unwrap(), before);
            assert_eq!(cleanup_orphan_temps(&child_output).unwrap(), 1);
            assert!(!child_output.exists());

            let mut recovered = before.clone();
            recovered
                .advance_height(before.height() + 1)
                .expect("advance recovered state height");
            recovered
                .apply_operation(
                    &ALICE,
                    &AssetOperation::Transfer {
                        asset_id,
                        recipient: BOB,
                        amount,
                    },
                    limits(),
                )
                .expect("apply recovered operation");

            save_atomic(&path, &recovered).unwrap();
            assert_eq!(load(&path, &NETWORK).unwrap(), recovered);
            assert_eq!(
                recovered.balance(&asset_id, &BOB),
                committed.balance(&asset_id, &BOB) + amount
            );
            recovered.verify_invariants().unwrap();
            committed = recovered;
        }
    }
}
