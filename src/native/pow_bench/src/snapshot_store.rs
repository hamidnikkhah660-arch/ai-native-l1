//! Crash-aware canonical snapshot file storage for the CP-0026-E research gate.
//!
//! The final path is the only committed snapshot. A new snapshot is written and synced
//! to a unique sibling temporary file and then atomically renamed over the final path.
//! Startup recovery must read only the final path; orphan temporary files are never
//! treated as committed state. Snapshot checksums detect corruption, not forgery.

use crate::state_machine::{LedgerState, NetworkId, StateError, MAX_ENCODED_SNAPSHOT_BYTES};
use std::{
    ffi::OsString,
    fmt,
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(1);
const FILE_IDENTITY_LOCK_OFFSET: u64 = 0x7fff_ffff_0000_0000;
const TEMP_MARKER: &str = ".cp0026e.";
const TEMP_SUFFIX: &str = ".tmp";

#[derive(Debug)]
pub enum SnapshotStoreError {
    Io(io::Error),
    State(StateError),
    InvalidPath,
    WriterLockBusy(PathBuf),
    InjectedFault(&'static str),
}

impl fmt::Display for SnapshotStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "snapshot file I/O failed: {error}"),
            Self::State(error) => write!(f, "snapshot validation failed: {error:?}"),
            Self::InvalidPath => write!(f, "snapshot path must name a file"),
            Self::WriterLockBusy(path) => write!(
                f,
                "snapshot writer lock is already held: {}",
                path.display()
            ),
            Self::InjectedFault(stage) => write!(f, "injected snapshot-store fault at {stage}"),
        }
    }
}

impl std::error::Error for SnapshotStoreError {}

impl From<io::Error> for SnapshotStoreError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<StateError> for SnapshotStoreError {
    fn from(value: StateError) -> Self {
        Self::State(value)
    }
}

/// Persist one canonical snapshot with a sibling temp file, sync, and atomic replacement.
/// This function returns only after the OS replace/write-through operation succeeds.
/// On Unix it additionally syncs the containing directory. If that final directory sync
/// fails, the destination may already contain the new snapshot; reload it before retrying.
pub(crate) fn save_atomic(path: &Path, state: &LedgerState) -> Result<(), SnapshotStoreError> {
    save_atomic_with_hook(path, state, |_| Ok(()))
}

/// Recover only the committed final path. Temp or backup files are never considered
/// fallback state because their commit status cannot be established after interruption.
pub fn load(
    path: &Path,
    expected_network_id: &NetworkId,
) -> Result<LedgerState, SnapshotStoreError> {
    let file = File::open(path)?;
    let length = file.metadata()?.len();
    if length > MAX_ENCODED_SNAPSHOT_BYTES as u64 {
        return Err(StateError::Oversize {
            actual: usize::try_from(length).unwrap_or(usize::MAX),
            limit: MAX_ENCODED_SNAPSHOT_BYTES,
        }
        .into());
    }
    let mut bytes = Vec::with_capacity(length as usize);
    file.take((MAX_ENCODED_SNAPSHOT_BYTES as u64) + 1)
        .read_to_end(&mut bytes)?;
    LedgerState::decode_snapshot(&bytes, expected_network_id).map_err(Into::into)
}

/// Remove orphan temp files for this destination. Call only during startup/recovery after
/// excluding concurrent writers; otherwise a live writer's uncommitted temp could be removed.
/// This never deletes or chooses the committed final path or unrelated files.
pub fn cleanup_orphan_temps(path: &Path) -> Result<usize, SnapshotStoreError> {
    let file_name = path.file_name().ok_or(SnapshotStoreError::InvalidPath)?;
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CommitStage {
    TempCreated,
    PartialWritten,
    FileSynced,
    BeforeReplace,
    AfterReplace,
}

impl CommitStage {
    #[cfg(test)]
    pub(crate) fn label(self) -> &'static str {
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

fn save_atomic_with_hook<F>(
    path: &Path,
    state: &LedgerState,
    hook: F,
) -> Result<(), SnapshotStoreError>
where
    F: FnMut(CommitStage) -> Result<(), SnapshotStoreError>,
{
    let bytes = state.encode_snapshot()?;
    // Verify the exact bytes before any filesystem mutation.
    let decoded = LedgerState::decode_snapshot(&bytes, &state.network_id())?;
    if decoded != *state {
        return Err(SnapshotStoreError::State(StateError::SnapshotNonCanonical));
    }
    atomic_write_bytes_with_hook(path, &bytes, hook)
}

/// Shared byte-level primitive for isolated research stores. Callers must validate and
/// canonicalize payload bytes before invoking this helper.
pub(crate) fn atomic_write_bytes_with_hook<F>(
    path: &Path,
    bytes: &[u8],
    mut hook: F,
) -> Result<(), SnapshotStoreError>
where
    F: FnMut(CommitStage) -> Result<(), SnapshotStoreError>,
{
    let parent = parent_directory(path);
    if !parent.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "snapshot parent directory does not exist",
        )
        .into());
    }
    let final_name = path.file_name().ok_or(SnapshotStoreError::InvalidPath)?;
    let temp_path = unique_temp_path(parent, final_name);
    // Keep the guard declared before the file (so the file closes before cleanup on
    // early return), but arm it only after create_new succeeds. A name collision must
    // never cause cleanup to remove another writer's temp file.
    let mut cleanup = TempCleanup::unarmed(temp_path.clone());
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temp_path)?;
    cleanup.armed = true;

    hook(CommitStage::TempCreated)?;

    // Separate writes let failure-injection tests simulate a partial payload. The final
    // path remains untouched until the sibling temp has been synced and atomically replaced.
    let midpoint = (bytes.len() / 2).max(1).min(bytes.len());
    file.write_all(&bytes[..midpoint])?;
    hook(CommitStage::PartialWritten)?;
    file.write_all(&bytes[midpoint..])?;
    file.flush()?;
    file.sync_all()?;
    hook(CommitStage::FileSynced)?;
    hook(CommitStage::BeforeReplace)?;
    drop(file);

    atomic_replace(&temp_path, path)?;
    hook(CommitStage::AfterReplace)?;

    // After rename the temporary path no longer exists; the final path remains committed.
    drop(cleanup);
    Ok(())
}

/// Exclusive, process-wide writer ownership for a ChainImportService snapshot path.
/// The stable sibling lock file is intentionally not deleted: OS-level locks are
/// released when the handle/process closes, while deleting the file could let another
/// process lock a newly-created inode/file and bypass an existing owner's lock.
pub(crate) struct SnapshotWriterLock {
    _file: File,
}

impl SnapshotWriterLock {
    pub(crate) fn acquire(snapshot_path: &Path) -> Result<Self, SnapshotStoreError> {
        let input_name = snapshot_path
            .file_name()
            .ok_or(SnapshotStoreError::InvalidPath)?;
        match fs::symlink_metadata(snapshot_path) {
            Ok(metadata) if metadata.file_type().is_symlink() || metadata.is_dir() => {
                // Symlink destinations have ambiguous semantics for atomic replacement:
                // reject them instead of locking one target and replacing another path entry.
                return Err(SnapshotStoreError::InvalidPath);
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        let canonical_target = match fs::canonicalize(snapshot_path) {
            Ok(path) => path,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let canonical_parent = fs::canonicalize(parent_directory(snapshot_path))?;
                canonical_parent.join(input_name)
            }
            Err(error) => return Err(error.into()),
        };
        let parent = canonical_target
            .parent()
            .ok_or(SnapshotStoreError::InvalidPath)?;
        let final_name = canonical_target
            .file_name()
            .ok_or(SnapshotStoreError::InvalidPath)?;
        // Resolve existing symlink aliases to the same canonical target before deriving the
        // stable sibling lock. Preserve the exact OS filename instead of lossy UTF-8 conversion.
        let mut lock_name = final_name.to_os_string();
        lock_name.push(".writer.lock");
        let lock_path = parent.join(lock_name);
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&lock_path)?;
        if let Err(error) = try_lock_exclusive(&file) {
            if error.kind() == io::ErrorKind::WouldBlock || error.raw_os_error() == Some(33) {
                return Err(SnapshotStoreError::WriterLockBusy(lock_path));
            }
            return Err(error.into());
        }
        Ok(Self { _file: file })
    }

    /// Add a second lock tied to the opened file object itself, not just its path.
    ///
    /// This is needed for append-in-place stores: distinct hard-link names can refer to the same
    /// file while deriving different sibling lock paths. Call only after opening the data file and
    /// before recovery or mutation; keep the returned lease for the writer's entire lifetime.
    pub(crate) fn acquire_file_identity(
        file: &File,
        display_path: &Path,
    ) -> Result<Self, SnapshotStoreError> {
        let lock_file = file.try_clone()?;
        // Lock a reserved byte far beyond the WAL's enforced size cap, so the lock does not
        // overlap normal data writes through the original handle on Windows.
        if let Err(error) = try_lock_exclusive_at(&lock_file, FILE_IDENTITY_LOCK_OFFSET) {
            if error.kind() == io::ErrorKind::WouldBlock || error.raw_os_error() == Some(33) {
                return Err(SnapshotStoreError::WriterLockBusy(
                    display_path.to_path_buf(),
                ));
            }
            return Err(error.into());
        }
        Ok(Self { _file: lock_file })
    }
}

fn try_lock_exclusive(file: &File) -> io::Result<()> {
    try_lock_exclusive_at(file, 0)
}

#[cfg(windows)]
fn try_lock_exclusive_at(file: &File, offset: u64) -> io::Result<()> {
    use std::{ffi::c_void, os::windows::io::AsRawHandle};

    #[repr(C)]
    struct Overlapped {
        internal: usize,
        internal_high: usize,
        offset: u32,
        offset_high: u32,
        event: *mut c_void,
    }
    extern "system" {
        fn LockFileEx(
            file: *mut c_void,
            flags: u32,
            reserved: u32,
            bytes_low: u32,
            bytes_high: u32,
            overlapped: *mut Overlapped,
        ) -> i32;
    }
    const LOCKFILE_EXCLUSIVE_LOCK: u32 = 0x0000_0002;
    const LOCKFILE_FAIL_IMMEDIATELY: u32 = 0x0000_0001;
    let mut overlapped = Overlapped {
        internal: 0,
        internal_high: 0,
        offset: offset as u32,
        offset_high: (offset >> 32) as u32,
        event: std::ptr::null_mut(),
    };
    let result = unsafe {
        LockFileEx(
            file.as_raw_handle() as *mut c_void,
            LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY,
            0,
            1,
            0,
            &mut overlapped,
        )
    };
    if result == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(unix)]
fn try_lock_exclusive_at(file: &File, _offset: u64) -> io::Result<()> {
    use std::os::fd::AsRawFd;
    extern "C" {
        fn flock(fd: i32, operation: i32) -> i32;
    }
    const LOCK_EX: i32 = 2;
    const LOCK_NB: i32 = 4;
    let result = unsafe { flock(file.as_raw_fd(), LOCK_EX | LOCK_NB) };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(not(any(windows, unix)))]
fn try_lock_exclusive_at(_file: &File, _offset: u64) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "snapshot writer locking is unsupported on this platform",
    ))
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

    // Source and destination are siblings, so replacement cannot cross volumes.
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
    use std::{process::Command, sync::atomic::AtomicUsize};

    static TEST_DIR_ID: AtomicUsize = AtomicUsize::new(1);
    const TEST_NETWORK: NetworkId = [0xA7; 32];

    struct TestDir(PathBuf);

    impl TestDir {
        fn new(label: &str) -> Self {
            let id = TEST_DIR_ID.fetch_add(1, Ordering::Relaxed);
            let path =
                std::env::temp_dir().join(format!("cp0026e_{label}_{}_{}", std::process::id(), id));
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

    fn state(sender_balance: u64) -> LedgerState {
        LedgerState::genesis(
            TEST_NETWORK,
            vec![([0x11; 32], sender_balance), ([0x22; 32], 0)],
        )
        .unwrap()
    }

    #[test]
    fn exclusive_writer_lock_rejects_competing_owner_and_releases_on_drop() {
        let dir = TestDir::new("writer_lock");
        let path = dir.file("ledger.stv2");
        let owner = SnapshotWriterLock::acquire(&path).unwrap();
        assert!(matches!(
            SnapshotWriterLock::acquire(&path),
            Err(SnapshotStoreError::WriterLockBusy(_))
        ));
        drop(owner);
        let next_owner = SnapshotWriterLock::acquire(&path).unwrap();
        drop(next_owner);
    }

    #[cfg(windows)]
    #[test]
    fn writer_lock_alias_through_directory_junction_resolves_same_existing_file() {
        let dir = TestDir::new("writer_lock_junction_alias");
        let real_dir = dir.file("real");
        let alias_dir = dir.file("junction");
        fs::create_dir_all(&real_dir).unwrap();

        // Directory junctions do not require the symbolic-link privilege disabled on this host.
        // This tests two path spellings that reach the same existing WAL/snapshot file.
        let command = format!("mklink /J {} {}", alias_dir.display(), real_dir.display());
        let output = Command::new("cmd.exe")
            .args(["/d", "/c"])
            .arg(command)
            .output()
            .expect("cmd.exe must be available on Windows");
        assert!(
            output.status.success(),
            "could not create test junction: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );

        let real_file = real_dir.join("ledger.stv2");
        let alias_file = alias_dir.join("ledger.stv2");
        fs::write(&real_file, b"one underlying file through two paths").unwrap();
        assert!(alias_file.exists());

        let owner = SnapshotWriterLock::acquire(&real_file).unwrap();
        assert!(matches!(
            SnapshotWriterLock::acquire(&alias_file),
            Err(SnapshotStoreError::WriterLockBusy(_))
        ));
        drop(owner);
        assert!(SnapshotWriterLock::acquire(&alias_file).is_ok());
    }

    #[test]
    fn writer_lock_rejects_final_symlink_paths_when_supported() {
        let dir = TestDir::new("writer_lock_symlink_alias");
        let path = dir.file("ledger.stv2");
        let alias = dir.file("ledger-alias.stv2");
        fs::write(&path, b"existing snapshot identity").unwrap();

        #[cfg(windows)]
        let symlink_result = std::os::windows::fs::symlink_file(&path, &alias);
        #[cfg(unix)]
        let symlink_result = std::os::unix::fs::symlink(&path, &alias);
        #[cfg(not(any(windows, unix)))]
        let symlink_result: io::Result<()> = Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "symlink tests are unsupported on this platform",
        ));

        if let Err(error) = symlink_result {
            // Some Windows hosts disable unprivileged symbolic-link creation. Keep the
            // portable test suite usable there; CI with symlink support exercises the assertion.
            eprintln!("SKIP writer-lock symlink alias test: {error}");
            return;
        }

        let owner = SnapshotWriterLock::acquire(&path).unwrap();
        assert!(matches!(
            SnapshotWriterLock::acquire(&alias),
            Err(SnapshotStoreError::InvalidPath)
        ));
        // A rejected alias must not disturb the real path's existing writer lease.
        assert!(matches!(
            SnapshotWriterLock::acquire(&path),
            Err(SnapshotStoreError::WriterLockBusy(_))
        ));
        drop(owner);
        assert!(SnapshotWriterLock::acquire(&path).is_ok());
    }

    #[test]
    fn atomic_first_save_replace_and_load_return_exact_state() {
        let dir = TestDir::new("replace");
        let path = dir.file("ledger.stv2");
        let first = state(1_000);
        let second = state(777);

        save_atomic(&path, &first).unwrap();
        let first_bytes = fs::read(&path).unwrap();
        assert_eq!(load(&path, &TEST_NETWORK).unwrap(), first);

        save_atomic(&path, &second).unwrap();
        let second_bytes = fs::read(&path).unwrap();
        assert_ne!(first_bytes, second_bytes);
        assert_eq!(load(&path, &TEST_NETWORK).unwrap(), second);
        assert_eq!(
            LedgerState::decode_snapshot(&second_bytes, &TEST_NETWORK).unwrap(),
            second
        );
        assert_eq!(cleanup_orphan_temps(&path).unwrap(), 0);
    }

    #[test]
    fn precommit_faults_preserve_previous_snapshot_and_clean_temp() {
        let dir = TestDir::new("precommit_faults");
        let path = dir.file("ledger.stv2");
        let committed = state(1_000);
        let candidate = state(700);
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
                    Err(SnapshotStoreError::InjectedFault(stage.label()))
                } else {
                    Ok(())
                }
            });
            assert!(matches!(result, Err(SnapshotStoreError::InjectedFault(_))));
            assert_eq!(
                fs::read(&path).unwrap(),
                committed_bytes,
                "fault={target:?}"
            );
            assert_eq!(
                load(&path, &TEST_NETWORK).unwrap(),
                committed,
                "fault={target:?}"
            );
            assert_eq!(cleanup_orphan_temps(&path).unwrap(), 0, "fault={target:?}");
        }
    }

    #[test]
    fn postreplace_fault_recovers_new_complete_snapshot_not_partial_bytes() {
        let dir = TestDir::new("postreplace_fault");
        let path = dir.file("ledger.stv2");
        let old = state(1_000);
        let new = state(321);
        save_atomic(&path, &old).unwrap();

        let result = save_atomic_with_hook(&path, &new, |stage| {
            if stage == CommitStage::AfterReplace {
                Err(SnapshotStoreError::InjectedFault(stage.label()))
            } else {
                Ok(())
            }
        });
        assert!(matches!(
            result,
            Err(SnapshotStoreError::InjectedFault("after-replace"))
        ));
        assert_eq!(load(&path, &TEST_NETWORK).unwrap(), new);
        assert_eq!(
            LedgerState::decode_snapshot(&fs::read(&path).unwrap(), &TEST_NETWORK).unwrap(),
            new
        );
    }

    #[test]
    fn orphan_temp_cleanup_never_selects_temp_or_deletes_unrelated_files() {
        let dir = TestDir::new("orphan");
        let path = dir.file("ledger.stv2");
        let committed = state(123);
        save_atomic(&path, &committed).unwrap();
        let committed_bytes = fs::read(&path).unwrap();

        let orphan = dir.file(".ledger.stv2.cp0026e.4242.99.tmp");
        let unrelated = dir.file(".other.cp0026e.4242.99.tmp");
        fs::write(&orphan, b"partial uncommitted bytes").unwrap();
        fs::write(&unrelated, b"unrelated").unwrap();

        assert_eq!(cleanup_orphan_temps(&path).unwrap(), 1);
        assert!(!orphan.exists());
        assert!(unrelated.exists());
        assert_eq!(fs::read(&path).unwrap(), committed_bytes);
        assert_eq!(load(&path, &TEST_NETWORK).unwrap(), committed);
    }

    #[test]
    fn load_rejects_corrupt_or_crossnetwork_snapshots_without_fallback() {
        let dir = TestDir::new("reject");
        let path = dir.file("ledger.stv2");
        save_atomic(&path, &state(456)).unwrap();
        assert!(matches!(
            load(&path, &[0xB8; 32]),
            Err(SnapshotStoreError::State(
                StateError::SnapshotNetworkMismatch
            ))
        ));

        let mut damaged = fs::read(&path).unwrap();
        damaged[10] ^= 0x01;
        fs::write(&path, &damaged).unwrap();
        assert!(matches!(
            load(&path, &TEST_NETWORK),
            Err(SnapshotStoreError::State(
                StateError::SnapshotChecksumMismatch
            ))
        ));
    }

    #[test]
    fn child_process_restore_probe() {
        let Ok(source) = std::env::var("CP0026E_RESTORE_PATH") else {
            // Invoked only by the parent process-equivalence test below.
            return;
        };
        let output =
            std::env::var("CP0026E_RESTORE_OUTPUT").expect("parent supplied child output path");
        let network_hex =
            std::env::var("CP0026E_RESTORE_NETWORK").expect("parent supplied expected network id");
        let expected_network: NetworkId = (0..network_hex.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&network_hex[index..index + 2], 16).unwrap())
            .collect::<Vec<_>>()
            .try_into()
            .expect("32-byte expected network");
        let restored =
            load(Path::new(&source), &expected_network).expect("child loads committed snapshot");
        fs::write(output, restored.encode_snapshot().unwrap())
            .expect("child emits restored canonical snapshot");
    }

    #[test]
    fn separate_process_reopens_committed_snapshot_byte_for_byte() {
        let dir = TestDir::new("child_restore");
        let path = dir.file("ledger.stv2");
        let output = dir.file("child-restored.stv2");
        let original = state(987);
        save_atomic(&path, &original).unwrap();
        let expected_bytes = fs::read(&path).unwrap();

        let test_executable = std::env::current_exe().expect("current Rust test executable");
        let status = Command::new(test_executable)
            .arg("--exact")
            .arg("snapshot_store::tests::child_process_restore_probe")
            .arg("--nocapture")
            .env("CP0026E_RESTORE_PATH", &path)
            .env("CP0026E_RESTORE_OUTPUT", &output)
            .env("CP0026E_RESTORE_NETWORK", hex(&TEST_NETWORK))
            .status()
            .expect("launch snapshot restore child");
        assert!(
            status.success(),
            "snapshot restore child failed: {status:?}"
        );
        assert_eq!(fs::read(&output).unwrap(), expected_bytes);
        assert_eq!(load(&path, &TEST_NETWORK).unwrap(), original);
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }
}
