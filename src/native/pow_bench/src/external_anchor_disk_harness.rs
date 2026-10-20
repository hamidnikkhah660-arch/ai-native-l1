//! Test-only disk-backed harness for the external manifest-anchor crash protocol.
//!
//! This uses real temporary files and atomic replacement, while the separate anchor directory
//! is only a simulated provider. It is not a production CAS service, not canonical persistence,
//! and not connected to consensus. Crash recovery accepts only the exact old or new anchored pair.
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
    process::{self, Command, Stdio},
    sync::atomic::{AtomicU64, Ordering},
    thread,
    time::{Duration, Instant},
};

const DOMAIN: [u8; 32] = [0x51; 32];
const SCHEMA: u16 = 1;
const CATALOG_MAGIC: &[u8; 4] = b"AMC1";
const ANCHOR_MAGIC: &[u8; 4] = b"EAN1";
const INTENT_MAGIC: &[u8; 4] = b"AIN1";
const STORE_ENV: &str = "CP0136_AE_DISK_STORE";
const ANCHOR_DIR_ENV: &str = "CP0136_AE_DISK_ANCHOR_DIR";
const MARKER_ENV: &str = "CP0136_AE_DISK_MARKER";
static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Record {
    generation: u64,
    digest: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Intent {
    from: Record,
    to: Record,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stage {
    AfterPrepared,
    AfterIntent,
    AfterAnchor,
    AfterManifest,
    AfterIntentCleared,
}

impl Stage {
    fn label(self) -> &'static str {
        match self {
            Self::AfterPrepared => "after-prepared",
            Self::AfterIntent => "after-intent",
            Self::AfterAnchor => "after-anchor",
            Self::AfterManifest => "after-manifest",
            Self::AfterIntentCleared => "after-intent-cleared",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DiskError {
    Io,
    Missing,
    Malformed,
    Checksum,
    WrongDomain,
    WrongSchema,
    InvalidTransition,
    AnchorMismatch,
    MissingPreparedPayload,
    AmbiguousRecovery,
    Injected(&'static str),
}

impl From<io::Error> for DiskError {
    fn from(_: io::Error) -> Self {
        Self::Io
    }
}

fn state_bytes(magic: &[u8; 4], record: Record) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(4 + 32 + 2 + 8 + 32 + 32);
    bytes.extend_from_slice(magic);
    bytes.extend_from_slice(&DOMAIN);
    bytes.extend_from_slice(&SCHEMA.to_be_bytes());
    bytes.extend_from_slice(&record.generation.to_be_bytes());
    bytes.extend_from_slice(&record.digest);
    let checksum: [u8; 32] = Sha256::digest(&bytes).into();
    bytes.extend_from_slice(&checksum);
    bytes
}

fn parse_state(bytes: &[u8], magic: &[u8; 4]) -> Result<Record, DiskError> {
    if bytes.len() != 110 || &bytes[..4] != magic {
        return Err(DiskError::Malformed);
    }
    let expected: [u8; 32] = Sha256::digest(&bytes[..78]).into();
    if bytes[78..] != expected {
        return Err(DiskError::Checksum);
    }
    if bytes[4..36] != DOMAIN {
        return Err(DiskError::WrongDomain);
    }
    if u16::from_be_bytes(bytes[36..38].try_into().unwrap()) != SCHEMA {
        return Err(DiskError::WrongSchema);
    }
    Ok(Record {
        generation: u64::from_be_bytes(bytes[38..46].try_into().unwrap()),
        digest: bytes[46..78].try_into().unwrap(),
    })
}

fn intent_bytes(intent: Intent) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(4 + 32 + 2 + 8 + 32 + 8 + 32 + 32);
    bytes.extend_from_slice(INTENT_MAGIC);
    bytes.extend_from_slice(&DOMAIN);
    bytes.extend_from_slice(&SCHEMA.to_be_bytes());
    bytes.extend_from_slice(&intent.from.generation.to_be_bytes());
    bytes.extend_from_slice(&intent.from.digest);
    bytes.extend_from_slice(&intent.to.generation.to_be_bytes());
    bytes.extend_from_slice(&intent.to.digest);
    let checksum: [u8; 32] = Sha256::digest(&bytes).into();
    bytes.extend_from_slice(&checksum);
    bytes
}

fn parse_intent(bytes: &[u8]) -> Result<Intent, DiskError> {
    if bytes.len() != 150 || &bytes[..4] != INTENT_MAGIC {
        return Err(DiskError::Malformed);
    }
    let expected: [u8; 32] = Sha256::digest(&bytes[..118]).into();
    if bytes[118..] != expected {
        return Err(DiskError::Checksum);
    }
    if bytes[4..36] != DOMAIN {
        return Err(DiskError::WrongDomain);
    }
    if u16::from_be_bytes(bytes[36..38].try_into().unwrap()) != SCHEMA {
        return Err(DiskError::WrongSchema);
    }
    let intent = Intent {
        from: Record {
            generation: u64::from_be_bytes(bytes[38..46].try_into().unwrap()),
            digest: bytes[46..78].try_into().unwrap(),
        },
        to: Record {
            generation: u64::from_be_bytes(bytes[78..86].try_into().unwrap()),
            digest: bytes[86..118].try_into().unwrap(),
        },
    };
    if intent.from.generation.checked_add(1) != Some(intent.to.generation)
        || intent.from.digest == intent.to.digest
    {
        return Err(DiskError::InvalidTransition);
    }
    Ok(intent)
}

fn read_file(path: &Path) -> Result<Vec<u8>, DiskError> {
    let file = File::open(path).map_err(|e| {
        if e.kind() == io::ErrorKind::NotFound {
            DiskError::Missing
        } else {
            DiskError::Io
        }
    })?;
    let length = file.metadata()?.len();
    if length > 4096 {
        return Err(DiskError::Malformed);
    }
    let mut bytes = Vec::with_capacity(length as usize);
    file.take(4097).read_to_end(&mut bytes)?;
    if bytes.len() > 4096 {
        return Err(DiskError::Malformed);
    }
    Ok(bytes)
}

fn sync_parent(path: &Path) -> io::Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    #[cfg(unix)]
    {
        File::open(parent)?.sync_all()
    }
    #[cfg(windows)]
    {
        let _ = parent;
        Ok(())
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = parent;
        Ok(())
    }
}

#[cfg(windows)]
fn replace_file(source: &Path, destination: &Path) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    const MOVEFILE_REPLACE_EXISTING: u32 = 0x1;
    const MOVEFILE_WRITE_THROUGH: u32 = 0x8;
    let from: Vec<u16> = source.as_os_str().encode_wide().chain(Some(0)).collect();
    let to: Vec<u16> = destination
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect();
    #[link(name = "Kernel32")]
    extern "system" {
        fn MoveFileExW(existing: *const u16, new_name: *const u16, flags: u32) -> i32;
    }
    let success = unsafe {
        MoveFileExW(
            from.as_ptr(),
            to.as_ptr(),
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
fn replace_file(source: &Path, destination: &Path) -> io::Result<()> {
    fs::rename(source, destination)?;
    sync_parent(destination)
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), DiskError> {
    let parent = path.parent().ok_or(DiskError::Malformed)?;
    if !parent.is_dir() {
        return Err(DiskError::Missing);
    }
    let id = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
    let name = path
        .file_name()
        .ok_or(DiskError::Malformed)?
        .to_string_lossy();
    let temp = parent.join(format!(".{name}.tmp-{}-{id}", process::id()));
    let result = (|| -> io::Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp)?;
        file.write_all(bytes)?;
        file.flush()?;
        file.sync_all()?;
        drop(file);
        replace_file(&temp, path)?;
        sync_parent(path)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result.map_err(|_| DiskError::Io)
}

fn remove_synced(path: &Path) -> Result<(), DiskError> {
    match fs::remove_file(path) {
        Ok(()) => sync_parent(path).map_err(|_| DiskError::Io),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(DiskError::Io),
    }
}

/// An OS-managed exclusive lock used only to serialize fixture anchor writers.
/// The kernel releases ownership when the process exits or is killed. Keep the lock file itself:
/// removing it while another process holds or waits on it could split contenders across file objects.
/// This is still a local test fixture, not an independent production monotonic CAS authority.
struct FixtureFileLock {
    _file: File,
}

impl FixtureFileLock {
    fn acquire(path: PathBuf) -> Result<Self, DiskError> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)?;
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            match try_lock_fixture_file(&file) {
                Ok(()) => return Ok(Self { _file: file }),
                Err(error)
                    if (error.kind() == io::ErrorKind::WouldBlock
                        || error.raw_os_error() == Some(33))
                        && Instant::now() < deadline =>
                {
                    thread::sleep(Duration::from_millis(2));
                }
                Err(_) => return Err(DiskError::Io),
            }
        }
    }
}

// Use OS-managed file locking here instead of File::try_lock(), which is not available on the
// project's pinned Rust 1.82 toolchain. Closing the held file releases the kernel lock after a
// process exits or is killed, preserving the crash-harness property on Windows and Unix.
fn try_lock_fixture_file(file: &File) -> io::Result<()> {
    #[cfg(windows)]
    {
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
            offset: 0,
            offset_high: 0,
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
    {
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
    {
        let _ = file;
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "fixture file locking is unsupported on this platform",
        ))
    }
}

/// A file-based fake anchor provider for tests only. Cooperating writer processes are serialized
/// by a kernel-managed local file lock, then expected-value checked. This is not an external
/// monotonic authority: the anchor file can still be restored together with the manifest. It does
/// not establish production rollback resistance.
struct SimulatedAnchorProvider {
    path: PathBuf,
}

impl SimulatedAnchorProvider {
    fn read(&self) -> Result<Record, DiskError> {
        parse_state(&read_file(&self.path)?, ANCHOR_MAGIC)
    }

    fn compare_and_swap(&self, expected: Record, next: Record) -> Result<(), DiskError> {
        let _guard = FixtureFileLock::acquire(self.path.with_extension("cas.lock"))?;
        let current = self.read()?;
        if current != expected {
            return Err(DiskError::AnchorMismatch);
        }
        if expected.generation.checked_add(1) != Some(next.generation)
            || expected.digest == next.digest
        {
            return Err(DiskError::InvalidTransition);
        }
        write_atomic(&self.path, &state_bytes(ANCHOR_MAGIC, next))
    }
}

struct DiskHarness {
    store_dir: PathBuf,
    anchor: SimulatedAnchorProvider,
}

impl DiskHarness {
    fn new(store_dir: &Path, anchor_dir: &Path) -> Self {
        Self {
            store_dir: store_dir.to_path_buf(),
            anchor: SimulatedAnchorProvider {
                path: anchor_dir.join("trusted-anchor.bin"),
            },
        }
    }

    fn manifest(&self) -> PathBuf {
        self.store_dir.join("manifest.bin")
    }
    fn prepared(&self, generation: u64) -> PathBuf {
        self.store_dir
            .join(format!("prepared-{generation:020}.bin"))
    }
    fn intent(&self) -> PathBuf {
        self.store_dir.join("pending.intent")
    }

    fn bootstrap(&self, initial: Record) -> Result<(), DiskError> {
        fs::create_dir_all(&self.store_dir)?;
        if let Some(parent) = self.anchor.path.parent() {
            fs::create_dir_all(parent)?;
        }
        write_atomic(&self.manifest(), &state_bytes(CATALOG_MAGIC, initial))?;
        write_atomic(&self.anchor.path, &state_bytes(ANCHOR_MAGIC, initial))
    }

    fn commit_with_hook<F>(&self, next_digest: [u8; 32], mut hook: F) -> Result<Record, DiskError>
    where
        F: FnMut(Stage) -> Result<(), DiskError>,
    {
        let current = parse_state(&read_file(&self.manifest())?, CATALOG_MAGIC)?;
        if self.anchor.read()? != current {
            return Err(DiskError::AnchorMismatch);
        }
        let next = Record {
            generation: current
                .generation
                .checked_add(1)
                .ok_or(DiskError::InvalidTransition)?,
            digest: next_digest,
        };
        if next.digest == current.digest {
            return Err(DiskError::InvalidTransition);
        }
        let intent = Intent {
            from: current,
            to: next,
        };
        let prepared_path = self.prepared(next.generation);
        write_atomic(&prepared_path, &state_bytes(CATALOG_MAGIC, next))?;
        hook(Stage::AfterPrepared)?;
        write_atomic(&self.intent(), &intent_bytes(intent))?;
        hook(Stage::AfterIntent)?;
        self.anchor.compare_and_swap(current, next)?;
        hook(Stage::AfterAnchor)?;
        let prepared_bytes = read_file(&prepared_path)?;
        if parse_state(&prepared_bytes, CATALOG_MAGIC)? != next {
            return Err(DiskError::MissingPreparedPayload);
        }
        replace_file(&prepared_path, &self.manifest()).map_err(|_| DiskError::Io)?;
        sync_parent(&self.manifest()).map_err(|_| DiskError::Io)?;
        hook(Stage::AfterManifest)?;
        remove_synced(&self.intent())?;
        hook(Stage::AfterIntentCleared)?;
        Ok(next)
    }

    /// Reopen only accepts exact state anchored by the separate provider. If the external
    /// anchor advanced, a durable matching intent and fully valid prepared catalog are required.
    fn recover(&self) -> Result<Record, DiskError> {
        let anchor = self.anchor.read()?;
        let local = match read_file(&self.manifest()) {
            Ok(bytes) => Some(parse_state(&bytes, CATALOG_MAGIC)?),
            Err(DiskError::Missing) => None,
            Err(error) => return Err(error),
        };
        let intent = match read_file(&self.intent()) {
            Ok(bytes) => Some(parse_intent(&bytes)?),
            Err(DiskError::Missing) => None,
            Err(error) => return Err(error),
        };

        if let Some(intent) = intent {
            let prepared_path = self.prepared(intent.to.generation);
            let prepared = match read_file(&prepared_path) {
                Ok(bytes) => Some(parse_state(&bytes, CATALOG_MAGIC)?),
                Err(DiskError::Missing) => None,
                Err(error) => return Err(error),
            };
            if prepared.is_some_and(|record| record != intent.to) {
                return Err(DiskError::MissingPreparedPayload);
            }
            if local == Some(intent.to) && anchor == intent.to {
                remove_synced(&self.intent())?;
                remove_synced(&prepared_path)?;
                return Ok(intent.to);
            }
            if local == Some(intent.from) && anchor == intent.from {
                remove_synced(&self.intent())?;
                remove_synced(&prepared_path)?;
                return Ok(intent.from);
            }
            if (local == Some(intent.from) || local.is_none())
                && anchor == intent.to
                && prepared == Some(intent.to)
            {
                replace_file(&prepared_path, &self.manifest()).map_err(|_| DiskError::Io)?;
                sync_parent(&self.manifest()).map_err(|_| DiskError::Io)?;
                remove_synced(&self.intent())?;
                return Ok(intent.to);
            }
            return Err(DiskError::AmbiguousRecovery);
        }

        match local {
            Some(record) if record == anchor => {
                // Prepared files with no durable intent are uncommitted orphans, never commits.
                for entry in fs::read_dir(&self.store_dir)? {
                    let entry = entry?;
                    let name = entry.file_name();
                    if name.to_string_lossy().starts_with("prepared-") {
                        fs::remove_file(entry.path())?;
                    }
                }
                sync_parent(&self.manifest()).map_err(|_| DiskError::Io)?;
                Ok(record)
            }
            Some(_) => Err(DiskError::AnchorMismatch),
            None => Err(DiskError::AmbiguousRecovery),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    static NEXT_TEST_ID: AtomicU64 = AtomicU64::new(1);

    struct TestDir(PathBuf);
    impl TestDir {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "ain1_cp0136_ae_{}_{}",
                process::id(),
                NEXT_TEST_ID.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }
        fn store(&self) -> PathBuf {
            self.0.join("store")
        }
        fn anchor(&self) -> PathBuf {
            self.0.join("anchor-domain")
        }
    }
    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    const CHILD_STAGE_ENV: &str = "CP0136_AE_CHILD_MODE";
    const CAS_RACE_GO_ENV: &str = "CP0137_AE_CAS_RACE_GO";

    fn seed(harness: &DiskHarness) -> Record {
        let initial = Record {
            generation: 0,
            digest: [0xA0; 32],
        };
        harness.bootstrap(initial).unwrap();
        initial
    }

    #[test]
    fn child_commit_probe() {
        let (Ok(mode), Ok(store_dir), Ok(anchor_dir), Ok(marker)) = (
            std::env::var(CHILD_STAGE_ENV),
            std::env::var(STORE_ENV),
            std::env::var(ANCHOR_DIR_ENV),
            std::env::var(MARKER_ENV),
        ) else {
            return;
        };
        if mode == "hold-cas-lock" {
            let harness = DiskHarness::new(Path::new(&store_dir), Path::new(&anchor_dir));
            let _guard = FixtureFileLock::acquire(harness.anchor.path.with_extension("cas.lock"))
                .expect("child acquires the kernel-managed CAS lock");
            fs::write(&marker, b"lock-held").expect("write lock-held marker");
            loop {
                thread::sleep(Duration::from_secs(1));
            }
        }

        if mode == "cas-race-b1" || mode == "cas-race-b2" {
            let go_path = PathBuf::from(
                std::env::var(CAS_RACE_GO_ENV).expect("CAS race gate path is required"),
            );
            fs::write(&marker, b"ready").expect("write CAS race ready marker");
            let deadline = Instant::now() + Duration::from_secs(12);
            while !go_path.exists() && Instant::now() < deadline {
                thread::sleep(Duration::from_millis(5));
            }
            assert!(go_path.exists(), "parent did not release the CAS race gate");
            let expected = Record {
                generation: 0,
                digest: [0xA0; 32],
            };
            let next = Record {
                generation: 1,
                digest: if mode == "cas-race-b1" {
                    [0xB1; 32]
                } else {
                    [0xB2; 32]
                },
            };
            match DiskHarness::new(Path::new(&store_dir), Path::new(&anchor_dir))
                .anchor
                .compare_and_swap(expected, next)
            {
                Ok(()) => println!("CP0137_PROCESS_CAS_RESULT=WINNER"),
                Err(DiskError::AnchorMismatch) => {
                    println!("CP0137_PROCESS_CAS_RESULT=LOSER_ANCHOR_MISMATCH")
                }
                other => panic!("unexpected process CAS result: {other:?}"),
            }
            return;
        }

        let stage = match mode.as_str() {
            "after-prepared" => Stage::AfterPrepared,
            "after-intent" => Stage::AfterIntent,
            "after-anchor" => Stage::AfterAnchor,
            "after-manifest" => Stage::AfterManifest,
            "after-intent-cleared" => Stage::AfterIntentCleared,
            other => panic!("unsupported crash stage: {other}"),
        };
        let harness = DiskHarness::new(Path::new(&store_dir), Path::new(&anchor_dir));
        let result = harness.commit_with_hook([0xA1; 32], |seen| {
            if seen == stage {
                fs::write(&marker, seen.label().as_bytes()).expect("write crash marker");
                loop {
                    thread::sleep(Duration::from_secs(1));
                }
            }
            Ok(())
        });
        panic!("child unexpectedly returned from commit: {result:?}");
    }

    fn kill_child_at(stage: Stage) -> Record {
        let dir = TestDir::new();
        let harness = DiskHarness::new(&dir.store(), &dir.anchor());
        let old = seed(&harness);
        let marker = dir.0.join(format!("{}.ready", stage.label()));
        let mut child = Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg("external_anchor_disk_harness::tests::child_commit_probe")
            .arg("--nocapture")
            .env(CHILD_STAGE_ENV, stage.label())
            .env(STORE_ENV, dir.store())
            .env(ANCHOR_DIR_ENV, dir.anchor())
            .env(MARKER_ENV, &marker)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn child commit probe");
        let until = Instant::now() + Duration::from_secs(12);
        while Instant::now() < until && !marker.exists() {
            if let Some(status) = child.try_wait().unwrap() {
                panic!("child exited before stage marker {stage:?}: {status:?}");
            }
            thread::sleep(Duration::from_millis(10));
        }
        assert!(marker.exists(), "child failed to reach {stage:?}");
        child.kill().expect("kill child at commit boundary");
        let _ = child.wait().expect("wait for killed child");
        let recovered = harness.recover().unwrap();
        let expected = match stage {
            Stage::AfterPrepared | Stage::AfterIntent => old,
            Stage::AfterAnchor | Stage::AfterManifest | Stage::AfterIntentCleared => Record {
                generation: 1,
                digest: [0xA1; 32],
            },
        };
        assert_eq!(recovered, expected, "stage={stage:?}");
        assert_eq!(
            parse_state(&read_file(&harness.manifest()).unwrap(), CATALOG_MAGIC).unwrap(),
            expected
        );
        assert_eq!(harness.anchor.read().unwrap(), expected);
        recovered
    }

    #[test]
    fn real_child_process_kills_recover_old_or_new_state_at_every_commit_boundary() {
        for stage in [
            Stage::AfterPrepared,
            Stage::AfterIntent,
            Stage::AfterAnchor,
            Stage::AfterManifest,
            Stage::AfterIntentCleared,
        ] {
            kill_child_at(stage);
        }
    }

    #[test]
    fn missing_manifest_after_anchor_advance_recovers_only_from_exact_intent_and_prepared_payload()
    {
        let dir = TestDir::new();
        let harness = DiskHarness::new(&dir.store(), &dir.anchor());
        seed(&harness);
        let result = harness.commit_with_hook([0xA1; 32], |stage| {
            if stage == Stage::AfterAnchor {
                Err(DiskError::Injected(stage.label()))
            } else {
                Ok(())
            }
        });
        assert_eq!(result, Err(DiskError::Injected("after-anchor")));
        fs::remove_file(harness.manifest()).unwrap();
        let recovered = harness.recover().unwrap();
        assert_eq!(
            recovered,
            Record {
                generation: 1,
                digest: [0xA1; 32]
            }
        );
    }

    #[test]
    fn advanced_anchor_without_prepared_payload_fails_closed() {
        let dir = TestDir::new();
        let harness = DiskHarness::new(&dir.store(), &dir.anchor());
        seed(&harness);
        let result = harness.commit_with_hook([0xA1; 32], |stage| {
            if stage == Stage::AfterAnchor {
                Err(DiskError::Injected(stage.label()))
            } else {
                Ok(())
            }
        });
        assert_eq!(result, Err(DiskError::Injected("after-anchor")));
        fs::remove_file(harness.prepared(1)).unwrap();
        assert_eq!(harness.recover(), Err(DiskError::AmbiguousRecovery));
    }

    #[test]
    fn torn_intent_and_corrupted_prepared_payload_fail_closed_without_guessing() {
        let dir = TestDir::new();
        let harness = DiskHarness::new(&dir.store(), &dir.anchor());
        seed(&harness);
        let result = harness.commit_with_hook([0xA1; 32], |stage| {
            if stage == Stage::AfterIntent {
                Err(DiskError::Injected(stage.label()))
            } else {
                Ok(())
            }
        });
        assert_eq!(result, Err(DiskError::Injected("after-intent")));
        fs::write(harness.intent(), b"AIN1-torn").unwrap();
        assert!(matches!(harness.recover(), Err(DiskError::Malformed)));

        let dir2 = TestDir::new();
        let harness2 = DiskHarness::new(&dir2.store(), &dir2.anchor());
        seed(&harness2);
        let result2 = harness2.commit_with_hook([0xA1; 32], |stage| {
            if stage == Stage::AfterAnchor {
                Err(DiskError::Injected(stage.label()))
            } else {
                Ok(())
            }
        });
        assert_eq!(result2, Err(DiskError::Injected("after-anchor")));
        let prepared = harness2.prepared(1);
        let mut bytes = read_file(&prepared).unwrap();
        bytes[50] ^= 0x80;
        fs::write(prepared, bytes).unwrap();
        assert!(matches!(harness2.recover(), Err(DiskError::Checksum)));
    }

    #[test]
    fn concurrent_compare_and_swap_writers_have_exactly_one_winner() {
        use std::sync::{Arc, Barrier};

        let dir = TestDir::new();
        let harness = DiskHarness::new(&dir.store(), &dir.anchor());
        let old = seed(&harness);
        let provider = Arc::new(SimulatedAnchorProvider {
            path: harness.anchor.path.clone(),
        });
        let barrier = Arc::new(Barrier::new(3));
        let candidates = [
            Record {
                generation: 1,
                digest: [0xB1; 32],
            },
            Record {
                generation: 1,
                digest: [0xB2; 32],
            },
        ];
        let handles: Vec<_> = candidates
            .into_iter()
            .map(|next| {
                let provider = Arc::clone(&provider);
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    barrier.wait();
                    provider.compare_and_swap(old, next)
                })
            })
            .collect();

        barrier.wait();
        let outcomes: Vec<_> = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect();
        assert_eq!(outcomes.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(
            outcomes
                .iter()
                .filter(|result| **result == Err(DiskError::AnchorMismatch))
                .count(),
            1
        );
        let final_anchor = provider.read().unwrap();
        assert_eq!(final_anchor.generation, 1);
        assert!(candidates.contains(&final_anchor));
    }

    #[test]
    fn killing_lock_owner_releases_kernel_file_lock_and_cas_continues() {
        let dir = TestDir::new();
        let harness = DiskHarness::new(&dir.store(), &dir.anchor());
        let old = seed(&harness);
        let marker = dir.0.join("cas-lock-held.ready");
        let mut child = Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg("external_anchor_disk_harness::tests::child_commit_probe")
            .arg("--nocapture")
            .arg("--test-threads=1")
            .env(CHILD_STAGE_ENV, "hold-cas-lock")
            .env(STORE_ENV, harness.store_dir.as_os_str())
            .env(
                ANCHOR_DIR_ENV,
                harness.anchor.path.parent().unwrap().as_os_str(),
            )
            .env(MARKER_ENV, &marker)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn child that holds the CAS lock");

        let deadline = Instant::now() + Duration::from_secs(12);
        while !marker.exists() && Instant::now() < deadline {
            if let Some(status) = child.try_wait().unwrap() {
                panic!("lock-holding process exited before marker: {status:?}");
            }
            thread::sleep(Duration::from_millis(10));
        }
        if !marker.exists() {
            let _ = child.kill();
            let _ = child.wait();
            panic!("child process did not confirm ownership of CAS lock");
        }

        child
            .kill()
            .expect("kill process while it owns the CAS lock");
        child.wait().expect("reap killed lock-holding process");

        let lock_path = harness.anchor.path.with_extension("cas.lock");
        assert!(
            lock_path.exists(),
            "retain the same lock file so waiters cannot split across file objects"
        );
        let next = Record {
            generation: 1,
            digest: [0xD1; 32],
        };
        harness
            .anchor
            .compare_and_swap(old, next)
            .expect("kernel must release the lock when the owner is killed");
        assert_eq!(harness.anchor.read().unwrap(), next);
    }

    #[test]
    fn two_separate_processes_racing_anchor_cas_have_exactly_one_winner() {
        let dir = TestDir::new();
        let harness = DiskHarness::new(&dir.store(), &dir.anchor());
        let old = seed(&harness);
        let gate = dir.0.join("release-cas-race");
        let mut children = Vec::new();
        let cases = [
            ("cas-race-b1", dir.0.join("cas-b1.ready")),
            ("cas-race-b2", dir.0.join("cas-b2.ready")),
        ];

        for (mode, marker) in &cases {
            let child = Command::new(std::env::current_exe().unwrap())
                .arg("--exact")
                .arg("external_anchor_disk_harness::tests::child_commit_probe")
                .arg("--nocapture")
                .arg("--test-threads=1")
                .env(CHILD_STAGE_ENV, mode)
                .env(STORE_ENV, harness.store_dir.as_os_str())
                .env(
                    ANCHOR_DIR_ENV,
                    harness.anchor.path.parent().unwrap().as_os_str(),
                )
                .env(MARKER_ENV, marker)
                .env(CAS_RACE_GO_ENV, &gate)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .expect("spawn independent process for anchor CAS race");
            children.push((child, marker.clone()));
        }

        let ready_deadline = Instant::now() + Duration::from_secs(12);
        while cases.iter().any(|(_, marker)| !marker.exists()) && Instant::now() < ready_deadline {
            for (child, marker) in &mut children {
                if let Some(status) = child.try_wait().unwrap() {
                    panic!(
                        "CAS process exited before ready marker {}: {status:?}",
                        marker.display()
                    );
                }
            }
            thread::sleep(Duration::from_millis(10));
        }
        assert!(
            cases.iter().all(|(_, marker)| marker.exists()),
            "both independent CAS processes must be ready before release"
        );

        fs::write(&gate, b"go").expect("release both CAS contenders together");
        let mut done = vec![false; children.len()];
        let finish_deadline = Instant::now() + Duration::from_secs(12);
        while done.iter().any(|finished| !finished) && Instant::now() < finish_deadline {
            for (index, (child, _)) in children.iter_mut().enumerate() {
                if !done[index] {
                    if let Some(status) = child.try_wait().unwrap() {
                        assert!(status.success(), "CAS worker process failed: {status:?}");
                        done[index] = true;
                    }
                }
            }
            thread::sleep(Duration::from_millis(10));
        }
        if done.iter().any(|finished| !finished) {
            for (index, (child, _)) in children.iter_mut().enumerate() {
                if !done[index] {
                    let _ = child.kill();
                }
            }
            panic!("independent CAS worker processes did not complete before deadline");
        }

        let outputs: Vec<_> = children
            .into_iter()
            .map(|(child, _)| {
                let output = child.wait_with_output().expect("collect CAS worker output");
                assert!(output.status.success(), "CAS worker returned failure");
                String::from_utf8_lossy(&output.stdout).into_owned()
            })
            .collect();
        let winners = outputs
            .iter()
            .filter(|output| output.contains("CP0137_PROCESS_CAS_RESULT=WINNER"))
            .count();
        let losers = outputs
            .iter()
            .filter(|output| output.contains("CP0137_PROCESS_CAS_RESULT=LOSER_ANCHOR_MISMATCH"))
            .count();
        assert_eq!(winners, 1, "exactly one separate process must win CAS");
        assert_eq!(losers, 1, "the losing process must observe anchor mismatch");

        let final_anchor = harness.anchor.read().unwrap();
        let candidates = [
            Record {
                generation: 1,
                digest: [0xB1; 32],
            },
            Record {
                generation: 1,
                digest: [0xB2; 32],
            },
        ];
        assert_eq!(old.generation, 0);
        assert_eq!(final_anchor.generation, 1);
        assert!(candidates.contains(&final_anchor));
    }

    #[test]
    fn restored_manifest_or_restored_anchor_alone_fails_closed() {
        // Restore only the old manifest after a newer anchor was committed.
        let dir = TestDir::new();
        let harness = DiskHarness::new(&dir.store(), &dir.anchor());
        let old = seed(&harness);
        let old_manifest = fs::read(harness.manifest()).unwrap();
        let old_anchor = fs::read(&harness.anchor.path).unwrap();
        harness.commit_with_hook([0xC1; 32], |_| Ok(())).unwrap();
        fs::write(harness.manifest(), &old_manifest).unwrap();
        assert_eq!(harness.recover(), Err(DiskError::AnchorMismatch));

        // Separate fresh fixture: restore only the anchor while leaving the new manifest.
        let dir2 = TestDir::new();
        let harness2 = DiskHarness::new(&dir2.store(), &dir2.anchor());
        seed(&harness2);
        let old_anchor2 = fs::read(&harness2.anchor.path).unwrap();
        harness2.commit_with_hook([0xC2; 32], |_| Ok(())).unwrap();
        fs::write(&harness2.anchor.path, old_anchor2).unwrap();
        assert_eq!(harness2.recover(), Err(DiskError::AnchorMismatch));

        // Keep values live so this test documents both exact old-state fixtures explicitly.
        assert_eq!(old.generation, 0);
        assert_eq!(parse_state(&old_anchor, ANCHOR_MAGIC).unwrap(), old);
    }

    #[test]
    fn joint_restore_of_anchor_and_manifest_reproduces_the_known_rollback_gap() {
        // This is intentionally a limitation test, not a security success: both "trusted"
        // anchor and local catalog are in rollbackable storage in this fixture.
        let dir = TestDir::new();
        let harness = DiskHarness::new(&dir.store(), &dir.anchor());
        let old = seed(&harness);
        let old_manifest = fs::read(harness.manifest()).unwrap();
        let old_anchor = fs::read(&harness.anchor.path).unwrap();

        harness.commit_with_hook([0xD1; 32], |_| Ok(())).unwrap();
        fs::write(harness.manifest(), old_manifest).unwrap();
        fs::write(&harness.anchor.path, old_anchor).unwrap();

        // Reopening accepts the old pair because the simulated provider itself was rolled back.
        assert_eq!(harness.recover(), Ok(old));
    }

    #[test]
    fn corrupted_external_anchor_fails_closed() {
        let dir = TestDir::new();
        let harness = DiskHarness::new(&dir.store(), &dir.anchor());
        seed(&harness);
        let mut anchor = fs::read(&harness.anchor.path).unwrap();
        anchor[61] ^= 0x40;
        fs::write(&harness.anchor.path, anchor).unwrap();
        assert_eq!(harness.recover(), Err(DiskError::Checksum));
    }

    #[test]
    fn compare_and_swap_rejects_generation_skips_and_unchanged_digest() {
        let dir = TestDir::new();
        let harness = DiskHarness::new(&dir.store(), &dir.anchor());
        let old = seed(&harness);
        let skipped = Record {
            generation: 2,
            digest: [0xE2; 32],
        };
        let unchanged = Record {
            generation: 1,
            digest: old.digest,
        };
        assert_eq!(
            harness.anchor.compare_and_swap(old, skipped),
            Err(DiskError::InvalidTransition)
        );
        assert_eq!(
            harness.anchor.compare_and_swap(old, unchanged),
            Err(DiskError::InvalidTransition)
        );
        assert_eq!(harness.anchor.read().unwrap(), old);
    }
}
