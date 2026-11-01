//! OS-backed exclusive writer lock for durable candidate stores.
//!
//! The lock file is intentionally persistent. Ownership is the OS lock on a reserved byte range,
//! not the PID text or existence of the pathname. Closing the file handle (including on process
//! termination) releases ownership; the next opener can safely reuse the same lock file.

use std::{
    fs::{File, OpenOptions},
    io,
    path::Path,
};

#[cfg(unix)]
fn safe_lock_file_metadata(metadata: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    metadata.is_file() && !metadata.file_type().is_symlink() && metadata.nlink() == 1
}

#[cfg(windows)]
fn safe_lock_file_metadata(metadata: &std::fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
    metadata.is_file() && metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT == 0
}

#[cfg(windows)]
fn safe_lock_file_handle(file: &File) -> io::Result<bool> {
    use std::os::windows::io::AsRawHandle;

    #[repr(C)]
    struct FileTime {
        low: u32,
        high: u32,
    }
    #[repr(C)]
    struct ByHandleFileInformation {
        attributes: u32,
        creation_time: FileTime,
        last_access_time: FileTime,
        last_write_time: FileTime,
        volume_serial_number: u32,
        size_high: u32,
        size_low: u32,
        number_of_links: u32,
        file_index_high: u32,
        file_index_low: u32,
    }
    #[link(name = "Kernel32")]
    extern "system" {
        fn GetFileInformationByHandle(
            file: *mut std::ffi::c_void,
            information: *mut ByHandleFileInformation,
        ) -> i32;
    }

    let mut information = std::mem::MaybeUninit::<ByHandleFileInformation>::uninit();
    let success = unsafe {
        GetFileInformationByHandle(
            file.as_raw_handle() as *mut std::ffi::c_void,
            information.as_mut_ptr(),
        )
    };
    if success == 0 {
        return Err(io::Error::last_os_error());
    }
    let information = unsafe { information.assume_init() };
    Ok(information.number_of_links == 1)
}

#[cfg(not(any(unix, windows)))]
fn safe_lock_file_metadata(metadata: &std::fs::Metadata) -> bool {
    metadata.is_file() && !metadata.file_type().is_symlink()
}

#[cfg(not(windows))]
fn safe_lock_file_handle(_file: &File) -> io::Result<bool> {
    Ok(true)
}

#[cfg(unix)]
fn open_lock_file(path: &Path) -> io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    const O_NOFOLLOW: i32 = libc::O_NOFOLLOW;
    const O_CLOEXEC: i32 = libc::O_CLOEXEC;
    const O_NONBLOCK: i32 = libc::O_NONBLOCK;
    OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .custom_flags(O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
        .open(path)
}

#[cfg(windows)]
fn open_lock_file(path: &Path) -> io::Result<File> {
    use std::os::windows::fs::OpenOptionsExt;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
}

#[cfg(not(any(unix, windows)))]
fn open_lock_file(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)
}

pub(crate) struct StoreWriterLock {
    file: File,
    locked: bool,
    #[cfg(windows)]
    overlapped: WindowsOverlapped,
}

impl StoreWriterLock {
    pub(crate) fn acquire(directory: &Path, file_name: &str) -> io::Result<Self> {
        let path = directory.join(file_name);
        match std::fs::symlink_metadata(&path) {
            Ok(metadata) if !safe_lock_file_metadata(&metadata) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "writer lock path must be a single-link regular file, not a symlink/reparse point",
                ));
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        let file = open_lock_file(&path)?;
        if !safe_lock_file_metadata(&file.metadata()?) || !safe_lock_file_handle(&file)? {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "opened writer lock is not a safe single-link regular file",
            ));
        }

        let mut lock = Self {
            file,
            locked: false,
            #[cfg(windows)]
            overlapped: WindowsOverlapped::default(),
        };
        lock.lock_exclusive()?;
        lock.locked = true;

        // The lock file is deliberately never modified. Its kernel lock state, not its
        // contents, is the ownership primitive; avoiding writes also avoids truncating a
        // hard-linked target if an attacker races link creation after the metadata check.
        Ok(lock)
    }

    fn lock_exclusive(&mut self) -> io::Result<()> {
        #[cfg(windows)]
        {
            use std::os::windows::io::AsRawHandle;

            const LOCKFILE_FAIL_IMMEDIATELY: u32 = 0x0000_0001;
            const LOCKFILE_EXCLUSIVE_LOCK: u32 = 0x0000_0002;
            // ERROR_LOCK_VIOLATION is returned when another process/handle owns the byte range.
            const ERROR_LOCK_VIOLATION: i32 = 33;

            // SAFETY: file is a valid open handle; OVERLAPPED is correctly laid out and stored
            // in this guard for the whole lock lifetime. The operation is immediate, not pending.
            // It locks byte 4096 of the persistent lock file.
            let result = unsafe {
                LockFileEx(
                    self.file.as_raw_handle() as *mut std::ffi::c_void,
                    LOCKFILE_FAIL_IMMEDIATELY | LOCKFILE_EXCLUSIVE_LOCK,
                    0,
                    1,
                    0,
                    &mut self.overlapped,
                )
            };
            if result == 0 {
                let error = io::Error::last_os_error();
                if error.raw_os_error() == Some(ERROR_LOCK_VIOLATION) {
                    return Err(io::Error::new(io::ErrorKind::WouldBlock, error));
                }
                return Err(error);
            }
            return Ok(());
        }

        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;

            const LOCK_EX: i32 = 2;
            const LOCK_NB: i32 = 4;

            // SAFETY: raw fd is borrowed from a live File; flock doesn't retain the pointer.
            let result = unsafe { flock(self.file.as_raw_fd(), LOCK_EX | LOCK_NB) };
            if result == 0 {
                return Ok(());
            }
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::WouldBlock {
                return Err(io::Error::new(io::ErrorKind::WouldBlock, error));
            }
            return Err(error);
        }

        #[cfg(not(any(windows, unix)))]
        {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "OS-backed writer locking is unsupported on this target",
            ))
        }
    }
}

#[cfg(windows)]
#[repr(C)]
struct WindowsOverlapped {
    internal: usize,
    internal_high: usize,
    offset: u32,
    offset_high: u32,
    event: *mut std::ffi::c_void,
}

#[cfg(windows)]
impl Default for WindowsOverlapped {
    fn default() -> Self {
        Self {
            internal: 0,
            internal_high: 0,
            // Reserve byte 4096 as the persistent lock range; file contents are not used.
            offset: 4096,
            offset_high: 0,
            event: std::ptr::null_mut(),
        }
    }
}

impl Drop for StoreWriterLock {
    fn drop(&mut self) {
        if !self.locked {
            return;
        }
        #[cfg(windows)]
        {
            use std::os::windows::io::AsRawHandle;
            // SAFETY: the same file handle and byte range were successfully locked by this guard.
            unsafe {
                let _ = UnlockFileEx(
                    self.file.as_raw_handle() as *mut std::ffi::c_void,
                    0,
                    1,
                    0,
                    &mut self.overlapped,
                );
            }
        }
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            const LOCK_UN: i32 = 8;
            // SAFETY: raw fd is borrowed from this guard's live file handle.
            unsafe {
                let _ = flock(self.file.as_raw_fd(), LOCK_UN);
            }
        }
        self.locked = false;
    }
}

#[cfg(windows)]
#[link(name = "kernel32")]
extern "system" {
    fn LockFileEx(
        file: *mut std::ffi::c_void,
        flags: u32,
        reserved: u32,
        bytes_low: u32,
        bytes_high: u32,
        overlapped: *mut WindowsOverlapped,
    ) -> i32;
    fn UnlockFileEx(
        file: *mut std::ffi::c_void,
        reserved: u32,
        bytes_low: u32,
        bytes_high: u32,
        overlapped: *mut WindowsOverlapped,
    ) -> i32;
}

#[cfg(unix)]
extern "C" {
    fn flock(fd: i32, operation: i32) -> i32;
}

#[cfg(test)]
mod tests {
    use super::StoreWriterLock;
    use std::{
        fs,
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };

    fn temp_dir() -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "ain1_os_writer_lock_{}_{}",
            std::process::id(),
            nonce
        ));
        fs::create_dir_all(&path).unwrap();
        path
    }

    #[test]
    fn same_path_is_exclusive_and_persistent_lockfile_is_reusable_after_owner_drop() {
        let directory = temp_dir();
        let first = StoreWriterLock::acquire(&directory, "writer.lock").unwrap();
        let lock_path = directory.join("writer.lock");
        assert!(lock_path.exists());

        let second = StoreWriterLock::acquire(&directory, "writer.lock");
        assert!(
            second
                .as_ref()
                .is_err_and(|error| error.kind() == std::io::ErrorKind::WouldBlock),
            "a second writer must fail while the first OS lock is held"
        );

        drop(first);
        assert!(
            lock_path.exists(),
            "the persistent lock pathname must not be removed on unlock"
        );
        let reopened = StoreWriterLock::acquire(&directory, "writer.lock").unwrap();
        assert_eq!(fs::read(&lock_path).unwrap(), Vec::<u8>::new());
        drop(reopened);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn stale_diagnostic_bytes_do_not_affect_os_lock_acquisition_or_get_rewritten() {
        let directory = temp_dir();
        let lock_path = directory.join("writer.lock");
        fs::write(&lock_path, "pid=stale\n").unwrap();

        let lock = StoreWriterLock::acquire(&directory, "writer.lock").unwrap();
        assert_eq!(fs::read(&lock_path).unwrap(), b"pid=stale\n");
        drop(lock);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn hard_linked_lockfile_is_rejected_without_truncating_the_other_name() {
        let directory = temp_dir();
        let protected = directory.join("protected.data");
        let lock_path = directory.join("writer.lock");
        fs::write(&protected, b"do-not-truncate").unwrap();
        fs::hard_link(&protected, &lock_path).unwrap();

        let result = StoreWriterLock::acquire(&directory, "writer.lock");
        assert!(result.is_err_and(|error| error.kind() == std::io::ErrorKind::InvalidInput));
        assert_eq!(fs::read(&protected).unwrap(), b"do-not-truncate");
        fs::remove_dir_all(directory).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn lockfile_fifo_open_is_nonblocking_for_metadata_validation() {
        use std::{ffi::CString, os::unix::ffi::OsStrExt};

        let directory = temp_dir();
        let lock_path = directory.join("writer.lock");
        let c_path = CString::new(lock_path.as_os_str().as_bytes()).unwrap();
        let created = unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) };
        assert_eq!(
            created,
            0,
            "mkfifo failed: {}",
            std::io::Error::last_os_error()
        );

        // Simulate the race where a path that passed the earlier metadata check is replaced
        // before open. The opener must return a handle for type validation, never wait for a peer.
        let opened = super::open_lock_file(&lock_path)
            .expect("O_NONBLOCK must prevent a FIFO lock path from hanging open");
        assert!(!super::safe_lock_file_metadata(&opened.metadata().unwrap()));
        drop(opened);
        fs::remove_dir_all(directory).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_lockfile_is_rejected_without_touching_its_target() {
        let directory = temp_dir();
        let protected = directory.join("protected.data");
        let lock_path = directory.join("writer.lock");
        fs::write(&protected, b"do-not-truncate").unwrap();
        std::os::unix::fs::symlink(&protected, &lock_path).unwrap();

        let result = StoreWriterLock::acquire(&directory, "writer.lock");
        assert!(result.is_err());
        assert_eq!(fs::read(&protected).unwrap(), b"do-not-truncate");
        fs::remove_dir_all(directory).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn reparse_point_lockfile_is_rejected_when_file_symlinks_are_available() {
        let directory = temp_dir();
        let protected = directory.join("protected.data");
        let lock_path = directory.join("writer.lock");
        fs::write(&protected, b"do-not-truncate").unwrap();
        if std::os::windows::fs::symlink_file(&protected, &lock_path).is_err() {
            fs::remove_dir_all(directory).unwrap();
            return;
        }

        let result = StoreWriterLock::acquire(&directory, "writer.lock");
        assert!(result.is_err());
        assert_eq!(fs::read(&protected).unwrap(), b"do-not-truncate");
        fs::remove_dir_all(directory).unwrap();
    }
}
