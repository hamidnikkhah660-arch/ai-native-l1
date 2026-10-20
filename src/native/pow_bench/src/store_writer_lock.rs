//! OS-backed exclusive writer lock for durable candidate stores.
//!
//! The lock file is intentionally persistent. Ownership is the OS lock on a reserved byte range,
//! not the PID text or existence of the pathname. Closing the file handle (including on process
//! termination) releases ownership; the next opener can safely reuse the same lock file.

use std::{
    fs::{File, OpenOptions},
    io::{self, Seek, SeekFrom, Write},
    path::Path,
    process,
};

pub(crate) struct StoreWriterLock {
    file: File,
    locked: bool,
    #[cfg(windows)]
    overlapped: WindowsOverlapped,
}

impl StoreWriterLock {
    pub(crate) fn acquire(directory: &Path, file_name: &str) -> io::Result<Self> {
        let path = directory.join(file_name);
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)?;

        let mut lock = Self {
            file,
            locked: false,
            #[cfg(windows)]
            overlapped: WindowsOverlapped::default(),
        };
        lock.lock_exclusive()?;
        lock.locked = true;

        // Write diagnostic ownership only after acquiring the OS lock. It is never used as
        // the locking primitive or as proof that a prior PID is dead.
        lock.file.set_len(0)?;
        lock.file.seek(SeekFrom::Start(0))?;
        lock.file
            .write_all(format!("pid={}\n", process::id()).as_bytes())?;
        lock.file.sync_all()?;
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
            // It locks byte 4096, separate from the diagnostic PID header rewritten at offset 0.
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
            // Reserve byte 4096 for locking so rewriting/truncating the diagnostic PID header
            // at the beginning of the file does not overlap the locked byte range.
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
        let content = fs::read_to_string(&lock_path).unwrap();
        assert_eq!(content, format!("pid={}\n", std::process::id()));
        drop(reopened);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn stale_pid_text_does_not_prevent_os_lock_acquisition() {
        let directory = temp_dir();
        let lock_path = directory.join("writer.lock");
        fs::write(&lock_path, "pid=stale\n").unwrap();

        let lock = StoreWriterLock::acquire(&directory, "writer.lock").unwrap();
        assert_eq!(
            fs::read_to_string(&lock_path).unwrap(),
            format!("pid={}\n", std::process::id())
        );
        drop(lock);
        fs::remove_dir_all(directory).unwrap();
    }
}
