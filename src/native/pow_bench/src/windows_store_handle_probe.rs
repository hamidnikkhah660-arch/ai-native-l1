//! Retained-handle Win32 probe for the final store-path component.
//!
//! This is deliberately NOT a complete path qualifier. It opens the final
//! component with FILE_FLAG_OPEN_REPARSE_POINT, checks that exact handle, and
//! retains it. Ancestor traversal, physical-volume identity, and effective ACL
//! evaluation are not established here; callers must not turn this probe into
//! complete WindowsStorePathEvidence or use it to authorize production I/O.

#[cfg(windows)]
mod imp {
    use super::StoreObjectKind;
    use std::ffi::c_void;
    use std::fs::File;
    use std::io;
    use std::mem::MaybeUninit;
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::{FromRawHandle, RawHandle};
    use std::path::Path;

    type Handle = *mut c_void;
    const INVALID_HANDLE_VALUE: Handle = -1isize as Handle;
    const FILE_READ_ATTRIBUTES: u32 = 0x0080;
    // Deliberately omit FILE_SHARE_DELETE while a trusted root candidate is retained.
    const FILE_SHARE_READ_WRITE: u32 = 0x0000_0003;
    const OPEN_EXISTING: u32 = 3;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    const FILE_ATTRIBUTE_DEVICE: u32 = 0x40;
    const FILE_TYPE_DISK: u32 = 1;
    const FILE_ATTRIBUTE_TAG_INFO_CLASS: i32 = 9;
    const FILE_ID_INFO_CLASS: i32 = 18;
    const FILE_NAME_NORMALIZED: u32 = 0;
    const VOLUME_NAME_GUID: u32 = 1;

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct FileAttributeTagInfo {
        file_attributes: u32,
        reparse_tag: u32,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct FileIdInfo {
        volume_serial_number: u64,
        file_id: [u8; 16],
    }
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn CreateFileW(
            file_name: *const u16,
            desired_access: u32,
            share_mode: u32,
            security_attributes: *mut c_void,
            creation_disposition: u32,
            flags_and_attributes: u32,
            template_file: Handle,
        ) -> Handle;
        fn GetFileType(file: Handle) -> u32;
        fn GetFileInformationByHandleEx(
            file: Handle,
            class: i32,
            info: *mut c_void,
            size: u32,
        ) -> i32;
        fn GetFinalPathNameByHandleW(
            file: Handle,
            file_path: *mut u16,
            buffer_length: u32,
            flags: u32,
        ) -> u32;
    }

    /// Volume serial plus 128-bit file ID queried from one retained file handle.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct WindowsStoreHandleIdentity {
        pub volume_serial_number: u64,
        pub file_id: [u8; 16],
    }

    /// An open handle and facts queried from that exact handle.
    ///
    /// The handle is retained for the lifetime of this value. It was opened
    /// with FILE_READ_ATTRIBUTES only; this is a qualification probe, not a
    /// general-purpose read/write store handle.
    #[derive(Debug)]
    pub struct WindowsStoreHandleProbe {
        handle: File,
        final_path: String,
        object_kind: StoreObjectKind,
    }

    impl WindowsStoreHandleProbe {
        pub fn handle(&self) -> &File {
            &self.handle
        }

        pub fn final_path(&self) -> &str {
            &self.final_path
        }

        /// Return the 128-bit file ID and volume serial from this exact retained handle.
        pub fn identity(&self) -> io::Result<WindowsStoreHandleIdentity> {
            let mut info = FileIdInfo {
                volume_serial_number: 0,
                file_id: [0; 16],
            };
            // SAFETY: the retained file handle and writable FILE_ID_INFO buffer are valid.
            let ok = unsafe {
                GetFileInformationByHandleEx(
                    self.handle.as_raw_handle() as Handle,
                    FILE_ID_INFO_CLASS,
                    (&mut info as *mut FileIdInfo).cast(),
                    std::mem::size_of::<FileIdInfo>() as u32,
                )
            };
            if ok == 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(WindowsStoreHandleIdentity {
                volume_serial_number: info.volume_serial_number,
                file_id: info.file_id,
            })
        }
        pub fn object_kind(&self) -> StoreObjectKind {
            self.object_kind
        }

        /// Explicitly false until ancestor, volume, and ACL providers are implemented.
        pub const fn is_complete_for_store_policy(&self) -> bool {
            false
        }
    }

    /// Opens and inspects only the final path component without following a
    /// reparse point at that component. Ancestor components may still have
    /// been traversed by the Win32 path parser and are NOT qualified.
    pub fn open_final_component(path: &Path) -> io::Result<WindowsStoreHandleProbe> {
        let mut wide: Vec<u16> = path.as_os_str().encode_wide().collect();
        if wide.contains(&0) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "path contains NUL",
            ));
        }
        wide.push(0);
        let flags = FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS;
        // SAFETY: `wide` is NUL-terminated and remains alive for the call; all
        // other pointers are null by API contract. The returned HANDLE is
        // checked and immediately transferred to File for RAII ownership.
        let raw = unsafe {
            CreateFileW(
                wide.as_ptr(),
                FILE_READ_ATTRIBUTES,
                FILE_SHARE_READ_WRITE,
                std::ptr::null_mut(),
                OPEN_EXISTING,
                flags,
                std::ptr::null_mut(),
            )
        };
        if raw == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `raw` is a valid, newly-created Win32 handle uniquely owned here.
        let handle = unsafe { File::from_raw_handle(raw as RawHandle) };
        // Reject non-disk handles (pipes, character devices, etc.) before classifying.
        // SAFETY: `handle` is a live HANDLE owned by this function.
        let file_type = unsafe { GetFileType(handle.as_raw_handle() as Handle) };
        if file_type != FILE_TYPE_DISK {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "final component is not a disk file-system object",
            ));
        }

        let mut info = MaybeUninit::<FileAttributeTagInfo>::zeroed();
        // SAFETY: `info` points to a correctly-sized writable FILE_ATTRIBUTE_TAG_INFO.
        let ok = unsafe {
            GetFileInformationByHandleEx(
                handle.as_raw_handle(),
                FILE_ATTRIBUTE_TAG_INFO_CLASS,
                info.as_mut_ptr().cast(),
                std::mem::size_of::<FileAttributeTagInfo>() as u32,
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: successful GetFileInformationByHandleEx initialized the structure.
        let info = unsafe { info.assume_init() };
        if info.file_attributes & FILE_ATTRIBUTE_DEVICE != 0 {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "final component is a device object",
            ));
        }
        if info.file_attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "final component is a reparse point",
            ));
        }
        let object_kind = if info.file_attributes & FILE_ATTRIBUTE_DIRECTORY != 0 {
            StoreObjectKind::Directory
        } else {
            StoreObjectKind::RegularFile
        };
        let final_path = final_path_for_handle(handle.as_raw_handle())?;
        Ok(WindowsStoreHandleProbe {
            handle,
            final_path,
            object_kind,
        })
    }

    use std::os::windows::io::AsRawHandle;

    fn final_path_for_handle(handle: RawHandle) -> io::Result<String> {
        let mut buffer = vec![0u16; 512];
        loop {
            // SAFETY: buffer is writable for `buffer.len()` UTF-16 code units and
            // the handle remains live in the caller for this synchronous call.
            let count = unsafe {
                GetFinalPathNameByHandleW(
                    handle as Handle,
                    buffer.as_mut_ptr(),
                    buffer.len() as u32,
                    FILE_NAME_NORMALIZED | VOLUME_NAME_GUID,
                )
            };
            if count == 0 {
                return Err(io::Error::last_os_error());
            }
            if count as usize >= buffer.len() {
                buffer.resize(count as usize + 1, 0);
                continue;
            }
            buffer.truncate(count as usize);
            return String::from_utf16(&buffer).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Win32 returned invalid UTF-16 path",
                )
            });
        }
    }
}

#[cfg(windows)]
pub use imp::{open_final_component, WindowsStoreHandleIdentity, WindowsStoreHandleProbe};

#[cfg(not(windows))]
/// Windows-only API; this platform deliberately supplies no fallback provider.
pub fn open_final_component(_path: &std::path::Path) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "Win32 handle probe is available only on Windows",
    ))
}

use crate::windows_store_path_qualifier::StoreObjectKind;

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Write;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_root() -> std::path::PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("qrun-handle-probe-{}-{nonce}", std::process::id()))
    }

    #[test]
    fn opens_regular_file_and_retains_the_inspected_handle() {
        let root = temp_root();
        fs::create_dir(&root).unwrap();
        let path = root.join("probe.bin");
        let mut f = fs::File::create(&path).unwrap();
        f.write_all(b"synthetic probe data").unwrap();
        drop(f);

        let probe = open_final_component(&path).unwrap();
        assert_eq!(probe.object_kind(), StoreObjectKind::RegularFile);
        assert!(probe
            .final_path()
            .to_ascii_lowercase()
            .contains("probe.bin"));
        assert!(!probe.is_complete_for_store_policy());
        assert!(probe.handle().metadata().unwrap().is_file());
        drop(probe);
        fs::remove_file(path).unwrap();
        fs::remove_dir(root).unwrap();
    }

    #[test]
    fn opens_directory_with_backup_semantics_but_does_not_claim_full_qualification() {
        let root = temp_root();
        fs::create_dir(&root).unwrap();
        let probe = open_final_component(&root).unwrap();
        assert_eq!(probe.object_kind(), StoreObjectKind::Directory);
        assert!(!probe.is_complete_for_store_policy());
        assert!(probe.handle().metadata().unwrap().is_dir());
        drop(probe);
        fs::remove_dir(root).unwrap();
    }

    #[test]
    fn retained_root_handle_reports_identity_across_namespace_rename_attempt() {
        let root = temp_root();
        let moved = root.with_file_name(format!(
            "{}-moved",
            root.file_name().unwrap().to_string_lossy()
        ));
        fs::create_dir(&root).unwrap();

        let probe = open_final_component(&root).unwrap();
        let first_identity = probe.identity().unwrap();
        assert_ne!(first_identity.file_id, [0; 16]);

        let second_probe = open_final_component(&root).unwrap();
        assert_eq!(second_probe.identity().unwrap(), first_identity);

        // A handle that omits FILE_SHARE_DELETE is not sufficient by itself:
        // the filesystem may authorize directory rename through FILE_DELETE_CHILD
        // on the parent. Record the actual host behavior without assuming either route.
        match fs::rename(&root, &moved) {
            Ok(()) => {
                eprintln!("OBSERVED: parent FILE_DELETE_CHILD route renamed the root despite retained no-share-delete handles");
                assert!(!root.exists());
                let moved_probe = open_final_component(&moved).unwrap();
                assert_eq!(moved_probe.identity().unwrap(), first_identity);
                assert_eq!(probe.identity().unwrap(), first_identity);
                drop(moved_probe);
            }
            Err(error) if error.raw_os_error() == Some(32) => {
                eprintln!("OBSERVED: retained root handle blocked namespace rename with sharing violation");
                assert!(root.exists());
            }
            Err(error) => panic!("unexpected root rename error: {error}"),
        }

        drop(second_probe);
        drop(probe);
        if moved.exists() {
            fs::remove_dir(moved).unwrap();
        } else {
            fs::remove_dir(root).unwrap();
        }
    }
    #[test]
    fn rejects_a_final_component_that_is_a_reparse_point_when_supported() {
        let root = temp_root();
        fs::create_dir(&root).unwrap();
        let target = root.join("target");
        let link = root.join("link");
        fs::write(&target, b"synthetic").unwrap();
        match std::os::windows::fs::symlink_file(&target, &link) {
            Ok(()) => {
                let error = open_final_component(&link).unwrap_err();
                assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
                fs::remove_file(link).unwrap();
            }
            Err(e)
                if e.raw_os_error() == Some(1314)
                    || e.kind() == std::io::ErrorKind::PermissionDenied
                    || e.kind() == std::io::ErrorKind::Unsupported => {}
            Err(e) => panic!("unexpected symlink setup error: {e}"),
        }
        fs::remove_file(target).unwrap();
        fs::remove_dir(root).unwrap();
    }
    #[test]
    fn rejects_a_final_directory_junction_when_supported() {
        let root = temp_root();
        fs::create_dir(&root).unwrap();
        let target = root.join("target");
        let junction = root.join("junction");
        fs::create_dir(&target).unwrap();
        let output = std::process::Command::new("cmd.exe")
            .args(["/C", "mklink", "/J"])
            .arg(&junction)
            .arg(&target)
            .output()
            .unwrap();
        if output.status.success() {
            let error = open_final_component(&junction).unwrap_err();
            assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
            fs::remove_dir(&junction).unwrap();
        } else {
            let message = String::from_utf8_lossy(&output.stderr);
            eprintln!("junction creation unavailable; test skipped: {message}");
        }
        fs::remove_dir(target).unwrap();
        fs::remove_dir(root).unwrap();
    }
}
