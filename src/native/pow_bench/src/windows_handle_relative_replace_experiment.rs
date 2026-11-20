//! Experimental Windows handle-relative publication for isolated STH1-style files.
//!
//! The source object is opened relative to a retained directory handle. The final
//! rename uses NtSetInformationFile(FileRenameInformation) on that source handle,
//! with RootDirectory set to the retained destination-directory handle and a
//! single-component destination name. This avoids reopening either source or
//! destination by a full pathname during publication.
//!
//! This is a test-only experiment. It does not qualify ancestor containment,
//! volume identity, ACL policy, directory durability, or whole-volume rollback.

#[cfg(windows)]
mod imp {
    use std::{
        ffi::c_void,
        fs::File,
        io::{self, Read, Seek, SeekFrom, Write},
        mem::{offset_of, size_of},
        os::windows::ffi::OsStrExt,
        os::windows::io::{AsRawHandle, FromRawHandle, RawHandle},
        path::Path,
        ptr,
    };

    type Handle = *mut c_void;

    const OBJ_CASE_INSENSITIVE: u32 = 0x0000_0040;
    const OBJ_DONT_REPARSE: u32 = 0x0000_1000;
    const FILE_READ_DATA: u32 = 0x0000_0001;
    const FILE_WRITE_DATA: u32 = 0x0000_0002;
    const FILE_ADD_FILE: u32 = 0x0000_0002;
    const FILE_TRAVERSE: u32 = 0x0000_0020;
    const FILE_READ_ATTRIBUTES: u32 = 0x0000_0080;
    const DELETE: u32 = 0x0001_0000;
    const SYNCHRONIZE: u32 = 0x0010_0000;
    const FILE_SHARE_READ: u32 = 0x0000_0001;
    const FILE_SHARE_WRITE: u32 = 0x0000_0002;
    const FILE_SHARE_DELETE: u32 = 0x0000_0004;
    const FILE_ATTRIBUTE_NORMAL: u32 = 0x0000_0080;
    const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x0000_0010;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
    const FILE_ATTRIBUTE_TAG_INFO_CLASS: i32 = 9;
    const FILE_ID_INFO_CLASS: i32 = 18;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    const OPEN_EXISTING: u32 = 3;
    const FILE_OPEN: u32 = 1;
    const FILE_CREATE: u32 = 2;
    const FILE_NON_DIRECTORY_FILE: u32 = 0x0000_0040;
    const FILE_SYNCHRONOUS_IO_NONALERT: u32 = 0x0000_0020;
    const FILE_TYPE_DISK: u32 = 1;
    const INVALID_HANDLE_VALUE: Handle = -1isize as Handle;

    #[repr(C)]
    struct UnicodeString {
        length: u16,
        maximum_length: u16,
        buffer: *mut u16,
    }

    #[repr(C)]
    struct ObjectAttributes {
        length: u32,
        root_directory: Handle,
        object_name: *mut UnicodeString,
        attributes: u32,
        security_descriptor: *mut c_void,
        security_quality_of_service: *mut c_void,
    }

    #[repr(C)]
    union IoStatusValue {
        status: i32,
        pointer: *mut c_void,
    }

    #[repr(C)]
    struct IoStatusBlock {
        status: IoStatusValue,
        information: usize,
    }

    #[repr(C)]
    struct FileAttributeTagInfo {
        file_attributes: u32,
        reparse_tag: u32,
    }
    #[repr(C)]
    struct FileIdInfo {
        volume_serial_number: u64,
        file_id: [u8; 16],
    }

    // The first four bytes are the ReplaceIfExists / Flags union. repr(C)
    // supplies the architecture-specific HANDLE alignment before RootDirectory.
    #[repr(C)]
    struct FileRenameInfo {
        replace_if_exists: u32,
        root_directory: Handle,
        file_name_length: u32,
        file_name: [u16; 1],
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
    }

    #[link(name = "ntdll")]
    unsafe extern "system" {
        fn NtSetInformationFile(
            file: Handle,
            io_status_block: *mut IoStatusBlock,
            info: *mut c_void,
            length: u32,
            information_class: u32,
        ) -> i32;
        fn NtCreateFile(
            file_handle: *mut Handle,
            desired_access: u32,
            object_attributes: *mut ObjectAttributes,
            io_status_block: *mut IoStatusBlock,
            allocation_size: *mut i64,
            file_attributes: u32,
            share_access: u32,
            create_disposition: u32,
            create_options: u32,
            ea_buffer: *mut c_void,
            ea_length: u32,
        ) -> i32;
    }

    fn validate_component(name: &str) -> io::Result<Vec<u16>> {
        if name.is_empty()
            || name == "."
            || name == ".."
            || name.ends_with('.')
            || name.ends_with(' ')
            || name.contains(['\\', '/', ':', '\0'])
            || name.chars().any(char::is_control)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "destination must be one ordinary Windows filename component",
            ));
        }
        let encoded: Vec<u16> = name.encode_utf16().collect();
        if encoded.is_empty() || encoded.len() > (u16::MAX as usize / 2) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "destination filename length is invalid",
            ));
        }
        Ok(encoded)
    }

    /// Open one existing temporary directory and retain its exact Win32 handle.
    /// This checks the final component only; caller-provided ancestors are not qualified.
    pub fn open_test_directory(path: &Path) -> io::Result<File> {
        let mut wide: Vec<u16> = path.as_os_str().encode_wide().collect();
        if wide.contains(&0) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "path contains NUL",
            ));
        }
        wide.push(0);
        let raw = unsafe {
            CreateFileW(
                wide.as_ptr(),
                FILE_READ_ATTRIBUTES | FILE_TRAVERSE | FILE_ADD_FILE | SYNCHRONIZE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                ptr::null_mut(),
                OPEN_EXISTING,
                FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
                ptr::null_mut(),
            )
        };
        if raw == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        let handle = unsafe { File::from_raw_handle(raw as RawHandle) };
        if unsafe { GetFileType(handle.as_raw_handle() as Handle) } != FILE_TYPE_DISK {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "destination directory is not a disk filesystem object",
            ));
        }
        let mut tag = FileAttributeTagInfo {
            file_attributes: 0,
            reparse_tag: 0,
        };
        if unsafe {
            GetFileInformationByHandleEx(
                handle.as_raw_handle() as Handle,
                FILE_ATTRIBUTE_TAG_INFO_CLASS,
                (&mut tag as *mut FileAttributeTagInfo).cast(),
                size_of::<FileAttributeTagInfo>() as u32,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        if tag.file_attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
            || tag.file_attributes & FILE_ATTRIBUTE_DIRECTORY == 0
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "destination handle is a reparse point or not a directory",
            ));
        }
        Ok(handle)
    }

    /// Open or create one file relative to a retained directory handle.
    pub fn open_child_relative(
        parent: &File,
        name: &str,
        create_new: bool,
        for_publication: bool,
    ) -> io::Result<File> {
        let mut encoded = validate_component(name)?;
        let byte_len = encoded
            .len()
            .checked_mul(size_of::<u16>())
            .and_then(|value| u16::try_from(value).ok())
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "name too long"))?;
        let mut unicode_name = UnicodeString {
            length: byte_len,
            maximum_length: byte_len,
            buffer: encoded.as_mut_ptr(),
        };
        let mut attributes = ObjectAttributes {
            length: size_of::<ObjectAttributes>() as u32,
            root_directory: parent.as_raw_handle() as Handle,
            object_name: &mut unicode_name,
            attributes: OBJ_CASE_INSENSITIVE | OBJ_DONT_REPARSE,
            security_descriptor: ptr::null_mut(),
            security_quality_of_service: ptr::null_mut(),
        };
        let desired_access = if for_publication {
            FILE_WRITE_DATA | FILE_READ_DATA | FILE_READ_ATTRIBUTES | DELETE | SYNCHRONIZE
        } else {
            FILE_READ_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE
        };
        let mut raw: Handle = ptr::null_mut();
        let mut status = IoStatusBlock {
            status: IoStatusValue { status: 0 },
            information: 0,
        };
        let result = unsafe {
            NtCreateFile(
                &mut raw,
                desired_access,
                &mut attributes,
                &mut status,
                ptr::null_mut(),
                FILE_ATTRIBUTE_NORMAL,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                if create_new { FILE_CREATE } else { FILE_OPEN },
                FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
                ptr::null_mut(),
                0,
            )
        };
        if result < 0 {
            return Err(io::Error::from_raw_os_error(result));
        }
        if raw.is_null() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "NtCreateFile returned success without a handle",
            ));
        }
        Ok(unsafe { File::from_raw_handle(raw as RawHandle) })
    }

    /// Rename the already-open source file to a single name relative to the
    /// retained destination directory handle. Source must have DELETE access.
    pub fn rename_source_handle_relative(
        source: &File,
        destination_directory: &File,
        destination_name: &str,
        replace_if_exists: bool,
    ) -> io::Result<()> {
        let encoded = validate_component(destination_name)?;
        let name_bytes = encoded
            .len()
            .checked_mul(size_of::<u16>())
            .and_then(|value| u32::try_from(value).ok())
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "name too long"))?;
        let name_offset = offset_of!(FileRenameInfo, file_name);
        let buffer_size = name_offset
            .checked_add((encoded.len() + 1) * size_of::<u16>())
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "buffer overflow"))?;
        let word_count = buffer_size
            .checked_add(size_of::<usize>() - 1)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "buffer overflow"))?
            / size_of::<usize>();
        let mut storage = vec![0usize; word_count];
        let info = storage.as_mut_ptr().cast::<FileRenameInfo>();
        unsafe {
            ptr::write(
                info,
                FileRenameInfo {
                    replace_if_exists: u32::from(replace_if_exists),
                    root_directory: destination_directory.as_raw_handle() as Handle,
                    file_name_length: name_bytes,
                    file_name: [0],
                },
            );
            ptr::copy_nonoverlapping(
                encoded.as_ptr(),
                (*info).file_name.as_mut_ptr(),
                encoded.len(),
            );
        }
        let buffer_size = u32::try_from(buffer_size)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "rename buffer too large"))?;
        let mut io_status = IoStatusBlock {
            status: IoStatusValue { status: 0 },
            information: 0,
        };
        let status = unsafe {
            NtSetInformationFile(
                source.as_raw_handle() as Handle,
                &mut io_status,
                info.cast(),
                buffer_size,
                10, // FileRenameInformation in the Native API enum.
            )
        };
        if status < 0 {
            return Err(io::Error::from_raw_os_error(status));
        }
        Ok(())
    }

    pub fn file_identity(file: &File) -> io::Result<(u64, [u8; 16])> {
        let mut info = FileIdInfo {
            volume_serial_number: 0,
            file_id: [0; 16],
        };
        let result = unsafe {
            GetFileInformationByHandleEx(
                file.as_raw_handle() as Handle,
                FILE_ID_INFO_CLASS,
                (&mut info as *mut FileIdInfo).cast(),
                size_of::<FileIdInfo>() as u32,
            )
        };
        if result == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok((info.volume_serial_number, info.file_id))
    }
    pub fn read_all(file: &mut File) -> io::Result<Vec<u8>> {
        file.seek(SeekFrom::Start(0))?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        Ok(bytes)
    }

    pub fn write_and_sync(file: &mut File, bytes: &[u8]) -> io::Result<()> {
        file.write_all(bytes)?;
        file.flush()?;
        file.sync_all()
    }
}

#[cfg(all(test, windows))]
mod tests {
    use super::imp::{
        file_identity, open_child_relative, open_test_directory, read_all,
        rename_source_handle_relative, write_and_sync,
    };
    use std::{
        fs, io,
        sync::atomic::{AtomicU64, Ordering},
    };

    static NEXT_TEST_ID: AtomicU64 = AtomicU64::new(1);

    fn temp_root() -> std::path::PathBuf {
        let sequence = NEXT_TEST_ID.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "qrun-handle-relative-publish-{}-{sequence}",
            std::process::id()
        ))
    }

    #[test]
    fn publishes_exact_open_source_to_existing_name_relative_to_retained_directory() {
        let root = temp_root();
        fs::create_dir(&root).unwrap();
        let destination = root.join("signers.sth1");
        fs::write(&destination, b"old committed state").unwrap();

        let directory_handle = open_test_directory(&root).unwrap();
        let mut source =
            open_child_relative(&directory_handle, ".signers.sth1.synthetic.tmp", true, true)
                .unwrap();
        write_and_sync(&mut source, b"new committed state").unwrap();
        let source_identity = file_identity(&source).unwrap();
        rename_source_handle_relative(&source, &directory_handle, "signers.sth1", true).unwrap();
        let mut published =
            open_child_relative(&directory_handle, "signers.sth1", false, false).unwrap();
        assert_eq!(file_identity(&published).unwrap(), source_identity);
        assert_eq!(read_all(&mut published).unwrap(), b"new committed state");

        assert_eq!(fs::read(&destination).unwrap(), b"new committed state");
        assert_eq!(
            read_all(&mut source).unwrap(),
            b"new committed state",
            "the retained source handle must remain the exact object published at the target name"
        );

        drop(source);
        drop(directory_handle);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rejects_traversal_and_stream_names_before_issuing_rename() {
        let root = temp_root();
        fs::create_dir(&root).unwrap();
        let directory_handle = open_test_directory(&root).unwrap();
        let mut source = open_child_relative(&directory_handle, "staged.tmp", true, true).unwrap();
        write_and_sync(&mut source, b"still staged").unwrap();

        for invalid in ["", ".", "..", "../outside", "child\\state", "state:stream"] {
            assert_eq!(
                rename_source_handle_relative(&source, &directory_handle, invalid, true)
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::InvalidInput,
                "invalid target component: {invalid:?}"
            );
        }
        assert_eq!(read_all(&mut source).unwrap(), b"still staged");

        drop(source);
        drop(directory_handle);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn refuses_existing_destination_when_replace_flag_is_false() {
        let root = temp_root();
        fs::create_dir(&root).unwrap();
        let destination = root.join("state.sth1");
        fs::write(&destination, b"old").unwrap();
        let directory_handle = open_test_directory(&root).unwrap();
        let mut source = open_child_relative(&directory_handle, "staged.tmp", true, true).unwrap();
        write_and_sync(&mut source, b"new").unwrap();

        let result = rename_source_handle_relative(&source, &directory_handle, "state.sth1", false);
        assert_eq!(
            result.unwrap_err().raw_os_error(),
            Some(0xC000_0035_u32 as i32)
        );
        assert_eq!(fs::read(&destination).unwrap(), b"old");
        assert_eq!(read_all(&mut source).unwrap(), b"new");

        drop(source);
        drop(directory_handle);
        fs::remove_dir_all(root).unwrap();
    }
}

#[cfg(not(windows))]
// Keep the experiment unavailable rather than providing a pathname-based fallback.
mod imp {}
