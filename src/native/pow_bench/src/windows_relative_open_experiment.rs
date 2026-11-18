//! Experimental only: component-relative NtCreateFile opens from a retained root handle.
//!
//! This module records observed behavior on the current Windows host. It is not
//! wired into production stores and does not claim a documented race-free
//! containment guarantee. In particular, Microsoft has not published an
//! end-to-end guarantee for concurrent rename/replacement interleavings.

#[cfg(windows)]
mod imp {
    use std::ffi::c_void;
    use std::fs::File;
    use std::os::windows::io::{AsRawHandle, FromRawHandle, RawHandle};

    type Handle = *mut c_void;
    const FILE_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
    const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x0000_0010;
    const FILE_ATTRIBUTE_TAG_INFO_CLASS: i32 = 9;
    const FILE_READ_ATTRIBUTES: u32 = 0x0080;
    const SYNCHRONIZE: u32 = 0x0010_0000;
    const FILE_SHARE_READ: u32 = 0x0000_0001;
    const FILE_SHARE_WRITE: u32 = 0x0000_0002;
    const FILE_SHARE_DELETE: u32 = 0x0000_0004;
    const FILE_DIRECTORY_FILE: u32 = 0x0000_0001;
    const FILE_NON_DIRECTORY_FILE: u32 = 0x0000_0040;
    const FILE_SYNCHRONOUS_IO_NONALERT: u32 = 0x0000_0020;
    const FILE_OPEN: u32 = 1;

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
    #[repr(C)]
    struct FileAttributeTagInfo {
        file_attributes: u32,
        reparse_tag: u32,
    }
    #[repr(C)]
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

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetFileInformationByHandleEx(
            file: Handle,
            class: i32,
            info: *mut c_void,
            size: u32,
        ) -> i32;
    }
    #[link(name = "ntdll")]
    unsafe extern "system" {
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

    #[derive(Clone, Copy)]
    pub enum RelativeObjectKind {
        Directory,
        File,
    }

    /// Retains the root and every component handle in an experimental relative walk.
    /// This does not prevent a filesystem from moving an opened directory object.
    #[derive(Debug)]
    pub struct RelativePathHandleChain {
        handles: Vec<File>,
    }

    impl RelativePathHandleChain {
        pub fn final_handle(&self) -> &File {
            self.handles
                .last()
                .expect("chain always retains its root handle")
        }

        pub fn retained_component_count(&self) -> usize {
            self.handles.len().saturating_sub(1)
        }
    }

    /// Opens a sequence of single components relative to the preceding retained
    /// directory handle. Intermediate components must be directories; the final
    /// component uses `final_kind`. Every child open sets FILE_OPEN_REPARSE_POINT and
    /// omits FILE_SHARE_DELETE. This remains an experiment, not a race-free policy.
    pub fn open_path_chain_experimental(
        root: &File,
        components: &[&str],
        final_kind: RelativeObjectKind,
    ) -> Result<RelativePathHandleChain, i32> {
        if components.is_empty() {
            return Err(0xC000_0033_u32 as i32);
        }
        let root_clone = root
            .try_clone()
            .map_err(|error| error.raw_os_error().unwrap_or(0xC000_0001_u32 as i32))?;
        let mut handles = vec![root_clone];
        for (index, component) in components.iter().enumerate() {
            let is_final = index + 1 == components.len();
            let kind = if is_final {
                final_kind
            } else {
                RelativeObjectKind::Directory
            };
            let child = open_child_experimental(
                handles.last().expect("root handle retained"),
                component,
                kind,
                false,
            )?;
            handles.push(child);
        }
        Ok(RelativePathHandleChain { handles })
    }
    fn is_reserved_windows_component(component: &str) -> bool {
        let stem = component.split('.').next().unwrap_or(component);
        let upper = stem.to_ascii_uppercase();
        matches!(
            upper.as_str(),
            "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
        ) || (upper.len() == 4
            && (upper.starts_with("COM") || upper.starts_with("LPT"))
            && matches!(upper.as_bytes()[3], b'1'..=b'9'))
    }
    /// Opens exactly one child name relative to the supplied directory handle.
    /// This helper is intentionally confined to the experiment module.
    pub fn open_child_experimental(
        parent: &File,
        component: &str,
        kind: RelativeObjectKind,
        share_delete: bool,
    ) -> Result<File, i32> {
        if component.is_empty()
            || component == "."
            || component == ".."
            || component.contains(['\\', '/', ':', '\0'])
            || component.ends_with('.')
            || component.ends_with(' ')
            || component.chars().any(char::is_control)
            || is_reserved_windows_component(component)
        {
            return Err(0xC000_0033_u32 as i32); // STATUS_OBJECT_NAME_INVALID
        }
        let mut name: Vec<u16> = component.encode_utf16().collect();
        let byte_len = name.len().checked_mul(2).ok_or(0xC000_000D_u32 as i32)?;
        if name.len() > 255 {
            return Err(0xC000_0106_u32 as i32); // STATUS_NAME_TOO_LONG
        }
        name.push(0);
        let mut unicode_name = UnicodeString {
            length: byte_len as u16,
            maximum_length: (byte_len + 2) as u16,
            buffer: name.as_mut_ptr(),
        };
        let mut attributes = ObjectAttributes {
            length: std::mem::size_of::<ObjectAttributes>() as u32,
            root_directory: parent.as_raw_handle() as Handle,
            object_name: &mut unicode_name,
            // Use only the documented, ordinary OBJECT_ATTRIBUTES contract.
            attributes: 0,
            security_descriptor: std::ptr::null_mut(),
            security_quality_of_service: std::ptr::null_mut(),
        };
        let create_options = match kind {
            RelativeObjectKind::Directory => {
                FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_REPARSE_POINT
            }
            RelativeObjectKind::File => {
                FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_REPARSE_POINT
            }
        };
        let share_access =
            FILE_SHARE_READ | FILE_SHARE_WRITE | if share_delete { FILE_SHARE_DELETE } else { 0 };
        let mut raw: Handle = std::ptr::null_mut();
        let mut io_status = IoStatusBlock {
            status: IoStatusValue { status: 0 },
            information: 0,
        };
        // SAFETY: all structures and buffers remain live for the synchronous call;
        // ObjectName is one validated component and RootDirectory is a live handle.
        let status = unsafe {
            NtCreateFile(
                &mut raw,
                FILE_READ_ATTRIBUTES | SYNCHRONIZE,
                &mut attributes,
                &mut io_status,
                std::ptr::null_mut(),
                0,
                share_access,
                FILE_OPEN,
                create_options,
                std::ptr::null_mut(),
                0,
            )
        };
        if status < 0 {
            return Err(status);
        }
        if raw.is_null() {
            return Err(0xC000_0001_u32 as i32); // STATUS_UNSUCCESSFUL
        }
        // SAFETY: NtCreateFile returned STATUS_SUCCESS and transferred a new handle.
        let opened = unsafe { File::from_raw_handle(raw as RawHandle) };
        let mut tag = FileAttributeTagInfo {
            file_attributes: 0,
            reparse_tag: 0,
        };
        // FILE_OPEN_REPARSE_POINT opens the reparse object itself. Inspect this exact
        // handle and reject it before a caller can use it as the next parent.
        let tag_ok = unsafe {
            GetFileInformationByHandleEx(
                opened.as_raw_handle() as Handle,
                FILE_ATTRIBUTE_TAG_INFO_CLASS,
                (&mut tag as *mut FileAttributeTagInfo).cast(),
                std::mem::size_of::<FileAttributeTagInfo>() as u32,
            )
        };
        if tag_ok == 0 {
            return Err(std::io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or(0xC000_0001_u32 as i32));
        }
        if tag.file_attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(0xC000_050B_u32 as i32); // STATUS_REPARSE_POINT_ENCOUNTERED
        }
        let actual_is_directory = tag.file_attributes & FILE_ATTRIBUTE_DIRECTORY != 0;
        let expected_directory = matches!(kind, RelativeObjectKind::Directory);
        if actual_is_directory != expected_directory {
            return Err(if expected_directory {
                0xC000_0103_u32 as i32 // STATUS_NOT_A_DIRECTORY
            } else {
                0xC000_00BA_u32 as i32 // STATUS_FILE_IS_A_DIRECTORY
            });
        }
        Ok(opened)
    }
}

#[cfg(windows)]
pub use imp::{open_child_experimental, open_path_chain_experimental, RelativeObjectKind};

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_TEMP_ROOT_ID: AtomicU64 = AtomicU64::new(1);

    fn temp_root() -> std::path::PathBuf {
        let nonce = NEXT_TEMP_ROOT_ID.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!("qrun-relative-open-{}-{nonce}", std::process::id()))
    }

    #[cfg(windows)]
    #[test]
    fn opens_existing_directory_relative_to_a_win32_root_handle() {
        let root = temp_root();
        fs::create_dir(&root).unwrap();
        let child = root.join("child");
        fs::create_dir(&child).unwrap();
        let root_handle = crate::windows_store_handle_probe::open_final_component(&root).unwrap();
        let opened = open_child_experimental(
            root_handle.handle(),
            "child",
            RelativeObjectKind::Directory,
            true,
        )
        .unwrap();
        assert!(opened.metadata().unwrap().is_dir());
        drop(opened);
        drop(root_handle);
        fs::remove_dir(child).unwrap();
        fs::remove_dir(root).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn rejects_a_junction_during_component_relative_open() {
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
            let root_handle =
                crate::windows_store_handle_probe::open_final_component(&root).unwrap();
            let result = open_child_experimental(
                root_handle.handle(),
                "junction",
                RelativeObjectKind::Directory,
                true,
            );
            assert_eq!(result.unwrap_err(), 0xC000_050B_u32 as i32);
            drop(root_handle);
            fs::remove_dir(&junction).unwrap();
        } else {
            eprintln!(
                "junction creation unavailable; test skipped: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        fs::remove_dir(target).unwrap();
        fs::remove_dir(root).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn rejects_unsafe_and_reserved_windows_components() {
        let root = temp_root();
        fs::create_dir(&root).unwrap();
        let root_handle = crate::windows_store_handle_probe::open_final_component(&root).unwrap();
        for name in [
            "",
            ".",
            "..",
            "../escape",
            "child\\name",
            "child/name",
            "state:stream",
            "trailing.",
            "trailing ",
            "CON",
            "con.txt",
            "PRN.log",
            "AUX",
            "NUL.bin",
            "COM1",
            "LPT9.dat",
            "bad\u{0001}name",
        ] {
            assert_eq!(
                open_child_experimental(
                    root_handle.handle(),
                    name,
                    RelativeObjectKind::File,
                    false,
                )
                .unwrap_err(),
                0xC000_0033_u32 as i32,
                "unsafe Windows component must fail before native open: {name:?}"
            );
        }
        drop(root_handle);
        fs::remove_dir(root).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn rejects_file_directory_kind_mismatch_from_opened_handle_metadata() {
        let root = temp_root();
        fs::create_dir(&root).unwrap();
        let dir = root.join("dir");
        let file = root.join("file.bin");
        fs::create_dir(&dir).unwrap();
        fs::write(&file, b"synthetic").unwrap();
        let root_handle = crate::windows_store_handle_probe::open_final_component(&root).unwrap();

        assert_eq!(
            open_child_experimental(
                root_handle.handle(),
                "file.bin",
                RelativeObjectKind::Directory,
                false,
            )
            .unwrap_err(),
            0xC000_0103_u32 as i32
        );
        assert_eq!(
            open_child_experimental(root_handle.handle(), "dir", RelativeObjectKind::File, false,)
                .unwrap_err(),
            0xC000_00BA_u32 as i32
        );

        drop(root_handle);
        fs::remove_file(file).unwrap();
        fs::remove_dir(dir).unwrap();
        fs::remove_dir(root).unwrap();
    }
    #[cfg(windows)]
    #[test]
    fn refuses_multi_component_names() {
        let root = temp_root();
        fs::create_dir(&root).unwrap();
        let root_handle = crate::windows_store_handle_probe::open_final_component(&root).unwrap();
        let result = open_child_experimental(
            root_handle.handle(),
            "child\\..\\outside",
            RelativeObjectKind::Directory,
            true,
        );
        assert_eq!(result.unwrap_err(), 0xC000_0033_u32 as i32);
        drop(root_handle);
        fs::remove_dir(root).unwrap();
    }
    #[cfg(windows)]
    #[test]
    fn opens_a_regular_file_relative_to_the_root_handle() {
        let root = temp_root();
        fs::create_dir(&root).unwrap();
        let file_path = root.join("payload.bin");
        fs::write(&file_path, b"synthetic relative file").unwrap();
        let root_handle = crate::windows_store_handle_probe::open_final_component(&root).unwrap();
        let opened = open_child_experimental(
            root_handle.handle(),
            "payload.bin",
            RelativeObjectKind::File,
            true,
        )
        .unwrap();
        assert!(opened.metadata().unwrap().is_file());
        drop(opened);
        drop(root_handle);
        fs::remove_file(file_path).unwrap();
        fs::remove_dir(root).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn measures_whether_a_retained_child_handle_can_be_moved_outside_its_root() {
        let root = temp_root();
        let outside = root.with_file_name(format!(
            "{}-outside",
            root.file_name().unwrap().to_string_lossy()
        ));
        fs::create_dir(&root).unwrap();
        fs::create_dir(&outside).unwrap();
        let child = root.join("child");
        let moved_child = outside.join("moved-child");
        fs::create_dir(&child).unwrap();
        fs::write(child.join("marker.bin"), b"same opened directory object").unwrap();
        let root_handle = crate::windows_store_handle_probe::open_final_component(&root).unwrap();
        let child_handle = open_child_experimental(
            root_handle.handle(),
            "child",
            RelativeObjectKind::Directory,
            false,
        )
        .unwrap();
        let rename_while_open = fs::rename(&child, &moved_child);
        if rename_while_open.is_ok() {
            // The retained child handle still resolves its descendants after the
            // directory's pathname has been moved outside the original root.
            let marker = open_child_experimental(
                &child_handle,
                "marker.bin",
                RelativeObjectKind::File,
                true,
            )
            .expect("retained directory handle stopped resolving its own child");
            assert!(marker.metadata().unwrap().is_file());
            eprintln!("OBSERVED: rename outside root succeeded while child handle remained open without FILE_SHARE_DELETE; descendant open through retained handle also succeeded");
            drop(marker);
        } else {
            eprintln!("OBSERVED: this Windows/filesystem configuration blocked moving the child while the no-share-delete handle was open: {}", rename_while_open.unwrap_err());
        }
        drop(child_handle);
        drop(root_handle);
        fs::remove_dir_all(root).unwrap();
        fs::remove_dir_all(outside).unwrap();
    }
    #[cfg(windows)]
    #[test]
    fn walks_multiple_components_with_all_parent_handles_retained() {
        let root = temp_root();
        fs::create_dir_all(root.join("level-one").join("level-two")).unwrap();
        let payload = root.join("level-one").join("level-two").join("payload.bin");
        fs::write(&payload, b"synthetic path-chain payload").unwrap();
        let root_handle = crate::windows_store_handle_probe::open_final_component(&root).unwrap();
        let chain = open_path_chain_experimental(
            root_handle.handle(),
            &["level-one", "level-two", "payload.bin"],
            RelativeObjectKind::File,
        )
        .unwrap();
        assert_eq!(chain.retained_component_count(), 3);
        assert!(chain.final_handle().metadata().unwrap().is_file());
        drop(chain);
        drop(root_handle);
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn path_chain_rejects_reparse_point_in_an_intermediate_component() {
        let root = temp_root();
        fs::create_dir_all(&root).unwrap();
        let target = root.join("target");
        let junction = root.join("junction");
        fs::create_dir(&target).unwrap();
        fs::write(target.join("payload.bin"), b"outside target").unwrap();
        let output = std::process::Command::new("cmd.exe")
            .args(["/C", "mklink", "/J"])
            .arg(&junction)
            .arg(&target)
            .output()
            .unwrap();
        if output.status.success() {
            let root_handle =
                crate::windows_store_handle_probe::open_final_component(&root).unwrap();
            let result = open_path_chain_experimental(
                root_handle.handle(),
                &["junction", "payload.bin"],
                RelativeObjectKind::File,
            );
            assert_eq!(result.unwrap_err(), 0xC000_050B_u32 as i32);
            drop(root_handle);
            fs::remove_dir(&junction).unwrap();
        } else {
            eprintln!(
                "junction creation unavailable; test skipped: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        fs::remove_dir_all(target).unwrap();
        fs::remove_dir(root).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn path_chain_rejects_empty_and_traversal_components() {
        let root = temp_root();
        fs::create_dir(&root).unwrap();
        let child = root.join("child");
        fs::create_dir(&child).unwrap();
        let root_handle = crate::windows_store_handle_probe::open_final_component(&root).unwrap();
        assert_eq!(
            open_path_chain_experimental(root_handle.handle(), &[], RelativeObjectKind::Directory)
                .unwrap_err(),
            0xC000_0033_u32 as i32
        );
        assert_eq!(
            open_path_chain_experimental(
                root_handle.handle(),
                &["child", "..", "outside"],
                RelativeObjectKind::Directory
            )
            .unwrap_err(),
            0xC000_0033_u32 as i32
        );
        drop(root_handle);
        fs::remove_dir(child).unwrap();
        fs::remove_dir(root).unwrap();
    }
    #[cfg(windows)]
    #[test]
    fn parent_delete_child_and_object_delete_denies_block_directory_rename_escape() {
        use crate::windows_acl_snapshot_probe::{
            access_check_current_process_token, open_temp_handle, set_null_dacl_for_temp_test,
            set_object_deny_delete_for_temp_test, set_parent_deny_delete_child_for_temp_test,
        };
        const FILE_DELETE_CHILD: u32 = 0x0000_0040;
        const DELETE_RIGHT: u32 = 0x0001_0000;
        let root = temp_root();
        let outside = root.with_file_name(format!(
            "{}-outside",
            root.file_name().unwrap().to_string_lossy()
        ));
        fs::create_dir(&root).unwrap();
        fs::create_dir(&outside).unwrap();
        let child = root.join("child");
        let moved = outside.join("moved-child");
        fs::create_dir(&child).unwrap();
        fs::write(child.join("marker.bin"), b"synthetic rename control").unwrap();

        let parent_acl_handle = open_temp_handle(&root, true).unwrap();
        let child_acl_handle = open_temp_handle(&child, true).unwrap();
        let root_handle = crate::windows_store_handle_probe::open_final_component(&root).unwrap();
        let child_handle = open_child_experimental(
            root_handle.handle(),
            "child",
            RelativeObjectKind::Directory,
            false,
        )
        .unwrap();

        // Positive control: on this host, the open child handle alone did not block rename.
        let baseline_rename = fs::rename(&child, &moved);
        let baseline_rename_ok = baseline_rename.is_ok();
        let baseline_restore_ok = if baseline_rename_ok {
            fs::rename(&moved, &child).is_ok()
        } else {
            false
        };

        let parent_before =
            access_check_current_process_token(&parent_acl_handle, FILE_DELETE_CHILD);
        let child_before = access_check_current_process_token(&child_acl_handle, DELETE_RIGHT);
        let parent_set = set_parent_deny_delete_child_for_temp_test(&parent_acl_handle);
        let child_set = set_object_deny_delete_for_temp_test(&child_acl_handle);
        let parent_after =
            access_check_current_process_token(&parent_acl_handle, FILE_DELETE_CHILD);
        let child_after = access_check_current_process_token(&child_acl_handle, DELETE_RIGHT);
        let denied_rename = if parent_set.is_ok() && child_set.is_ok() {
            fs::rename(&child, &moved)
        } else {
            Ok(())
        };
        let child_acl_reset = if child_set.is_ok() {
            set_null_dacl_for_temp_test(&child_acl_handle)
        } else {
            Ok(())
        };
        let parent_acl_reset = if parent_set.is_ok() {
            set_null_dacl_for_temp_test(&parent_acl_handle)
        } else {
            Ok(())
        };

        eprintln!(
            "Rename ACL experiment: baseline_rename_ok={}, parent_delete_child_before={:?}, child_delete_before={:?}, parent_delete_child_after={:?}, child_delete_after={:?}, denied_rename_error={:?}",
            baseline_rename_ok,
            parent_before.as_ref().map(|value| value.allowed),
            child_before.as_ref().map(|value| value.allowed),
            parent_after.as_ref().map(|value| value.allowed),
            child_after.as_ref().map(|value| value.allowed),
            denied_rename.as_ref().err(),
        );

        drop(child_handle);
        drop(root_handle);
        drop(child_acl_handle);
        drop(parent_acl_handle);
        let _ = fs::remove_dir_all(root);
        let _ = fs::remove_dir_all(outside);

        assert!(
            baseline_rename_ok && baseline_restore_ok,
            "baseline rename control did not behave as observed on this host"
        );
        assert!(
            parent_set.is_ok(),
            "failed to install parent FILE_DELETE_CHILD deny: {:?}",
            parent_set.err()
        );
        assert!(
            child_set.is_ok(),
            "failed to install child DELETE deny: {:?}",
            child_set.err()
        );
        assert!(
            parent_before.is_ok(),
            "parent AccessCheck failed: {:?}",
            parent_before.err()
        );
        assert!(
            child_before.is_ok_and(|value| value.allowed),
            "child DELETE should be allowed before the deny DACL"
        );
        assert!(
            parent_after.is_ok_and(|value| !value.allowed),
            "parent FILE_DELETE_CHILD should be denied after DACL change"
        );
        assert!(
            child_after.is_ok_and(|value| !value.allowed),
            "child DELETE should be denied after DACL change"
        );
        assert!(denied_rename.is_err(), "rename unexpectedly succeeded despite parent FILE_DELETE_CHILD and child DELETE denies");
        assert!(child_acl_reset.is_ok(), "child temporary DACL reset failed");
        assert!(
            parent_acl_reset.is_ok(),
            "parent temporary DACL reset failed"
        );
    }
    #[cfg(windows)]
    #[test]
    fn inherited_parent_and_child_rename_denies_block_retained_handle_escape() {
        use crate::windows_acl_snapshot_probe::{
            access_check_current_process_token, open_temp_handle,
            set_inherited_rename_route_denies_for_temp_test, set_null_dacl_for_temp_test,
            snapshot_acl_from_handle,
        };
        const FILE_DELETE_CHILD: u32 = 0x0000_0040;
        const DELETE_RIGHT: u32 = 0x0001_0000;
        let root = temp_root();
        let outside = root.with_file_name(format!(
            "{}-outside",
            root.file_name().unwrap().to_string_lossy()
        ));
        fs::create_dir(&root).unwrap();
        fs::create_dir(&outside).unwrap();

        let parent_acl_handle = open_temp_handle(&root, true).unwrap();
        let parent_set = set_inherited_rename_route_denies_for_temp_test(&parent_acl_handle);
        assert!(
            parent_set.is_ok(),
            "failed to install synthetic inherited rename DACL: {parent_set:?}"
        );

        // Create the child only after the parent DACL is installed, so the DELETE deny is inherited.
        let child = root.join("child");
        let moved = outside.join("moved-child");
        fs::create_dir(&child).unwrap();

        let child_acl_handle = open_temp_handle(&child, true).unwrap();
        let root_handle = crate::windows_store_handle_probe::open_final_component(&root).unwrap();
        let child_handle = open_child_experimental(
            root_handle.handle(),
            "child",
            RelativeObjectKind::Directory,
            false,
        )
        .unwrap();

        let parent_access =
            access_check_current_process_token(&parent_acl_handle, FILE_DELETE_CHILD);
        let child_access = access_check_current_process_token(&child_acl_handle, DELETE_RIGHT);
        let child_snapshot = snapshot_acl_from_handle(&child_acl_handle).unwrap();
        let inherited_delete_denies: Vec<_> = child_snapshot
            .aces
            .iter()
            .filter(|ace| {
                ace.ace_type == 1
                    && ace.trustee_sid.as_deref() == Some("S-1-1-0")
                    && ace.inherited
                    && ace.mask.is_some_and(|mask| mask & DELETE_RIGHT != 0)
            })
            .collect();

        // Reuse the same path-based rename used by CP-0722/0723 while retaining the no-share-delete child handle.
        let rename_result = if parent_access.as_ref().is_ok_and(|value| !value.allowed)
            && child_access.as_ref().is_ok_and(|value| !value.allowed)
            && inherited_delete_denies.len() == 1
        {
            fs::rename(&child, &moved)
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "preconditions failed; rename was not attempted",
            ))
        };
        let moved_outside = moved.exists();
        let child_acl_reset = set_null_dacl_for_temp_test(&child_acl_handle);
        let parent_acl_reset = set_null_dacl_for_temp_test(&parent_acl_handle);
        let restore_move = if moved_outside {
            fs::rename(&moved, &child)
        } else {
            Ok(())
        };

        eprintln!(
            "Inherited rename ACL probe: parent_FILE_DELETE_CHILD={:?}, child_DELETE={:?}, child_inherited_delete_aces={}, child_ace_flags={:?}, rename_error={:?}, moved_outside={}",
            parent_access.as_ref().map(|value| value.allowed),
            child_access.as_ref().map(|value| value.allowed),
            inherited_delete_denies.len(),
            inherited_delete_denies.iter().map(|ace| ace.ace_flags).collect::<Vec<_>>(),
            rename_result.as_ref().err(),
            moved_outside,
        );

        drop(child_handle);
        drop(root_handle);
        drop(child_acl_handle);
        drop(parent_acl_handle);
        let cleanup = fs::remove_dir_all(&root).and_then(|_| fs::remove_dir_all(&outside));

        assert!(
            parent_access.as_ref().is_ok_and(|value| !value.allowed),
            "parent FILE_DELETE_CHILD was not denied: {parent_access:?}"
        );
        assert!(
            child_access.as_ref().is_ok_and(|value| !value.allowed),
            "child DELETE was not denied: {child_access:?}"
        );
        assert_eq!(
            inherited_delete_denies.len(),
            1,
            "child must carry one inherited Everyone DELETE deny"
        );
        assert!(
            rename_result.is_err(),
            "rename unexpectedly succeeded while both authorization routes were denied"
        );
        assert!(
            !moved_outside,
            "source directory was moved outside the protected parent"
        );
        assert!(
            child_acl_reset.is_ok(),
            "child temporary DACL reset failed: {child_acl_reset:?}"
        );
        assert!(
            parent_acl_reset.is_ok(),
            "parent temporary DACL reset failed: {parent_acl_reset:?}"
        );
        assert!(
            restore_move.is_ok(),
            "failed to restore moved child before cleanup: {restore_move:?}"
        );
        assert!(
            cleanup.is_ok(),
            "temporary rename tree cleanup failed: {cleanup:?}"
        );
    }

    #[cfg(windows)]
    #[test]
    fn write_dac_mutations_expose_parent_inheritance_and_child_rename_routes() {
        use crate::windows_acl_snapshot_probe::{
            access_check_current_process_token, open_temp_handle,
            set_inherited_rename_route_denies_for_temp_test, set_null_dacl_for_temp_test,
            set_parent_allow_delete_child_for_temp_test, snapshot_acl_from_handle,
        };
        const FILE_DELETE_CHILD: u32 = 0x0000_0040;
        const DELETE_RIGHT: u32 = 0x0001_0000;
        const WRITE_DAC_RIGHT: u32 = 0x0004_0000;

        for mutation in 0..3 {
            let label = match mutation {
                0 => "parent-null-only",
                1 => "parent-allow-refreshes-inheritance",
                _ => "child-null-only",
            };
            let root = temp_root();
            let outside = root.with_file_name(format!(
                "{}-outside-{label}",
                root.file_name().unwrap().to_string_lossy()
            ));
            fs::create_dir(&root).unwrap();
            fs::create_dir(&outside).unwrap();

            // Apply the combined deny policy before child creation so child DELETE is inherited.
            let policy_handle = open_temp_handle(&root, true).unwrap();
            set_inherited_rename_route_denies_for_temp_test(&policy_handle).unwrap();
            drop(policy_handle);

            let child = root.join("child");
            let moved = outside.join("moved-child");
            fs::create_dir(&child).unwrap();

            // Reopen with WRITE_DAC after the restrictive DACL is in place; this verifies a fresh grant.
            let parent_acl_handle = open_temp_handle(&root, true).unwrap();
            let child_acl_handle = open_temp_handle(&child, true).unwrap();
            let root_handle =
                crate::windows_store_handle_probe::open_final_component(&root).unwrap();
            let child_handle = open_child_experimental(
                root_handle.handle(),
                "child",
                RelativeObjectKind::Directory,
                false,
            )
            .unwrap();

            let parent_fdc_before =
                access_check_current_process_token(&parent_acl_handle, FILE_DELETE_CHILD).unwrap();
            let child_delete_before =
                access_check_current_process_token(&child_acl_handle, DELETE_RIGHT).unwrap();
            let parent_write_dac =
                access_check_current_process_token(&parent_acl_handle, WRITE_DAC_RIGHT).unwrap();
            let child_write_dac =
                access_check_current_process_token(&child_acl_handle, WRITE_DAC_RIGHT).unwrap();
            assert!(!parent_fdc_before.allowed && !child_delete_before.allowed);
            assert!(parent_write_dac.allowed && child_write_dac.allowed);

            // Mutate only the selected descriptor. Parent DACL replacement may refresh inherited child ACEs.
            let selected_reset = match mutation {
                0 => set_null_dacl_for_temp_test(&parent_acl_handle),
                1 => set_parent_allow_delete_child_for_temp_test(&parent_acl_handle),
                _ => set_null_dacl_for_temp_test(&child_acl_handle),
            };
            let parent_fdc_after =
                access_check_current_process_token(&parent_acl_handle, FILE_DELETE_CHILD).unwrap();
            let child_delete_after =
                access_check_current_process_token(&child_acl_handle, DELETE_RIGHT).unwrap();
            let child_snapshot_after = snapshot_acl_from_handle(&child_acl_handle).unwrap();
            let child_delete_denies_after = child_snapshot_after
                .aces
                .iter()
                .filter(|ace| {
                    ace.ace_type == 1
                        && ace.trustee_sid.as_deref() == Some("S-1-1-0")
                        && ace.mask.is_some_and(|mask| mask & DELETE_RIGHT != 0)
                })
                .count();

            let (state_matches, rename_should_succeed) = match mutation {
                0 => (
                    parent_fdc_after.allowed
                        && !child_delete_after.allowed
                        && child_delete_denies_after == 0,
                    false,
                ),
                1 => (
                    parent_fdc_after.allowed
                        && child_delete_after.allowed
                        && child_delete_denies_after == 0,
                    true,
                ),
                _ => (
                    !parent_fdc_after.allowed
                        && child_delete_after.allowed
                        && child_delete_denies_after == 0,
                    true,
                ),
            };
            let rename_result = if state_matches {
                fs::rename(&child, &moved)
            } else {
                Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "post-mutation DACL state did not match the expected matrix row",
                ))
            };
            let moved_outside = moved.exists();

            // Reset both descriptors, restore any moved directory, then clean the disposable tree.
            let child_acl_reset = set_null_dacl_for_temp_test(&child_acl_handle);
            let parent_acl_reset = set_null_dacl_for_temp_test(&parent_acl_handle);
            let restore_move = if moved_outside {
                fs::rename(&moved, &child)
            } else {
                Ok(())
            };

            eprintln!(
                "WRITE_DAC rename matrix: case={label}, parent_WRITE_DAC={}, child_WRITE_DAC={}, parent_FDC_after={}, child_DELETE_after={}, child_DACL_state={:?}, child_ACE_count={}, child_inherited_DELETE_denies_after={}, rename_succeeded={}, moved_outside={}",
                parent_write_dac.allowed, child_write_dac.allowed,
                parent_fdc_after.allowed, child_delete_after.allowed, child_snapshot_after.dacl_state,
                child_snapshot_after.aces.len(), child_delete_denies_after, rename_result.is_ok(), moved_outside
            );

            drop(child_handle);
            drop(root_handle);
            drop(child_acl_handle);
            drop(parent_acl_handle);
            let cleanup = fs::remove_dir_all(&root).and_then(|_| fs::remove_dir_all(&outside));

            assert!(
                selected_reset.is_ok(),
                "WRITE_DAC mutation {label} failed: {selected_reset:?}"
            );
            assert!(
                state_matches,
                "post-mutation ACL state did not match expected case {label}"
            );
            assert_eq!(
                rename_result.is_ok(),
                rename_should_succeed,
                "unexpected rename result for {label}: {rename_result:?}"
            );
            if mutation == 0 {
                assert_eq!(
                    rename_result
                        .as_ref()
                        .err()
                        .and_then(|error| error.raw_os_error()),
                    Some(5),
                    "parent NULL DACL alone should preserve the observed AccessDenied result"
                );
            } else {
                assert!(moved_outside, "expected rename success for {label}");
            }
            assert!(
                child_acl_reset.is_ok(),
                "child DACL reset failed: {child_acl_reset:?}"
            );
            assert!(
                parent_acl_reset.is_ok(),
                "parent DACL reset failed: {parent_acl_reset:?}"
            );
            assert!(
                restore_move.is_ok(),
                "failed to restore moved child before cleanup: {restore_move:?}"
            );
            assert!(
                cleanup.is_ok(),
                "temporary WRITE_DAC tree cleanup failed: {cleanup:?}"
            );
        }
    }

    #[cfg(windows)]
    #[test]
    fn parent_delete_child_allow_authorizes_rename_even_when_child_delete_is_denied() {
        use crate::windows_acl_snapshot_probe::{
            access_check_current_process_token, open_temp_handle, set_null_dacl_for_temp_test,
            set_object_deny_delete_for_temp_test, set_parent_allow_delete_child_for_temp_test,
        };
        const FILE_DELETE_CHILD: u32 = 0x0000_0040;
        const DELETE_RIGHT: u32 = 0x0001_0000;
        let root = temp_root();
        let outside = root.with_file_name(format!(
            "{}-outside",
            root.file_name().unwrap().to_string_lossy()
        ));
        fs::create_dir(&root).unwrap();
        fs::create_dir(&outside).unwrap();
        let child = root.join("child");
        let moved = outside.join("moved-child");
        fs::create_dir(&child).unwrap();
        fs::write(
            child.join("marker.bin"),
            b"synthetic parent delete-child route",
        )
        .unwrap();

        let parent_acl_handle = open_temp_handle(&root, true).unwrap();
        let child_acl_handle = open_temp_handle(&child, true).unwrap();
        let root_handle = crate::windows_store_handle_probe::open_final_component(&root).unwrap();
        let child_handle = open_child_experimental(
            root_handle.handle(),
            "child",
            RelativeObjectKind::Directory,
            false,
        )
        .unwrap();

        let child_set = set_object_deny_delete_for_temp_test(&child_acl_handle);
        let parent_set = set_parent_allow_delete_child_for_temp_test(&parent_acl_handle);
        let parent_access =
            access_check_current_process_token(&parent_acl_handle, FILE_DELETE_CHILD);
        let child_access = access_check_current_process_token(&child_acl_handle, DELETE_RIGHT);
        let rename_result = if child_set.is_ok() && parent_set.is_ok() {
            fs::rename(&child, &moved)
        } else {
            Ok(())
        };
        let child_acl_reset = if child_set.is_ok() {
            set_null_dacl_for_temp_test(&child_acl_handle)
        } else {
            Ok(())
        };
        let parent_acl_reset = if parent_set.is_ok() {
            set_null_dacl_for_temp_test(&parent_acl_handle)
        } else {
            Ok(())
        };

        eprintln!(
            "Parent FILE_DELETE_CHILD route: parent_access={:?}, child_DELETE_access={:?}, rename_succeeded={}",
            parent_access.as_ref().map(|value| value.allowed),
            child_access.as_ref().map(|value| value.allowed),
            rename_result.is_ok(),
        );

        drop(child_handle);
        drop(root_handle);
        drop(child_acl_handle);
        drop(parent_acl_handle);
        let _ = fs::remove_dir_all(root);
        let _ = fs::remove_dir_all(outside);

        assert!(
            child_set.is_ok(),
            "failed to deny child DELETE: {:?}",
            child_set.err()
        );
        assert!(
            parent_set.is_ok(),
            "failed to allow parent FILE_DELETE_CHILD: {:?}",
            parent_set.err()
        );
        assert!(
            parent_access.is_ok_and(|value| value.allowed),
            "parent FILE_DELETE_CHILD should be allowed"
        );
        assert!(
            child_access.is_ok_and(|value| !value.allowed),
            "child DELETE should be denied"
        );
        assert!(
            rename_result.is_ok(),
            "parent FILE_DELETE_CHILD should authorize rename despite child DELETE deny"
        );
        assert!(child_acl_reset.is_ok(), "child temporary DACL reset failed");
        assert!(
            parent_acl_reset.is_ok(),
            "parent temporary DACL reset failed"
        );
    }
}
