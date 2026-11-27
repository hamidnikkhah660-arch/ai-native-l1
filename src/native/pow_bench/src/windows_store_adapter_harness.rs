//! CP-0757 test-only Windows handle-bound adapter harness.
//!
//! The harness accepts an already-open root handle and a separately supplied
//! expected root identity. It retains each child opened relative to its parent,
//! snapshots owner/DACL/ACE evidence from those exact handles, and binds lock,
//! state and staging objects to the same retained store-directory identity.
//!
//! It is not a production provider. Test fixtures create disposable files by path;
//! the qualification path itself never re-resolves the configured root pathname.
//! ACL evidence is a conservative upper bound over the ACL parser's supported ACE
//! subset. Unknown ACE types and NULL/absent DACLs fail closed.

use std::{
    collections::BTreeSet,
    ffi::c_void,
    fs::{self, File},
    io,
    os::windows::{
        ffi::OsStrExt,
        io::{AsRawHandle, FromRawHandle, RawHandle},
    },
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use crate::windows_acl_snapshot_probe::{
    derive_conservative_mutation_evidence, set_null_dacl_for_temp_test,
    set_owner_rights_write_dac_allow_for_temp_test, set_parent_allow_delete_child_for_temp_test,
    set_parent_deny_delete_child_for_temp_test, snapshot_acl_from_handle, AclSnapshot, DaclState,
};

type Handle = *mut c_void;

const FILE_READ_ATTRIBUTES: u32 = 0x0000_0080;
const READ_CONTROL: u32 = 0x0002_0000;
const FILE_TRAVERSE: u32 = 0x0000_0020;
const SYNCHRONIZE: u32 = 0x0010_0000;
const FILE_SHARE_READ: u32 = 0x0000_0001;
const FILE_SHARE_WRITE: u32 = 0x0000_0002;
const OPEN_EXISTING: u32 = 3;
const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x0000_0010;
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
const FILE_ATTRIBUTE_TAG_INFO_CLASS: i32 = 9;
const FILE_ID_INFO_CLASS: i32 = 18;
const FILE_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
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
union IoStatusValue {
    status: i32,
    pointer: *mut c_void,
}
#[repr(C)]
struct IoStatusBlock {
    status: IoStatusValue,
    information: usize,
}

#[derive(Clone, Copy)]
enum ObjectKind {
    Directory,
    File,
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

fn open_child_relative_experimental(
    parent: &File,
    component: &str,
    kind: ObjectKind,
    share_delete: bool,
) -> io::Result<File> {
    if component.is_empty()
        || component == "."
        || component == ".."
        || component
            .chars()
            .any(|ch| ch == char::from(92) || ch == '/' || ch == ':' || ch == char::from(0))
        || component.ends_with('.')
        || component.ends_with(' ')
        || component.chars().any(char::is_control)
        || component.encode_utf16().count() > 255
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "unsafe path component",
        ));
    }
    let mut encoded: Vec<u16> = component.encode_utf16().collect();
    let byte_len = encoded
        .len()
        .checked_mul(2)
        .and_then(|value| u16::try_from(value).ok())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "component too long"))?;
    encoded.push(0);
    let mut name = UnicodeString {
        length: byte_len,
        maximum_length: byte_len + 2,
        buffer: encoded.as_mut_ptr(),
    };
    let mut attributes = ObjectAttributes {
        length: std::mem::size_of::<ObjectAttributes>() as u32,
        root_directory: parent.as_raw_handle() as Handle,
        object_name: &mut name,
        attributes: 0,
        security_descriptor: std::ptr::null_mut(),
        security_quality_of_service: std::ptr::null_mut(),
    };
    let mut raw: Handle = std::ptr::null_mut();
    let mut iosb = IoStatusBlock {
        status: IoStatusValue { status: 0 },
        information: 0,
    };
    let create_options = match kind {
        ObjectKind::Directory => FILE_DIRECTORY_FILE,
        ObjectKind::File => FILE_NON_DIRECTORY_FILE,
    } | FILE_SYNCHRONOUS_IO_NONALERT
        | FILE_OPEN_REPARSE_POINT;
    let share = FILE_SHARE_READ | FILE_SHARE_WRITE | if share_delete { 4 } else { 0 };
    let status = unsafe {
        NtCreateFile(
            &mut raw,
            FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE,
            &mut attributes,
            &mut iosb,
            std::ptr::null_mut(),
            0,
            share,
            FILE_OPEN,
            create_options,
            std::ptr::null_mut(),
            0,
        )
    };
    if status < 0 {
        return Err(io::Error::from_raw_os_error(status));
    }
    if raw.is_null() {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "NtCreateFile returned no handle",
        ));
    }
    let opened = unsafe { File::from_raw_handle(raw as RawHandle) };
    let mut tag = FileAttributeTagInfo {
        file_attributes: 0,
        reparse_tag: 0,
    };
    let ok = unsafe {
        GetFileInformationByHandleEx(
            opened.as_raw_handle() as Handle,
            FILE_ATTRIBUTE_TAG_INFO_CLASS,
            (&mut tag as *mut FileAttributeTagInfo).cast(),
            std::mem::size_of::<FileAttributeTagInfo>() as u32,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    if tag.file_attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "reparse point rejected",
        ));
    }
    let actual_directory = tag.file_attributes & FILE_ATTRIBUTE_DIRECTORY != 0;
    if actual_directory != matches!(kind, ObjectKind::Directory) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "object kind mismatch",
        ));
    }
    Ok(opened)
}

const DELETE_RIGHT: u32 = 0x0001_0000;
const WRITE_DAC_RIGHT: u32 = 0x0004_0000;
const WRITE_OWNER_RIGHT: u32 = 0x0008_0000;
const ACCESS_SYSTEM_SECURITY_RIGHT: u32 = 0x0100_0000;
const FILE_WRITE_DATA_RIGHT: u32 = 0x0000_0002;
const FILE_APPEND_DATA_RIGHT: u32 = 0x0000_0004;
const FILE_WRITE_EA_RIGHT: u32 = 0x0000_0010;
const FILE_DELETE_CHILD_RIGHT: u32 = 0x0000_0040;
const FILE_WRITE_ATTRIBUTES_RIGHT: u32 = 0x0000_0100;
const STORE_NAMESPACE_MUTATION_MASK: u32 = DELETE_RIGHT
    | WRITE_DAC_RIGHT
    | WRITE_OWNER_RIGHT
    | ACCESS_SYSTEM_SECURITY_RIGHT
    | FILE_WRITE_DATA_RIGHT
    | FILE_APPEND_DATA_RIGHT
    | FILE_WRITE_EA_RIGHT
    | FILE_DELETE_CHILD_RIGHT
    | FILE_WRITE_ATTRIBUTES_RIGHT;

#[repr(C)]
struct FileIdInfo {
    volume_serial_number: u64,
    file_id: [u8; 16],
}

#[repr(C)]
struct FileAttributeTagInfo {
    file_attributes: u32,
    reparse_tag: u32,
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
    fn GetFileInformationByHandleEx(file: Handle, class: i32, info: *mut c_void, size: u32) -> i32;
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
struct ObjectId {
    volume_serial: u64,
    file_id: [u8; 16],
}

fn object_id(file: &File) -> io::Result<ObjectId> {
    let mut info = FileIdInfo {
        volume_serial_number: 0,
        file_id: [0; 16],
    };
    // SAFETY: the caller supplies a live HANDLE and a correctly sized output buffer.
    let ok = unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle() as Handle,
            FILE_ID_INFO_CLASS,
            (&mut info as *mut FileIdInfo).cast(),
            std::mem::size_of::<FileIdInfo>() as u32,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    if info.file_id == [0; 16] {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "zero file identity",
        ));
    }
    Ok(ObjectId {
        volume_serial: info.volume_serial_number,
        file_id: info.file_id,
    })
}

/// Opens the fixture root once and returns the retained handle. Production callers
/// must supply a root handle from a separate enrollment/provisioning channel.
fn open_fixture_root(path: &Path) -> io::Result<File> {
    let mut wide: Vec<u16> = path.as_os_str().encode_wide().collect();
    if wide.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "root path contains NUL",
        ));
    }
    wide.push(0);
    // Deliberately omit FILE_SHARE_DELETE. The path is used only by the test fixture
    // to obtain the initial handle; subsequent child opens are relative to this handle.
    let raw = unsafe {
        CreateFileW(
            wide.as_ptr(),
            FILE_READ_ATTRIBUTES | READ_CONTROL | FILE_TRAVERSE | SYNCHRONIZE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            std::ptr::null_mut(),
            OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
            std::ptr::null_mut(),
        )
    };
    if raw == -1isize as Handle {
        return Err(io::Error::last_os_error());
    }
    let file = unsafe { File::from_raw_handle(raw as RawHandle) };
    let mut tag = FileAttributeTagInfo {
        file_attributes: 0,
        reparse_tag: 0,
    };
    let ok = unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle() as Handle,
            FILE_ATTRIBUTE_TAG_INFO_CLASS,
            (&mut tag as *mut FileAttributeTagInfo).cast(),
            std::mem::size_of::<FileAttributeTagInfo>() as u32,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    if tag.file_attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || tag.file_attributes & FILE_ATTRIBUTE_DIRECTORY == 0
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "fixture root is a reparse point or not a directory",
        ));
    }
    Ok(file)
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct MutationPrincipal {
    sid: String,
    rights: u32,
    owner_implicit_write_dac: bool,
    source_ace_indices: Vec<usize>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct HandleObjectObservation {
    label: String,
    identity: ObjectId,
    parent: Option<ObjectId>,
    acl: AclSnapshot,
    mutation_principals: Vec<MutationPrincipal>,
}

impl HandleObjectObservation {
    fn capture(label: &str, file: &File, parent: Option<ObjectId>) -> io::Result<Self> {
        let identity = object_id(file)?;
        let acl = snapshot_acl_from_handle(file)?;
        let conservative = derive_conservative_mutation_evidence(&acl);
        let mutation_principals = conservative
            .principals
            .into_iter()
            .map(|entry| MutationPrincipal {
                sid: entry.sid,
                rights: entry.potential_mutation_rights & STORE_NAMESPACE_MUTATION_MASK,
                owner_implicit_write_dac: entry.owner_implicit_write_dac,
                source_ace_indices: entry.source_ace_indices,
            })
            .filter(|entry| entry.rights != 0)
            .collect();
        Ok(Self {
            label: label.to_string(),
            identity,
            parent,
            acl,
            mutation_principals,
        })
    }

    fn acl_is_complete(&self) -> bool {
        self.acl.dacl_state == DaclState::Present && self.acl.structurally_complete
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct StoreObservation {
    root: HandleObjectObservation,
    directories: Vec<HandleObjectObservation>,
    store_directory: ObjectId,
    writer_lock: HandleObjectObservation,
    current_state: HandleObjectObservation,
    staged_state: HandleObjectObservation,
    state_read_identity: ObjectId,
    state_size_check_identity: ObjectId,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct AdapterPolicy {
    pinned_root: ObjectId,
    pinned_store_directory: ObjectId,
    allowed_mutation_principals: BTreeSet<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum AdapterFailure {
    RootIdentityMismatch,
    StoreDirectoryIdentityMismatch,
    ParentChildDiscontinuity(String),
    CrossVolumeObject(String),
    FileParentMismatch(String),
    IncompleteAcl(String),
    UnexpectedMutationPrincipal {
        object: String,
        sid: String,
        rights: u32,
    },
    ReadHandleMismatch,
    SizeCheckHandleMismatch,
    SnapshotChanged(String),
}

impl AdapterPolicy {
    fn validate(&self, observed: &StoreObservation) -> Result<(), AdapterFailure> {
        if observed.root.identity != self.pinned_root {
            return Err(AdapterFailure::RootIdentityMismatch);
        }
        let mut expected_parent = self.pinned_root.clone();
        for directory in &observed.directories {
            if directory.parent.as_ref() != Some(&expected_parent) {
                return Err(AdapterFailure::ParentChildDiscontinuity(
                    directory.label.clone(),
                ));
            }
            validate_object(self, directory)?;
            expected_parent = directory.identity.clone();
        }
        if expected_parent != self.pinned_store_directory
            || observed.store_directory != self.pinned_store_directory
        {
            return Err(AdapterFailure::StoreDirectoryIdentityMismatch);
        }
        if observed.root.identity.volume_serial != self.pinned_root.volume_serial {
            return Err(AdapterFailure::CrossVolumeObject("root".into()));
        }
        validate_object(self, &observed.root)?;
        for file in [
            &observed.writer_lock,
            &observed.current_state,
            &observed.staged_state,
        ] {
            if file.parent.as_ref() != Some(&observed.store_directory) {
                return Err(AdapterFailure::FileParentMismatch(file.label.clone()));
            }
            validate_object(self, file)?;
        }
        if observed.state_read_identity != observed.current_state.identity {
            return Err(AdapterFailure::ReadHandleMismatch);
        }
        if observed.state_size_check_identity != observed.state_read_identity {
            return Err(AdapterFailure::SizeCheckHandleMismatch);
        }
        Ok(())
    }

    fn compare_during_operation(
        &self,
        before: &StoreObservation,
        after: &StoreObservation,
        phase: &str,
    ) -> Result<(), AdapterFailure> {
        self.validate(before)?;
        self.validate(after)?;
        if before != after {
            return Err(AdapterFailure::SnapshotChanged(phase.to_string()));
        }
        Ok(())
    }
}

fn validate_object(
    policy: &AdapterPolicy,
    object: &HandleObjectObservation,
) -> Result<(), AdapterFailure> {
    if object.identity.volume_serial != policy.pinned_root.volume_serial {
        return Err(AdapterFailure::CrossVolumeObject(object.label.clone()));
    }
    if !object.acl_is_complete() {
        return Err(AdapterFailure::IncompleteAcl(object.label.clone()));
    }
    for principal in &object.mutation_principals {
        if !policy
            .allowed_mutation_principals
            .iter()
            .any(|sid| sid.eq_ignore_ascii_case(&principal.sid))
        {
            return Err(AdapterFailure::UnexpectedMutationPrincipal {
                object: object.label.clone(),
                sid: principal.sid.clone(),
                rights: principal.rights,
            });
        }
    }
    Ok(())
}

struct Fixture {
    root_path: PathBuf,
    root: File,
    qrun: File,
    identity_dir: File,
    lock: File,
    state: File,
    staged: File,
    policy: AdapterPolicy,
    baseline: StoreObservation,
}

impl Fixture {
    fn new() -> io::Result<Self> {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| io::Error::other(error.to_string()))?
            .as_nanos();
        let root_path = std::env::temp_dir().join(format!(
            "qrun-cp0757-handle-harness-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir_all(root_path.join("QRun").join("Identity"))?;
        let store_path = root_path.join("QRun").join("Identity");
        fs::write(store_path.join("writer.lock"), b"synthetic lock object")?;
        fs::write(store_path.join("state.stb1"), b"synthetic STB1 state")?;
        fs::write(store_path.join("state.stb1.tmp"), b"synthetic staged state")?;

        let root = open_fixture_root(&root_path)?;
        let pinned_root = object_id(&root)?;
        let qrun = open_child_relative_experimental(&root, "QRun", ObjectKind::Directory, false)?;
        let identity_dir =
            open_child_relative_experimental(&qrun, "Identity", ObjectKind::Directory, false)?;
        let store_id = object_id(&identity_dir)?;
        let lock = open_child_relative_experimental(
            &identity_dir,
            "writer.lock",
            ObjectKind::File,
            false,
        )?;
        let state =
            open_child_relative_experimental(&identity_dir, "state.stb1", ObjectKind::File, false)?;
        let staged = open_child_relative_experimental(
            &identity_dir,
            "state.stb1.tmp",
            ObjectKind::File,
            false,
        )?;

        let mut baseline = capture(&root, &qrun, &identity_dir, &lock, &state, &staged)?;
        let mut allowed = BTreeSet::new();
        for object in std::iter::once(&baseline.root)
            .chain(baseline.directories.iter())
            .chain([
                &baseline.writer_lock,
                &baseline.current_state,
                &baseline.staged_state,
            ])
        {
            allowed.insert(object.acl.owner_sid.clone());
            for principal in &object.mutation_principals {
                allowed.insert(principal.sid.clone());
            }
        }
        let policy = AdapterPolicy {
            pinned_root,
            pinned_store_directory: store_id,
            allowed_mutation_principals: allowed,
        };
        policy.validate(&baseline).map_err(|failure| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("baseline fixture failed qualification: {failure:?}"),
            )
        })?;
        // Keep the observation owned by the fixture for mutation/ABA comparisons.
        baseline.state_read_identity = object_id(&state)?;
        baseline.state_size_check_identity = object_id(&state)?;
        Ok(Self {
            root_path,
            root,
            qrun,
            identity_dir,
            lock,
            state,
            staged,
            policy,
            baseline,
        })
    }

    fn capture(&self) -> io::Result<StoreObservation> {
        capture(
            &self.root,
            &self.qrun,
            &self.identity_dir,
            &self.lock,
            &self.state,
            &self.staged,
        )
    }

    fn mutation_handle(&self, relative_path: &str) -> io::Result<File> {
        use crate::windows_acl_snapshot_probe::open_temp_handle_with_access;
        const FILE_READ_ATTRIBUTES: u32 = 0x80;
        const READ_CONTROL: u32 = 0x0002_0000;
        const WRITE_DAC: u32 = 0x0004_0000;
        open_temp_handle_with_access(
            &self.root_path.join(relative_path),
            FILE_READ_ATTRIBUTES | READ_CONTROL | WRITE_DAC,
        )
    }

    fn cleanup(self) {
        drop(self.staged);
        drop(self.state);
        drop(self.lock);
        drop(self.identity_dir);
        drop(self.qrun);
        drop(self.root);
        let _ = fs::remove_dir_all(self.root_path);
    }
}

fn capture(
    root: &File,
    qrun: &File,
    identity_dir: &File,
    lock: &File,
    state: &File,
    staged: &File,
) -> io::Result<StoreObservation> {
    let root_observation = HandleObjectObservation::capture("root", root, None)?;
    let qrun_observation =
        HandleObjectObservation::capture("QRun", qrun, Some(root_observation.identity.clone()))?;
    let qrun_id = qrun_observation.identity.clone();
    let store_observation =
        HandleObjectObservation::capture("Identity", identity_dir, Some(qrun_id))?;
    let store_id = store_observation.identity.clone();
    let writer_lock =
        HandleObjectObservation::capture("writer.lock", lock, Some(store_id.clone()))?;
    let current_state =
        HandleObjectObservation::capture("state.stb1", state, Some(store_id.clone()))?;
    let staged_state =
        HandleObjectObservation::capture("state.stb1.tmp", staged, Some(store_id.clone()))?;
    // Size is intentionally queried from the same retained state handle; the second
    // identity read proves the size observation is not silently rebound by pathname.
    let state_read_identity = object_id(state)?;
    let _state_size = state.metadata()?.len();
    let state_size_check_identity = object_id(state)?;
    Ok(StoreObservation {
        root: root_observation,
        directories: vec![qrun_observation, store_observation],
        store_directory: store_id,
        writer_lock,
        current_state,
        staged_state,
        state_read_identity,
        state_size_check_identity,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cp0757_accepts_handle_relative_chain_and_same_object_file_bindings() {
        let fixture = Fixture::new().unwrap();
        fixture.policy.validate(&fixture.baseline).unwrap();
        let current = fixture.capture().unwrap();
        fixture
            .policy
            .compare_during_operation(&fixture.baseline, &current, "after-open")
            .unwrap();
        assert_eq!(current.directories.len(), 2);
        assert_eq!(
            current.writer_lock.parent,
            Some(current.store_directory.clone())
        );
        assert_eq!(
            current.current_state.parent,
            Some(current.store_directory.clone())
        );
        assert_eq!(
            current.staged_state.parent,
            Some(current.store_directory.clone())
        );
        assert_eq!(
            current.state_read_identity,
            current.state_size_check_identity
        );
        fixture.cleanup();
    }

    #[test]
    fn cp0757_detects_parent_file_delete_child_added_after_the_initial_snapshot() {
        let fixture = Fixture::new().unwrap();
        let mutator = fixture.mutation_handle("QRun").unwrap();
        set_parent_allow_delete_child_for_temp_test(&mutator).unwrap();
        let changed = fixture.capture().unwrap();
        assert!(matches!(
            fixture.policy.validate(&changed),
            Err(AdapterFailure::UnexpectedMutationPrincipal { ref sid, rights, .. })
                if sid == "S-1-1-0" && rights & FILE_DELETE_CHILD_RIGHT != 0
        ));
        assert_eq!(
            fixture.policy.compare_during_operation(
                &fixture.baseline,
                &changed,
                "after-lock-before-state-read"
            ),
            Err(AdapterFailure::UnexpectedMutationPrincipal {
                object: "QRun".into(),
                sid: "S-1-1-0".into(),
                rights: FILE_DELETE_CHILD_RIGHT | FILE_ADD_SUBDIRECTORY_RIGHT,
            })
        );
        drop(mutator);
        fixture.cleanup();
    }

    #[test]
    fn cp0757_detects_owner_rights_write_dac_added_to_state_file() {
        let fixture = Fixture::new().unwrap();
        let mutator = fixture
            .mutation_handle(r"QRun\Identity\state.stb1")
            .unwrap();
        set_owner_rights_write_dac_allow_for_temp_test(&mutator).unwrap();
        let changed = fixture.capture().unwrap();
        assert!(matches!(
            fixture.policy.validate(&changed),
            Err(AdapterFailure::UnexpectedMutationPrincipal { ref object, ref sid, rights })
                if object == "state.stb1" && sid == "S-1-3-4" && rights & WRITE_DAC_RIGHT != 0
        ));
        assert_ne!(
            fixture.baseline.current_state.acl,
            changed.current_state.acl
        );
        drop(mutator);
        fixture.cleanup();
    }

    #[test]
    fn cp0757_rejects_null_dacl_and_unsupported_incomplete_acl_evidence() {
        let fixture = Fixture::new().unwrap();
        let mutator = fixture
            .mutation_handle(r"QRun\Identity\state.stb1")
            .unwrap();
        set_null_dacl_for_temp_test(&mutator).unwrap();
        let changed = fixture.capture().unwrap();
        assert!(matches!(
            fixture.policy.validate(&changed),
            Err(AdapterFailure::IncompleteAcl(ref object)) if object == "state.stb1"
        ));
        drop(mutator);
        fixture.cleanup();
    }

    #[test]
    fn cp0757_detects_persistent_acl_change_between_adapter_phases() {
        let fixture = Fixture::new().unwrap();
        let mutator = fixture.mutation_handle("QRun").unwrap();
        set_parent_deny_delete_child_for_temp_test(&mutator).unwrap();
        let changed = fixture.capture().unwrap();
        assert!(matches!(
            fixture.policy.compare_during_operation(
                &fixture.baseline,
                &changed,
                "after-stage-before-publish"
            ),
            Err(AdapterFailure::SnapshotChanged(ref phase)) if phase == "after-stage-before-publish"
        ));
        drop(mutator);
        fixture.cleanup();
    }

    #[test]
    fn cp0757_detects_owner_rights_write_owner_added_to_state_file() {
        let fixture = Fixture::new().unwrap();
        let mutator = fixture
            .mutation_handle(r"QRun\Identity\state.stb1")
            .unwrap();
        crate::windows_acl_snapshot_probe::set_owner_rights_write_owner_dacl_for_temp_test(
            &mutator, true,
        )
        .unwrap();
        let changed = fixture.capture().unwrap();
        assert!(matches!(
            fixture.policy.validate(&changed),
            Err(AdapterFailure::UnexpectedMutationPrincipal { ref object, ref sid, rights })
                if object == "state.stb1" && sid == "S-1-3-4" && rights & WRITE_OWNER_RIGHT != 0
        ));
        drop(mutator);
        fixture.cleanup();
    }

    #[test]
    fn cp0757_records_inherited_mutation_aces_on_descendant_directory_handles() {
        let mut fixture = Fixture::new().unwrap();
        let mutator = fixture.mutation_handle("QRun").unwrap();
        crate::windows_acl_snapshot_probe::set_conflicting_inheritable_write_dacl_for_temp_test(
            &mutator, true,
        )
        .unwrap();
        let changed = fixture.capture().unwrap();
        assert!(changed.directories[1]
            .acl
            .aces
            .iter()
            .any(|ace| ace.inherited && ace.trustee_sid.as_deref() == Some("S-1-1-0")));
        fixture.policy.allowed_mutation_principals.remove("S-1-1-0");
        assert!(changed.directories[1]
            .mutation_principals
            .iter()
            .any(|principal| {
                principal.sid == "S-1-1-0" && principal.rights & FILE_WRITE_DATA_RIGHT != 0
            }));
        assert!(matches!(
            validate_object(&fixture.policy, &changed.directories[1]),
            Err(AdapterFailure::UnexpectedMutationPrincipal { ref object, ref sid, rights })
                if object == "Identity" && sid == "S-1-1-0" && rights & FILE_WRITE_DATA_RIGHT != 0
        ));
        drop(mutator);
        fixture.cleanup();
    }

    #[test]
    fn cp0757_detects_store_directory_name_rebound_after_parent_delete_child_route() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root_path = std::env::temp_dir().join(format!(
            "qrun-cp0757-rename-route-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir_all(root_path.join("QRun").join("Identity")).unwrap();

        let root = open_fixture_root(&root_path).unwrap();
        let qrun =
            open_child_relative_experimental(&root, "QRun", ObjectKind::Directory, false).unwrap();
        // Pin the original child identity, then close the target handle. Retain only
        // the parent chain so this isolates the parent FILE_DELETE_CHILD route.
        let original =
            open_child_relative_experimental(&qrun, "Identity", ObjectKind::Directory, false)
                .unwrap();
        let pinned_identity = object_id(&original).unwrap();
        drop(original);

        let mutator = crate::windows_acl_snapshot_probe::open_temp_handle_with_access(
            &root_path.join("QRun"),
            FILE_READ_ATTRIBUTES | READ_CONTROL | 0x0004_0000,
        )
        .unwrap();
        set_parent_allow_delete_child_for_temp_test(&mutator).unwrap();

        let old_path = root_path.join("QRun").join("Identity");
        let displaced_path = root_path.join("QRun").join("Identity-displaced");
        fs::rename(&old_path, &displaced_path)
            .expect("parent FILE_DELETE_CHILD permits rename when target handle is not retained");
        fs::create_dir(&old_path).unwrap();

        let rebound =
            open_child_relative_experimental(&qrun, "Identity", ObjectKind::Directory, false)
                .unwrap();
        let rebound_identity = object_id(&rebound).unwrap();
        assert_ne!(
            rebound_identity, pinned_identity,
            "the same directory name now refers to a new filesystem object"
        );

        drop(rebound);
        drop(mutator);
        drop(qrun);
        drop(root);
        fs::remove_dir_all(root_path).unwrap();
    }
}

const FILE_ADD_SUBDIRECTORY_RIGHT: u32 = 0x0000_0004;

#[cfg(test)]
mod cp0758_tests {
    use super::*;
    use std::{
        io::{Read, Seek, SeekFrom, Write},
        mem::{offset_of, size_of},
        os::windows::io::{AsRawHandle, FromRawHandle, RawHandle},
    };

    const FILE_READ_DATA: u32 = 0x0000_0001;
    const FILE_WRITE_DATA: u32 = 0x0000_0002;
    const DELETE_ACCESS: u32 = 0x0001_0000;
    const FILE_SHARE_DELETE: u32 = 0x0000_0004;
    const FILE_CREATE: u32 = 2;
    const FILE_ATTRIBUTE_NORMAL: u32 = 0x0000_0080;
    const LOCKFILE_FAIL_IMMEDIATELY: u32 = 0x0000_0001;
    const LOCKFILE_EXCLUSIVE_LOCK: u32 = 0x0000_0002;
    const ERROR_LOCK_VIOLATION: i32 = 33;

    #[repr(C)]
    struct FileRenameInfo {
        flags: u32,
        root_directory: Handle,
        file_name_length: u32,
        file_name: [u16; 1],
    }

    #[repr(C)]
    struct WindowsOverlapped {
        internal: usize,
        internal_high: usize,
        offset: u32,
        offset_high: u32,
        event: Handle,
    }

    impl Default for WindowsOverlapped {
        fn default() -> Self {
            Self {
                internal: 0,
                internal_high: 0,
                offset: 4096,
                offset_high: 0,
                event: std::ptr::null_mut(),
            }
        }
    }

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn LockFileEx(
            file: Handle,
            flags: u32,
            reserved: u32,
            bytes_low: u32,
            bytes_high: u32,
            overlapped: *mut WindowsOverlapped,
        ) -> i32;
        fn UnlockFileEx(
            file: Handle,
            reserved: u32,
            bytes_low: u32,
            bytes_high: u32,
            overlapped: *mut WindowsOverlapped,
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
    }

    /// Open or create a single ordinary file component using only the retained
    /// parent handle. The initial test fixture may still create its tree by path;
    /// all adapter operations below are relative to retained directory handles.
    fn open_file_relative(
        parent: &File,
        component: &str,
        desired_access: u32,
        share_delete: bool,
        create_new: bool,
    ) -> io::Result<File> {
        if component.is_empty()
            || component == "."
            || component == ".."
            || component.ends_with('.')
            || component.ends_with(' ')
            || component.chars().any(char::is_control)
            || component
                .chars()
                .any(|ch| ch == char::from(92) || ch == '/' || ch == ':' || ch == char::from(0))
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "unsafe CP-0758 file component",
            ));
        }
        let base = component
            .split('.')
            .next()
            .unwrap_or(component)
            .to_ascii_uppercase();
        if matches!(
            base.as_str(),
            "CON"
                | "PRN"
                | "AUX"
                | "NUL"
                | "COM1"
                | "COM2"
                | "COM3"
                | "COM4"
                | "COM5"
                | "COM6"
                | "COM7"
                | "COM8"
                | "COM9"
                | "LPT1"
                | "LPT2"
                | "LPT3"
                | "LPT4"
                | "LPT5"
                | "LPT6"
                | "LPT7"
                | "LPT8"
                | "LPT9"
        ) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "reserved Windows device name",
            ));
        }

        let mut encoded: Vec<u16> = component.encode_utf16().collect();
        if encoded.is_empty() || encoded.len() > 255 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid CP-0758 component length",
            ));
        }
        let byte_len = encoded
            .len()
            .checked_mul(size_of::<u16>())
            .and_then(|value| u16::try_from(value).ok())
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "component too long"))?;
        let mut name = UnicodeString {
            length: byte_len,
            maximum_length: byte_len,
            buffer: encoded.as_mut_ptr(),
        };
        let mut attributes = ObjectAttributes {
            length: size_of::<ObjectAttributes>() as u32,
            root_directory: parent.as_raw_handle() as Handle,
            object_name: &mut name,
            attributes: 0,
            security_descriptor: std::ptr::null_mut(),
            security_quality_of_service: std::ptr::null_mut(),
        };
        let mut raw: Handle = std::ptr::null_mut();
        let mut status = IoStatusBlock {
            status: IoStatusValue { status: 0 },
            information: 0,
        };
        let share =
            FILE_SHARE_READ | FILE_SHARE_WRITE | if share_delete { FILE_SHARE_DELETE } else { 0 };
        let disposition = if create_new { FILE_CREATE } else { FILE_OPEN };
        let result = unsafe {
            NtCreateFile(
                &mut raw,
                desired_access,
                &mut attributes,
                &mut status,
                std::ptr::null_mut(),
                FILE_ATTRIBUTE_NORMAL,
                share,
                disposition,
                FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_REPARSE_POINT,
                std::ptr::null_mut(),
                0,
            )
        };
        if result < 0 {
            return Err(io::Error::from_raw_os_error(result));
        }
        if raw.is_null() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "NtCreateFile returned success without a CP-0758 file handle",
            ));
        }
        let file = unsafe { File::from_raw_handle(raw as RawHandle) };
        let mut tag = FileAttributeTagInfo {
            file_attributes: 0,
            reparse_tag: 0,
        };
        let ok = unsafe {
            GetFileInformationByHandleEx(
                file.as_raw_handle() as Handle,
                FILE_ATTRIBUTE_TAG_INFO_CLASS,
                (&mut tag as *mut FileAttributeTagInfo).cast(),
                size_of::<FileAttributeTagInfo>() as u32,
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        if tag.file_attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
            || tag.file_attributes & FILE_ATTRIBUTE_DIRECTORY != 0
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "CP-0758 file handle is a reparse point or directory",
            ));
        }
        Ok(file)
    }

    const FILE_LIST_DIRECTORY: u32 = 0x0000_0001;
    const FILE_ADD_FILE: u32 = 0x0000_0002;

    fn open_directory_relative(
        parent: &File,
        component: &str,
        desired_access: u32,
        share_delete: bool,
    ) -> io::Result<File> {
        if component.is_empty()
            || component == "."
            || component == ".."
            || component.contains(['\\', '/', ':', '\0'])
            || component.ends_with('.')
            || component.ends_with(' ')
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "unsafe CP-0758 directory component",
            ));
        }
        let mut encoded: Vec<u16> = component.encode_utf16().collect();
        let byte_len = encoded
            .len()
            .checked_mul(size_of::<u16>())
            .and_then(|value| u16::try_from(value).ok())
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "directory name too long")
            })?;
        let mut name = UnicodeString {
            length: byte_len,
            maximum_length: byte_len,
            buffer: encoded.as_mut_ptr(),
        };
        let mut attributes = ObjectAttributes {
            length: size_of::<ObjectAttributes>() as u32,
            root_directory: parent.as_raw_handle() as Handle,
            object_name: &mut name,
            attributes: 0,
            security_descriptor: std::ptr::null_mut(),
            security_quality_of_service: std::ptr::null_mut(),
        };
        let mut raw: Handle = std::ptr::null_mut();
        let mut status = IoStatusBlock {
            status: IoStatusValue { status: 0 },
            information: 0,
        };
        let share =
            FILE_SHARE_READ | FILE_SHARE_WRITE | if share_delete { FILE_SHARE_DELETE } else { 0 };
        let result = unsafe {
            NtCreateFile(
                &mut raw,
                desired_access,
                &mut attributes,
                &mut status,
                std::ptr::null_mut(),
                FILE_ATTRIBUTE_NORMAL,
                share,
                FILE_OPEN,
                FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_REPARSE_POINT,
                std::ptr::null_mut(),
                0,
            )
        };
        if result < 0 {
            return Err(io::Error::from_raw_os_error(result));
        }
        if raw.is_null() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "NtCreateFile returned success without a CP-0758 directory handle",
            ));
        }
        let directory = unsafe { File::from_raw_handle(raw as RawHandle) };
        let mut tag = FileAttributeTagInfo {
            file_attributes: 0,
            reparse_tag: 0,
        };
        let ok = unsafe {
            GetFileInformationByHandleEx(
                directory.as_raw_handle() as Handle,
                FILE_ATTRIBUTE_TAG_INFO_CLASS,
                (&mut tag as *mut FileAttributeTagInfo).cast(),
                size_of::<FileAttributeTagInfo>() as u32,
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        if tag.file_attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
            || tag.file_attributes & FILE_ATTRIBUTE_DIRECTORY == 0
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "CP-0758 directory handle is a reparse point or not a directory",
            ));
        }
        Ok(directory)
    }

    struct HandleWriterLock {
        file: File,
        locked: bool,
    }

    impl HandleWriterLock {
        fn acquire(file: File) -> io::Result<Self> {
            let mut overlapped = WindowsOverlapped::default();
            let result = unsafe {
                LockFileEx(
                    file.as_raw_handle() as Handle,
                    LOCKFILE_FAIL_IMMEDIATELY | LOCKFILE_EXCLUSIVE_LOCK,
                    0,
                    1,
                    0,
                    &mut overlapped,
                )
            };
            if result == 0 {
                let error = io::Error::last_os_error();
                if error.raw_os_error() == Some(ERROR_LOCK_VIOLATION) {
                    return Err(io::Error::new(io::ErrorKind::WouldBlock, error));
                }
                return Err(error);
            }
            Ok(Self { file, locked: true })
        }
    }

    impl Drop for HandleWriterLock {
        fn drop(&mut self) {
            if !self.locked {
                return;
            }
            let mut overlapped = WindowsOverlapped::default();
            unsafe {
                let _ = UnlockFileEx(
                    self.file.as_raw_handle() as Handle,
                    0,
                    1,
                    0,
                    &mut overlapped,
                );
            }
            self.locked = false;
        }
    }

    fn rename_source_relative(
        source: &File,
        destination_directory: &File,
        destination_name: &str,
    ) -> io::Result<()> {
        if destination_name.is_empty()
            || destination_name == "."
            || destination_name == ".."
            || destination_name.contains(['\\', '/', ':', '\0'])
            || destination_name.ends_with('.')
            || destination_name.ends_with(' ')
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "unsafe CP-0758 destination component",
            ));
        }
        let encoded: Vec<u16> = destination_name.encode_utf16().collect();
        let name_bytes = encoded
            .len()
            .checked_mul(size_of::<u16>())
            .and_then(|value| u32::try_from(value).ok())
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "rename name too long"))?;
        let name_offset = offset_of!(FileRenameInfo, file_name);
        let buffer_size = name_offset
            .checked_add((encoded.len() + 1) * size_of::<u16>())
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "rename size overflow"))?;
        let word_count = buffer_size
            .checked_add(size_of::<usize>() - 1)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "rename size overflow"))?
            / size_of::<usize>();
        let mut storage = vec![0usize; word_count];
        let info = storage.as_mut_ptr().cast::<FileRenameInfo>();
        unsafe {
            std::ptr::write(
                info,
                FileRenameInfo {
                    // Replace the existing target using POSIX semantics so existing
                    // readers retain the old object while new opens resolve to the new one.
                    flags: 0x0000_0001 | 0x0000_0002,
                    root_directory: destination_directory.as_raw_handle() as Handle,
                    file_name_length: name_bytes,
                    file_name: [0],
                },
            );
            std::ptr::copy_nonoverlapping(
                encoded.as_ptr(),
                (*info).file_name.as_mut_ptr(),
                encoded.len(),
            );
        }
        let size = u32::try_from(buffer_size)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "rename buffer too large"))?;
        let mut io_status = IoStatusBlock {
            status: IoStatusValue { status: 0 },
            information: 0,
        };
        let result = unsafe {
            NtSetInformationFile(
                source.as_raw_handle() as Handle,
                &mut io_status,
                info.cast(),
                size,
                65, // FileRenameInformationEx: replace + POSIX semantics (open target handles survive).
            )
        };
        if result < 0 {
            return Err(io::Error::from_raw_os_error(result));
        }
        Ok(())
    }

    fn read_bounded_same_handle(file: &mut File, maximum_bytes: u64) -> io::Result<Vec<u8>> {
        let identity_before = object_id(file)?;
        let size_before = file.metadata()?.len();
        if size_before > maximum_bytes {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "STB1 state exceeds the configured size ceiling",
            ));
        }
        let capacity = usize::try_from(size_before).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "STB1 state size cannot fit memory",
            )
        })?;
        file.seek(SeekFrom::Start(0))?;
        let mut bytes = Vec::with_capacity(capacity);
        (&mut *file)
            .take(maximum_bytes.saturating_add(1))
            .read_to_end(&mut bytes)?;
        let size_after = file.metadata()?.len();
        let identity_after = object_id(file)?;
        if bytes.len() as u64 != size_before
            || size_after != size_before
            || identity_after != identity_before
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "STB1 state changed during same-handle read/size qualification",
            ));
        }
        Ok(bytes)
    }

    fn reopen_state_with_delete_sharing(fixture: &mut Fixture) -> io::Result<()> {
        let replacement = open_file_relative(
            &fixture.identity_dir,
            "state.stb1",
            FILE_READ_DATA | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE,
            true,
            false,
        )?;
        let previous = std::mem::replace(&mut fixture.state, replacement);
        drop(previous);
        Ok(())
    }

    fn acquire_fixture_lock(fixture: &Fixture) -> io::Result<HandleWriterLock> {
        let lock_file = open_file_relative(
            &fixture.identity_dir,
            "writer.lock",
            FILE_READ_DATA | FILE_WRITE_DATA | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE,
            false,
            false,
        )?;
        HandleWriterLock::acquire(lock_file)
    }

    fn validate_fixture_policy(fixture: &Fixture) -> io::Result<()> {
        let observed = fixture.capture()?;
        fixture.policy.validate(&observed).map_err(|failure| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("CP-0758 store policy rejected evidence: {failure:?}"),
            )
        })
    }

    #[test]
    fn cp0758_lockfile_exclusivity_is_acquired_on_the_retained_relative_handle() {
        let fixture = Fixture::new().unwrap();
        let first = acquire_fixture_lock(&fixture).unwrap();
        let second_file = open_file_relative(
            &fixture.identity_dir,
            "writer.lock",
            FILE_READ_DATA | FILE_WRITE_DATA | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE,
            false,
            false,
        )
        .unwrap();
        let second = HandleWriterLock::acquire(second_file);
        assert!(second.is_err_and(|error| error.kind() == io::ErrorKind::WouldBlock));

        drop(first);
        let reopened = acquire_fixture_lock(&fixture).unwrap();
        drop(reopened);
        fixture.cleanup();
    }

    #[test]
    fn cp0758_reads_sizes_stages_publishes_and_reopens_by_retained_handles() {
        const MAX_STATE_BYTES: u64 = 1024;
        let mut fixture = Fixture::new().unwrap();
        // Pin the writer-directory object once. State, lock, stage and publication
        // are all opened relative to this exact retained handle, not merely another
        // handle that happens to report the same FILE_ID_INFO.
        let writer_directory = open_directory_relative(
            &fixture.qrun,
            "Identity",
            FILE_LIST_DIRECTORY
                | FILE_ADD_FILE
                | FILE_READ_ATTRIBUTES
                | READ_CONTROL
                | FILE_TRAVERSE
                | SYNCHRONIZE,
            false,
        )
        .unwrap();
        let store_id = object_id(&writer_directory).unwrap();
        assert_eq!(store_id, object_id(&fixture.identity_dir).unwrap());
        let writer_directory_evidence = HandleObjectObservation::capture(
            "Identity.cp0758-writer-handle",
            &writer_directory,
            Some(object_id(&fixture.qrun).unwrap()),
        )
        .unwrap();
        validate_object(&fixture.policy, &writer_directory_evidence).unwrap();

        let replacement_state = open_file_relative(
            &writer_directory,
            "state.stb1",
            FILE_READ_DATA | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE,
            true,
            false,
        )
        .unwrap();
        let previous_state = std::mem::replace(&mut fixture.state, replacement_state);
        drop(previous_state);
        let original_id = object_id(&fixture.state).unwrap();
        let old_bytes = read_bounded_same_handle(&mut fixture.state, MAX_STATE_BYTES).unwrap();
        assert_eq!(old_bytes, b"synthetic STB1 state");

        let lock_file = open_file_relative(
            &writer_directory,
            "writer.lock",
            FILE_READ_DATA | FILE_WRITE_DATA | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE,
            false,
            false,
        )
        .unwrap();
        let _writer_lock = HandleWriterLock::acquire(lock_file).unwrap();

        let next_bytes = b"CP-0758 exact staged STB1 successor";
        assert!(next_bytes.len() as u64 <= MAX_STATE_BYTES);

        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let stage_name = format!("state.stb1.cp0758-{nonce}.tmp");
        let mut staged = open_file_relative(
            &writer_directory,
            &stage_name,
            FILE_READ_DATA
                | FILE_WRITE_DATA
                | FILE_READ_ATTRIBUTES
                | READ_CONTROL
                | DELETE_ACCESS
                | SYNCHRONIZE,
            false,
            true,
        )
        .unwrap();
        let staged_id_before = object_id(&staged).unwrap();
        staged.write_all(next_bytes).unwrap();
        staged.flush().unwrap();
        staged.sync_all().unwrap();
        assert_eq!(staged.metadata().unwrap().len(), next_bytes.len() as u64);
        assert_eq!(object_id(&staged).unwrap(), staged_id_before);

        let stage_evidence = HandleObjectObservation::capture(
            "state.stb1.cp0758-stage",
            &staged,
            Some(store_id.clone()),
        )
        .unwrap();
        validate_object(&fixture.policy, &stage_evidence).unwrap();
        let operation_snapshot = capture(
            &fixture.root,
            &fixture.qrun,
            &writer_directory,
            &_writer_lock.file,
            &fixture.state,
            &staged,
        )
        .unwrap();
        fixture.policy.validate(&operation_snapshot).unwrap();
        assert_eq!(operation_snapshot.store_directory, store_id);

        // Keep a separate DELETE-capable handle to the exact existing target object.
        // This avoids asking the directory for FILE_DELETE_CHILD: the directory handle
        // needs only FILE_ADD_FILE, while replacement authorization is object-bound.
        let old_target_delete_handle = open_file_relative(
            &writer_directory,
            "state.stb1",
            FILE_READ_ATTRIBUTES | READ_CONTROL | DELETE_ACCESS | SYNCHRONIZE,
            true,
            false,
        )
        .unwrap();
        assert_eq!(object_id(&old_target_delete_handle).unwrap(), original_id);

        // The old state handles permit FILE_SHARE_DELETE. The staged source is renamed
        // relative to the same retained, identity-checked destination-directory handle.
        rename_source_relative(&staged, &writer_directory, "state.stb1").unwrap();
        assert_eq!(object_id(&old_target_delete_handle).unwrap(), original_id);
        drop(old_target_delete_handle);
        assert_eq!(object_id(&staged).unwrap(), staged_id_before);
        assert_eq!(object_id(&fixture.state).unwrap(), original_id);

        let mut published = open_file_relative(
            &writer_directory,
            "state.stb1",
            FILE_READ_DATA | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE,
            true,
            false,
        )
        .unwrap();
        let published_id = object_id(&published).unwrap();
        assert_eq!(published_id, staged_id_before);
        assert_eq!(
            read_bounded_same_handle(&mut published, MAX_STATE_BYTES).unwrap(),
            next_bytes
        );
        // The stage handle was already flushed and synced before publication.
        // This reopened target handle is read-only; do not request a write flush here.

        let published_evidence = HandleObjectObservation::capture(
            "state.stb1.cp0758-published",
            &published,
            Some(store_id.clone()),
        )
        .unwrap();
        validate_object(&fixture.policy, &published_evidence).unwrap();
        let committed_snapshot = capture(
            &fixture.root,
            &fixture.qrun,
            &writer_directory,
            &_writer_lock.file,
            &published,
            &staged,
        )
        .unwrap();
        fixture.policy.validate(&committed_snapshot).unwrap();
        assert_eq!(committed_snapshot.store_directory, store_id);
        assert_eq!(
            committed_snapshot.state_read_identity,
            committed_snapshot.state_size_check_identity
        );
        assert_ne!(published_id, original_id);

        drop(published);
        drop(staged);
        drop(writer_directory);
        drop(_writer_lock);
        fixture.cleanup();
    }

    #[test]
    fn cp0758_rejects_oversized_state_before_any_stage_or_publication() {
        let mut fixture = Fixture::new().unwrap();
        reopen_state_with_delete_sharing(&mut fixture).unwrap();
        let original_id = object_id(&fixture.state).unwrap();
        let oversized = read_bounded_same_handle(&mut fixture.state, 4);
        assert!(oversized.is_err_and(|error| error.kind() == io::ErrorKind::InvalidData));
        assert_eq!(object_id(&fixture.state).unwrap(), original_id);
        assert_eq!(
            read_bounded_same_handle(&mut fixture.state, 1024).unwrap(),
            b"synthetic STB1 state"
        );
        validate_fixture_policy(&fixture).unwrap();
        fixture.cleanup();
    }

    #[test]
    fn cp0758_aborts_before_publish_when_parent_mutation_rights_change_after_staging() {
        const MAX_STATE_BYTES: u64 = 1024;
        let mut fixture = Fixture::new().unwrap();
        reopen_state_with_delete_sharing(&mut fixture).unwrap();
        let original_id = object_id(&fixture.state).unwrap();
        let original_bytes = read_bounded_same_handle(&mut fixture.state, MAX_STATE_BYTES).unwrap();
        let _writer_lock = acquire_fixture_lock(&fixture).unwrap();

        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let stage_name = format!("state.stb1.cp0758-abort-{nonce}.tmp");
        let mut staged = open_file_relative(
            &fixture.identity_dir,
            &stage_name,
            FILE_READ_DATA
                | FILE_WRITE_DATA
                | FILE_READ_ATTRIBUTES
                | READ_CONTROL
                | DELETE_ACCESS
                | SYNCHRONIZE,
            false,
            true,
        )
        .unwrap();
        staged.write_all(b"must-not-publish").unwrap();
        staged.flush().unwrap();
        staged.sync_all().unwrap();

        let mutator = fixture.mutation_handle("QRun").unwrap();
        set_parent_allow_delete_child_for_temp_test(&mutator).unwrap();
        let changed = fixture.capture().unwrap();
        assert!(matches!(
            fixture.policy.validate(&changed),
            Err(AdapterFailure::UnexpectedMutationPrincipal { ref object, ref sid, rights })
                if object == "QRun" && sid == "S-1-1-0" && rights & FILE_DELETE_CHILD_RIGHT != 0
        ));

        let mut current = open_file_relative(
            &fixture.identity_dir,
            "state.stb1",
            FILE_READ_DATA | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE,
            true,
            false,
        )
        .unwrap();
        assert_eq!(object_id(&current).unwrap(), original_id);
        assert_eq!(
            read_bounded_same_handle(&mut current, MAX_STATE_BYTES).unwrap(),
            original_bytes
        );

        drop(current);
        drop(mutator);
        drop(staged);
        drop(_writer_lock);
        fixture.cleanup();
    }
}
