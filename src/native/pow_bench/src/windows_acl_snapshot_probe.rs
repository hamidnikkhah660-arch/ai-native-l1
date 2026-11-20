//! Read-only ACL snapshot/parser experiment for Windows file and directory handles.
//!
//! This test-only probe preserves raw ACE data and deliberately does not claim
//! effective-rights enumeration or immunity to concurrent security-descriptor
//! changes. Unsupported ACE types make the snapshot incomplete.

#[cfg(windows)]
mod imp {
    use std::ffi::c_void;
    use std::fs::File;
    use std::io;
    use std::os::windows::io::{AsRawHandle, FromRawHandle, RawHandle};

    type Handle = *mut c_void;
    const SE_FILE_OBJECT: i32 = 1;
    const OWNER_SECURITY_INFORMATION: u32 = 0x0000_0001;
    const GROUP_SECURITY_INFORMATION: u32 = 0x0000_0002;
    const DACL_SECURITY_INFORMATION: u32 = 0x0000_0004;
    const READ_CONTROL: u32 = 0x0002_0000;
    const WRITE_DAC: u32 = 0x0004_0000;
    const FILE_READ_ATTRIBUTES: u32 = 0x0080;
    const FILE_SHARE_ALL: u32 = 0x0000_0007;
    const OPEN_EXISTING: u32 = 3;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    const ACL_SIZE_INFORMATION_CLASS: i32 = 2;
    const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;
    const ACCESS_DENIED_ACE_TYPE: u8 = 1;
    const INHERITED_ACE: u8 = 0x10;
    const TOKEN_QUERY: u32 = 0x0008;
    const TOKEN_DUPLICATE: u32 = 0x0002;
    const SECURITY_IMPERSONATION: i32 = 2;
    const TOKEN_IMPERSONATION: i32 = 2;

    #[repr(C)]
    struct AclSizeInformation {
        ace_count: u32,
        acl_bytes_in_use: u32,
        acl_bytes_free: u32,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct AceHeader {
        ace_type: u8,
        ace_flags: u8,
        ace_size: u16,
    }

    struct LocalBuffer(*mut c_void);
    impl Drop for LocalBuffer {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: the pointer was allocated by an API documented to use LocalFree.
                unsafe { LocalFree(self.0) };
            }
        }
    }

    #[derive(Debug, Clone, Copy, Eq, PartialEq)]
    pub enum DaclState {
        Present,
        Null,
        Absent,
    }

    #[derive(Debug, Clone, Eq, PartialEq)]
    pub struct AceSnapshot {
        pub ace_type: u8,
        pub ace_flags: u8,
        pub inherited: bool,
        pub mask: Option<u32>,
        pub trustee_sid: Option<String>,
        pub raw: Vec<u8>,
        pub understood_standard_allow_or_deny: bool,
    }

    #[derive(Debug, Clone, Eq, PartialEq)]
    pub struct AclSnapshot {
        pub owner_sid: String,
        pub dacl_state: DaclState,
        pub dacl_defaulted: bool,
        pub aces: Vec<AceSnapshot>,
        pub unsupported_ace_types: Vec<u8>,
        /// False for NULL/absent DACLs or any ACE type not parsed by this narrow prototype.
        /// Structural ACE parsing only; this is NOT effective-rights evaluation.
        pub structurally_complete: bool,
    }

    #[link(name = "advapi32")]
    unsafe extern "system" {
        fn AccessCheck(
            security_descriptor: *mut c_void,
            client_token: Handle,
            desired_access: u32,
            generic_mapping: *mut GenericMapping,
            privilege_set: *mut c_void,
            privilege_set_length: *mut u32,
            granted_access: *mut u32,
            access_status: *mut i32,
        ) -> i32;
        fn GetSecurityInfo(
            handle: Handle,
            object_type: i32,
            security_info: u32,
            owner: *mut *mut c_void,
            group: *mut *mut c_void,
            dacl: *mut *mut c_void,
            sacl: *mut *mut c_void,
            security_descriptor: *mut *mut c_void,
        ) -> u32;
        fn GetSecurityDescriptorDacl(
            security_descriptor: *mut c_void,
            dacl_present: *mut i32,
            dacl: *mut *mut c_void,
            dacl_defaulted: *mut i32,
        ) -> i32;
        fn GetAclInformation(
            acl: *mut c_void,
            information: *mut c_void,
            information_length: u32,
            information_class: i32,
        ) -> i32;
        fn GetAce(acl: *mut c_void, ace_index: u32, ace: *mut *mut c_void) -> i32;
        fn IsValidSid(sid: *mut c_void) -> i32;
        fn GetLengthSid(sid: *mut c_void) -> u32;
        fn ConvertSidToStringSidW(sid: *mut c_void, string_sid: *mut *mut u16) -> i32;
        fn InitializeAcl(acl: *mut c_void, acl_length: u32, revision: u32) -> i32;
        fn AddAccessDeniedAceEx(
            acl: *mut c_void,
            revision: u32,
            ace_flags: u32,
            mask: u32,
            sid: *mut c_void,
        ) -> i32;
        fn AddAccessAllowedAceEx(
            acl: *mut c_void,
            revision: u32,
            ace_flags: u32,
            mask: u32,
            sid: *mut c_void,
        ) -> i32;
        fn ConvertStringSidToSidW(string_sid: *const u16, sid: *mut *mut c_void) -> i32;
        fn SetSecurityInfo(
            handle: Handle,
            object_type: i32,
            security_info: u32,
            owner: *mut c_void,
            group: *mut c_void,
            dacl: *mut c_void,
            sacl: *mut c_void,
        ) -> u32;
    }

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetCurrentProcess() -> Handle;
        fn OpenProcessToken(process: Handle, desired_access: u32, token: *mut Handle) -> i32;
        fn GetTokenInformation(
            token: Handle,
            information_class: u32,
            information: *mut c_void,
            information_length: u32,
            return_length: *mut u32,
        ) -> i32;
        fn DuplicateTokenEx(
            existing_token: Handle,
            desired_access: u32,
            token_attributes: *mut c_void,
            impersonation_level: i32,
            token_type: i32,
            new_token: *mut Handle,
        ) -> i32;
        fn CloseHandle(handle: Handle) -> i32;
        fn CreateFileW(
            file_name: *const u16,
            desired_access: u32,
            share_mode: u32,
            security_attributes: *mut c_void,
            creation_disposition: u32,
            flags_and_attributes: u32,
            template_file: Handle,
        ) -> Handle;
        fn LocalFree(memory: *mut c_void) -> *mut c_void;
    }

    #[repr(C)]
    struct TokenOwnerInfo {
        owner: *mut c_void,
    }

    #[repr(C)]
    struct GenericMapping {
        generic_read: u32,
        generic_write: u32,
        generic_execute: u32,
        generic_all: u32,
    }

    struct TokenHandle(Handle);
    impl Drop for TokenHandle {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: token handles in this guard are owned and closed exactly once.
                unsafe { CloseHandle(self.0) };
            }
        }
    }

    #[derive(Debug, Clone, Copy, Eq, PartialEq)]
    pub struct TokenAccessResult {
        pub desired_access: u32,
        pub granted_access: u32,
        pub allowed: bool,
    }

    /// Runs AccessCheck only for the current process token. This is not an
    /// enumeration of other users/groups and cannot qualify every mutator.
    const GENERIC_READ: u32 = 0x8000_0000;
    const GENERIC_WRITE: u32 = 0x4000_0000;
    const GENERIC_EXECUTE: u32 = 0x2000_0000;
    const GENERIC_ALL: u32 = 0x1000_0000;
    const DELETE_RIGHT: u32 = 0x0001_0000;
    const WRITE_DAC_RIGHT: u32 = 0x0004_0000;
    const WRITE_OWNER_RIGHT: u32 = 0x0008_0000;
    const ACCESS_SYSTEM_SECURITY_RIGHT: u32 = 0x0100_0000;
    const FILE_WRITE_DATA_RIGHT: u32 = 0x0000_0002;
    const FILE_APPEND_DATA_RIGHT: u32 = 0x0000_0004;
    const FILE_WRITE_EA_RIGHT: u32 = 0x0000_0010;
    const FILE_DELETE_CHILD_RIGHT: u32 = 0x0000_0040;
    const FILE_WRITE_ATTRIBUTES_RIGHT: u32 = 0x0000_0100;
    const MUTATION_RIGHTS_MASK: u32 = DELETE_RIGHT
        | WRITE_DAC_RIGHT
        | WRITE_OWNER_RIGHT
        | ACCESS_SYSTEM_SECURITY_RIGHT
        | FILE_WRITE_DATA_RIGHT
        | FILE_APPEND_DATA_RIGHT
        | FILE_WRITE_EA_RIGHT
        | FILE_DELETE_CHILD_RIGHT
        | FILE_WRITE_ATTRIBUTES_RIGHT;

    #[derive(Debug, Clone, Eq, PartialEq)]
    pub struct MutationPrincipalEvidence {
        pub sid: String,
        pub potential_mutation_rights: u32,
        pub source_ace_indices: Vec<usize>,
        pub owner_implicit_write_dac: bool,
    }

    #[derive(Debug, Clone, Eq, PartialEq)]
    pub struct ConservativeMutationEvidence {
        pub principals: Vec<MutationPrincipalEvidence>,
        pub unsupported_ace_types: Vec<u8>,
        /// True only that every ACE was parsed by the narrow allow/deny parser.
        /// It does not mean effective rights or all token principals are known.
        pub ace_stream_understood: bool,
    }

    fn map_file_generic_access(mut mask: u32) -> u32 {
        if mask & GENERIC_READ != 0 {
            mask = (mask & !GENERIC_READ) | 0x0012_0089;
        }
        if mask & GENERIC_WRITE != 0 {
            mask = (mask & !GENERIC_WRITE) | 0x0012_0116;
        }
        if mask & GENERIC_EXECUTE != 0 {
            mask = (mask & !GENERIC_EXECUTE) | 0x0012_00A0;
        }
        if mask & GENERIC_ALL != 0 {
            mask = (mask & !GENERIC_ALL) | 0x001F_01FF;
        }
        mask
    }

    /// Conservative upper bound over explicit allow ACEs. Deny ACEs are kept
    /// in the source snapshot but never subtracted here; group/token semantics,
    /// callback/object ACEs and conditional access are intentionally unresolved.
    pub fn derive_conservative_mutation_evidence(
        snapshot: &AclSnapshot,
    ) -> ConservativeMutationEvidence {
        use std::collections::BTreeMap;
        let mut principals: BTreeMap<String, MutationPrincipalEvidence> = BTreeMap::new();
        let mut unsupported_ace_types = snapshot.unsupported_ace_types.clone();
        let mut ace_stream_understood = snapshot.structurally_complete;
        if snapshot.dacl_state != DaclState::Present {
            principals.insert(
                "S-1-1-0".to_string(),
                MutationPrincipalEvidence {
                    sid: "S-1-1-0".to_string(),
                    potential_mutation_rights: MUTATION_RIGHTS_MASK,
                    source_ace_indices: Vec::new(),
                    owner_implicit_write_dac: false,
                },
            );
            ace_stream_understood = false;
        } else {
            // Conservative: owner can normally change the DACL. OWNER RIGHTS ACE
            // semantics are not implemented, so do not subtract this upper bound.
            principals.insert(
                snapshot.owner_sid.clone(),
                MutationPrincipalEvidence {
                    sid: snapshot.owner_sid.clone(),
                    potential_mutation_rights: WRITE_DAC_RIGHT,
                    source_ace_indices: Vec::new(),
                    owner_implicit_write_dac: true,
                },
            );
            for (index, ace) in snapshot.aces.iter().enumerate() {
                if !ace.understood_standard_allow_or_deny {
                    if !unsupported_ace_types.contains(&ace.ace_type) {
                        unsupported_ace_types.push(ace.ace_type);
                    }
                    ace_stream_understood = false;
                    continue;
                }
                if ace.ace_type != ACCESS_ALLOWED_ACE_TYPE {
                    continue;
                }
                let (Some(sid), Some(mask)) = (&ace.trustee_sid, ace.mask) else {
                    ace_stream_understood = false;
                    continue;
                };
                let mutation = map_file_generic_access(mask) & MUTATION_RIGHTS_MASK;
                if mutation == 0 {
                    continue;
                }
                let entry =
                    principals
                        .entry(sid.clone())
                        .or_insert_with(|| MutationPrincipalEvidence {
                            sid: sid.clone(),
                            potential_mutation_rights: 0,
                            source_ace_indices: Vec::new(),
                            owner_implicit_write_dac: false,
                        });
                entry.potential_mutation_rights |= mutation;
                entry.source_ace_indices.push(index);
            }
        }
        ConservativeMutationEvidence {
            principals: principals.into_values().collect(),
            unsupported_ace_types,
            ace_stream_understood,
        }
    }
    pub fn access_check_current_process_token(
        handle: &File,
        desired_access: u32,
    ) -> io::Result<TokenAccessResult> {
        if desired_access & 0xF000_0000 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "AccessCheck requires generic rights to be mapped first",
            ));
        }
        let mut owner = std::ptr::null_mut();
        let mut security_descriptor = std::ptr::null_mut();
        // SAFETY: output pointers are valid; handle must have READ_CONTROL.
        let status = unsafe {
            GetSecurityInfo(
                handle.as_raw_handle(),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                &mut owner,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut security_descriptor,
            )
        };
        if status != 0 {
            return Err(io::Error::from_raw_os_error(status as i32));
        }
        if security_descriptor.is_null() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "null security descriptor",
            ));
        }
        let _sd = LocalBuffer(security_descriptor);

        let mut primary: Handle = std::ptr::null_mut();
        // SAFETY: GetCurrentProcess returns a valid pseudo-handle; primary is writable.
        if unsafe {
            OpenProcessToken(
                GetCurrentProcess(),
                TOKEN_QUERY | TOKEN_DUPLICATE,
                &mut primary,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        let _primary = TokenHandle(primary);
        let mut impersonation: Handle = std::ptr::null_mut();
        // SAFETY: primary is a live process token; request a queryable impersonation token.
        if unsafe {
            DuplicateTokenEx(
                primary,
                TOKEN_QUERY,
                std::ptr::null_mut(),
                SECURITY_IMPERSONATION,
                TOKEN_IMPERSONATION,
                &mut impersonation,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        let _impersonation = TokenHandle(impersonation);
        let mut mapping = GenericMapping {
            generic_read: 0x0012_0089,
            generic_write: 0x0012_0116,
            generic_execute: 0x0012_00A0,
            generic_all: 0x001F_01FF,
        };
        let mut privilege_set = vec![0u64; 128];
        let mut privilege_set_length = (privilege_set.len() * std::mem::size_of::<u64>()) as u32;
        let mut granted_access = 0u32;
        let mut access_status = 0i32;
        // SAFETY: descriptor/token are live; buffers and output pointers are correctly sized/aligned.
        let ok = unsafe {
            AccessCheck(
                security_descriptor,
                impersonation,
                desired_access,
                &mut mapping,
                privilege_set.as_mut_ptr().cast(),
                &mut privilege_set_length,
                &mut granted_access,
                &mut access_status,
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(TokenAccessResult {
            desired_access,
            granted_access,
            allowed: access_status != 0,
        })
    }
    /// Returns the current process token's default owner SID (TokenOwner class).
    /// This is distinct from TokenUser and is the relevant owner identity for
    /// newly created filesystem objects under the token's default-owner policy.
    pub fn current_process_default_owner_sid() -> io::Result<String> {
        let mut token: Handle = std::ptr::null_mut();
        // SAFETY: GetCurrentProcess returns a valid pseudo-handle; token is writable.
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let _token = TokenHandle(token);
        let mut required = 0u32;
        // SAFETY: the first call intentionally queries the required buffer size.
        let first =
            unsafe { GetTokenInformation(token, 4, std::ptr::null_mut(), 0, &mut required) };
        if first != 0 || required < std::mem::size_of::<TokenOwnerInfo>() as u32 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("TokenOwner size query failed or returned an invalid size ({required})"),
            ));
        }
        let mut storage = vec![0u64; (required as usize).div_ceil(std::mem::size_of::<u64>())];
        let mut returned = 0u32;
        // SAFETY: storage is aligned and large enough for the TokenOwner structure and its SID.
        if unsafe {
            GetTokenInformation(
                token,
                4,
                storage.as_mut_ptr().cast(),
                required,
                &mut returned,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        if returned < std::mem::size_of::<TokenOwnerInfo>() as u32 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "TokenOwner response was shorter than TOKEN_OWNER",
            ));
        }
        // SAFETY: successful GetTokenInformation initialized a TOKEN_OWNER at the buffer start.
        let owner = unsafe { (*storage.as_ptr().cast::<TokenOwnerInfo>()).owner };
        if owner.is_null() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "TokenOwner returned a null owner SID",
            ));
        }
        sid_to_string(owner)
    }

    pub fn snapshot_acl_from_handle(handle: &File) -> io::Result<AclSnapshot> {
        let mut owner = std::ptr::null_mut();
        let mut dacl_from_get = std::ptr::null_mut();
        let mut security_descriptor = std::ptr::null_mut();
        // SAFETY: all output pointers are valid and the caller supplies a live
        // file/directory handle opened with READ_CONTROL.
        let status = unsafe {
            GetSecurityInfo(
                handle.as_raw_handle(),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                &mut owner,
                std::ptr::null_mut(),
                &mut dacl_from_get,
                std::ptr::null_mut(),
                &mut security_descriptor,
            )
        };
        if status != 0 {
            return Err(io::Error::from_raw_os_error(status as i32));
        }
        if security_descriptor.is_null() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "GetSecurityInfo returned a null descriptor",
            ));
        }
        let _security_descriptor = LocalBuffer(security_descriptor);
        if owner.is_null() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "security descriptor has no owner SID",
            ));
        }
        let owner_sid = sid_to_string(owner)?;

        let mut dacl_present = 0;
        let mut dacl = std::ptr::null_mut();
        let mut dacl_defaulted = 0;
        // SAFETY: the descriptor was returned by GetSecurityInfo and remains live.
        let ok = unsafe {
            GetSecurityDescriptorDacl(
                security_descriptor,
                &mut dacl_present,
                &mut dacl,
                &mut dacl_defaulted,
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        let dacl_state = if dacl_present == 0 {
            DaclState::Absent
        } else if dacl.is_null() {
            DaclState::Null
        } else {
            DaclState::Present
        };
        if dacl_state != DaclState::Present {
            return Ok(AclSnapshot {
                owner_sid,
                dacl_state,
                dacl_defaulted: dacl_defaulted != 0,
                aces: Vec::new(),
                unsupported_ace_types: Vec::new(),
                structurally_complete: false,
            });
        }

        let mut size_info = AclSizeInformation {
            ace_count: 0,
            acl_bytes_in_use: 0,
            acl_bytes_free: 0,
        };
        // SAFETY: size_info is writable and dacl points into the live descriptor.
        let ok = unsafe {
            GetAclInformation(
                dacl,
                (&mut size_info as *mut AclSizeInformation).cast(),
                std::mem::size_of::<AclSizeInformation>() as u32,
                ACL_SIZE_INFORMATION_CLASS,
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        if size_info.acl_bytes_in_use < 8 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "ACL size is shorter than ACL header",
            ));
        }

        let mut aces = Vec::with_capacity(size_info.ace_count as usize);
        let mut unsupported_ace_types = Vec::new();
        let acl_base = dacl as usize;
        for index in 0..size_info.ace_count {
            let mut ace_ptr: *mut c_void = std::ptr::null_mut();
            // SAFETY: dacl is a valid ACL and index is bounded by AceCount.
            let ok = unsafe { GetAce(dacl, index, &mut ace_ptr) };
            if ok == 0 || ace_ptr.is_null() {
                return Err(io::Error::last_os_error());
            }
            let ace_offset = (ace_ptr as usize).checked_sub(acl_base).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "ACE pointer precedes ACL")
            })?;
            // SAFETY: GetAce returned a pointer to an ACE header within the ACL.
            let header = unsafe { std::ptr::read_unaligned(ace_ptr.cast::<AceHeader>()) };
            let ace_size = header.ace_size as usize;
            if ace_size < std::mem::size_of::<AceHeader>()
                || ace_offset
                    .checked_add(ace_size)
                    .is_none_or(|end| end > size_info.acl_bytes_in_use as usize)
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "ACE bounds exceed ACL",
                ));
            }
            // SAFETY: validated ACE pointer and size lie within AclBytesInUse.
            let raw =
                unsafe { std::slice::from_raw_parts(ace_ptr.cast::<u8>(), ace_size) }.to_vec();
            let standard = matches!(
                header.ace_type,
                ACCESS_ALLOWED_ACE_TYPE | ACCESS_DENIED_ACE_TYPE
            );
            let (mask, trustee_sid) = if standard {
                if ace_size < 8 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "standard ACE shorter than mask and SID prefix",
                    ));
                }
                // SAFETY: the standard ACE layout stores ACCESS_MASK at byte offset 4.
                let mask = unsafe {
                    std::ptr::read_unaligned((ace_ptr as *const u8).add(4).cast::<u32>())
                };
                let sid = unsafe { (ace_ptr as *mut u8).add(8).cast::<c_void>() };
                // SAFETY: SID pointer lies inside the ACE; validate before reading its length.
                if unsafe { IsValidSid(sid) } == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "ACE contains invalid SID",
                    ));
                }
                let sid_len = unsafe { GetLengthSid(sid) } as usize;
                if sid_len == 0 || sid_len > ace_size - 8 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "ACE SID length exceeds ACE bounds",
                    ));
                }
                (Some(mask), Some(sid_to_string(sid)?))
            } else {
                unsupported_ace_types.push(header.ace_type);
                (None, None)
            };
            aces.push(AceSnapshot {
                ace_type: header.ace_type,
                ace_flags: header.ace_flags,
                inherited: header.ace_flags & INHERITED_ACE != 0,
                mask,
                trustee_sid,
                raw,
                understood_standard_allow_or_deny: standard,
            });
        }
        Ok(AclSnapshot {
            owner_sid,
            dacl_state,
            dacl_defaulted: dacl_defaulted != 0,
            aces,
            structurally_complete: unsupported_ace_types.is_empty(),
            unsupported_ace_types,
        })
    }

    fn sid_to_string(sid: *mut c_void) -> io::Result<String> {
        // SAFETY: caller supplies a SID pointer validated by the security APIs.
        if unsafe { IsValidSid(sid) } == 0 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid SID"));
        }
        let mut string_sid: *mut u16 = std::ptr::null_mut();
        // SAFETY: output pointer is valid; Windows allocates the result for LocalFree.
        if unsafe { ConvertSidToStringSidW(sid, &mut string_sid) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let _string_buffer = LocalBuffer(string_sid.cast());
        let mut length = 0usize;
        // Bound scan to 256 UTF-16 units; SID strings are much shorter.
        while length < 256 && unsafe { *string_sid.add(length) } != 0 {
            length += 1;
        }
        if length == 256 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "SID string was not terminated",
            ));
        }
        String::from_utf16(unsafe { std::slice::from_raw_parts(string_sid, length) })
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "SID string is invalid UTF-16"))
    }

    pub fn open_temp_handle(path: &std::path::Path, allow_write_dac: bool) -> io::Result<File> {
        let access =
            READ_CONTROL | FILE_READ_ATTRIBUTES | if allow_write_dac { WRITE_DAC } else { 0 };
        open_temp_handle_with_access(path, access)
    }

    pub fn open_temp_handle_with_access(
        path: &std::path::Path,
        desired_access: u32,
    ) -> io::Result<File> {
        use std::os::windows::ffi::OsStrExt;
        let mut wide: Vec<u16> = path.as_os_str().encode_wide().collect();
        if wide.contains(&0) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "path contains NUL",
            ));
        }
        wide.push(0);
        // SAFETY: wide is NUL-terminated and the returned handle is checked before ownership transfer.
        let raw = unsafe {
            CreateFileW(
                wide.as_ptr(),
                desired_access,
                FILE_SHARE_ALL,
                std::ptr::null_mut(),
                OPEN_EXISTING,
                FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
                std::ptr::null_mut(),
            )
        };
        if raw == -1isize as Handle {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: raw is a new valid handle owned by this function.
        Ok(unsafe { File::from_raw_handle(raw as RawHandle) })
    }

    pub fn set_ordered_dacl_for_temp_test(handle: &File) -> io::Result<()> {
        const ACL_REVISION: u32 = 2;
        const FILE_WRITE_DATA: u32 = 0x0000_0002;
        const READ_CONTROL_MASK: u32 = 0x0002_0000;
        let sid_text: Vec<u16> = "S-1-1-0".encode_utf16().chain(std::iter::once(0)).collect();
        let mut sid = std::ptr::null_mut();
        // SAFETY: sid_text is NUL-terminated and sid is a valid output pointer.
        if unsafe { ConvertStringSidToSidW(sid_text.as_ptr(), &mut sid) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let _sid_buffer = LocalBuffer(sid);
        // Use u64 backing storage to provide alignment suitable for ACL/ACE structures.
        let mut storage = vec![0u64; 128];
        let acl = storage.as_mut_ptr().cast::<c_void>();
        // SAFETY: storage is writable, aligned, and large enough for this synthetic ACL.
        if unsafe { InitializeAcl(acl, (storage.len() * 8) as u32, ACL_REVISION) } == 0 {
            return Err(io::Error::last_os_error());
        }
        // Deny then allow; inherited parent ACEs remain visible in the returned DACL.
        // SAFETY: acl is initialized and sid is a valid allocated SID.
        if unsafe { AddAccessDeniedAceEx(acl, ACL_REVISION, 0, FILE_WRITE_DATA, sid) } == 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: acl is initialized and sid is a valid allocated SID.
        if unsafe { AddAccessAllowedAceEx(acl, ACL_REVISION, 0, READ_CONTROL_MASK, sid) } == 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: SetSecurityInfo copies the DACL synchronously; storage remains live for the call.
        let status = unsafe {
            SetSecurityInfo(
                handle.as_raw_handle(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                acl,
                std::ptr::null_mut(),
            )
        };
        if status == 0 {
            Ok(())
        } else {
            Err(io::Error::from_raw_os_error(status as i32))
        }
    }
    /// Installs conflicting FILE_WRITE_DATA ACEs in the requested order on a disposable test object.
    /// This is deliberately test-only: it records how the current token's AccessCheck treats ACE order.
    pub fn set_conflicting_write_dacl_for_temp_test(
        handle: &File,
        deny_first: bool,
    ) -> io::Result<()> {
        const ACL_REVISION: u32 = 2;
        const FILE_WRITE_DATA: u32 = 0x0000_0002;
        const READ_CONTROL_MASK: u32 = 0x0002_0000;
        let sid_text: Vec<u16> = "S-1-1-0".encode_utf16().chain(std::iter::once(0)).collect();
        let mut sid = std::ptr::null_mut();
        if unsafe { ConvertStringSidToSidW(sid_text.as_ptr(), &mut sid) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let _sid_buffer = LocalBuffer(sid);
        let mut storage = vec![0u64; 128];
        let acl = storage.as_mut_ptr().cast::<c_void>();
        if unsafe { InitializeAcl(acl, (storage.len() * 8) as u32, ACL_REVISION) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let add_deny =
            || unsafe { AddAccessDeniedAceEx(acl, ACL_REVISION, 0, FILE_WRITE_DATA, sid) };
        let add_allow = || unsafe {
            AddAccessAllowedAceEx(
                acl,
                ACL_REVISION,
                0,
                FILE_WRITE_DATA | READ_CONTROL_MASK,
                sid,
            )
        };
        let (first, second) = if deny_first {
            (add_deny(), add_allow())
        } else {
            (add_allow(), add_deny())
        };
        if first == 0 || second == 0 {
            return Err(io::Error::last_os_error());
        }
        let status = unsafe {
            SetSecurityInfo(
                handle.as_raw_handle(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                acl,
                std::ptr::null_mut(),
            )
        };
        if status == 0 {
            Ok(())
        } else {
            Err(io::Error::from_raw_os_error(status as i32))
        }
    }
    /// Installs conflicting inheritable FILE_WRITE_DATA ACEs on a disposable parent directory.
    /// The child should receive inherited copies, allowing order and AccessCheck to be observed.
    pub fn set_conflicting_inheritable_write_dacl_for_temp_test(
        handle: &File,
        deny_first: bool,
    ) -> io::Result<()> {
        const ACL_REVISION: u32 = 2;
        const INHERIT_FLAGS: u32 = 0x0003; // OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE
        const FILE_WRITE_DATA: u32 = 0x0000_0002;
        const FILE_ADD_SUBDIRECTORY: u32 = 0x0000_0004;
        const FILE_LIST_DIRECTORY: u32 = 0x0000_0001;
        const FILE_TRAVERSE: u32 = 0x0000_0020;
        const FILE_READ_ATTRIBUTES: u32 = 0x0000_0080;
        const READ_CONTROL_MASK: u32 = 0x0002_0000;
        let sid_text: Vec<u16> = "S-1-1-0".encode_utf16().chain(std::iter::once(0)).collect();
        let mut sid = std::ptr::null_mut();
        if unsafe { ConvertStringSidToSidW(sid_text.as_ptr(), &mut sid) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let _sid_buffer = LocalBuffer(sid);
        let mut storage = vec![0u64; 128];
        let acl = storage.as_mut_ptr().cast::<c_void>();
        if unsafe { InitializeAcl(acl, (storage.len() * 8) as u32, ACL_REVISION) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let allowed = FILE_WRITE_DATA
            | FILE_ADD_SUBDIRECTORY
            | FILE_LIST_DIRECTORY
            | FILE_TRAVERSE
            | FILE_READ_ATTRIBUTES
            | READ_CONTROL_MASK;
        let add_deny = || unsafe {
            AddAccessDeniedAceEx(acl, ACL_REVISION, INHERIT_FLAGS, FILE_WRITE_DATA, sid)
        };
        let add_allow =
            || unsafe { AddAccessAllowedAceEx(acl, ACL_REVISION, INHERIT_FLAGS, allowed, sid) };
        let (first, second) = if deny_first {
            (add_deny(), add_allow())
        } else {
            (add_allow(), add_deny())
        };
        if first == 0 || second == 0 {
            return Err(io::Error::last_os_error());
        }
        let status = unsafe {
            SetSecurityInfo(
                handle.as_raw_handle(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                acl,
                std::ptr::null_mut(),
            )
        };
        if status == 0 {
            Ok(())
        } else {
            Err(io::Error::from_raw_os_error(status as i32))
        }
    }
    /// Installs a deny ACE with caller-selected inheritance flags plus an inheritable allow
    /// ACE that keeps a disposable directory tree creatable for the probe.
    pub fn set_inheritance_scope_probe_dacl_for_temp_test(
        handle: &File,
        deny_flags: u32,
    ) -> io::Result<()> {
        const ACL_REVISION: u32 = 2;
        const INHERIT_FLAGS: u32 = 0x0003;
        const FILE_WRITE_DATA: u32 = 0x0000_0002;
        const FILE_ADD_SUBDIRECTORY: u32 = 0x0000_0004;
        const FILE_LIST_DIRECTORY: u32 = 0x0000_0001;
        const FILE_TRAVERSE: u32 = 0x0000_0020;
        const FILE_READ_ATTRIBUTES: u32 = 0x0000_0080;
        const READ_CONTROL_MASK: u32 = 0x0002_0000;
        if deny_flags & !0x000F != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "unsupported ACE inheritance flags",
            ));
        }
        let sid_text: Vec<u16> = "S-1-1-0".encode_utf16().chain(std::iter::once(0)).collect();
        let mut sid = std::ptr::null_mut();
        if unsafe { ConvertStringSidToSidW(sid_text.as_ptr(), &mut sid) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let _sid_buffer = LocalBuffer(sid);
        let mut storage = vec![0u64; 128];
        let acl = storage.as_mut_ptr().cast::<c_void>();
        if unsafe { InitializeAcl(acl, (storage.len() * 8) as u32, ACL_REVISION) } == 0 {
            return Err(io::Error::last_os_error());
        }
        if unsafe { AddAccessDeniedAceEx(acl, ACL_REVISION, deny_flags, FILE_WRITE_DATA, sid) } == 0
        {
            return Err(io::Error::last_os_error());
        }
        let allowed = FILE_WRITE_DATA
            | FILE_ADD_SUBDIRECTORY
            | FILE_LIST_DIRECTORY
            | FILE_TRAVERSE
            | FILE_READ_ATTRIBUTES
            | READ_CONTROL_MASK;
        if unsafe { AddAccessAllowedAceEx(acl, ACL_REVISION, INHERIT_FLAGS, allowed, sid) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let status = unsafe {
            SetSecurityInfo(
                handle.as_raw_handle(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                acl,
                std::ptr::null_mut(),
            )
        };
        if status == 0 {
            Ok(())
        } else {
            Err(io::Error::from_raw_os_error(status as i32))
        }
    }
    /// Installs a DELETE deny ACE with caller-selected inheritance scope and an inheritable
    /// allow ACE for disposable file/directory creation and cleanup.
    pub fn set_inheritance_object_container_probe_dacl_for_temp_test(
        handle: &File,
        deny_flags: u32,
    ) -> io::Result<()> {
        const ACL_REVISION: u32 = 2;
        const INHERIT_FLAGS: u32 = 0x0003;
        const DELETE_RIGHT: u32 = 0x0001_0000;
        const FILE_ADD_FILE: u32 = 0x0000_0002;
        const FILE_ADD_SUBDIRECTORY: u32 = 0x0000_0004;
        const FILE_LIST_DIRECTORY: u32 = 0x0000_0001;
        const FILE_TRAVERSE: u32 = 0x0000_0020;
        const FILE_READ_ATTRIBUTES: u32 = 0x0000_0080;
        const READ_CONTROL_MASK: u32 = 0x0002_0000;
        if deny_flags & !0x000F != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "unsupported ACE inheritance flags",
            ));
        }
        let sid_text: Vec<u16> = "S-1-1-0".encode_utf16().chain(std::iter::once(0)).collect();
        let mut sid = std::ptr::null_mut();
        if unsafe { ConvertStringSidToSidW(sid_text.as_ptr(), &mut sid) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let _sid_buffer = LocalBuffer(sid);
        let mut storage = vec![0u64; 128];
        let acl = storage.as_mut_ptr().cast::<c_void>();
        if unsafe { InitializeAcl(acl, (storage.len() * 8) as u32, ACL_REVISION) } == 0 {
            return Err(io::Error::last_os_error());
        }
        if unsafe { AddAccessDeniedAceEx(acl, ACL_REVISION, deny_flags, DELETE_RIGHT, sid) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let allowed = DELETE_RIGHT
            | FILE_ADD_FILE
            | FILE_ADD_SUBDIRECTORY
            | FILE_LIST_DIRECTORY
            | FILE_TRAVERSE
            | FILE_READ_ATTRIBUTES
            | READ_CONTROL_MASK;
        if unsafe { AddAccessAllowedAceEx(acl, ACL_REVISION, INHERIT_FLAGS, allowed, sid) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let status = unsafe {
            SetSecurityInfo(
                handle.as_raw_handle(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                acl,
                std::ptr::null_mut(),
            )
        };
        if status == 0 {
            Ok(())
        } else {
            Err(io::Error::from_raw_os_error(status as i32))
        }
    }
    /// Installs a parent FILE_DELETE_CHILD deny and a container-inherited child DELETE deny.
    /// The remaining allows are limited to operations needed by the disposable rename probe.
    pub fn set_inherited_rename_route_denies_for_temp_test(handle: &File) -> io::Result<()> {
        const ACL_REVISION: u32 = 2;
        const CONTAINER_INHERIT: u32 = 0x0002;
        const DELETE_RIGHT: u32 = 0x0001_0000;
        const FILE_DELETE_CHILD: u32 = 0x0000_0040;
        const FILE_ADD_FILE: u32 = 0x0000_0002;
        const FILE_ADD_SUBDIRECTORY: u32 = 0x0000_0004;
        const FILE_LIST_DIRECTORY: u32 = 0x0000_0001;
        const FILE_TRAVERSE: u32 = 0x0000_0020;
        const FILE_READ_ATTRIBUTES: u32 = 0x0000_0080;
        const READ_CONTROL_MASK: u32 = 0x0002_0000;
        const WRITE_DAC_MASK: u32 = 0x0004_0000;
        const SYNCHRONIZE_MASK: u32 = 0x0010_0000;
        let sid_text: Vec<u16> = "S-1-1-0".encode_utf16().chain(std::iter::once(0)).collect();
        let mut sid = std::ptr::null_mut();
        if unsafe { ConvertStringSidToSidW(sid_text.as_ptr(), &mut sid) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let _sid_buffer = LocalBuffer(sid);
        let mut storage = vec![0u64; 128];
        let acl = storage.as_mut_ptr().cast::<c_void>();
        if unsafe { InitializeAcl(acl, (storage.len() * 8) as u32, ACL_REVISION) } == 0 {
            return Err(io::Error::last_os_error());
        }
        // This deny applies to the source parent itself: it closes the parent-mediated rename route.
        if unsafe { AddAccessDeniedAceEx(acl, ACL_REVISION, 0, FILE_DELETE_CHILD, sid) } == 0 {
            return Err(io::Error::last_os_error());
        }
        // This deny is inherited by child directories: it closes the child-object DELETE route.
        if unsafe { AddAccessDeniedAceEx(acl, ACL_REVISION, CONTAINER_INHERIT, DELETE_RIGHT, sid) }
            == 0
        {
            return Err(io::Error::last_os_error());
        }
        let allowed = DELETE_RIGHT
            | FILE_DELETE_CHILD
            | FILE_ADD_FILE
            | FILE_ADD_SUBDIRECTORY
            | FILE_LIST_DIRECTORY
            | FILE_TRAVERSE
            | FILE_READ_ATTRIBUTES
            | READ_CONTROL_MASK
            | WRITE_DAC_MASK
            | SYNCHRONIZE_MASK;
        if unsafe { AddAccessAllowedAceEx(acl, ACL_REVISION, CONTAINER_INHERIT, allowed, sid) } == 0
        {
            return Err(io::Error::last_os_error());
        }
        let status = unsafe {
            SetSecurityInfo(
                handle.as_raw_handle(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                acl,
                std::ptr::null_mut(),
            )
        };
        if status == 0 {
            Ok(())
        } else {
            Err(io::Error::from_raw_os_error(status as i32))
        }
    }
    /// Adds an OWNER RIGHTS deny for WRITE_DAC to a protected disposable-object DACL.
    /// Everyone receives only the read rights needed by the probe; no explicit WRITE_DAC
    /// allow ACE is present. The owner-rights SID is S-1-3-4.
    pub fn set_owner_rights_write_dac_deny_for_temp_test(handle: &File) -> io::Result<()> {
        const ACL_REVISION: u32 = 2;
        const READ_CONTROL_MASK: u32 = 0x0002_0000;
        const WRITE_DAC_MASK: u32 = 0x0004_0000;
        const FILE_READ_ATTRIBUTES: u32 = 0x0000_0080;
        const SYNCHRONIZE_MASK: u32 = 0x0010_0000;
        const PROTECTED_DACL_SECURITY_INFORMATION: u32 = 0x8000_0000;

        let everyone_text: Vec<u16> = "S-1-1-0".encode_utf16().chain(std::iter::once(0)).collect();
        let owner_rights_text: Vec<u16> =
            "S-1-3-4".encode_utf16().chain(std::iter::once(0)).collect();
        let mut everyone_sid = std::ptr::null_mut();
        let mut owner_rights_sid = std::ptr::null_mut();
        if unsafe { ConvertStringSidToSidW(everyone_text.as_ptr(), &mut everyone_sid) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let _everyone_buffer = LocalBuffer(everyone_sid);
        if unsafe { ConvertStringSidToSidW(owner_rights_text.as_ptr(), &mut owner_rights_sid) } == 0
        {
            return Err(io::Error::last_os_error());
        }
        let _owner_rights_buffer = LocalBuffer(owner_rights_sid);

        let mut storage = vec![0u64; 128];
        let acl = storage.as_mut_ptr().cast::<c_void>();
        if unsafe { InitializeAcl(acl, (storage.len() * 8) as u32, ACL_REVISION) } == 0 {
            return Err(io::Error::last_os_error());
        }
        if unsafe { AddAccessDeniedAceEx(acl, ACL_REVISION, 0, WRITE_DAC_MASK, owner_rights_sid) }
            == 0
        {
            return Err(io::Error::last_os_error());
        }
        let read_only = READ_CONTROL_MASK | FILE_READ_ATTRIBUTES | SYNCHRONIZE_MASK;
        if unsafe { AddAccessAllowedAceEx(acl, ACL_REVISION, 0, read_only, everyone_sid) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let status = unsafe {
            SetSecurityInfo(
                handle.as_raw_handle(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                acl,
                std::ptr::null_mut(),
            )
        };
        if status == 0 {
            Ok(())
        } else {
            Err(io::Error::from_raw_os_error(status as i32))
        }
    }

    /// Installs a protected disposable DACL; optionally grants WRITE_OWNER to OWNER RIGHTS only.
    pub fn set_owner_rights_write_owner_dacl_for_temp_test(
        handle: &File,
        owner_rights_allow: bool,
    ) -> io::Result<()> {
        const ACL_REVISION: u32 = 2;
        const READ_CONTROL_MASK: u32 = 0x0002_0000;
        const WRITE_OWNER_MASK: u32 = 0x0008_0000;
        const FILE_READ_ATTRIBUTES: u32 = 0x0000_0080;
        const SYNCHRONIZE_MASK: u32 = 0x0010_0000;
        const PROTECTED_DACL_SECURITY_INFORMATION: u32 = 0x8000_0000;
        let everyone_text: Vec<u16> = "S-1-1-0".encode_utf16().chain(std::iter::once(0)).collect();
        let owner_rights_text: Vec<u16> =
            "S-1-3-4".encode_utf16().chain(std::iter::once(0)).collect();
        let mut everyone_sid = std::ptr::null_mut();
        let mut owner_rights_sid = std::ptr::null_mut();
        if unsafe { ConvertStringSidToSidW(everyone_text.as_ptr(), &mut everyone_sid) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let _everyone_buffer = LocalBuffer(everyone_sid);
        if unsafe { ConvertStringSidToSidW(owner_rights_text.as_ptr(), &mut owner_rights_sid) } == 0
        {
            return Err(io::Error::last_os_error());
        }
        let _owner_rights_buffer = LocalBuffer(owner_rights_sid);
        let mut storage = vec![0u64; 128];
        let acl = storage.as_mut_ptr().cast::<c_void>();
        if unsafe { InitializeAcl(acl, (storage.len() * 8) as u32, ACL_REVISION) } == 0 {
            return Err(io::Error::last_os_error());
        }
        if owner_rights_allow
            && unsafe {
                AddAccessAllowedAceEx(acl, ACL_REVISION, 0, WRITE_OWNER_MASK, owner_rights_sid)
            } == 0
        {
            return Err(io::Error::last_os_error());
        }
        let read_only = READ_CONTROL_MASK | FILE_READ_ATTRIBUTES | SYNCHRONIZE_MASK;
        if unsafe { AddAccessAllowedAceEx(acl, ACL_REVISION, 0, read_only, everyone_sid) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let status = unsafe {
            SetSecurityInfo(
                handle.as_raw_handle(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                acl,
                std::ptr::null_mut(),
            )
        };
        if status == 0 {
            Ok(())
        } else {
            Err(io::Error::from_raw_os_error(status as i32))
        }
    }

    /// Adds an OWNER RIGHTS allow ACE for WRITE_DAC to a protected disposable-object DACL.
    /// Everyone receives only the read rights needed by the probe; the sole WRITE_DAC
    /// allow ACE is targeted to the OWNER RIGHTS SID (S-1-3-4).
    pub fn set_owner_rights_write_dac_allow_for_temp_test(handle: &File) -> io::Result<()> {
        const ACL_REVISION: u32 = 2;
        const READ_CONTROL_MASK: u32 = 0x0002_0000;
        const WRITE_DAC_MASK: u32 = 0x0004_0000;
        const FILE_READ_ATTRIBUTES: u32 = 0x0000_0080;
        const SYNCHRONIZE_MASK: u32 = 0x0010_0000;
        const PROTECTED_DACL_SECURITY_INFORMATION: u32 = 0x8000_0000;
        let everyone_text: Vec<u16> = "S-1-1-0".encode_utf16().chain(std::iter::once(0)).collect();
        let owner_rights_text: Vec<u16> =
            "S-1-3-4".encode_utf16().chain(std::iter::once(0)).collect();
        let mut everyone_sid = std::ptr::null_mut();
        let mut owner_rights_sid = std::ptr::null_mut();
        if unsafe { ConvertStringSidToSidW(everyone_text.as_ptr(), &mut everyone_sid) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let _everyone_buffer = LocalBuffer(everyone_sid);
        if unsafe { ConvertStringSidToSidW(owner_rights_text.as_ptr(), &mut owner_rights_sid) } == 0
        {
            return Err(io::Error::last_os_error());
        }
        let _owner_rights_buffer = LocalBuffer(owner_rights_sid);
        let mut storage = vec![0u64; 128];
        let acl = storage.as_mut_ptr().cast::<c_void>();
        if unsafe { InitializeAcl(acl, (storage.len() * 8) as u32, ACL_REVISION) } == 0 {
            return Err(io::Error::last_os_error());
        }
        if unsafe { AddAccessAllowedAceEx(acl, ACL_REVISION, 0, WRITE_DAC_MASK, owner_rights_sid) }
            == 0
        {
            return Err(io::Error::last_os_error());
        }
        let read_only = READ_CONTROL_MASK | FILE_READ_ATTRIBUTES | SYNCHRONIZE_MASK;
        if unsafe { AddAccessAllowedAceEx(acl, ACL_REVISION, 0, read_only, everyone_sid) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let status = unsafe {
            SetSecurityInfo(
                handle.as_raw_handle(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                acl,
                std::ptr::null_mut(),
            )
        };
        if status == 0 {
            Ok(())
        } else {
            Err(io::Error::from_raw_os_error(status as i32))
        }
    }

    /// Installs the inherited rename denies without granting WRITE_DAC/WRITE_OWNER
    /// in any explicit allow ACE. Used to isolate owner-implicit WRITE_DAC.
    pub fn set_inherited_rename_route_denies_without_write_dac_for_temp_test(
        handle: &File,
    ) -> io::Result<()> {
        const ACL_REVISION: u32 = 2;
        const PROTECTED_DACL_SECURITY_INFORMATION: u32 = 0x8000_0000;
        const CONTAINER_INHERIT: u32 = 0x0002;
        const DELETE_RIGHT: u32 = 0x0001_0000;
        const FILE_DELETE_CHILD: u32 = 0x0000_0040;
        const FILE_ADD_FILE: u32 = 0x0000_0002;
        const FILE_ADD_SUBDIRECTORY: u32 = 0x0000_0004;
        const FILE_LIST_DIRECTORY: u32 = 0x0000_0001;
        const FILE_TRAVERSE: u32 = 0x0000_0020;
        const FILE_READ_ATTRIBUTES: u32 = 0x0000_0080;
        const READ_CONTROL_MASK: u32 = 0x0002_0000;
        const SYNCHRONIZE_MASK: u32 = 0x0010_0000;
        let sid_text: Vec<u16> = "S-1-1-0".encode_utf16().chain(std::iter::once(0)).collect();
        let mut sid = std::ptr::null_mut();
        if unsafe { ConvertStringSidToSidW(sid_text.as_ptr(), &mut sid) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let _sid_buffer = LocalBuffer(sid);
        let mut storage = vec![0u64; 128];
        let acl = storage.as_mut_ptr().cast::<c_void>();
        if unsafe { InitializeAcl(acl, (storage.len() * 8) as u32, ACL_REVISION) } == 0 {
            return Err(io::Error::last_os_error());
        }
        if unsafe { AddAccessDeniedAceEx(acl, ACL_REVISION, 0, FILE_DELETE_CHILD, sid) } == 0 {
            return Err(io::Error::last_os_error());
        }
        if unsafe { AddAccessDeniedAceEx(acl, ACL_REVISION, CONTAINER_INHERIT, DELETE_RIGHT, sid) }
            == 0
        {
            return Err(io::Error::last_os_error());
        }
        let allowed = DELETE_RIGHT
            | FILE_DELETE_CHILD
            | FILE_ADD_FILE
            | FILE_ADD_SUBDIRECTORY
            | FILE_LIST_DIRECTORY
            | FILE_TRAVERSE
            | FILE_READ_ATTRIBUTES
            | READ_CONTROL_MASK
            | SYNCHRONIZE_MASK;
        if unsafe { AddAccessAllowedAceEx(acl, ACL_REVISION, CONTAINER_INHERIT, allowed, sid) } == 0
        {
            return Err(io::Error::last_os_error());
        }
        let status = unsafe {
            SetSecurityInfo(
                handle.as_raw_handle(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                acl,
                std::ptr::null_mut(),
            )
        };
        if status == 0 {
            Ok(())
        } else {
            Err(io::Error::from_raw_os_error(status as i32))
        }
    }

    /// Installs a deny FILE_DELETE_CHILD ACE for Everyone on a disposable test directory.
    /// The allow ACE retains only the read/traverse rights needed by the test probe.
    pub fn set_parent_deny_delete_child_for_temp_test(handle: &File) -> io::Result<()> {
        const ACL_REVISION: u32 = 2;
        const FILE_DELETE_CHILD: u32 = 0x0000_0040;
        const FILE_LIST_DIRECTORY: u32 = 0x0000_0001;
        const FILE_TRAVERSE: u32 = 0x0000_0020;
        const FILE_READ_ATTRIBUTES: u32 = 0x0000_0080;
        const READ_CONTROL_MASK: u32 = 0x0002_0000;
        let sid_text: Vec<u16> = "S-1-1-0".encode_utf16().chain(std::iter::once(0)).collect();
        let mut sid = std::ptr::null_mut();
        if unsafe { ConvertStringSidToSidW(sid_text.as_ptr(), &mut sid) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let _sid_buffer = LocalBuffer(sid);
        let mut storage = vec![0u64; 128];
        let acl = storage.as_mut_ptr().cast::<c_void>();
        if unsafe { InitializeAcl(acl, (storage.len() * 8) as u32, ACL_REVISION) } == 0 {
            return Err(io::Error::last_os_error());
        }
        if unsafe { AddAccessDeniedAceEx(acl, ACL_REVISION, 0, FILE_DELETE_CHILD, sid) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let allowed =
            READ_CONTROL_MASK | FILE_LIST_DIRECTORY | FILE_TRAVERSE | FILE_READ_ATTRIBUTES;
        if unsafe { AddAccessAllowedAceEx(acl, ACL_REVISION, 0, allowed, sid) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let status = unsafe {
            SetSecurityInfo(
                handle.as_raw_handle(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                acl,
                std::ptr::null_mut(),
            )
        };
        if status == 0 {
            Ok(())
        } else {
            Err(io::Error::from_raw_os_error(status as i32))
        }
    }
    /// Denies DELETE on a disposable test object while retaining read/traverse access.
    pub fn set_object_deny_delete_for_temp_test(handle: &File) -> io::Result<()> {
        const ACL_REVISION: u32 = 2;
        const DELETE_RIGHT: u32 = 0x0001_0000;
        const FILE_LIST_DIRECTORY: u32 = 0x0000_0001;
        const FILE_TRAVERSE: u32 = 0x0000_0020;
        const FILE_READ_ATTRIBUTES: u32 = 0x0000_0080;
        const READ_CONTROL_MASK: u32 = 0x0002_0000;
        let sid_text: Vec<u16> = "S-1-1-0".encode_utf16().chain(std::iter::once(0)).collect();
        let mut sid = std::ptr::null_mut();
        if unsafe { ConvertStringSidToSidW(sid_text.as_ptr(), &mut sid) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let _sid_buffer = LocalBuffer(sid);
        let mut storage = vec![0u64; 128];
        let acl = storage.as_mut_ptr().cast::<c_void>();
        if unsafe { InitializeAcl(acl, (storage.len() * 8) as u32, ACL_REVISION) } == 0 {
            return Err(io::Error::last_os_error());
        }
        if unsafe { AddAccessDeniedAceEx(acl, ACL_REVISION, 0, DELETE_RIGHT, sid) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let allowed =
            READ_CONTROL_MASK | FILE_LIST_DIRECTORY | FILE_TRAVERSE | FILE_READ_ATTRIBUTES;
        if unsafe { AddAccessAllowedAceEx(acl, ACL_REVISION, 0, allowed, sid) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let status = unsafe {
            SetSecurityInfo(
                handle.as_raw_handle(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                acl,
                std::ptr::null_mut(),
            )
        };
        if status == 0 {
            Ok(())
        } else {
            Err(io::Error::from_raw_os_error(status as i32))
        }
    }
    /// Allows parent-directory FILE_DELETE_CHILD on a disposable test directory.
    pub fn set_parent_allow_delete_child_for_temp_test(handle: &File) -> io::Result<()> {
        const ACL_REVISION: u32 = 2;
        const FILE_DELETE_CHILD: u32 = 0x0000_0040;
        const FILE_LIST_DIRECTORY: u32 = 0x0000_0001;
        const FILE_TRAVERSE: u32 = 0x0000_0020;
        const FILE_READ_ATTRIBUTES: u32 = 0x0000_0080;
        const FILE_ADD_SUBDIRECTORY: u32 = 0x0000_0004;
        const READ_CONTROL_MASK: u32 = 0x0002_0000;
        let sid_text: Vec<u16> = "S-1-1-0".encode_utf16().chain(std::iter::once(0)).collect();
        let mut sid = std::ptr::null_mut();
        if unsafe { ConvertStringSidToSidW(sid_text.as_ptr(), &mut sid) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let _sid_buffer = LocalBuffer(sid);
        let mut storage = vec![0u64; 128];
        let acl = storage.as_mut_ptr().cast::<c_void>();
        if unsafe { InitializeAcl(acl, (storage.len() * 8) as u32, ACL_REVISION) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let allowed = FILE_DELETE_CHILD
            | FILE_ADD_SUBDIRECTORY
            | READ_CONTROL_MASK
            | FILE_LIST_DIRECTORY
            | FILE_TRAVERSE
            | FILE_READ_ATTRIBUTES;
        if unsafe { AddAccessAllowedAceEx(acl, ACL_REVISION, 0, allowed, sid) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let status = unsafe {
            SetSecurityInfo(
                handle.as_raw_handle(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                acl,
                std::ptr::null_mut(),
            )
        };
        if status == 0 {
            Ok(())
        } else {
            Err(io::Error::from_raw_os_error(status as i32))
        }
    }
    pub fn set_null_dacl_for_temp_test(handle: &File) -> io::Result<()> {
        // SAFETY: null DACL intentionally sets an unrestricted DACL on a disposable test object only.
        let status = unsafe {
            SetSecurityInfo(
                handle.as_raw_handle(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        if status == 0 {
            Ok(())
        } else {
            Err(io::Error::from_raw_os_error(status as i32))
        }
    }
}

#[cfg(windows)]
#[allow(unused_imports)]
pub use imp::{
    access_check_current_process_token, current_process_default_owner_sid,
    derive_conservative_mutation_evidence, open_temp_handle, open_temp_handle_with_access,
    set_conflicting_inheritable_write_dacl_for_temp_test, set_conflicting_write_dacl_for_temp_test,
    set_inheritance_object_container_probe_dacl_for_temp_test,
    set_inheritance_scope_probe_dacl_for_temp_test,
    set_inherited_rename_route_denies_for_temp_test,
    set_inherited_rename_route_denies_without_write_dac_for_temp_test, set_null_dacl_for_temp_test,
    set_object_deny_delete_for_temp_test, set_ordered_dacl_for_temp_test,
    set_owner_rights_write_dac_allow_for_temp_test, set_owner_rights_write_dac_deny_for_temp_test,
    set_owner_rights_write_owner_dacl_for_temp_test, set_parent_allow_delete_child_for_temp_test,
    set_parent_deny_delete_child_for_temp_test, snapshot_acl_from_handle, AceSnapshot, AclSnapshot,
    DaclState, TokenAccessResult,
};

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_root() -> std::path::PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("qrun-acl-probe-{}-{nonce}", std::process::id()))
    }

    #[test]
    fn snapshots_owner_and_raw_standard_aces_from_a_handle() {
        let root = temp_root();
        fs::create_dir(&root).unwrap();
        let handle = open_temp_handle(&root, false).unwrap();
        let snapshot = snapshot_acl_from_handle(&handle).unwrap();
        assert!(snapshot.owner_sid.starts_with("S-1-"));
        assert_eq!(snapshot.dacl_state, DaclState::Present);
        assert!(!snapshot.aces.is_empty());
        for ace in &snapshot.aces {
            assert!(!ace.raw.is_empty());
            assert!(ace.inherited == (ace.ace_flags & 0x10 != 0));
        }
        eprintln!(
            "ACL snapshot: owner={}, ACEs={}, unsupported={:?}, complete={}",
            snapshot.owner_sid,
            snapshot.aces.len(),
            snapshot.unsupported_ace_types,
            snapshot.structurally_complete
        );
        drop(handle);
        fs::remove_dir(root).unwrap();
    }

    #[test]
    fn current_owner_can_reopen_write_dac_without_explicit_allow_ace() {
        const WRITE_DAC_RIGHT: u32 = 0x0004_0000;
        let root = temp_root();
        let child = root.join("child");
        fs::create_dir(&root).unwrap();

        // Keep a parent cleanup handle, then install a protected DACL with no explicit WRITE_DAC.
        let parent_restore_handle = open_temp_handle(&root, true).unwrap();
        set_inherited_rename_route_denies_without_write_dac_for_temp_test(&parent_restore_handle)
            .unwrap();

        // Create the child after the policy so it inherits only the synthetic parent DACL.
        fs::create_dir(&child).unwrap();
        let child_restore_handle = open_temp_handle(&child, true).unwrap();

        let parent_snapshot = snapshot_acl_from_handle(&parent_restore_handle).unwrap();
        let child_snapshot = snapshot_acl_from_handle(&child_restore_handle).unwrap();
        let token_owner = current_process_default_owner_sid().unwrap();
        let parent_owner_matches = parent_snapshot.owner_sid == token_owner;
        let child_owner_matches = child_snapshot.owner_sid == token_owner;
        let has_explicit_parent_write_dac = parent_snapshot.aces.iter().any(|ace| {
            ace.ace_type == 0 && ace.mask.is_some_and(|mask| mask & WRITE_DAC_RIGHT != 0)
        });
        let has_explicit_child_write_dac = child_snapshot.aces.iter().any(|ace| {
            ace.ace_type == 0 && ace.mask.is_some_and(|mask| mask & WRITE_DAC_RIGHT != 0)
        });
        let parent_write_dac_aces: Vec<_> = parent_snapshot
            .aces
            .iter()
            .filter(|ace| {
                ace.ace_type == 0 && ace.mask.is_some_and(|mask| mask & WRITE_DAC_RIGHT != 0)
            })
            .map(|ace| {
                (
                    ace.ace_type,
                    ace.ace_flags,
                    ace.inherited,
                    ace.mask,
                    ace.trustee_sid.clone(),
                )
            })
            .collect();
        let child_write_dac_aces: Vec<_> = child_snapshot
            .aces
            .iter()
            .filter(|ace| {
                ace.ace_type == 0 && ace.mask.is_some_and(|mask| mask & WRITE_DAC_RIGHT != 0)
            })
            .map(|ace| {
                (
                    ace.ace_type,
                    ace.ace_flags,
                    ace.inherited,
                    ace.mask,
                    ace.trustee_sid.clone(),
                )
            })
            .collect();
        let parent_write_dac =
            access_check_current_process_token(&parent_restore_handle, WRITE_DAC_RIGHT).unwrap();
        let child_write_dac =
            access_check_current_process_token(&child_restore_handle, WRITE_DAC_RIGHT).unwrap();

        // Reopen fresh handles after installing the DACL. Retain the pre-policy handles as cleanup fallback.
        let parent_fresh = open_temp_handle(&root, true);
        let child_fresh = open_temp_handle(&child, true);
        let parent_reset = match parent_fresh.as_ref() {
            Ok(handle) => set_null_dacl_for_temp_test(handle),
            Err(_) => set_null_dacl_for_temp_test(&parent_restore_handle),
        };
        let child_reset = match child_fresh.as_ref() {
            Ok(handle) => set_null_dacl_for_temp_test(handle),
            Err(_) => set_null_dacl_for_temp_test(&child_restore_handle),
        };

        let parent_fresh_ok = parent_fresh.is_ok();
        let child_fresh_ok = child_fresh.is_ok();
        let parent_fresh_error = parent_fresh.as_ref().err().map(ToString::to_string);
        let child_fresh_error = child_fresh.as_ref().err().map(ToString::to_string);

        eprintln!(
            "Owner WRITE_DAC probe: token_default_owner={}, parent_owner={}, child_owner={}, parent_owner_match={}, child_owner_match={}, explicit_parent_WRITE_DAC_ACE={}, explicit_child_WRITE_DAC_ACE={}, parent_WRITE_DAC_ACES={:?}, child_WRITE_DAC_ACES={:?}, parent_AccessCheck={}, child_AccessCheck={}, parent_fresh_handle={}, child_fresh_handle={}",
            token_owner,
            parent_snapshot.owner_sid,
            child_snapshot.owner_sid,
            parent_owner_matches,
            child_owner_matches,
            has_explicit_parent_write_dac,
            has_explicit_child_write_dac,
            parent_write_dac_aces,
            child_write_dac_aces,
            parent_write_dac.allowed,
            child_write_dac.allowed,
            parent_fresh.is_ok(),
            child_fresh.is_ok(),
        );

        drop(parent_fresh);
        drop(child_fresh);
        drop(child_restore_handle);
        drop(parent_restore_handle);
        let cleanup = fs::remove_dir_all(&root);

        assert!(
            parent_owner_matches,
            "parent owner does not match the token's default owner SID"
        );
        assert!(
            child_owner_matches,
            "child owner does not match the token's default owner SID"
        );
        assert!(
            !has_explicit_parent_write_dac,
            "parent unexpectedly has an explicit WRITE_DAC allow ACE"
        );
        assert!(
            !has_explicit_child_write_dac,
            "child unexpectedly has an explicit WRITE_DAC allow ACE"
        );
        assert!(
            parent_write_dac.allowed,
            "owner-implicit parent WRITE_DAC was not allowed"
        );
        assert!(
            child_write_dac.allowed,
            "owner-implicit child WRITE_DAC was not allowed"
        );
        assert!(
            parent_fresh_ok,
            "fresh parent handle could not acquire WRITE_DAC: {:?}",
            parent_fresh_error
        );
        assert!(
            child_fresh_ok,
            "fresh child handle could not acquire WRITE_DAC: {:?}",
            child_fresh_error
        );
        assert!(
            parent_reset.is_ok(),
            "parent DACL mutation through WRITE_DAC failed: {parent_reset:?}"
        );
        assert!(
            child_reset.is_ok(),
            "child DACL mutation through WRITE_DAC failed: {child_reset:?}"
        );
        assert!(
            cleanup.is_ok(),
            "owner-implicit WRITE_DAC temporary tree cleanup failed: {cleanup:?}"
        );
    }

    #[test]
    fn owner_rights_deny_can_remove_owner_implicit_write_dac() {
        const WRITE_DAC_RIGHT: u32 = 0x0004_0000;
        let root = temp_root();
        fs::create_dir(&root).unwrap();

        // Keep a WRITE_DAC-capable handle before policy installation solely for cleanup.
        let restore_handle = open_temp_handle(&root, true).unwrap();
        set_owner_rights_write_dac_deny_for_temp_test(&restore_handle).unwrap();

        let snapshot = snapshot_acl_from_handle(&restore_handle).unwrap();
        let token_owner = current_process_default_owner_sid().unwrap();
        let owner_matches = snapshot.owner_sid == token_owner;
        let owner_rights_denies: Vec<_> = snapshot
            .aces
            .iter()
            .filter(|ace| {
                ace.ace_type == 1
                    && ace.trustee_sid.as_deref() == Some("S-1-3-4")
                    && ace.mask.is_some_and(|mask| mask & WRITE_DAC_RIGHT != 0)
            })
            .collect();
        let write_dac_allow_aces: Vec<_> = snapshot
            .aces
            .iter()
            .filter(|ace| {
                ace.ace_type == 0 && ace.mask.is_some_and(|mask| mask & WRITE_DAC_RIGHT != 0)
            })
            .collect();

        let access = access_check_current_process_token(&restore_handle, WRITE_DAC_RIGHT).unwrap();
        let fresh = open_temp_handle(&root, true);
        let fresh_ok = fresh.is_ok();
        let fresh_error = fresh.as_ref().err().map(ToString::to_string);
        let fresh_error_code = fresh.as_ref().err().and_then(std::io::Error::raw_os_error);

        // Restore the temporary DACL through the retained pre-policy handle before cleanup.
        let reset = set_null_dacl_for_temp_test(&restore_handle);
        eprintln!(
            "OWNER RIGHTS probe: token_default_owner={}, object_owner={}, owner_match={}, owner_rights_deny_count={}, owner_rights_deny_flags={:?}, WRITE_DAC_allow_ACE_count={}, AccessCheck_WRITE_DAC={}, fresh_WRITE_DAC_handle={}, fresh_error={:?}",
            token_owner,
            snapshot.owner_sid,
            owner_matches,
            owner_rights_denies.len(),
            owner_rights_denies.iter().map(|ace| ace.ace_flags).collect::<Vec<_>>(),
            write_dac_allow_aces.len(),
            access.allowed,
            fresh_ok,
            fresh_error,
        );

        drop(fresh);
        drop(restore_handle);
        let cleanup = fs::remove_dir(&root);

        assert!(
            owner_matches,
            "object owner does not match token default owner SID"
        );
        assert_eq!(
            owner_rights_denies.len(),
            1,
            "expected one OWNER RIGHTS WRITE_DAC deny ACE"
        );
        assert!(
            write_dac_allow_aces.is_empty(),
            "unexpected explicit WRITE_DAC allow ACE"
        );
        assert!(
            !access.allowed,
            "OWNER RIGHTS deny should suppress owner-implicit WRITE_DAC"
        );
        assert!(!fresh_ok, "fresh handle unexpectedly acquired WRITE_DAC despite OWNER RIGHTS deny: {fresh_error:?}");
        assert_eq!(
            fresh_error_code,
            Some(5),
            "fresh handle should fail with ERROR_ACCESS_DENIED"
        );
        assert!(
            reset.is_ok(),
            "failed to reset disposable OWNER RIGHTS DACL: {reset:?}"
        );
        assert!(
            cleanup.is_ok(),
            "OWNER RIGHTS temporary directory cleanup failed: {cleanup:?}"
        );
    }

    #[test]
    fn owner_rights_allow_grants_write_dac_to_the_owner_token() {
        const WRITE_DAC_RIGHT: u32 = 0x0004_0000;
        let root = temp_root();
        fs::create_dir(&root).unwrap();

        // Retain a pre-policy handle so cleanup does not depend on the OWNER RIGHTS ACE.
        let restore_handle = open_temp_handle(&root, true).unwrap();
        set_owner_rights_write_dac_allow_for_temp_test(&restore_handle).unwrap();

        let snapshot = snapshot_acl_from_handle(&restore_handle).unwrap();
        let token_owner = current_process_default_owner_sid().unwrap();
        let owner_matches = snapshot.owner_sid == token_owner;
        let owner_rights_allows: Vec<_> = snapshot
            .aces
            .iter()
            .filter(|ace| {
                ace.ace_type == 0
                    && ace.trustee_sid.as_deref() == Some("S-1-3-4")
                    && ace.mask.is_some_and(|mask| mask & WRITE_DAC_RIGHT != 0)
            })
            .collect();
        let other_write_dac_allows: Vec<_> = snapshot
            .aces
            .iter()
            .filter(|ace| {
                ace.ace_type == 0
                    && ace.trustee_sid.as_deref() != Some("S-1-3-4")
                    && ace.mask.is_some_and(|mask| mask & WRITE_DAC_RIGHT != 0)
            })
            .collect();

        let access = access_check_current_process_token(&restore_handle, WRITE_DAC_RIGHT).unwrap();
        let fresh = open_temp_handle(&root, true);
        let fresh_ok = fresh.is_ok();
        let fresh_error = fresh.as_ref().err().map(ToString::to_string);
        let reset = set_null_dacl_for_temp_test(&restore_handle);

        eprintln!(
            "OWNER RIGHTS allow probe: token_default_owner={}, object_owner={}, owner_match={}, owner_rights_allow_count={}, other_WRITE_DAC_allow_count={}, AccessCheck_WRITE_DAC={}, fresh_WRITE_DAC_handle={}, fresh_error={:?}",
            token_owner, snapshot.owner_sid, owner_matches, owner_rights_allows.len(),
            other_write_dac_allows.len(), access.allowed, fresh_ok, fresh_error,
        );

        drop(fresh);
        drop(restore_handle);
        let cleanup = fs::remove_dir(&root);

        assert!(
            owner_matches,
            "object owner does not match token default owner SID"
        );
        assert_eq!(
            owner_rights_allows.len(),
            1,
            "expected one OWNER RIGHTS WRITE_DAC allow ACE"
        );
        assert!(
            other_write_dac_allows.is_empty(),
            "unexpected non-OWNER-RIGHTS WRITE_DAC allow ACE"
        );
        assert!(
            access.allowed,
            "OWNER RIGHTS allow should grant WRITE_DAC to the owner token"
        );
        assert!(
            fresh_ok,
            "fresh handle could not acquire OWNER RIGHTS WRITE_DAC: {fresh_error:?}"
        );
        assert!(
            reset.is_ok(),
            "failed to reset disposable OWNER RIGHTS DACL: {reset:?}"
        );
        assert!(
            cleanup.is_ok(),
            "OWNER RIGHTS allow temporary directory cleanup failed: {cleanup:?}"
        );
    }

    #[test]
    fn write_owner_is_not_implicit_but_owner_rights_ace_can_grant_it() {
        const WRITE_OWNER_RIGHT: u32 = 0x0008_0000;
        const HANDLE_ACCESS: u32 = 0x0002_0000 | 0x0000_0080 | WRITE_OWNER_RIGHT;
        let root = temp_root();
        fs::create_dir(&root).unwrap();
        let restore_handle = open_temp_handle(&root, true).unwrap();
        let token_owner = current_process_default_owner_sid().unwrap();

        // With no OWNER RIGHTS ACE, ownership alone should not grant WRITE_OWNER.
        set_owner_rights_write_owner_dacl_for_temp_test(&restore_handle, false).unwrap();
        let baseline_snapshot = snapshot_acl_from_handle(&restore_handle).unwrap();
        let baseline_access =
            access_check_current_process_token(&restore_handle, WRITE_OWNER_RIGHT).unwrap();
        let baseline_fresh = open_temp_handle_with_access(&root, HANDLE_ACCESS);
        let baseline_fresh_ok = baseline_fresh.is_ok();
        let baseline_fresh_error = baseline_fresh.as_ref().err().map(ToString::to_string);
        let baseline_owner_matches = baseline_snapshot.owner_sid == token_owner;

        // Add only OWNER RIGHTS WRITE_OWNER; do not add the right to Everyone or another SID.
        set_owner_rights_write_owner_dacl_for_temp_test(&restore_handle, true).unwrap();
        let allowed_snapshot = snapshot_acl_from_handle(&restore_handle).unwrap();
        let owner_rights_allows: Vec<_> = allowed_snapshot
            .aces
            .iter()
            .filter(|ace| {
                ace.ace_type == 0
                    && ace.trustee_sid.as_deref() == Some("S-1-3-4")
                    && ace.mask.is_some_and(|mask| mask & WRITE_OWNER_RIGHT != 0)
            })
            .collect();
        let other_write_owner_allows: Vec<_> = allowed_snapshot
            .aces
            .iter()
            .filter(|ace| {
                ace.ace_type == 0
                    && ace.trustee_sid.as_deref() != Some("S-1-3-4")
                    && ace.mask.is_some_and(|mask| mask & WRITE_OWNER_RIGHT != 0)
            })
            .collect();
        let allowed_access =
            access_check_current_process_token(&restore_handle, WRITE_OWNER_RIGHT).unwrap();
        let allowed_fresh = open_temp_handle_with_access(&root, HANDLE_ACCESS);
        let allowed_fresh_ok = allowed_fresh.is_ok();
        let allowed_fresh_error = allowed_fresh.as_ref().err().map(ToString::to_string);

        let reset = set_null_dacl_for_temp_test(&restore_handle);
        eprintln!(
            "WRITE_OWNER probe: token_default_owner={}, object_owner={}, owner_match={}, baseline_AccessCheck={}, baseline_fresh_handle={}, baseline_fresh_error={:?}, OWNER_RIGHTS_allow_count={}, other_WRITE_OWNER_allow_count={}, allowed_AccessCheck={}, allowed_fresh_handle={}, allowed_fresh_error={:?}",
            token_owner, baseline_snapshot.owner_sid, baseline_owner_matches,
            baseline_access.allowed, baseline_fresh_ok, baseline_fresh_error,
            owner_rights_allows.len(), other_write_owner_allows.len(),
            allowed_access.allowed, allowed_fresh_ok, allowed_fresh_error,
        );

        drop(baseline_fresh);
        drop(allowed_fresh);
        drop(restore_handle);
        let cleanup = fs::remove_dir(&root);

        assert!(
            baseline_owner_matches,
            "object owner does not match token default owner SID"
        );
        assert!(
            !baseline_access.allowed,
            "WRITE_OWNER must not be inferred from ownership alone"
        );
        assert!(
            !baseline_fresh_ok,
            "fresh handle unexpectedly received implicit WRITE_OWNER: {baseline_fresh_error:?}"
        );
        assert_eq!(
            owner_rights_allows.len(),
            1,
            "expected one OWNER RIGHTS WRITE_OWNER allow ACE"
        );
        assert!(
            other_write_owner_allows.is_empty(),
            "unexpected WRITE_OWNER allow ACE outside OWNER RIGHTS"
        );
        assert!(
            allowed_access.allowed,
            "OWNER RIGHTS allow should grant WRITE_OWNER"
        );
        assert!(allowed_fresh_ok, "fresh WRITE_OWNER handle should open after OWNER RIGHTS allow: {allowed_fresh_error:?}");
        assert!(
            reset.is_ok(),
            "failed to reset disposable WRITE_OWNER DACL: {reset:?}"
        );
        assert!(
            cleanup.is_ok(),
            "WRITE_OWNER temporary directory cleanup failed: {cleanup:?}"
        );
    }

    #[test]
    fn null_dacl_is_detected_and_never_marked_complete() {
        let root = temp_root();
        fs::create_dir(&root).unwrap();
        let handle = open_temp_handle(&root, true).unwrap();
        set_null_dacl_for_temp_test(&handle).unwrap();
        let snapshot = snapshot_acl_from_handle(&handle).unwrap();
        assert_eq!(snapshot.dacl_state, DaclState::Null);
        assert!(!snapshot.structurally_complete);
        drop(handle);
        fs::remove_dir(root).unwrap();
    }
    #[test]
    fn preserves_deny_allow_order_masks_sid_and_inherited_aces() {
        let root = temp_root();
        fs::create_dir(&root).unwrap();
        let handle = open_temp_handle(&root, true).unwrap();
        set_ordered_dacl_for_temp_test(&handle).unwrap();
        let snapshot = snapshot_acl_from_handle(&handle).unwrap();
        assert_eq!(snapshot.dacl_state, DaclState::Present);
        assert!(snapshot.aces.len() >= 2);
        assert_eq!(snapshot.aces[0].ace_type, 1);
        assert_eq!(snapshot.aces[0].mask, Some(0x0000_0002));
        assert_eq!(snapshot.aces[0].trustee_sid.as_deref(), Some("S-1-1-0"));
        assert_eq!(snapshot.aces[1].ace_type, 0);
        assert!(snapshot.aces.iter().any(|ace| ace.ace_type == 0
            && ace.mask == Some(0x0002_0000)
            && ace.trustee_sid.as_deref() == Some("S-1-1-0")
            && !ace.inherited));
        assert!(snapshot.aces.iter().any(|ace| ace.inherited));
        assert!(snapshot.structurally_complete);
        drop(handle);
        fs::remove_dir(root).unwrap();
    }
    #[test]
    fn conflicting_ace_order_changes_current_token_access_check_result() {
        const FILE_WRITE_DATA: u32 = 0x0000_0002;
        let root = temp_root();
        fs::create_dir(&root).unwrap();
        let handle = open_temp_handle(&root, true).unwrap();

        set_conflicting_write_dacl_for_temp_test(&handle, true).unwrap();
        let deny_first = access_check_current_process_token(&handle, FILE_WRITE_DATA).unwrap();
        let deny_first_snapshot = snapshot_acl_from_handle(&handle).unwrap();
        assert!(
            !deny_first.allowed,
            "deny-first DACL must not grant FILE_WRITE_DATA"
        );
        assert_eq!(deny_first_snapshot.aces[0].ace_type, 1);
        assert_eq!(deny_first_snapshot.aces[1].ace_type, 0);

        set_conflicting_write_dacl_for_temp_test(&handle, false).unwrap();
        let allow_first = access_check_current_process_token(&handle, FILE_WRITE_DATA).unwrap();
        let allow_first_snapshot = snapshot_acl_from_handle(&handle).unwrap();
        assert!(
            allow_first.allowed,
            "allow-first DACL should satisfy the requested right before the later deny ACE"
        );
        assert_eq!(allow_first_snapshot.aces[0].ace_type, 0);
        assert_eq!(allow_first_snapshot.aces[1].ace_type, 1);

        eprintln!(
            "ACE order probe: deny_first_allowed={}, allow_first_allowed={}",
            deny_first.allowed, allow_first.allowed
        );
        set_null_dacl_for_temp_test(&handle).unwrap();
        drop(handle);
        fs::remove_dir(root).unwrap();
    }

    #[test]
    fn inherited_conflicting_ace_order_is_preserved_and_applied_to_child() {
        const FILE_WRITE_DATA: u32 = 0x0000_0002;
        let root = temp_root();
        fs::create_dir(&root).unwrap();

        for (label, deny_first) in [("deny-first", true), ("allow-first", false)] {
            let parent_path = root.join(label);
            fs::create_dir(&parent_path).unwrap();
            let parent_handle = open_temp_handle(&parent_path, true).unwrap();
            set_conflicting_inheritable_write_dacl_for_temp_test(&parent_handle, deny_first)
                .unwrap();

            let child_path = parent_path.join("child");
            fs::create_dir(&child_path).unwrap();
            let child_handle = open_temp_handle(&child_path, true).unwrap();
            let snapshot = snapshot_acl_from_handle(&child_handle).unwrap();
            let conflict_aces: Vec<_> = snapshot
                .aces
                .iter()
                .filter(|ace| {
                    ace.trustee_sid.as_deref() == Some("S-1-1-0")
                        && ace.mask.is_some_and(|mask| mask & FILE_WRITE_DATA != 0)
                        && (ace.ace_type == 0 || ace.ace_type == 1)
                })
                .collect();
            assert_eq!(
                conflict_aces.len(),
                2,
                "child must inherit both conflicting ACEs"
            );
            assert!(conflict_aces.iter().all(|ace| ace.inherited));
            let ace_order: Vec<u8> = conflict_aces.iter().map(|ace| ace.ace_type).collect();
            let access =
                access_check_current_process_token(&child_handle, FILE_WRITE_DATA).unwrap();
            let expected_order: &[u8] = if deny_first { &[1, 0] } else { &[0, 1] };

            eprintln!(
                "Inherited ACE probe: parent_deny_first={}, child_ace_order={:?}, child_write_allowed={}",
                deny_first, ace_order, access.allowed
            );
            assert_eq!(
                ace_order.as_slice(),
                expected_order,
                "child should preserve the parent's conflicting ACE order"
            );
            assert_eq!(
                access.allowed,
                expected_order.first() == Some(&0),
                "current-token decision should follow the first matching inherited ACE"
            );

            set_null_dacl_for_temp_test(&child_handle).unwrap();
            set_null_dacl_for_temp_test(&parent_handle).unwrap();
            drop(child_handle);
            drop(parent_handle);
            fs::remove_dir(&child_path).unwrap();
            fs::remove_dir(&parent_path).unwrap();
        }
        fs::remove_dir(root).unwrap();
    }

    #[test]
    fn inherit_only_and_no_propagate_flags_bound_child_inheritance_scope() {
        const FILE_WRITE_DATA: u32 = 0x0000_0002;
        let root = temp_root();
        fs::create_dir(&root).unwrap();

        // INHERIT_ONLY: the deny ACE must not affect the parent; inspect the inherited copy on a child.
        let inherit_only_parent_path = root.join("inherit-only-parent");
        fs::create_dir(&inherit_only_parent_path).unwrap();
        let inherit_only_parent = open_temp_handle(&inherit_only_parent_path, true).unwrap();
        set_inheritance_scope_probe_dacl_for_temp_test(&inherit_only_parent, 0x000B).unwrap();
        let inherit_only_parent_access =
            access_check_current_process_token(&inherit_only_parent, FILE_WRITE_DATA).unwrap();
        assert!(
            inherit_only_parent_access.allowed,
            "INHERIT_ONLY deny must not apply to its parent"
        );
        let inherit_only_child_path = inherit_only_parent_path.join("child");
        fs::create_dir(&inherit_only_child_path).unwrap();
        let inherit_only_child = open_temp_handle(&inherit_only_child_path, true).unwrap();
        let inherit_only_snapshot = snapshot_acl_from_handle(&inherit_only_child).unwrap();
        let inherit_only_denies: Vec<_> = inherit_only_snapshot
            .aces
            .iter()
            .filter(|ace| {
                ace.ace_type == 1
                    && ace.trustee_sid.as_deref() == Some("S-1-1-0")
                    && ace.mask.is_some_and(|mask| mask & FILE_WRITE_DATA != 0)
            })
            .collect();
        assert_eq!(
            inherit_only_denies.len(),
            1,
            "child should inherit the INHERIT_ONLY deny ACE"
        );
        assert!(inherit_only_denies[0].inherited);
        let inherit_only_child_access =
            access_check_current_process_token(&inherit_only_child, FILE_WRITE_DATA).unwrap();
        eprintln!(
            "INHERIT_ONLY probe: parent_allowed={}, child_ace_flags=0x{:02x}, child_allowed={}",
            inherit_only_parent_access.allowed,
            inherit_only_denies[0].ace_flags,
            inherit_only_child_access.allowed
        );

        set_null_dacl_for_temp_test(&inherit_only_child).unwrap();
        set_null_dacl_for_temp_test(&inherit_only_parent).unwrap();
        drop(inherit_only_child);
        drop(inherit_only_parent);
        fs::remove_dir(&inherit_only_child_path).unwrap();
        fs::remove_dir(&inherit_only_parent_path).unwrap();

        // NO_PROPAGATE: inherited deny reaches one child generation, but not the grandchild.
        let no_prop_parent_path = root.join("no-propagate-parent");
        fs::create_dir(&no_prop_parent_path).unwrap();
        let no_prop_parent = open_temp_handle(&no_prop_parent_path, true).unwrap();
        set_inheritance_scope_probe_dacl_for_temp_test(&no_prop_parent, 0x0007).unwrap();
        let no_prop_parent_access =
            access_check_current_process_token(&no_prop_parent, FILE_WRITE_DATA).unwrap();
        assert!(
            !no_prop_parent_access.allowed,
            "ordinary deny ACE must apply to its parent"
        );

        let no_prop_child_path = no_prop_parent_path.join("child");
        fs::create_dir(&no_prop_child_path).unwrap();
        let no_prop_child = open_temp_handle(&no_prop_child_path, true).unwrap();
        let no_prop_child_snapshot = snapshot_acl_from_handle(&no_prop_child).unwrap();
        let child_denies: Vec<_> = no_prop_child_snapshot
            .aces
            .iter()
            .filter(|ace| {
                ace.ace_type == 1
                    && ace.trustee_sid.as_deref() == Some("S-1-1-0")
                    && ace.mask.is_some_and(|mask| mask & FILE_WRITE_DATA != 0)
            })
            .collect();
        assert_eq!(
            child_denies.len(),
            1,
            "direct child should inherit the NO_PROPAGATE deny"
        );
        assert!(child_denies[0].inherited);
        assert_eq!(
            child_denies[0].ace_flags & 0x0003,
            0,
            "child copy should no longer be inheritable"
        );
        let no_prop_child_access =
            access_check_current_process_token(&no_prop_child, FILE_WRITE_DATA).unwrap();
        assert!(
            !no_prop_child_access.allowed,
            "inherited deny should apply to the direct child"
        );

        let grandchild_path = no_prop_child_path.join("grandchild");
        fs::create_dir(&grandchild_path).unwrap();
        let grandchild = open_temp_handle(&grandchild_path, true).unwrap();
        let grandchild_snapshot = snapshot_acl_from_handle(&grandchild).unwrap();
        let grandchild_denies = grandchild_snapshot
            .aces
            .iter()
            .filter(|ace| {
                ace.ace_type == 1
                    && ace.trustee_sid.as_deref() == Some("S-1-1-0")
                    && ace.mask.is_some_and(|mask| mask & FILE_WRITE_DATA != 0)
            })
            .count();
        let grandchild_access =
            access_check_current_process_token(&grandchild, FILE_WRITE_DATA).unwrap();
        eprintln!(
            "NO_PROPAGATE probe: parent_allowed={}, child_allowed={}, child_deny_flags=0x{:02x}, grandchild_deny_count={}, grandchild_allowed={}",
            no_prop_parent_access.allowed,
            no_prop_child_access.allowed,
            child_denies[0].ace_flags,
            grandchild_denies,
            grandchild_access.allowed
        );
        assert_eq!(
            grandchild_denies, 0,
            "NO_PROPAGATE deny must not reach the grandchild"
        );
        assert!(
            grandchild_access.allowed,
            "inherited allow should remain effective after the deny stops propagating"
        );

        set_null_dacl_for_temp_test(&grandchild).unwrap();
        set_null_dacl_for_temp_test(&no_prop_child).unwrap();
        set_null_dacl_for_temp_test(&no_prop_parent).unwrap();
        drop(grandchild);
        drop(no_prop_child);
        drop(no_prop_parent);
        fs::remove_dir(&grandchild_path).unwrap();
        fs::remove_dir(&no_prop_child_path).unwrap();
        fs::remove_dir(&no_prop_parent_path).unwrap();
        fs::remove_dir(root).unwrap();
    }

    #[test]
    fn object_and_container_inherit_flags_separate_file_and_directory_children() {
        const DELETE_RIGHT: u32 = 0x0001_0000;
        let root = temp_root();
        fs::create_dir(&root).unwrap();

        // OBJECT_INHERIT: files inherit an effective deny; directories carry it as inherit-only.
        let object_parent_path = root.join("object-parent");
        fs::create_dir(&object_parent_path).unwrap();
        let object_parent = open_temp_handle(&object_parent_path, true).unwrap();
        set_inheritance_object_container_probe_dacl_for_temp_test(&object_parent, 0x0001).unwrap();
        let object_parent_access =
            access_check_current_process_token(&object_parent, DELETE_RIGHT).unwrap();
        assert!(!object_parent_access.allowed);

        let object_child_dir_path = object_parent_path.join("child-directory");
        fs::create_dir(&object_child_dir_path).unwrap();
        let object_child_file_path = object_parent_path.join("child-file.bin");
        fs::write(&object_child_file_path, b"probe").unwrap();
        let object_nested_file_path = object_child_dir_path.join("nested-file.bin");
        fs::write(&object_nested_file_path, b"probe").unwrap();

        let object_child_dir = open_temp_handle(&object_child_dir_path, true).unwrap();
        let object_child_file = open_temp_handle(&object_child_file_path, true).unwrap();
        let object_nested_file = open_temp_handle(&object_nested_file_path, true).unwrap();
        let object_dir_snapshot = snapshot_acl_from_handle(&object_child_dir).unwrap();
        let object_dir_denies: Vec<_> = object_dir_snapshot
            .aces
            .iter()
            .filter(|ace| {
                ace.ace_type == 1
                    && ace.trustee_sid.as_deref() == Some("S-1-1-0")
                    && ace.mask.is_some_and(|mask| mask & DELETE_RIGHT != 0)
            })
            .collect();
        assert_eq!(object_dir_denies.len(), 1);
        assert!(object_dir_denies[0].inherited);
        assert_ne!(
            object_dir_denies[0].ace_flags & 0x0008,
            0,
            "OI-only ACE on a directory should be inherit-only"
        );
        let object_dir_access =
            access_check_current_process_token(&object_child_dir, DELETE_RIGHT).unwrap();
        assert!(
            object_dir_access.allowed,
            "inherit-only OI ACE should not deny the directory itself"
        );

        let object_file_snapshot = snapshot_acl_from_handle(&object_child_file).unwrap();
        let object_file_denies: Vec<_> = object_file_snapshot
            .aces
            .iter()
            .filter(|ace| {
                ace.ace_type == 1
                    && ace.trustee_sid.as_deref() == Some("S-1-1-0")
                    && ace.mask.is_some_and(|mask| mask & DELETE_RIGHT != 0)
            })
            .collect();
        assert_eq!(object_file_denies.len(), 1);
        assert!(object_file_denies[0].inherited);
        assert_eq!(object_file_denies[0].ace_flags & 0x0008, 0);
        let object_file_access =
            access_check_current_process_token(&object_child_file, DELETE_RIGHT).unwrap();
        assert!(!object_file_access.allowed);

        let object_nested_snapshot = snapshot_acl_from_handle(&object_nested_file).unwrap();
        assert!(
            object_nested_snapshot.aces.iter().any(|ace| {
                ace.ace_type == 1
                    && ace.trustee_sid.as_deref() == Some("S-1-1-0")
                    && ace.inherited
                    && ace.mask.is_some_and(|mask| mask & DELETE_RIGHT != 0)
            }),
            "OI-only deny should propagate through the directory to its file child"
        );
        let object_nested_access =
            access_check_current_process_token(&object_nested_file, DELETE_RIGHT).unwrap();
        assert!(!object_nested_access.allowed);
        eprintln!(
            "OBJECT_INHERIT probe: parent_allowed={}, directory_deny_flags=0x{:02x}, directory_allowed={}, direct_file_allowed={}, nested_file_allowed={}",
            object_parent_access.allowed, object_dir_denies[0].ace_flags, object_dir_access.allowed, object_file_access.allowed, object_nested_access.allowed
        );

        set_null_dacl_for_temp_test(&object_nested_file).unwrap();
        set_null_dacl_for_temp_test(&object_child_file).unwrap();
        set_null_dacl_for_temp_test(&object_child_dir).unwrap();
        set_null_dacl_for_temp_test(&object_parent).unwrap();
        drop(object_nested_file);
        drop(object_child_file);
        drop(object_child_dir);
        drop(object_parent);
        fs::remove_file(&object_nested_file_path).unwrap();
        fs::remove_file(&object_child_file_path).unwrap();
        fs::remove_dir(&object_child_dir_path).unwrap();
        fs::remove_dir(&object_parent_path).unwrap();

        // CONTAINER_INHERIT: directories inherit the effective deny; files do not inherit it.
        let container_parent_path = root.join("container-parent");
        fs::create_dir(&container_parent_path).unwrap();
        let container_parent = open_temp_handle(&container_parent_path, true).unwrap();
        set_inheritance_object_container_probe_dacl_for_temp_test(&container_parent, 0x0002)
            .unwrap();
        let container_parent_access =
            access_check_current_process_token(&container_parent, DELETE_RIGHT).unwrap();
        assert!(!container_parent_access.allowed);

        let container_child_dir_path = container_parent_path.join("child-directory");
        fs::create_dir(&container_child_dir_path).unwrap();
        let container_child_file_path = container_parent_path.join("child-file.bin");
        fs::write(&container_child_file_path, b"probe").unwrap();
        let container_nested_file_path = container_child_dir_path.join("nested-file.bin");
        fs::write(&container_nested_file_path, b"probe").unwrap();

        let container_child_dir = open_temp_handle(&container_child_dir_path, true).unwrap();
        let container_child_file = open_temp_handle(&container_child_file_path, true).unwrap();
        let container_nested_file = open_temp_handle(&container_nested_file_path, true).unwrap();
        let container_dir_snapshot = snapshot_acl_from_handle(&container_child_dir).unwrap();
        let container_dir_denies: Vec<_> = container_dir_snapshot
            .aces
            .iter()
            .filter(|ace| {
                ace.ace_type == 1
                    && ace.trustee_sid.as_deref() == Some("S-1-1-0")
                    && ace.mask.is_some_and(|mask| mask & DELETE_RIGHT != 0)
            })
            .collect();
        assert_eq!(container_dir_denies.len(), 1);
        assert!(container_dir_denies[0].inherited);
        assert_eq!(container_dir_denies[0].ace_flags & 0x0008, 0);
        let container_dir_access =
            access_check_current_process_token(&container_child_dir, DELETE_RIGHT).unwrap();
        assert!(!container_dir_access.allowed);

        let container_file_snapshot = snapshot_acl_from_handle(&container_child_file).unwrap();
        let container_file_denies = container_file_snapshot
            .aces
            .iter()
            .filter(|ace| {
                ace.ace_type == 1
                    && ace.trustee_sid.as_deref() == Some("S-1-1-0")
                    && ace.mask.is_some_and(|mask| mask & DELETE_RIGHT != 0)
            })
            .count();
        let container_file_access =
            access_check_current_process_token(&container_child_file, DELETE_RIGHT).unwrap();
        assert_eq!(
            container_file_denies, 0,
            "CI-only deny must not reach a file child"
        );
        assert!(container_file_access.allowed);

        let container_nested_snapshot = snapshot_acl_from_handle(&container_nested_file).unwrap();
        let container_nested_denies = container_nested_snapshot
            .aces
            .iter()
            .filter(|ace| {
                ace.ace_type == 1
                    && ace.trustee_sid.as_deref() == Some("S-1-1-0")
                    && ace.mask.is_some_and(|mask| mask & DELETE_RIGHT != 0)
            })
            .count();
        let container_nested_access =
            access_check_current_process_token(&container_nested_file, DELETE_RIGHT).unwrap();
        assert_eq!(
            container_nested_denies, 0,
            "CI-only deny must not reach a file below a child directory"
        );
        assert!(container_nested_access.allowed);
        eprintln!(
            "CONTAINER_INHERIT probe: parent_allowed={}, directory_allowed={}, direct_file_deny_count={}, direct_file_allowed={}, nested_file_deny_count={}, nested_file_allowed={}",
            container_parent_access.allowed, container_dir_access.allowed, container_file_denies, container_file_access.allowed, container_nested_denies, container_nested_access.allowed
        );

        set_null_dacl_for_temp_test(&container_nested_file).unwrap();
        set_null_dacl_for_temp_test(&container_child_file).unwrap();
        set_null_dacl_for_temp_test(&container_child_dir).unwrap();
        set_null_dacl_for_temp_test(&container_parent).unwrap();
        drop(container_nested_file);
        drop(container_child_file);
        drop(container_child_dir);
        drop(container_parent);
        fs::remove_file(&container_nested_file_path).unwrap();
        fs::remove_file(&container_child_file_path).unwrap();
        fs::remove_dir(&container_child_dir_path).unwrap();
        fs::remove_dir(&container_parent_path).unwrap();
        fs::remove_dir(root).unwrap();
    }

    #[test]
    fn access_check_evaluates_the_current_token_against_the_test_dacl_only() {
        const FILE_WRITE_DATA: u32 = 0x0000_0002;
        const READ_CONTROL_MASK: u32 = 0x0002_0000;
        let root = temp_root();
        fs::create_dir(&root).unwrap();
        let handle = open_temp_handle(&root, true).unwrap();
        set_ordered_dacl_for_temp_test(&handle).unwrap();
        let write = access_check_current_process_token(&handle, FILE_WRITE_DATA).unwrap();
        let read_control = access_check_current_process_token(&handle, READ_CONTROL_MASK).unwrap();
        assert!(
            !write.allowed,
            "Everyone deny ACE should deny FILE_WRITE_DATA to this token"
        );
        assert!(
            read_control.allowed,
            "Everyone allow ACE should grant READ_CONTROL to this token"
        );
        eprintln!(
            "AccessCheck current token: write_allowed={}, read_control_allowed={}",
            write.allowed, read_control.allowed
        );
        drop(handle);
        fs::remove_dir(root).unwrap();
    }
    #[test]
    fn conservative_mutator_model_maps_generic_write_and_keeps_deny_non_granting() {
        let snapshot = AclSnapshot {
            owner_sid: "S-1-5-21-OWNER".into(),
            dacl_state: DaclState::Present,
            dacl_defaulted: false,
            aces: vec![
                AceSnapshot {
                    ace_type: 1,
                    ace_flags: 0,
                    inherited: false,
                    mask: Some(0x0000_0002),
                    trustee_sid: Some("S-1-1-0".into()),
                    raw: vec![1, 0, 12, 0, 2, 0, 0, 0],
                    understood_standard_allow_or_deny: true,
                },
                AceSnapshot {
                    ace_type: 0,
                    ace_flags: 0,
                    inherited: true,
                    mask: Some(0x4000_0000),
                    trustee_sid: Some("S-1-5-32-544".into()),
                    raw: vec![0, 0, 12, 0, 0, 0, 0, 0],
                    understood_standard_allow_or_deny: true,
                },
            ],
            unsupported_ace_types: Vec::new(),
            structurally_complete: true,
        };
        let evidence = derive_conservative_mutation_evidence(&snapshot);
        let everyone = evidence.principals.iter().find(|p| p.sid == "S-1-1-0");
        assert!(
            everyone.is_none(),
            "a deny ACE must not be treated as a grant"
        );
        let admins = evidence
            .principals
            .iter()
            .find(|p| p.sid == "S-1-5-32-544")
            .unwrap();
        assert!(admins.potential_mutation_rights & 0x0000_0002 != 0);
        assert!(admins.potential_mutation_rights & 0x0000_0004 != 0);
        assert!(evidence
            .principals
            .iter()
            .any(|p| p.sid == "S-1-5-21-OWNER" && p.owner_implicit_write_dac));
        assert!(evidence.ace_stream_understood);
    }

    #[test]
    fn conservative_owner_write_dac_upper_bound_is_not_reduced_by_owner_rights_deny() {
        const WRITE_DAC_RIGHT: u32 = 0x0004_0000;
        let snapshot = AclSnapshot {
            owner_sid: "S-1-5-21-OWNER".into(),
            dacl_state: DaclState::Present,
            dacl_defaulted: false,
            aces: vec![AceSnapshot {
                ace_type: 1,
                ace_flags: 0,
                inherited: false,
                mask: Some(WRITE_DAC_RIGHT),
                trustee_sid: Some("S-1-3-4".into()),
                raw: vec![1, 0, 12, 0, 0, 0, 4, 0, 1, 1, 0, 0],
                understood_standard_allow_or_deny: true,
            }],
            unsupported_ace_types: Vec::new(),
            structurally_complete: true,
        };

        let evidence = derive_conservative_mutation_evidence(&snapshot);
        let owner = evidence
            .principals
            .iter()
            .find(|principal| principal.sid == "S-1-5-21-OWNER")
            .unwrap();

        // This model is an upper bound, not OWNER RIGHTS-aware effective access evaluation.
        assert!(owner.owner_implicit_write_dac);
        assert_ne!(owner.potential_mutation_rights & WRITE_DAC_RIGHT, 0);
        assert!(
            !evidence
                .principals
                .iter()
                .any(|principal| principal.sid == "S-1-3-4"),
            "a deny ACE for OWNER RIGHTS must not be treated as an allow principal"
        );
        assert!(evidence.ace_stream_understood);
    }

    #[test]
    fn null_dacl_conservatively_marks_everyone_as_mutator_and_unknown_aces_fail_closed() {
        let null_snapshot = AclSnapshot {
            owner_sid: "S-1-5-21-OWNER".into(),
            dacl_state: DaclState::Null,
            dacl_defaulted: false,
            aces: Vec::new(),
            unsupported_ace_types: Vec::new(),
            structurally_complete: false,
        };
        let null_evidence = derive_conservative_mutation_evidence(&null_snapshot);
        assert!(!null_evidence.ace_stream_understood);
        assert!(null_evidence
            .principals
            .iter()
            .any(|p| p.sid == "S-1-1-0" && p.potential_mutation_rights == 0x010D_0156));

        let mut unknown = null_snapshot;
        unknown.dacl_state = DaclState::Present;
        unknown.structurally_complete = false;
        unknown.aces.push(AceSnapshot {
            ace_type: 5,
            ace_flags: 0,
            inherited: false,
            mask: None,
            trustee_sid: None,
            raw: vec![5, 0, 4, 0],
            understood_standard_allow_or_deny: false,
        });
        let unknown_evidence = derive_conservative_mutation_evidence(&unknown);
        assert!(!unknown_evidence.ace_stream_understood);
        assert!(unknown_evidence.unsupported_ace_types.contains(&5));
    }
}
