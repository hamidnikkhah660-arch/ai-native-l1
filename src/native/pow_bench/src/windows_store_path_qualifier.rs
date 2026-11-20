//! Testable policy core for qualifying Windows-backed durable-store paths.
//!
//! This module deliberately contains no Win32 calls and is not wired into either
//! production store. A future Windows provider must obtain every field from the
//! exact retained OS handles used for subsequent I/O; pathname-only evidence is
//! insufficient. Until that provider and its integration tests exist, this
//! module is a policy/test harness, not proof that a path is safe.

use std::collections::BTreeSet;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PhysicalVolumeIdentity {
    /// Canonical volume-GUID path, e.g. `\\\\?\\Volume{...}\\`.
    pub volume_guid_path: String,
    /// Filesystem name reported for the opened volume (policy currently permits NTFS/ReFS).
    pub filesystem: String,
    /// Volume serial number; corroborating evidence, not a stand-alone trust anchor.
    pub volume_serial: u32,
    /// Device number returned by the storage stack for the opened volume/device.
    pub storage_device_number: u32,
    /// Stable device-instance identifier from the storage device descriptor/property query.
    pub device_instance_id: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StoreObjectKind {
    Directory,
    RegularFile,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WindowsStorePathEvidence {
    /// Final normalized path queried from the same handle that will be used for I/O.
    pub final_path: String,
    /// True only if each ancestor and the final object was opened and checked by handle.
    pub complete_handle_walk: bool,
    /// True only if no component in that handle walk had FILE_ATTRIBUTE_REPARSE_POINT.
    pub reparse_free: bool,
    /// True only if the evidence and later I/O refer to the same retained object handle.
    pub io_uses_qualified_handle: bool,
    pub object_kind: StoreObjectKind,
    pub volume: PhysicalVolumeIdentity,
    /// Canonical SID string from the opened object's security descriptor.
    pub owner_sid: String,
    /// True only if owner, DACL, inherited ACEs and relevant rights were completely parsed.
    pub acl_complete: bool,
    /// Principals with effective write/delete/ownership/DACL-change capability.
    pub principals_with_mutation_rights: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WindowsStorePathPolicy {
    pub expected_final_path_prefix: String,
    pub expected_volume: PhysicalVolumeIdentity,
    pub expected_owner_sid: String,
    /// Explicit allowlist for principals permitted to mutate the store namespace.
    pub allowed_mutation_principals: BTreeSet<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QualificationFailure {
    IncompleteHandleWalk,
    ReparsePoint,
    PathNotBoundToIoHandle,
    UnexpectedObjectKind,
    FinalPathOutsidePolicy,
    VolumeIdentityUnqualified,
    FilesystemUnsupported,
    OwnerUnqualified,
    AclUnqualified,
    UnexpectedMutationPrincipal,
    InvalidPolicyConfiguration,
}

fn normalized_windows_path(value: &str) -> String {
    value
        .replace('/', "\\")
        .trim_end_matches('\\')
        .to_ascii_lowercase()
}

fn path_is_within_prefix(path: &str, prefix: &str) -> bool {
    let path = normalized_windows_path(path);
    let prefix = normalized_windows_path(prefix);
    !prefix.is_empty()
        && (path == prefix
            || path
                .strip_prefix(&prefix)
                .is_some_and(|suffix| suffix.starts_with('\\')))
}

fn volume_identity_matches(
    actual: &PhysicalVolumeIdentity,
    expected: &PhysicalVolumeIdentity,
) -> bool {
    !actual.volume_guid_path.trim().is_empty()
        && !actual.device_instance_id.trim().is_empty()
        && actual
            .volume_guid_path
            .eq_ignore_ascii_case(&expected.volume_guid_path)
        && actual.filesystem.eq_ignore_ascii_case(&expected.filesystem)
        && actual.volume_serial == expected.volume_serial
        && actual.storage_device_number == expected.storage_device_number
        && actual
            .device_instance_id
            .eq_ignore_ascii_case(&expected.device_instance_id)
}

impl WindowsStorePathPolicy {
    /// Validate a provider's evidence. This function performs no I/O and changes nothing.
    pub fn validate(
        &self,
        evidence: &WindowsStorePathEvidence,
        expected_kind: StoreObjectKind,
    ) -> Result<(), QualificationFailure> {
        if !path_is_within_prefix(
            &self.expected_final_path_prefix,
            &self.expected_volume.volume_guid_path,
        ) {
            return Err(QualificationFailure::InvalidPolicyConfiguration);
        }

        if !evidence.complete_handle_walk {
            return Err(QualificationFailure::IncompleteHandleWalk);
        }
        if !evidence.reparse_free {
            return Err(QualificationFailure::ReparsePoint);
        }
        if !evidence.io_uses_qualified_handle {
            return Err(QualificationFailure::PathNotBoundToIoHandle);
        }
        if evidence.object_kind != expected_kind {
            return Err(QualificationFailure::UnexpectedObjectKind);
        }
        if !path_is_within_prefix(&evidence.final_path, &self.expected_final_path_prefix) {
            return Err(QualificationFailure::FinalPathOutsidePolicy);
        }
        if !volume_identity_matches(&evidence.volume, &self.expected_volume) {
            return Err(QualificationFailure::VolumeIdentityUnqualified);
        }
        if !matches!(
            evidence.volume.filesystem.to_ascii_uppercase().as_str(),
            "NTFS" | "REFS"
        ) {
            return Err(QualificationFailure::FilesystemUnsupported);
        }
        if evidence.owner_sid.trim().is_empty()
            || !evidence
                .owner_sid
                .eq_ignore_ascii_case(&self.expected_owner_sid)
        {
            return Err(QualificationFailure::OwnerUnqualified);
        }
        if !evidence.acl_complete {
            return Err(QualificationFailure::AclUnqualified);
        }
        if evidence.principals_with_mutation_rights.iter().any(|sid| {
            !self
                .allowed_mutation_principals
                .iter()
                .any(|allowed| allowed.eq_ignore_ascii_case(sid))
        }) {
            return Err(QualificationFailure::UnexpectedMutationPrincipal);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn volume() -> PhysicalVolumeIdentity {
        PhysicalVolumeIdentity {
            volume_guid_path: r"\\?\Volume{11111111-2222-3333-4444-555555555555}\".into(),
            filesystem: "NTFS".into(),
            volume_serial: 0x1234_abcd,
            storage_device_number: 1,
            device_instance_id: "SCSI\\DISK&VEN-TEST&PROD-SSD\\SERIAL-01".into(),
        }
    }

    fn policy() -> WindowsStorePathPolicy {
        WindowsStorePathPolicy {
            expected_final_path_prefix:
                r"\\?\Volume{11111111-2222-3333-4444-555555555555}\QRun\Identity".into(),
            expected_volume: volume(),
            expected_owner_sid: "S-1-5-18".into(),
            allowed_mutation_principals: ["S-1-5-18".to_string(), "S-1-5-32-544".to_string()]
                .into_iter()
                .collect(),
        }
    }

    fn evidence() -> WindowsStorePathEvidence {
        WindowsStorePathEvidence {
            final_path: r"\\?\Volume{11111111-2222-3333-4444-555555555555}\QRun\Identity\peer.piv1"
                .into(),
            complete_handle_walk: true,
            reparse_free: true,
            io_uses_qualified_handle: true,
            object_kind: StoreObjectKind::RegularFile,
            volume: volume(),
            owner_sid: "S-1-5-18".into(),
            acl_complete: true,
            principals_with_mutation_rights: vec!["S-1-5-32-544".into()],
        }
    }

    #[test]
    fn accepts_fully_qualified_file_evidence() {
        assert_eq!(
            policy().validate(&evidence(), StoreObjectKind::RegularFile),
            Ok(())
        );
    }

    #[test]
    fn rejects_incomplete_ancestor_handle_walk() {
        let mut e = evidence();
        e.complete_handle_walk = false;
        assert_eq!(
            policy().validate(&e, StoreObjectKind::RegularFile),
            Err(QualificationFailure::IncompleteHandleWalk)
        );
    }

    #[test]
    fn rejects_reparse_point_in_any_component() {
        let mut e = evidence();
        e.reparse_free = false;
        assert_eq!(
            policy().validate(&e, StoreObjectKind::RegularFile),
            Err(QualificationFailure::ReparsePoint)
        );
    }

    #[test]
    fn rejects_path_checked_on_a_different_handle() {
        let mut e = evidence();
        e.io_uses_qualified_handle = false;
        assert_eq!(
            policy().validate(&e, StoreObjectKind::RegularFile),
            Err(QualificationFailure::PathNotBoundToIoHandle)
        );
    }

    #[test]
    fn rejects_path_prefix_confusion() {
        let mut e = evidence();
        e.final_path =
            r"\\?\Volume{11111111-2222-3333-4444-555555555555}\QRun\Identity-evil\peer.piv1".into();
        assert_eq!(
            policy().validate(&e, StoreObjectKind::RegularFile),
            Err(QualificationFailure::FinalPathOutsidePolicy)
        );
    }

    #[test]
    fn rejects_changed_physical_device_identity() {
        let mut e = evidence();
        e.volume.storage_device_number = 9;
        assert_eq!(
            policy().validate(&e, StoreObjectKind::RegularFile),
            Err(QualificationFailure::VolumeIdentityUnqualified)
        );
    }

    #[test]
    fn rejects_unsupported_filesystem_even_if_volume_fields_match() {
        let mut e = evidence();
        e.volume.filesystem = "FAT32".into();
        let mut p = policy();
        p.expected_volume.filesystem = "FAT32".into();
        assert_eq!(
            p.validate(&e, StoreObjectKind::RegularFile),
            Err(QualificationFailure::FilesystemUnsupported)
        );
    }

    #[test]
    fn rejects_incomplete_acl_and_unexpected_writer() {
        let mut e = evidence();
        e.acl_complete = false;
        assert_eq!(
            policy().validate(&e, StoreObjectKind::RegularFile),
            Err(QualificationFailure::AclUnqualified)
        );
        e.acl_complete = true;
        e.principals_with_mutation_rights
            .push("S-1-5-21-999".into());
        assert_eq!(
            policy().validate(&e, StoreObjectKind::RegularFile),
            Err(QualificationFailure::UnexpectedMutationPrincipal)
        );
    }

    #[test]
    fn rejects_policy_prefix_on_a_different_volume() {
        let mut p = policy();
        p.expected_final_path_prefix =
            r"\\?\Volume{99999999-2222-3333-4444-555555555555}\QRun\Identity".into();
        assert_eq!(
            p.validate(&evidence(), StoreObjectKind::RegularFile),
            Err(QualificationFailure::InvalidPolicyConfiguration)
        );
    }

    #[test]
    fn compares_allowlisted_sid_case_insensitively() {
        let mut p = policy();
        p.allowed_mutation_principals = ["s-1-5-32-544".to_string()].into_iter().collect();
        assert_eq!(
            p.validate(&evidence(), StoreObjectKind::RegularFile),
            Ok(())
        );
    }
    #[test]
    fn rejects_wrong_owner_and_object_kind() {
        let mut e = evidence();
        e.owner_sid = "S-1-5-21-999".into();
        assert_eq!(
            policy().validate(&e, StoreObjectKind::RegularFile),
            Err(QualificationFailure::OwnerUnqualified)
        );
        e.owner_sid = "S-1-5-18".into();
        assert_eq!(
            policy().validate(&e, StoreObjectKind::Directory),
            Err(QualificationFailure::UnexpectedObjectKind)
        );
    }
}
