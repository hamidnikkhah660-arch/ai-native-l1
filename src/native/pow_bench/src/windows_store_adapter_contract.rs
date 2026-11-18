//! Pure, test-only contract for a complete Windows-backed STH1 store adapter.
//!
//! This module performs no operating-system calls and is not wired into runtime.
//! It is a fail-closed model that a future native provider must satisfy using
//! evidence collected from the exact retained handles later used for I/O.

use std::collections::BTreeSet;

use crate::windows_store_path_qualifier::PhysicalVolumeIdentity;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoreObjectIdentity {
    pub volume: PhysicalVolumeIdentity,
    pub file_id: [u8; 16],
}

impl StoreObjectIdentity {
    fn is_well_formed(&self) -> bool {
        !self.volume.volume_guid_path.trim().is_empty()
            && !self.volume.filesystem.trim().is_empty()
            && !self.volume.device_instance_id.trim().is_empty()
            && self.file_id != [0; 16]
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RootHandleEvidence {
    pub identity: StoreObjectIdentity,
    pub retained: bool,
    pub share_delete_allowed: bool,
    pub owner_sid: String,
    pub acl_complete: bool,
    pub principals_with_mutation_rights: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DirectoryHandleEvidence {
    pub component: String,
    pub parent_identity: StoreObjectIdentity,
    pub identity: StoreObjectIdentity,
    pub reparse_point: bool,
    pub retained: bool,
    pub share_delete_allowed: bool,
    pub owner_sid: String,
    pub acl_complete: bool,
    pub principals_with_mutation_rights: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoreFileEvidence {
    pub identity: StoreObjectIdentity,
    pub parent_identity: StoreObjectIdentity,
    pub owner_sid: String,
    pub acl_complete: bool,
    pub principals_with_mutation_rights: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdapterBindingEvidence {
    pub root: RootHandleEvidence,
    /// Ordered from the pinned root down to the directory containing the state and lock files.
    pub directory_chain: Vec<DirectoryHandleEvidence>,
    pub store_directory_identity: StoreObjectIdentity,
    pub writer_lock: StoreFileEvidence,
    pub current_state_file: StoreFileEvidence,
    pub staged_state_file: StoreFileEvidence,
    pub writer_lock_handle_identity: StoreObjectIdentity,
    pub state_read_handle_identity: StoreObjectIdentity,
    pub state_size_check_handle_identity: StoreObjectIdentity,
    pub published_source_handle_identity: StoreObjectIdentity,
    pub published_target_handle_identity: StoreObjectIdentity,
    pub publication_parent_identity: StoreObjectIdentity,
    pub writer_lock_held: bool,
    pub lock_opened_relative_to_store_directory: bool,
    pub state_opened_relative_to_store_directory: bool,
    pub size_check_uses_state_read_handle: bool,
    pub staging_created_relative_to_store_directory: bool,
    pub publication_uses_staged_source_handle: bool,
    pub target_reopened_relative_to_store_directory: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WindowsStoreAdapterContract {
    /// This identity must come from an independent provisioning/enrollment channel,
    /// not from the pathname currently being qualified.
    pub pinned_root_identity: StoreObjectIdentity,
    /// Independently pinned identity of the directory holding the STB1 state and writer lock.
    pub pinned_store_directory_identity: StoreObjectIdentity,
    pub allowed_mutation_principals: BTreeSet<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdapterContractFailure {
    InvalidPinnedIdentity,
    InvalidObservedIdentity,
    RootIdentityMismatch,
    RootHandleNotRetained,
    DeleteSharingEnabled,
    AclIncomplete,
    OwnerNotEnumeratedAsMutator,
    UnexpectedMutationPrincipal,
    InvalidComponentName,
    ParentChildDiscontinuity,
    ReparsePoint,
    DirectoryHandleNotRetained,
    ExpectedStoreDirectoryMismatch,
    FileParentMismatch,
    CrossVolumeObject,
    WriterLockNotHeld,
    WriterLockHandleMismatch,
    StateReadHandleMismatch,
    StateSizeCheckHandleMismatch,
    OperationNotRelativeToStoreDirectory,
    PublicationParentMismatch,
    PublishedSourceHandleMismatch,
    PublishedTargetIdentityMismatch,
}

fn same_volume(left: &StoreObjectIdentity, right: &StoreObjectIdentity) -> bool {
    left.volume == right.volume
}

fn is_valid_component(name: &str) -> bool {
    if name.is_empty()
        || name == "."
        || name == ".."
        || name.contains(['\\', '/', ':', '\0'])
        || name.ends_with('.')
        || name.ends_with(' ')
        || name.chars().any(char::is_control)
        || name.encode_utf16().count() > 255
    {
        return false;
    }

    let stem = name.split('.').next().unwrap_or(name);
    let upper = stem.to_ascii_uppercase();
    !matches!(
        upper.as_str(),
        "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
    ) && !(upper.len() == 4
        && (upper.starts_with("COM") || upper.starts_with("LPT"))
        && matches!(upper.as_bytes()[3], b'1'..=b'9'))
}

impl WindowsStoreAdapterContract {
    fn validate_identity(
        &self,
        identity: &StoreObjectIdentity,
    ) -> Result<(), AdapterContractFailure> {
        if !identity.is_well_formed() {
            return Err(AdapterContractFailure::InvalidObservedIdentity);
        }
        if !same_volume(identity, &self.pinned_root_identity) {
            return Err(AdapterContractFailure::CrossVolumeObject);
        }
        Ok(())
    }

    fn validate_acl(
        &self,
        owner_sid: &str,
        acl_complete: bool,
        principals: &[String],
    ) -> Result<(), AdapterContractFailure> {
        if !acl_complete {
            return Err(AdapterContractFailure::AclIncomplete);
        }
        if owner_sid.trim().is_empty()
            || !principals
                .iter()
                .any(|sid| sid.eq_ignore_ascii_case(owner_sid))
        {
            return Err(AdapterContractFailure::OwnerNotEnumeratedAsMutator);
        }
        if principals.iter().any(|sid| {
            !self
                .allowed_mutation_principals
                .iter()
                .any(|allowed| allowed.eq_ignore_ascii_case(sid))
        }) {
            return Err(AdapterContractFailure::UnexpectedMutationPrincipal);
        }
        Ok(())
    }

    /// Validate handle-identity continuity and operation binding. No I/O is performed.
    pub fn validate(
        &self,
        evidence: &AdapterBindingEvidence,
    ) -> Result<(), AdapterContractFailure> {
        if !self.pinned_root_identity.is_well_formed()
            || !self.pinned_store_directory_identity.is_well_formed()
            || !same_volume(
                &self.pinned_store_directory_identity,
                &self.pinned_root_identity,
            )
            || self.allowed_mutation_principals.is_empty()
        {
            return Err(AdapterContractFailure::InvalidPinnedIdentity);
        }

        self.validate_identity(&evidence.root.identity)?;
        if evidence.root.identity != self.pinned_root_identity {
            return Err(AdapterContractFailure::RootIdentityMismatch);
        }
        if !evidence.root.retained {
            return Err(AdapterContractFailure::RootHandleNotRetained);
        }
        if evidence.root.share_delete_allowed {
            return Err(AdapterContractFailure::DeleteSharingEnabled);
        }
        self.validate_acl(
            &evidence.root.owner_sid,
            evidence.root.acl_complete,
            &evidence.root.principals_with_mutation_rights,
        )?;

        let mut expected_parent = evidence.root.identity.clone();
        for step in &evidence.directory_chain {
            if !is_valid_component(&step.component) {
                return Err(AdapterContractFailure::InvalidComponentName);
            }
            self.validate_identity(&step.parent_identity)?;
            self.validate_identity(&step.identity)?;
            if step.parent_identity != expected_parent {
                return Err(AdapterContractFailure::ParentChildDiscontinuity);
            }
            if step.reparse_point {
                return Err(AdapterContractFailure::ReparsePoint);
            }
            if !step.retained {
                return Err(AdapterContractFailure::DirectoryHandleNotRetained);
            }
            if step.share_delete_allowed {
                return Err(AdapterContractFailure::DeleteSharingEnabled);
            }
            self.validate_acl(
                &step.owner_sid,
                step.acl_complete,
                &step.principals_with_mutation_rights,
            )?;
            expected_parent = step.identity.clone();
        }

        self.validate_identity(&evidence.store_directory_identity)?;
        if expected_parent != evidence.store_directory_identity
            || evidence.store_directory_identity != self.pinned_store_directory_identity
        {
            return Err(AdapterContractFailure::ExpectedStoreDirectoryMismatch);
        }

        for file in [
            &evidence.writer_lock,
            &evidence.current_state_file,
            &evidence.staged_state_file,
        ] {
            self.validate_identity(&file.identity)?;
            self.validate_identity(&file.parent_identity)?;
            if file.parent_identity != evidence.store_directory_identity {
                return Err(AdapterContractFailure::FileParentMismatch);
            }
            self.validate_acl(
                &file.owner_sid,
                file.acl_complete,
                &file.principals_with_mutation_rights,
            )?;
        }

        self.validate_identity(&evidence.writer_lock_handle_identity)?;
        self.validate_identity(&evidence.state_read_handle_identity)?;
        self.validate_identity(&evidence.state_size_check_handle_identity)?;
        self.validate_identity(&evidence.published_source_handle_identity)?;
        self.validate_identity(&evidence.published_target_handle_identity)?;
        self.validate_identity(&evidence.publication_parent_identity)?;

        if !evidence.writer_lock_held {
            return Err(AdapterContractFailure::WriterLockNotHeld);
        }
        if evidence.writer_lock_handle_identity != evidence.writer_lock.identity {
            return Err(AdapterContractFailure::WriterLockHandleMismatch);
        }
        if !evidence.lock_opened_relative_to_store_directory
            || !evidence.state_opened_relative_to_store_directory
            || !evidence.staging_created_relative_to_store_directory
            || !evidence.publication_uses_staged_source_handle
            || !evidence.target_reopened_relative_to_store_directory
        {
            return Err(AdapterContractFailure::OperationNotRelativeToStoreDirectory);
        }
        if evidence.state_read_handle_identity != evidence.current_state_file.identity {
            return Err(AdapterContractFailure::StateReadHandleMismatch);
        }
        if !evidence.size_check_uses_state_read_handle
            || evidence.state_size_check_handle_identity != evidence.state_read_handle_identity
        {
            return Err(AdapterContractFailure::StateSizeCheckHandleMismatch);
        }
        if evidence.publication_parent_identity != evidence.store_directory_identity {
            return Err(AdapterContractFailure::PublicationParentMismatch);
        }
        if evidence.published_source_handle_identity != evidence.staged_state_file.identity {
            return Err(AdapterContractFailure::PublishedSourceHandleMismatch);
        }
        if evidence.published_target_handle_identity != evidence.published_source_handle_identity {
            return Err(AdapterContractFailure::PublishedTargetIdentityMismatch);
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

    fn identity(id: u8) -> StoreObjectIdentity {
        StoreObjectIdentity {
            volume: volume(),
            file_id: [id; 16],
        }
    }

    fn principals() -> Vec<String> {
        vec!["S-1-5-18".into(), "S-1-5-32-544".into()]
    }

    fn acl_object(id: u8, parent: u8) -> StoreFileEvidence {
        StoreFileEvidence {
            identity: identity(id),
            parent_identity: identity(parent),
            owner_sid: "S-1-5-18".into(),
            acl_complete: true,
            principals_with_mutation_rights: principals(),
        }
    }

    fn fixture() -> (WindowsStoreAdapterContract, AdapterBindingEvidence) {
        let root = identity(1);
        let level_one = identity(2);
        let store_directory = identity(3);
        let lock = acl_object(4, 3);
        let state = acl_object(5, 3);
        let staged = acl_object(6, 3);

        let policy = WindowsStoreAdapterContract {
            pinned_root_identity: root.clone(),
            pinned_store_directory_identity: store_directory.clone(),
            allowed_mutation_principals: ["S-1-5-18".to_string(), "S-1-5-32-544".to_string()]
                .into_iter()
                .collect(),
        };

        let evidence = AdapterBindingEvidence {
            root: RootHandleEvidence {
                identity: root.clone(),
                retained: true,
                share_delete_allowed: false,
                owner_sid: "S-1-5-18".into(),
                acl_complete: true,
                principals_with_mutation_rights: principals(),
            },
            directory_chain: vec![
                DirectoryHandleEvidence {
                    component: "QRun".into(),
                    parent_identity: root,
                    identity: level_one.clone(),
                    reparse_point: false,
                    retained: true,
                    share_delete_allowed: false,
                    owner_sid: "S-1-5-18".into(),
                    acl_complete: true,
                    principals_with_mutation_rights: principals(),
                },
                DirectoryHandleEvidence {
                    component: "Identity".into(),
                    parent_identity: level_one,
                    identity: store_directory.clone(),
                    reparse_point: false,
                    retained: true,
                    share_delete_allowed: false,
                    owner_sid: "S-1-5-18".into(),
                    acl_complete: true,
                    principals_with_mutation_rights: principals(),
                },
            ],
            store_directory_identity: store_directory.clone(),
            writer_lock: lock.clone(),
            current_state_file: state.clone(),
            staged_state_file: staged.clone(),
            writer_lock_handle_identity: lock.identity,
            state_read_handle_identity: state.identity.clone(),
            state_size_check_handle_identity: state.identity,
            published_source_handle_identity: staged.identity.clone(),
            published_target_handle_identity: staged.identity,
            publication_parent_identity: store_directory,
            writer_lock_held: true,
            lock_opened_relative_to_store_directory: true,
            state_opened_relative_to_store_directory: true,
            size_check_uses_state_read_handle: true,
            staging_created_relative_to_store_directory: true,
            publication_uses_staged_source_handle: true,
            target_reopened_relative_to_store_directory: true,
        };
        (policy, evidence)
    }

    #[test]
    fn accepts_fully_bound_root_chain_lock_read_and_publish_evidence() {
        let (policy, evidence) = fixture();
        assert_eq!(policy.validate(&evidence), Ok(()));
    }

    #[test]
    fn rejects_a_root_that_is_not_the_independently_pinned_object() {
        let (policy, mut evidence) = fixture();
        evidence.root.identity = identity(9);
        assert_eq!(
            policy.validate(&evidence),
            Err(AdapterContractFailure::RootIdentityMismatch)
        );
    }

    #[test]
    fn rejects_a_broken_parent_child_identity_chain() {
        let (policy, mut evidence) = fixture();
        evidence.directory_chain[1].parent_identity = identity(9);
        assert_eq!(
            policy.validate(&evidence),
            Err(AdapterContractFailure::ParentChildDiscontinuity)
        );
    }

    #[test]
    fn rejects_reparse_points_and_unretained_or_delete_shareable_ancestors() {
        let (policy, mut evidence) = fixture();
        evidence.directory_chain[0].reparse_point = true;
        assert_eq!(
            policy.validate(&evidence),
            Err(AdapterContractFailure::ReparsePoint)
        );
        evidence.directory_chain[0].reparse_point = false;
        evidence.directory_chain[1].retained = false;
        assert_eq!(
            policy.validate(&evidence),
            Err(AdapterContractFailure::DirectoryHandleNotRetained)
        );
        evidence.directory_chain[1].retained = true;
        evidence.directory_chain[1].share_delete_allowed = true;
        assert_eq!(
            policy.validate(&evidence),
            Err(AdapterContractFailure::DeleteSharingEnabled)
        );
    }

    #[test]
    fn rejects_incomplete_acl_missing_owner_or_unexpected_mutator_on_any_ancestor() {
        let (policy, mut evidence) = fixture();
        evidence.directory_chain[0].acl_complete = false;
        assert_eq!(
            policy.validate(&evidence),
            Err(AdapterContractFailure::AclIncomplete)
        );
        evidence.directory_chain[0].acl_complete = true;
        evidence.directory_chain[0]
            .principals_with_mutation_rights
            .clear();
        assert_eq!(
            policy.validate(&evidence),
            Err(AdapterContractFailure::OwnerNotEnumeratedAsMutator)
        );
        evidence.directory_chain[0].principals_with_mutation_rights = principals();
        evidence.directory_chain[1]
            .principals_with_mutation_rights
            .push("S-1-5-21-999".into());
        assert_eq!(
            policy.validate(&evidence),
            Err(AdapterContractFailure::UnexpectedMutationPrincipal)
        );
    }

    #[test]
    fn rejects_unsafe_or_reserved_component_names() {
        for name in [
            "",
            ".",
            "..",
            "a/b",
            "a\\b",
            "state:stream",
            "trailing.",
            "trailing ",
            "CON",
            "con.txt",
            "PRN.log",
            "COM1",
            "LPT9.dat",
        ] {
            assert!(!is_valid_component(name), "invalid component: {name:?}");
        }
        for name in ["ordinary", "store-v2", "CONSOLE", "COM10", "name.ext"] {
            assert!(is_valid_component(name), "valid component: {name:?}");
        }
    }

    #[test]
    fn rejects_lock_state_staging_and_publish_parent_mismatches() {
        let (policy, mut evidence) = fixture();
        evidence.writer_lock.parent_identity = identity(2);
        assert_eq!(
            policy.validate(&evidence),
            Err(AdapterContractFailure::FileParentMismatch)
        );
        evidence.writer_lock.parent_identity = identity(3);
        evidence.publication_parent_identity = identity(8);
        assert_eq!(
            policy.validate(&evidence),
            Err(AdapterContractFailure::PublicationParentMismatch)
        );
    }

    #[test]
    fn rejects_lock_not_held_or_operations_not_opened_relative_to_store_handle() {
        let (policy, mut evidence) = fixture();
        evidence.writer_lock_held = false;
        assert_eq!(
            policy.validate(&evidence),
            Err(AdapterContractFailure::WriterLockNotHeld)
        );
        evidence.writer_lock_held = true;
        evidence.staging_created_relative_to_store_directory = false;
        assert_eq!(
            policy.validate(&evidence),
            Err(AdapterContractFailure::OperationNotRelativeToStoreDirectory)
        );
    }

    #[test]
    fn rejects_state_size_check_that_uses_a_different_handle() {
        let (policy, mut evidence) = fixture();
        evidence.state_size_check_handle_identity = identity(9);
        assert_eq!(
            policy.validate(&evidence),
            Err(AdapterContractFailure::StateSizeCheckHandleMismatch)
        );
        evidence.state_size_check_handle_identity = evidence.state_read_handle_identity.clone();
        evidence.size_check_uses_state_read_handle = false;
        assert_eq!(
            policy.validate(&evidence),
            Err(AdapterContractFailure::StateSizeCheckHandleMismatch)
        );
    }

    #[test]
    fn rejects_publish_source_or_target_that_is_not_the_staged_object() {
        let (policy, mut evidence) = fixture();
        evidence.published_source_handle_identity = identity(7);
        assert_eq!(
            policy.validate(&evidence),
            Err(AdapterContractFailure::PublishedSourceHandleMismatch)
        );
        evidence.published_source_handle_identity = evidence.staged_state_file.identity.clone();
        evidence.published_target_handle_identity = identity(8);
        assert_eq!(
            policy.validate(&evidence),
            Err(AdapterContractFailure::PublishedTargetIdentityMismatch)
        );
    }

    #[test]
    fn rejects_file_or_directory_objects_from_an_unpinned_volume() {
        let (policy, mut evidence) = fixture();
        evidence
            .staged_state_file
            .identity
            .volume
            .device_instance_id = "OTHER-DISK".into();
        assert_eq!(
            policy.validate(&evidence),
            Err(AdapterContractFailure::CrossVolumeObject)
        );
    }
}
