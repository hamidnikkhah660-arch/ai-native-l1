//! Candidate-only QRA1 immutable archive for the complete old PFS2 branch catalog.
//!
//! This module preserves exact branch payload bytes before a future checkpoint-rooted manifest
//! rebase. It does not perform provider CAS, update QCF1, replace an active PFS2 manifest, or
//! prove full consensus ancestry. Callers must first open/replay the source PFS2 store successfully.

use crate::{
    consensus::{pow_digest, ConsensusParameters, Uint256},
    private_testnet_fork_choice::MAX_FORK_ARCHIVE_BLOCKS,
    private_testnet_fork_store::{
        decode_manifest, manifest_anchor_commitment, ParsedManifest, PrivateTestnetForkStore,
        MAX_MANIFEST_BYTES,
    },
    private_testnet_wire::{decode_candidate_network_block, MAX_CANDIDATE_NETWORK_ENVELOPE_BYTES},
    qrun_v05_checkpoint_migration_candidate::QRunCheckpointMigrationJournal,
    store_writer_lock::StoreWriterLock,
};
use sha2::{Digest, Sha256};
#[cfg(unix)]
use std::fs::File;
use std::{
    fs::{self, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

const PFS2_MANIFEST_NAME: &str = "forkstore.manifest";
const PFS2_LOCK_NAME: &str = "forkstore.lock";
const PFS2_PENDING_NAME: &str = "qrun-v05-external-cas.pending";
const ARCHIVE_ROOT_LOCK_NAME: &str = "qrun-history-archive.lock";
const QRA1_DESCRIPTOR_NAME: &str = "archive.qra1";
const BRANCH_PREFIX: &str = "branch-";
const BRANCH_SUFFIX: &str = ".ptb2";

pub const QRA1_MAGIC: [u8; 4] = *b"QRA1";
pub const QRA1_VERSION: u16 = 1;
pub const QRA1_CHECKSUM_BYTES: usize = 32;
pub const QRA1_CHECKSUM_DOMAIN: &[u8] = b"QRUN-V05-PFS2-HISTORY-ARCHIVE-DESCRIPTOR-V1\0";
pub const QRA1_COMMITMENT_DOMAIN: &[u8] = b"QRUN-V05-PFS2-HISTORY-ARCHIVE-COMMITMENT-V1\0";

const QRA1_FIXED_BYTES: usize = 4 + 2 + 2 + 32 + 32 + 4 + 4 + QRA1_CHECKSUM_BYTES;
const QRA1_ENTRY_BYTES: usize = 32 + 8 + 32;
pub const MAX_QRA1_DESCRIPTOR_BYTES: usize =
    QRA1_FIXED_BYTES + MAX_MANIFEST_BYTES + MAX_FORK_ARCHIVE_BLOCKS * QRA1_ENTRY_BYTES;
pub const MAX_QRA1_TOTAL_PAYLOAD_BYTES: u64 =
    (MAX_FORK_ARCHIVE_BLOCKS as u64) * (MAX_CANDIDATE_NETWORK_ENVELOPE_BYTES as u64);

static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Debug)]
pub enum QRunHistoryArchiveError {
    Io(io::Error),
    InvalidDirectory,
    PathOverlap,
    SymlinkOrReparsePoint,
    UnexpectedStoreEntry,
    PendingCommitPresent,
    Oversize,
    Malformed,
    UnsupportedVersion(u16),
    ChecksumMismatch,
    ManifestAnchorMismatch,
    ManifestProfileMismatch,
    ArchiveIdMismatch,
    ArchiveCommitmentMismatch,
    BranchCatalogMismatch,
    BranchPayloadMismatch,
    BranchFilenameDigestMismatch,
    UnsupportedExecutionVariant,
    DuplicateDigest,
    ArchiveAlreadyExistsInvalid,
}

impl std::fmt::Display for QRunHistoryArchiveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for QRunHistoryArchiveError {}

impl From<io::Error> for QRunHistoryArchiveError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}
impl From<crate::private_testnet_fork_store::ForkStoreError> for QRunHistoryArchiveError {
    fn from(value: crate::private_testnet_fork_store::ForkStoreError) -> Self {
        use crate::private_testnet_fork_store::ForkStoreError;
        match value {
            ForkStoreError::ManifestAnchorMismatch => Self::ManifestAnchorMismatch,
            ForkStoreError::ManifestChecksumMismatch => Self::ChecksumMismatch,
            ForkStoreError::ManifestMalformed => Self::Malformed,
            ForkStoreError::UnexpectedStoreEntry => Self::UnexpectedStoreEntry,
            ForkStoreError::MissingReferencedBranch => Self::BranchCatalogMismatch,
            ForkStoreError::BranchFilenameDigestMismatch => Self::BranchFilenameDigestMismatch,
            _ => Self::ManifestProfileMismatch,
        }
    }
}
impl From<crate::private_testnet_wire::PrivateTestnetWireError> for QRunHistoryArchiveError {
    fn from(_: crate::private_testnet_wire::PrivateTestnetWireError) -> Self {
        Self::BranchPayloadMismatch
    }
}
impl From<crate::consensus::ConsensusError> for QRunHistoryArchiveError {
    fn from(_: crate::consensus::ConsensusError) -> Self {
        Self::BranchFilenameDigestMismatch
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Qra1VerifiedArchiveSeal;

/// This value is an opaque verification witness: callers can inspect it through accessors, but
/// cannot construct or mutate its bindings. It is returned only after QRA1 creation has published
/// and re-verified the archive, or after an explicit full archive verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QRunHistoryArchiveSummary {
    pub(crate) archive_id: [u8; 32],
    pub(crate) archive_commitment: [u8; 32],
    pub(crate) previous_manifest_anchor: [u8; 32],
    previous_manifest_bytes: Vec<u8>,
    pub(crate) network_id: [u8; 32],
    pub(crate) profile_fingerprint: [u8; 32],
    pub(crate) genesis_tip: [u8; 32],
    pub(crate) canonical_tip: [u8; 32],
    pub(crate) branch_count: u32,
    pub(crate) total_payload_bytes: u64,
    _verified: Qra1VerifiedArchiveSeal,
}

impl QRunHistoryArchiveSummary {
    pub fn archive_id(&self) -> &[u8; 32] {
        &self.archive_id
    }

    pub fn archive_commitment(&self) -> &[u8; 32] {
        &self.archive_commitment
    }

    pub fn previous_manifest_anchor(&self) -> &[u8; 32] {
        &self.previous_manifest_anchor
    }

    /// Exact PFS2 manifest bytes covered by the verified QRA1 descriptor and anchor.
    pub fn previous_manifest_bytes(&self) -> &[u8] {
        &self.previous_manifest_bytes
    }

    pub fn network_id(&self) -> &[u8; 32] {
        &self.network_id
    }

    pub fn profile_fingerprint(&self) -> &[u8; 32] {
        &self.profile_fingerprint
    }

    pub fn genesis_tip(&self) -> &[u8; 32] {
        &self.genesis_tip
    }

    pub fn canonical_tip(&self) -> &[u8; 32] {
        &self.canonical_tip
    }

    pub fn branch_count(&self) -> u32 {
        self.branch_count
    }

    pub fn total_payload_bytes(&self) -> u64 {
        self.total_payload_bytes
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Qra1Entry {
    digest: [u8; 32],
    payload_len: u64,
    payload_sha256: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Qra1Descriptor {
    archive_id: [u8; 32],
    previous_manifest_anchor: [u8; 32],
    previous_manifest: Vec<u8>,
    entries: Vec<Qra1Entry>,
}

impl Qra1Descriptor {
    fn validate_context(
        &self,
        expected_network_id: [u8; 32],
        expected_profile_fingerprint: [u8; 32],
        expected_genesis_tip: [u8; 32],
        expected_manifest_anchor: [u8; 32],
    ) -> Result<ParsedManifest, QRunHistoryArchiveError> {
        if self.previous_manifest.is_empty() || self.previous_manifest.len() > MAX_MANIFEST_BYTES {
            return Err(QRunHistoryArchiveError::Oversize);
        }
        if manifest_anchor_commitment(&self.previous_manifest) != self.previous_manifest_anchor
            || self.previous_manifest_anchor != expected_manifest_anchor
        {
            return Err(QRunHistoryArchiveError::ManifestAnchorMismatch);
        }
        if self.archive_id
            != QRunCheckpointMigrationJournal::archive_id_for_previous_manifest(
                self.previous_manifest_anchor,
            )
        {
            return Err(QRunHistoryArchiveError::ArchiveIdMismatch);
        }
        let manifest = decode_manifest(&self.previous_manifest)?;
        if manifest.network_id != expected_network_id
            || manifest.profile_fingerprint != expected_profile_fingerprint
            || manifest.genesis_tip != expected_genesis_tip
            || manifest.canonical_tip == [0; 32]
            || !manifest.digests.contains(&manifest.canonical_tip)
            || manifest.digests.len() != self.entries.len()
            || manifest.digests.len() > MAX_FORK_ARCHIVE_BLOCKS
        {
            return Err(QRunHistoryArchiveError::ManifestProfileMismatch);
        }

        let mut total = 0u64;
        let mut previous_digest = None;
        for (manifest_digest, entry) in manifest.digests.iter().zip(&self.entries) {
            if entry.digest != *manifest_digest {
                return Err(QRunHistoryArchiveError::BranchCatalogMismatch);
            }
            if previous_digest.is_some_and(|previous| previous >= entry.digest) {
                return Err(QRunHistoryArchiveError::DuplicateDigest);
            }
            if entry.payload_len == 0
                || entry.payload_len > MAX_CANDIDATE_NETWORK_ENVELOPE_BYTES as u64
                || entry.payload_sha256 == [0; 32]
            {
                return Err(QRunHistoryArchiveError::Oversize);
            }
            total = total
                .checked_add(entry.payload_len)
                .ok_or(QRunHistoryArchiveError::Oversize)?;
            if total > MAX_QRA1_TOTAL_PAYLOAD_BYTES {
                return Err(QRunHistoryArchiveError::Oversize);
            }
            previous_digest = Some(entry.digest);
        }
        if self.entries.is_empty() {
            return Err(QRunHistoryArchiveError::BranchCatalogMismatch);
        }
        Ok(manifest)
    }

    fn encode(
        &self,
        expected_network_id: [u8; 32],
        expected_profile_fingerprint: [u8; 32],
        expected_genesis_tip: [u8; 32],
        expected_manifest_anchor: [u8; 32],
    ) -> Result<Vec<u8>, QRunHistoryArchiveError> {
        self.validate_context(
            expected_network_id,
            expected_profile_fingerprint,
            expected_genesis_tip,
            expected_manifest_anchor,
        )?;
        let manifest_len = u32::try_from(self.previous_manifest.len())
            .map_err(|_| QRunHistoryArchiveError::Oversize)?;
        let entry_count =
            u32::try_from(self.entries.len()).map_err(|_| QRunHistoryArchiveError::Oversize)?;
        let mut bytes = Vec::with_capacity(
            QRA1_FIXED_BYTES + self.previous_manifest.len() + self.entries.len() * QRA1_ENTRY_BYTES,
        );
        bytes.extend_from_slice(&QRA1_MAGIC);
        bytes.extend_from_slice(&QRA1_VERSION.to_be_bytes());
        bytes.extend_from_slice(&0u16.to_be_bytes());
        bytes.extend_from_slice(&self.archive_id);
        bytes.extend_from_slice(&self.previous_manifest_anchor);
        bytes.extend_from_slice(&manifest_len.to_be_bytes());
        bytes.extend_from_slice(&self.previous_manifest);
        bytes.extend_from_slice(&entry_count.to_be_bytes());
        for entry in &self.entries {
            bytes.extend_from_slice(&entry.digest);
            bytes.extend_from_slice(&entry.payload_len.to_be_bytes());
            bytes.extend_from_slice(&entry.payload_sha256);
        }
        if bytes.len().saturating_add(QRA1_CHECKSUM_BYTES) > MAX_QRA1_DESCRIPTOR_BYTES {
            return Err(QRunHistoryArchiveError::Oversize);
        }
        let mut preimage = Vec::with_capacity(QRA1_CHECKSUM_DOMAIN.len() + bytes.len());
        preimage.extend_from_slice(QRA1_CHECKSUM_DOMAIN);
        preimage.extend_from_slice(&bytes);
        bytes.extend_from_slice(&Sha256::digest(preimage));
        Ok(bytes)
    }

    fn decode(
        bytes: &[u8],
        expected_network_id: [u8; 32],
        expected_profile_fingerprint: [u8; 32],
        expected_genesis_tip: [u8; 32],
        expected_manifest_anchor: [u8; 32],
    ) -> Result<Self, QRunHistoryArchiveError> {
        if bytes.len() > MAX_QRA1_DESCRIPTOR_BYTES || bytes.len() < QRA1_FIXED_BYTES {
            return Err(QRunHistoryArchiveError::Oversize);
        }
        if bytes.get(..4) != Some(QRA1_MAGIC.as_slice()) {
            return Err(QRunHistoryArchiveError::Malformed);
        }
        let version = read_u16(bytes, 4)?;
        if version != QRA1_VERSION {
            return Err(QRunHistoryArchiveError::UnsupportedVersion(version));
        }
        if read_u16(bytes, 6)? != 0 {
            return Err(QRunHistoryArchiveError::Malformed);
        }
        let checksum_offset = bytes
            .len()
            .checked_sub(QRA1_CHECKSUM_BYTES)
            .ok_or(QRunHistoryArchiveError::Malformed)?;
        let mut preimage = Vec::with_capacity(QRA1_CHECKSUM_DOMAIN.len() + checksum_offset);
        preimage.extend_from_slice(QRA1_CHECKSUM_DOMAIN);
        preimage.extend_from_slice(&bytes[..checksum_offset]);
        if Sha256::digest(preimage).as_slice() != &bytes[checksum_offset..] {
            return Err(QRunHistoryArchiveError::ChecksumMismatch);
        }

        let payload = &bytes[..checksum_offset];
        let mut cursor = 8usize;
        let archive_id = take_array::<32>(payload, &mut cursor)?;
        let previous_manifest_anchor = take_array::<32>(payload, &mut cursor)?;
        let manifest_len = take_u32(payload, &mut cursor)? as usize;
        if manifest_len == 0 || manifest_len > MAX_MANIFEST_BYTES {
            return Err(QRunHistoryArchiveError::Oversize);
        }
        let previous_manifest = take_slice(payload, &mut cursor, manifest_len)?.to_vec();
        let entry_count = take_u32(payload, &mut cursor)? as usize;
        if entry_count == 0 || entry_count > MAX_FORK_ARCHIVE_BLOCKS {
            return Err(QRunHistoryArchiveError::Oversize);
        }
        let expected_end = cursor
            .checked_add(
                entry_count
                    .checked_mul(QRA1_ENTRY_BYTES)
                    .ok_or(QRunHistoryArchiveError::Oversize)?,
            )
            .ok_or(QRunHistoryArchiveError::Oversize)?;
        if expected_end != payload.len() {
            return Err(QRunHistoryArchiveError::Malformed);
        }
        let mut entries = Vec::with_capacity(entry_count);
        for _ in 0..entry_count {
            entries.push(Qra1Entry {
                digest: take_array::<32>(payload, &mut cursor)?,
                payload_len: take_u64(payload, &mut cursor)?,
                payload_sha256: take_array::<32>(payload, &mut cursor)?,
            });
        }
        if cursor != payload.len() {
            return Err(QRunHistoryArchiveError::Malformed);
        }
        let descriptor = Self {
            archive_id,
            previous_manifest_anchor,
            previous_manifest,
            entries,
        };
        descriptor.validate_context(
            expected_network_id,
            expected_profile_fingerprint,
            expected_genesis_tip,
            expected_manifest_anchor,
        )?;
        let canonical = descriptor.encode(
            expected_network_id,
            expected_profile_fingerprint,
            expected_genesis_tip,
            expected_manifest_anchor,
        )?;
        if canonical.as_slice() != bytes {
            return Err(QRunHistoryArchiveError::Malformed);
        }
        Ok(descriptor)
    }
}

fn archive_commitment(descriptor_bytes: &[u8]) -> [u8; 32] {
    let mut preimage =
        Vec::with_capacity(QRA1_COMMITMENT_DOMAIN.len() + 8 + descriptor_bytes.len());
    preimage.extend_from_slice(QRA1_COMMITMENT_DOMAIN);
    preimage.extend_from_slice(&(descriptor_bytes.len() as u64).to_be_bytes());
    preimage.extend_from_slice(descriptor_bytes);
    Sha256::digest(preimage).into()
}

/// Copy and durably publish every branch from an already-open, fully replay-validated
/// Genesis-rooted QRun v0.5 PFS2 store. The borrowed store keeps its OS writer lock held for the
/// entire copy. A raw directory path is deliberately not accepted as proof of a validated store.
pub fn create_or_verify_qrun_v05_history_archive(
    source_store: &PrivateTestnetForkStore,
    archive_root: impl AsRef<Path>,
    params: &ConsensusParameters,
) -> Result<QRunHistoryArchiveSummary, QRunHistoryArchiveError> {
    params
        .validate()
        .map_err(|_| QRunHistoryArchiveError::ManifestProfileMismatch)?;
    let (
        source_directory,
        expected_network_id,
        expected_profile_fingerprint,
        expected_genesis_tip,
        expected_manifest_anchor,
    ) = source_store.qrun_v05_history_archive_identity()?;
    let validated_entries = source_store.qrun_v05_history_archive_entries()?;
    let validated_entry_map: std::collections::BTreeMap<_, _> = validated_entries
        .iter()
        .map(|(digest, length, payload_hash)| (*digest, (*length, *payload_hash)))
        .collect();
    let source = canonical_real_directory(&source_directory)?;
    let archive_root = canonical_real_directory(archive_root.as_ref())?;
    if source.starts_with(&archive_root) || archive_root.starts_with(&source) {
        return Err(QRunHistoryArchiveError::PathOverlap);
    }

    reject_symlink_if_present(&source.join(PFS2_LOCK_NAME))?;
    reject_symlink_if_present(&archive_root.join(ARCHIVE_ROOT_LOCK_NAME))?;
    let _archive_lock = StoreWriterLock::acquire(&archive_root, ARCHIVE_ROOT_LOCK_NAME)?;

    if source.join(PFS2_PENDING_NAME).exists() {
        return Err(QRunHistoryArchiveError::PendingCommitPresent);
    }
    let manifest_path = source.join(PFS2_MANIFEST_NAME);
    let manifest_bytes = read_regular_file_nofollow(&manifest_path, MAX_MANIFEST_BYTES)?;
    if manifest_anchor_commitment(&manifest_bytes) != expected_manifest_anchor {
        return Err(QRunHistoryArchiveError::ManifestAnchorMismatch);
    }
    let manifest = decode_manifest(&manifest_bytes)?;
    if manifest.network_id != expected_network_id
        || manifest.profile_fingerprint != expected_profile_fingerprint
        || manifest.genesis_tip != expected_genesis_tip
        || manifest.canonical_tip == [0; 32]
        || !manifest.digests.contains(&manifest.canonical_tip)
        || manifest.digests.is_empty()
    {
        return Err(QRunHistoryArchiveError::ManifestProfileMismatch);
    }
    if validated_entry_map.keys().copied().collect::<Vec<_>>() != manifest.digests {
        return Err(QRunHistoryArchiveError::BranchCatalogMismatch);
    }
    let archive_id =
        QRunCheckpointMigrationJournal::archive_id_for_previous_manifest(expected_manifest_anchor);
    let target_directory = archive_root.join(encode_hex(&archive_id));

    if target_directory.exists() {
        let summary = verify_qrun_v05_history_archive(
            &target_directory,
            expected_network_id,
            expected_profile_fingerprint,
            expected_genesis_tip,
            expected_manifest_anchor,
            params,
        )
        .map_err(|_| QRunHistoryArchiveError::ArchiveAlreadyExistsInvalid)?;
        if summary.archive_id != archive_id {
            return Err(QRunHistoryArchiveError::ArchiveAlreadyExistsInvalid);
        }
        return Ok(summary);
    }

    let _source_layout = validate_source_layout(&source, &manifest)?;
    let temp_directory = loop {
        let temp_id = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
        let candidate = archive_root.join(format!(".qra1-{}-{temp_id}.tmp", std::process::id()));
        match fs::create_dir(&candidate) {
            Ok(()) => break candidate,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(QRunHistoryArchiveError::Io(error)),
        }
    };

    let creation = (|| {
        let mut entries = Vec::with_capacity(manifest.digests.len());
        let mut total_payload_bytes = 0u64;
        for digest in &manifest.digests {
            let source_path = source.join(branch_file_name(digest));
            let payload =
                read_regular_file_nofollow(&source_path, MAX_CANDIDATE_NETWORK_ENVELOPE_BYTES)?;
            let (validated_length, validated_payload_hash) = validated_entry_map
                .get(digest)
                .ok_or(QRunHistoryArchiveError::BranchCatalogMismatch)?;
            let source_payload_hash: [u8; 32] = Sha256::digest(&payload).into();
            if payload.len() as u64 != *validated_length
                || source_payload_hash != *validated_payload_hash
            {
                return Err(QRunHistoryArchiveError::BranchPayloadMismatch);
            }
            validate_branch_payload(&payload, digest, expected_network_id, params)?;
            let payload_len =
                u64::try_from(payload.len()).map_err(|_| QRunHistoryArchiveError::Oversize)?;
            total_payload_bytes = total_payload_bytes
                .checked_add(payload_len)
                .ok_or(QRunHistoryArchiveError::Oversize)?;
            if total_payload_bytes > MAX_QRA1_TOTAL_PAYLOAD_BYTES {
                return Err(QRunHistoryArchiveError::Oversize);
            }
            let payload_sha256: [u8; 32] = Sha256::digest(&payload).into();
            write_synced_new(&temp_directory.join(branch_file_name(digest)), &payload)?;
            entries.push(Qra1Entry {
                digest: *digest,
                payload_len,
                payload_sha256,
            });
        }

        // Re-read the manifest while the source writer lock is held. No manifest replacement
        // can have occurred through the supported PFS2 writer API during the archive copy.
        let manifest_after_copy = read_regular_file_nofollow(&manifest_path, MAX_MANIFEST_BYTES)?;
        if manifest_after_copy != manifest_bytes {
            return Err(QRunHistoryArchiveError::ManifestAnchorMismatch);
        }

        let descriptor = Qra1Descriptor {
            archive_id,
            previous_manifest_anchor: expected_manifest_anchor,
            previous_manifest: manifest_bytes.clone(),
            entries,
        };
        let descriptor_bytes = descriptor.encode(
            expected_network_id,
            expected_profile_fingerprint,
            expected_genesis_tip,
            expected_manifest_anchor,
        )?;
        write_synced_new(
            &temp_directory.join(QRA1_DESCRIPTOR_NAME),
            &descriptor_bytes,
        )?;
        sync_directory(&temp_directory)?;
        Ok((descriptor_bytes, total_payload_bytes))
    })();

    let (descriptor_bytes, _) = match creation {
        Ok(value) => value,
        Err(error) => {
            let _ = fs::remove_dir_all(&temp_directory);
            return Err(error);
        }
    };

    // Validate the complete temp archive before publishing its deterministic final directory.
    let expected_commitment = archive_commitment(&descriptor_bytes);
    let temp_summary = match verify_qrun_v05_history_archive_inner(
        &temp_directory,
        expected_network_id,
        expected_profile_fingerprint,
        expected_genesis_tip,
        expected_manifest_anchor,
        params,
        false,
    ) {
        Ok(summary) => summary,
        Err(error) => {
            let _ = fs::remove_dir_all(&temp_directory);
            return Err(error);
        }
    };
    if temp_summary.archive_commitment != expected_commitment {
        let _ = fs::remove_dir_all(&temp_directory);
        return Err(QRunHistoryArchiveError::ArchiveCommitmentMismatch);
    }

    if target_directory.exists() {
        let _ = fs::remove_dir_all(&temp_directory);
        return Err(QRunHistoryArchiveError::ArchiveAlreadyExistsInvalid);
    }
    if let Err(error) = publish_directory_no_replace(&temp_directory, &target_directory) {
        let _ = fs::remove_dir_all(&temp_directory);
        return Err(QRunHistoryArchiveError::Io(error));
    }
    sync_directory(&archive_root)?;

    verify_qrun_v05_history_archive(
        &target_directory,
        expected_network_id,
        expected_profile_fingerprint,
        expected_genesis_tip,
        expected_manifest_anchor,
        params,
    )
}

/// Verify a QRA1 archive against the exact prior PFS2 identity and consensus PoW parameters.
pub fn verify_qrun_v05_history_archive(
    archive_directory: impl AsRef<Path>,
    expected_network_id: [u8; 32],
    expected_profile_fingerprint: [u8; 32],
    expected_genesis_tip: [u8; 32],
    expected_manifest_anchor: [u8; 32],
    params: &ConsensusParameters,
) -> Result<QRunHistoryArchiveSummary, QRunHistoryArchiveError> {
    verify_qrun_v05_history_archive_inner(
        archive_directory.as_ref(),
        expected_network_id,
        expected_profile_fingerprint,
        expected_genesis_tip,
        expected_manifest_anchor,
        params,
        true,
    )
}

fn verify_qrun_v05_history_archive_inner(
    archive_directory: &Path,
    expected_network_id: [u8; 32],
    expected_profile_fingerprint: [u8; 32],
    expected_genesis_tip: [u8; 32],
    expected_manifest_anchor: [u8; 32],
    params: &ConsensusParameters,
    require_archive_directory_name: bool,
) -> Result<QRunHistoryArchiveSummary, QRunHistoryArchiveError> {
    params
        .validate()
        .map_err(|_| QRunHistoryArchiveError::ManifestProfileMismatch)?;
    let directory = canonical_real_directory(archive_directory)?;
    let descriptor_path = directory.join(QRA1_DESCRIPTOR_NAME);
    let descriptor_bytes = read_regular_file_nofollow(&descriptor_path, MAX_QRA1_DESCRIPTOR_BYTES)?;
    let descriptor = Qra1Descriptor::decode(
        &descriptor_bytes,
        expected_network_id,
        expected_profile_fingerprint,
        expected_genesis_tip,
        expected_manifest_anchor,
    )?;
    let manifest = decode_manifest(&descriptor.previous_manifest)?;
    let expected_name = encode_hex(&descriptor.archive_id);
    if require_archive_directory_name
        && directory.file_name().and_then(|name| name.to_str()) != Some(expected_name.as_str())
    {
        return Err(QRunHistoryArchiveError::ArchiveIdMismatch);
    }

    let mut expected_entries = std::collections::BTreeSet::new();
    expected_entries.insert(QRA1_DESCRIPTOR_NAME.to_string());
    let mut total_payload_bytes = 0u64;
    for entry in &descriptor.entries {
        let name = branch_file_name(&entry.digest);
        expected_entries.insert(name.clone());
        let payload = read_regular_file_nofollow(
            &directory.join(&name),
            MAX_CANDIDATE_NETWORK_ENVELOPE_BYTES,
        )?;
        if payload.len() as u64 != entry.payload_len {
            return Err(QRunHistoryArchiveError::BranchPayloadMismatch);
        }
        let payload_hash: [u8; 32] = Sha256::digest(&payload).into();
        if payload_hash != entry.payload_sha256 {
            return Err(QRunHistoryArchiveError::BranchPayloadMismatch);
        }
        validate_branch_payload(&payload, &entry.digest, expected_network_id, params)?;
        total_payload_bytes = total_payload_bytes
            .checked_add(entry.payload_len)
            .ok_or(QRunHistoryArchiveError::Oversize)?;
        if total_payload_bytes > MAX_QRA1_TOTAL_PAYLOAD_BYTES {
            return Err(QRunHistoryArchiveError::Oversize);
        }
    }
    validate_exact_directory_entries(&directory, &expected_entries)?;

    Ok(QRunHistoryArchiveSummary {
        archive_id: descriptor.archive_id,
        archive_commitment: archive_commitment(&descriptor_bytes),
        previous_manifest_anchor: descriptor.previous_manifest_anchor,
        previous_manifest_bytes: descriptor.previous_manifest,
        network_id: manifest.network_id,
        profile_fingerprint: manifest.profile_fingerprint,
        genesis_tip: manifest.genesis_tip,
        canonical_tip: manifest.canonical_tip,
        branch_count: descriptor.entries.len() as u32,
        total_payload_bytes,
        _verified: Qra1VerifiedArchiveSeal,
    })
}

fn validate_source_layout(
    source: &Path,
    manifest: &ParsedManifest,
) -> Result<(), QRunHistoryArchiveError> {
    let mut expected = std::collections::BTreeSet::new();
    expected.insert(PFS2_MANIFEST_NAME.to_string());
    expected.insert(PFS2_LOCK_NAME.to_string());
    for digest in &manifest.digests {
        expected.insert(branch_file_name(digest));
    }
    validate_exact_directory_entries(source, &expected)
}

fn validate_exact_directory_entries(
    directory: &Path,
    expected_names: &std::collections::BTreeSet<String>,
) -> Result<(), QRunHistoryArchiveError> {
    let mut observed = std::collections::BTreeSet::new();
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        if file_type.is_symlink() || !file_type.is_file() {
            return Err(QRunHistoryArchiveError::SymlinkOrReparsePoint);
        }
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| QRunHistoryArchiveError::UnexpectedStoreEntry)?;
        let metadata = fs::symlink_metadata(entry.path())?;
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
            if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                return Err(QRunHistoryArchiveError::SymlinkOrReparsePoint);
            }
        }
        #[cfg(not(windows))]
        let _ = metadata;
        if !observed.insert(name) {
            return Err(QRunHistoryArchiveError::UnexpectedStoreEntry);
        }
    }
    if &observed != expected_names {
        return Err(QRunHistoryArchiveError::UnexpectedStoreEntry);
    }
    Ok(())
}

fn canonical_real_directory(path: &Path) -> Result<PathBuf, QRunHistoryArchiveError> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        return Err(QRunHistoryArchiveError::InvalidDirectory);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(QRunHistoryArchiveError::SymlinkOrReparsePoint);
        }
    }
    Ok(fs::canonicalize(path)?)
}

fn reject_symlink_if_present(path: &Path) -> Result<(), QRunHistoryArchiveError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() {
                return Err(QRunHistoryArchiveError::SymlinkOrReparsePoint);
            }
            #[cfg(windows)]
            {
                use std::os::windows::fs::MetadataExt;
                const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
                if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                    return Err(QRunHistoryArchiveError::SymlinkOrReparsePoint);
                }
            }
            Ok(())
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(QRunHistoryArchiveError::Io(error)),
    }
}

fn read_regular_file_nofollow(
    path: &Path,
    max_bytes: usize,
) -> Result<Vec<u8>, QRunHistoryArchiveError> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let file = options.open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(QRunHistoryArchiveError::SymlinkOrReparsePoint);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(QRunHistoryArchiveError::SymlinkOrReparsePoint);
        }
    }
    let length = metadata.len();
    if length > max_bytes as u64 {
        return Err(QRunHistoryArchiveError::Oversize);
    }
    let mut bytes = Vec::with_capacity(length as usize);
    file.take(max_bytes as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > max_bytes || bytes.len() as u64 != length {
        return Err(QRunHistoryArchiveError::Oversize);
    }
    Ok(bytes)
}

fn validate_branch_payload(
    payload: &[u8],
    expected_digest: &[u8; 32],
    expected_network_id: [u8; 32],
    params: &ConsensusParameters,
) -> Result<(), QRunHistoryArchiveError> {
    let decoded = decode_candidate_network_block(payload)?;
    if decoded.fee_block.is_none() {
        return Err(QRunHistoryArchiveError::UnsupportedExecutionVariant);
    }
    if decoded.header.network_id != expected_network_id
        || decoded.header.protocol_version != params.protocol_version
    {
        return Err(QRunHistoryArchiveError::BranchFilenameDigestMismatch);
    }
    let digest = pow_digest(&decoded.header, params.pow)?;
    if &digest != expected_digest || Uint256::from_be_bytes(digest) > decoded.header.target {
        return Err(QRunHistoryArchiveError::BranchFilenameDigestMismatch);
    }
    Ok(())
}

fn write_synced_new(path: &Path, bytes: &[u8]) -> Result<(), QRunHistoryArchiveError> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(bytes)?;
    file.flush()?;
    file.sync_all()?;
    Ok(())
}

fn sync_directory(path: &Path) -> Result<(), QRunHistoryArchiveError> {
    #[cfg(unix)]
    {
        File::open(path)?.sync_all()?;
    }
    // Windows publication uses MoveFileExW(MOVEFILE_WRITE_THROUGH) below; opening a directory
    // with File::open is not a portable durability primitive on Windows.
    #[cfg(windows)]
    let _ = path;
    Ok(())
}

fn publish_directory_no_replace(source: &Path, destination: &Path) -> io::Result<()> {
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        #[link(name = "kernel32")]
        extern "system" {
            fn MoveFileExW(existing: *const u16, new: *const u16, flags: u32) -> i32;
        }
        // Omitting MOVEFILE_REPLACE_EXISTING preserves no-replace semantics. WRITE_THROUGH
        // requests completion of the move before the call returns.
        const MOVEFILE_WRITE_THROUGH: u32 = 0x0000_0008;
        let source_wide: Vec<u16> = source.as_os_str().encode_wide().chain(Some(0)).collect();
        let destination_wide: Vec<u16> = destination
            .as_os_str()
            .encode_wide()
            .chain(Some(0))
            .collect();
        // SAFETY: both paths are NUL-terminated UTF-16 buffers that live across the call.
        let result = unsafe {
            MoveFileExW(
                source_wide.as_ptr(),
                destination_wide.as_ptr(),
                MOVEFILE_WRITE_THROUGH,
            )
        };
        if result == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
    #[cfg(target_os = "linux")]
    {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        extern "C" {
            fn renameat2(
                olddirfd: i32,
                oldpath: *const std::ffi::c_char,
                newdirfd: i32,
                newpath: *const std::ffi::c_char,
                flags: u32,
            ) -> i32;
        }
        const AT_FDCWD: i32 = -100;
        const RENAME_NOREPLACE: u32 = 1;
        let source_c = CString::new(source.as_os_str().as_bytes())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "source path contains NUL"))?;
        let destination_c = CString::new(destination.as_os_str().as_bytes()).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "destination path contains NUL")
        })?;
        // SAFETY: C strings live through the call; renameat2 atomically refuses an existing
        // destination instead of replacing it.
        let result = unsafe {
            renameat2(
                AT_FDCWD,
                source_c.as_ptr(),
                AT_FDCWD,
                destination_c.as_ptr(),
                RENAME_NOREPLACE,
            )
        };
        if result != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
    #[cfg(target_os = "macos")]
    {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        extern "C" {
            fn renamex_np(
                oldpath: *const std::ffi::c_char,
                newpath: *const std::ffi::c_char,
                flags: u32,
            ) -> i32;
        }
        const RENAME_EXCL: u32 = 0x0000_0004;
        let source_c = CString::new(source.as_os_str().as_bytes())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "source path contains NUL"))?;
        let destination_c = CString::new(destination.as_os_str().as_bytes()).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "destination path contains NUL")
        })?;
        // SAFETY: C strings live through the call; RENAME_EXCL refuses an existing target.
        let result = unsafe { renamex_np(source_c.as_ptr(), destination_c.as_ptr(), RENAME_EXCL) };
        if result != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
    #[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
    {
        let _ = (source, destination);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "atomic no-replace directory publication is unsupported on this Unix target",
        ))
    }
}

fn branch_file_name(digest: &[u8; 32]) -> String {
    format!("{BRANCH_PREFIX}{}{BRANCH_SUFFIX}", encode_hex(digest))
}

fn encode_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(DIGITS[(byte >> 4) as usize] as char);
        output.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    output
}

fn take_slice<'a>(
    bytes: &'a [u8],
    cursor: &mut usize,
    length: usize,
) -> Result<&'a [u8], QRunHistoryArchiveError> {
    let end = cursor
        .checked_add(length)
        .ok_or(QRunHistoryArchiveError::Malformed)?;
    let value = bytes
        .get(*cursor..end)
        .ok_or(QRunHistoryArchiveError::Malformed)?;
    *cursor = end;
    Ok(value)
}

fn take_array<const N: usize>(
    bytes: &[u8],
    cursor: &mut usize,
) -> Result<[u8; N], QRunHistoryArchiveError> {
    take_slice(bytes, cursor, N)?
        .try_into()
        .map_err(|_| QRunHistoryArchiveError::Malformed)
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, QRunHistoryArchiveError> {
    let end = offset
        .checked_add(2)
        .ok_or(QRunHistoryArchiveError::Malformed)?;
    Ok(u16::from_be_bytes(
        bytes
            .get(offset..end)
            .ok_or(QRunHistoryArchiveError::Malformed)?
            .try_into()
            .map_err(|_| QRunHistoryArchiveError::Malformed)?,
    ))
}

fn take_u32(bytes: &[u8], cursor: &mut usize) -> Result<u32, QRunHistoryArchiveError> {
    Ok(u32::from_be_bytes(take_array::<4>(bytes, cursor)?))
}

fn take_u64(bytes: &[u8], cursor: &mut usize) -> Result<u64, QRunHistoryArchiveError> {
    Ok(u64::from_be_bytes(take_array::<8>(bytes, cursor)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        consensus::{PowAlgorithm, PowHeader, Uint256},
        private_testnet_fork_choice::PrivateTestnetForkChoice,
        private_testnet_fork_store::PrivateTestnetForkStore,
        qrun_v05_fee_pow_wire_candidate::encode_qrun_v05_fee_pow_block,
        qrun_v05_genesis_candidate::QRunGenesisV05,
        state_machine::{Block, QRunV05FeeBlock, TransactionAuthenticator},
    };
    use std::{
        process,
        sync::atomic::{AtomicU64, Ordering},
    };

    static TEST_ID: AtomicU64 = AtomicU64::new(1);

    struct TestDir(PathBuf);
    impl TestDir {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "qrun_qra1_history_archive_{}_{}",
                process::id(),
                TEST_ID.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    struct RejectAllAuthenticator;
    impl TransactionAuthenticator for RejectAllAuthenticator {
        fn verify(&self, _: &[u8; 32], _: &[u8; 32], _: &[u8]) -> Result<(), ()> {
            Err(())
        }
    }

    struct FixedClock;
    impl crate::chain_admission::ReferenceTimeProvider for FixedClock {
        fn sample(
            &self,
        ) -> Result<
            crate::chain_admission::ReferenceTimeSample,
            crate::chain_admission::ReferenceTimeError,
        > {
            Ok(crate::chain_admission::ReferenceTimeSample {
                unix_seconds: 100,
                provenance: crate::chain_admission::ReferenceTimeProvenance::ConfiguredProvider,
                source_id: "qra1-history-archive-test-clock",
            })
        }
    }

    struct Fixture {
        _temp: TestDir,
        source: PathBuf,
        store: PrivateTestnetForkStore,
        archive_root: PathBuf,
        network_id: [u8; 32],
        profile_fingerprint: [u8; 32],
        genesis_tip: [u8; 32],
        manifest_anchor: [u8; 32],
        manifest_bytes: Vec<u8>,
        params: ConsensusParameters,
        branch_digest: [u8; 32],
    }

    fn fixture() -> Fixture {
        let temp = TestDir::new();
        let source = temp.0.join("source");
        let archive_root = temp.0.join("archives");
        fs::create_dir(&source).unwrap();
        fs::create_dir(&archive_root).unwrap();

        let mut params = ConsensusParameters::candidate_testnet().unwrap();
        params.protocol_version = 5;
        params.target_block_time_secs = 1;
        params.initial_target = Uint256::MAX;
        params.pow_limit = Uint256::MAX;
        params.pow.algorithm = PowAlgorithm::Argon2id;
        params.pow.memory_kib = 8 * 1024;
        params.pow.iterations = 1;

        let owner = [0x2A; 32];
        let genesis_candidate = QRunGenesisV05::new([0x51; 32], owner).unwrap();
        let genesis = genesis_candidate.ledger().clone();
        let genesis_archive =
            PrivateTestnetForkChoice::new_qrun_v05_fee_only(genesis.clone(), params.clone())
                .unwrap();
        let previous_consensus_hash = genesis_archive.canonical_chain().chain_tip().tip_hash;

        let mut fee_block = QRunV05FeeBlock {
            body: Block {
                height: 1,
                timestamp: 100,
                parent_hash: genesis.tip_hash(),
                state_root: [0; 32],
                transactions: Vec::new(),
            },
            producer: [0x77; 32],
        };
        fee_block.body.state_root = genesis
            .preview_qrun_v05_fee_state_root_after(&fee_block, &RejectAllAuthenticator)
            .unwrap();
        let header = PowHeader {
            protocol_version: params.protocol_version,
            network_id: genesis.network_id(),
            height: 1,
            timestamp: 100,
            parent_hash: genesis.tip_hash(),
            previous_consensus_hash,
            state_root: crate::qrun_v05_fee_pow_wire_candidate::qrun_v05_fee_pow_state_commitment(
                &fee_block,
            )
            .unwrap(),
            target: params.initial_target,
            nonce: 0,
        };
        let envelope = encode_qrun_v05_fee_pow_block(&header, &fee_block).unwrap();

        let mut store = PrivateTestnetForkStore::open_qrun_v05_fee_only(
            &source,
            genesis.clone(),
            params.clone(),
            &RejectAllAuthenticator,
            &FixedClock,
        )
        .unwrap();
        let outcome = store
            .submit(&envelope, &RejectAllAuthenticator, &FixedClock)
            .unwrap();
        let manifest_anchor = store.manifest_anchor().unwrap();
        let manifest_bytes =
            read_regular_file_nofollow(&source.join(PFS2_MANIFEST_NAME), MAX_MANIFEST_BYTES)
                .unwrap();
        let manifest = decode_manifest(&manifest_bytes).unwrap();
        assert_eq!(outcome.block_digest, manifest.canonical_tip);
        Fixture {
            _temp: temp,
            source,
            store,
            archive_root,
            network_id: genesis.network_id(),
            profile_fingerprint: manifest.profile_fingerprint,
            genesis_tip: manifest.genesis_tip,
            manifest_anchor,
            manifest_bytes,
            params,
            branch_digest: outcome.block_digest,
        }
    }

    fn create(fixture: &Fixture) -> QRunHistoryArchiveSummary {
        create_or_verify_qrun_v05_history_archive(
            &fixture.store,
            &fixture.archive_root,
            &fixture.params,
        )
        .unwrap()
    }

    #[test]
    fn qra1_summary_binds_exact_qrm1_archive_identity_and_manifest() {
        let (mut journal, pin, params) =
            crate::qrun_v05_checkpoint_migration_candidate::tests::fixture();
        let fixture = fixture();
        let archive = create(&fixture);
        // The journal fixture uses a sentinel commitment for codec isolation; replace it with the
        // commitment from this independently created and re-verified QRA1 archive before invoking
        // the public strict QRM1 API.
        journal.archive_id = archive.archive_id;
        journal.archive_commitment = archive.archive_commitment;

        let old_manifest = decode_manifest(&journal.previous_manifest).unwrap();
        assert_eq!(archive.archive_id, journal.archive_id);
        assert_eq!(archive.archive_commitment, journal.archive_commitment);
        assert_eq!(
            archive.previous_manifest_anchor,
            manifest_anchor_commitment(&journal.previous_manifest)
        );
        assert_eq!(archive.network_id, pin.network_id);
        assert_eq!(
            archive.profile_fingerprint,
            old_manifest.profile_fingerprint
        );
        assert_eq!(archive.genesis_tip, old_manifest.genesis_tip);
        assert_eq!(archive.canonical_tip, old_manifest.canonical_tip);
        assert_eq!(archive.branch_count as usize, old_manifest.digests.len());

        let bytes = journal.encode(&pin, &params, &archive).unwrap();
        let decoded =
            QRunCheckpointMigrationJournal::decode(&bytes, &pin, &params, &archive).unwrap();
        assert_eq!(decoded, journal);

        let mut wrong_commitment = journal.clone();
        wrong_commitment.archive_commitment[0] ^= 1;
        assert_eq!(
            wrong_commitment.encode(&pin, &params, &archive),
            Err(crate::qrun_v05_checkpoint_migration_candidate::QRunCheckpointMigrationError::ArchiveBindingMismatch)
        );

        let mut wrong_tip = archive.clone();
        wrong_tip.canonical_tip[0] ^= 1;
        assert_eq!(
            QRunCheckpointMigrationJournal::decode(&bytes, &pin, &params, &wrong_tip),
            Err(crate::qrun_v05_checkpoint_migration_candidate::QRunCheckpointMigrationError::ArchiveBindingMismatch)
        );

        let mut wrong_profile = archive.clone();
        wrong_profile.profile_fingerprint[0] ^= 1;
        assert_eq!(
            journal.encode(&pin, &params, &wrong_profile),
            Err(crate::qrun_v05_checkpoint_migration_candidate::QRunCheckpointMigrationError::ArchiveBindingMismatch)
        );

        let mut wrong_genesis = archive.clone();
        wrong_genesis.genesis_tip[0] ^= 1;
        assert_eq!(
            journal.encode(&pin, &params, &wrong_genesis),
            Err(crate::qrun_v05_checkpoint_migration_candidate::QRunCheckpointMigrationError::ArchiveBindingMismatch)
        );

        let mut wrong_branch_count = archive.clone();
        wrong_branch_count.branch_count += 1;
        assert_eq!(
            journal.encode(&pin, &params, &wrong_branch_count),
            Err(crate::qrun_v05_checkpoint_migration_candidate::QRunCheckpointMigrationError::ArchiveBindingMismatch)
        );

        let mut wrong_manifest_bytes = archive.clone();
        wrong_manifest_bytes.previous_manifest_bytes[138] ^= 1;
        assert_eq!(
            journal.encode(&pin, &params, &wrong_manifest_bytes),
            Err(crate::qrun_v05_checkpoint_migration_candidate::QRunCheckpointMigrationError::ArchiveBindingMismatch)
        );
    }

    #[test]
    fn qrm1_preflight_builds_exact_checkpoint_manifest_and_cas_intent_without_provider_writes() {
        use crate::{
            external_cas_anchor_candidate::{ExternalCasPin, ExternalCasRecord},
            qrun_v05_checkpoint_candidate::QRunV05PowCheckpoint,
            qrun_v05_checkpoint_migration_candidate::{
                prepare_qrun_v05_checkpoint_migration, QRunCheckpointMigrationJournal,
            },
            v4_fat1_trust_candidate::ML_DSA_65_PUBLIC_KEY_BYTES,
        };

        let mut fixture = fixture();
        let archive = create(&fixture);
        let owner = [0x2A; 32];
        let genesis = QRunGenesisV05::new(fixture.network_id, owner).unwrap();
        let pin = ExternalCasPin {
            provider_id: [0x91; 32],
            network_id: fixture.network_id,
            genesis_digest: genesis.commitment(),
            receipt_key_id: [0x92; 32],
            receipt_public_key: [0x93; ML_DSA_65_PUBLIC_KEY_BYTES],
        };
        let previous_record = ExternalCasRecord {
            generation: 7,
            provider_id: pin.provider_id,
            network_id: pin.network_id,
            genesis_digest: pin.genesis_digest,
            previous_record_digest: [0x94; 32],
            previous_state_digest: [0x95; 32],
            next_state_digest: fixture.manifest_anchor,
            operation_id: [0x96; 32],
            request_digest: [0x97; 32],
        };
        let expected_parent = [0x98; 32];
        let plan = prepare_qrun_v05_checkpoint_migration(
            &fixture.store,
            &archive,
            owner,
            &fixture.params,
            &pin,
            previous_record.clone(),
            8,
            expected_parent,
        )
        .unwrap();

        let journal = plan.journal();
        assert_eq!(journal.previous_record, previous_record);
        assert_eq!(journal.previous_manifest, fixture.manifest_bytes);
        assert_eq!(journal.archive_id, archive.archive_id);
        assert_eq!(journal.archive_commitment, archive.archive_commitment);
        assert_eq!(
            journal.expected_parent_checkpoint_commitment,
            expected_parent
        );
        assert_eq!(
            journal.minimum_checkpoint_height,
            fixture.store.canonical_height()
        );
        assert_eq!(
            QRunV05PowCheckpoint::commitment_for_bytes(&journal.checkpoint_bytes),
            journal.checkpoint_commitment
        );

        let next_manifest = decode_manifest(&journal.next_manifest).unwrap();
        assert_eq!(next_manifest.network_id, fixture.network_id);
        assert_eq!(next_manifest.genesis_tip, fixture.branch_digest);
        assert_eq!(next_manifest.canonical_tip, fixture.branch_digest);
        assert!(next_manifest.digests.is_empty());
        assert_eq!(
            journal.previous_object_generation,
            journal.previous_record.generation + 1
        );
        assert_eq!(
            journal.next_object_generation,
            journal.next_record.generation + 1
        );

        let request = plan.external_cas_write_request(&pin).unwrap();
        assert_ne!(request.request_nonce, [0; 32]);
        assert_ne!(request.operation_id, [0; 32]);
        assert_eq!(request.expected_generation, previous_record.generation);
        assert_eq!(request.expected_object_generation, 8);
        assert_eq!(request.next_record, journal.next_record);
        assert_eq!(
            QRunCheckpointMigrationJournal::decode(
                plan.journal_bytes(),
                &pin,
                &fixture.params,
                &archive
            )
            .unwrap(),
            *journal
        );

        // The preflight only builds local evidence. The active Genesis-rooted PFS2 remains intact.
        assert_eq!(
            fixture.store.manifest_anchor().unwrap(),
            fixture.manifest_anchor
        );
        assert_eq!(fixture.store.canonical_tip(), fixture.branch_digest);
        assert_eq!(fixture.store.canonical_height(), 1);

        let mut wrong_anchor_record = previous_record;
        wrong_anchor_record.next_state_digest[0] ^= 1;
        assert!(matches!(
            prepare_qrun_v05_checkpoint_migration(
                &fixture.store,
                &archive,
                owner,
                &fixture.params,
                &pin,
                wrong_anchor_record,
                8,
                expected_parent
            ),
            Err(crate::qrun_v05_checkpoint_migration_candidate::QRunCheckpointMigrationError::InvalidBinding)
        ));

        let mut wrong_archive = archive.clone();
        wrong_archive.canonical_tip[0] ^= 1;
        let correct_record = plan.journal().previous_record.clone();
        assert!(matches!(
            prepare_qrun_v05_checkpoint_migration(
                &fixture.store,
                &wrong_archive,
                owner,
                &fixture.params,
                &pin,
                correct_record,
                8,
                expected_parent
            ),
            Err(crate::qrun_v05_checkpoint_migration_candidate::QRunCheckpointMigrationError::ArchiveBindingMismatch)
        ));

        // QRM1 and an ordinary QAP1 block-commit intent may never coexist.
        let qap1_path = fixture.source.join("qrun-v05-external-cas.pending");
        fs::write(&qap1_path, b"pending-qap1").unwrap();
        assert!(matches!(
            fixture.store.persist_qrun_v05_migration_intent(&plan),
            Err(crate::private_testnet_fork_store::ForkStoreError::PendingRecoveryRequired)
        ));
        fs::remove_file(&qap1_path).unwrap();

        // Durable staging is create-once and local-only. It blocks further PFS2 writes and
        // ordinary restart until the dedicated signed-provider/QCF1 migration recovery exists.
        let intent_path = fixture.source.join("qrun-v05-migration.qrm1");
        fixture
            .store
            .persist_qrun_v05_migration_intent(&plan)
            .unwrap();
        assert_eq!(fs::read(&intent_path).unwrap(), plan.journal_bytes());
        fixture
            .store
            .persist_qrun_v05_migration_intent(&plan)
            .unwrap();
        assert!(matches!(
            fixture
                .store
                .submit(&[], &RejectAllAuthenticator, &FixedClock),
            Err(crate::private_testnet_fork_store::ForkStoreError::MigrationRecoveryRequired)
        ));
        fs::write(&intent_path, b"existing-intent-must-not-be-replaced").unwrap();
        assert!(matches!(
            fixture.store.persist_qrun_v05_migration_intent(&plan),
            Err(crate::private_testnet_fork_store::ForkStoreError::MigrationIntentConflict)
        ));
        assert_eq!(
            fs::read(&intent_path).unwrap(),
            b"existing-intent-must-not-be-replaced"
        );
        drop(fixture.store);
        assert!(matches!(
            PrivateTestnetForkStore::open_qrun_v05_fee_only(
                &fixture.source,
                genesis.ledger().clone(),
                fixture.params.clone(),
                &RejectAllAuthenticator,
                &FixedClock
            ),
            Err(crate::private_testnet_fork_store::ForkStoreError::MigrationRecoveryRequired)
        ));
    }

    #[test]
    fn qrm1_unpublished_temp_is_cleaned_on_reopen_without_changing_active_history() {
        let fixture = fixture();
        let orphan_temp = fixture.source.join(".qrun-v05-migration.qrm1.tmp-12345.7");
        fs::write(&orphan_temp, b"crash-before-final-publication").unwrap();
        let genesis = QRunGenesisV05::new(fixture.network_id, [0x2A; 32]).unwrap();
        drop(fixture.store);

        let reopened = PrivateTestnetForkStore::open_qrun_v05_fee_only(
            &fixture.source,
            genesis.ledger().clone(),
            fixture.params.clone(),
            &RejectAllAuthenticator,
            &FixedClock,
        )
        .unwrap();
        assert!(!orphan_temp.exists());
        assert_eq!(reopened.canonical_tip(), fixture.branch_digest);
        assert_eq!(reopened.canonical_height(), 1);
        assert_eq!(reopened.manifest_anchor().unwrap(), fixture.manifest_anchor);
    }

    #[test]
    fn qra1_copies_every_manifest_branch_and_is_idempotently_verifiable() {
        let fixture = fixture();
        let source_before = fs::read(
            fixture
                .source
                .join(branch_file_name(&fixture.branch_digest)),
        )
        .unwrap();
        let summary = create(&fixture);
        assert_eq!(summary.branch_count, 1);
        assert_eq!(summary.canonical_tip, fixture.branch_digest);
        assert_eq!(summary.previous_manifest_anchor, fixture.manifest_anchor);

        let archive_dir = fixture.archive_root.join(encode_hex(&summary.archive_id));
        let copied = fs::read(archive_dir.join(branch_file_name(&fixture.branch_digest))).unwrap();
        assert_eq!(copied, source_before);
        let verified = verify_qrun_v05_history_archive(
            &archive_dir,
            fixture.network_id,
            fixture.profile_fingerprint,
            fixture.genesis_tip,
            fixture.manifest_anchor,
            &fixture.params,
        )
        .unwrap();
        assert_eq!(verified, summary);
        assert_eq!(create(&fixture), summary);
        assert_eq!(
            fs::read(
                fixture
                    .source
                    .join(branch_file_name(&fixture.branch_digest))
            )
            .unwrap(),
            source_before
        );
    }

    #[test]
    fn qra1_rejects_source_branch_substitution_after_pfs2_store_open() {
        let fixture = fixture();
        let source_path = fixture
            .source
            .join(branch_file_name(&fixture.branch_digest));
        let original = fs::read(&source_path).unwrap();
        let mut substituted = original.clone();
        let mutation_offset = substituted.len() / 2;
        substituted[mutation_offset] ^= 1;
        fs::write(&source_path, substituted).unwrap();

        assert!(matches!(
            create_or_verify_qrun_v05_history_archive(
                &fixture.store,
                &fixture.archive_root,
                &fixture.params,
            ),
            Err(QRunHistoryArchiveError::BranchPayloadMismatch)
                | Err(QRunHistoryArchiveError::BranchFilenameDigestMismatch)
                | Err(QRunHistoryArchiveError::Io(_))
        ));
        assert!(fs::read_dir(&fixture.archive_root).unwrap().count() <= 1);
        fs::write(&source_path, original).unwrap();
    }

    #[test]
    fn qra1_rejects_payload_mutation_even_when_archive_descriptor_is_untouched() {
        let fixture = fixture();
        let summary = create(&fixture);
        let archive_dir = fixture.archive_root.join(encode_hex(&summary.archive_id));
        let payload_path = archive_dir.join(branch_file_name(&fixture.branch_digest));
        let mut bytes = fs::read(&payload_path).unwrap();
        let mutation_offset = bytes.len() / 2;
        bytes[mutation_offset] ^= 1;
        fs::write(&payload_path, bytes).unwrap();
        assert!(matches!(
            verify_qrun_v05_history_archive(
                &archive_dir,
                fixture.network_id,
                fixture.profile_fingerprint,
                fixture.genesis_tip,
                fixture.manifest_anchor,
                &fixture.params,
            ),
            Err(QRunHistoryArchiveError::BranchPayloadMismatch)
                | Err(QRunHistoryArchiveError::BranchFilenameDigestMismatch)
                | Err(QRunHistoryArchiveError::Io(_))
        ));
    }

    #[test]
    fn qra1_directory_publication_never_replaces_an_existing_target() {
        let temp = TestDir::new();
        let source = temp.0.join("source");
        let destination = temp.0.join("destination");
        fs::create_dir(&source).unwrap();
        fs::create_dir(&destination).unwrap();
        fs::write(source.join("complete.marker"), b"complete").unwrap();

        let result = publish_directory_no_replace(&source, &destination);
        assert!(result.is_err());
        assert!(source.join("complete.marker").exists());
        assert!(destination.exists());
        assert_eq!(fs::read_dir(&destination).unwrap().count(), 0);
    }

    #[test]
    fn qra1_rejects_archive_descriptor_checksum_mutation() {
        let fixture = fixture();
        let summary = create(&fixture);
        let archive_dir = fixture.archive_root.join(encode_hex(&summary.archive_id));
        let descriptor_path = archive_dir.join(QRA1_DESCRIPTOR_NAME);
        let mut bytes = fs::read(&descriptor_path).unwrap();
        bytes[40] ^= 1;
        fs::write(&descriptor_path, bytes).unwrap();
        assert!(matches!(
            verify_qrun_v05_history_archive(
                &archive_dir,
                fixture.network_id,
                fixture.profile_fingerprint,
                fixture.genesis_tip,
                fixture.manifest_anchor,
                &fixture.params,
            ),
            Err(QRunHistoryArchiveError::ChecksumMismatch)
        ));
    }

    #[test]
    fn qra1_rejects_unexpected_orphan_branch_in_source_without_pruning_it() {
        let fixture = fixture();
        let orphan_name = format!("branch-{}.ptb2", "ab".repeat(32));
        let orphan_path = fixture.source.join(orphan_name);
        fs::write(&orphan_path, b"orphan").unwrap();
        assert!(matches!(
            create_or_verify_qrun_v05_history_archive(
                &fixture.store,
                &fixture.archive_root,
                &fixture.params,
            ),
            Err(QRunHistoryArchiveError::UnexpectedStoreEntry)
        ));
        assert!(orphan_path.exists());
    }

    #[test]
    fn qra1_rejects_symlinked_source_branch() {
        let fixture = fixture();
        let branch_path = fixture
            .source
            .join(branch_file_name(&fixture.branch_digest));
        let original = fs::read(&branch_path).unwrap();
        let backup = fixture.source.join("branch-backup.ptb2");
        fs::rename(&branch_path, &backup).unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(&backup, &branch_path).unwrap();
        #[cfg(windows)]
        if std::os::windows::fs::symlink_file(&backup, &branch_path).is_err() {
            fs::rename(&backup, &branch_path).unwrap();
            return;
        }
        assert!(matches!(
            create_or_verify_qrun_v05_history_archive(
                &fixture.store,
                &fixture.archive_root,
                &fixture.params,
            ),
            Err(QRunHistoryArchiveError::SymlinkOrReparsePoint)
                | Err(QRunHistoryArchiveError::UnexpectedStoreEntry)
                | Err(QRunHistoryArchiveError::Io(_))
        ));
        fs::remove_file(&branch_path).unwrap();
        fs::rename(&backup, &branch_path).unwrap();
        assert_eq!(fs::read(&branch_path).unwrap(), original);
    }

    #[test]
    fn qra1_rejects_source_archive_path_overlap() {
        let fixture = fixture();
        let nested_archive_root = fixture.source.join("archives");
        fs::create_dir(&nested_archive_root).unwrap();
        assert!(matches!(
            create_or_verify_qrun_v05_history_archive(
                &fixture.store,
                &nested_archive_root,
                &fixture.params,
            ),
            Err(QRunHistoryArchiveError::PathOverlap)
        ));
    }

    #[test]
    fn qra1_rejects_a_manifest_rewritten_after_store_open_and_pending_cas_journal() {
        let fixture = fixture();
        let manifest_path = fixture.source.join(PFS2_MANIFEST_NAME);
        let mut rewritten = fixture.manifest_bytes.clone();
        // Canonical-tip begins at byte offset 102 in PFS2 v2. Keep the checksum valid so the
        // open store's replayed in-memory tip, not a corrupt checksum, detects the rewrite.
        rewritten[102] ^= 1;
        let checksum_offset = rewritten.len() - 32;
        let checksum: [u8; 32] = Sha256::digest(&rewritten[..checksum_offset]).into();
        rewritten[checksum_offset..].copy_from_slice(&checksum);
        fs::write(&manifest_path, rewritten).unwrap();
        assert!(matches!(
            create_or_verify_qrun_v05_history_archive(
                &fixture.store,
                &fixture.archive_root,
                &fixture.params,
            ),
            Err(QRunHistoryArchiveError::ManifestAnchorMismatch)
                | Err(QRunHistoryArchiveError::ManifestProfileMismatch)
        ));

        fs::write(&manifest_path, &fixture.manifest_bytes).unwrap();
        fs::write(fixture.source.join(PFS2_PENDING_NAME), b"QAP1").unwrap();
        assert!(matches!(
            create_or_verify_qrun_v05_history_archive(
                &fixture.store,
                &fixture.archive_root,
                &fixture.params,
            ),
            Err(QRunHistoryArchiveError::PendingCommitPresent)
        ));
    }
}
