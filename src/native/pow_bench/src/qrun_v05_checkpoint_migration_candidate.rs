//! Candidate-only QRM1 journal codec for live External-CAS checkpoint re-rooting.
//!
//! This module does not execute a provider CAS, publish a PFS2 manifest, copy an archive,
//! initialize QCF1, or alter node startup. It encodes and validates the exact evidence required
//! by the proposed offline migration transaction. QRM1 v2 persists the original CAS request nonce
//! so recovery can reconstruct the exact same signed-CAS operation after a crash. Runtime
//! integration remains a separate gate.

use crate::{
    consensus::ConsensusParameters,
    external_cas_anchor_candidate::{
        ExternalCasError, ExternalCasPin, ExternalCasRecord, ExternalCasWriteRequest,
        EXTERNAL_CAS_RECORD_BYTES,
    },
    private_testnet_fork_choice::PrivateTestnetForkChoice,
    private_testnet_fork_store::{
        decode_manifest, encode_manifest, manifest_anchor_commitment,
        qrun_v05_fee_checkpoint_profile_fingerprint, qrun_v05_fee_profile_fingerprint,
        PrivateTestnetForkStore, MAX_MANIFEST_BYTES,
    },
    qrun_v05_checkpoint_candidate::{QRunCheckpointError, QRunV05PowCheckpoint, MAX_QRCP_BYTES},
    qrun_v05_genesis_candidate::QRunGenesisV05,
    qrun_v05_history_archive_candidate::{QRunHistoryArchiveReplay, QRunHistoryArchiveSummary},
    state_machine::MAX_TOTAL_SUPPLY_ATOMS,
};
use sha2::{Digest, Sha256};
use std::fmt;

pub const QRM1_MAGIC: [u8; 4] = *b"QRM1";
pub const QRM1_VERSION: u16 = 2;
pub const QRM1_CHECKSUM_BYTES: usize = 32;
pub const QRM1_CHECKSUM_DOMAIN: &[u8] = b"QRUN-V05-LIVE-CAS-REBASE-JOURNAL-V2\0";
pub const QRM1_ARCHIVE_ID_DOMAIN: &[u8] = b"QRUN-V05-QRM1-HISTORY-ARCHIVE-ID-V1\0";

const FIXED_BYTES: usize = 4
    + 2
    + 2
    + 8
    + 8
    + (EXTERNAL_CAS_RECORD_BYTES * 2)
    + (32 * 8)
    + 8
    + 4
    + 4
    + 4
    + QRM1_CHECKSUM_BYTES;

/// Bound includes the exact QRCP bytes, old PFS2 manifest and new PFS2 manifest.
/// QRM1 encode/decode additionally require an opaque, fully verified QRA1 archive summary.
pub const MAX_QRM1_BYTES: usize = FIXED_BYTES + MAX_QRCP_BYTES + (MAX_MANIFEST_BYTES * 2);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QRunCheckpointMigrationError {
    Oversize,
    Malformed,
    UnsupportedVersion(u16),
    ChecksumMismatch,
    InvalidBinding,
    InvalidObjectGeneration,
    Record(ExternalCasError),
    Checkpoint(QRunCheckpointError),
    GenesisMismatch,
    ProfileMismatch,
    ManifestBindingMismatch,
    ArchiveBindingMismatch,
    HistoryReplayMismatch,
    SourceStoreMismatch,
    RandomnessUnavailable,
    GenerationOverflow,
}

impl fmt::Display for QRunCheckpointMigrationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for QRunCheckpointMigrationError {}

impl From<ExternalCasError> for QRunCheckpointMigrationError {
    fn from(value: ExternalCasError) -> Self {
        Self::Record(value)
    }
}
impl From<QRunCheckpointError> for QRunCheckpointMigrationError {
    fn from(value: QRunCheckpointError) -> Self {
        Self::Checkpoint(value)
    }
}

/// Canonical evidence record for one offline, exact-tip QFP5 manifest re-root operation.
///
/// The struct deliberately stores exact QRCP, old-manifest and new-manifest bytes. It does not
/// store historical block envelopes: those belong to the separately committed QRA1 archive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QRunCheckpointMigrationJournal {
    pub previous_record: ExternalCasRecord,
    pub next_record: ExternalCasRecord,
    pub previous_object_generation: u64,
    pub next_object_generation: u64,
    /// Exact challenge nonce persisted so crash recovery can reconstruct the identical CAS write.
    pub cas_request_nonce: [u8; 32],
    pub owner_account: [u8; 32],
    pub receipt_key_id: [u8; 32],
    pub receipt_public_key_hash: [u8; 32],
    pub checkpoint_commitment: [u8; 32],
    pub expected_parent_checkpoint_commitment: [u8; 32],
    pub minimum_checkpoint_height: u64,
    pub checkpoint_bytes: Vec<u8>,
    pub previous_manifest: Vec<u8>,
    pub next_manifest: Vec<u8>,
    pub archive_id: [u8; 32],
    pub archive_commitment: [u8; 32],
}

/// A fully validated, local-only migration preflight. Holding this value does not authorize or
/// execute a provider write; callers must re-read and verify the provider state immediately before
/// any future CAS executor uses the journal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QRunV05CheckpointMigrationPlan {
    journal: QRunCheckpointMigrationJournal,
    journal_bytes: Vec<u8>,
}

/// The only recovery actions permitted after QRM1, a fresh signed provider observation,
/// the independent QCF1 floor, and the active PFS2 manifest have all been verified.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QRunCheckpointMigrationRecoveryAction {
    /// Provider still shows the predecessor. Re-submit the byte-identical QRM1 CAS request;
    /// an old signed read alone cannot prove the earlier request is no longer in flight.
    RetryExactPreparedCas,
    /// The provider committed the exact successor; advance QCF1 before installing its manifest.
    AdvanceFloorThenInstallManifest,
    /// QCF1 already records the exact successor; install only the journal's exact next manifest.
    InstallNextManifest,
    /// Provider, floor and manifest all name the successor; verify the checkpoint store then clear QRM1.
    VerifyCommittedCheckpointStoreAndClearIntent,
    /// Any unknown, inconsistent, skipped, or impossible mixed state must be quarantined.
    Quarantine,
}

/// Classify the durable evidence matrix for a previously decoded QRM1 journal.
///
/// Callers must first verify the QRM1 checksum/domain/pin/consensus bindings, independently verify
/// its QRA1 archive, and obtain a fresh challenge-bound signed provider read plus a locked QCF1
/// snapshot. This pure classifier performs no I/O and deliberately accepts only byte-exact
/// previous/next records, object generations, and PFS2 manifests. An exact-old observation
/// maps to RetryExactPreparedCas, never an abort: the original CAS may have been delayed after
/// the read, and QRM1 preserves the nonce/operation ID for a safe idempotent retry.
pub fn classify_qrun_v05_checkpoint_migration_recovery(
    journal: &QRunCheckpointMigrationJournal,
    provider_record: &ExternalCasRecord,
    provider_object_generation: u64,
    floor_record: &ExternalCasRecord,
    floor_object_generation: u64,
    active_manifest: &[u8],
) -> QRunCheckpointMigrationRecoveryAction {
    let previous_object_generation = journal.previous_record.generation.checked_add(1);
    let next_object_generation = journal.next_record.generation.checked_add(1);
    let journal_is_consistent = journal.previous_record.validate_shape().is_ok()
        && journal
            .previous_record
            .validate_successor(&journal.next_record)
            .is_ok()
        && previous_object_generation == Some(journal.previous_object_generation)
        && next_object_generation == Some(journal.next_object_generation)
        && journal.previous_object_generation.checked_add(1)
            == Some(journal.next_object_generation)
        && !journal.cas_request_nonce.iter().all(|byte| *byte == 0)
        && !journal.archive_commitment.iter().all(|byte| *byte == 0)
        && !journal.checkpoint_bytes.is_empty()
        && QRunV05PowCheckpoint::commitment_for_bytes(&journal.checkpoint_bytes)
            == journal.checkpoint_commitment
        && manifest_anchor_commitment(&journal.previous_manifest)
            == journal.previous_record.next_state_digest
        && manifest_anchor_commitment(&journal.next_manifest)
            == journal.next_record.next_state_digest
        && journal.archive_id
            == QRunCheckpointMigrationJournal::archive_id_for_previous_manifest(
                manifest_anchor_commitment(&journal.previous_manifest),
            )
        && decode_manifest(&journal.previous_manifest).is_ok()
        && decode_manifest(&journal.next_manifest).is_ok();

    if !journal_is_consistent {
        return QRunCheckpointMigrationRecoveryAction::Quarantine;
    }

    let provider_is_previous = provider_record == &journal.previous_record
        && provider_object_generation == journal.previous_object_generation;
    let provider_is_next = provider_record == &journal.next_record
        && provider_object_generation == journal.next_object_generation;
    let floor_is_previous = floor_record == &journal.previous_record
        && floor_object_generation == journal.previous_object_generation;
    let floor_is_next = floor_record == &journal.next_record
        && floor_object_generation == journal.next_object_generation;
    let manifest_is_previous = active_manifest == journal.previous_manifest;
    let manifest_is_next = active_manifest == journal.next_manifest;

    match (
        provider_is_previous,
        provider_is_next,
        floor_is_previous,
        floor_is_next,
        manifest_is_previous,
        manifest_is_next,
    ) {
        (true, false, true, false, true, false) => {
            QRunCheckpointMigrationRecoveryAction::RetryExactPreparedCas
        }
        (false, true, true, false, true, false) => {
            QRunCheckpointMigrationRecoveryAction::AdvanceFloorThenInstallManifest
        }
        (false, true, false, true, true, false) => {
            QRunCheckpointMigrationRecoveryAction::InstallNextManifest
        }
        (false, true, false, true, false, true) => {
            QRunCheckpointMigrationRecoveryAction::VerifyCommittedCheckpointStoreAndClearIntent
        }
        _ => QRunCheckpointMigrationRecoveryAction::Quarantine,
    }
}

impl QRunV05CheckpointMigrationPlan {
    pub fn journal(&self) -> &QRunCheckpointMigrationJournal {
        &self.journal
    }

    /// Canonical QRM1 v2 bytes suitable for durable local journal publication.
    pub fn journal_bytes(&self) -> &[u8] {
        &self.journal_bytes
    }

    pub fn external_cas_write_request(
        &self,
        pin: &ExternalCasPin,
    ) -> Result<ExternalCasWriteRequest, QRunCheckpointMigrationError> {
        self.journal.external_cas_write_request(pin)
    }
}

/// Build a local-only exact-tip migration intent from a replay-validated Genesis-rooted PFS2 store
/// and a QRA1 archive that has already been fully verified. No provider CAS, QCF1 floor advance,
/// or PFS2 manifest write occurs here. previous_record and its object generation must come from
/// independently trusted state (for example, the pinned QCF1 floor); a future executor must still
/// perform a fresh signed provider read and compare it exactly before attempting the CAS.
#[allow(clippy::too_many_arguments)]
/// Build a local-only exact-tip migration plan only from a completely replayed QRA1 archive.
/// The supplied replay witness binds every archived branch to the original wallet Genesis,
/// QFP5 execution rules, exact canonical tip and byte-identical QRCP checkpoint.
#[allow(clippy::too_many_arguments)]
pub fn prepare_qrun_v05_checkpoint_migration(
    source_store: &PrivateTestnetForkStore,
    replay: &QRunHistoryArchiveReplay,
    owner_account: [u8; 32],
    params: &ConsensusParameters,
    pin: &ExternalCasPin,
    previous_record: ExternalCasRecord,
    previous_object_generation: u64,
    expected_parent_checkpoint_commitment: [u8; 32],
) -> Result<QRunV05CheckpointMigrationPlan, QRunCheckpointMigrationError> {
    let plan = prepare_qrun_v05_checkpoint_migration_from_archive(
        source_store,
        replay.summary(),
        owner_account,
        params,
        pin,
        previous_record,
        previous_object_generation,
        expected_parent_checkpoint_commitment,
    )?;
    plan.journal()
        .validate_replayed_history(pin, params, replay)?;
    Ok(plan)
}

pub(crate) fn prepare_qrun_v05_checkpoint_migration_from_archive(
    source_store: &PrivateTestnetForkStore,
    archive: &QRunHistoryArchiveSummary,
    owner_account: [u8; 32],
    params: &ConsensusParameters,
    pin: &ExternalCasPin,
    previous_record: ExternalCasRecord,
    previous_object_generation: u64,
    expected_parent_checkpoint_commitment: [u8; 32],
) -> Result<QRunV05CheckpointMigrationPlan, QRunCheckpointMigrationError> {
    pin.validate()?;
    params
        .validate()
        .map_err(|_| QRunCheckpointMigrationError::ProfileMismatch)?;

    let genesis = QRunGenesisV05::new(pin.network_id, owner_account)
        .map_err(|_| QRunCheckpointMigrationError::GenesisMismatch)?;
    if genesis.commitment() != pin.genesis_digest
        || genesis.ledger() != source_store.genesis_state()
        || !source_store.matches_qrun_v05_genesis_and_profile(genesis.ledger(), params)
    {
        return Err(QRunCheckpointMigrationError::GenesisMismatch);
    }

    let (_, network_id, profile_fingerprint, genesis_tip, manifest_anchor) = source_store
        .qrun_v05_history_archive_identity()
        .map_err(|_| QRunCheckpointMigrationError::SourceStoreMismatch)?;
    let previous_manifest = archive.previous_manifest_bytes();
    let old_manifest = decode_manifest(previous_manifest)
        .map_err(|_| QRunCheckpointMigrationError::ManifestBindingMismatch)?;
    let source_entries = source_store
        .qrun_v05_history_archive_entries()
        .map_err(|_| QRunCheckpointMigrationError::SourceStoreMismatch)?;
    let source_digests: Vec<[u8; 32]> = source_entries
        .iter()
        .map(|(digest, _, _)| *digest)
        .collect();

    if network_id != pin.network_id
        || archive.network_id != network_id
        || archive.profile_fingerprint != profile_fingerprint
        || archive.genesis_tip != genesis_tip
        || archive.previous_manifest_anchor != manifest_anchor
        || manifest_anchor_commitment(previous_manifest) != manifest_anchor
        || archive.canonical_tip != source_store.canonical_tip()
        || archive.branch_count as usize != old_manifest.digests.len()
        || old_manifest.network_id != network_id
        || old_manifest.profile_fingerprint != profile_fingerprint
        || old_manifest.genesis_tip != genesis_tip
        || old_manifest.canonical_tip != archive.canonical_tip
        || old_manifest.digests != source_digests
    {
        return Err(QRunCheckpointMigrationError::ArchiveBindingMismatch);
    }

    previous_record.validate_shape()?;
    if previous_record.provider_id != pin.provider_id
        || previous_record.network_id != pin.network_id
        || previous_record.genesis_digest != pin.genesis_digest
        || previous_record.next_state_digest != manifest_anchor
        || previous_object_generation == 0
        || previous_record.generation.checked_add(1) != Some(previous_object_generation)
    {
        return Err(QRunCheckpointMigrationError::InvalidBinding);
    }

    let checkpoint = QRunV05PowCheckpoint::capture(
        pin.network_id,
        pin.genesis_digest,
        params,
        source_store.archive().canonical_chain(),
        expected_parent_checkpoint_commitment,
    )?;
    if checkpoint.height == 0 || checkpoint.consensus_tip_digest != archive.canonical_tip {
        return Err(QRunCheckpointMigrationError::ManifestBindingMismatch);
    }
    let minimum_checkpoint_height = checkpoint.height;
    let checkpoint_bytes = checkpoint.encode(params)?;
    let checkpoint_commitment = checkpoint.commitment(params)?;
    let checkpoint_base = QRunV05PowCheckpoint::restore_chain_anchored(
        &checkpoint_bytes,
        &pin.network_id,
        &pin.genesis_digest,
        params,
        checkpoint_commitment,
        minimum_checkpoint_height,
    )?;
    let checkpoint_profile = qrun_v05_fee_checkpoint_profile_fingerprint(
        checkpoint_base.state(),
        params,
        checkpoint_commitment,
    )
    .map_err(|_| QRunCheckpointMigrationError::ProfileMismatch)?;
    let next_manifest = encode_manifest(
        &pin.network_id,
        &checkpoint_profile,
        &checkpoint.consensus_tip_digest,
        &checkpoint.consensus_tip_digest,
        &[],
    )
    .map_err(|_| QRunCheckpointMigrationError::ManifestBindingMismatch)?;

    let next_generation = previous_record
        .generation
        .checked_add(1)
        .ok_or(QRunCheckpointMigrationError::GenerationOverflow)?;
    let next_object_generation = previous_object_generation
        .checked_add(1)
        .ok_or(QRunCheckpointMigrationError::GenerationOverflow)?;
    let operation_id = migration_random_nonzero_digest()?;
    let cas_request_nonce = migration_random_nonzero_digest()?;
    let next_record = ExternalCasRecord {
        generation: next_generation,
        provider_id: pin.provider_id,
        network_id: pin.network_id,
        genesis_digest: pin.genesis_digest,
        previous_record_digest: previous_record.digest()?,
        previous_state_digest: previous_record.next_state_digest,
        next_state_digest: manifest_anchor_commitment(&next_manifest),
        operation_id,
        request_digest: [0xA5; 32],
    };
    let mut write_request = ExternalCasWriteRequest {
        request_nonce: cas_request_nonce,
        operation_id,
        request_digest: [0xA5; 32],
        expected_generation: previous_record.generation,
        expected_object_generation: previous_object_generation,
        expected_record_digest: previous_record.digest()?,
        expected_state_digest: previous_record.next_state_digest,
        next_record,
    };
    write_request.bind_request_digest(pin)?;

    let receipt_public_key_hash: [u8; 32] = Sha256::digest(pin.receipt_public_key).into();
    let journal = QRunCheckpointMigrationJournal {
        previous_record,
        next_record: write_request.next_record.clone(),
        previous_object_generation,
        next_object_generation,
        cas_request_nonce,
        owner_account,
        receipt_key_id: pin.receipt_key_id,
        receipt_public_key_hash,
        checkpoint_commitment,
        expected_parent_checkpoint_commitment,
        minimum_checkpoint_height,
        checkpoint_bytes,
        previous_manifest: previous_manifest.to_vec(),
        next_manifest,
        archive_id: archive.archive_id,
        archive_commitment: archive.archive_commitment,
    };
    let journal_bytes = journal.encode(pin, params, archive)?;
    let decoded = QRunCheckpointMigrationJournal::decode(&journal_bytes, pin, params, archive)?;
    if decoded != journal {
        return Err(QRunCheckpointMigrationError::Malformed);
    }

    Ok(QRunV05CheckpointMigrationPlan {
        journal,
        journal_bytes,
    })
}

fn migration_random_nonzero_digest() -> Result<[u8; 32], QRunCheckpointMigrationError> {
    for _ in 0..4 {
        let mut value = [0u8; 32];
        getrandom::getrandom(&mut value)
            .map_err(|_| QRunCheckpointMigrationError::RandomnessUnavailable)?;
        if value.iter().any(|byte| *byte != 0) {
            return Ok(value);
        }
    }
    Err(QRunCheckpointMigrationError::RandomnessUnavailable)
}

impl QRunCheckpointMigrationJournal {
    /// Prove that this journal's exact QRCP bytes are the canonical checkpoint of a fully
    /// replayed QRA1 history. The replay witness is produced only by the QRA1 full-history replay
    /// API, which executes every archived QFP5 branch from the original wallet-bound Genesis.
    pub fn validate_replayed_history(
        &self,
        pin: &ExternalCasPin,
        params: &ConsensusParameters,
        replay: &QRunHistoryArchiveReplay,
    ) -> Result<(), QRunCheckpointMigrationError> {
        self.validate(pin, params, replay.summary())?;
        let previous_manifest = decode_manifest(&self.previous_manifest)
            .map_err(|_| QRunCheckpointMigrationError::ManifestBindingMismatch)?;
        let replayed = replay.replayed_archive();
        if replay.summary().network_id() != &pin.network_id
            || replay.genesis_commitment() != &pin.genesis_digest
            || replay.summary().profile_fingerprint() != &previous_manifest.profile_fingerprint
            || replay.summary().genesis_tip() != &previous_manifest.genesis_tip
            || replay.summary().canonical_tip() != &previous_manifest.canonical_tip
            || replayed.genesis_tip() != previous_manifest.genesis_tip
            || replayed.archive_len() != previous_manifest.digests.len()
            || replay.canonical_tip() != previous_manifest.canonical_tip
            || replay.canonical_height() != self.minimum_checkpoint_height
        {
            return Err(QRunCheckpointMigrationError::HistoryReplayMismatch);
        }

        let rebuilt = QRunV05PowCheckpoint::capture(
            pin.network_id,
            pin.genesis_digest,
            params,
            replayed.canonical_chain(),
            self.expected_parent_checkpoint_commitment,
        )?;
        let rebuilt_bytes = rebuilt.encode(params)?;
        if rebuilt_bytes != self.checkpoint_bytes
            || rebuilt.commitment(params)? != self.checkpoint_commitment
        {
            return Err(QRunCheckpointMigrationError::HistoryReplayMismatch);
        }
        Ok(())
    }

    /// Derive the archive directory identifier from the old PFS2 manifest anchor.
    pub fn archive_id_for_previous_manifest(previous_manifest_anchor: [u8; 32]) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(QRM1_ARCHIVE_ID_DOMAIN);
        hash.update(previous_manifest_anchor);
        hash.finalize().into()
    }

    /// Reconstruct the exact immutable CAS request from the persisted journal. This includes the
    /// original nonce; generating a fresh nonce would change the request digest and would not be
    /// an idempotent retry of the original operation.
    pub fn external_cas_write_request(
        &self,
        pin: &ExternalCasPin,
    ) -> Result<ExternalCasWriteRequest, QRunCheckpointMigrationError> {
        let request = ExternalCasWriteRequest {
            request_nonce: self.cas_request_nonce,
            operation_id: self.next_record.operation_id,
            request_digest: self.next_record.request_digest,
            expected_generation: self.previous_record.generation,
            expected_object_generation: self.previous_object_generation,
            expected_record_digest: self.previous_record.digest()?,
            expected_state_digest: self.previous_record.next_state_digest,
            next_record: self.next_record.clone(),
        };
        request.validate(pin)?;
        if request.calculate_request_digest(pin)? != self.next_record.request_digest {
            return Err(QRunCheckpointMigrationError::InvalidBinding);
        }
        Ok(request)
    }

    /// Validate all self-contained QRM1 bindings against an independently configured CAS pin
    /// and the selected QRun v0.5 consensus parameters. This lower-level check deliberately does
    /// not establish that the referenced QRA1 archive exists or matches the claimed commitment.
    fn validate_without_archive(
        &self,
        pin: &ExternalCasPin,
        params: &ConsensusParameters,
    ) -> Result<(), QRunCheckpointMigrationError> {
        pin.validate()?;
        params
            .validate()
            .map_err(|_| QRunCheckpointMigrationError::ProfileMismatch)?;

        self.previous_record.validate_shape()?;
        self.previous_record.validate_successor(&self.next_record)?;

        if self.previous_object_generation == 0
            || self.previous_object_generation.checked_add(1) != Some(self.next_object_generation)
            || self.previous_record.generation.checked_add(1)
                != Some(self.previous_object_generation)
            || self.next_record.generation.checked_add(1) != Some(self.next_object_generation)
        {
            return Err(QRunCheckpointMigrationError::InvalidObjectGeneration);
        }
        if self.cas_request_nonce.iter().all(|byte| *byte == 0)
            || self.owner_account.iter().all(|byte| *byte == 0)
            || self.receipt_key_id.iter().all(|byte| *byte == 0)
            || self.receipt_public_key_hash.iter().all(|byte| *byte == 0)
            || self.checkpoint_commitment.iter().all(|byte| *byte == 0)
            || self
                .expected_parent_checkpoint_commitment
                .iter()
                .all(|byte| *byte == 0)
            || self.minimum_checkpoint_height == 0
            || self.archive_id.iter().all(|byte| *byte == 0)
            || self.archive_commitment.iter().all(|byte| *byte == 0)
        {
            return Err(QRunCheckpointMigrationError::InvalidBinding);
        }

        if self.previous_record.provider_id != pin.provider_id
            || self.next_record.provider_id != pin.provider_id
            || self.previous_record.network_id != pin.network_id
            || self.next_record.network_id != pin.network_id
            || self.previous_record.genesis_digest != pin.genesis_digest
            || self.next_record.genesis_digest != pin.genesis_digest
            || self.receipt_key_id != pin.receipt_key_id
        {
            return Err(QRunCheckpointMigrationError::InvalidBinding);
        }
        self.external_cas_write_request(pin)?;

        let expected_key_hash: [u8; 32] = Sha256::digest(pin.receipt_public_key).into();
        if expected_key_hash != self.receipt_public_key_hash {
            return Err(QRunCheckpointMigrationError::InvalidBinding);
        }

        let genesis = QRunGenesisV05::new(pin.network_id, self.owner_account)
            .map_err(|_| QRunCheckpointMigrationError::GenesisMismatch)?;
        if genesis.commitment() != pin.genesis_digest {
            return Err(QRunCheckpointMigrationError::GenesisMismatch);
        }

        if self.checkpoint_bytes.is_empty()
            || self.checkpoint_bytes.len() > MAX_QRCP_BYTES
            || self.previous_manifest.is_empty()
            || self.previous_manifest.len() > MAX_MANIFEST_BYTES
            || self.next_manifest.is_empty()
            || self.next_manifest.len() > MAX_MANIFEST_BYTES
        {
            return Err(QRunCheckpointMigrationError::Oversize);
        }

        if QRunV05PowCheckpoint::commitment_for_bytes(&self.checkpoint_bytes)
            != self.checkpoint_commitment
        {
            return Err(QRunCheckpointMigrationError::Checkpoint(
                QRunCheckpointError::CommitmentMismatch,
            ));
        }
        let checkpoint = QRunV05PowCheckpoint::decode_anchored_with_parent(
            &self.checkpoint_bytes,
            &pin.network_id,
            &pin.genesis_digest,
            params,
            self.checkpoint_commitment,
            self.minimum_checkpoint_height,
            self.expected_parent_checkpoint_commitment,
        )?;
        if checkpoint.height == 0
            || checkpoint.total_supply_atoms != MAX_TOTAL_SUPPLY_ATOMS
            || checkpoint.genesis_commitment != pin.genesis_digest
        {
            return Err(QRunCheckpointMigrationError::InvalidBinding);
        }

        let old_manifest_anchor = manifest_anchor_commitment(&self.previous_manifest);
        let new_manifest_anchor = manifest_anchor_commitment(&self.next_manifest);
        if old_manifest_anchor != self.previous_record.next_state_digest
            || new_manifest_anchor != self.next_record.next_state_digest
            || self.archive_id != Self::archive_id_for_previous_manifest(old_manifest_anchor)
        {
            return Err(QRunCheckpointMigrationError::ManifestBindingMismatch);
        }

        let old_manifest = decode_manifest(&self.previous_manifest)
            .map_err(|_| QRunCheckpointMigrationError::ManifestBindingMismatch)?;
        let new_manifest = decode_manifest(&self.next_manifest)
            .map_err(|_| QRunCheckpointMigrationError::ManifestBindingMismatch)?;

        let legacy_profile = qrun_v05_fee_profile_fingerprint(genesis.ledger(), params)
            .map_err(|_| QRunCheckpointMigrationError::ProfileMismatch)?;
        let genesis_archive = PrivateTestnetForkChoice::new_qrun_v05_fee_only(
            genesis.ledger().clone(),
            params.clone(),
        )
        .map_err(|_| QRunCheckpointMigrationError::ProfileMismatch)?;
        let checkpoint_base = QRunV05PowCheckpoint::restore_chain_anchored(
            &self.checkpoint_bytes,
            &pin.network_id,
            &pin.genesis_digest,
            params,
            self.checkpoint_commitment,
            self.minimum_checkpoint_height,
        )?;
        let checkpoint_profile = qrun_v05_fee_checkpoint_profile_fingerprint(
            checkpoint_base.state(),
            params,
            self.checkpoint_commitment,
        )
        .map_err(|_| QRunCheckpointMigrationError::ProfileMismatch)?;

        if old_manifest.network_id != pin.network_id
            || old_manifest.profile_fingerprint != legacy_profile
            || old_manifest.genesis_tip != genesis_archive.genesis_tip()
            || old_manifest.canonical_tip != checkpoint.consensus_tip_digest
            || !old_manifest
                .digests
                .contains(&checkpoint.consensus_tip_digest)
            || new_manifest.network_id != pin.network_id
            || new_manifest.profile_fingerprint != checkpoint_profile
            || new_manifest.genesis_tip != checkpoint.consensus_tip_digest
            || new_manifest.canonical_tip != checkpoint.consensus_tip_digest
            || !new_manifest.digests.is_empty()
            || checkpoint_base.chain_tip().tip_hash != checkpoint.consensus_tip_digest
        {
            return Err(QRunCheckpointMigrationError::ManifestBindingMismatch);
        }

        Ok(())
    }

    /// Bind this journal to a QRA1 summary returned by the archive create/verify APIs. The summary
    /// carries an unforgeable verification seal and immutable bindings; a caller cannot substitute
    /// a hand-built or edited set of archive metadata.
    pub fn validate(
        &self,
        pin: &ExternalCasPin,
        params: &ConsensusParameters,
        archive: &QRunHistoryArchiveSummary,
    ) -> Result<(), QRunCheckpointMigrationError> {
        self.validate_without_archive(pin, params)?;
        self.validate_archive_binding(archive)
    }

    fn validate_archive_binding(
        &self,
        archive: &QRunHistoryArchiveSummary,
    ) -> Result<(), QRunCheckpointMigrationError> {
        let old_manifest = decode_manifest(&self.previous_manifest)
            .map_err(|_| QRunCheckpointMigrationError::ManifestBindingMismatch)?;
        if archive.archive_id != self.archive_id
            || archive.archive_commitment != self.archive_commitment
            || archive.previous_manifest_bytes() != self.previous_manifest
            || archive.previous_manifest_anchor
                != manifest_anchor_commitment(&self.previous_manifest)
            || archive.network_id != old_manifest.network_id
            || archive.profile_fingerprint != old_manifest.profile_fingerprint
            || archive.genesis_tip != old_manifest.genesis_tip
            || archive.canonical_tip != old_manifest.canonical_tip
            || archive.branch_count as usize != old_manifest.digests.len()
        {
            return Err(QRunCheckpointMigrationError::ArchiveBindingMismatch);
        }
        Ok(())
    }

    /// Encode a canonical, bounded QRM1 record only after the referenced QRA1 archive has been
    /// independently verified and its opaque summary has been bound to this journal.
    pub fn encode(
        &self,
        pin: &ExternalCasPin,
        params: &ConsensusParameters,
        archive: &QRunHistoryArchiveSummary,
    ) -> Result<Vec<u8>, QRunCheckpointMigrationError> {
        self.validate(pin, params, archive)?;
        self.encode_without_archive(pin, params)
    }

    fn encode_without_archive(
        &self,
        pin: &ExternalCasPin,
        params: &ConsensusParameters,
    ) -> Result<Vec<u8>, QRunCheckpointMigrationError> {
        self.validate_without_archive(pin, params)?;

        let previous = self.previous_record.encode()?;
        let next = self.next_record.encode()?;
        let checkpoint_len = u32::try_from(self.checkpoint_bytes.len())
            .map_err(|_| QRunCheckpointMigrationError::Oversize)?;
        let previous_manifest_len = u32::try_from(self.previous_manifest.len())
            .map_err(|_| QRunCheckpointMigrationError::Oversize)?;
        let next_manifest_len = u32::try_from(self.next_manifest.len())
            .map_err(|_| QRunCheckpointMigrationError::Oversize)?;

        let mut bytes = Vec::with_capacity(
            FIXED_BYTES
                + self.checkpoint_bytes.len()
                + self.previous_manifest.len()
                + self.next_manifest.len(),
        );
        bytes.extend_from_slice(&QRM1_MAGIC);
        bytes.extend_from_slice(&QRM1_VERSION.to_be_bytes());
        bytes.extend_from_slice(&0u16.to_be_bytes());
        bytes.extend_from_slice(&self.previous_object_generation.to_be_bytes());
        bytes.extend_from_slice(&self.next_object_generation.to_be_bytes());
        bytes.extend_from_slice(&self.cas_request_nonce);
        bytes.extend_from_slice(&previous);
        bytes.extend_from_slice(&next);
        bytes.extend_from_slice(&self.owner_account);
        bytes.extend_from_slice(&self.receipt_key_id);
        bytes.extend_from_slice(&self.receipt_public_key_hash);
        bytes.extend_from_slice(&self.checkpoint_commitment);
        bytes.extend_from_slice(&self.expected_parent_checkpoint_commitment);
        bytes.extend_from_slice(&self.minimum_checkpoint_height.to_be_bytes());
        bytes.extend_from_slice(&self.archive_id);
        bytes.extend_from_slice(&self.archive_commitment);
        bytes.extend_from_slice(&checkpoint_len.to_be_bytes());
        bytes.extend_from_slice(&self.checkpoint_bytes);
        bytes.extend_from_slice(&previous_manifest_len.to_be_bytes());
        bytes.extend_from_slice(&self.previous_manifest);
        bytes.extend_from_slice(&next_manifest_len.to_be_bytes());
        bytes.extend_from_slice(&self.next_manifest);

        if bytes.len().saturating_add(QRM1_CHECKSUM_BYTES) > MAX_QRM1_BYTES {
            return Err(QRunCheckpointMigrationError::Oversize);
        }
        let mut checksum_preimage = Vec::with_capacity(QRM1_CHECKSUM_DOMAIN.len() + bytes.len());
        checksum_preimage.extend_from_slice(QRM1_CHECKSUM_DOMAIN);
        checksum_preimage.extend_from_slice(&bytes);
        bytes.extend_from_slice(&Sha256::digest(&checksum_preimage));
        Ok(bytes)
    }

    /// Decode a complete canonical QRM1 journal and require its archive commitment to match a
    /// separately verified QRA1 archive. The opaque summary must come from QRA1 create/verify.
    pub fn decode(
        bytes: &[u8],
        pin: &ExternalCasPin,
        params: &ConsensusParameters,
        archive: &QRunHistoryArchiveSummary,
    ) -> Result<Self, QRunCheckpointMigrationError> {
        let journal = Self::decode_without_archive(bytes, pin, params)?;
        journal.validate_archive_binding(archive)?;
        Ok(journal)
    }

    fn decode_without_archive(
        bytes: &[u8],
        pin: &ExternalCasPin,
        params: &ConsensusParameters,
    ) -> Result<Self, QRunCheckpointMigrationError> {
        if bytes.len() > MAX_QRM1_BYTES || bytes.len() < FIXED_BYTES {
            return Err(QRunCheckpointMigrationError::Oversize);
        }
        if bytes.get(..4) != Some(QRM1_MAGIC.as_slice()) {
            return Err(QRunCheckpointMigrationError::Malformed);
        }
        let version = u16::from_be_bytes(
            bytes
                .get(4..6)
                .ok_or(QRunCheckpointMigrationError::Malformed)?
                .try_into()
                .map_err(|_| QRunCheckpointMigrationError::Malformed)?,
        );
        if version != QRM1_VERSION {
            return Err(QRunCheckpointMigrationError::UnsupportedVersion(version));
        }
        if take_u16(bytes, 6)? != 0 {
            return Err(QRunCheckpointMigrationError::Malformed);
        }

        let checksum_offset = bytes
            .len()
            .checked_sub(QRM1_CHECKSUM_BYTES)
            .ok_or(QRunCheckpointMigrationError::Malformed)?;
        let mut checksum_preimage =
            Vec::with_capacity(QRM1_CHECKSUM_DOMAIN.len() + checksum_offset);
        checksum_preimage.extend_from_slice(QRM1_CHECKSUM_DOMAIN);
        checksum_preimage.extend_from_slice(&bytes[..checksum_offset]);
        if Sha256::digest(&checksum_preimage).as_slice() != &bytes[checksum_offset..] {
            return Err(QRunCheckpointMigrationError::ChecksumMismatch);
        }

        let payload = &bytes[..checksum_offset];
        let mut cursor = 8usize;
        let previous_object_generation = take_u64(payload, &mut cursor)?;
        let next_object_generation = take_u64(payload, &mut cursor)?;
        let cas_request_nonce = take_array::<32>(payload, &mut cursor)?;
        let previous_record = ExternalCasRecord::decode(take_slice(
            payload,
            &mut cursor,
            EXTERNAL_CAS_RECORD_BYTES,
        )?)?;
        let next_record = ExternalCasRecord::decode(take_slice(
            payload,
            &mut cursor,
            EXTERNAL_CAS_RECORD_BYTES,
        )?)?;
        let owner_account = take_array::<32>(payload, &mut cursor)?;
        let receipt_key_id = take_array::<32>(payload, &mut cursor)?;
        let receipt_public_key_hash = take_array::<32>(payload, &mut cursor)?;
        let checkpoint_commitment = take_array::<32>(payload, &mut cursor)?;
        let expected_parent_checkpoint_commitment = take_array::<32>(payload, &mut cursor)?;
        let minimum_checkpoint_height = take_u64(payload, &mut cursor)?;
        let archive_id = take_array::<32>(payload, &mut cursor)?;
        let archive_commitment = take_array::<32>(payload, &mut cursor)?;

        let checkpoint_len = take_u32(payload, &mut cursor)? as usize;
        if checkpoint_len == 0 || checkpoint_len > MAX_QRCP_BYTES {
            return Err(QRunCheckpointMigrationError::Oversize);
        }
        let checkpoint_bytes = take_slice(payload, &mut cursor, checkpoint_len)?.to_vec();

        let previous_manifest_len = take_u32(payload, &mut cursor)? as usize;
        if previous_manifest_len == 0 || previous_manifest_len > MAX_MANIFEST_BYTES {
            return Err(QRunCheckpointMigrationError::Oversize);
        }
        let previous_manifest = take_slice(payload, &mut cursor, previous_manifest_len)?.to_vec();

        let next_manifest_len = take_u32(payload, &mut cursor)? as usize;
        if next_manifest_len == 0 || next_manifest_len > MAX_MANIFEST_BYTES {
            return Err(QRunCheckpointMigrationError::Oversize);
        }
        let next_manifest = take_slice(payload, &mut cursor, next_manifest_len)?.to_vec();

        if cursor != payload.len() {
            return Err(QRunCheckpointMigrationError::Malformed);
        }

        let journal = Self {
            previous_record,
            next_record,
            previous_object_generation,
            next_object_generation,
            cas_request_nonce,
            owner_account,
            receipt_key_id,
            receipt_public_key_hash,
            checkpoint_commitment,
            expected_parent_checkpoint_commitment,
            minimum_checkpoint_height,
            checkpoint_bytes,
            previous_manifest,
            next_manifest,
            archive_id,
            archive_commitment,
        };
        journal.validate_without_archive(pin, params)?;
        let canonical = journal.encode_without_archive(pin, params)?;
        if canonical.as_slice() != bytes {
            return Err(QRunCheckpointMigrationError::Malformed);
        }
        Ok(journal)
    }
}

fn take_slice<'a>(
    bytes: &'a [u8],
    cursor: &mut usize,
    length: usize,
) -> Result<&'a [u8], QRunCheckpointMigrationError> {
    let end = cursor
        .checked_add(length)
        .ok_or(QRunCheckpointMigrationError::Malformed)?;
    if end > bytes.len() {
        return Err(QRunCheckpointMigrationError::Malformed);
    }
    let part = bytes
        .get(*cursor..end)
        .ok_or(QRunCheckpointMigrationError::Malformed)?;
    *cursor = end;
    Ok(part)
}

fn take_array<const N: usize>(
    bytes: &[u8],
    cursor: &mut usize,
) -> Result<[u8; N], QRunCheckpointMigrationError> {
    take_slice(bytes, cursor, N)?
        .try_into()
        .map_err(|_| QRunCheckpointMigrationError::Malformed)
}

fn take_u16(bytes: &[u8], offset: usize) -> Result<u16, QRunCheckpointMigrationError> {
    let end = offset
        .checked_add(2)
        .ok_or(QRunCheckpointMigrationError::Malformed)?;
    let value = bytes
        .get(offset..end)
        .ok_or(QRunCheckpointMigrationError::Malformed)?;
    Ok(u16::from_be_bytes(
        value
            .try_into()
            .map_err(|_| QRunCheckpointMigrationError::Malformed)?,
    ))
}

fn take_u32(bytes: &[u8], cursor: &mut usize) -> Result<u32, QRunCheckpointMigrationError> {
    Ok(u32::from_be_bytes(take_array::<4>(bytes, cursor)?))
}

fn take_u64(bytes: &[u8], cursor: &mut usize) -> Result<u64, QRunCheckpointMigrationError> {
    Ok(u64::from_be_bytes(take_array::<8>(bytes, cursor)?))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::{
        consensus::Uint256,
        private_testnet_fork_store::encode_manifest,
        qrun_v05_fee_pow_wire_candidate::encode_qrun_v05_fee_pow_block,
        state_machine::{Block, QRunV05FeeBlock, TransactionAuthenticator},
    };

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
                source_id: "qrm1-test-clock",
            })
        }
    }

    fn test_profile() -> ConsensusParameters {
        let mut params = ConsensusParameters::candidate_testnet().unwrap();
        params.protocol_version = 5;
        params.target_block_time_secs = 1;
        params.initial_target = Uint256::MAX;
        params.pow_limit = Uint256::MAX;
        params.pow.memory_kib = 8 * 1024;
        params.pow.iterations = 1;
        params
    }

    pub(crate) fn fixture() -> (
        QRunCheckpointMigrationJournal,
        ExternalCasPin,
        ConsensusParameters,
    ) {
        let params = test_profile();
        let owner = [0x2A; 32];
        let genesis_candidate = QRunGenesisV05::new([0x51; 32], owner).unwrap();
        let genesis = genesis_candidate.ledger().clone();
        let genesis_commitment = genesis_candidate.commitment();

        let mut genesis_archive =
            PrivateTestnetForkChoice::new_qrun_v05_fee_only(genesis.clone(), params.clone())
                .unwrap();
        let chain = genesis_archive.canonical_chain().clone();

        let fee_block = QRunV05FeeBlock {
            body: Block {
                height: 1,
                timestamp: 100,
                parent_hash: chain.state().tip_hash(),
                state_root: [0; 32],
                transactions: Vec::new(),
            },
            producer: [0x77; 32],
        };
        let mut fee_block = fee_block;
        fee_block.body.state_root = chain
            .state()
            .preview_qrun_v05_fee_state_root_after(&fee_block, &RejectAllAuthenticator)
            .unwrap();
        let header = crate::consensus::PowHeader {
            protocol_version: params.protocol_version,
            network_id: chain.state().network_id(),
            height: 1,
            timestamp: 100,
            parent_hash: chain.state().tip_hash(),
            previous_consensus_hash: chain.chain_tip().tip_hash,
            state_root: crate::qrun_v05_fee_pow_wire_candidate::qrun_v05_fee_pow_state_commitment(
                &fee_block,
            )
            .unwrap(),
            target: params.initial_target,
            nonce: 0,
        };
        let envelope = encode_qrun_v05_fee_pow_block(&header, &fee_block).unwrap();
        genesis_archive
            .insert_encoded(&envelope, &RejectAllAuthenticator, &FixedClock)
            .unwrap();

        let checkpoint_chain = genesis_archive.canonical_chain().clone();
        let checkpoint = QRunV05PowCheckpoint::capture(
            genesis.network_id(),
            genesis_commitment,
            &params,
            &checkpoint_chain,
            [0xC7; 32],
        )
        .unwrap();
        let checkpoint_bytes = checkpoint.encode(&params).unwrap();
        let checkpoint_commitment = QRunV05PowCheckpoint::commitment_for_bytes(&checkpoint_bytes);

        let legacy_profile = qrun_v05_fee_profile_fingerprint(&genesis, &params).unwrap();
        let old_genesis_archive =
            PrivateTestnetForkChoice::new_qrun_v05_fee_only(genesis.clone(), params.clone())
                .unwrap();
        let old_manifest = encode_manifest(
            &genesis.network_id(),
            &legacy_profile,
            &old_genesis_archive.genesis_tip(),
            &checkpoint.consensus_tip_digest,
            &[checkpoint.consensus_tip_digest],
        )
        .unwrap();

        let checkpoint_base = QRunV05PowCheckpoint::restore_chain_anchored(
            &checkpoint_bytes,
            &genesis.network_id(),
            &genesis_commitment,
            &params,
            checkpoint_commitment,
            1,
        )
        .unwrap();
        let checkpoint_profile = qrun_v05_fee_checkpoint_profile_fingerprint(
            checkpoint_base.state(),
            &params,
            checkpoint_commitment,
        )
        .unwrap();
        let new_manifest = encode_manifest(
            &genesis.network_id(),
            &checkpoint_profile,
            &checkpoint.consensus_tip_digest,
            &checkpoint.consensus_tip_digest,
            &[],
        )
        .unwrap();

        let provider_id = [0x31; 32];
        let receipt_key_id = [0x32; 32];
        let receipt_public_key = [0x33; crate::v4_fat1_trust_candidate::ML_DSA_65_PUBLIC_KEY_BYTES];
        let pin = ExternalCasPin {
            provider_id,
            network_id: genesis.network_id(),
            genesis_digest: genesis_commitment,
            receipt_key_id,
            receipt_public_key,
        };

        let previous_manifest_anchor = manifest_anchor_commitment(&old_manifest);
        let previous_record = ExternalCasRecord {
            generation: 7,
            provider_id,
            network_id: genesis.network_id(),
            genesis_digest: genesis_commitment,
            previous_record_digest: [0x41; 32],
            previous_state_digest: [0x42; 32],
            next_state_digest: previous_manifest_anchor,
            operation_id: [0x43; 32],
            request_digest: [0x44; 32],
        };
        let next_record = ExternalCasRecord {
            generation: 8,
            provider_id,
            network_id: genesis.network_id(),
            genesis_digest: genesis_commitment,
            previous_record_digest: previous_record.digest().unwrap(),
            previous_state_digest: previous_record.next_state_digest,
            next_state_digest: manifest_anchor_commitment(&new_manifest),
            operation_id: [0x45; 32],
            request_digest: [0x46; 32],
        };

        let cas_request_nonce = [0x48; 32];
        let mut write_request = ExternalCasWriteRequest {
            request_nonce: cas_request_nonce,
            operation_id: next_record.operation_id,
            request_digest: [0x49; 32],
            expected_generation: previous_record.generation,
            expected_object_generation: 8,
            expected_record_digest: previous_record.digest().unwrap(),
            expected_state_digest: previous_record.next_state_digest,
            next_record: next_record.clone(),
        };
        write_request.bind_request_digest(&pin).unwrap();
        let next_record = write_request.next_record.clone();

        let archive_id = QRunCheckpointMigrationJournal::archive_id_for_previous_manifest(
            previous_manifest_anchor,
        );
        let archive_commitment = [0x47; 32];
        let key_hash: [u8; 32] = Sha256::digest(pin.receipt_public_key).into();
        let journal = QRunCheckpointMigrationJournal {
            previous_record,
            next_record,
            previous_object_generation: 8,
            next_object_generation: 9,
            cas_request_nonce,
            owner_account: owner,
            receipt_key_id,
            receipt_public_key_hash: key_hash,
            checkpoint_commitment,
            expected_parent_checkpoint_commitment: [0xC7; 32],
            minimum_checkpoint_height: 1,
            checkpoint_bytes,
            previous_manifest: old_manifest,
            next_manifest: new_manifest,
            archive_id,
            archive_commitment,
        };
        (journal, pin, params)
    }

    #[test]
    fn qrm1_recovery_classifier_accepts_only_the_four_exact_crash_states() {
        use QRunCheckpointMigrationRecoveryAction as Action;

        let (journal, _, _) = fixture();
        let provider_states = [
            (
                journal.previous_record.clone(),
                journal.previous_object_generation,
            ),
            (journal.next_record.clone(), journal.next_object_generation),
        ];
        let floor_states = provider_states.clone();
        let manifest_states = [
            journal.previous_manifest.clone(),
            journal.next_manifest.clone(),
        ];

        for (provider_index, (provider, provider_generation)) in provider_states.iter().enumerate()
        {
            for (floor_index, (floor, floor_generation)) in floor_states.iter().enumerate() {
                for (manifest_index, manifest) in manifest_states.iter().enumerate() {
                    let expected = match (provider_index, floor_index, manifest_index) {
                        (0, 0, 0) => Action::RetryExactPreparedCas,
                        (1, 0, 0) => Action::AdvanceFloorThenInstallManifest,
                        (1, 1, 0) => Action::InstallNextManifest,
                        (1, 1, 1) => Action::VerifyCommittedCheckpointStoreAndClearIntent,
                        _ => Action::Quarantine,
                    };
                    assert_eq!(
                        classify_qrun_v05_checkpoint_migration_recovery(
                            &journal,
                            provider,
                            *provider_generation,
                            floor,
                            *floor_generation,
                            manifest,
                        ),
                        expected,
                        "provider={provider_index}, floor={floor_index}, manifest={manifest_index}"
                    );
                }
            }
        }
    }

    #[test]
    fn qrm1_recovery_classifier_quarantines_unrelated_records_generations_and_manifest_bytes() {
        use QRunCheckpointMigrationRecoveryAction as Action;

        let (journal, _, _) = fixture();
        let mut unrelated_provider = journal.previous_record.clone();
        unrelated_provider.operation_id[0] ^= 1;
        assert_eq!(
            classify_qrun_v05_checkpoint_migration_recovery(
                &journal,
                &unrelated_provider,
                journal.previous_object_generation,
                &journal.previous_record,
                journal.previous_object_generation,
                &journal.previous_manifest,
            ),
            Action::Quarantine
        );

        assert_eq!(
            classify_qrun_v05_checkpoint_migration_recovery(
                &journal,
                &journal.previous_record,
                journal.previous_object_generation + 1,
                &journal.previous_record,
                journal.previous_object_generation,
                &journal.previous_manifest,
            ),
            Action::Quarantine
        );

        let mut altered_manifest = journal.previous_manifest.clone();
        let last_manifest_byte = altered_manifest.len() - 1;
        altered_manifest[last_manifest_byte] ^= 1;
        assert_eq!(
            classify_qrun_v05_checkpoint_migration_recovery(
                &journal,
                &journal.previous_record,
                journal.previous_object_generation,
                &journal.previous_record,
                journal.previous_object_generation,
                &altered_manifest,
            ),
            Action::Quarantine
        );

        let mut corrupt_journal = journal;
        corrupt_journal.next_object_generation += 1;
        assert_eq!(
            classify_qrun_v05_checkpoint_migration_recovery(
                &corrupt_journal,
                &corrupt_journal.previous_record,
                corrupt_journal.previous_object_generation,
                &corrupt_journal.previous_record,
                corrupt_journal.previous_object_generation,
                &corrupt_journal.previous_manifest,
            ),
            Action::Quarantine
        );
    }

    #[test]
    fn qrm1_roundtrips_exact_checkpoint_manifest_and_cas_successor() {
        let (journal, pin, params) = fixture();
        let bytes = journal.encode_without_archive(&pin, &params).unwrap();
        assert!(bytes.len() <= MAX_QRM1_BYTES);
        let decoded =
            QRunCheckpointMigrationJournal::decode_without_archive(&bytes, &pin, &params).unwrap();
        assert_eq!(decoded, journal);
        assert_eq!(decoded.previous_record.generation, 7);
        assert_eq!(decoded.next_record.generation, 8);
        assert_eq!(decoded.previous_object_generation, 8);
        assert_eq!(decoded.next_object_generation, 9);
        assert_eq!(
            u16::from_be_bytes(bytes[4..6].try_into().unwrap()),
            QRM1_VERSION
        );

        let request = decoded.external_cas_write_request(&pin).unwrap();
        assert_eq!(request.request_nonce, journal.cas_request_nonce);
        assert_eq!(request.operation_id, journal.next_record.operation_id);
        assert_eq!(request.request_digest, journal.next_record.request_digest);
        assert_eq!(
            request.expected_generation,
            journal.previous_record.generation
        );
        assert_eq!(
            request.expected_object_generation,
            journal.previous_object_generation
        );
        assert_eq!(
            request.expected_record_digest,
            journal.previous_record.digest().unwrap()
        );
        assert_eq!(
            request.expected_state_digest,
            journal.previous_record.next_state_digest
        );
        assert_eq!(request.next_record, journal.next_record);
    }

    #[test]
    fn qrm1_rejects_object_generation_not_linked_to_record_generation() {
        let (mut journal, pin, params) = fixture();
        journal.previous_object_generation += 1;
        journal.next_object_generation += 1;
        assert_eq!(
            journal.encode_without_archive(&pin, &params),
            Err(QRunCheckpointMigrationError::InvalidObjectGeneration)
        );
    }

    #[test]
    fn qrm1_rejects_changed_cas_nonce_or_request_digest_and_legacy_v1() {
        let (journal, pin, params) = fixture();
        let bytes = journal.encode_without_archive(&pin, &params).unwrap();

        let mut wrong_nonce = journal.clone();
        wrong_nonce.cas_request_nonce[0] ^= 1;
        assert!(wrong_nonce.external_cas_write_request(&pin).is_err());
        assert!(wrong_nonce.encode_without_archive(&pin, &params).is_err());

        let mut wrong_request_digest = journal.clone();
        wrong_request_digest.next_record.request_digest[0] ^= 1;
        assert!(wrong_request_digest
            .external_cas_write_request(&pin)
            .is_err());
        assert!(wrong_request_digest
            .encode_without_archive(&pin, &params)
            .is_err());

        let mut legacy_v1 = bytes;
        legacy_v1[4..6].copy_from_slice(&1u16.to_be_bytes());
        assert_eq!(
            QRunCheckpointMigrationJournal::decode_without_archive(&legacy_v1, &pin, &params),
            Err(QRunCheckpointMigrationError::UnsupportedVersion(1))
        );
    }

    #[test]
    fn qrm1_rejects_wrong_provider_key_pin_and_archive_id() {
        let (journal, pin, params) = fixture();
        let mut wrong_pin = pin.clone();
        wrong_pin.receipt_key_id[0] ^= 1;
        assert!(matches!(
            journal.encode_without_archive(&wrong_pin, &params),
            Err(QRunCheckpointMigrationError::InvalidBinding)
        ));

        let mut wrong_key = pin.clone();
        wrong_key.receipt_public_key[0] ^= 1;
        assert!(matches!(
            journal.encode_without_archive(&wrong_key, &params),
            Err(QRunCheckpointMigrationError::InvalidBinding)
        ));

        let mut wrong_archive = journal.clone();
        wrong_archive.archive_id[0] ^= 1;
        assert!(matches!(
            wrong_archive.encode_without_archive(&pin, &params),
            Err(QRunCheckpointMigrationError::ManifestBindingMismatch)
        ));
    }

    #[test]
    fn qrm1_rejects_old_manifest_that_omits_the_claimed_canonical_tip() {
        let (mut journal, pin, params) = fixture();
        let mut rebound_manifest = journal.previous_manifest.clone();
        // A valid PFS2 manifest with one digest has its sole digest at bytes 138..170.
        // Rewrite that digest while preserving a correct checksum to model an attacker who
        // can construct a self-consistent manifest header/catalog pair.
        rebound_manifest[138] ^= 1;
        let checksum_offset = rebound_manifest.len() - 32;
        let checksum: [u8; 32] = Sha256::digest(&rebound_manifest[..checksum_offset]).into();
        rebound_manifest[checksum_offset..].copy_from_slice(&checksum);
        let rebound_anchor = manifest_anchor_commitment(&rebound_manifest);

        journal.previous_manifest = rebound_manifest;
        journal.previous_record.next_state_digest = rebound_anchor;
        journal.next_record.previous_record_digest = journal.previous_record.digest().unwrap();
        journal.next_record.previous_state_digest = rebound_anchor;
        journal.archive_id =
            QRunCheckpointMigrationJournal::archive_id_for_previous_manifest(rebound_anchor);

        let mut request = ExternalCasWriteRequest {
            request_nonce: journal.cas_request_nonce,
            operation_id: journal.next_record.operation_id,
            request_digest: [0x4A; 32],
            expected_generation: journal.previous_record.generation,
            expected_object_generation: journal.previous_object_generation,
            expected_record_digest: journal.previous_record.digest().unwrap(),
            expected_state_digest: journal.previous_record.next_state_digest,
            next_record: journal.next_record.clone(),
        };
        request.bind_request_digest(&pin).unwrap();
        journal.next_record = request.next_record;

        assert!(matches!(
            journal.encode_without_archive(&pin, &params),
            Err(QRunCheckpointMigrationError::ManifestBindingMismatch)
        ));
    }

    #[test]
    fn qrm1_rejects_unrelated_checkpoint_parent_and_non_exact_successor() {
        let (journal, pin, params) = fixture();
        let mut wrong_parent = journal.clone();
        wrong_parent.expected_parent_checkpoint_commitment[0] ^= 1;
        assert!(matches!(
            wrong_parent.encode_without_archive(&pin, &params),
            Err(QRunCheckpointMigrationError::Checkpoint(
                QRunCheckpointError::ParentCheckpointCommitmentMismatch
            ))
        ));

        let mut wrong_generation = journal;
        wrong_generation.next_record.generation += 1;
        assert!(matches!(
            wrong_generation.encode_without_archive(&pin, &params),
            Err(QRunCheckpointMigrationError::Record(
                ExternalCasError::NotExactSuccessor
            ))
        ));
    }

    #[test]
    fn qrm1_decoder_rejects_checksum_truncation_and_trailing_bytes() {
        let (journal, pin, params) = fixture();
        let bytes = journal.encode_without_archive(&pin, &params).unwrap();

        let mut corrupt = bytes.clone();
        let body_index = corrupt.len() / 2;
        corrupt[body_index] ^= 1;
        assert_eq!(
            QRunCheckpointMigrationJournal::decode_without_archive(&corrupt, &pin, &params),
            Err(QRunCheckpointMigrationError::ChecksumMismatch)
        );

        assert!(matches!(
            QRunCheckpointMigrationJournal::decode_without_archive(
                &bytes[..bytes.len() - 1],
                &pin,
                &params
            ),
            Err(QRunCheckpointMigrationError::Oversize)
                | Err(QRunCheckpointMigrationError::ChecksumMismatch)
        ));

        let mut trailing = bytes;
        trailing.push(0);
        assert!(matches!(
            QRunCheckpointMigrationJournal::decode_without_archive(&trailing, &pin, &params),
            Err(QRunCheckpointMigrationError::ChecksumMismatch)
                | Err(QRunCheckpointMigrationError::Malformed)
        ));
    }
}
