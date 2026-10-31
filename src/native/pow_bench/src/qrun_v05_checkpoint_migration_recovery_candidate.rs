//! Explicit, fail-closed QRM1 startup-recovery transaction.
//!
//! This module is separate from ordinary PFS2 open. A final QRM1 intent blocks normal startup;
//! callers must explicitly invoke this recovery routine with the exact external pin, independent
//! QCF1 floor, original wallet Genesis, QRA1 root and receipt verifier.
//!
//! Recovery retries only the exact persisted CAS request, advances QCF1 monotonically, installs
//! only the byte-exact manifest stored in QRM1, rechecks all authorities, and clears QRM1 only
//! after the committed checkpoint-rooted state has been reconstructed.

use crate::{
    chain_admission::ReferenceTimeProvider,
    consensus::ConsensusParameters,
    external_cas_anchor_candidate::{
        ExternalCasClientError, ExternalCasPin, ExternalCasProviderTransport, ExternalCasRecord,
        VerifiedExternalCasClient,
    },
    external_cas_floor_store_candidate::{ExternalCasFloorError, ExternalCasFloorStore},
    private_testnet_fork_store::{
        decode_manifest, manifest_anchor_commitment, qrun_v05_fee_checkpoint_profile_fingerprint,
        sync_parent, write_manifest_atomic, ForkStoreError, MAX_MANIFEST_BYTES,
    },
    qrun_v05_checkpoint_candidate::{QRunCheckpointError, QRunV05PowCheckpoint},
    qrun_v05_checkpoint_migration_candidate::{
        classify_qrun_v05_checkpoint_migration_recovery, QRunCheckpointMigrationError,
        QRunCheckpointMigrationJournal, QRunCheckpointMigrationRecoveryAction, MAX_QRM1_BYTES,
    },
    qrun_v05_genesis_candidate::QRunGenesisV05,
    qrun_v05_history_archive_candidate::{
        encode_hex, read_regular_file_nofollow, replay_qrun_v05_history_archive,
        verify_qrun_v05_history_archive, QRunHistoryArchiveError,
    },
    state_machine::{LedgerState, TransactionAuthenticator, MAX_TOTAL_SUPPLY_ATOMS},
    store_writer_lock::StoreWriterLock,
    v4_fat1_trust_candidate::MlDsa65Verifier,
};
use sha2::{Digest, Sha256};
use std::{fs, io, path::Path};

const STORE_LOCK_NAME: &str = "forkstore.lock";
const ACTIVE_MANIFEST_NAME: &str = "forkstore.manifest";
const QAP1_PENDING_NAME: &str = "qrun-v05-external-cas.pending";
const QRM1_INTENT_NAME: &str = "qrun-v05-migration.qrm1";
const MAX_EXACT_CAS_RETRIES: usize = 2;

#[derive(Debug)]
pub enum QRunCheckpointMigrationRecoveryError {
    Io(io::Error),
    LockHeld,
    MissingIntent,
    IntentChanged,
    Qap1CommitPresent,
    GenesisMismatch,
    PinMismatch,
    Archive(QRunHistoryArchiveError),
    Journal(QRunCheckpointMigrationError),
    Checkpoint(QRunCheckpointError),
    CheckpointProfileMismatch,
    Client(ExternalCasClientError),
    Floor(ExternalCasFloorError),
    Store(ForkStoreError),
    RetryStillPending,
    Quarantined,
}

impl std::fmt::Display for QRunCheckpointMigrationRecoveryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for QRunCheckpointMigrationRecoveryError {}

impl From<io::Error> for QRunCheckpointMigrationRecoveryError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}
impl From<QRunHistoryArchiveError> for QRunCheckpointMigrationRecoveryError {
    fn from(value: QRunHistoryArchiveError) -> Self {
        Self::Archive(value)
    }
}
impl From<QRunCheckpointMigrationError> for QRunCheckpointMigrationRecoveryError {
    fn from(value: QRunCheckpointMigrationError) -> Self {
        Self::Journal(value)
    }
}
impl From<QRunCheckpointError> for QRunCheckpointMigrationRecoveryError {
    fn from(value: QRunCheckpointError) -> Self {
        Self::Checkpoint(value)
    }
}
impl From<ExternalCasClientError> for QRunCheckpointMigrationRecoveryError {
    fn from(value: ExternalCasClientError) -> Self {
        Self::Client(value)
    }
}
impl From<ExternalCasFloorError> for QRunCheckpointMigrationRecoveryError {
    fn from(value: ExternalCasFloorError) -> Self {
        Self::Floor(value)
    }
}
impl From<ForkStoreError> for QRunCheckpointMigrationRecoveryError {
    fn from(value: ForkStoreError) -> Self {
        Self::Store(value)
    }
}

/// Exact data required to reopen the newly checkpoint-rooted QFP5 PFS2 store after QRM1 recovery.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QRunCheckpointMigrationRecoveryReport {
    pub checkpoint_bytes: Vec<u8>,
    pub checkpoint_commitment: [u8; 32],
    pub minimum_checkpoint_height: u64,
    pub expected_parent_checkpoint_commitment: [u8; 32],
    pub manifest_anchor: [u8; 32],
    pub provider_record: ExternalCasRecord,
    pub provider_object_generation: u64,
    pub archive_id: [u8; 32],
    pub archive_commitment: [u8; 32],
}

fn fresh_signed_read<P, V>(
    client: &mut VerifiedExternalCasClient<P, V>,
    expected: &ExternalCasRecord,
    minimum_object_generation: u64,
) -> Result<(ExternalCasRecord, u64), QRunCheckpointMigrationRecoveryError>
where
    P: ExternalCasProviderTransport,
    V: MlDsa65Verifier,
{
    let mut operation_id = [0u8; 32];
    getrandom::getrandom(&mut operation_id).map_err(|_| {
        QRunCheckpointMigrationRecoveryError::Client(ExternalCasClientError::RandomNonceUnavailable)
    })?;
    if operation_id == [0; 32] {
        return Err(QRunCheckpointMigrationRecoveryError::Client(
            ExternalCasClientError::RandomNonceUnavailable,
        ));
    }
    let mut digest = Sha256::new();
    digest.update(b"QRUN-V05-QRM1-RECOVERY-READ-V1\0");
    digest.update(operation_id);
    digest.update(expected.digest().map_err(ExternalCasClientError::from)?);
    let request_digest: [u8; 32] = digest.finalize().into();
    let request = client.fresh_read_request(operation_id, request_digest)?;
    let verified = client.read_current(
        &request,
        expected.generation,
        minimum_object_generation,
        Some(expected),
    )?;
    Ok((verified.record, verified.object_generation))
}

fn reject_qap1_if_present(directory: &Path) -> Result<(), QRunCheckpointMigrationRecoveryError> {
    match fs::symlink_metadata(directory.join(QAP1_PENDING_NAME)) {
        Ok(_) => Err(QRunCheckpointMigrationRecoveryError::Qap1CommitPresent),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(QRunCheckpointMigrationRecoveryError::Io(error)),
    }
}

fn read_active_manifest(directory: &Path) -> Result<Vec<u8>, QRunCheckpointMigrationRecoveryError> {
    Ok(read_regular_file_nofollow(
        &directory.join(ACTIVE_MANIFEST_NAME),
        MAX_MANIFEST_BYTES,
    )?)
}

fn validate_checkpoint_rooted_manifest(
    journal: &QRunCheckpointMigrationJournal,
    pin: &ExternalCasPin,
    owner_account: [u8; 32],
    params: &ConsensusParameters,
    active_manifest: &[u8],
) -> Result<(), QRunCheckpointMigrationRecoveryError> {
    if active_manifest != journal.next_manifest
        || manifest_anchor_commitment(active_manifest) != journal.next_record.next_state_digest
        || manifest_anchor_commitment(active_manifest)
            != manifest_anchor_commitment(&journal.next_manifest)
    {
        return Err(QRunCheckpointMigrationRecoveryError::Quarantined);
    }

    let wallet_genesis = QRunGenesisV05::new(pin.network_id, owner_account)
        .map_err(|_| QRunCheckpointMigrationRecoveryError::GenesisMismatch)?;
    if wallet_genesis.commitment() != pin.genesis_digest {
        return Err(QRunCheckpointMigrationRecoveryError::GenesisMismatch);
    }

    let mut base_chain = QRunV05PowCheckpoint::restore_chain_anchored(
        &journal.checkpoint_bytes,
        &pin.network_id,
        &pin.genesis_digest,
        params,
        journal.checkpoint_commitment,
        journal.minimum_checkpoint_height,
    )?;
    base_chain
        .enable_qrun_v05_fee_only_execution_for_genesis(pin.genesis_digest)
        .map_err(|_| QRunCheckpointMigrationRecoveryError::CheckpointProfileMismatch)?;
    if base_chain.state().network_id() != pin.network_id
        || base_chain.state().total_value().ok() != Some(MAX_TOTAL_SUPPLY_ATOMS)
        || base_chain.state().height() != journal.minimum_checkpoint_height
    {
        return Err(QRunCheckpointMigrationRecoveryError::CheckpointProfileMismatch);
    }

    let checkpoint_tip = base_chain.chain_tip().tip_hash;
    let checkpoint_profile = qrun_v05_fee_checkpoint_profile_fingerprint(
        base_chain.state(),
        params,
        journal.checkpoint_commitment,
    )?;
    let manifest = decode_manifest(active_manifest)?;
    if manifest.network_id != pin.network_id
        || manifest.profile_fingerprint != checkpoint_profile
        || manifest.genesis_tip != checkpoint_tip
        || manifest.canonical_tip != checkpoint_tip
        || !manifest.digests.is_empty()
    {
        return Err(QRunCheckpointMigrationRecoveryError::CheckpointProfileMismatch);
    }
    Ok(())
}

/// Recover one QRM1 checkpoint re-root under the active PFS2 writer lock.
///
/// The QRA1 archive and full QFP5 replay are verified before a provider write is attempted.
/// An old/old/old observation is not an abort: the exact prepared CAS request is retried at most
/// twice. If the provider still reports the predecessor, this function returns RetryStillPending
/// and intentionally retains QRM1; ordinary startup remains blocked.
#[allow(clippy::too_many_arguments)]
pub fn recover_qrun_v05_checkpoint_migration<P, V, A>(
    store_directory: impl AsRef<Path>,
    archive_root: impl AsRef<Path>,
    genesis: &LedgerState,
    owner_account: [u8; 32],
    params: &ConsensusParameters,
    pin: &ExternalCasPin,
    client: &mut VerifiedExternalCasClient<P, V>,
    floor: &ExternalCasFloorStore,
    authenticator: &A,
    clock: &dyn ReferenceTimeProvider,
) -> Result<QRunCheckpointMigrationRecoveryReport, QRunCheckpointMigrationRecoveryError>
where
    P: ExternalCasProviderTransport,
    V: MlDsa65Verifier,
    A: TransactionAuthenticator,
{
    pin.validate()
        .map_err(|_| QRunCheckpointMigrationRecoveryError::PinMismatch)?;
    if !client.is_pinned_to(pin) || floor.pin() != pin {
        return Err(QRunCheckpointMigrationRecoveryError::PinMismatch);
    }
    if params.protocol_version != 5 || genesis.network_id() != pin.network_id {
        return Err(QRunCheckpointMigrationRecoveryError::GenesisMismatch);
    }
    let wallet_genesis = QRunGenesisV05::new(pin.network_id, owner_account)
        .map_err(|_| QRunCheckpointMigrationRecoveryError::GenesisMismatch)?;
    if wallet_genesis.commitment() != pin.genesis_digest
        || wallet_genesis.ledger().state_root() != genesis.state_root()
        || genesis.height() != 0
        || genesis.tip_hash() != wallet_genesis.ledger().tip_hash()
        || genesis.total_value().ok() != Some(MAX_TOTAL_SUPPLY_ATOMS)
    {
        return Err(QRunCheckpointMigrationRecoveryError::GenesisMismatch);
    }

    let directory = fs::canonicalize(store_directory.as_ref())?;
    let archive_root = fs::canonicalize(archive_root.as_ref())?;
    if directory.starts_with(&archive_root) || archive_root.starts_with(&directory) {
        return Err(QRunCheckpointMigrationRecoveryError::Quarantined);
    }

    // Exclusive PFS2 maintenance lock: no local or external-CAS block writer can race this flow.
    let _writer_lock = StoreWriterLock::acquire(&directory, STORE_LOCK_NAME).map_err(|error| {
        if error.kind() == io::ErrorKind::WouldBlock {
            QRunCheckpointMigrationRecoveryError::LockHeld
        } else {
            QRunCheckpointMigrationRecoveryError::Io(error)
        }
    })?;
    reject_qap1_if_present(&directory)?;

    let intent_path = directory.join(QRM1_INTENT_NAME);
    let intent_bytes = match fs::symlink_metadata(&intent_path) {
        Ok(metadata) if metadata.file_type().is_file() => {
            read_regular_file_nofollow(&intent_path, MAX_QRM1_BYTES)?
        }
        Ok(_) => return Err(QRunCheckpointMigrationRecoveryError::IntentChanged),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Err(QRunCheckpointMigrationRecoveryError::MissingIntent)
        }
        Err(error) => return Err(QRunCheckpointMigrationRecoveryError::Io(error)),
    };

    // This bounded structural decode is used only to locate the committed archive. No provider
    // or floor mutation occurs until the opaque QRA1 summary and full replay witness validate it.
    let journal =
        QRunCheckpointMigrationJournal::decode_without_archive(&intent_bytes, pin, params)?;
    if journal.owner_account != owner_account {
        return Err(QRunCheckpointMigrationRecoveryError::GenesisMismatch);
    }
    let previous_manifest_anchor = manifest_anchor_commitment(&journal.previous_manifest);
    let derived_archive_id =
        QRunCheckpointMigrationJournal::archive_id_for_previous_manifest(previous_manifest_anchor);
    if journal.archive_id != derived_archive_id {
        return Err(QRunCheckpointMigrationRecoveryError::Quarantined);
    }

    let archive_directory = archive_root.join(encode_hex(&journal.archive_id));
    let old_manifest = decode_manifest(&journal.previous_manifest)?;
    let archive_summary = verify_qrun_v05_history_archive(
        &archive_directory,
        pin.network_id,
        old_manifest.profile_fingerprint,
        old_manifest.genesis_tip,
        previous_manifest_anchor,
        params,
    )?;
    journal.validate(pin, params, &archive_summary)?;
    let replay = replay_qrun_v05_history_archive(
        &archive_directory,
        pin.network_id,
        pin.genesis_digest,
        old_manifest.profile_fingerprint,
        old_manifest.genesis_tip,
        previous_manifest_anchor,
        owner_account,
        params,
        authenticator,
        clock,
    )?;
    journal.validate_replayed_history(pin, params, &replay)?;

    let mut retries = 0usize;
    loop {
        let floor_snapshot = floor.snapshot()?;
        let (provider_record, provider_object_generation) = fresh_signed_read(
            client,
            &floor_snapshot.trusted_record,
            floor_snapshot.minimum_object_generation,
        )?;
        let active_manifest = read_active_manifest(&directory)?;
        let action = classify_qrun_v05_checkpoint_migration_recovery(
            &journal,
            &provider_record,
            provider_object_generation,
            &floor_snapshot.trusted_record,
            floor_snapshot.minimum_object_generation,
            &active_manifest,
        );

        match action {
            QRunCheckpointMigrationRecoveryAction::RetryExactPreparedCas => {
                if retries >= MAX_EXACT_CAS_RETRIES {
                    return Err(QRunCheckpointMigrationRecoveryError::RetryStillPending);
                }
                let exact_request = journal.external_cas_write_request(pin)?;
                // Regardless of response success/error, only the next fresh signed read decides.
                // The request is byte-identical: persisted nonce, operation ID and digest.
                let _ambiguous_result = client.compare_and_swap(&exact_request);
                retries += 1;
            }
            QRunCheckpointMigrationRecoveryAction::AdvanceFloorThenInstallManifest => {
                floor.advance(
                    &journal.previous_record,
                    journal.previous_object_generation,
                    &journal.next_record,
                    journal.next_object_generation,
                )?;
                let after_floor = floor.snapshot()?;
                if after_floor.trusted_record != journal.next_record
                    || after_floor.minimum_object_generation != journal.next_object_generation
                {
                    return Err(QRunCheckpointMigrationRecoveryError::Quarantined);
                }
                let (provider_after_floor, generation_after_floor) = fresh_signed_read(
                    client,
                    &after_floor.trusted_record,
                    after_floor.minimum_object_generation,
                )?;
                if provider_after_floor != journal.next_record
                    || generation_after_floor != journal.next_object_generation
                {
                    return Err(QRunCheckpointMigrationRecoveryError::Quarantined);
                }
                write_manifest_atomic(
                    &directory.join(ACTIVE_MANIFEST_NAME),
                    &journal.next_manifest,
                )?;
            }
            QRunCheckpointMigrationRecoveryAction::InstallNextManifest => {
                let (provider_before_install, generation_before_install) = fresh_signed_read(
                    client,
                    &floor_snapshot.trusted_record,
                    floor_snapshot.minimum_object_generation,
                )?;
                if provider_before_install != journal.next_record
                    || generation_before_install != journal.next_object_generation
                    || floor_snapshot.trusted_record != journal.next_record
                    || floor_snapshot.minimum_object_generation != journal.next_object_generation
                {
                    return Err(QRunCheckpointMigrationRecoveryError::Quarantined);
                }
                write_manifest_atomic(
                    &directory.join(ACTIVE_MANIFEST_NAME),
                    &journal.next_manifest,
                )?;
            }
            QRunCheckpointMigrationRecoveryAction::VerifyCommittedCheckpointStoreAndClearIntent => {
                let (provider_final, generation_final) = fresh_signed_read(
                    client,
                    &journal.next_record,
                    journal.next_object_generation,
                )?;
                let floor_final = floor.snapshot()?;
                let manifest_final = read_active_manifest(&directory)?;
                if provider_final != journal.next_record
                    || generation_final != journal.next_object_generation
                    || floor_final.trusted_record != journal.next_record
                    || floor_final.minimum_object_generation != journal.next_object_generation
                {
                    return Err(QRunCheckpointMigrationRecoveryError::Quarantined);
                }
                validate_checkpoint_rooted_manifest(
                    &journal,
                    pin,
                    owner_account,
                    params,
                    &manifest_final,
                )?;

                let current_intent = read_regular_file_nofollow(&intent_path, MAX_QRM1_BYTES)?;
                if current_intent != intent_bytes {
                    return Err(QRunCheckpointMigrationRecoveryError::IntentChanged);
                }
                fs::remove_file(&intent_path)?;
                sync_parent(&directory)?;
                return Ok(QRunCheckpointMigrationRecoveryReport {
                    checkpoint_bytes: journal.checkpoint_bytes.clone(),
                    checkpoint_commitment: journal.checkpoint_commitment,
                    minimum_checkpoint_height: journal.minimum_checkpoint_height,
                    expected_parent_checkpoint_commitment: journal
                        .expected_parent_checkpoint_commitment,
                    manifest_anchor: journal.next_record.next_state_digest,
                    provider_record: provider_final,
                    provider_object_generation: generation_final,
                    archive_id: journal.archive_id,
                    archive_commitment: journal.archive_commitment,
                });
            }
            QRunCheckpointMigrationRecoveryAction::Quarantine => {
                return Err(QRunCheckpointMigrationRecoveryError::Quarantined)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn qrm1_recovery_constants_are_distinct_from_qap1() {
        assert_ne!(QRM1_INTENT_NAME, QAP1_PENDING_NAME);
        assert_ne!(ACTIVE_MANIFEST_NAME, QRM1_INTENT_NAME);
    }
}
