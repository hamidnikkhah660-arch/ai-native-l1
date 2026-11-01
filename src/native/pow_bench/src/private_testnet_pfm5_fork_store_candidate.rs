//! CP-0392 candidate-only durable PFM5 checkpoint-rooted PMT4 branch store.
//!
//! This store persists a PCP4 checkpoint, content-addressed PMT4 envelopes, and a canonical
//! PFM5 manifest. Every reopen replays the complete retained branch set from the checkpoint.
//! Local checksums/commitments detect corruption but do not establish freshness or prevent
//! rollback. Callers needing rollback resistance must obtain the exact manifest commitment from
//! an independently verified External-CAS read and use open_with_manifest_anchor.
//!
//! External-CAS publication and cross-host object distribution are intentionally not implemented
//! here. A manifest commitment does not make local branch files remotely available, and a
//! local-only submit is not an externally committed chain update.

use crate::{
    chain_admission::ReferenceTimeProvider,
    consensus::{pow_digest, ConsensusParameters},
    private_testnet_checkpoint_candidate::{
        Pcp4CheckpointError, Pcp4CheckpointRecord, Pcp4ValidationContext, MAX_PCP4_RECORD_BYTES,
    },
    private_testnet_monetary_wire::{
        decode_candidate_v4_hybrid_monetary_network_block,
        MAX_PRIVATE_TESTNET_V4_HYBRID_MONETARY_ENVELOPE_BYTES,
    },
    private_testnet_pfm5_manifest_candidate::{
        Pfm5CheckpointManifest, Pfm5ManifestError, MAX_PFM5_MANIFEST_BYTES,
    },
    private_testnet_v4_hybrid_fork_choice_candidate::{
        next_pfm5_manifest_after_replay, PrivateTestnetV4HybridForkChoice, V4HybridForkChoiceError,
        V4HybridForkChoiceOutcome, MAX_V4_HYBRID_FORK_ARCHIVE_BLOCKS,
        MAX_V4_HYBRID_FORK_ARCHIVE_BYTES,
    },
    state_machine::{MonetaryLedgerState, StateError},
    store_writer_lock::StoreWriterLock,
    v4_account_identity_candidate::MlDsa65Verifier,
};
use std::{
    collections::BTreeSet,
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
    process,
    sync::atomic::{AtomicU64, Ordering as AtomicOrdering},
};

const MANIFEST_NAME: &str = "checkpoint-forkstore.pfm5";
const CHECKPOINT_NAME: &str = "checkpoint-forkstore.pcp4";
const LOCK_NAME: &str = "checkpoint-forkstore.lock";
const BRANCH_PREFIX: &str = "checkpoint-branch-";
const BRANCH_SUFFIX: &str = ".pmt4";
const TEMP_MARKER: &str = ".tmp-";
static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Debug)]
pub enum Pfm5ForkStoreError {
    Io(io::Error),
    State(StateError),
    Checkpoint(Pcp4CheckpointError),
    Manifest(Pfm5ManifestError),
    Fork(V4HybridForkChoiceError),
    LockHeld,
    InvalidConsensusProfile,
    MissingManifest,
    MissingCheckpoint,
    ManifestTooLarge,
    CheckpointTooLarge,
    BranchTooLarge,
    MissingReferencedBranch,
    BranchDigestMismatch,
    ManifestAnchorMismatch,
    NoStateChange,
    ExternalAnchorRequired,
    AlreadyInitialized,
    UnexpectedStoreEntry,
    UnexpectedBranchFileName,
    TooManyStoreEntries,
}

impl std::fmt::Display for Pfm5ForkStoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(f, "PFM5 fork-store I/O error: {error}"),
            Self::State(error) => write!(f, "PFM5 fork-store state error: {error:?}"),
            Self::Checkpoint(error) => write!(f, "PFM5 PCP4 checkpoint rejected: {error}"),
            Self::Manifest(error) => write!(f, "PFM5 manifest rejected: {error}"),
            Self::Fork(error) => write!(f, "PFM5 PMT4 archive replay rejected: {error}"),
            Self::LockHeld => write!(f, "PFM5 fork-store writer lock is already held"),
            Self::InvalidConsensusProfile => write!(f, "PFM5 consensus profile is invalid"),
            Self::MissingManifest => write!(f, "PFM5 store manifest is missing"),
            Self::MissingCheckpoint => write!(f, "PFM5 referenced PCP4 checkpoint is missing"),
            Self::ManifestTooLarge => write!(f, "PFM5 manifest exceeds its byte limit"),
            Self::CheckpointTooLarge => write!(f, "PCP4 checkpoint exceeds its byte limit"),
            Self::BranchTooLarge => write!(f, "PFM5 PMT4 branch envelope exceeds its byte limit"),
            Self::MissingReferencedBranch => {
                write!(f, "PFM5 manifest references a missing PMT4 branch")
            }
            Self::BranchDigestMismatch => write!(
                f,
                "PFM5 branch filename/digest does not match its PMT4 bytes"
            ),
            Self::ManifestAnchorMismatch => write!(
                f,
                "PFM5 manifest differs from the caller's expected commitment"
            ),
            Self::NoStateChange => write!(f, "PFM5 submission does not add a new retained branch"),
            Self::ExternalAnchorRequired => write!(
                f,
                "externally anchored PFM5 store cannot use local-only submit"
            ),
            Self::AlreadyInitialized => write!(f, "PFM5 store is already initialized"),
            Self::UnexpectedStoreEntry => {
                write!(f, "PFM5 store contains an unexpected filesystem entry")
            }
            Self::UnexpectedBranchFileName => write!(f, "PFM5 branch filename is not canonical"),
            Self::TooManyStoreEntries => {
                write!(f, "PFM5 store contains too many branch/temp files")
            }
        }
    }
}
impl std::error::Error for Pfm5ForkStoreError {}

impl From<io::Error> for Pfm5ForkStoreError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}
impl From<StateError> for Pfm5ForkStoreError {
    fn from(value: StateError) -> Self {
        Self::State(value)
    }
}
impl From<Pcp4CheckpointError> for Pfm5ForkStoreError {
    fn from(value: Pcp4CheckpointError) -> Self {
        Self::Checkpoint(value)
    }
}
impl From<Pfm5ManifestError> for Pfm5ForkStoreError {
    fn from(value: Pfm5ManifestError) -> Self {
        Self::Manifest(value)
    }
}
impl From<V4HybridForkChoiceError> for Pfm5ForkStoreError {
    fn from(value: V4HybridForkChoiceError) -> Self {
        Self::Fork(value)
    }
}

/// Single-writer durable store for a checkpoint-rooted PMT4 branch graph.
///
/// The anchored flag means only that the caller opened against an externally obtained exact
/// manifest commitment. The store cannot independently prove where that commitment came from.
pub struct PrivateTestnetPfm5ForkStoreCandidate {
    directory: PathBuf,
    network_id: [u8; 32],
    trusted_genesis: MonetaryLedgerState,
    params: ConsensusParameters,
    transaction_manifest_id: [u8; 32],
    checkpoint: Pcp4CheckpointRecord,
    manifest: Pfm5CheckpointManifest,
    archive: PrivateTestnetV4HybridForkChoice,
    minimum_generation: u64,
    minimum_checkpoint_height: u64,
    anchored: bool,
    _writer_lock: StoreWriterLock,
}

impl PrivateTestnetPfm5ForkStoreCandidate {
    /// Initialize a new local candidate store from a caller-validated PCP4 checkpoint.
    /// The immutable checkpoint is written first and the generation-1 PFM5 manifest second.
    /// This does not obtain an External-CAS receipt or establish anti-rollback protection.
    pub fn initialize<V: MlDsa65Verifier>(
        directory: impl AsRef<Path>,
        checkpoint: Pcp4CheckpointRecord,
        context: &Pcp4ValidationContext<'_>,
        verifier: &V,
    ) -> Result<Self, Pfm5ForkStoreError> {
        let directory = directory.as_ref().to_path_buf();
        fs::create_dir_all(&directory)?;
        validate_lock_entry(&directory)?;
        let writer_lock = acquire_writer_lock(&directory)?;
        let checkpoint_bytes = checkpoint.encode(context)?;
        let manifest = initial_manifest(&checkpoint, context, checkpoint_bytes.len())?;
        let manifest_commitment = manifest.commitment()?;
        let manifest_path = directory.join(MANIFEST_NAME);
        let checkpoint_path = directory.join(CHECKPOINT_NAME);
        if manifest_path.exists() {
            return Err(Pfm5ForkStoreError::AlreadyInitialized);
        }
        ensure_initialization_directory(&directory)?;

        // A crash after checkpoint sync but before manifest publication is safely retryable,
        // but only if the existing immutable checkpoint is byte-for-byte identical.
        if checkpoint_path.exists() {
            let existing =
                read_bounded_file(&checkpoint_path, MAX_PCP4_RECORD_BYTES).map_err(|error| {
                    match error {
                        BoundedReadError::Io(error) => Pfm5ForkStoreError::Io(error),
                        BoundedReadError::TooLarge => Pfm5ForkStoreError::CheckpointTooLarge,
                    }
                })?;
            if existing != checkpoint_bytes {
                return Err(Pfm5ForkStoreError::AlreadyInitialized);
            }
        } else {
            write_synced_new(&checkpoint_path, &checkpoint_bytes)?;
        }
        write_manifest_atomic(&manifest_path, &manifest.encode()?)?;
        let archive = PrivateTestnetV4HybridForkChoice::rebuild_from_pfm5_checkpoint(
            &manifest,
            &checkpoint,
            context,
            manifest_commitment,
            1,
            checkpoint.logical_height,
            Vec::<Vec<u8>>::new(),
            verifier,
        )?;
        cleanup_store_entries(&directory, &BTreeSet::new())?;

        Ok(Self {
            directory,
            network_id: *context.network_id,
            trusted_genesis: context.trusted_genesis.clone(),
            params: context.params.clone(),
            transaction_manifest_id: *context.active_transaction_manifest_id,
            checkpoint,
            manifest,
            archive,
            minimum_generation: 1,
            minimum_checkpoint_height: 0,
            anchored: false,
            _writer_lock: writer_lock,
        })
    }

    /// Reopen without an independent anchor. This validates checksums, checkpoint bindings and
    /// every PMT4 envelope, but does not provide rollback-resistant recovery.
    pub fn open_local_unanchored<V: MlDsa65Verifier>(
        directory: impl AsRef<Path>,
        network_id: [u8; 32],
        trusted_genesis: MonetaryLedgerState,
        params: ConsensusParameters,
        transaction_manifest_id: [u8; 32],
        minimum_generation: u64,
        minimum_checkpoint_height: u64,
        verifier: &V,
    ) -> Result<Self, Pfm5ForkStoreError> {
        Self::open_inner(
            directory,
            network_id,
            trusted_genesis,
            params,
            transaction_manifest_id,
            None,
            minimum_generation,
            minimum_checkpoint_height,
            verifier,
        )
    }

    /// Reopen against an exact manifest commitment supplied after an independent authenticated
    /// read (for example, a verified External-CAS read). This compares local bytes to that
    /// commitment only; it performs no provider I/O or receipt verification.
    pub fn open_with_manifest_anchor<V: MlDsa65Verifier>(
        directory: impl AsRef<Path>,
        network_id: [u8; 32],
        trusted_genesis: MonetaryLedgerState,
        params: ConsensusParameters,
        transaction_manifest_id: [u8; 32],
        expected_manifest_commitment: [u8; 32],
        minimum_generation: u64,
        minimum_checkpoint_height: u64,
        verifier: &V,
    ) -> Result<Self, Pfm5ForkStoreError> {
        if expected_manifest_commitment == [0; 32] {
            return Err(Pfm5ForkStoreError::ManifestAnchorMismatch);
        }
        Self::open_inner(
            directory,
            network_id,
            trusted_genesis,
            params,
            transaction_manifest_id,
            Some(expected_manifest_commitment),
            minimum_generation,
            minimum_checkpoint_height,
            verifier,
        )
    }

    fn open_inner<V: MlDsa65Verifier>(
        directory: impl AsRef<Path>,
        network_id: [u8; 32],
        trusted_genesis: MonetaryLedgerState,
        params: ConsensusParameters,
        transaction_manifest_id: [u8; 32],
        expected_manifest_commitment: Option<[u8; 32]>,
        minimum_generation: u64,
        minimum_checkpoint_height: u64,
        verifier: &V,
    ) -> Result<Self, Pfm5ForkStoreError> {
        params
            .validate_monetary_execution_compatibility()
            .map_err(|_| Pfm5ForkStoreError::InvalidConsensusProfile)?;
        if minimum_generation == 0 {
            return Err(Pfm5ForkStoreError::Manifest(
                Pfm5ManifestError::InvalidGeneration,
            ));
        }
        let directory = directory.as_ref().to_path_buf();
        fs::create_dir_all(&directory)?;
        validate_lock_entry(&directory)?;
        let writer_lock = acquire_writer_lock(&directory)?;
        validate_store_entry_layout(&directory)?;
        let context = Pcp4ValidationContext {
            network_id: &network_id,
            trusted_genesis: &trusted_genesis,
            params: &params,
            active_transaction_manifest_id: &transaction_manifest_id,
        };

        let manifest_path = directory.join(MANIFEST_NAME);
        let checkpoint_path = directory.join(CHECKPOINT_NAME);
        let manifest_bytes = read_bounded_file(&manifest_path, MAX_PFM5_MANIFEST_BYTES).map_err(
            |error| match error {
                BoundedReadError::Io(error) if error.kind() == io::ErrorKind::NotFound => {
                    Pfm5ForkStoreError::MissingManifest
                }
                BoundedReadError::Io(error) => Pfm5ForkStoreError::Io(error),
                BoundedReadError::TooLarge => Pfm5ForkStoreError::ManifestTooLarge,
            },
        )?;
        let manifest = Pfm5CheckpointManifest::decode(&manifest_bytes)?;
        let manifest_commitment = manifest.commitment()?;
        if expected_manifest_commitment.is_some_and(|expected| expected != manifest_commitment) {
            return Err(Pfm5ForkStoreError::ManifestAnchorMismatch);
        }
        let checkpoint_bytes = read_bounded_file(&checkpoint_path, MAX_PCP4_RECORD_BYTES).map_err(
            |error| match error {
                BoundedReadError::Io(error) if error.kind() == io::ErrorKind::NotFound => {
                    Pfm5ForkStoreError::MissingCheckpoint
                }
                BoundedReadError::Io(error) => Pfm5ForkStoreError::Io(error),
                BoundedReadError::TooLarge => Pfm5ForkStoreError::CheckpointTooLarge,
            },
        )?;
        let checkpoint = Pcp4CheckpointRecord::decode(&checkpoint_bytes, &context)?;
        manifest.validate_checkpoint(&checkpoint, &context)?;

        let mut envelopes = Vec::with_capacity(manifest.branch_digests.len());
        let known: BTreeSet<[u8; 32]> = manifest.branch_digests.iter().copied().collect();
        for digest in &manifest.branch_digests {
            let path = directory.join(branch_file_name(digest));
            let bytes =
                read_bounded_file(&path, MAX_PRIVATE_TESTNET_V4_HYBRID_MONETARY_ENVELOPE_BYTES)
                    .map_err(|error| match error {
                        BoundedReadError::Io(error) if error.kind() == io::ErrorKind::NotFound => {
                            Pfm5ForkStoreError::MissingReferencedBranch
                        }
                        BoundedReadError::Io(error) => Pfm5ForkStoreError::Io(error),
                        BoundedReadError::TooLarge => Pfm5ForkStoreError::BranchTooLarge,
                    })?;
            let decoded = decode_candidate_v4_hybrid_monetary_network_block(&bytes)
                .map_err(|_| Pfm5ForkStoreError::BranchDigestMismatch)?;
            if decoded.header.network_id != network_id
                || pow_digest(&decoded.header, params.pow)
                    .map_err(|_| Pfm5ForkStoreError::BranchDigestMismatch)?
                    != *digest
            {
                return Err(Pfm5ForkStoreError::BranchDigestMismatch);
            }
            envelopes.push(bytes);
        }

        let archive = PrivateTestnetV4HybridForkChoice::rebuild_from_pfm5_checkpoint(
            &manifest,
            &checkpoint,
            &context,
            manifest_commitment,
            minimum_generation,
            minimum_checkpoint_height,
            envelopes,
            verifier,
        )?;
        cleanup_store_entries(&directory, &known)?;

        Ok(Self {
            directory,
            network_id,
            trusted_genesis,
            params,
            transaction_manifest_id,
            checkpoint,
            manifest,
            archive,
            minimum_generation,
            minimum_checkpoint_height,
            anchored: expected_manifest_commitment.is_some(),
            _writer_lock: writer_lock,
        })
    }

    pub fn manifest(&self) -> &Pfm5CheckpointManifest {
        &self.manifest
    }
    pub fn archive(&self) -> &PrivateTestnetV4HybridForkChoice {
        &self.archive
    }
    pub fn canonical_height(&self) -> u64 {
        self.archive.canonical_chain().chain_tip().height
    }
    pub fn canonical_tip(&self) -> [u8; 32] {
        self.archive.canonical_chain().chain_tip().tip_hash
    }
    pub fn is_externally_anchored(&self) -> bool {
        self.anchored
    }

    /// Return the exact PFM5 content commitment after checking the durable checkpoint/manifest
    /// and every referenced envelope against the in-memory replayed archive.
    pub fn manifest_anchor(&self) -> Result<[u8; 32], Pfm5ForkStoreError> {
        let manifest_bytes =
            read_bounded_file(&self.directory.join(MANIFEST_NAME), MAX_PFM5_MANIFEST_BYTES)
                .map_err(|error| match error {
                    BoundedReadError::Io(error) => Pfm5ForkStoreError::Io(error),
                    BoundedReadError::TooLarge => Pfm5ForkStoreError::ManifestTooLarge,
                })?;
        let durable_manifest = Pfm5CheckpointManifest::decode(&manifest_bytes)?;
        if durable_manifest != self.manifest {
            return Err(Pfm5ForkStoreError::ManifestAnchorMismatch);
        }
        let context = self.validation_context();
        durable_manifest.validate_checkpoint(&self.checkpoint, &context)?;
        let checkpoint_bytes =
            read_bounded_file(&self.directory.join(CHECKPOINT_NAME), MAX_PCP4_RECORD_BYTES)
                .map_err(|error| match error {
                    BoundedReadError::Io(error) => Pfm5ForkStoreError::Io(error),
                    BoundedReadError::TooLarge => Pfm5ForkStoreError::CheckpointTooLarge,
                })?;
        if checkpoint_bytes != self.checkpoint.encode(&context)? {
            return Err(Pfm5ForkStoreError::ManifestAnchorMismatch);
        }
        let mut actual = Vec::new();
        for envelope in self.archive.archive_envelopes_bounded(
            MAX_V4_HYBRID_FORK_ARCHIVE_BLOCKS,
            MAX_V4_HYBRID_FORK_ARCHIVE_BYTES,
        )? {
            let decoded = decode_candidate_v4_hybrid_monetary_network_block(&envelope)
                .map_err(|_| Pfm5ForkStoreError::BranchDigestMismatch)?;
            let digest = pow_digest(&decoded.header, self.params.pow)
                .map_err(|_| Pfm5ForkStoreError::BranchDigestMismatch)?;
            let branch_bytes = read_bounded_file(
                &self.directory.join(branch_file_name(&digest)),
                MAX_PRIVATE_TESTNET_V4_HYBRID_MONETARY_ENVELOPE_BYTES,
            )
            .map_err(|error| match error {
                BoundedReadError::Io(error) => Pfm5ForkStoreError::Io(error),
                BoundedReadError::TooLarge => Pfm5ForkStoreError::BranchTooLarge,
            })?;
            if branch_bytes != envelope {
                return Err(Pfm5ForkStoreError::BranchDigestMismatch);
            }
            actual.push(digest);
        }
        actual.sort_unstable();
        if actual != self.manifest.branch_digests {
            return Err(Pfm5ForkStoreError::ManifestAnchorMismatch);
        }
        Ok(self.manifest.commitment()?)
    }

    /// Commit one new branch locally. The envelope is validated on a cloned archive, persisted
    /// before the atomic PFM5 manifest replacement, and replayed on every reopen. This is
    /// deliberately disabled after opening against an external anchor until a PFM5 CAS publisher
    /// can atomically advance that independent anchor too.
    pub fn submit_local<A: MlDsa65Verifier>(
        &mut self,
        envelope: &[u8],
        authenticator: &A,
        clock: &dyn ReferenceTimeProvider,
    ) -> Result<V4HybridForkChoiceOutcome, Pfm5ForkStoreError> {
        if self.anchored {
            return Err(Pfm5ForkStoreError::ExternalAnchorRequired);
        }
        let previous_commitment = self.manifest_anchor()?;
        let mut candidate_archive = self.archive.clone();
        let outcome = candidate_archive.insert_encoded(envelope, authenticator, clock)?;
        if candidate_archive.archive_len() == self.archive.archive_len() {
            return Err(Pfm5ForkStoreError::NoStateChange);
        }
        let context = self.validation_context();
        let next_manifest = next_pfm5_manifest_after_replay(
            &self.manifest,
            &self.checkpoint,
            &context,
            previous_commitment,
            self.minimum_generation.max(self.manifest.generation),
            self.minimum_checkpoint_height
                .max(self.manifest.checkpoint_height),
            &candidate_archive,
        )?;
        persist_archive_envelopes(&self.directory, &candidate_archive, &self.params)?;
        write_manifest_atomic(
            &self.directory.join(MANIFEST_NAME),
            &next_manifest.encode()?,
        )?;
        self.archive = candidate_archive;
        self.manifest = next_manifest;
        Ok(outcome)
    }

    fn validation_context(&self) -> Pcp4ValidationContext<'_> {
        Pcp4ValidationContext {
            network_id: &self.network_id,
            trusted_genesis: &self.trusted_genesis,
            params: &self.params,
            active_transaction_manifest_id: &self.transaction_manifest_id,
        }
    }
}

fn initial_manifest(
    checkpoint: &Pcp4CheckpointRecord,
    context: &Pcp4ValidationContext<'_>,
    checkpoint_len: usize,
) -> Result<Pfm5CheckpointManifest, Pfm5ForkStoreError> {
    let profile =
        crate::private_testnet_checkpoint_candidate::consensus_profile_fingerprint(context.params)?;
    let checkpoint_record_len =
        u32::try_from(checkpoint_len).map_err(|_| Pfm5ForkStoreError::CheckpointTooLarge)?;
    let manifest = Pfm5CheckpointManifest {
        network_id: *context.network_id,
        consensus_profile_fingerprint: profile,
        genesis_fingerprint: checkpoint.genesis_fingerprint,
        generation: 1,
        parent_manifest_commitment: [0; 32],
        checkpoint_height: checkpoint.logical_height,
        checkpoint_record_commitment: checkpoint.commitment(context)?,
        checkpoint_record_len,
        checkpoint_consensus_tip_digest: checkpoint.consensus_tip_digest,
        checkpoint_ledger_tip_hash: checkpoint.ledger_tip_hash,
        checkpoint_state_root: checkpoint.monetary_state_root,
        checkpoint_total_mined_atoms: checkpoint.total_mined_atoms,
        checkpoint_cumulative_chainwork: checkpoint.cumulative_chainwork,
        canonical_tip_height: checkpoint.logical_height,
        canonical_tip_digest: checkpoint.consensus_tip_digest,
        branch_digests: Vec::new(),
    };
    manifest.validate_checkpoint(checkpoint, context)?;
    Ok(manifest)
}

fn persist_archive_envelopes(
    directory: &Path,
    archive: &PrivateTestnetV4HybridForkChoice,
    params: &ConsensusParameters,
) -> Result<(), Pfm5ForkStoreError> {
    let envelopes = archive.archive_envelopes_bounded(
        MAX_V4_HYBRID_FORK_ARCHIVE_BLOCKS,
        MAX_V4_HYBRID_FORK_ARCHIVE_BYTES,
    )?;
    for envelope in envelopes {
        let decoded = decode_candidate_v4_hybrid_monetary_network_block(&envelope)
            .map_err(|_| Pfm5ForkStoreError::BranchDigestMismatch)?;
        let digest = pow_digest(&decoded.header, params.pow)
            .map_err(|_| Pfm5ForkStoreError::BranchDigestMismatch)?;
        let path = directory.join(branch_file_name(&digest));
        if path.exists() {
            let current =
                read_bounded_file(&path, MAX_PRIVATE_TESTNET_V4_HYBRID_MONETARY_ENVELOPE_BYTES)
                    .map_err(|error| match error {
                        BoundedReadError::Io(error) => Pfm5ForkStoreError::Io(error),
                        BoundedReadError::TooLarge => Pfm5ForkStoreError::BranchTooLarge,
                    })?;
            if current != envelope {
                return Err(Pfm5ForkStoreError::BranchDigestMismatch);
            }
        } else {
            write_branch_create_new(&path, &envelope)?;
        }
    }
    Ok(())
}

#[derive(Debug)]
enum BoundedReadError {
    Io(io::Error),
    TooLarge,
}

fn read_bounded_file(path: &Path, max_bytes: usize) -> Result<Vec<u8>, BoundedReadError> {
    let path_metadata = fs::symlink_metadata(path).map_err(BoundedReadError::Io)?;
    if !path_metadata.file_type().is_file() {
        return Err(BoundedReadError::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            "PFM5 store entry is not a regular file",
        )));
    }
    let file = File::open(path).map_err(BoundedReadError::Io)?;
    let length = file.metadata().map_err(BoundedReadError::Io)?.len();
    if length > max_bytes as u64 {
        return Err(BoundedReadError::TooLarge);
    }
    let mut bytes = Vec::with_capacity(length as usize);
    file.take(max_bytes as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(BoundedReadError::Io)?;
    if bytes.len() > max_bytes {
        return Err(BoundedReadError::TooLarge);
    }
    Ok(bytes)
}

fn validate_lock_entry(directory: &Path) -> Result<(), Pfm5ForkStoreError> {
    match fs::symlink_metadata(directory.join(LOCK_NAME)) {
        Ok(metadata)
            if metadata.file_type().is_file()
                && lock_entry_has_single_link(&directory.join(LOCK_NAME), &metadata) =>
        {
            Ok(())
        }
        Ok(_) => Err(Pfm5ForkStoreError::UnexpectedStoreEntry),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(Pfm5ForkStoreError::Io(error)),
    }
}

#[cfg(unix)]
fn lock_entry_has_single_link(_path: &Path, metadata: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    metadata.nlink() == 1
}

#[cfg(windows)]
fn lock_entry_has_single_link(path: &Path, _metadata: &fs::Metadata) -> bool {
    use std::os::windows::io::AsRawHandle;

    #[repr(C)]
    struct FileTime {
        low: u32,
        high: u32,
    }
    #[repr(C)]
    struct ByHandleFileInformation {
        attributes: u32,
        creation_time: FileTime,
        last_access_time: FileTime,
        last_write_time: FileTime,
        volume_serial_number: u32,
        file_size_high: u32,
        file_size_low: u32,
        number_of_links: u32,
        file_index_high: u32,
        file_index_low: u32,
    }
    #[link(name = "kernel32")]
    extern "system" {
        fn GetFileInformationByHandle(
            file: *mut std::ffi::c_void,
            information: *mut ByHandleFileInformation,
        ) -> i32;
    }

    let Ok(file) = File::open(path) else {
        return false;
    };
    let mut information = ByHandleFileInformation {
        attributes: 0,
        creation_time: FileTime { low: 0, high: 0 },
        last_access_time: FileTime { low: 0, high: 0 },
        last_write_time: FileTime { low: 0, high: 0 },
        volume_serial_number: 0,
        file_size_high: 0,
        file_size_low: 0,
        number_of_links: 0,
        file_index_high: 0,
        file_index_low: 0,
    };
    // SAFETY: the handle is owned by `file` and the output struct matches the Win32 ABI.
    let success = unsafe {
        GetFileInformationByHandle(
            file.as_raw_handle() as *mut std::ffi::c_void,
            &mut information,
        )
    };
    success != 0 && information.number_of_links == 1
}

#[cfg(not(any(unix, windows)))]
fn lock_entry_has_single_link(_path: &Path, _metadata: &fs::Metadata) -> bool {
    true
}

fn acquire_writer_lock(directory: &Path) -> Result<StoreWriterLock, Pfm5ForkStoreError> {
    StoreWriterLock::acquire(directory, LOCK_NAME).map_err(|error| {
        if error.kind() == io::ErrorKind::WouldBlock {
            Pfm5ForkStoreError::LockHeld
        } else {
            Pfm5ForkStoreError::Io(error)
        }
    })
}

fn branch_file_name(digest: &[u8; 32]) -> String {
    format!("{BRANCH_PREFIX}{}{BRANCH_SUFFIX}", encode_hex(digest))
}

fn parse_branch_file_name(name: &str) -> Result<[u8; 32], Pfm5ForkStoreError> {
    let hex = name
        .strip_prefix(BRANCH_PREFIX)
        .and_then(|value| value.strip_suffix(BRANCH_SUFFIX))
        .ok_or(Pfm5ForkStoreError::UnexpectedBranchFileName)?;
    if hex.len() != 64 {
        return Err(Pfm5ForkStoreError::UnexpectedBranchFileName);
    }
    let mut digest = [0u8; 32];
    for (index, pair) in hex.as_bytes().chunks_exact(2).enumerate() {
        let pair =
            std::str::from_utf8(pair).map_err(|_| Pfm5ForkStoreError::UnexpectedBranchFileName)?;
        digest[index] = u8::from_str_radix(pair, 16)
            .map_err(|_| Pfm5ForkStoreError::UnexpectedBranchFileName)?;
    }
    if branch_file_name(&digest) != name {
        return Err(Pfm5ForkStoreError::UnexpectedBranchFileName);
    }
    Ok(digest)
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn write_synced_new(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    let result = file
        .write_all(bytes)
        .and_then(|_| file.flush())
        .and_then(|_| file.sync_all());
    drop(file);
    if let Err(error) = result {
        let _ = fs::remove_file(path);
        let _ = sync_parent(parent);
        return Err(error);
    }
    sync_parent(parent)
}

fn write_branch_create_new(path: &Path, bytes: &[u8]) -> Result<(), Pfm5ForkStoreError> {
    if bytes.len() > MAX_PRIVATE_TESTNET_V4_HYBRID_MONETARY_ENVELOPE_BYTES {
        return Err(Pfm5ForkStoreError::BranchTooLarge);
    }
    match write_synced_new(path, bytes) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            let current =
                read_bounded_file(path, MAX_PRIVATE_TESTNET_V4_HYBRID_MONETARY_ENVELOPE_BYTES)
                    .map_err(|read_error| match read_error {
                        BoundedReadError::Io(error) => Pfm5ForkStoreError::Io(error),
                        BoundedReadError::TooLarge => Pfm5ForkStoreError::BranchTooLarge,
                    })?;
            if current == bytes {
                Ok(())
            } else {
                Err(Pfm5ForkStoreError::BranchDigestMismatch)
            }
        }
        Err(error) => Err(Pfm5ForkStoreError::Io(error)),
    }
}

fn unique_temp_path(parent: &Path, final_name: &std::ffi::OsStr) -> PathBuf {
    let id = NEXT_TEMP_ID.fetch_add(1, AtomicOrdering::Relaxed);
    let mut name = final_name.to_os_string();
    name.push(format!("{TEMP_MARKER}{}-{id}", process::id()));
    parent.join(name)
}

fn write_manifest_atomic(path: &Path, bytes: &[u8]) -> Result<(), Pfm5ForkStoreError> {
    if bytes.len() > MAX_PFM5_MANIFEST_BYTES {
        return Err(Pfm5ForkStoreError::ManifestTooLarge);
    }
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let final_name = path
        .file_name()
        .ok_or(Pfm5ForkStoreError::UnexpectedStoreEntry)?;
    let temp = unique_temp_path(parent, final_name);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temp)?;
    let result = file
        .write_all(bytes)
        .and_then(|_| file.flush())
        .and_then(|_| file.sync_all());
    if let Err(error) = result {
        drop(file);
        let _ = fs::remove_file(&temp);
        return Err(Pfm5ForkStoreError::Io(error));
    }
    drop(file);
    if let Err(error) = atomic_replace(&temp, path) {
        let _ = fs::remove_file(&temp);
        return Err(Pfm5ForkStoreError::Io(error));
    }
    Ok(())
}

fn ensure_initialization_directory(directory: &Path) -> Result<(), Pfm5ForkStoreError> {
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| Pfm5ForkStoreError::UnexpectedStoreEntry)?;
        if !entry.file_type()?.is_file() || (name != LOCK_NAME && name != CHECKPOINT_NAME) {
            return Err(Pfm5ForkStoreError::UnexpectedStoreEntry);
        }
    }
    Ok(())
}

fn validate_store_entry_layout(directory: &Path) -> Result<(), Pfm5ForkStoreError> {
    let mut branch_count = 0usize;
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            return Err(Pfm5ForkStoreError::UnexpectedStoreEntry);
        }
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| Pfm5ForkStoreError::UnexpectedStoreEntry)?;
        if name == LOCK_NAME || name == MANIFEST_NAME || name == CHECKPOINT_NAME {
            continue;
        }
        if name.starts_with(MANIFEST_NAME) && name.contains(TEMP_MARKER) {
            continue;
        }
        if name.starts_with(BRANCH_PREFIX) && name.ends_with(BRANCH_SUFFIX) {
            parse_branch_file_name(&name)?;
            branch_count += 1;
            if branch_count > MAX_V4_HYBRID_FORK_ARCHIVE_BLOCKS + 256 {
                return Err(Pfm5ForkStoreError::TooManyStoreEntries);
            }
            continue;
        }
        return Err(Pfm5ForkStoreError::UnexpectedStoreEntry);
    }
    Ok(())
}

fn cleanup_store_entries(
    directory: &Path,
    known_digests: &BTreeSet<[u8; 32]>,
) -> Result<(), Pfm5ForkStoreError> {
    let mut seen = 0usize;
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let kind = entry.file_type()?;
        let name = entry.file_name();
        let name = name
            .to_str()
            .ok_or(Pfm5ForkStoreError::UnexpectedStoreEntry)?;
        if !kind.is_file() {
            return Err(Pfm5ForkStoreError::UnexpectedStoreEntry);
        }
        if name == LOCK_NAME || name == MANIFEST_NAME || name == CHECKPOINT_NAME {
            continue;
        }
        if name.starts_with(MANIFEST_NAME) && name.contains(TEMP_MARKER) {
            fs::remove_file(entry.path())?;
            continue;
        }
        if name.starts_with(BRANCH_PREFIX) && name.ends_with(BRANCH_SUFFIX) {
            seen += 1;
            if seen > MAX_V4_HYBRID_FORK_ARCHIVE_BLOCKS + 256 {
                return Err(Pfm5ForkStoreError::TooManyStoreEntries);
            }
            let digest = parse_branch_file_name(name)?;
            if !known_digests.contains(&digest) {
                fs::remove_file(entry.path())?;
            }
            continue;
        }
        return Err(Pfm5ForkStoreError::UnexpectedStoreEntry);
    }
    sync_parent(directory)?;
    Ok(())
}

#[cfg(windows)]
fn atomic_replace(source: &Path, destination: &Path) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    const MOVEFILE_REPLACE_EXISTING: u32 = 0x1;
    const MOVEFILE_WRITE_THROUGH: u32 = 0x8;
    let from: Vec<u16> = source.as_os_str().encode_wide().chain(Some(0)).collect();
    let to: Vec<u16> = destination
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect();
    #[link(name = "Kernel32")]
    extern "system" {
        fn MoveFileExW(existing: *const u16, new_name: *const u16, flags: u32) -> i32;
    }
    let success = unsafe {
        MoveFileExW(
            from.as_ptr(),
            to.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if success == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(not(windows))]
fn atomic_replace(source: &Path, destination: &Path) -> io::Result<()> {
    fs::rename(source, destination)?;
    sync_parent(destination.parent().unwrap_or_else(|| Path::new(".")))
}

#[cfg(windows)]
fn sync_parent(_directory: &Path) -> io::Result<()> {
    Ok(())
}
#[cfg(unix)]
fn sync_parent(directory: &Path) -> io::Result<()> {
    File::open(directory)?.sync_all()
}
#[cfg(not(any(windows, unix)))]
fn sync_parent(_directory: &Path) -> io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        chain_admission::{ReferenceTimeError, ReferenceTimeProvenance, ReferenceTimeSample},
        consensus::{ConsensusParameters, PowHeader, Uint256},
        private_testnet_checkpoint_candidate::{
            consensus_profile_fingerprint, trusted_genesis_fingerprint,
        },
        private_testnet_driver::PrivateTestnetChain,
        private_testnet_monetary_wire::encode_candidate_v4_hybrid_monetary_network_block,
        state_machine::{V4HybridMonetaryBlock, MONETARY_PUBLIC_GOODS_BUDGET_ATOMS},
        v4_fat1_mldsa65_candidate::LibcruxMlDsa65VerifierCandidate,
    };
    use std::sync::atomic::AtomicU64;

    const NETWORK: [u8; 32] = [0x81; 32];
    const TX_MANIFEST: [u8; 32] = [0x44; 32];
    static NEXT_TEST_PATH: AtomicU64 = AtomicU64::new(1);

    struct TestDirectory(PathBuf);
    impl TestDirectory {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "ain1-pfm5-store-{}-{}",
                process::id(),
                NEXT_TEST_PATH.fetch_add(1, AtomicOrdering::Relaxed)
            ));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }
        fn path(&self) -> &Path {
            &self.0
        }
    }
    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    struct FixedClock;
    impl ReferenceTimeProvider for FixedClock {
        fn sample(&self) -> Result<ReferenceTimeSample, ReferenceTimeError> {
            Ok(ReferenceTimeSample {
                unix_seconds: 200,
                provenance: ReferenceTimeProvenance::ConfiguredProvider,
                source_id: "pfm5-test-clock",
            })
        }
    }

    struct Fixture {
        network: [u8; 32],
        genesis: MonetaryLedgerState,
        params: ConsensusParameters,
        transaction_manifest_id: [u8; 32],
        checkpoint: Pcp4CheckpointRecord,
    }

    impl Fixture {
        fn new() -> Self {
            let network = NETWORK;
            let genesis = MonetaryLedgerState::genesis(
                network,
                [0x11; 32],
                vec![([0x22; 32], MONETARY_PUBLIC_GOODS_BUDGET_ATOMS as u64)],
            )
            .unwrap();
            let mut params = ConsensusParameters::candidate_testnet().unwrap();
            params.initial_target = Uint256::MAX;
            params.pow_limit = Uint256::MAX;
            params.pow.memory_kib = 8;
            params.pow.iterations = 1;
            params.pow.lanes = 1;
            let transaction_manifest_id = TX_MANIFEST;
            let context = Pcp4ValidationContext {
                network_id: &network,
                trusted_genesis: &genesis,
                params: &params,
                active_transaction_manifest_id: &transaction_manifest_id,
            };
            let chain = PrivateTestnetChain::new_monetary(genesis.clone(), params.clone()).unwrap();
            let state = chain.monetary_state().unwrap();
            let checkpoint = Pcp4CheckpointRecord {
                network_id: network,
                genesis_fingerprint: trusted_genesis_fingerprint(&context).unwrap(),
                consensus_profile_fingerprint: consensus_profile_fingerprint(&params).unwrap(),
                transaction_manifest_id,
                logical_height: state.height(),
                consensus_tip_digest: chain.chain_tip().tip_hash,
                ledger_tip_hash: state.tip_hash(),
                monetary_state_root: state.state_root(),
                total_mined_atoms: state.total_mined_atoms(),
                cumulative_chainwork: chain.cumulative_work(),
                parent_checkpoint_commitment: [0; 32],
                monetary_snapshot: state.encode_snapshot().unwrap(),
                target_history: chain.target_history().checkpoint_snapshot().unwrap(),
            };
            Self {
                network,
                genesis,
                params,
                transaction_manifest_id,
                checkpoint,
            }
        }

        fn context(&self) -> Pcp4ValidationContext<'_> {
            Pcp4ValidationContext {
                network_id: &self.network,
                trusted_genesis: &self.genesis,
                params: &self.params,
                active_transaction_manifest_id: &self.transaction_manifest_id,
            }
        }
    }

    fn first_envelope(parent: &PrivateTestnetChain, params: &ConsensusParameters) -> Vec<u8> {
        let verifier = LibcruxMlDsa65VerifierCandidate;
        let state = parent.monetary_state().unwrap();
        let mut block = V4HybridMonetaryBlock {
            height: state.height() + 1,
            timestamp: 100 + state.height(),
            parent_hash: state.tip_hash(),
            state_root: [0; 32],
            transactions: Vec::new(),
            miner: [0x33; 32],
            claimed_subsidy_atoms: state.expected_miner_reward().unwrap(),
        };
        block.state_root = state
            .preview_v4_hybrid_state_root_after(&block, &TX_MANIFEST, &verifier)
            .unwrap();
        let header = PowHeader {
            protocol_version: params.protocol_version,
            network_id: NETWORK,
            height: block.height,
            timestamp: block.timestamp,
            parent_hash: block.parent_hash,
            previous_consensus_hash: parent.chain_tip().tip_hash,
            state_root: block.state_root,
            target: parent.expected_target(None).unwrap(),
            nonce: 0x0102_0304_0506_0708,
        };
        encode_candidate_v4_hybrid_monetary_network_block(&header, &block).unwrap()
    }

    fn open_unanchored(
        directory: &Path,
        fixture: &Fixture,
        verifier: &LibcruxMlDsa65VerifierCandidate,
        minimum_generation: u64,
    ) -> PrivateTestnetPfm5ForkStoreCandidate {
        PrivateTestnetPfm5ForkStoreCandidate::open_local_unanchored(
            directory,
            fixture.network,
            fixture.genesis.clone(),
            fixture.params.clone(),
            fixture.transaction_manifest_id,
            minimum_generation,
            fixture.checkpoint.logical_height,
            verifier,
        )
        .unwrap()
    }

    #[test]
    fn pfm5_store_initializes_submits_reopens_and_checks_external_manifest_anchor() {
        let fixture = Fixture::new();
        let context = fixture.context();
        let verifier = LibcruxMlDsa65VerifierCandidate;
        let directory = TestDirectory::new();

        let mut store = PrivateTestnetPfm5ForkStoreCandidate::initialize(
            directory.path(),
            fixture.checkpoint.clone(),
            &context,
            &verifier,
        )
        .unwrap();
        assert_eq!(store.manifest().generation, 1);
        assert_eq!(store.canonical_height(), fixture.checkpoint.logical_height);
        let parent = store.archive().canonical_chain().clone();
        let envelope = first_envelope(&parent, &fixture.params);
        let outcome = store
            .submit_local(&envelope, &verifier, &FixedClock)
            .unwrap();
        assert_eq!(outcome.canonical_height, 1);
        assert_eq!(store.manifest().generation, 2);
        assert_eq!(store.manifest().branch_digests.len(), 1);
        let expected_anchor = store.manifest_anchor().unwrap();
        assert!(!store.is_externally_anchored());
        drop(store);

        let reopened = open_unanchored(directory.path(), &fixture, &verifier, 2);
        assert_eq!(reopened.manifest().generation, 2);
        assert_eq!(reopened.canonical_height(), 1);
        assert_eq!(reopened.canonical_tip(), outcome.canonical_tip);
        assert_eq!(reopened.manifest_anchor().unwrap(), expected_anchor);
        drop(reopened);

        assert!(matches!(
            PrivateTestnetPfm5ForkStoreCandidate::open_with_manifest_anchor(
                directory.path(),
                fixture.network,
                fixture.genesis.clone(),
                fixture.params.clone(),
                fixture.transaction_manifest_id,
                [0xEE; 32],
                2,
                fixture.checkpoint.logical_height,
                &verifier,
            ),
            Err(Pfm5ForkStoreError::ManifestAnchorMismatch)
        ));

        let anchored = PrivateTestnetPfm5ForkStoreCandidate::open_with_manifest_anchor(
            directory.path(),
            fixture.network,
            fixture.genesis.clone(),
            fixture.params.clone(),
            fixture.transaction_manifest_id,
            expected_anchor,
            2,
            fixture.checkpoint.logical_height,
            &verifier,
        )
        .unwrap();
        assert!(anchored.is_externally_anchored());
        let rejected = {
            let parent = anchored.archive().canonical_chain().clone();
            let next = first_envelope(&parent, &fixture.params);
            let mut anchored = anchored;
            anchored.submit_local(&next, &verifier, &FixedClock)
        };
        assert!(matches!(
            rejected,
            Err(Pfm5ForkStoreError::ExternalAnchorRequired)
        ));
    }

    #[test]
    fn pfm5_store_rejects_corrupted_referenced_branch_before_replay() {
        let fixture = Fixture::new();
        let context = fixture.context();
        let verifier = LibcruxMlDsa65VerifierCandidate;
        let directory = TestDirectory::new();
        let mut store = PrivateTestnetPfm5ForkStoreCandidate::initialize(
            directory.path(),
            fixture.checkpoint.clone(),
            &context,
            &verifier,
        )
        .unwrap();
        let parent = store.archive().canonical_chain().clone();
        let envelope = first_envelope(&parent, &fixture.params);
        store
            .submit_local(&envelope, &verifier, &FixedClock)
            .unwrap();
        let digest = store.manifest().branch_digests[0];
        drop(store);

        let path = directory.path().join(branch_file_name(&digest));
        let mut bytes = fs::read(&path).unwrap();
        bytes[0] ^= 0x01;
        fs::write(&path, bytes).unwrap();

        assert!(matches!(
            PrivateTestnetPfm5ForkStoreCandidate::open_local_unanchored(
                directory.path(),
                fixture.network,
                fixture.genesis.clone(),
                fixture.params.clone(),
                fixture.transaction_manifest_id,
                2,
                fixture.checkpoint.logical_height,
                &verifier,
            ),
            Err(Pfm5ForkStoreError::BranchDigestMismatch)
        ));
    }

    #[test]
    fn pfm5_store_rejects_symlinked_writer_lock_before_touching_target() {
        let fixture = Fixture::new();
        let context = fixture.context();
        let verifier = LibcruxMlDsa65VerifierCandidate;
        let directory = TestDirectory::new();
        let target = directory.path().with_extension("external-lock-target");
        fs::write(&target, b"preserve external operator data").unwrap();
        let lock_path = directory.path().join(LOCK_NAME);

        #[cfg(unix)]
        std::os::unix::fs::symlink(&target, &lock_path).unwrap();
        #[cfg(windows)]
        if std::os::windows::fs::symlink_file(&target, &lock_path).is_err() {
            let _ = fs::remove_file(&target);
            return;
        }

        assert!(matches!(
            PrivateTestnetPfm5ForkStoreCandidate::open_local_unanchored(
                directory.path(),
                fixture.network,
                fixture.genesis.clone(),
                fixture.params.clone(),
                fixture.transaction_manifest_id,
                1,
                fixture.checkpoint.logical_height,
                &verifier,
            ),
            Err(Pfm5ForkStoreError::UnexpectedStoreEntry)
        ));
        assert!(matches!(
            PrivateTestnetPfm5ForkStoreCandidate::initialize(
                directory.path(),
                fixture.checkpoint.clone(),
                &context,
                &verifier,
            ),
            Err(Pfm5ForkStoreError::UnexpectedStoreEntry)
        ));
        assert_eq!(
            fs::read(&target).unwrap(),
            b"preserve external operator data"
        );
        let _ = fs::remove_file(&target);
    }

    #[test]
    fn pfm5_store_rejects_hard_linked_writer_lock_before_touching_target() {
        let fixture = Fixture::new();
        let context = fixture.context();
        let verifier = LibcruxMlDsa65VerifierCandidate;
        let directory = TestDirectory::new();
        let target = directory.path().with_extension("external-hardlink-target");
        fs::write(&target, b"preserve external operator data").unwrap();
        let lock_path = directory.path().join(LOCK_NAME);
        fs::hard_link(&target, &lock_path).unwrap();

        assert!(matches!(
            PrivateTestnetPfm5ForkStoreCandidate::open_local_unanchored(
                directory.path(),
                fixture.network,
                fixture.genesis.clone(),
                fixture.params.clone(),
                fixture.transaction_manifest_id,
                1,
                fixture.checkpoint.logical_height,
                &verifier,
            ),
            Err(Pfm5ForkStoreError::UnexpectedStoreEntry)
        ));
        assert!(matches!(
            PrivateTestnetPfm5ForkStoreCandidate::initialize(
                directory.path(),
                fixture.checkpoint.clone(),
                &context,
                &verifier,
            ),
            Err(Pfm5ForkStoreError::UnexpectedStoreEntry)
        ));
        assert_eq!(
            fs::read(&target).unwrap(),
            b"preserve external operator data"
        );
        let _ = fs::remove_file(&target);
    }

    #[test]
    fn pfm5_bounded_reader_rejects_a_directory_as_a_store_file() {
        let directory = TestDirectory::new();
        assert!(matches!(
            read_bounded_file(directory.path(), 1024),
            Err(BoundedReadError::Io(error))
                if error.kind() == io::ErrorKind::InvalidInput
        ));
    }

    #[test]
    fn pfm5_store_rejects_nonempty_directory_before_initialization_writes() {
        let fixture = Fixture::new();
        let context = fixture.context();
        let verifier = LibcruxMlDsa65VerifierCandidate;
        let directory = TestDirectory::new();
        fs::write(directory.path().join("operator-data.txt"), b"preserve").unwrap();

        assert!(matches!(
            PrivateTestnetPfm5ForkStoreCandidate::initialize(
                directory.path(),
                fixture.checkpoint.clone(),
                &context,
                &verifier,
            ),
            Err(Pfm5ForkStoreError::UnexpectedStoreEntry)
        ));
        assert_eq!(
            fs::read(directory.path().join("operator-data.txt")).unwrap(),
            b"preserve"
        );
        assert!(!directory.path().join(MANIFEST_NAME).exists());
        assert!(!directory.path().join(CHECKPOINT_NAME).exists());
    }

    #[test]
    fn pfm5_store_reopen_reconciles_unreferenced_branch_and_manifest_temp_files() {
        let fixture = Fixture::new();
        let context = fixture.context();
        let verifier = LibcruxMlDsa65VerifierCandidate;
        let directory = TestDirectory::new();
        let store = PrivateTestnetPfm5ForkStoreCandidate::initialize(
            directory.path(),
            fixture.checkpoint.clone(),
            &context,
            &verifier,
        )
        .unwrap();
        let orphan = directory.path().join(branch_file_name(&[0xA5; 32]));
        fs::write(&orphan, b"orphan bytes from interrupted branch publication").unwrap();
        let stale_temp = directory
            .path()
            .join(format!("{MANIFEST_NAME}{TEMP_MARKER}123-1"));
        fs::write(&stale_temp, b"stale temporary manifest").unwrap();
        drop(store);

        let reopened = open_unanchored(directory.path(), &fixture, &verifier, 1);
        assert_eq!(reopened.manifest().generation, 1);
        assert!(!orphan.exists());
        assert!(!stale_temp.exists());
    }

    #[test]
    fn pfm5_store_retries_interrupted_checkpoint_before_manifest_publication() {
        let fixture = Fixture::new();
        let context = fixture.context();
        let verifier = LibcruxMlDsa65VerifierCandidate;
        let directory = TestDirectory::new();
        let checkpoint_bytes = fixture.checkpoint.encode(&context).unwrap();

        // Simulate a crash after the immutable PCP4 file was synced but before PFM5 appeared.
        write_synced_new(&directory.path().join(CHECKPOINT_NAME), &checkpoint_bytes).unwrap();

        let store = PrivateTestnetPfm5ForkStoreCandidate::initialize(
            directory.path(),
            fixture.checkpoint.clone(),
            &context,
            &verifier,
        )
        .unwrap();
        assert_eq!(store.manifest().generation, 1);
        assert_eq!(
            store.manifest().checkpoint_height,
            fixture.checkpoint.logical_height
        );
        assert!(directory.path().join(MANIFEST_NAME).is_file());
    }
}
